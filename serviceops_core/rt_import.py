"""One-time (or re-run-until-clean) import of Request Tracker (RT) tickets
into ServiceOps, via RT's REST2.0 JSON API.

Design mirrors serviceops_core/netbox_sync.py: manual/admin-triggered,
dry-run preview before anything commits, per-record error isolation so one
bad RT ticket doesn't abort the whole batch, and idempotent re-runs via
EnterpriseRecord.external_source="rt" / external_id=<RT ticket id> -- a
ticket already imported is skipped, never duplicated or overwritten, so
fixing a mapping problem and re-running only picks up what previously
failed.

RT tickets are routine, team-handled work items rather than formal ITIL
incidents, so each one becomes an "IT operations events" EnterpriseRecord
(domain="event", record_type="RT Ticket") rather than a ServiceOps
Incident -- *except* a ticket whose Subject contains the literal tag
"[CR]" (case-insensitive), which is this org's convention for a change
request; those import as a ServiceOps Change (Ticket, kind="change") with
a ChangeGovernance/ChangeOwnership row instead. Historical changes are
inserted directly rather than going through the live approval-chain
creation used by ticket_new() -- these already happened, so spinning up
fresh CCB/approval tasks for them would be spurious and would notify
approvers about years-old work.

Either way, the RT Queue maps to an owning team (matched/aliased/created
the same way CSV CI import resolves team names), and each Requestor/Owner
maps to a ServiceOps User by email, auto-creating a requester-role
placeholder account when no match exists. Correspondence is folded into
the description as a chronological log for IT operations events (which
have no comment-thread model the way Ticket does); Changes get the same
log appended to their description too, for consistency and because a
historical import has no natural place to "replay" as live comments
either. Real file attachments found along the way are downloaded and
saved as FileAttachment rows against the imported record (Ticket gained
this already; EnterpriseRecord gained an attachments relationship for
this feature) -- going through the same extension/magic-byte allowlist
and malware scan a normal browser upload gets, so an attachment that
wouldn't be allowed in through the UI isn't allowed in through RT import
either. One that's rejected (disallowed type, failed scan) is still noted
by filename in the description log, just without the file itself.

IMPORTANT: RT REST2.0's exact JSON shape (custom field names, whether a
Queue/Owner reference is inlined or requires a follow-up request) can vary
by RT version and by admin customization. This module fetches full,
unambiguous ticket/queue/user records via GET rather than relying on
guessed field-expansion query syntax, but the very first dry run against a
real instance should still be inspected -- the per-ticket preview rows are
built specifically so a human can eyeball a handful before ever committing.
"""
import base64
import hashlib
import json
import os
import re
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor

import requests
from serviceops_core.localization import tr

# RT's own web UI does one round trip per transaction and per attachment
# too, but it's rendering one ticket a human is looking at -- a bulk import
# doing that sequentially for every ticket in a batch is what made 10
# tickets take ~10 minutes against a real (slow) RT instance. These GETs
# are independent reads with no ordering dependency between them, so
# fetching a ticket's transactions (and each transaction's attachments) in
# parallel is a straightforward, safe speedup. Kept modest -- this is
# concurrency against one admin-configured RT instance during an admin-
# triggered import, not something that needs to be tuned per deployment.
_CONCURRENCY = 8

# Crash-safety limits. A real RT instance can return enormous attachments,
# thousands of transactions, odd JSON and text PostgreSQL rejects; none of that
# may take the background worker down or poison the whole import.
_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024   # larger attachments are noted, not downloaded
_MAX_RESPONSE_BYTES = 40 * 1024 * 1024     # any single RT response (base64 adds a third)
_MAX_HISTORY_TRANSACTIONS = 2000           # per ticket
_MAX_SUMMARY_ITEMS = 500                   # errors and preview rows kept in a job result
_DRY_RUN_SAMPLE = 200                      # a preview looks at most this many new tickets

# RT ships with new/open/stalled/resolved/rejected/deleted by default, but
# almost every real deployment (this one included) customizes its lifecycle
# to add statuses like "closed". Unrecognized statuses are NOT silently
# defaulted to "New" -- see _map_status -- because that actively misreports
# a ticket that's actually finished as brand new. EnterpriseRecord and
# Ticket have different valid state vocabularies (EnterpriseRecord has
# "Rejected", Ticket has "Cancelled" instead), so each import target gets
# its own map.
RT_STATUS_MAP_EVENT = {
    "new": "New", "open": "In Progress", "stalled": "Pending",
    "resolved": "Resolved", "rejected": "Rejected", "deleted": "Rejected",
    "closed": "Closed",
}
RT_STATUS_MAP_CHANGE = {
    "new": "New", "open": "In Progress", "stalled": "Pending",
    "resolved": "Resolved", "rejected": "Cancelled", "deleted": "Cancelled",
    "closed": "Closed",
}

COMMENT_TRANSACTION_TYPES = {"Create", "Correspond", "Comment"}
_HTML_TAG_RE = re.compile(r"<[^>]+>")
# This org's convention for tagging an RT ticket as a change request rather
# than routine work, checked case-insensitively against the Subject.
CHANGE_REQUEST_TAG = "[cr]"


def _is_change_request(subject):
    return CHANGE_REQUEST_TAG in (subject or "").lower()


class RTImportError(RuntimeError):
    """Raised for conditions that must abort the whole import (e.g. not configured)."""


# RT's default priority scale is 0-100 (0 = no priority set). This bucketing
# is a reasonable default, not a guarantee it matches a customized scale --
# reviewable/adjustable per the dry-run preview.
def _map_priority(rt_priority):
    try:
        value = int(rt_priority)
    except (TypeError, ValueError):
        return "P3"
    if value >= 75:
        return "P1"
    if value >= 50:
        return "P2"
    if value >= 25:
        return "P3"
    return "P4"


def _map_status(rt_status, status_map, summary=None):
    key = (rt_status or "").strip().lower()
    if key in status_map:
        return status_map[key]
    if summary is not None:
        _note(summary, "errors", 
            f"Unrecognized RT status '{rt_status}' -- defaulted to New. "
            "Add it to the status map in rt_import.py if your RT lifecycle uses it."
        )
    return "New"


def _write_ca_bundle(pem_text):
    fd, path = tempfile.mkstemp(prefix="rt-ca-", suffix=".pem")
    with os.fdopen(fd, "w") as handle:
        handle.write(pem_text)
    return path


def _rt_session(base_url, token):
    """Isolated in its own function so tests can monkeypatch it with a fake,
    matching the app.ldap_server_and_service_connection / netbox_sync._netbox_session
    mocking convention used elsewhere in this codebase.

    Certificate verification is on by default. An internal RT instance
    served from a corporate CA that isn't in the public trust store should
    be handled by pasting that CA's certificate into the RT_CA_CERT
    setting -- that's the secure fix and takes priority here.
    RT_TLS_INSECURE is a separate, explicit admin-opt-in escape hatch for
    when the CA can't be obtained; it disables verification entirely and is
    deliberately not the default."""
    import app as core_app

    session = requests.Session()
    proxies = core_app.resolve_component_proxies("RT")
    if proxies:
        session.proxies.update(proxies)
    session.trust_env = False
    session.headers.update({
        "Authorization": f"token {token}",
        "Accept": "application/json",
    })
    ca_cert = core_app.setting_value("RT_CA_CERT", "").strip()
    if ca_cert:
        session.verify = _write_ca_bundle(ca_cert)
    elif core_app.setting_bool("RT_TLS_INSECURE"):
        session.verify = False
        from flask import current_app
        current_app.logger.warning(
            "Request Tracker TLS certificate verification is disabled (RT_TLS_INSECURE); "
            "configure RT_CA_CERT instead."
        )
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


# The running import's heartbeat (set by import_from_rt for its duration), so
# slow inner loops can keep the background worker's liveness file fresh.
_tick = None


def _heartbeat():
    if _tick:
        _tick()


class RTResponseError(requests.RequestException):
    """RT answered, but not with usable JSON (a login page, a proxy error page,
    a truncated or oversized body). Treated like a failed request, so the
    same per-ticket / per-attachment isolation applies."""


def _get(session, base_url, path, params=None, max_bytes=_MAX_RESPONSE_BYTES):
    url = base_url.rstrip("/") + path
    response = session.get(url, params=params, timeout=15, stream=True)
    try:
        response.raise_for_status()
        if hasattr(response, "iter_content"):
            # Read with a size cap: a huge attachment or a runaway response
            # must not exhaust the worker's memory.
            declared = str(getattr(response, "headers", {}).get("Content-Length") or "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise RTResponseError(f"RT response too large ({int(declared)} bytes)")
            body = bytearray()
            for chunk in response.iter_content(65536):
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise RTResponseError("RT response too large")
            text = bytes(body).decode("utf-8", errors="replace")
            payload = json.loads(text)
        else:  # adapters/fakes without streaming
            payload = response.json()
    except ValueError as error:
        raise RTResponseError(f"RT returned a non-JSON response from {path}") from error
    finally:
        close = getattr(response, "close", None)
        if close:
            close()
    if not isinstance(payload, dict):
        raise RTResponseError(f"RT returned an unexpected JSON shape from {path}")
    return payload


def _clean(text, limit=None):
    """Text PostgreSQL accepts: NUL characters (which RT mail bodies and
    filenames can contain) are refused by PostgreSQL text columns and would
    fail the ticket. Optionally truncated to a column's length."""
    if text is None:
        return None
    text = str(text).replace("\x00", "")
    return text[:limit] if limit else text


def _note(summary, key, item):
    """Appends to a bounded summary list, so a pathological import cannot grow
    the job result (stored in the database, shown on the page) without limit."""
    items = summary[key]
    if len(items) < _MAX_SUMMARY_ITEMS:
        items.append(item)
    elif len(items) == _MAX_SUMMARY_ITEMS:
        items.append("... further entries omitted" if key == "errors" else {"omitted": True})


def _fetch_many(session, base_url, path_template, ids, params=None):
    """Fetches `path_template.format(id)` for each id in `ids` concurrently
    (bounded by _CONCURRENCY) and returns {id: json_or_None} -- None marks
    an id that failed to fetch, same as the sequential try/except-continue
    pattern used elsewhere in this module, just parallelized."""
    results = {}
    if not ids:
        return results

    def fetch(item_id):
        try:
            return item_id, _get(session, base_url, path_template.format(item_id), params=params)
        except Exception:  # noqa: BLE001 - one unreadable item must not fail the others
            return item_id, None

    with ThreadPoolExecutor(max_workers=min(_CONCURRENCY, len(ids))) as pool:
        for item_id, payload in pool.map(fetch, ids):
            results[item_id] = payload
    return results


def _paginate_ticket_ids(session, base_url, query):
    """Yields RT ticket ids matching `query` (RT's TicketSQL search language,
    e.g. "id > 0" for everything). Only ids are pulled from the search
    endpoint -- full ticket detail is fetched separately per id, which is
    simpler and more robust than relying on RT2.0's field-expansion query
    syntax for nested Queue/Owner references."""
    page = 1
    per_page = 100
    while True:
        payload = _get(session, base_url, "/REST/2.0/tickets", params={
            "query": query, "page": page, "per_page": per_page,
        })
        items = payload.get("items")
        items = items if isinstance(items, list) else []
        for item in items:
            ticket_id = (item.get("id") or item.get("Id")) if isinstance(item, dict) else None
            if ticket_id:
                yield str(ticket_id)
        try:
            pages = int(payload.get("pages") or 1)
        except (TypeError, ValueError):
            pages = page + 1 if len(items) >= per_page else page
        if page >= pages or not items:
            return
        page += 1


class _RecordCache:
    """Caches RT queue-id -> name and user-id -> {email, name} lookups so a
    batch of thousands of tickets referencing a handful of queues/owners
    doesn't issue a fresh request per ticket for each."""

    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self._queues = {}
        self._users = {}

    def queue_name(self, queue_ref):
        queue_id = _ref_id(queue_ref)
        if not queue_id:
            return _ref_name(queue_ref)
        if queue_id not in self._queues:
            try:
                record = _get(self.session, self.base_url, f"/REST/2.0/queue/{queue_id}")
                self._queues[queue_id] = _clean(record.get("Name"), 120) or f"RT Queue {queue_id}"
            except requests.RequestException:
                self._queues[queue_id] = f"RT Queue {queue_id}"
        return self._queues[queue_id]

    def user_contact(self, user_ref):
        user_id = _ref_id(user_ref)
        if not user_id:
            return None
        if user_id not in self._users:
            try:
                record = _get(self.session, self.base_url, f"/REST/2.0/user/{user_id}")
                self._users[user_id] = {
                    "email": _clean(record.get("EmailAddress")) or "",
                    "name": _clean(record.get("RealName") or record.get("Name")) or "",
                }
            except requests.RequestException:
                self._users[user_id] = None
        return self._users[user_id]


def _ref_id(ref):
    if isinstance(ref, dict):
        return ref.get("id")
    return None


def _ref_name(ref):
    if isinstance(ref, dict):
        return ref.get("Name") or ref.get("_url")
    if isinstance(ref, str):
        return ref
    return None


def _resolve_or_create_user(email, name, tenant_id, summary):
    import app as core_app
    from app import db

    email = (_clean(email) or "").strip().lower()
    if not email or len(email) > 160 or "@" not in email:
        return None
    user = core_app.User.query.filter(db.func.lower(core_app.User.email) == email).first()
    if user:
        if user.tenant_id == tenant_id:
            return user
        # Email addresses are unique across the whole installation. The same
        # person belongs to another tenant: never reuse or move that account;
        # the ticket falls back to the unresolved-requester placeholder.
        _note(summary, "errors", f"Requester {email} belongs to another tenant; recorded as unresolved.")
        return None
    base_username = email.split("@", 1)[0][:70] or "rt-user"
    candidate, suffix = base_username, 1
    while core_app.User.query.filter_by(username=candidate).first():
        suffix += 1
        candidate = f"{base_username[:65]}-{suffix}"
    user = core_app.User(
        username=candidate, name=(_clean(name, 120) or email[:120]), email=email,
        password_hash=core_app.generate_password_hash(core_app.uuid.uuid4().hex),
        role="requester", tenant_id=tenant_id,
    )
    db.session.add(user)
    db.session.flush()
    summary["users_created"] += 1
    return user


def _placeholder_requester(tenant_id, summary):
    """RT tickets whose Requestor has no resolvable email (a deleted RT
    user, a queue's auto-generated requestor, etc.) need *some* requester
    since ServiceOps requires one -- but silently crediting the admin
    account that happens to be running the import would misrepresent who
    actually filed the ticket, and would look identical for every such
    ticket regardless of who's running the import. A single, clearly-named
    placeholder account (reused across every ticket and every import run,
    same as an unmatched RT queue reuses one SupportGroup) makes the gap
    visible and searchable instead."""
    # Emails are unique installation-wide, so each tenant needs its own
    # placeholder address (tenant 1 keeps the original one).
    address = ("unresolved-rt-requester@rt-import.invalid" if tenant_id == 1
               else f"unresolved-rt-requester+t{tenant_id}@rt-import.invalid")
    return _resolve_or_create_user(address, "RT Import (unresolved requester)", tenant_id, summary)


def _resolve_or_create_group(queue_name, tenant_id, summary):
    import app as core_app
    from app import db

    queue_name = _clean(queue_name, 120) or "RT Import"
    group = core_app.resolve_support_group_by_name(queue_name, tenant_id)
    if group:
        return group
    group = core_app.SupportGroup(name=queue_name, group_type="IT Fulfillment", tenant_id=tenant_id)
    db.session.add(group)
    db.session.flush()
    summary["teams_created"] += 1
    return group


def _decode_attachment_bytes(raw, encoding=None):
    """RT reports how Content is encoded via the attachment's
    ContentEncoding field -- "base64" for binary parts, "quoted-printable"
    for some mail-originated text parts, "none" (or absent) for plain text
    -- rather than always being base64 regardless of version. Trusting
    that field instead of guessing avoids corrupting the small share of
    attachments that aren't base64, while still falling back to a base64
    attempt (the common case) when no encoding is reported."""
    if not raw:
        return b""
    encoding = (encoding or "").strip().lower()
    if encoding == "quoted-printable":
        import quopri
        return quopri.decodestring(raw.encode("utf-8", errors="replace"))
    if encoding == "none":
        return raw.encode("utf-8", errors="replace")
    try:
        # validate=True rejects the input outright if it contains ANY
        # character outside the base64 alphabet -- including the line-wrap
        # newlines RT/Perl's MIME::Base64 inserts every 76 characters,
        # which is exactly how RT returns Content. That was silently
        # falling through to "treat as raw text" below, i.e. saving the
        # base64 *text* itself as the file's bytes -- which of course
        # never matches any real file's magic-byte signature, no matter
        # the type. validate=False strips non-alphabet characters
        # (whitespace/newlines) before decoding instead of rejecting them.
        return base64.b64decode(raw, validate=False)
    except Exception:  # noqa: BLE001 - not valid base64, treat as already raw text
        return raw.encode("utf-8", errors="replace")


def _decode_attachment_content(raw, encoding=None):
    return _decode_attachment_bytes(raw, encoding).decode("utf-8", errors="replace")


def _save_imported_attachment(filename, content_bytes, uploaded_by_id, ticket, enterprise_record, summary):
    """Saves real RT attachment content as a FileAttachment, going through
    the same magic-byte/extension allowlist and malware scan real uploads
    get (save_ticket_attachment in app.py) -- RT's import path must not be
    a way to smuggle a disallowed or infected file past those controls just
    because it arrived via API instead of a browser upload."""
    import app as core_app
    from app import db
    from flask import current_app

    original = (core_app.secure_filename(_clean(filename) or "") or "")[:200]
    if not original:
        _note(summary, "errors", f"Attachment '{filename}': invalid filename, not imported.")
        return None
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    allowed = core_app.ATTACHMENT_ALLOWED_TYPES.get(ext)
    if not allowed:
        _note(summary, "errors", f"Attachment '{original}': file type not allowed, not imported.")
        return None
    signature, mime_type = allowed
    if signature and not content_bytes.startswith(signature):
        _note(summary, "errors", f"Attachment '{original}': content doesn't match its extension, not imported.")
        return None
    stored = f"{uuid.uuid4().hex}-{original}"
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], stored)
    with open(path, "wb") as handle:
        handle.write(content_bytes)
    # Remembered so a ticket that later fails (and is rolled back) does not
    # leave orphaned files behind in the upload folder.
    summary.setdefault("_written", []).append(path)
    scan_status = core_app.scan_attachment(path)
    if scan_status == "infected":
        os.remove(path)
        _note(summary, "errors", f"Attachment '{original}': rejected by malware scan, not imported.")
        return None
    attachment = core_app.FileAttachment(
        ticket_id=(ticket.id if ticket else None),
        enterprise_record_id=(enterprise_record.id if enterprise_record else None),
        uploaded_by_id=uploaded_by_id, original_name=original, stored_name=stored,
        mime_type=mime_type, size_bytes=len(content_bytes), sha256=hashlib.sha256(content_bytes).hexdigest(),
        scan_status=scan_status,
        tenant_id=(ticket.tenant_id if ticket else enterprise_record.tenant_id),
    )
    db.session.add(attachment)
    summary["attachments_imported"] += 1
    return attachment


def _transaction_body(session, base_url, transaction_id, transaction, actor_user_id, ticket, enterprise_record, summary):
    """A transaction's message body isn't always inlined on the transaction
    object itself (RT's Create transaction tends to include it, Correspond
    often doesn't) -- when missing, fetch it from the transaction's
    attachments instead, the same way RT's own web UI resolves it. Any real
    file attachment (not just the message body) found along the way is
    imported as a FileAttachment against `ticket` or `enterprise_record`
    (whichever this RT ticket routed to). Returns (body_text, [notes]) --
    notes covers both attachments that were imported (so the log still
    mentions them even when there's no text body) and ones that couldn't be
    (disallowed type, failed scan, etc.), so nothing about the transaction
    silently vanishes.

    IMPORTANT: the attachment listing is fetched unconditionally, even when
    `transaction.get("Content")` is already populated -- RT's Create and
    Correspond transactions routinely have BOTH an inline text body AND one
    or more real file attachments (e.g. a reply with a screenshot). Early-
    returning on inline content (the original bug here) meant every
    attachment on any transaction with a text body was silently skipped --
    which in practice is most of them, since Content is usually present."""
    content = (transaction.get("Content") or "").strip()
    try:
        listing = _get(
            session, base_url, f"/REST/2.0/transaction/{transaction_id}/attachments",
            params={"per_page": 20},
        )
    except requests.RequestException:
        return content, []
    body = content
    imported_filenames = []
    skipped_filenames = []
    items = listing.get("items") if isinstance(listing.get("items"), list) else []
    attachment_ids = [item.get("id") for item in items if isinstance(item, dict) and item.get("id")]
    # RT's attachment endpoint omits the (potentially large) Content field
    # by default, unless explicitly asked for -- without `fields=Content`,
    # every real file downloads as an empty body and fails its magic-byte
    # check regardless of type, which is what made every attachment (not
    # just disallowed ones) show up as "content doesn't match its
    # extension" against a real RT instance.
    metas = _fetch_many(
        session, base_url, "/REST/2.0/attachment/{}", attachment_ids,
        params={"fields": "Content,ContentType,ContentEncoding,Filename"},
    )
    for attachment_id in attachment_ids:
        meta = metas.get(attachment_id)
        if not meta:
            continue
        content_type = (meta.get("ContentType") or "").lower()
        filename = meta.get("Filename")
        encoding = meta.get("ContentEncoding")
        if content_type.startswith("text/") and not filename:
            if not body:
                text = _decode_attachment_content(meta.get("Content"), encoding).strip()
                if content_type.startswith("text/html"):
                    text = _HTML_TAG_RE.sub("", text)
                body = text
            continue
        if not filename:
            continue
        content_bytes = _decode_attachment_bytes(meta.get("Content"), encoding)
        if len(content_bytes) > _MAX_ATTACHMENT_BYTES:
            _note(summary, "errors", f"Attachment '{_clean(filename)}': larger than "
                  f"{_MAX_ATTACHMENT_BYTES // (1024 * 1024)} MB, not imported.")
            skipped_filenames.append(filename)
            continue
        saved = _save_imported_attachment(filename, content_bytes, actor_user_id, ticket, enterprise_record, summary)
        if saved:
            imported_filenames.append(filename)
        else:
            skipped_filenames.append(filename)
    notes = []
    if imported_filenames:
        notes.append(f"[Attachment(s): {', '.join(_clean(n) for n in imported_filenames)}]")
    if skipped_filenames:
        notes.append(f"[Attachment(s) not imported: {', '.join(_clean(n) or '?' for n in skipped_filenames)}]")
    return _clean(body), notes


def _ticket_history(session, base_url, rt_id):
    """Every page of a ticket's history (RT returns at most per_page items per
    page), up to _MAX_HISTORY_TRANSACTIONS, as one {"items": [...]} payload."""
    items, page = [], 1
    while len(items) < _MAX_HISTORY_TRANSACTIONS:
        payload = _get(session, base_url, f"/REST/2.0/ticket/{rt_id}/history", params={"per_page": 200, "page": page})
        batch = payload.get("items") if isinstance(payload.get("items"), list) else []
        items.extend(batch)
        try:
            pages = int(payload.get("pages") or 1)
        except (TypeError, ValueError):
            pages = page
        if not batch or page >= pages:
            break
        page += 1
    return {"items": items[:_MAX_HISTORY_TRANSACTIONS]}


def _correspondence_log(session, base_url, rt_id, tenant_id, actor_user_id, cache, ticket, enterprise_record,
                        summary, history=None):
    """Fetches RT's full transaction history and formats every
    Create/Correspond/Comment message (falling back to attachment content
    when a transaction doesn't inline its own body) plus every status
    change into a chronological plain-text log, for folding into the
    imported record's description -- EnterpriseRecord has no comment-thread
    model the way Ticket does, so there's nowhere else to put this. Real
    file attachments found along the way are imported as FileAttachment
    rows against `ticket` or `enterprise_record` (whichever this RT ticket
    routed to). Transactions are fetched concurrently, and creator lookups
    go through `cache` (the same one used for Queue/Owner) since a handful
    of people usually account for all the back-and-forth on a ticket --
    without the cache, a 20-message thread between the same two people did
    20 redundant user lookups instead of 2.

    `history` lets a caller pass an already-fetched history payload (see
    _import_one_ticket, which fetches it concurrently with the ticket
    detail) so it isn't fetched twice."""
    if history is None:
        try:
            history = _ticket_history(session, base_url, rt_id)
        except requests.RequestException as error:
            _note(summary, "errors", f"RT #{rt_id}: could not fetch history: {type(error).__name__}")
            return ""
    items = history.get("items") if isinstance(history.get("items"), list) else []
    transaction_ids = [item.get("id") for item in items if isinstance(item, dict) and item.get("id")]
    transactions_by_id = _fetch_many(session, base_url, "/REST/2.0/transaction/{}", transaction_ids)
    entries = []
    for transaction_id in transaction_ids:
        _heartbeat()
        transaction = transactions_by_id.get(transaction_id)
        if not transaction:
            continue
        txn_type = transaction.get("Type")
        created = transaction.get("Created") or ""
        creator_contact = cache.user_contact(transaction.get("Creator"))
        creator_label = (
            (creator_contact.get("name") or creator_contact.get("email"))
            if creator_contact else None
        ) or "Unknown"

        if txn_type in COMMENT_TRANSACTION_TYPES:
            body, notes = _transaction_body(
                session, base_url, transaction_id, transaction, actor_user_id, ticket, enterprise_record, summary,
            )
            if not body and not notes:
                continue
            lines = [f"--- {created} · {creator_label} ({txn_type}) ---"]
            if body:
                lines.append(body)
            lines.extend(notes)
            entries.append("\n".join(lines))
            summary["comments_imported"] += 1
        elif txn_type == "Status":
            old_value = transaction.get("OldValue") or "?"
            new_value = transaction.get("NewValue") or "?"
            entries.append(
                f"--- {created} · {creator_label} ---\nStatus changed from '{old_value}' to '{new_value}'"
            )
    return "\n\n".join(entries)


def _already_imported(rt_id, tenant_id):
    """Checks both possible target tables -- a ticket's routing (event vs.
    change) depends on its Subject, which isn't known until after fetching
    it, so the already-imported check has to cover wherever it might have
    landed."""
    import app as core_app

    if core_app.EnterpriseRecord.query.filter_by(
        tenant_id=tenant_id, external_source="rt", external_id=rt_id,
    ).first():
        return True
    if core_app.Ticket.query.filter_by(
        tenant_id=tenant_id, external_source="rt", external_id=rt_id,
    ).first():
        return True
    return False


def _custom_fields(detail):
    """RT's REST2.0 ticket endpoint omits CustomFields unless explicitly
    requested (fields=CustomFields, same "sparse fieldset" behavior as
    attachment Content elsewhere in this module) -- returns a flat
    {name: "value" or "value1, value2"} dict, skipping fields with no value
    set so an unfilled custom field on the RT side doesn't show up as an
    empty row after import."""
    result = {}
    fields = detail.get("CustomFields")
    for field in (fields if isinstance(fields, list) else []):
        if not isinstance(field, dict):
            continue
        name = _clean(field.get("name"))
        raw = field.get("values")
        values = [_clean(v) for v in (raw if isinstance(raw, list) else [raw]) if v]
        if name and values:
            result[name] = ", ".join(values)
    return result


def _format_custom_fields_block(custom_fields):
    if not custom_fields:
        return ""
    lines = "\n".join(f"- {name}: {value}" for name, value in custom_fields.items())
    return f"RT custom fields:\n{lines}"


def _set_created_at(row, detail):
    import app as core_app

    created = detail.get("Created")
    if isinstance(created, str) and created:
        try:
            parsed = core_app.parse_form_datetime(created.replace("T", " ").rstrip("Z"))
        except Exception:  # noqa: BLE001 - an odd date keeps the import time instead
            parsed = None
        if parsed:
            row.created_at = parsed


def _create_event_record(rt_id, tenant_id, title, description, detail, requester, assignee, group, summary):
    import app as core_app
    from app import db

    custom_fields = _custom_fields(detail)
    record = core_app.EnterpriseRecord(
        number=core_app.next_enterprise_number("event"),
        domain="event", record_type="RT Ticket",
        title=title, description=description[:60000],
        state=_map_status(detail.get("Status"), RT_STATUS_MAP_EVENT, summary),
        priority=_map_priority(detail.get("Priority")),
        risk="Medium", requester_id=requester.id,
        assignee_id=(assignee.id if assignee else None),
        support_group_id=group.id,
        metadata_json=json.dumps({"rt_custom_fields": custom_fields}, sort_keys=True) if custom_fields else "{}",
        tenant_id=tenant_id, external_source="rt", external_id=rt_id,
    )
    _set_created_at(record, detail)
    db.session.add(record)
    db.session.flush()
    return record


def _create_change_ticket(rt_id, tenant_id, title, description, detail, requester, assignee, group, summary):
    """Historical changes are inserted directly (Ticket + ChangeGovernance +
    ChangeOwnership) rather than through ticket_new()'s live approval-chain
    creation -- these already happened, so generating fresh CCB/approval
    tasks and notifying today's approvers about years-old work would be
    wrong. The record reflects RT's own status/history, not a re-run of
    ServiceOps' governance workflow."""
    import app as core_app
    from app import db

    def build():
        ticket = core_app.Ticket(
            number=core_app.sequence_number(core_app.Ticket, "CHG"),
            kind="change", title=title, description=description[:20000],
            state=_map_status(detail.get("Status"), RT_STATUS_MAP_CHANGE, summary),
            priority=_map_priority(detail.get("Priority")),
            category="General", requester_id=requester.id,
            assignee_id=(assignee.id if assignee else None),
            tenant_id=tenant_id, external_source="rt", external_id=rt_id,
        )
        _set_created_at(ticket, detail)
        db.session.add(ticket)
        return ticket
    ticket = core_app.create_with_retry_on_number_collision(build)
    db.session.add(core_app.ChangeGovernance(
        ticket_id=ticket.id, change_type="Normal", ccb_required=False,
        tenant_id=tenant_id,
    ))
    db.session.add(core_app.ChangeOwnership(ticket_id=ticket.id, group_id=group.id))
    return ticket


def _import_one_ticket(session, base_url, rt_id, tenant_id, actor_user_id, cache, summary, dry_run):
    if _already_imported(rt_id, tenant_id):
        summary["already_imported"] += 1
        return

    # Detail and history are independent reads -- fetching them together
    # instead of one after the other shaves a full round trip off every
    # ticket, which adds up fast against a slow RT instance. History is
    # only needed when actually importing (dry runs skip correspondence
    # entirely to keep the preview fast), so it's only requested then.
    # CustomFields is omitted from RT's default ticket representation unless
    # explicitly requested, the same "sparse fieldset" behavior that made
    # attachment Content silently vanish earlier -- fields=CustomFields adds
    # it without dropping any of the normally-included fields.
    detail_params = {"fields": "CustomFields"}
    history = None
    if dry_run:
        detail = _get(session, base_url, f"/REST/2.0/ticket/{rt_id}", params=detail_params)
    else:
        with ThreadPoolExecutor(max_workers=2) as pool:
            detail_future = pool.submit(_get, session, base_url, f"/REST/2.0/ticket/{rt_id}", params=detail_params)
            history_future = pool.submit(_ticket_history, session, base_url, rt_id)
            detail = detail_future.result()
            try:
                history = history_future.result()
            except requests.RequestException as error:
                _note(summary, "errors", f"RT #{rt_id}: could not fetch history: {type(error).__name__}")
                history = {"items": []}

    queue_name = cache.queue_name(detail.get("Queue")) or "RT Import"
    group = _resolve_or_create_group(queue_name, tenant_id, summary)

    requestor_emails = []
    requestors = detail.get("Requestor")
    for ref in (requestors if isinstance(requestors, list) else [requestors] if requestors else []):
        contact = cache.user_contact(ref)
        if contact and contact.get("email"):
            requestor_emails.append((contact["email"], contact.get("name")))
    requester = None
    if requestor_emails:
        requester = _resolve_or_create_user(*requestor_emails[0], tenant_id, summary)
    if not requester:
        requester = _placeholder_requester(tenant_id, summary)

    assignee = None
    owner_contact = cache.user_contact(detail.get("Owner"))
    if owner_contact and owner_contact.get("email"):
        assignee = _resolve_or_create_user(owner_contact["email"], owner_contact.get("name"), tenant_id, summary)

    title = (_clean(detail.get("Subject")) or f"RT ticket #{rt_id}").strip()[:180] or f"RT ticket #{rt_id}"
    is_change = _is_change_request(detail.get("Subject"))
    if is_change:
        row = _create_change_ticket(rt_id, tenant_id, title, title, detail, requester, assignee, group, summary)
        summary["changes_created"] += 1
    else:
        row = _create_event_record(rt_id, tenant_id, title, title, detail, requester, assignee, group, summary)
        summary["events_created"] += 1
    summary["records_created"] += 1

    if not dry_run:
        # The row needs an id (for FileAttachment rows) before real
        # attachments found in its history can be imported, so the
        # correspondence log -- which imports them as a side effect -- runs
        # after creation and updates the description in place.
        log = _correspondence_log(
            session, base_url, rt_id, tenant_id, actor_user_id, cache,
            ticket=(row if is_change else None),
            enterprise_record=(None if is_change else row),
            summary=summary, history=history,
        )
        if is_change:
            # Ticket has no JSON metadata column the way EnterpriseRecord
            # does, so custom fields go into the description text instead --
            # and unlike event records, they need to show up even when there's
            # no correspondence log at all.
            parts = [title, _format_custom_fields_block(_custom_fields(detail)), log]
            row.description = "\n\n".join(part for part in parts if part)[:20000]
        elif log:
            row.description = f"{title}\n\n{log}"[:60000]
    _note(summary, "preview", {
        "rt_id": rt_id, "type": "Change" if is_change else "IT operations event",
        "number": row.number, "title": title,
        "queue": queue_name, "state": row.state, "priority": row.priority,
        "requester": requester.email if requester else None,
    })


def import_from_rt(tenant_id, actor_user_id, dry_run=False, query="id > 0",
                   limit=None, session_factory=_rt_session, deadline=None, tick=None):
    """Imports RT tickets matching `query` (RT TicketSQL, default "id > 0"
    = everything) into ServiceOps for `tenant_id` as "IT operations events"
    (EnterpriseRecord, domain="event"), attributing system actions (the
    comment-authorship fallback) to `actor_user_id` (the admin running the
    import). `limit` caps how many NEW records are processed in one call,
    for testing a mapping against a small batch before running the full
    import.

    Fails closed on missing tenant/configuration. dry_run performs the same
    matching/creation logic (so the preview reflects exactly what would
    happen, including which teams/users would be auto-created) but rolls
    back instead of committing.

    Crash safety: each ticket runs in its own savepoint, so one ticket's
    database error cannot poison the tickets after it. A real import commits
    after every ticket, so a worker that is stopped keeps everything done so
    far (re-running skips it). `deadline` (a time.monotonic() value) ends the
    run early with summary["finished"] = False so the caller can resume it
    later, and `tick` is called regularly so a long run can keep the worker's
    liveness heartbeat fresh. A dry run looks at no more than
    _DRY_RUN_SAMPLE new tickets."""
    import time
    import app as core_app
    from app import db

    if not tenant_id or not isinstance(tenant_id, int):
        raise RTImportError(tr("A valid integer tenant_id is required; refusing to import."))
    tenant = db.session.get(core_app.Tenant, tenant_id)
    if not tenant or not tenant.active:
        raise RTImportError(tr("Tenant {tenant_id} does not exist or is inactive; refusing to import.", tenant_id=tenant_id))
    if not core_app.setting_bool("RT_ENABLED"):
        raise RTImportError(tr("RT import is not enabled; refusing to import."))

    base_url = core_app.setting_value("RT_BASE_URL", "")
    token = core_app.setting_value("RT_API_TOKEN", "")
    if not base_url or not token:
        raise RTImportError(tr("RT base URL and API token must both be configured."))
    if not core_app.integration_endpoint_valid(base_url, allow_private_network=True):
        raise RTImportError(tr("RT base URL failed safety validation (must be an https host)."))
    if not core_app.integration_endpoint_resolves_safely(base_url, allow_private_network=True):
        raise RTImportError(tr("RT base URL failed DNS safety validation."))

    summary = {
        "tenant_id": tenant_id, "dry_run": bool(dry_run),
        "tickets_seen": 0, "records_created": 0, "events_created": 0, "changes_created": 0,
        "already_imported": 0, "teams_created": 0, "users_created": 0, "comments_imported": 0,
        "attachments_imported": 0, "errors": [], "preview": [], "finished": True,
    }
    if dry_run:
        limit = min(limit, _DRY_RUN_SAMPLE) if limit else _DRY_RUN_SAMPLE

    def heartbeat():
        if tick:
            try:
                tick()
            except Exception:  # noqa: BLE001 - a heartbeat problem must not stop the import
                pass

    global _tick
    _tick = heartbeat
    # PostgreSQL: each ticket in its own savepoint. SQLite's Python driver
    # turns a released savepoint into a real commit, which would make a dry
    # run persist; there a failing ticket rolls back the (uncommitted) run.
    savepoints = db.engine.dialect.name != "sqlite"
    session = session_factory(base_url, token)
    cache = _RecordCache(session, base_url)
    try:
        for rt_id in _paginate_ticket_ids(session, base_url, query):
            heartbeat()
            if limit is not None and summary["records_created"] >= limit:
                break
            if deadline is not None and time.monotonic() >= deadline:
                summary["finished"] = False  # resumed on the worker's next pass
                break
            summary["tickets_seen"] += 1
            summary["_written"] = []
            try:
                if savepoints:
                    with db.session.begin_nested():
                        _import_one_ticket(session, base_url, rt_id, tenant_id, actor_user_id, cache, summary, dry_run)
                else:
                    _import_one_ticket(session, base_url, rt_id, tenant_id, actor_user_id, cache, summary, dry_run)
                if not dry_run:
                    db.session.commit()
            except Exception as error:  # noqa: BLE001 - isolate one bad ticket from the whole batch
                if not dry_run or not savepoints:
                    db.session.rollback()
                for path in summary.get("_written", []):
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                _note(summary, "errors", f"RT #{rt_id}: {type(error).__name__}: {str(error)[:300]}")
    except requests.RequestException as error:
        _note(summary, "errors", f"RT request failed: {type(error).__name__}: {error}")
    finally:
        _tick = None
        session.close()
        ca_bundle_path = getattr(session, "verify", None)
        if isinstance(ca_bundle_path, str) and ca_bundle_path.startswith(tempfile.gettempdir()):
            try:
                os.unlink(ca_bundle_path)
            except OSError:
                pass

    summary.pop("_written", None)
    if dry_run:
        db.session.rollback()
    else:
        db.session.commit()

    return summary


# ---- Small views of stored job results -------------------------------------------------------
# Results saved by imports before 1.114.15 were not capped and can be tens of megabytes. The import
# page must never load or parse those in full (it did, about ten times per job, and the web worker
# was OOM-killed), so it reads a bounded summary instead.
RESULT_VIEW_ITEMS = 100
RESULT_FULL_PARSE_BYTES = 2 * 1024 * 1024
_COUNT_KEYS = ("tickets_seen", "records_created", "events_created", "changes_created", "already_imported",
               "teams_created", "users_created", "comments_imported", "attachments_imported")


def summarize_result(result):
    """Counts plus the first RESULT_VIEW_ITEMS errors and preview rows, with the totals."""
    if not isinstance(result, dict):
        return None
    view = {key: result.get(key, 0) for key in _COUNT_KEYS}
    for key in ("errors", "preview"):
        items = result.get(key) if isinstance(result.get(key), list) else []
        items = [item for item in items if not (isinstance(item, dict) and item.get("omitted"))
                 and not (isinstance(item, str) and item.startswith("... further entries omitted"))]
        view[key] = items[:RESULT_VIEW_ITEMS]
        view[key + "_total"] = len(items)
    view["dry_run"] = bool(result.get("dry_run"))
    return view


def summarize_result_head(head):
    """Counts read from the start of an oversized stored result (they are written before the lists)."""
    view = {key: 0 for key in _COUNT_KEYS}
    for key in _COUNT_KEYS:
        found = re.search(rf'"{key}"\s*:\s*(\d+)', head or "")
        if found:
            view[key] = int(found.group(1))
    view.update(errors=[], preview=[], errors_total=None, preview_total=None, truncated=True)
    return view


def job_summaries(job_ids):
    """{job id: bounded summary} for the import page, without loading large results in full."""
    import app as core_app
    from app import db

    job = core_app.RTImportJob
    summaries = {}
    if not job_ids:
        return summaries
    sizes = db.session.query(job.id, db.func.length(job.result_json)).filter(job.id.in_(job_ids)).all()
    for job_id, size in sizes:
        if not size:
            continue
        if size <= RESULT_FULL_PARSE_BYTES:
            text = db.session.query(job.result_json).filter(job.id == job_id).scalar()
            try:
                summaries[job_id] = summarize_result(json.loads(text))
            except ValueError:
                summaries[job_id] = summarize_result_head(text[:4000])
        else:
            head = db.session.query(db.func.substr(job.result_json, 1, 4000)).filter(job.id == job_id).scalar()
            summaries[job_id] = summarize_result_head(head)
    return summaries
