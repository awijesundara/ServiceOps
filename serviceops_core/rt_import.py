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
either.

IMPORTANT: RT REST2.0's exact JSON shape (custom field names, whether a
Queue/Owner reference is inlined or requires a follow-up request) can vary
by RT version and by admin customization. This module fetches full,
unambiguous ticket/queue/user records via GET rather than relying on
guessed field-expansion query syntax, but the very first dry run against a
real instance should still be inspected -- the per-ticket preview rows are
built specifically so a human can eyeball a handful before ever committing.
"""
import base64
import os
import re
import tempfile

import requests

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
        summary["errors"].append(
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
    session.headers.update({
        "Authorization": f"token {token}",
        "Accept": "application/json",
    })
    ca_cert = core_app.setting_value("RT_CA_CERT", "").strip()
    if ca_cert:
        session.verify = _write_ca_bundle(ca_cert)
    elif core_app.setting_bool("RT_TLS_INSECURE"):
        session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


def _get(session, base_url, path, params=None):
    url = base_url.rstrip("/") + path
    response = session.get(url, params=params, timeout=15)
    response.raise_for_status()
    return response.json()


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
        items = payload.get("items", [])
        for item in items:
            ticket_id = item.get("id") or item.get("Id")
            if ticket_id:
                yield str(ticket_id)
        if page >= (payload.get("pages") or 1) or not items:
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
                self._queues[queue_id] = record.get("Name") or f"RT Queue {queue_id}"
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
                    "email": record.get("EmailAddress") or "",
                    "name": record.get("RealName") or record.get("Name") or "",
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

    email = (email or "").strip().lower()
    if not email:
        return None
    user = core_app.tenant_query(core_app.User).filter(
        db.func.lower(core_app.User.email) == email
    ).first()
    if user:
        return user
    base_username = email.split("@", 1)[0][:70] or "rt-user"
    candidate, suffix = base_username, 1
    while core_app.User.query.filter_by(username=candidate).first():
        suffix += 1
        candidate = f"{base_username[:65]}-{suffix}"
    user = core_app.User(
        username=candidate, name=name or email, email=email,
        password_hash=core_app.generate_password_hash(core_app.uuid.uuid4().hex),
        role="requester", tenant_id=tenant_id,
    )
    db.session.add(user)
    db.session.flush()
    summary["users_created"] += 1
    return user


def _resolve_or_create_group(queue_name, tenant_id, summary):
    import app as core_app
    from app import db

    group = core_app.resolve_support_group_by_name(queue_name, tenant_id)
    if group:
        return group
    group = core_app.SupportGroup(name=queue_name, group_type="IT Fulfillment", tenant_id=tenant_id)
    db.session.add(group)
    db.session.flush()
    summary["teams_created"] += 1
    return group


def _decode_attachment_content(raw):
    """RT's attachment Content is base64-encoded for binary parts but is
    sometimes sent as plain text for text/plain parts depending on version
    -- try base64 first (the documented behavior) and fall back to using
    the raw string as-is if it doesn't decode cleanly."""
    if not raw:
        return ""
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - not valid base64, treat as already plain text
        return raw


def _transaction_body(session, base_url, transaction_id, transaction):
    """A transaction's message body isn't always inlined on the transaction
    object itself (RT's Create transaction tends to include it, Correspond
    often doesn't) -- when missing, fetch it from the transaction's
    attachments instead, the same way RT's own web UI resolves it. Returns
    (body_text, [filenames]) -- filenames covers real file attachments
    (e.g. a spreadsheet) that have no text body of their own, so their
    existence is at least noted even though the file itself isn't imported."""
    content = (transaction.get("Content") or "").strip()
    if content:
        return content, []
    try:
        listing = _get(
            session, base_url, f"/REST/2.0/transaction/{transaction_id}/attachments",
            params={"per_page": 20},
        )
    except requests.RequestException:
        return "", []
    body = ""
    filenames = []
    for item in listing.get("items", []):
        attachment_id = item.get("id")
        try:
            meta = _get(session, base_url, f"/REST/2.0/attachment/{attachment_id}")
        except requests.RequestException:
            continue
        content_type = (meta.get("ContentType") or "").lower()
        filename = meta.get("Filename")
        if filename:
            filenames.append(filename)
        if not body and content_type.startswith("text/"):
            text = _decode_attachment_content(meta.get("Content")).strip()
            if content_type.startswith("text/html"):
                text = _HTML_TAG_RE.sub("", text)
            body = text
    return body, filenames


def _correspondence_log(session, base_url, rt_id, tenant_id, summary):
    """Fetches RT's full transaction history and formats every
    Create/Correspond/Comment message (falling back to attachment content
    when a transaction doesn't inline its own body) plus every status
    change into a chronological plain-text log, for folding into the
    imported record's description -- EnterpriseRecord has no comment-thread
    model the way Ticket does, so there's nowhere else to put this."""
    try:
        history = _get(session, base_url, f"/REST/2.0/ticket/{rt_id}/history", params={"per_page": 200})
    except requests.RequestException as error:
        summary["errors"].append(f"RT #{rt_id}: could not fetch history: {type(error).__name__}")
        return ""
    entries = []
    for item in history.get("items", []):
        transaction_id = item.get("id")
        try:
            transaction = _get(session, base_url, f"/REST/2.0/transaction/{transaction_id}")
        except requests.RequestException:
            continue
        txn_type = transaction.get("Type")
        created = transaction.get("Created") or ""
        creator = transaction.get("Creator")
        creator_label = "Unknown"
        if isinstance(creator, dict):
            creator_id = _ref_id(creator)
            if creator_id:
                try:
                    contact = _get(session, base_url, f"/REST/2.0/user/{creator_id}")
                    creator_label = contact.get("RealName") or contact.get("EmailAddress") or "Unknown"
                except requests.RequestException:
                    pass

        if txn_type in COMMENT_TRANSACTION_TYPES:
            body, filenames = _transaction_body(session, base_url, transaction_id, transaction)
            if not body and not filenames:
                continue
            lines = [f"--- {created} · {creator_label} ({txn_type}) ---"]
            if body:
                lines.append(body)
            if filenames:
                lines.append(f"[Attachment(s) not imported: {', '.join(filenames)}]")
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


def _set_created_at(row, detail):
    import app as core_app

    created = detail.get("Created")
    if created:
        parsed = core_app.parse_form_datetime(created.replace("T", " ").rstrip("Z"))
        if parsed:
            row.created_at = parsed


def _create_event_record(rt_id, tenant_id, title, description, detail, requester, assignee, group, summary):
    import app as core_app
    from app import db

    record = core_app.EnterpriseRecord(
        number=core_app.next_enterprise_number("event"),
        domain="event", record_type="RT Ticket",
        title=title, description=description[:60000],
        state=_map_status(detail.get("Status"), RT_STATUS_MAP_EVENT, summary),
        priority=_map_priority(detail.get("Priority")),
        risk="Medium", requester_id=requester.id,
        assignee_id=(assignee.id if assignee else None),
        support_group_id=group.id,
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
    db.session.flush()
    db.session.add(core_app.ChangeGovernance(
        ticket_id=ticket.id, change_type="Normal", ccb_required=False,
        tenant_id=tenant_id,
    ))
    db.session.add(core_app.ChangeOwnership(ticket_id=ticket.id, group_id=group.id))
    return ticket


def _import_one_ticket(session, base_url, rt_id, tenant_id, actor_user_id, cache, summary, dry_run):
    import app as core_app
    from app import db

    if _already_imported(rt_id, tenant_id):
        summary["already_imported"] += 1
        return

    detail = _get(session, base_url, f"/REST/2.0/ticket/{rt_id}")
    queue_name = cache.queue_name(detail.get("Queue")) or "RT Import"
    group = _resolve_or_create_group(queue_name, tenant_id, summary)

    requestor_emails = []
    for ref in (detail.get("Requestor") or []):
        contact = cache.user_contact(ref)
        if contact and contact.get("email"):
            requestor_emails.append((contact["email"], contact.get("name")))
    requester = None
    if requestor_emails:
        requester = _resolve_or_create_user(*requestor_emails[0], tenant_id, summary)
    if not requester:
        requester = db.session.get(core_app.User, actor_user_id)

    assignee = None
    owner_contact = cache.user_contact(detail.get("Owner"))
    if owner_contact and owner_contact.get("email"):
        assignee = _resolve_or_create_user(owner_contact["email"], owner_contact.get("name"), tenant_id, summary)

    title = (detail.get("Subject") or f"RT ticket #{rt_id}").strip()[:180]
    description = title
    if not dry_run:
        log = _correspondence_log(session, base_url, rt_id, tenant_id, summary)
        if log:
            description = f"{title}\n\n{log}"

    is_change = _is_change_request(detail.get("Subject"))
    if is_change:
        row = _create_change_ticket(rt_id, tenant_id, title, description, detail, requester, assignee, group, summary)
        summary["changes_created"] += 1
    else:
        row = _create_event_record(rt_id, tenant_id, title, description, detail, requester, assignee, group, summary)
        summary["events_created"] += 1
    summary["records_created"] += 1
    summary["preview"].append({
        "rt_id": rt_id, "type": "Change" if is_change else "IT operations event",
        "number": row.number, "title": title,
        "queue": queue_name, "state": row.state, "priority": row.priority,
        "requester": requester.email if requester else None,
    })


def import_from_rt(tenant_id, actor_user_id, dry_run=False, query="id > 0",
                   limit=None, session_factory=_rt_session):
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
    back instead of committing."""
    import app as core_app
    from app import db

    if not tenant_id or not isinstance(tenant_id, int):
        raise RTImportError("A valid integer tenant_id is required; refusing to import.")
    tenant = db.session.get(core_app.Tenant, tenant_id)
    if not tenant or not tenant.active:
        raise RTImportError(f"Tenant {tenant_id} does not exist or is inactive; refusing to import.")
    if not core_app.setting_bool("RT_ENABLED"):
        raise RTImportError("RT import is not enabled; refusing to import.")

    base_url = core_app.setting_value("RT_BASE_URL", "")
    token = core_app.setting_value("RT_API_TOKEN", "")
    if not base_url or not token:
        raise RTImportError("RT base URL and API token must both be configured.")
    if not core_app.integration_endpoint_valid(base_url, allow_private_network=True):
        raise RTImportError("RT base URL failed safety validation (must be an https host).")
    if not core_app.integration_endpoint_resolves_safely(base_url, allow_private_network=True):
        raise RTImportError("RT base URL failed DNS safety validation.")

    summary = {
        "tenant_id": tenant_id, "dry_run": bool(dry_run),
        "tickets_seen": 0, "records_created": 0, "events_created": 0, "changes_created": 0,
        "already_imported": 0, "teams_created": 0, "users_created": 0, "comments_imported": 0,
        "errors": [], "preview": [],
    }

    session = session_factory(base_url, token)
    cache = _RecordCache(session, base_url)
    try:
        for rt_id in _paginate_ticket_ids(session, base_url, query):
            if limit is not None and summary["records_created"] >= limit:
                break
            summary["tickets_seen"] += 1
            try:
                _import_one_ticket(session, base_url, rt_id, tenant_id, actor_user_id, cache, summary, dry_run)
            except Exception as error:  # noqa: BLE001 - isolate one bad ticket from the whole batch
                summary["errors"].append(f"RT #{rt_id}: {type(error).__name__}: {error}")
    except requests.RequestException as error:
        summary["errors"].append(f"RT request failed: {type(error).__name__}: {error}")
    finally:
        session.close()
        ca_bundle_path = getattr(session, "verify", None)
        if isinstance(ca_bundle_path, str) and ca_bundle_path.startswith(tempfile.gettempdir()):
            try:
                os.unlink(ca_bundle_path)
            except OSError:
                pass

    if dry_run:
        db.session.rollback()
    else:
        db.session.commit()

    return summary
