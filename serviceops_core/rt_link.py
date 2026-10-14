"""Reference one Request Tracker (RT) ticket from a change (CHG).

Optional, off by default (RT_CHANGE_LINK_ENABLED, on the RT page). The
change form fetches an RT ticket's summary to prefill the change; saving
links the change to it through Ticket.external_source="rt" /
external_id=<RT id>, the same reference the bulk import uses, so a later
import never duplicates a linked ticket.

Unlike the bulk import (serviceops_core/rt_import.py) this only reads: it
never creates teams or users and never stores attachments.
"""
import re

import requests

from serviceops_core import rt_import
from serviceops_core.localization import tr

RT_ID = re.compile(r"#? *(\d{1,10})")
_HTML_TAG = re.compile(r"<[^<>]+>")  # excluding "<" keeps stripping linear on unclosed tags


class RTLinkError(RuntimeError):
    """A message the person can act on (shown as-is)."""


def enabled():
    import app as core
    return core.setting_bool("RT_ENABLED") and core.setting_bool("RT_CHANGE_LINK_ENABLED")


def parse_rt_id(value):
    """'1234', '#1234' or ' 1234 ' -> '1234'; anything else -> None."""
    match = RT_ID.fullmatch(" ".join(str(value or "").split()))
    return match.group(1) if match else None


def rt_web_url(rt_id):
    import app as core
    base = (core.setting_value("RT_BASE_URL", "") or "").rstrip("/")
    return f"{base}/Ticket/Display.html?id={rt_id}" if base and rt_id else None


def linked_change(rt_id, tenant_id):
    """The change in this tenant already referencing RT #rt_id, or None."""
    import app as core
    return core.Ticket.query.filter_by(
        tenant_id=tenant_id, external_source="rt", external_id=str(rt_id),
    ).first()


def _opening_message(session, base_url, rt_id):
    """The text of the ticket's Create transaction: inline Content, else its
    first text attachment without a filename (the message body)."""
    history = rt_import._get(session, base_url, f"/REST/2.0/ticket/{rt_id}/history", params={"per_page": 50})
    for item in history.get("items", []):
        transaction_id = item.get("id")
        if not transaction_id:
            continue
        transaction = rt_import._get(session, base_url, f"/REST/2.0/transaction/{transaction_id}")
        if transaction.get("Type") != "Create":
            continue
        content = (transaction.get("Content") or "").strip()
        if content:
            return content
        listing = rt_import._get(session, base_url, f"/REST/2.0/transaction/{transaction_id}/attachments",
                                 params={"per_page": 20})
        for attachment in listing.get("items", []):
            if not attachment.get("id"):
                continue
            meta = rt_import._get(session, base_url, f"/REST/2.0/attachment/{attachment['id']}",
                                  params={"fields": "Content,ContentType,ContentEncoding,Filename"})
            content_type = (meta.get("ContentType") or "").lower()
            if content_type.startswith("text/") and not meta.get("Filename"):
                text = rt_import._decode_attachment_content(meta.get("Content"), meta.get("ContentEncoding")).strip()
                return _HTML_TAG.sub("", text) if content_type.startswith("text/html") else text
        return ""
    return ""


def fetch_summary(rt_id, tenant_id, session_factory=None):
    """What the change form needs from RT #rt_id. Raises RTLinkError."""
    import app as core
    if not enabled():
        raise RTLinkError(tr("Referencing RT tickets from changes is turned off."))
    rt_id = parse_rt_id(rt_id)
    if not rt_id:
        raise RTLinkError(tr("Enter an RT ticket number."))
    base_url = core.setting_value("RT_BASE_URL", "")
    token = core.setting_value("RT_API_TOKEN", "")
    if not base_url or not token:
        raise RTLinkError(tr("RT is not configured: set the RT base URL and API token on the RT page."))
    session = (session_factory or rt_import._rt_session)(base_url, token)
    try:
        detail = rt_import._get(session, base_url, f"/REST/2.0/ticket/{rt_id}", params={"fields": "CustomFields"})
    except requests.HTTPError as error:
        status = getattr(error.response, "status_code", None)
        if status == 404:
            raise RTLinkError(tr("RT #{id} was not found.", id=rt_id)) from None
        if status in (401, 403):
            raise RTLinkError(tr("RT refused the request: check the API token's rights.")) from None
        raise RTLinkError(tr("RT answered with an error ({status}).", status=status)) from None
    except requests.RequestException:
        raise RTLinkError(tr("Could not reach RT. Try again in a moment.")) from None
    cache = rt_import._RecordCache(session, base_url)
    queue = cache.queue_name(detail.get("Queue")) or ""
    requestors = []
    for ref in detail.get("Requestor") or []:
        contact = cache.user_contact(ref)
        if contact and (contact.get("name") or contact.get("email")):
            requestors.append(contact)
    try:
        message = _opening_message(session, base_url, rt_id)
    except requests.RequestException:
        message = ""
    team = core.resolve_support_group_by_name(queue, tenant_id) if queue else None
    custom_fields = rt_import._custom_fields(detail)
    existing = linked_change(rt_id, tenant_id)
    return {
        "id": rt_id,
        "subject": (detail.get("Subject") or "").strip(),
        "status": detail.get("Status") or "",
        "queue": queue,
        "created": detail.get("Created") or "",
        "requestors": requestors,
        "message": message[:15000],
        "custom_fields": custom_fields,
        "url": rt_web_url(rt_id),
        "team_id": team.id if team and team.active else None,
        "team_name": team.name if team and team.active else None,
        "linked_change": {"number": existing.number, "id": existing.id} if existing else None,
    }


def change_description(summary):
    """The prefilled change description: RT's opening message plus who asked,
    the queue and custom fields, and the link back to RT."""
    lines = []
    if summary.get("message"):
        lines += [summary["message"], ""]
    who = ", ".join(r.get("name") or r.get("email") for r in summary.get("requestors") or [])
    lines.append(f"From RT #{summary['id']}" + (f" ({summary['queue']})" if summary.get("queue") else "")
                 + (f", requested by {who}" if who else "") + ".")
    if summary.get("custom_fields"):
        lines.append(rt_import._format_custom_fields_block(summary["custom_fields"]))
    if summary.get("url"):
        lines.append(summary["url"])
    return "\n".join(lines).strip()
