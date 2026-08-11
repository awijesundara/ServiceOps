"""Client Management email channel: pure parsing/threading/classification
logic, with zero IMAP/SMTP/Flask/DB dependency (mirrors client_automation.py's
"the engine has no I/O" shape) so it's unit-testable in isolation. app.py's
process_client_email_inbox()/deliver_client_email_reply() do the actual
IMAP/SMTP I/O and call into these functions.

Design choices, per research into how Zendesk/Freshdesk/Help Scout/Zoho Desk
document their own email channels (see the BACKLOG entry for citations):
- Threading prefers Message-ID/In-Reply-To/References headers (most robust,
  survives subject-line mangling by mail clients/gateways) with a bracketed
  ticket-number subject token as the documented fallback, not the primary
  signal.
- Auto-generated mail (autoresponders, bounces, mailing-list posts) is
  detected via Auto-Submitted/Precedence headers and never becomes a
  ticket, to avoid mail loops -- the same signal Zendesk's own loop
  documentation names as primary.
- A small free-mail-domain denylist gates automatic organization creation
  by sender domain, matching Freshdesk's documented convention of letting
  admins exclude personal-mail domains from auto-linking a "company."
"""
import re
from email import message_from_bytes, policy
from email.utils import parseaddr

TICKET_TOKEN_PATTERN = re.compile(r"\[([A-Z]{2,6}\d{5,})\]")

# Matches Freshdesk's documented free-mail-domain exclusion list for
# automatic company/organization linking.
FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "aol.com", "protonmail.com", "live.com", "msn.com",
}

MAX_ATTACHMENT_TOTAL_BYTES = 20 * 1024 * 1024  # matches Freshdesk's paid-tier ceiling


def extract_ticket_token(subject):
    """The bracketed ticket-number fallback threading signal, e.g. a
    subject "Re: [CXT0000123] Cannot log in" -> "CXT0000123". Returns None
    if no token is present."""
    if not subject:
        return None
    match = TICKET_TOKEN_PATTERN.search(subject)
    return match.group(1) if match else None


def is_free_mail_domain(domain):
    return (domain or "").strip().lower() in FREE_MAIL_DOMAINS


def is_auto_generated(headers):
    """True if this message was itself machine-generated (autoresponder,
    bounce, mailing-list digest) and must never become a ticket or be
    replied to -- the primary mail-loop defense, per Zendesk's own
    documented convention of checking these exact two headers."""
    auto_submitted = (headers.get("Auto-Submitted") or "").strip().lower()
    if auto_submitted and auto_submitted != "no":
        return True
    precedence = (headers.get("Precedence") or "").strip().lower()
    if precedence in ("bulk", "list", "junk"):
        return True
    return False


def parse_inbound_email(raw_bytes):
    """Parses a raw RFC 5322 email into a plain dict:
    {from_email, from_name, subject, body_text, message_id, in_reply_to,
    references, is_auto_generated, attachments: [{filename, mime_type, data}]}.
    Never raises on malformed input beyond what Python's own email parser
    tolerates -- a message this can't usefully parse should be skipped by
    the caller, not crash the whole inbox poll."""
    msg = message_from_bytes(raw_bytes, policy=policy.default)
    from_name, from_email = parseaddr(msg.get("From", ""))
    subject = str(msg.get("Subject", "") or "")

    body_text = ""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get_content_disposition() or "")
            if disposition == "attachment" or (part.get_filename() and content_type != "text/plain"):
                data = part.get_payload(decode=True)
                if data is not None:
                    attachments.append({
                        "filename": part.get_filename() or "attachment",
                        "mime_type": content_type,
                        "data": data,
                    })
            elif content_type == "text/plain" and not body_text:
                payload = part.get_payload(decode=True)
                if payload is not None:
                    body_text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            elif content_type == "text/html" and not body_text:
                payload = part.get_payload(decode=True)
                if payload is not None:
                    html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    body_text = re.sub(r"<[^>]+>", " ", html)
    else:
        payload = msg.get_payload(decode=True)
        if payload is not None:
            body_text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")

    return {
        "from_email": (from_email or "").strip().lower(),
        "from_name": (from_name or "").strip(),
        "subject": subject.strip(),
        "body_text": body_text.strip(),
        "message_id": (msg.get("Message-ID") or "").strip(),
        "in_reply_to": (msg.get("In-Reply-To") or "").strip(),
        "references": (msg.get("References") or "").strip(),
        "is_auto_generated": is_auto_generated(msg),
        "attachments": attachments,
    }


def referenced_message_ids(in_reply_to, references):
    """All Message-IDs an inbound reply points back to, most-specific
    first -- In-Reply-To is the direct parent, References is the full
    ancestor chain (RFC 5322 3.6.4). Used to thread against
    ClientTicketMessage.message_id."""
    ids = []
    if in_reply_to:
        ids.append(in_reply_to.strip())
    if references:
        # References is a whitespace-separated list of <angle-bracketed> ids.
        for token in re.findall(r"<[^<>]+>", references):
            if token not in ids:
                ids.append(token)
    return ids


def build_references_header(prior_message_id, prior_references):
    """RFC 5322 References-chain construction for an outbound reply: the
    prior message's own References plus its Message-ID appended."""
    chain = []
    if prior_references:
        chain.extend(re.findall(r"<[^<>]+>", prior_references))
    if prior_message_id and prior_message_id not in chain:
        chain.append(prior_message_id)
    return " ".join(chain)
