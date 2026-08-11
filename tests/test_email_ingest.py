"""serviceops_core.email_ingest: parsing/threading/classification logic for
the Client Management email channel. Exercised directly with real RFC 5322
message bytes (no mocks needed -- this module has no I/O), isolated from
Flask/DB fixtures. IMAP/SMTP wiring (process_client_email_inbox/
deliver_client_email_reply) is covered by a real GreenMail end-to-end pass,
not here.
"""
from email.message import EmailMessage

from serviceops_core.email_ingest import (
    build_references_header, extract_ticket_token, is_auto_generated,
    is_free_mail_domain, parse_inbound_email, referenced_message_ids,
)


def _build_raw_email(subject, body, from_addr="customer@example.test", extra_headers=None, attachment=None):
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = "support@ourcompany.test"
    msg["Subject"] = subject
    msg["Message-ID"] = "<abc123@example.test>"
    for key, value in (extra_headers or {}).items():
        msg[key] = value
    msg.set_content(body)
    if attachment:
        msg.add_attachment(
            attachment["data"], maintype="application", subtype="octet-stream",
            filename=attachment["filename"],
        )
    return msg.as_bytes()


def test_parse_inbound_email_extracts_core_fields():
    raw = _build_raw_email("Cannot log in", "My password reset link is broken.", from_addr="Jane Doe <jane@example.test>")
    parsed = parse_inbound_email(raw)
    assert parsed["from_email"] == "jane@example.test"
    assert parsed["from_name"] == "Jane Doe"
    assert parsed["subject"] == "Cannot log in"
    assert "password reset link is broken" in parsed["body_text"]
    assert parsed["message_id"] == "<abc123@example.test>"
    assert parsed["is_auto_generated"] is False
    assert parsed["attachments"] == []


def test_parse_inbound_email_extracts_attachment():
    raw = _build_raw_email(
        "Screenshot attached", "See attached.",
        attachment={"filename": "screenshot.png", "data": b"\x89PNG fake bytes"},
    )
    parsed = parse_inbound_email(raw)
    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["filename"] == "screenshot.png"
    assert parsed["attachments"][0]["data"] == b"\x89PNG fake bytes"


def test_parse_inbound_email_detects_reply_headers():
    raw = _build_raw_email(
        "Re: Cannot log in", "Still broken, any update?",
        extra_headers={"In-Reply-To": "<original@ourcompany.test>", "References": "<original@ourcompany.test>"},
    )
    parsed = parse_inbound_email(raw)
    assert parsed["in_reply_to"] == "<original@ourcompany.test>"
    assert referenced_message_ids(parsed["in_reply_to"], parsed["references"]) == ["<original@ourcompany.test>"]


def test_is_auto_generated_detects_autoresponder_and_bulk_mail():
    raw_autoreply = _build_raw_email(
        "Out of office", "I am away.", extra_headers={"Auto-Submitted": "auto-replied"},
    )
    assert parse_inbound_email(raw_autoreply)["is_auto_generated"] is True

    raw_bulk = _build_raw_email(
        "Newsletter", "Sign up now!", extra_headers={"Precedence": "bulk"},
    )
    assert parse_inbound_email(raw_bulk)["is_auto_generated"] is True

    raw_normal = _build_raw_email("Question", "How do I reset my password?")
    assert parse_inbound_email(raw_normal)["is_auto_generated"] is False


def test_is_auto_generated_header_helper_directly():
    assert is_auto_generated({"Auto-Submitted": "auto-generated"}) is True
    assert is_auto_generated({"Auto-Submitted": "no"}) is False
    assert is_auto_generated({}) is False
    assert is_auto_generated({"Precedence": "list"}) is True


def test_extract_ticket_token():
    assert extract_ticket_token("Re: [CXT0000123] Cannot log in") == "CXT0000123"
    assert extract_ticket_token("Cannot log in") is None
    assert extract_ticket_token("") is None
    assert extract_ticket_token(None) is None


def test_is_free_mail_domain():
    assert is_free_mail_domain("gmail.com") is True
    assert is_free_mail_domain("GMAIL.COM") is True
    assert is_free_mail_domain("ourcompany.test") is False
    assert is_free_mail_domain("") is False


def test_build_references_header_chains_prior_references_and_message_id():
    result = build_references_header("<msg2@x>", "<msg1@x>")
    assert result == "<msg1@x> <msg2@x>"
    # No prior references at all -- just the one Message-ID.
    assert build_references_header("<msg1@x>", "") == "<msg1@x>"
    # No prior message at all (first message in the thread).
    assert build_references_header("", "") == ""


def test_referenced_message_ids_prefers_in_reply_to_first():
    ids = referenced_message_ids("<direct-parent@x>", "<grandparent@x> <direct-parent@x>")
    assert ids[0] == "<direct-parent@x>"
    assert "<grandparent@x>" in ids
