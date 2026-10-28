"""The look of every notification email: a branded HTML version with a
plain-text alternative.

The HTML is table-based with inline styles, because Outlook (Word's
renderer), Gmail and Apple Mail each drop different parts of modern CSS.
The company logo, when one is uploaded, travels inside the message as an
inline image, so it shows without the mail client fetching anything. Text
from tickets is always escaped (Jinja autoescape); nothing a requester
types can add markup to the email.
"""
import os
import re
from email.utils import make_msgid

from flask import current_app

SEVERITY_COLORS = {"critical": "#b42318", "warning": "#b54708", "info": None}
_HEX = re.compile(r"#[0-9a-fA-F]{6}")


def _core():
    import app as core
    return core


def brand_color():
    value = _core().setting_value("BRAND_TEAL", "#003e4c") or "#003e4c"
    return value if _HEX.fullmatch(value) else "#003e4c"


def _logo_bytes():
    try:
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], "company-logo.png")
        if os.path.getsize(path) <= 512 * 1024:
            with open(path, "rb") as handle:
                data = handle.read()
            return data if data.startswith(b"\x89PNG\r\n\x1a\n") else None
    except (OSError, KeyError, RuntimeError):
        return None
    return None


def paragraphs(body):
    """Blank-line separated paragraphs, each a list of lines."""
    blocks = re.split(r"\n\s*\n", str(body or "").strip())
    return [[line for line in block.splitlines()] for block in blocks if block.strip()]


def render_email(message, *, title, body, eyebrow="", reason="", link_url=None, link_label="Open in ServiceOps",
                 severity=None, preferences_url=None, reference=None):
    """Fills `message` with a text part and a branded HTML alternative."""
    core = _core()
    instance = core.setting_value("INSTANCE_NAME", "ServiceOps") or "ServiceOps"
    accent = SEVERITY_COLORS.get(severity) or brand_color()
    logo = _logo_bytes()
    logo_cid = make_msgid(domain="serviceops.logo") if logo else None
    from serviceops_core.localization import tr
    context = dict(
        tr=tr, instance=instance, title=title, paragraphs=paragraphs(body), body=str(body or "").strip(), eyebrow=eyebrow,
        reason=reason, link_url=link_url, link_label=link_label, preferences_url=preferences_url,
        brand=brand_color(), accent=accent, severity=severity, reference=reference,
        logo_cid=logo_cid[1:-1] if logo_cid else None,
        preheader=" ".join(str(body or "").split())[:140],
    )
    # The Jinja environment directly, not render_template: the outbox worker
    # has no signed-in user for the web page context processors.
    environment = current_app.jinja_env
    message.set_content(environment.get_template("email/notification.txt").render(**context))
    message.add_alternative(environment.get_template("email/notification.html").render(**context), subtype="html")
    if logo:
        html_part = message.get_payload()[1]
        html_part.add_related(logo, "image", "png", cid=logo_cid, filename="logo.png", disposition="inline")
    return message
