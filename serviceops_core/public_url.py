"""Absolute links that leave the request -- emailed password-reset links, the
OIDC callback registered with the identity provider, SCIM resource
locations -- built from the deployment's configured public origin rather
than from the request.

`url_for(..., _external=True)` takes its host from the request's Host /
X-Forwarded-Host headers. Those are client-controlled unless every proxy in
front rewrites them, so a password-reset request carrying
`X-Forwarded-Host: attacker.example` would otherwise email the victim a
working reset token pointing at the attacker's server.
"""
import os
from urllib.parse import urlsplit

from flask import url_for


def public_origin():
    """`scheme://host[:port]` from PUBLIC_BASE_URL, falling back to the
    passkey WEBAUTHN_ORIGIN (already the deployment's HTTPS origin wherever
    passkeys are enabled). None when neither is a usable http(s) origin."""
    for name in ("PUBLIC_BASE_URL", "WEBAUTHN_ORIGIN"):
        parts = urlsplit(os.getenv(name, "").strip())
        if parts.scheme in {"http", "https"} and parts.netloc and "@" not in parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
    return None


def public_url_for(endpoint, **values):
    """Like `url_for(endpoint, _external=True)`, but anchored to the
    configured public origin when there is one. The path still comes from
    `url_for`, so a reverse-proxy path prefix (X-Forwarded-Prefix) is kept."""
    origin = public_origin()
    if origin:
        return origin + url_for(endpoint, **values)
    return url_for(endpoint, _external=True, **values)
