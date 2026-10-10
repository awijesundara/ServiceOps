"""Redirects to caller-supplied destinations (a form's return path, the
Referer of a POST) that can only ever land inside this application.

The destination is reduced to a relative path -- scheme and host are
discarded, never compared -- and refused unless it is an absolute path that
browsers cannot reinterpret as another origin ("//host", "/\\host").
"""
from urllib.parse import urlparse, urlsplit, urlunsplit

from flask import redirect, request


def redirect_internal(target, fallback, code=302):
    """Redirect to `target` when it is a same-app relative path, else to
    `fallback` (a URL this app built, e.g. with url_for)."""
    target = target or ""
    if target.startswith("/") and not target.startswith("//") and "\\" not in target:
        parsed = urlparse(target)
        if not parsed.scheme and not parsed.netloc:
            return redirect(target, code=code)
    return redirect(fallback, code=code)


def redirect_to_referrer(fallback, code=302):
    """Return to the page that submitted this request when it is one of this
    application's own pages; otherwise go to `fallback`."""
    parts = urlsplit(request.referrer or "")
    if parts.scheme in {"http", "https"} and parts.netloc == request.host:
        relative = urlunsplit(("", "", parts.path or "/", parts.query, parts.fragment))
        return redirect_internal(relative, fallback, code=code)
    return redirect(fallback, code=code)
