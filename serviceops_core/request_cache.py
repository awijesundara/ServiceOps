"""Read caches that live exactly as long as one HTTP request.

They are kept in the WSGI environ rather than flask.g: g belongs to the app
context, which a worker, script or test may hold open across several requests,
so a value cached on g could outlive the request that computed it.
"""
from flask import has_request_context, request

_ENVIRON_KEY = "serviceops.request_cache"


def request_cache():
    """This request's cache dict, or None outside a request."""
    if not has_request_context():
        return None
    return request.environ.setdefault(_ENVIRON_KEY, {})
