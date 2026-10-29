"""Gzip responses at the origin.

Production reaches users through a Cloudflare tunnel that connects straight to
the app, so every page, stylesheet and script crossed the server's uplink at
full size before the edge compressed it for the browser. Compressing here
shrinks that leg to about a quarter (a 58 KB ticket list becomes ~9 KB).

Security: pages carry a CSRF token. The edge already compresses these pages on
the leg an attacker could observe (edge to browser), and the origin leg runs
inside the encrypted tunnel, so compressing here adds no BREACH exposure.

Versioned static files never change within a release, so their compressed
bytes are kept in a small in-process cache instead of being recompressed on
every request.
"""
import gzip
import threading
from collections import OrderedDict

from flask import request

COMPRESSIBLE = {
    "text/html", "text/css", "text/plain", "text/csv", "text/javascript", "application/javascript",
    "application/json", "application/manifest+json", "application/xml", "image/svg+xml",
}
MINIMUM_BYTES = 1024
LEVEL = 6
_STATIC_CACHE = OrderedDict()
_STATIC_CACHE_LIMIT = 256
_STATIC_CACHE_MAX_BYTES = 8 * 1024 * 1024
_STATIC_CACHE_LOCK = threading.Lock()  # gunicorn serves several threads per worker


def _accepts_gzip():
    return request.accept_encodings["gzip"] > 0


def compress_response(response):
    if (
        request.method == "HEAD"
        or response.status_code < 200 or response.status_code in (204, 206, 304)
        # Generated streams (live events) are never buffered, and of the file
        # responses only static assets are compressed, never downloads.
        or (response.is_streamed and not response.direct_passthrough)
        or (response.direct_passthrough and request.endpoint != "static")
        or "Content-Encoding" in response.headers
        or response.mimetype not in COMPRESSIBLE
    ):
        return response
    response.vary.add("Accept-Encoding")
    if not _accepts_gzip():
        return response
    static_key = None
    if request.endpoint == "static" and response.status_code == 200 and response.headers.get("ETag"):
        # Query strings are caller-controlled; only the actual asset and its
        # validator identify immutable bytes. Bound both cache count and size.
        static_key = (request.path, response.headers["ETag"])
        with _STATIC_CACHE_LOCK:
            cached = _STATIC_CACHE.get(static_key)
            if cached is not None:
                _STATIC_CACHE.move_to_end(static_key)
        if cached is not None:
            if hasattr(response.response, "close"):
                response.response.close()  # the unread file
            return _apply(response, cached)
    # Static files arrive as a file wrapper; read them so they can be compressed.
    response.direct_passthrough = False
    body = response.get_data()
    if len(body) < MINIMUM_BYTES:
        return response
    compressed = gzip.compress(body, compresslevel=LEVEL, mtime=0)
    if len(compressed) >= len(body):
        return response
    if static_key is not None and len(compressed) <= _STATIC_CACHE_MAX_BYTES:
        with _STATIC_CACHE_LOCK:
            _STATIC_CACHE[static_key] = compressed
            while (len(_STATIC_CACHE) > _STATIC_CACHE_LIMIT
                   or sum(map(len, _STATIC_CACHE.values())) > _STATIC_CACHE_MAX_BYTES):
                _STATIC_CACHE.popitem(last=False)
    return _apply(response, compressed)


def _apply(response, compressed):
    response.direct_passthrough = False
    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    if response.headers.get("ETag"):
        # A different representation needs a different validator.
        etag, weak = response.get_etag()
        if etag and not etag.endswith("-gzip"):
            response.set_etag(f"{etag}-gzip", weak=weak)
    if request.endpoint == "static":
        response.make_conditional(request)
    return response
