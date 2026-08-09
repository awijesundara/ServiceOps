"""Closes the DNS TOCTOU gap between validating a webhook destination's
resolved addresses and the HTTP client actually connecting to them.

app.py's `integration_endpoint_resolves_safely()` re-resolves a webhook's
hostname and checks every A/AAAA record is safe immediately before delivery
-- but `requests.post()` then performs its OWN independent resolution to
actually open the connection. A short-TTL, attacker-controlled DNS record
can return a public address for the validation lookup and a private/loopback
one a moment later for the connection lookup (DNS rebinding's classic
check-then-connect race).

The fix pins the *exact* addresses just validated for the duration of the
one `requests.post()` call that follows, by wrapping `socket.getaddrinfo`
so it returns only the pinned answer while a pin is active for the calling
thread. A `threading.local()` pin (not a plain global) is required because
gunicorn serves this app with multiple threads per worker (see
tools/gunicorn-entrypoint.sh's `--threads`) and multiple webhook deliveries
can be in flight concurrently -- a bare module-level override would let one
thread's pin leak into another thread's unrelated DNS lookups.
"""
import socket
import threading

_local = threading.local()
_real_getaddrinfo = socket.getaddrinfo


def _matching_pinned_addresses(infos, port, family, type_, proto):
    """The pin was captured via a bare `getaddrinfo(hostname, None)` (see
    resolve_endpoint_addresses_safely()), which -- with no socket type
    requested -- returns one entry per (address, SOCK_STREAM/SOCK_DGRAM/
    SOCK_RAW) combination, all with port 0. The real caller (requests/
    urllib3) asks for a specific family/type/proto and a real port; handing
    that caller the raw, unfiltered, port-0 pin verbatim returns entries it
    can't actually connect with (wrong socket type, port 0), breaking every
    real delivery -- this filters to what the caller actually asked for and
    substitutes the real port into each matching entry."""
    port = 0 if port is None else port
    matches = []
    for fam, socktype, sockproto, canonname, sockaddr in infos:
        if family and fam != family:
            continue
        if type_ and socktype != type_:
            continue
        if proto and sockproto != proto:
            continue
        new_sockaddr = (sockaddr[0], port) + tuple(sockaddr[2:])
        matches.append((fam, socktype, sockproto, canonname, new_sockaddr))
    # Every pinned address was already validated safe regardless of socket
    # type -- if the filter somehow matches nothing (an unexpected family/
    # type combination), fall back to the full pinned set with the port
    # substituted rather than silently resolving fresh (which would reopen
    # the exact TOCTOU window this module exists to close).
    if not matches:
        matches = [
            (fam, socktype, sockproto, canonname, (sockaddr[0], port) + tuple(sockaddr[2:]))
            for fam, socktype, sockproto, canonname, sockaddr in infos
        ]
    return matches


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    pinned = getattr(_local, "pins", None)
    if pinned and host in pinned:
        return _matching_pinned_addresses(pinned[host], port, family, type, proto)
    return _real_getaddrinfo(host, port, family, type, proto, flags)


# Installed once, at import time. Idempotent: re-importing this module
# (e.g. under pytest's module reload) must not wrap an already-patched
# function, or the "real" fallback would start pointing at our own wrapper.
if socket.getaddrinfo is not _patched_getaddrinfo:
    socket.getaddrinfo = _patched_getaddrinfo


class pin_resolved_addresses:
    """Context manager: for the calling thread only, `socket.getaddrinfo(host,
    ...)` returns exactly `infos` (the same shape `socket.getaddrinfo` itself
    returns) instead of performing a new DNS lookup. Always clears the pin on
    exit, including on exception, so a failed delivery can never leave a
    stale pin behind for a later, unrelated call on the same thread."""

    def __init__(self, host, infos):
        self.host = host
        self.infos = infos

    def __enter__(self):
        pins = getattr(_local, "pins", None)
        if pins is None:
            pins = {}
            _local.pins = pins
        self._previous = pins.get(self.host)
        pins[self.host] = self.infos
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pins = getattr(_local, "pins", None)
        if pins is None:
            return False
        if self._previous is None:
            pins.pop(self.host, None)
        else:
            pins[self.host] = self._previous
        return False
