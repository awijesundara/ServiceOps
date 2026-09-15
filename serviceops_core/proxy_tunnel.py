"""Lets smtplib connect through an HTTP/HTTPS forward proxy in deployments
without direct internet access.

Python's stdlib `requests` already understands HTTP proxies natively (its
own `proxies=` kwarg), which covers webhook/chat notification delivery.
`smtplib` has no equivalent -- SMTP isn't HTTP, so there is no `proxies=`
kwarg to pass. The standard way a plain TCP protocol like SMTP tunnels
through an HTTP(S) proxy is the same `CONNECT host:port` method browsers use
for HTTPS: open a TCP connection to the proxy, ask it to open a raw tunnel to
the real destination, then speak the real protocol (SMTP, then STARTTLS/TLS)
through that tunnel exactly as if connected directly.

This mirrors serviceops_core.dns_pin's established pattern: a thread-local,
idempotently-installed monkeypatch of a stdlib socket function, active only
for the duration of a `with` block on the calling thread, so concurrent
deliveries on other threads (gunicorn `--threads`) are unaffected.
"""
import base64
import socket
import threading
from urllib.parse import urlparse


_local = threading.local()
_real_create_connection = socket.create_connection


def parse_proxy_url(proxy_url):
    """Returns (hostname, port, username, password) for an http(s):// proxy
    URL, or raises ValueError for anything else -- called both here and by
    app.py so a malformed admin-entered value fails the same way in both
    the SMTP tunnel and the settings-save validation."""
    parsed = urlparse(proxy_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Proxy URL must be http:// or https://host:port.")
    return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), parsed.username, parsed.password


def _read_connect_response(sock, timeout):
    """Reads exactly through the proxy's CONNECT response headers, one byte
    at a time, so nothing past the blank line that ends them is consumed --
    the caller (smtplib) must see the tunneled server's own first bytes
    (its SMTP banner) untouched. A CONNECT response is at most a few hundred
    bytes, so the per-byte recv() cost here is negligible."""
    sock.settimeout(timeout)
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(1)
        if not chunk:
            raise OSError("Proxy closed the connection during CONNECT.")
        buffer += chunk
        if len(buffer) > 8192:
            raise OSError("Proxy CONNECT response exceeded the expected header size.")
    return buffer


def _patched_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    proxy = getattr(_local, "proxy", None)
    if not proxy:
        return _real_create_connection(address, timeout, source_address)
    host, port = address
    proxy_host, proxy_port, username, password = proxy
    effective_timeout = 30 if timeout is socket._GLOBAL_DEFAULT_TIMEOUT else timeout
    proxy_sock = _real_create_connection((proxy_host, proxy_port), effective_timeout, source_address)
    try:
        request_lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
        if username:
            credentials = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
            request_lines.append(f"Proxy-Authorization: Basic {credentials}")
        request_lines.append("\r\n")
        proxy_sock.sendall("\r\n".join(request_lines).encode())
        response = _read_connect_response(proxy_sock, effective_timeout)
        status_line = response.split(b"\r\n", 1)[0]
        status_parts = status_line.split(b" ", 2)
        if len(status_parts) < 2 or status_parts[1] != b"200":
            raise OSError(
                f"Proxy CONNECT to {host}:{port} was refused: "
                f"{status_line.decode('latin-1', 'replace')}"
            )
        proxy_sock.settimeout(None if timeout is socket._GLOBAL_DEFAULT_TIMEOUT else timeout)
        return proxy_sock
    except Exception:
        proxy_sock.close()
        raise


if socket.create_connection is not _patched_create_connection:
    socket.create_connection = _patched_create_connection


class tunnel_through_proxy:
    """Context manager: for the calling thread only, `socket.create_connection`
    transparently tunnels through the given HTTP(S) proxy via CONNECT.
    `proxy_url` of None or empty is a deliberate no-op (direct connection
    unchanged) so every call site can wrap unconditionally rather than
    branching on whether a proxy is configured."""

    def __init__(self, proxy_url):
        self.parsed = parse_proxy_url(proxy_url) if proxy_url else None

    def __enter__(self):
        self._previous = getattr(_local, "proxy", None)
        _local.proxy = self.parsed
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        _local.proxy = self._previous
        return False
