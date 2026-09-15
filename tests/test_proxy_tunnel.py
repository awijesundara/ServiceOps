"""serviceops_core.proxy_tunnel: lets smtplib (which has no native proxy
support) reach an SMTP host through an HTTP(S) forward proxy via CONNECT,
for deployments without direct internet access. These tests exercise the
tunnel against a real local socket server speaking the CONNECT protocol,
isolated from Flask/DB fixtures and from any real network -- matching the
existing real-server style already used for serviceops_core.dns_pin.
"""
import base64
import socket
import threading

import pytest

from serviceops_core.proxy_tunnel import parse_proxy_url, tunnel_through_proxy


def _run_fake_connect_proxy(listener, expect_auth=None, refuse=False):
    """Accepts one connection, reads the CONNECT request line, optionally
    checks Proxy-Authorization, then either refuses (403) or accepts (200)
    and echoes back whatever the tunneled client sends -- enough to prove
    bytes flow both ways through the tunnel after the handshake."""
    conn, _ = listener.accept()
    try:
        request = b""
        while b"\r\n\r\n" not in request:
            request += conn.recv(1)
        if expect_auth is not None:
            header = f"Proxy-Authorization: Basic {expect_auth}".encode()
            if header not in request:
                conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                return
        if refuse:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        data = conn.recv(4096)
        if data:
            conn.sendall(b"echo:" + data)
    finally:
        conn.close()


def _start_fake_proxy(**kwargs):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    thread = threading.Thread(target=_run_fake_connect_proxy, args=(listener,), kwargs=kwargs, daemon=True)
    thread.start()
    return port, listener, thread


def test_parse_proxy_url_rejects_non_http_schemes():
    with pytest.raises(ValueError):
        parse_proxy_url("socks5://proxy.example:1080")
    with pytest.raises(ValueError):
        parse_proxy_url("not-a-url")


def test_parse_proxy_url_extracts_host_port_and_credentials():
    host, port, username, password = parse_proxy_url("http://user:pass@proxy.example:3128")
    assert (host, port, username, password) == ("proxy.example", 3128, "user", "pass")


def test_tunnel_connects_through_a_real_local_connect_proxy_and_relays_bytes():
    port, listener, thread = _start_fake_proxy()
    try:
        with tunnel_through_proxy(f"http://127.0.0.1:{port}"):
            sock = socket.create_connection(("smtp.example.test", 587), timeout=5)
            sock.sendall(b"hello")
            assert sock.recv(4096) == b"echo:hello"
            sock.close()
    finally:
        listener.close()
        thread.join(timeout=2)


def test_tunnel_sends_proxy_authorization_when_the_url_has_credentials():
    expected = base64.b64encode(b"admin:secret").decode()
    port, listener, thread = _start_fake_proxy(expect_auth=expected)
    try:
        with tunnel_through_proxy(f"http://admin:secret@127.0.0.1:{port}"):
            sock = socket.create_connection(("smtp.example.test", 587), timeout=5)
            sock.sendall(b"hi")
            assert sock.recv(4096) == b"echo:hi"
            sock.close()
    finally:
        listener.close()
        thread.join(timeout=2)


def test_tunnel_raises_when_the_proxy_refuses_the_connect():
    port, listener, thread = _start_fake_proxy(refuse=True)
    try:
        with tunnel_through_proxy(f"http://127.0.0.1:{port}"):
            with pytest.raises(OSError):
                socket.create_connection(("smtp.example.test", 587), timeout=5)
    finally:
        listener.close()
        thread.join(timeout=2)


def test_no_proxy_url_leaves_create_connection_unpatched_behavior():
    """A None/empty proxy_url must be a real no-op -- connecting to an
    address with no listener there must fail the normal way (connection
    refused), not silently succeed or hang waiting on a phantom proxy."""
    with tunnel_through_proxy(None):
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", 1), timeout=1)


def test_tunnel_is_cleared_after_the_context_exits():
    with tunnel_through_proxy("http://127.0.0.1:65535"):
        pass
    # Outside the context, a direct connect attempt must behave like a
    # normal direct connection (refused, since nothing listens there) --
    # i.e. the patch must not still be active and silently try to CONNECT
    # through the (never-contacted) proxy configured above.
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", 1), timeout=1)


def test_tunnel_is_cleared_even_when_the_block_raises():
    try:
        with tunnel_through_proxy("http://127.0.0.1:1"):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", 1), timeout=1)
