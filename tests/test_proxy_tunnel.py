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


def test_https_proxy_never_sends_connect_or_credentials_to_plaintext_peer():
    captured = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    def receive():
        conn, _ = listener.accept()
        with conn:
            captured.append(conn.recv(4096))
    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    try:
        with tunnel_through_proxy(f'https://synthetic:password@127.0.0.1:{listener.getsockname()[1]}'):
            with pytest.raises(OSError):
                socket.create_connection(('smtp.example.test', 587), timeout=2)
        thread.join(timeout=3)
        assert captured and captured[0][0] == 0x16
        assert b'CONNECT' not in captured[0] and b'Proxy-Authorization' not in captured[0]
    finally:
        listener.close()


def test_https_proxy_supports_verified_outer_and_destination_tls(tmp_path, monkeypatch):
    import datetime
    import ipaddress
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from urllib3.util.ssltransport import SSLTransport
    import serviceops_core.proxy_tunnel as tunnel

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    current = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(current - datetime.timedelta(minutes=1))
            .not_valid_after(current + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('smtp.example.test'),
                                                       x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_file, key_file)
    client_context = ssl.create_default_context(cafile=str(cert_file))
    monkeypatch.setattr(tunnel.ssl, 'create_default_context', lambda: client_context)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    errors = []
    class ServerBIOContext:
        def wrap_bio(self, incoming, outgoing, **options):
            return server_context.wrap_bio(incoming, outgoing, server_side=True)
    def serve():
        try:
            raw, _ = listener.accept()
            with server_context.wrap_socket(raw, server_side=True) as outer:
                request = b''
                while b'\r\n\r\n' not in request:
                    request += outer.recv(1)
                assert b'CONNECT smtp.example.test:465' in request
                assert b'Proxy-Authorization: Basic' in request
                outer.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                with SSLTransport(outer, ServerBIOContext()) as inner:
                    inner.sendall(b'220 nested TLS SMTP\r\n')
                    assert inner.recv(4) == b'QUIT'
        except Exception as error:
            errors.append(error)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with tunnel_through_proxy(f'https://synthetic:password@127.0.0.1:{listener.getsockname()[1]}'):
            outer = socket.create_connection(('smtp.example.test', 465), timeout=3)
            with client_context.wrap_socket(outer, server_hostname='smtp.example.test') as inner:
                assert inner.recv(100) == b'220 nested TLS SMTP\r\n'
                inner.sendall(b'QUIT')
        thread.join(timeout=4)
        assert not thread.is_alive() and not errors
    finally:
        listener.close()
