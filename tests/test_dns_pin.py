"""serviceops_core.dns_pin: closes the webhook DNS TOCTOU gap (see the
module docstring and deliver_webhook() in app.py) by pinning a validated
resolution to the calling thread only. These tests exercise the pinning
mechanism directly, isolated from Flask/DB fixtures.
"""
import socket
import threading

from serviceops_core.dns_pin import pin_resolved_addresses


def test_pin_filters_to_requested_socket_type_and_substitutes_the_real_port():
    """Regression test: the pin is captured via getaddrinfo(host, None) --
    no socket type requested -- which returns one entry per (address,
    SOCK_STREAM/SOCK_DGRAM/SOCK_RAW) combination, all with port 0. A caller
    (requests/urllib3) always asks for a specific type (SOCK_STREAM) and a
    real port; handing back the raw pin unfiltered previously broke every
    real webhook delivery with a "Protocol not supported" connection error,
    since the caller got DGRAM/RAW entries with port 0 mixed in with the
    STREAM ones it needed."""
    raw_infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.9", 0)),
        (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.9", 0)),
        (socket.AF_INET, socket.SOCK_RAW, 0, "", ("203.0.113.9", 0)),
    ]
    with pin_resolved_addresses("pinned.example.test", raw_infos):
        result = socket.getaddrinfo(
            "pinned.example.test", 443, family=socket.AF_INET, type=socket.SOCK_STREAM,
        )
    assert len(result) == 1
    family, socktype, proto, canonname, sockaddr = result[0]
    assert socktype == socket.SOCK_STREAM
    assert sockaddr == ("203.0.113.9", 443)


def test_pin_overrides_getaddrinfo_only_for_pinned_host():
    fake_infos = [(2, 1, 6, "", ("203.0.113.9", 0))]
    with pin_resolved_addresses("pinned.example.test", fake_infos):
        assert socket.getaddrinfo("pinned.example.test", None) == fake_infos
        # An unrelated host on the same thread still resolves normally
        # (falls through to the real resolver) instead of also returning
        # the pinned host's addresses.
        assert socket.getaddrinfo("localhost", None) != fake_infos


def test_pin_is_cleared_after_the_context_exits():
    fake_infos = [(2, 1, 6, "", ("203.0.113.9", 0))]
    with pin_resolved_addresses("pinned.example.test", fake_infos):
        pass
    # Outside the context, the same host is no longer overridden -- a real
    # (or in this sandboxed test environment, failing) lookup happens
    # instead of silently returning the stale pin.
    try:
        result = socket.getaddrinfo("pinned.example.test", None)
    except OSError:
        result = None
    assert result != fake_infos


def test_pin_is_cleared_even_when_the_block_raises():
    fake_infos = [(2, 1, 6, "", ("203.0.113.9", 0))]
    try:
        with pin_resolved_addresses("pinned.example.test", fake_infos):
            raise RuntimeError("delivery failed")
    except RuntimeError:
        pass
    try:
        result = socket.getaddrinfo("pinned.example.test", None)
    except OSError:
        result = None
    assert result != fake_infos


def test_pin_does_not_leak_across_threads():
    """Two threads pinning different hosts concurrently must never see each
    other's pin -- the whole reason this uses threading.local() rather than
    a plain module-level override (gunicorn serves this app with multiple
    threads per worker; concurrent webhook deliveries are expected)."""
    thread_a_infos = [(2, 1, 6, "", ("203.0.113.1", 0))]
    thread_b_infos = [(2, 1, 6, "", ("203.0.113.2", 0))]
    results = {}
    barrier = threading.Barrier(2)

    def _lookup(host):
        try:
            return socket.getaddrinfo(host, None)
        except OSError:
            # No pin for this host on this thread -- falls through to a
            # real (and here, failing, since these are fake TLDs) lookup.
            # A failure is itself proof no cross-thread leak occurred.
            return None

    def run_a():
        with pin_resolved_addresses("host-a.example.test", thread_a_infos):
            barrier.wait()
            results["a_sees_a"] = _lookup("host-a.example.test")
            results["a_sees_b"] = _lookup("host-b.example.test")

    def run_b():
        with pin_resolved_addresses("host-b.example.test", thread_b_infos):
            barrier.wait()
            results["b_sees_b"] = _lookup("host-b.example.test")
            results["b_sees_a"] = _lookup("host-a.example.test")

    t1 = threading.Thread(target=run_a)
    t2 = threading.Thread(target=run_b)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results["a_sees_a"] == thread_a_infos
    assert results["b_sees_b"] == thread_b_infos
    # Neither thread's own pinned host resolved to the other thread's pin.
    assert results["a_sees_b"] != thread_a_infos
    assert results["b_sees_a"] != thread_b_infos
