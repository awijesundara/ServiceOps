"""Real client address behind proxies, device labels, location and reverse DNS."""
import tempfile
import time

import pytest

import app as app_module
from serviceops_core.client_identity import ClientAddressMiddleware, client_location, describe_device


def resolve(remote_addr, headers=None, **config):
    seen = {}

    def inner(environ, start_response):
        seen["addr"] = environ["REMOTE_ADDR"]
        return []

    middleware = ClientAddressMiddleware(inner, environ_source=config)
    environ = {"REMOTE_ADDR": remote_addr}
    for name, value in (headers or {}).items():
        environ["HTTP_" + name.upper().replace("-", "_")] = value
    middleware(environ, lambda *args: None)
    return seen["addr"]


def test_a_direct_client_cannot_forge_its_address():
    forged = {"X-Forwarded-For": "1.2.3.4", "CF-Connecting-IP": "1.2.3.4"}
    assert resolve("203.0.113.9", forged, CLIENT_IP_HEADER="CF-Connecting-IP") == "203.0.113.9"


def test_ingress_chain_resolves_to_the_client_not_the_cluster():
    assert resolve("10.1.0.12", {"X-Forwarded-For": "198.51.100.7"}) == "198.51.100.7"
    # nginx -> ingress -> pod: skip every private hop.
    assert resolve("10.1.0.12", {"X-Forwarded-For": "198.51.100.7, 10.1.0.3, 172.17.0.4"}) == "198.51.100.7"


def test_cloudflare_edge_hops_are_skipped_and_client_supplied_entries_ignored():
    # Visitor -> Cloudflare edge (172.70.x) -> ingress: the edge appended the visitor.
    assert resolve("10.1.0.12", {"X-Forwarded-For": "198.51.100.7, 172.70.33.2"}) == "198.51.100.7"
    # A value the visitor sent themselves sits left of their real address.
    assert resolve("10.1.0.12", {"X-Forwarded-For": "1.2.3.4, 198.51.100.7, 172.70.33.2"}) == "198.51.100.7"
    # With Cloudflare trust disabled the edge itself is the outermost untrusted hop.
    assert resolve("10.1.0.12", {"X-Forwarded-For": "198.51.100.7, 172.70.33.2"}, TRUST_CLOUDFLARE_PROXY="false") == "172.70.33.2"


def test_configured_client_ip_header_is_honored_only_from_a_trusted_proxy():
    headers = {"CF-Connecting-IP": "2001:db8::7", "X-Forwarded-For": "10.9.9.9"}
    assert resolve("10.1.0.12", headers, CLIENT_IP_HEADER="CF-Connecting-IP") == "2001:db8::7"
    assert resolve("10.1.0.12", {"X-Forwarded-For": "[2001:db8::8]:443"}) == "2001:db8::8"
    assert resolve("10.1.0.12", {"X-Forwarded-For": "garbage"}) == "10.1.0.12"


def test_extra_trusted_networks_cover_an_external_load_balancer():
    headers = {"X-Forwarded-For": "198.51.100.7"}
    assert resolve("203.0.113.50", headers) == "203.0.113.50"
    assert resolve("203.0.113.50", headers, TRUSTED_PROXY_CIDRS="203.0.113.0/24") == "198.51.100.7"


@pytest.mark.parametrize("headers,expected", [
    ({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
      "Sec-CH-UA-Platform-Version": '"15.0.0"', "Sec-CH-UA-Arch": '"x86"', "Sec-CH-UA-Bitness": '"64"',
      "Sec-CH-UA-Full-Version-List": '"Google Chrome";v="141.0.7390.54", "Chromium";v="141.0.7390.54"'},
     "Chrome 141 on Windows 11 (x86 64-bit)"),
    ({"User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
      "Sec-CH-UA-Model": '"Pixel 8"', "Sec-CH-UA-Platform-Version": '"15.0.0"'},
     "Chrome 141 on Android 15 · Pixel 8"),
    ({"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"},
     "Safari 18 on iOS 18.1 · iPhone"),
    ({"User-Agent": "ServiceOps/1.3.2 (iPhone; iOS 18.1)", "X-Device-Name": "Anushka's iPhone<script>"},
     "Browser on iOS 18.1 · iPhone · reported as Anushkas iPhonescript"),
])
def test_device_labels_are_specific_to_the_device(headers, expected):
    assert describe_device(headers) == expected


def test_location_comes_from_cloudflare_visitor_headers():
    assert client_location({"CF-IPCountry": "jp"}) == "JP"
    assert client_location({"CF-IPCountry": "JP", "CF-IPCity": "Tokyo", "CF-Region-Code": "13"}) == "Tokyo, 13, JP"
    assert client_location({"CF-IPCountry": "XX"}) is None and client_location({}) is None


def test_reverse_dns_is_bounded_and_cached(monkeypatch):
    calls = []

    def slow(address):
        calls.append(address)
        time.sleep(3)
        return "laptop.example"

    monkeypatch.setattr(app_module, "resolve_hostname", slow)
    monkeypatch.setattr(app_module, "setting_bool", lambda key, default=False: True)
    app_module._hostname_cache.clear()
    started = time.monotonic()
    assert app_module.verified_client_hostname("192.0.2.44") is None
    assert time.monotonic() - started < 2
    assert app_module.verified_client_hostname("192.0.2.44") is None  # cached: no second lookup
    assert calls == ["192.0.2.44"]

    monkeypatch.setattr(app_module, "resolve_hostname", lambda address: "ws-17.corp.example")
    monkeypatch.setattr(app_module, "resolve_ip", lambda hostname: ["192.0.2.45"])
    assert app_module.verified_client_hostname("192.0.2.45") == "ws-17.corp.example"
    monkeypatch.setattr(app_module, "resolve_ip", lambda hostname: ["192.0.2.99"])  # PTR not confirmed forward
    assert app_module.verified_client_hostname("192.0.2.46") is None


def test_login_session_records_the_real_client_behind_the_ingress(monkeypatch):
    from app import UserSession, create_app, db
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    with tempfile.NamedTemporaryFile(suffix=".db") as handle:
        proxied = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{handle.name}"})
        client = proxied.test_client()
        headers = {"X-Forwarded-For": "198.51.100.7, 172.70.33.2", "CF-IPCountry": "JP",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"}
        client.post("/login", data={"username": "admin", "password": "Admin123!"}, headers=headers,
                    environ_base={"REMOTE_ADDR": "10.1.0.12"})
        response = client.get("/", headers=headers, environ_base={"REMOTE_ADDR": "10.1.0.12"})
        assert "Sec-CH-UA-Model" in response.headers.get("Accept-CH", "")
        with proxied.app_context():
            record = UserSession.query.order_by(UserSession.id.desc()).first()
            assert record.ip_address == "198.51.100.7"
            assert record.device_label == "Chrome 141 on Windows 10"
            db.session.remove()
