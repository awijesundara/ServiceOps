"""Per-component outbound proxy policy.

Every outbound component configured through platform settings (NetBox,
Request Tracker, the Google Chat bot, iOS push, object storage, Cloudflare
Access, spreadsheet import and the update check) lets an administrator
inherit the system default proxy, connect directly, or use its own proxy,
the same choice AI models and notification channels already had."""
import pytest

from app import (PlatformSetting, db, describe_component_egress, object_storage_client,
                 resolve_component_proxies, resolve_component_proxy_url, resolve_smtp_proxy_url,
                 settings_cipher, setting_value)
from serviceops_core.config_schema import SETTING_DEFINITIONS, find_setting_definition
from serviceops_core.netbox_sync import _netbox_session
from serviceops_core.rt_import import _rt_session
from tests.test_app import app, client, login  # noqa: F401  (pytest fixtures)

DEFAULT_PROXY = "http://default-proxy:3128"
COMPONENT_PREFIXES = ("NETBOX", "RT", "GOOGLE_CHAT", "APNS", "UPDATE_CHECK", "OBJECT_STORAGE",
                      "CLOUDFLARE_ACCESS", "CMDB_IMPORT")


def put_setting(key, value, encrypted=False):
    stored = settings_cipher().encrypt(value.encode()).decode() if encrypted else value
    row = db.session.get(PlatformSetting, key)
    if row is None:
        row = PlatformSetting(key=key, tenant_id=1)
        db.session.add(row)
    row.value, row.encrypted = stored, encrypted
    db.session.commit()


@pytest.mark.parametrize("prefix", COMPONENT_PREFIXES)
def test_every_component_exposes_a_proxy_choice_defaulting_to_the_system_proxy(prefix):
    mode = find_setting_definition(f"{prefix}_PROXY_MODE")
    url = find_setting_definition(f"{prefix}_PROXY_URL")
    assert mode["choices"] == ["default", "none", "custom"] and mode["default"] == "default"
    assert url["type"] == "secret", "custom proxy URLs can carry credentials"


def test_component_policy_precedence_default_none_custom(app):
    with app.app_context():
        assert resolve_component_proxy_url("NETBOX") is None
        put_setting("OUTBOUND_PROXY_URL", DEFAULT_PROXY)
        assert resolve_component_proxy_url("NETBOX") == DEFAULT_PROXY
        assert describe_component_egress("NETBOX") == "the system default proxy"
        put_setting("NETBOX_PROXY_MODE", "none")
        assert resolve_component_proxy_url("NETBOX") is None
        assert describe_component_egress("NETBOX") == "a direct connection"
        put_setting("NETBOX_PROXY_MODE", "custom")
        put_setting("NETBOX_PROXY_URL", "http://user:pw@netbox-proxy:8080", encrypted=True)
        assert resolve_component_proxies("NETBOX") == {
            "http": "http://user:pw@netbox-proxy:8080", "https": "http://user:pw@netbox-proxy:8080",
        }
        assert describe_component_egress("NETBOX") == "its custom proxy"
        # One component's choice never leaks into another's.
        assert resolve_component_proxy_url("RT") == DEFAULT_PROXY


def test_malformed_custom_proxy_falls_back_to_direct(app):
    with app.app_context():
        put_setting("RT_PROXY_MODE", "custom")
        put_setting("RT_PROXY_URL", "socks5://host:1080", encrypted=True)
        assert resolve_component_proxy_url("RT") is None


def test_smtp_keeps_its_existing_policy(app):
    with app.app_context():
        put_setting("OUTBOUND_PROXY_URL", DEFAULT_PROXY)
        put_setting("SMTP_PROXY_MODE", "custom")
        put_setting("SMTP_PROXY_URL", "http://mail-proxy:8080")
        assert resolve_smtp_proxy_url() == "http://mail-proxy:8080"


def test_netbox_session_follows_the_netbox_policy(app):
    with app.app_context():
        put_setting("OUTBOUND_PROXY_URL", DEFAULT_PROXY)
        assert _netbox_session("https://netbox.example.com", "token").proxies["https"] == DEFAULT_PROXY
        put_setting("NETBOX_PROXY_MODE", "none")
        session = _netbox_session("https://netbox.example.com", "token")
        assert "https" not in session.proxies and session.trust_env is False
        put_setting("NETBOX_PROXY_MODE", "custom")
        put_setting("NETBOX_PROXY_URL", "http://netbox-proxy:8080", encrypted=True)
        assert _netbox_session("https://netbox.example.com", "token").proxies["https"] == "http://netbox-proxy:8080"


def test_rt_session_follows_the_rt_policy(app):
    with app.app_context():
        put_setting("OUTBOUND_PROXY_URL", DEFAULT_PROXY)
        put_setting("RT_PROXY_MODE", "none")
        assert "https" not in _rt_session("https://rt.example.com", "token").proxies


def test_object_storage_client_follows_its_policy(app):
    with app.app_context():
        put_setting("OUTBOUND_PROXY_URL", DEFAULT_PROXY)
        put_setting("OBJECT_STORAGE_PROXY_MODE", "custom")
        put_setting("OBJECT_STORAGE_PROXY_URL", "http://s3-proxy:8080", encrypted=True)
        assert object_storage_client().meta.config.proxies == {
            "http": "http://s3-proxy:8080", "https": "http://s3-proxy:8080",
        }
        put_setting("OBJECT_STORAGE_PROXY_MODE", "none")
        assert object_storage_client().meta.config.proxies == {}


def test_admin_can_choose_and_clear_a_custom_netbox_proxy(client, app):
    login(client, "admin", "Admin123!")
    page = client.get("/admin/settings/netbox_connection")
    assert page.status_code == 200
    assert b"NetBox proxy" in page.data and b"Connect directly (no proxy)" in page.data

    # Custom mode with no URL is refused rather than silently going direct.
    client.post("/admin/settings/netbox_connection", data={"NETBOX_PROXY_MODE": "custom"})
    with app.app_context():
        assert setting_value("NETBOX_PROXY_MODE", "default") == "default"

    client.post("/admin/settings/netbox_connection", data={"NETBOX_PROXY_URL": "ftp://nope"})
    with app.app_context():
        assert setting_value("NETBOX_PROXY_URL", "") == ""

    client.post("/admin/settings/netbox_connection", data={
        "NETBOX_PROXY_MODE": "custom", "NETBOX_PROXY_URL": "http://user:pw@netbox-proxy:8080",
    })
    with app.app_context():
        assert setting_value("NETBOX_PROXY_MODE", "") == "custom"
        row = db.session.get(PlatformSetting, "NETBOX_PROXY_URL")
        assert row.encrypted is True and "netbox-proxy" not in row.value
        assert resolve_component_proxy_url("NETBOX") == "http://user:pw@netbox-proxy:8080"
    assert b"Remove this custom proxy" in client.get("/admin/settings/netbox_connection").data

    # Clearing the URL while still in custom mode is refused as a whole.
    client.post("/admin/settings/netbox_connection", data={
        "NETBOX_PROXY_MODE": "custom", "NETBOX_PROXY_URL_CLEAR": "on",
    })
    with app.app_context():
        assert setting_value("NETBOX_PROXY_URL", "") == "http://user:pw@netbox-proxy:8080"

    client.post("/admin/settings/netbox_connection", data={
        "NETBOX_PROXY_MODE": "none", "NETBOX_PROXY_URL_CLEAR": "on",
    })
    with app.app_context():
        assert setting_value("NETBOX_PROXY_MODE", "") == "none"
        assert setting_value("NETBOX_PROXY_URL", "") == ""


def test_rt_page_renders_the_proxy_choice(client):
    login(client, "admin", "Admin123!")
    assert "RT_PROXY_MODE" in {item["key"] for item in SETTING_DEFINITIONS["request_tracker_connection"]}
    page = client.get("/tickets/import/rt")
    assert page.status_code == 200
    assert b'name="RT_PROXY_MODE"' in page.data
