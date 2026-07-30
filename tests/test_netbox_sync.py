"""Tests for the NetBox CMDB sync (serviceops_core/netbox_sync.py).

These mock NetBox entirely (no live NetBox instance required) by passing a
fake session factory into sync_from_netbox, matching the same
network-mocking approach used by tests/test_ldap_sync.py.
"""
import os
import tempfile

import pytest

from app import ConfigurationItem, PlatformSetting, Tenant, create_app, db
from serviceops_core.netbox_sync import NetboxSyncError, sync_from_netbox


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        db.session.commit()
    yield app
    os.unlink(path)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeSession:
    """Serves one page of results per endpoint path, ignoring pagination
    params (tests use small fixed device/VM lists)."""

    def __init__(self, devices=None, vms=None):
        self._pages = {
            "/api/dcim/devices/": {"results": devices or [], "next": None},
            "/api/virtualization/virtual-machines/": {"results": vms or [], "next": None},
        }

    def get(self, url, params=None, timeout=None):
        for path, payload in self._pages.items():
            if url.endswith(path):
                return FakeResponse(payload)
        return FakeResponse({"results": [], "next": None})

    def close(self):
        pass


def enable_netbox(devices=None, vms=None, monkeypatch=None):
    for key, value in (
        ("NETBOX_ENABLED", "true"),
        ("NETBOX_BASE_URL", "https://netbox.example.com"),
        ("NETBOX_API_TOKEN", "test-token"),
    ):
        existing = db.session.get(PlatformSetting, key)
        if existing:
            existing.value = value
        else:
            db.session.add(PlatformSetting(key=key, value=value, encrypted=False))
    db.session.commit()

    # No live network/DNS in the test environment: the DNS-rebinding re-check
    # (app.integration_endpoint_resolves_safely) is mocked to pass, since the
    # actual HTTP calls are mocked too via session_factory below.
    if monkeypatch is not None:
        import app as core_app
        monkeypatch.setattr(core_app, "integration_endpoint_resolves_safely", lambda url: True)

    def fake_session_factory(base_url, token):
        return FakeSession(devices=devices, vms=vms)

    return fake_session_factory


def make_device(id_, name, serial="", status="active", manufacturer="Dell", model="R640",
                 ip="10.0.0.1/24", site="CC1", location="9D-Row"):
    return {
        "id": id_, "name": name, "serial": serial,
        "status": {"value": status},
        "device_type": {"manufacturer": {"name": manufacturer}, "model": model},
        "primary_ip4": {"address": ip} if ip else None,
        "site": {"name": site} if site else None,
        "location": {"name": location} if location else None,
    }


def test_creates_new_ci_from_device(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "srv-01", serial="ABC123")
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, session_factory=factory)
        assert result["cis_created"] == 1
        assert result["devices_seen"] == 1
        ci = ConfigurationItem.query.filter_by(external_id="101").one()
        assert ci.name == "srv-01"
        assert ci.serial_number == "ABC123"
        assert ci.vendor == "Dell"
        assert ci.model == "R640"
        assert ci.ip_address == "10.0.0.1"
        assert ci.location == "CC1 / 9D-Row"
        assert ci.discovery_source == "API"
        assert ci.external_source == "netbox"


def test_resync_updates_matched_ci_idempotently(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "srv-01", serial="ABC123")
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        assert ConfigurationItem.query.count() == 1

        device["name"] = "srv-01-renamed"
        device["status"] = {"value": "offline"}
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, session_factory=factory)
        assert result["cis_created"] == 0
        assert result["cis_updated"] == 1
        assert ConfigurationItem.query.count() == 1
        ci = ConfigurationItem.query.filter_by(external_id="101").one()
        assert ci.name == "srv-01-renamed"
        assert ci.operational_status == "Retired"


def test_adopts_existing_manual_ci_by_serial_number(app, monkeypatch):
    with app.app_context():
        db.session.add(ConfigurationItem(
            name="manually-entered", ci_class="Server", serial_number="ABC123", tenant_id=1,
        ))
        db.session.commit()
        device = make_device(101, "srv-01", serial="ABC123")
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, session_factory=factory)
        assert result["cis_updated"] == 1
        assert result["cis_matched_by_serial"] == 1
        assert ConfigurationItem.query.count() == 1
        ci = ConfigurationItem.query.filter_by(serial_number="ABC123").one()
        assert ci.name == "srv-01"
        assert ci.external_source == "netbox"
        assert ci.external_id == "101"


def test_one_bad_record_does_not_abort_the_batch(app, monkeypatch):
    with app.app_context():
        good = make_device(101, "srv-01", serial="ABC123")
        bad = {"id": 102, "name": None}  # missing device_type/status -> should still map, not crash
        factory = enable_netbox(devices=[good, bad], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, session_factory=factory)
        assert result["devices_seen"] == 2
        assert result["cis_created"] >= 1
        assert ConfigurationItem.query.filter_by(external_id="101").one()


def test_dry_run_does_not_commit(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "srv-01", serial="ABC123")
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, dry_run=True, session_factory=factory)
        assert result["dry_run"] is True
        assert ConfigurationItem.query.count() == 0


def test_disabled_fails_closed(app, monkeypatch):
    with app.app_context():
        db.session.add(PlatformSetting(key="NETBOX_BASE_URL", value="https://example.com", encrypted=False))
        db.session.add(PlatformSetting(key="NETBOX_API_TOKEN", value="token", encrypted=False))
        db.session.commit()
        with pytest.raises(NetboxSyncError):
            sync_from_netbox(1)


def test_missing_or_invalid_tenant_id_fails_closed(app, monkeypatch):
    with app.app_context():
        enable_netbox(devices=[], monkeypatch=monkeypatch)
        with pytest.raises(NetboxSyncError):
            sync_from_netbox(None)
        with pytest.raises(NetboxSyncError):
            sync_from_netbox(999999)
