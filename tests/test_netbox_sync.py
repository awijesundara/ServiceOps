"""Tests for the NetBox CMDB sync (serviceops_core/netbox_sync.py).

These mock NetBox entirely (no live NetBox instance required) by passing a
fake session factory into sync_from_netbox, matching the same
network-mocking approach used by tests/test_ldap_sync.py.
"""
import os
import tempfile

import pytest

from app import ConfigurationItem, PlatformSetting, Rack, Tenant, create_app, db
from serviceops_core.netbox_sync import NetboxSyncError, _netbox_session, _paginate, sync_from_netbox


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
    def __init__(self, payload, *, is_redirect=False):
        self._payload = payload
        self.is_redirect = is_redirect

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeSession:
    """Serves one page of results per endpoint path, ignoring pagination
    params (tests use small fixed device/VM lists)."""

    def __init__(self, devices=None, vms=None, interfaces=None, console_ports=None,
                 power_ports=None, inventory_items=None, racks=None):
        self._pages = {
            "/api/dcim/devices/": {"results": devices or [], "next": None},
            "/api/virtualization/virtual-machines/": {"results": vms or [], "next": None},
            "/api/dcim/interfaces/": {"results": interfaces or [], "next": None},
            "/api/dcim/console-ports/": {"results": console_ports or [], "next": None},
            "/api/dcim/power-ports/": {"results": power_ports or [], "next": None},
            "/api/dcim/inventory-items/": {"results": inventory_items or [], "next": None},
            "/api/dcim/racks/": {"results": racks or [], "next": None},
        }

    def get(self, url, params=None, timeout=None, allow_redirects=None):
        for path, payload in self._pages.items():
            if url.endswith(path):
                return FakeResponse(payload)
        return FakeResponse({"results": [], "next": None})

    def close(self):
        pass


def enable_netbox(devices=None, vms=None, monkeypatch=None, interfaces=None,
                   console_ports=None, power_ports=None, inventory_items=None, racks=None):
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
        monkeypatch.setattr(core_app, "integration_endpoint_resolves_safely", lambda url, **kwargs: True)

    def fake_session_factory(base_url, token):
        return FakeSession(
            devices=devices, vms=vms, interfaces=interfaces, console_ports=console_ports,
            power_ports=power_ports, inventory_items=inventory_items, racks=racks,
        )

    return fake_session_factory


def make_device(id_, name, serial="", status="active", manufacturer="Dell", model="R640",
                 ip="10.0.0.1/24", site="CC1", location="9D-Row", role=None, rack_id=None,
                 position=None, u_height=None, face=None):
    return {
        "id": id_, "name": name, "serial": serial,
        "status": {"value": status},
        "device_type": {"manufacturer": {"name": manufacturer}, "model": model, "u_height": u_height},
        "primary_ip4": {"address": ip} if ip else None,
        "site": {"name": site} if site else None,
        "location": {"name": location} if location else None,
        "role": {"name": role} if role else None,
        "rack": {"id": rack_id} if rack_id else None,
        "position": position,
        "face": {"value": face} if face else None,
    }


def make_rack(id_, name, site="CC1", u_height=42):
    return {"id": id_, "name": name, "site": {"name": site} if site else None, "u_height": u_height}


def make_vm(id_, name, status="active", platform="Ubuntu", cluster="compute-a", site="CC1"):
    return {
        "id": id_, "name": name, "status": {"value": status, "label": status.title()},
        "platform": {"name": platform} if platform else None,
        "cluster": {"name": cluster} if cluster else None,
        "site": {"name": site} if site else None,
        "primary_ip4": {"address": "10.0.1.1/24"},
    }


def test_creates_new_ci_from_device(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "srv-01", serial="ABC123")
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, session_factory=factory)
        assert result["cis_created"] == 1
        assert result["devices_seen"] == 1
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
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
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        assert ci.name == "srv-01-renamed"
        assert ci.operational_status == "Down"
        assert ci.lifecycle_state == "In Use"


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
        assert ci.external_id == "dcim.device:101"


def test_extra_netbox_fields_are_captured_as_attributes(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "srv-01", serial="ABC123", position=2.0)
        device.update({
            "tenant": {"name": "CoreApps"}, "role": {"name": "server:linux"},
            "platform": {"name": "CentOS Linux 7"},
            "status": {"value": "active", "label": "Active"},
            "oob_ip": {"address": "10.68.88.51/24"},
            "tags": [{"name": "env:dev"}],
            "comments": "handles batch jobs",
            "custom_fields": {"end_of_support": "2022-11-18", "environment": "Development", "empty_field": None},
        })
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        # Rack/position are now structured columns, not free-text attributes
        # (see test_device_rack_position_face_and_role_are_synced below).
        assert "NetBox: Rack" not in ci.attributes
        assert "NetBox: Position" not in ci.attributes
        assert ci.rack_position == 2.0
        assert ci.attributes["NetBox: Tenant"] == "CoreApps"
        assert ci.attributes["NetBox: Role"] == "server:linux"
        assert ci.attributes["NetBox: Platform"] == "CentOS Linux 7"
        assert ci.attributes["NetBox: Out-of-band IP"] == "10.68.88.51"
        assert ci.attributes["NetBox: Tags"] == "env:dev"
        assert ci.attributes["NetBox: Comments"] == "handles batch jobs"
        assert ci.attributes["NetBox: End Of Support"] == "2022-11-18"
        assert ci.attributes["NetBox: Environment"] == "Development"
        assert "NetBox: Empty Field" not in ci.attributes


def test_resync_refreshes_netbox_attributes_without_dropping_csv_attributes(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "srv-01", serial="ABC123")
        device["comments"] = "first sync"
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        ci.attributes = {**ci.attributes, "Builder": "William Yao"}
        db.session.commit()

        device["comments"] = "second sync"
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        assert ci.attributes["NetBox: Comments"] == "second sync"
        assert ci.attributes["Builder"] == "William Yao"


def test_device_rack_position_face_and_role_are_synced(app, monkeypatch):
    with app.app_context():
        rack = make_rack(5, "9D05", site="CC1", u_height=42)
        device = make_device(
            101, "srv-01", serial="ABC123", role="Switch", rack_id=5,
            position=12.0, u_height=2, face="front",
        )
        factory = enable_netbox(devices=[device], racks=[rack], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, session_factory=factory)
        assert result["racks_created"] == 1
        local_rack = Rack.query.filter_by(external_id="dcim.rack:5").one()
        assert (local_rack.name, local_rack.site, local_rack.u_height) == ("9D05", "CC1", 42)
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        assert ci.ci_class == "Switch"
        assert ci.rack_id == local_rack.id
        assert ci.rack_position == 12.0
        assert ci.rack_u_height == 2
        assert ci.rack_face == "front"


def test_device_without_role_uses_neutral_device_ci_class(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "srv-01", serial="ABC123")
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        assert ci.ci_class == "Device"


def test_device_and_vm_with_same_netbox_numeric_id_remain_distinct(app, monkeypatch):
    with app.app_context():
        factory = enable_netbox(
            devices=[make_device(101, "physical-101", serial="P101")],
            vms=[make_vm(101, "virtual-101")], monkeypatch=monkeypatch,
        )
        result = sync_from_netbox(1, session_factory=factory)
        assert result["devices_seen"] == 1
        assert result["virtual_machines_seen"] == 1
        assert ConfigurationItem.query.count() == 2
        assert ConfigurationItem.query.filter_by(external_id="dcim.device:101").one().name == "physical-101"
        assert ConfigurationItem.query.filter_by(
            external_id="virtualization.virtualmachine:101"
        ).one().name == "virtual-101"


def test_vm_platform_and_cluster_are_attributes_not_model_and_location(app, monkeypatch):
    with app.app_context():
        vm = make_vm(22, "app-vm", platform="Red Hat Enterprise Linux", cluster="prod-esxi", site="DC-East")
        vm.update({"type": {"name": "General purpose"}, "device": {"name": "esxi-07"}, "disk": 40960})
        factory = enable_netbox(vms=[vm], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        ci = ConfigurationItem.query.filter_by(external_id="virtualization.virtualmachine:22").one()
        assert ci.ci_class == "Virtual Machine"
        assert ci.model is None
        assert ci.location == "DC-East"
        assert ci.attributes["NetBox: Platform"] == "Red Hat Enterprise Linux"
        assert ci.attributes["NetBox: Cluster"] == "prod-esxi"
        assert ci.attributes["NetBox: Host Device"] == "esxi-07"
        assert ci.attributes["NetBox: Type"] == "General purpose"
        assert ci.attributes["NetBox: Disk (MB)"] == 40960


def test_status_and_environment_map_to_controlled_cmdb_values(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "staged-01", status="staged", role="linux-server")
        device["custom_fields"] = {"environment": {"value": "preprod", "label": "Pre-production"}}
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        assert ci.ci_class == "Server"
        assert ci.operational_status == "Maintenance"
        assert ci.lifecycle_state == "Planned"
        assert ci.environment == "Staging"


def test_resync_clears_removed_netbox_owned_values(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "srv-01", serial="ABC123", rack_id=None)
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        device.update({"serial": "", "primary_ip4": None, "location": None, "device_type": None})
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        assert (ci.serial_number, ci.ip_address, ci.location, ci.vendor, ci.model) == (None, None, "CC1", None, None)


def test_legacy_untyped_external_id_is_migrated_only_when_identity_matches(app, monkeypatch):
    with app.app_context():
        db.session.add(ConfigurationItem(
            name="srv-01", ci_class="Server", serial_number="ABC123", tenant_id=1,
            external_source="netbox", external_id="101",
        ))
        db.session.commit()
        factory = enable_netbox(devices=[make_device(101, "srv-01", serial="ABC123")], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        assert ConfigurationItem.query.count() == 1
        assert ConfigurationItem.query.one().external_id == "dcim.device:101"


def test_pagination_advances_by_actual_server_capped_page_size():
    class CappedSession:
        def __init__(self):
            self.offsets = []

        def get(self, url, params=None, timeout=None, allow_redirects=None):
            offset = params["offset"]
            self.offsets.append(offset)
            pages = {
                0: {"results": [{"id": 1}, {"id": 2}], "next": "next"},
                2: {"results": [{"id": 3}, {"id": 4}], "next": "next"},
                4: {"results": [{"id": 5}], "next": None},
            }
            return FakeResponse(pages[offset])

    session = CappedSession()
    assert [row["id"] for row in _paginate(session, "https://netbox.example", "/api/dcim/devices/")] == [1, 2, 3, 4, 5]
    assert session.offsets == [0, 2, 4]


def test_api_redirect_is_rejected_instead_of_followed():
    class RedirectSession:
        def get(self, url, params=None, timeout=None, allow_redirects=None):
            assert allow_redirects is False
            return FakeResponse({}, is_redirect=True)

    with pytest.raises(NetboxSyncError, match="redirected"):
        list(_paginate(RedirectSession(), "https://netbox.example", "/api/dcim/devices/"))


def test_component_permission_failure_is_reported_without_losing_devices(app, monkeypatch):
    class PartiallyAuthorizedSession(FakeSession):
        def get(self, url, params=None, timeout=None, allow_redirects=None):
            if url.endswith("/api/dcim/interfaces/"):
                import requests
                raise requests.HTTPError("403 Forbidden")
            return super().get(url, params=params, timeout=timeout, allow_redirects=allow_redirects)

    with app.app_context():
        enable_netbox(monkeypatch=monkeypatch)
        factory = lambda base_url, token: PartiallyAuthorizedSession(  # noqa: E731
            devices=[make_device(101, "srv-01")]
        )
        result = sync_from_netbox(1, session_factory=factory)
        assert result["cis_created"] == 1
        assert result["warnings"] == ["Interfaces were not imported: HTTPError"]


def test_custom_status_preserves_existing_controlled_status(app, monkeypatch):
    with app.app_context():
        db.session.add(ConfigurationItem(
            name="srv-01", ci_class="Server", tenant_id=1,
            operational_status="Operational", lifecycle_state="Maintenance",
        ))
        db.session.commit()
        device = make_device(101, "srv-01", status="awaiting-customer", role="sandbox appliance")
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        assert ci.ci_class == "Device"
        assert ci.operational_status == "Operational"
        assert ci.lifecycle_state == "Maintenance"


def test_rack_resync_updates_existing_rack_by_external_id(app, monkeypatch):
    with app.app_context():
        rack = make_rack(5, "9D05", site="CC1", u_height=42)
        factory = enable_netbox(racks=[rack], monkeypatch=monkeypatch)
        sync_from_netbox(1, session_factory=factory)
        assert Rack.query.count() == 1

        rack["u_height"] = 47
        factory = enable_netbox(racks=[rack], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, session_factory=factory)
        assert result["racks_created"] == 0
        assert result["racks_updated"] == 1
        assert Rack.query.count() == 1
        assert Rack.query.filter_by(external_id="dcim.rack:5").one().u_height == 47


def test_device_components_are_captured_as_attribute_summaries(app, monkeypatch):
    with app.app_context():
        device = make_device(101, "srv-01", serial="ABC123")
        interfaces = [
            {"device": {"id": 101}, "name": "bond0", "type": {"label": "Link Aggregation Group (LAG)"}},
            {"device": {"id": 101}, "name": "em1", "type": {"label": "SFP+ (10GE)"},
             "mac_address": "AA:BB:CC:DD:EE:FF", "lag": {"name": "bond0"}, "enabled": False},
            {"device": {"id": 999}, "name": "other-device-nic"},
        ]
        console_ports = [{"device": {"id": 101}, "name": "Serial", "type": {"label": "DE-9"}}]
        power_ports = [{"device": {"id": 101}, "name": "Power 1", "type": {"label": "C14"}, "maximum_draw": 750}]
        inventory_items = [{"device": {"id": 101}, "name": "onload-dkms", "role": {"name": "pkg:rpm"}}]
        factory = enable_netbox(
            devices=[device], monkeypatch=monkeypatch, interfaces=interfaces,
            console_ports=console_ports, power_ports=power_ports, inventory_items=inventory_items,
        )
        sync_from_netbox(1, session_factory=factory)
        ci = ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()
        assert ci.attributes["NetBox: Interfaces"] == (
            "bond0 (Link Aggregation Group (LAG)); em1 (SFP+ (10GE), AA:BB:CC:DD:EE:FF, in bond0, disabled)"
        )
        assert ci.attributes["NetBox: Console Ports"] == "Serial (DE-9)"
        assert ci.attributes["NetBox: Power Ports"] == "Power 1 (C14, 750W)"
        assert ci.attributes["NetBox: Inventory Items"] == "onload-dkms (pkg:rpm)"


def test_device_without_serial_adopts_existing_ci_by_name(app, monkeypatch):
    with app.app_context():
        db.session.add(ConfigurationItem(
            name="srv-01", ci_class="Server", tenant_id=1, external_source="csv",
        ))
        db.session.commit()
        device = make_device(101, "srv-01", serial="")
        factory = enable_netbox(devices=[device], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, session_factory=factory)
        assert result["cis_created"] == 0
        assert result["cis_updated"] == 1
        assert ConfigurationItem.query.filter_by(name="srv-01").count() == 1
        ci = ConfigurationItem.query.filter_by(name="srv-01").one()
        assert ci.external_source == "netbox"
        assert ci.external_id == "dcim.device:101"


def test_one_bad_record_does_not_abort_the_batch(app, monkeypatch):
    with app.app_context():
        good = make_device(101, "srv-01", serial="ABC123")
        bad = {"id": 102, "name": None}  # missing device_type/status -> should still map, not crash
        factory = enable_netbox(devices=[good, bad], monkeypatch=monkeypatch)
        result = sync_from_netbox(1, session_factory=factory)
        assert result["devices_seen"] == 2
        assert result["cis_created"] >= 1
        assert ConfigurationItem.query.filter_by(external_id="dcim.device:101").one()


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


def test_session_verifies_with_default_bundle_when_no_ca_cert_configured(app):
    with app.app_context():
        session = _netbox_session("https://netbox.example.com", "token")
        assert session.verify is True


def test_session_uses_bearer_for_v2_token_and_token_for_legacy_token(app):
    with app.app_context():
        modern = _netbox_session("https://netbox.example.com", "nbt_key.secret")
        legacy = _netbox_session("https://netbox.example.com", "legacy-secret")
        assert modern.headers["Authorization"] == "Bearer nbt_key.secret"
        assert legacy.headers["Authorization"] == "Token legacy-secret"


def test_session_verifies_against_configured_internal_ca(app):
    with app.app_context():
        pem = "-----BEGIN CERTIFICATE-----\nMIIB...fake...\n-----END CERTIFICATE-----\n"
        db.session.add(PlatformSetting(key="NETBOX_CA_CERT", value=pem, encrypted=False))
        db.session.commit()
        session = _netbox_session("https://netbox.example.com", "token")
        assert session.verify != True  # noqa: E712 - must be a path, not the bool default
        with open(session.verify) as handle:
            assert handle.read() == pem.strip()
        os.unlink(session.verify)


def test_session_skips_verification_when_insecure_opt_in_is_set(app):
    with app.app_context():
        db.session.add(PlatformSetting(key="NETBOX_TLS_INSECURE", value="true", encrypted=False))
        db.session.commit()
        session = _netbox_session("https://netbox.example.com", "token")
        assert session.verify is False


def test_ca_cert_takes_priority_over_insecure_opt_in(app):
    with app.app_context():
        pem = "-----BEGIN CERTIFICATE-----\nMIIB...fake...\n-----END CERTIFICATE-----\n"
        db.session.add(PlatformSetting(key="NETBOX_CA_CERT", value=pem, encrypted=False))
        db.session.add(PlatformSetting(key="NETBOX_TLS_INSECURE", value="true", encrypted=False))
        db.session.commit()
        session = _netbox_session("https://netbox.example.com", "token")
        assert session.verify != False  # noqa: E712 - CA path wins, not blanket bypass
        os.unlink(session.verify)
