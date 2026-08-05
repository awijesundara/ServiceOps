"""Unit tests for serviceops_core/network_discovery.py's pure functions
(vendor/class guessing) and reconciliation logic. discover_host/discover_subnet
themselves are network I/O and are exercised via mocked facts here rather than
a real SNMP device -- see tests/test_app.py's cmdb_discovery route tests for
the HTTP-level flow with discover_host/discover_subnet monkeypatched."""
import os
import tempfile

import pytest

from app import CIRelationship, ConfigurationItem, create_app, db
from serviceops_core.network_discovery import (
    _format_ipv4, _format_mac, guess_ci_class, guess_vendor, probe_host,
    reconcile_facts_into_cmdb, tcp_liveness_probe,
)


class _FakeOctetString:
    """Stands in for pysnmp's OctetString/IpAddress: str() on the real thing
    gives mangled, unreadable characters for binary content (confirmed
    against a real Brother-branded network printer during validation) --
    the only correct way to get the actual bytes is .asOctets()."""
    def __init__(self, raw_bytes):
        self._raw = raw_bytes

    def asOctets(self):
        return self._raw

    def __str__(self):
        return self._raw.decode("latin-1")


def test_format_mac_renders_six_byte_octet_string_as_colon_hex():
    raw = bytes([0x50, 0xC2, 0xE8, 0xA8, 0x28, 0x60])
    assert _format_mac(_FakeOctetString(raw)) == "50:c2:e8:a8:28:60"


def test_format_ipv4_renders_four_byte_octet_string_as_dotted_decimal():
    raw = bytes([192, 168, 68, 1])
    assert _format_ipv4(_FakeOctetString(raw)) == "192.168.68.1"


def test_format_mac_and_ipv4_fall_back_to_str_for_non_octet_values():
    assert _format_mac("already-a-string") == "already-a-string"
    assert _format_ipv4("already-a-string") == "already-a-string"
    assert _format_mac(_FakeOctetString(b"")) == ""  # empty address, e.g. a loopback interface


def test_guess_vendor_matches_known_enterprise_prefixes():
    assert guess_vendor("1.3.6.1.4.1.9.1.1208") == "Cisco"
    assert guess_vendor("1.3.6.1.4.1.2636.1.1.1.2.57") == "Juniper"
    assert guess_vendor("1.3.6.1.4.1.2435.2.3.9.1") == "Brother"
    assert guess_vendor("") == ""
    assert guess_vendor("1.3.6.1.4.1.99999.1") == ""


def test_tcp_liveness_probe_true_when_a_port_connects(monkeypatch):
    import socket as socket_module

    class FakeSocket:
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def settimeout(self, value):
            pass
        def connect_ex(self, address):
            return 0 if address[1] == 443 else 111  # 111 == ECONNREFUSED on Linux

    monkeypatch.setattr(socket_module, "socket", lambda *a, **k: FakeSocket())
    assert tcp_liveness_probe("10.0.0.5", ports=(80, 443)) is True


def test_tcp_liveness_probe_false_when_everything_times_out(monkeypatch):
    import socket as socket_module

    class FakeSocket:
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def settimeout(self, value):
            pass
        def connect_ex(self, address):
            raise socket_module.timeout("timed out")

    monkeypatch.setattr(socket_module, "socket", lambda *a, **k: FakeSocket())
    assert tcp_liveness_probe("10.0.0.250", ports=(80, 443, 22)) is False


def test_probe_host_falls_back_to_bare_liveness_when_snmp_silent(monkeypatch):
    monkeypatch.setattr("serviceops_core.network_discovery.discover_host", lambda *a, **k: None)
    monkeypatch.setattr("serviceops_core.network_discovery.tcp_liveness_probe", lambda *a, **k: True)
    facts = probe_host("10.0.0.9", "public")
    assert facts["host"] == "10.0.0.9"
    assert facts["discovery_source"] == "Network sweep (no SNMP)"
    assert facts["ci_class"] == "Device"
    assert facts["interfaces"] == []


def test_probe_host_returns_none_when_neither_snmp_nor_tcp_responds(monkeypatch):
    monkeypatch.setattr("serviceops_core.network_discovery.discover_host", lambda *a, **k: None)
    monkeypatch.setattr("serviceops_core.network_discovery.tcp_liveness_probe", lambda *a, **k: False)
    assert probe_host("10.0.0.250", "public") is None


def test_probe_host_prefers_snmp_detail_over_bare_liveness(monkeypatch):
    monkeypatch.setattr(
        "serviceops_core.network_discovery.discover_host",
        lambda *a, **k: {"host": "10.0.0.9", "sys_name": "real-switch", "ci_class": "Network Switch"},
    )
    facts = probe_host("10.0.0.9", "public")
    assert facts["sys_name"] == "real-switch"
    assert facts["discovery_source"] == "SNMP Discovery"


def test_guess_ci_class_prefers_switch_signals():
    switch_facts = {
        "interfaces": [{"index": str(i), "descr": f"Gi0/{i}"} for i in range(8)],
        "lldp_neighbors": [{"neighbor_name": "core-sw-02", "neighbor_port": "Gi0/1"}],
        "sys_descr": "Cisco IOS Software",
        "vendor": "Cisco",
    }
    assert guess_ci_class(switch_facts) == "Network Switch"

    server_facts = {"interfaces": [{"index": "1", "descr": "eth0"}], "sys_descr": "Linux 6.1.0", "vendor": ""}
    assert guess_ci_class(server_facts) == "Server"

    bare_facts = {"interfaces": [], "sys_descr": "", "vendor": ""}
    assert guess_ci_class(bare_facts) == "Device"


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        db.session.commit()
        yield app
    os.unlink(path)


def test_reconcile_creates_cis_and_connects_to_relationship_from_lldp(app):
    with app.app_context():
        facts_list = [
            {
                "host": "10.0.0.1", "sys_name": "core-switch-1", "sys_descr": "Cisco IOS",
                "sys_object_id": "1.3.6.1.4.1.9.1.1208", "sys_uptime": "12345",
                "vendor": "Cisco", "ci_class": "Network Switch",
                "interfaces": [{"index": "1", "descr": "Gi0/1", "mac_address": "00:11:22:33:44:01"}],
                "arp_entries": [], "lldp_neighbors": [{"neighbor_name": "core-switch-2", "neighbor_port": "Gi0/2"}],
            },
            {
                "host": "10.0.0.2", "sys_name": "core-switch-2", "sys_descr": "Cisco IOS",
                "sys_object_id": "1.3.6.1.4.1.9.1.1208", "sys_uptime": "54321",
                "vendor": "Cisco", "ci_class": "Network Switch",
                "interfaces": [{"index": "1", "descr": "Gi0/2", "mac_address": "00:11:22:33:44:02"}],
                "arp_entries": [], "lldp_neighbors": [{"neighbor_name": "core-switch-1", "neighbor_port": "Gi0/1"}],
            },
        ]
        summary = reconcile_facts_into_cmdb(1, "core stack", facts_list)
        assert summary["created"] == 2
        assert summary["updated"] == 0
        assert summary["relationships_created"] == 1  # one edge, not two, for the mutual pair
        assert summary["errors"] == []

        switch_1 = ConfigurationItem.query.filter_by(ip_address="10.0.0.1").one()
        switch_2 = ConfigurationItem.query.filter_by(ip_address="10.0.0.2").one()
        assert switch_1.name == "core-switch-1"
        assert switch_1.discovery_source == "SNMP Discovery"
        assert switch_1.vendor == "Cisco"
        relationship = CIRelationship.query.one()
        assert relationship.relationship_type == "Connects to"
        assert {relationship.parent_id, relationship.child_id} == {switch_1.id, switch_2.id}


def test_reconcile_never_overwrites_manually_created_ci_identity(app):
    with app.app_context():
        db.session.add(ConfigurationItem(
            name="Hand-classified core switch", ci_class="Network Appliance",
            ip_address="10.0.0.1", vendor="Custom Vendor", discovery_source="Manual",
            tenant_id=1,
        ))
        db.session.commit()

        facts_list = [{
            "host": "10.0.0.1", "sys_name": "core-switch-1", "sys_descr": "Cisco IOS",
            "sys_object_id": "1.3.6.1.4.1.9.1.1208", "sys_uptime": "1",
            "vendor": "Cisco", "ci_class": "Network Switch",
            "interfaces": [], "arp_entries": [], "lldp_neighbors": [],
        }]
        summary = reconcile_facts_into_cmdb(1, "manual override check", facts_list)
        assert summary["created"] == 0
        assert summary["updated"] == 1

        ci = ConfigurationItem.query.filter_by(ip_address="10.0.0.1").one()
        assert ci.name == "Hand-classified core switch"
        assert ci.ci_class == "Network Appliance"
        assert ci.vendor == "Custom Vendor"
        assert ci.discovery_source == "Manual"
        assert ci.attributes.get("sys_descr") == "Cisco IOS"


def test_reconcile_one_bad_host_does_not_block_the_rest(app):
    with app.app_context():
        facts_list = [
            {"host": "10.0.0.5", "sys_name": "ok-host", "sys_object_id": "", "vendor": "", "ci_class": "Device",
             "interfaces": [], "arp_entries": [], "lldp_neighbors": []},
            {"sys_name": "broken", "sys_object_id": "", "vendor": "", "ci_class": "Device",
             "interfaces": [], "arp_entries": [], "lldp_neighbors": []},  # missing "host" -> KeyError
        ]
        summary = reconcile_facts_into_cmdb(1, "mixed run", facts_list)
        assert summary["created"] == 1
        assert len(summary["errors"]) == 1
        assert ConfigurationItem.query.filter_by(ip_address="10.0.0.5").count() == 1


def test_reconcile_creates_bare_ci_for_non_snmp_liveness_hit(app):
    with app.app_context():
        facts_list = [{
            "host": "10.0.0.20", "sys_descr": "", "sys_object_id": "", "sys_name": "10.0.0.20",
            "sys_uptime": "", "vendor": "", "ci_class": "Device",
            "interfaces": [], "arp_entries": [], "lldp_neighbors": [],
            "discovery_source": "Network sweep (no SNMP)",
        }]
        summary = reconcile_facts_into_cmdb(1, "bare sweep", facts_list)
        assert summary["created"] == 1
        assert summary["snmp_hosts"] == 0
        assert summary["bare_hosts"] == 1
        ci = ConfigurationItem.query.filter_by(ip_address="10.0.0.20").one()
        assert ci.discovery_source == "Network sweep (no SNMP)"
        assert ci.name == "10.0.0.20"


def test_reconcile_bare_hit_never_downgrades_a_previously_snmp_profiled_ci(app):
    """A device that answered full SNMP detail on an earlier run and only
    answers bare TCP liveness on a later one (e.g. its SNMP agent got
    disabled, or this particular run just missed it) must keep its earlier
    interfaces/vendor detail -- a bare hit must never blank out richer data
    that's still the best information we have."""
    with app.app_context():
        snmp_facts = [{
            "host": "10.0.0.30", "sys_name": "known-switch", "sys_descr": "Cisco IOS",
            "sys_object_id": "1.3.6.1.4.1.9.1.1", "sys_uptime": "1", "vendor": "Cisco",
            "ci_class": "Network Switch",
            "interfaces": [{"index": "1", "descr": "Gi0/1", "mac_address": "aa:bb:cc:dd:ee:ff"}],
            "arp_entries": [], "lldp_neighbors": [],
        }]
        reconcile_facts_into_cmdb(1, "first run", snmp_facts)

        bare_facts = [{
            "host": "10.0.0.30", "sys_descr": "", "sys_object_id": "", "sys_name": "10.0.0.30",
            "sys_uptime": "", "vendor": "", "ci_class": "Device",
            "interfaces": [], "arp_entries": [], "lldp_neighbors": [],
            "discovery_source": "Network sweep (no SNMP)",
        }]
        summary = reconcile_facts_into_cmdb(1, "second run", bare_facts)
        assert summary["updated"] == 1

        ci = ConfigurationItem.query.filter_by(ip_address="10.0.0.30").one()
        assert ci.name == "known-switch"
        assert ci.vendor == "Cisco"
        assert ci.discovery_source == "SNMP Discovery"
        assert ci.attributes["interfaces"] != []
