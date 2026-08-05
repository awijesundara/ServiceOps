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
    guess_ci_class, guess_vendor, reconcile_facts_into_cmdb,
)


def test_guess_vendor_matches_known_enterprise_prefixes():
    assert guess_vendor("1.3.6.1.4.1.9.1.1208") == "Cisco"
    assert guess_vendor("1.3.6.1.4.1.2636.1.1.1.2.57") == "Juniper"
    assert guess_vendor("") == ""
    assert guess_vendor("1.3.6.1.4.1.99999.1") == ""


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
