"""One configuration item merged from several sources.

Rehearses a real data-centre server: a spreadsheet import creates the CI
by hostname with operational data, then Snipe-IT adopts it by serial number
with asset data, rack placement and environment held in custom fields."""
import os
import tempfile
from datetime import date

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import text

from app import ConfigurationItem, Rack, create_app, db
from serviceops_core import ci_sources
from serviceops_core.cmdb_import import import_ci_rows, parse_ci_rows
from serviceops_core.snipeit_sync import sync_from_snipeit
from tests.test_app import app, client, login  # noqa: F401  (pytest fixtures)
from tests.test_snipeit_sync import FakeSnipeit, configure, factory, make_asset

SPREADSHEET = ("Host,Serial Number,Vendor,Model,Location,Description,Environment,Install Date,CPUs,Builder\n"
               "dci2dev09,5QMY0L2,Dell,Dell PowerEdge R730,CC1-9C-2b,QA/CI/CD,Development,2017-06-01,40,Jeff Yang\n")


def dc_asset(name="mmi2cloudctrl03", rack="9D03"):
    custom = {
        "Finance Asset Code": {"value": "F16036-010", "field_format": "ANY"},
        "Rack No.": {"value": rack, "field_format": "ANY"},
        "Position": {"value": "2", "field_format": "ANY"},
        "Orientation": {"value": "front", "field_format": "ANY"},
        "Service Environment": {"value": "JNX Internal - Dev", "field_format": "ANY"},
        "Depreciation End Date": {"value": "2022-09-01", "field_format": "DATE"},
    }
    asset = make_asset(6048, name=name, tag="569DC-0001715", serial="5QMY0L2", category="Server",
                       location="CC1-9C-2b", custom_fields=custom, purchase=None, warranty=None)
    asset["model"] = {"id": 3, "name": "Dell PowerEdge R730"}
    asset["manufacturer"] = {"id": 2, "name": "Dell"}
    asset["rtd_location"] = {"id": 4, "name": "CC1-9C-2b"}
    asset["assigned_to"] = {"id": 4, "type": "location", "name": "CC1-9C-2b"}
    asset["notes"] = ('BITS-RT: #10581<br>JNX: DC3 management<br>Moved under below ticket: '
                      '<a href="https://rt.example/Ticket/Display.html?id=1">RT 1</a>')
    return asset


def import_both(monkeypatch, asset=None):
    import_ci_rows(parse_ci_rows(SPREADSHEET), 1, dry_run=False)
    configure(monkeypatch)
    return sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={
        "/api/v1/hardware": [asset or dc_asset()]})))


def test_sources_merge_into_one_item_without_duplicates(app, monkeypatch):
    with app.app_context():
        result = import_both(monkeypatch)
        assert result["cis_created"] == 0 and result["cis_matched_by_serial"] == 1 and not result["errors"]
        (ci,) = ConfigurationItem.query.filter_by(serial_number="5QMY0L2").all()
        # The hostname stays; Snipe-IT's own asset name is kept as source data.
        assert ci.name == "dci2dev09"
        assert ci.attributes["Snipe-IT: Asset Name"] == "mmi2cloudctrl03"
        # Rack information from Snipe-IT creates the rack and places the server.
        rack = Rack.query.filter_by(name="9D03").one()
        assert (rack.site, rack.external_source) == ("CC1-9C-2b", "snipeit")
        assert (ci.rack_id, ci.rack_position, ci.rack_face) == (rack.id, 2.0, "front")
        assert ci.environment == "Development"
        # Spreadsheet data Snipe-IT does not hold is not blanked.
        assert ci.install_date == date(2017, 6, 1) and ci.description == "QA/CI/CD"
        assert ci.attributes["CPUs"] == "40" and ci.attributes["Builder"] == "Jeff Yang"
        # Values that only repeat a CMDB field are not stored.
        for duplicate in ("Asset ID", "Default Location", "Assigned To", "Assigned To Type", "Category",
                          "Rack No.", "Position", "Orientation", "Service Environment", "Created"):
            assert f"Snipe-IT: {duplicate}" not in ci.attributes, duplicate
        assert ci.attributes["Snipe-IT: Finance Asset Code"] == "F16036-010"
        assert ci.attributes["Snipe-IT: Notes"] == (
            "BITS-RT: #10581\nJNX: DC3 management\nMoved under below ticket: "
            "RT 1 (https://rt.example/Ticket/Display.html?id=1)")


def test_every_field_records_its_source(app, monkeypatch):
    with app.app_context():
        import_both(monkeypatch)
        ci = ConfigurationItem.query.filter_by(name="dci2dev09").one()
        sources = ci.field_sources
        assert sources["description"] == "csv" and sources["install_date"] == "csv"
        assert sources["rack_id"] == "snipeit" and sources["rack_position"] == "snipeit"
        assert sources["environment"] == "snipeit" and sources["location"] == "snipeit"
        assert "name" not in sources or sources["name"] == "csv"
        assert ci_sources.label(ci, "rack_id") == "Snipe-IT"


def test_rack_height_is_taken_from_the_same_model(app, monkeypatch):
    with app.app_context():
        db.session.add(ConfigurationItem(name="nb-r730", ci_class="Server", model="Dell PowerEdge R730",
                                         rack_u_height=2, tenant_id=1, external_source="netbox",
                                         external_id="dcim.device:9"))
        db.session.commit()
        import_both(monkeypatch)
        ci = ConfigurationItem.query.filter_by(name="dci2dev09").one()
        assert ci.rack_u_height == 2 and ci.field_sources["rack_u_height"] == "inferred"


def test_snipeit_name_is_followed_only_when_snipeit_named_the_item(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={
            "/api/v1/hardware": [make_asset(7, name="lab-box", serial="SN7")]})))
        sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={
            "/api/v1/hardware": [make_asset(7, name="lab-box-renamed", serial="SN7")]})))
        assert ConfigurationItem.query.filter_by(external_id="hardware:7").one().name == "lab-box-renamed"

        import_both(monkeypatch)
        sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={
            "/api/v1/hardware": [dc_asset(name="another-asset-name")]})))
        assert ConfigurationItem.query.filter_by(serial_number="5QMY0L2").one().name == "dci2dev09"


def test_edit_page_shows_one_record_with_sources_and_read_only_source_data(client, app, monkeypatch):
    with app.app_context():
        import_both(monkeypatch)
        ci = ConfigurationItem.query.filter_by(name="dci2dev09").one()
        ci_id = ci.id
        # Rows saved by an earlier version that stored duplicates are hidden too.
        ci.attributes = {**ci.attributes, "Snipe-IT: Default Location": "CC1-9C-2b",
                         "Snipe-IT: Rack No.": "9D03", "Snipe-IT: Asset ID": "6048"}
        db.session.commit()
    login(client)
    page = client.get(f"/cmdb/{ci_id}/edit").get_data(as_text=True)
    assert "Source data" in page and "Open in Snipe-IT ↗" in page
    assert "<dt>Finance Asset Code</dt>" in page and "<dt>Asset Name</dt>" in page
    for hidden in ("Default Location", "Rack No.", "Asset ID"):
        assert f"<dt>{hidden}</dt>" not in page and f'value="Snipe-IT: {hidden}"' not in page
    assert 'class="field-source source-snipeit"' in page and 'class="field-source source-csv"' in page
    assert 'value="None"' not in page
    assert 'name="attr_key" value="CPUs"' in page


def test_saving_the_form_keeps_source_data_stores_no_none_and_marks_manual_edits(client, app, monkeypatch):
    with app.app_context():
        import_both(monkeypatch)
        ci = ConfigurationItem.query.filter_by(name="dci2dev09").one()
        ci_id, rack_id, support = ci.id, ci.rack_id, ci.support_group_id
    login(client)
    response = client.post(f"/cmdb/{ci_id}/edit", data={
        "name": "dci2dev09", "ci_class": "Server", "description": "QA/CI/CD", "environment": "Development",
        "operational_status": "Operational", "lifecycle_state": "In Use", "business_criticality": "High",
        "ip_address": "None", "cost_center": "None", "serial_number": "5QMY0L2", "vendor": "Dell",
        "model": "Dell PowerEdge R730", "location": "CC1-9C-2b", "rack_id": str(rack_id), "rack_position": "2",
        "rack_face": "front", "support_group_id": str(support or ""), "discovery_source": "API",
        "attr_key": ["CPUs", "Snipe-IT: Finance Asset Code"], "attr_value": ["48", "tampered"],
    })
    assert response.status_code == 302
    with app.app_context():
        ci = db.session.get(ConfigurationItem, ci_id)
        assert ci.ip_address is None and ci.cost_center is None
        assert ci.attributes["CPUs"] == "48"
        assert ci.attributes["Snipe-IT: Finance Asset Code"] == "F16036-010"
        assert ci.attributes["Snipe-IT: Notes"].startswith("BITS-RT")
        assert ci.field_sources["business_criticality"] == "manual"
        assert ci.field_sources["rack_id"] == "snipeit"


def test_migration_clears_literal_none_and_adds_field_sources():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    migrated_app = create_app({"TESTING": True, "AUTO_MIGRATE_IN_TESTS": True,
                               "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    root = os.path.dirname(os.path.dirname(__file__))
    config = AlembicConfig(os.path.join(root, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(root, "migrations"))
    try:
        with migrated_app.app_context():
            db.session.remove()
            command.downgrade(config, "20260928_0107")
            db.session.execute(text(
                "INSERT INTO configuration_item (name, ci_class, environment, operational_status, lifecycle_state, "
                "business_criticality, discovery_source, attributes, tenant_id, ip_address, cost_center, vendor, "
                "require_ccb_approval, created_at, updated_at) VALUES ('legacy', 'Server', 'Production', "
                "'Operational', 'In Use', 'Medium', 'Manual', '{}', 1, 'None', 'None', 'Dell', 0, "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
            db.session.commit()
            db.session.remove()
            command.upgrade(config, "head")
            row = db.session.execute(text(
                "SELECT ip_address, cost_center, vendor, field_sources FROM configuration_item WHERE name = 'legacy'"
            )).one()
            assert row[0] is None and row[1] is None and row[2] == "Dell" and row[3] in ("{}", {})
    finally:
        os.unlink(path)
