"""Tests for CSV/spreadsheet CMDB import (serviceops_core/cmdb_import.py).

Pure CSV-string -> import_ci_rows tests; no network involved.
"""
import os
import tempfile

import pytest

from app import ConfigurationItem, SupportGroup, SupportGroupAlias, create_app, db
from serviceops_core.cmdb_import import CmdbImportError, import_ci_rows, parse_ci_rows


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        db.session.commit()
    yield app
    os.unlink(path)


SAMPLE_CSV = (
    "Host,System Owner,Desc of application,Serial Number,Vendor,Model,Location\n"
    "srv-01.example.com,Core apps,Core app server,ABC123,Dell,R640,CC1 / 9D-Row\n"
)


def test_parse_ci_rows_maps_known_headers_and_keeps_unknown_as_attributes():
    csv_text = "Host,Some Unrecognized Column,System Owner\nsrv-01,junk,Core apps\n"
    rows = parse_ci_rows(csv_text)
    assert rows == [{
        "name": "srv-01", "owning_team_name": "Core apps",
        "extra_attributes": {"Some Unrecognized Column": "junk"},
    }]


def test_parse_ci_rows_raises_on_empty_input():
    with pytest.raises(CmdbImportError):
        parse_ci_rows("")


def test_creates_new_ci_from_csv(app):
    with app.app_context():
        rows = parse_ci_rows(SAMPLE_CSV)
        result = import_ci_rows(rows, 1)
        assert result["cis_created"] == 1
        ci = ConfigurationItem.query.filter_by(name="srv-01.example.com").one()
        assert ci.serial_number == "ABC123"
        assert ci.vendor == "Dell"
        assert ci.external_source == "csv"
        assert ci.discovery_source == "Import"


def test_netbox_owned_ci_only_gets_non_hardware_fields_updated(app):
    with app.app_context():
        db.session.add(ConfigurationItem(
            name="srv-01.example.com", ci_class="Server", serial_number="ABC123",
            vendor="Dell", model="R640", location="CC1 / 9D-Row",
            external_source="netbox", external_id="101", tenant_id=1,
        ))
        db.session.commit()
        rows = parse_ci_rows(
            "Host,System Owner,Desc of application,Serial Number,Vendor,Model,Location\n"
            "srv-01.example.com,Core apps,Core app server,ZZZ999,HP,DL380,Somewhere Else\n"
        )
        result = import_ci_rows(rows, 1)
        assert result["cis_updated"] == 1
        assert result["fields_skipped_netbox_owned"] > 0
        ci = ConfigurationItem.query.filter_by(external_id="101").one()
        # NetBox-owned hardware fields untouched by the CSV import.
        assert ci.serial_number == "ABC123"
        assert ci.vendor == "Dell"
        assert ci.model == "R640"
        assert ci.location == "CC1 / 9D-Row"
        # Non-hardware field from the CSV was applied.
        assert ci.description == "Core app server"


def test_csv_sourced_ci_gets_all_fields_updated_on_resync(app):
    with app.app_context():
        rows = parse_ci_rows(SAMPLE_CSV)
        import_ci_rows(rows, 1)
        updated_rows = parse_ci_rows(
            "Host,System Owner,Desc of application,Serial Number,Vendor,Model,Location\n"
            "srv-01.example.com,Core apps,Updated app description,DEF456,HP,DL380,New Location\n"
        )
        result = import_ci_rows(updated_rows, 1)
        assert result["cis_updated"] == 1
        assert result["fields_skipped_netbox_owned"] == 0
        ci = ConfigurationItem.query.filter_by(name="srv-01.example.com").one()
        assert ci.serial_number == "DEF456"
        assert ci.vendor == "HP"
        assert ci.description == "Updated app description"


def test_owning_team_auto_created_from_name(app):
    with app.app_context():
        rows = parse_ci_rows(
            "Host,System Owner,Desc of application,Serial Number,Vendor,Model,Location\n"
            "srv-01.example.com,Platform Enablement,Core app server,ABC123,Dell,R640,CC1 / 9D-Row\n"
        )
        result = import_ci_rows(rows, 1)
        assert result["teams_created"] == ["Platform Enablement"]
        ci = ConfigurationItem.query.filter_by(name="srv-01.example.com").one()
        assert ci.support_group is not None
        assert ci.support_group.name == "Platform Enablement"


def test_owning_team_reused_across_rows(app):
    with app.app_context():
        db.session.add(SupportGroup(name="Platform Enablement", tenant_id=1))
        db.session.commit()
        rows = parse_ci_rows(
            "Host,System Owner,Desc of application,Serial Number,Vendor,Model,Location\n"
            "srv-01.example.com,Platform Enablement,Core app server,ABC123,Dell,R640,CC1 / 9D-Row\n"
        )
        result = import_ci_rows(rows, 1)
        assert result["teams_created"] == []
        assert SupportGroup.query.filter_by(name="Platform Enablement").count() == 1


def test_owning_team_alias_resolves_to_existing_group_instead_of_duplicating(app):
    with app.app_context():
        # "DBA" -> "Database" is seeded by default (seed_itil); staff use
        # both names interchangeably, so the import must not spawn a
        # duplicate "DBA" support group.
        database_group = SupportGroup.query.filter_by(name="Database").one()
        assert SupportGroupAlias.query.filter_by(alias="DBA").count() == 1
        rows = parse_ci_rows(
            "Host,System Owner,Serial Number\nsrv-db-01.example.com,DBA,XYZ001\n"
        )
        result = import_ci_rows(rows, 1)
        assert result["teams_created"] == []
        ci = ConfigurationItem.query.filter_by(name="srv-db-01.example.com").one()
        assert ci.support_group_id == database_group.id
        assert SupportGroup.query.filter_by(name="DBA").count() == 0


def test_owning_team_custom_alias_can_be_added_via_admin(app):
    with app.app_context():
        team = SupportGroup(name="Site Reliability", tenant_id=1)
        db.session.add(team)
        db.session.flush()
        db.session.add(SupportGroupAlias(alias="SRE", group_id=team.id, tenant_id=1))
        db.session.commit()
        rows = parse_ci_rows(
            "Host,System Owner,Serial Number\nsrv-sre-01.example.com,SRE,XYZ002\n"
        )
        result = import_ci_rows(rows, 1)
        assert result["teams_created"] == []
        ci = ConfigurationItem.query.filter_by(name="srv-sre-01.example.com").one()
        assert ci.support_group_id == team.id


def test_owning_team_spelling_variant_reuses_existing_group(app):
    """The CSV's Owner column says "Core apps" but the team already exists
    as "CoreApps" (seeded by default) -- these are the same team spelled
    differently and must not spawn a second group."""
    with app.app_context():
        assert SupportGroup.query.filter_by(name="CoreApps").count() == 1
        rows = parse_ci_rows(SAMPLE_CSV)
        result = import_ci_rows(rows, 1)
        assert result["teams_created"] == []
        assert SupportGroup.query.filter_by(name="CoreApps").count() == 1
        assert SupportGroup.query.filter_by(name="Core apps").count() == 0
        ci = ConfigurationItem.query.filter_by(name="srv-01.example.com").one()
        assert ci.support_group.name == "CoreApps"


def test_import_sweeps_up_preexisting_spelling_duplicate_teams(app):
    """If two spelling-variant teams already exist (e.g. from earlier,
    less careful imports), importing anything at all triggers the
    duplicate-team cleanup sweep, collapsing them."""
    with app.app_context():
        # "CoreApps" is already seeded by default; add the spelling variant.
        db.session.add(SupportGroup(name="Core apps", tenant_id=1))
        db.session.commit()
        rows = parse_ci_rows(
            "Host,System Owner\nother-srv.example.com,CoreApps\n"
        )
        result = import_ci_rows(rows, 1)
        assert result["teams_merged"] >= 1
        assert SupportGroup.query.filter(
            SupportGroup.name.in_(["CoreApps", "Core apps"])
        ).count() == 1


def test_blank_hostname_row_is_skipped_and_reported(app):
    with app.app_context():
        rows = parse_ci_rows("Host,System Owner\n,Core apps\n")
        result = import_ci_rows(rows, 1)
        assert result["cis_created"] == 0
        assert len(result["errors"]) == 1


def test_decommissioned_state_sets_retired_regardless_of_source_tab(app):
    with app.app_context():
        rows = parse_ci_rows(
            "Host,State,System Owner\n"
            "srv-old.example.com,Decomm'd,Core apps\n"
        )
        result = import_ci_rows(rows, 1)
        assert result["cis_created"] == 1
        ci = ConfigurationItem.query.filter_by(name="srv-old.example.com").one()
        assert ci.operational_status == "Retired"
        assert ci.lifecycle_state == "Retired"


def test_live_state_does_not_override_status(app):
    with app.app_context():
        rows = parse_ci_rows("Host,State\nsrv-live.example.com,Live\n")
        result = import_ci_rows(rows, 1)
        assert result["cis_created"] == 1
        ci = ConfigurationItem.query.filter_by(name="srv-live.example.com").one()
        assert ci.operational_status == "Operational"
        assert ci.lifecycle_state == "In Use"


def test_decommissioned_state_updates_existing_ci_on_resync(app):
    with app.app_context():
        db.session.add(ConfigurationItem(
            name="srv-01.example.com", ci_class="Server",
            external_source="csv", tenant_id=1,
        ))
        db.session.commit()
        rows = parse_ci_rows("Host,State\nsrv-01.example.com,Decommissioned\n")
        result = import_ci_rows(rows, 1)
        assert result["cis_updated"] == 1
        ci = ConfigurationItem.query.filter_by(name="srv-01.example.com").one()
        assert ci.operational_status == "Retired"
        assert ci.lifecycle_state == "Retired"


def test_unrecognized_columns_are_kept_as_attributes(app):
    with app.app_context():
        rows = parse_ci_rows(
            "Host,System Owner,Builder,CPUs,RAM (GB)\n"
            "srv-01.example.com,Core apps,William Yao,16,128\n"
        )
        result = import_ci_rows(rows, 1)
        assert result["cis_created"] == 1
        ci = ConfigurationItem.query.filter_by(name="srv-01.example.com").one()
        assert ci.vendor is None
        assert ci.attributes == {"Builder": "William Yao", "CPUs": "16", "RAM (GB)": "128"}


def test_dry_run_does_not_commit(app):
    with app.app_context():
        rows = parse_ci_rows(SAMPLE_CSV)
        result = import_ci_rows(rows, 1, dry_run=True)
        assert result["dry_run"] is True
        assert ConfigurationItem.query.count() == 0
