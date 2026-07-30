"""Tests for CSV/spreadsheet CMDB import (serviceops_core/cmdb_import.py).

Pure CSV-string -> import_ci_rows tests; no network involved.
"""
import os
import tempfile

import pytest
from werkzeug.security import generate_password_hash

from app import ConfigurationItem, User, create_app, db
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
    "Host,Owner,Desc of application,Serial Number,Vendor,Model,Location\n"
    "srv-01.example.com,Jane Doe,Core app server,ABC123,Dell,R640,CC1 / 9D-Row\n"
)


def test_parse_ci_rows_maps_known_headers_and_ignores_unknown():
    csv_text = "Host,Some Unrecognized Column,Owner\nsrv-01,junk,Jane Doe\n"
    rows = parse_ci_rows(csv_text)
    assert rows == [{"name": "srv-01", "owner_name": "Jane Doe"}]


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
            "Host,Owner,Desc of application,Serial Number,Vendor,Model,Location\n"
            "srv-01.example.com,Jane Doe,Core app server,ZZZ999,HP,DL380,Somewhere Else\n"
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
            "Host,Owner,Desc of application,Serial Number,Vendor,Model,Location\n"
            "srv-01.example.com,Jane Doe,Updated app description,DEF456,HP,DL380,New Location\n"
        )
        result = import_ci_rows(updated_rows, 1)
        assert result["cis_updated"] == 1
        assert result["fields_skipped_netbox_owned"] == 0
        ci = ConfigurationItem.query.filter_by(name="srv-01.example.com").one()
        assert ci.serial_number == "DEF456"
        assert ci.vendor == "HP"
        assert ci.description == "Updated app description"


def test_owner_resolved_by_name(app):
    with app.app_context():
        db.session.add(User(
            username="jane", name="Jane Doe", email="jane@test.invalid",
            password_hash=generate_password_hash("Password123!"), role="agent", tenant_id=1,
        ))
        db.session.commit()
        rows = parse_ci_rows(SAMPLE_CSV)
        result = import_ci_rows(rows, 1)
        assert result["unmatched_owners"] == []
        ci = ConfigurationItem.query.filter_by(name="srv-01.example.com").one()
        assert ci.owner is not None
        assert ci.owner.name == "Jane Doe"


def test_unmatched_owner_is_reported_not_errored(app):
    with app.app_context():
        rows = parse_ci_rows(SAMPLE_CSV)
        result = import_ci_rows(rows, 1)
        assert result["unmatched_owners"] == ["Jane Doe"]
        assert result["errors"] == []
        assert result["cis_created"] == 1


def test_blank_hostname_row_is_skipped_and_reported(app):
    with app.app_context():
        rows = parse_ci_rows("Host,Owner\n,Jane Doe\n")
        result = import_ci_rows(rows, 1)
        assert result["cis_created"] == 0
        assert len(result["errors"]) == 1


def test_dry_run_does_not_commit(app):
    with app.app_context():
        rows = parse_ci_rows(SAMPLE_CSV)
        result = import_ci_rows(rows, 1, dry_run=True)
        assert result["dry_run"] is True
        assert ConfigurationItem.query.count() == 0
