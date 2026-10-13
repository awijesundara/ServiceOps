"""Malformed form and API input answers 4xx, never 500 (stability review
2026-10-12). Each case below was a 500 found by tools/stability_fuzz.py."""
import os
import sys
import tempfile

import pytest
from werkzeug.security import generate_password_hash

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from app import (  # noqa: E402
    Asset, CatalogRequest, EnterpriseRecord, ImprovementItem, OperationalTask, RequestedItem, Tenant, User,
    audit, create_app, db,
)


@pytest.fixture(scope="module")
def app():
    import load_demo_dataset
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        load_demo_dataset.load_dataset()
        ids = {
            "problem": EnterpriseRecord.query.filter_by(domain="problem").first().id,
            "ritm": RequestedItem.query.first().id,
            "request": CatalogRequest.query.filter(CatalogRequest.state.in_(["Open", "Awaiting Approval"])).first().id,
            "task": OperationalTask.query.first().id,
        }
        other = Tenant(slug="other-org", name="Other org")
        db.session.add(other)
        db.session.flush()
        outsider = User(username="other.agent", name="Other Agent", email="other.agent@other.invalid",
                        role="agent", tenant_id=other.id, password_hash=generate_password_hash("Other123!"))
        db.session.add(outsider)
        db.session.commit()
        ids["outsider"] = outsider.id
        app.config["IDS"] = ids
    yield app
    os.unlink(path)


@pytest.fixture(scope="module")
def client(app):
    # One sign-in for the module: per-test sign-ins would trip the login rate limit.
    client = app.test_client()
    assert client.post("/login", data={"username": "admin", "password": "Admin123!"}).status_code == 302
    return client


def cases(ids):
    return [
        ("/assets/new", {"asset_tag": "", "name": "", "asset_type": "Laptop", "status": "In stock"}),
        ("/cmdb/1/edit", {"name": "x", "ci_class": "Server", "environment": "Production",
                          "operational_status": "Operational", "install_date": "not-a-date"}),
        ("/cmdb/relationships", {"parent_id": "zzz", "child_id": "1", "relationship_type": "Runs on"}),
        ("/improvements/new", {"title": "Better backups", "source_type": "incident", "source_id": "zzz"}),
        (f"/operational-task/{ids['task']}", {"assignee_id": "zzz", "state": "Open"}),
        ("/preferences", {"font_scale": "zzz"}),
        (f"/problem/{ids['problem']}/analysis", {"primary_ci_id": "zzz"}),
        (f"/problem/{ids['problem']}/tasks", {"group_id": "", "title": "Check logs"}),
        (f"/request/{ids['request']}/items", {"catalog_item_id": "zzz"}),
        (f"/ritm/{ids['ritm']}/tasks", {"group_id": "", "title": "Ship it"}),
    ]


@pytest.mark.parametrize("index", range(10))
def test_malformed_form_values_are_rejected_not_crashed(app, client, index):
    url, data = cases(app.config["IDS"])[index]
    response = client.post(url, data=data)
    # 400 with the field named: the request reached the value it was given.
    assert response.status_code == 400, (url, response.status_code)


def test_a_duplicate_asset_tag_is_a_conflict(app, client):
    data = {"asset_tag": "DUP-1", "name": "Laptop", "asset_type": "Laptop", "status": "In stock"}
    assert client.post("/assets/new", data=data).status_code == 302
    assert client.post("/assets/new", data={**data, "asset_tag": "dup-1"}).status_code == 409
    with app.app_context():
        assert Asset.query.filter(db.func.lower(Asset.asset_tag) == "dup-1").count() == 1


def test_an_improvement_owner_must_be_an_agent_in_the_same_tenant(app, client):
    with app.app_context():
        item_id = ImprovementItem.query.first().id if ImprovementItem.query.first() else None
    if item_id is None:
        client.post("/improvements/new", data={"title": "Owner check"})
        with app.app_context():
            item_id = ImprovementItem.query.first().id
    response = client.post(f"/improvement/{item_id}", data={"status": "Assessed", "owner_id": app.config["IDS"]["outsider"]})
    assert response.status_code == 400
    with app.app_context():
        assert db.session.get(ImprovementItem, item_id).owner_id != app.config["IDS"]["outsider"]


def test_an_audit_target_of_only_spaces_does_not_fail(app):
    with app.test_request_context():
        audit("update", "   ", "blank target")
        db.session.rollback()


def test_nul_characters_are_rejected_in_forms_queries_and_json(app, client):
    assert client.post("/preferences", data={"display_name": "a\x00b"}).status_code == 400
    assert client.get("/cmdb?q=a%00b").status_code == 400
    mobile = app.test_client()
    headers = {"X-ServiceOps-App-Version": "1.0", "X-ServiceOps-App-Build": "1",
               "X-ServiceOps-Platform": "iOS", "X-ServiceOps-Device": "test"}
    token = mobile.post("/api/v1/auth/mobile/login", headers=headers,
                        json={"username": "admin", "password": "Admin123!"}).get_json()["access_token"]
    headers.update({"Authorization": f"Bearer {token}", "Idempotency-Key": "nul-check"})
    assert mobile.post("/api/v1/incidents", headers=headers, json={"title": "a\x00b"}).status_code == 400


def test_overlong_text_is_a_bad_request_not_a_database_error(app):
    from serviceops_core.input_limits import ValueTooLong
    with app.test_request_context():
        tenant_id = User.query.filter_by(username="admin").one().tenant_id
        db.session.add(Asset(asset_tag="T" * 81, name="x", asset_type="Laptop", status="In stock", tenant_id=tenant_id))
        with pytest.raises(ValueTooLong) as raised:
            db.session.flush()
        assert "at most 80 characters" in raised.value.description
        db.session.rollback()
    with app.app_context():  # background jobs are not affected
        db.session.add(Asset(asset_tag="U" * 81, name="x", asset_type="Laptop", status="In stock", tenant_id=tenant_id))
        db.session.flush()
        db.session.rollback()


def test_malformed_provider_and_inventory_counts_read_as_zero():
    from serviceops_core.ai.routing import _token_count
    from serviceops_core.netbox_sync import _reported_count as netbox_count
    from serviceops_core.snipeit_sync import _reported_count as snipeit_count
    assert _token_count({"nested": 1}) == 0 and _token_count("abc") == 0 and _token_count("12") == 12
    assert netbox_count({"count": "many"}, "count") == 0 and netbox_count("<html>", "count") == 0
    assert snipeit_count({"total": 7}, "total") == 7


def test_a_row_with_a_legacy_overlong_value_stays_editable(app):
    # SQLite (and IPFS mode) never enforced lengths, so old rows may exceed them.
    from sqlalchemy import text
    from serviceops_core.input_limits import ValueTooLong
    with app.app_context():
        tenant_id = User.query.filter_by(username="admin").one().tenant_id
        db.session.add(Asset(asset_tag="LEGACY-1", name="x", asset_type="Laptop", status="In stock", tenant_id=tenant_id))
        db.session.commit()
        db.session.execute(text("UPDATE asset SET name = :n WHERE asset_tag = 'LEGACY-1'"), {"n": "N" * 300})
        db.session.commit()
    with app.test_request_context():
        asset = Asset.query.filter_by(asset_tag="LEGACY-1").one()
        asset.status = "In use"
        db.session.flush()  # the untouched long name is not re-validated
        asset.name = "M" * 200
        with pytest.raises(ValueTooLong):
            db.session.flush()
        db.session.rollback()


def test_asset_tags_are_unique_per_tenant_not_across_tenants(app, client):
    with app.app_context():
        other = Tenant(slug="asset-tags-b", name="Asset tags B")
        db.session.add(other)
        db.session.flush()
        db.session.add(User(username="tags.admin", name="Tags Admin", email="tags.admin@b.invalid", role="admin",
                            password_hash=generate_password_hash("TagsAdmin123!"), tenant_id=other.id))
        db.session.commit()
    data = {"asset_tag": "LAP-100", "name": "Laptop", "asset_type": "Laptop", "status": "In stock"}
    assert client.post("/assets/new", data=data).status_code == 302
    client.post("/logout")
    assert client.post("/login", data={"username": "tags.admin", "password": "TagsAdmin123!"}).status_code in (302, 303)
    assert client.post("/assets/new", data={**data, "asset_tag": "lap-100"}).status_code == 302  # other tenant
    assert client.post("/assets/new", data=data).status_code == 409  # same tenant, any case
    with app.app_context():
        assert Asset.query.filter(db.func.lower(Asset.asset_tag) == "lap-100").count() == 2
