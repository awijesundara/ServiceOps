"""SCIM provisioning regressions exercised through authenticated HTTP routes."""
import json

import pytest

from app import APIClient, Audit, Tenant, User, UserSession, create_api_token, db
from tests.test_app import app, client, login  # noqa: F401


@pytest.fixture
def scim_headers(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(
            name="SCIM regression", token_prefix=prefix, token_hash=token_hash,
            scopes_json=json.dumps(["users:provision"]), acting_user_id=admin.id,
            created_by_id=admin.id, tenant_id=admin.tenant_id,
        ))
        db.session.commit()
    return {"Authorization": f"Bearer {token}"}


def employee_id(app):
    with app.app_context():
        return User.query.filter_by(username="employee").one().id


@pytest.mark.parametrize("op", ["add", "replace"])
def test_pathless_deactivation_revokes_sessions(client, app, scim_headers, op):
    login(client, "employee", "Employee123!")
    client.get("/")
    user_id = employee_id(app)
    with app.app_context():
        auth_version = db.session.get(User, user_id).auth_version
        assert UserSession.query.filter_by(user_id=user_id, revoked_at=None).count() == 1
    response = client.patch(f"/scim/v2/Users/{user_id}", headers=scim_headers, json={
        "Operations": [{"op": op, "value": {"active": False, "displayName": "Departed Employee"}}],
    })
    assert response.status_code == 200
    assert response.json["active"] is False
    assert response.json["displayName"] == "Departed Employee"
    with app.app_context():
        assert db.session.get(User, user_id).auth_version == auth_version + 1
        assert UserSession.query.filter_by(user_id=user_id, revoked_at=None).count() == 0
        assert Audit.query.filter_by(action="scim update", target="employee").count() == 1
    assert client.get("/profile").status_code == 302


@pytest.mark.parametrize("method", ["put", "patch"])
@pytest.mark.parametrize("case_variant", [False, True])
def test_duplicate_email_is_conflict_without_partial_update(client, app, scim_headers, method, case_variant):
    user_id = employee_id(app)
    with app.app_context():
        duplicate = User.query.filter_by(username="database.manager").one().email
    if case_variant:
        duplicate = duplicate.upper()
    body = {"displayName": "Must not persist", "active": False, "emails": [{"value": duplicate}]}
    if method == "patch":
        body = {"Operations": [{"op": "replace", "value": body}]}
    response = getattr(client, method)(f"/scim/v2/Users/{user_id}", headers=scim_headers, json=body)
    assert response.status_code == 409
    assert response.json["scimType"] == "uniqueness"
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user.email == "employee@test.invalid"
        assert user.name == "Test Employee"
        assert user.active is True
        assert Audit.query.filter_by(action="scim update", target="employee").count() == 0


def test_unique_violation_after_precheck_rolls_back(client, app, scim_headers, monkeypatch):
    # Simulate the precheck passing while a conflicting value exists by the
    # time SQL executes. This exercises real DB enforcement and autoflush.
    monkeypatch.setattr("serviceops_core.web.api.scim_check_email", lambda *args: None)
    user_id = employee_id(app)
    response = client.put(f"/scim/v2/Users/{user_id}", headers=scim_headers, json={
        "active": False, "emails": [{"value": "database.manager@test.invalid"}],
    })
    assert response.status_code == 409
    assert response.json["scimType"] == "uniqueness"
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user.active is True
        assert user.email == "employee@test.invalid"
    assert client.get(f"/scim/v2/Users/{user_id}", headers=scim_headers).status_code == 200


@pytest.mark.parametrize("method", ["post", "put", "patch"])
@pytest.mark.parametrize("body", [["invalid"], "invalid", 42, True, None])
def test_non_object_payload_is_bad_request(client, app, scim_headers, method, body):
    endpoint = "/scim/v2/Users" if method == "post" else f"/scim/v2/Users/{employee_id(app)}"
    response = getattr(client, method)(endpoint, headers=scim_headers,
                                       data=json.dumps(body), content_type="application/json")
    assert response.status_code == 400
    assert response.json["status"] == "400"
    assert response.json["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


@pytest.mark.parametrize("operations", [
    None, {}, [], [None], ["invalid"], [{"op": []}],
    [{"op": "replace", "path": "active"}],
    [{"op": "replace", "path": "active", "value": "false"}],
    [{"op": "replace", "path": "active", "value": 0}],
    [{"op": "replace", "value": []}],
    [{"op": "replace", "value": {}}],
    [{"op": "replace", "path": [], "value": False}],
    [{"op": "replace", "path": "unknown", "value": False}],
    [{"op": "remove", "path": "active"}],
    [{"op": "replace", "value": {"unknown": False}}],
    [{"op": "replace", "value": {"emails": [None]}}],
])
def test_invalid_patch_is_atomic(client, app, scim_headers, operations):
    user_id = employee_id(app)
    # An invalid second operation must not persist the valid first operation.
    if isinstance(operations, list) and operations:
        operations = [{"op": "replace", "path": "active", "value": False}, *operations]
    response = client.patch(f"/scim/v2/Users/{user_id}", headers=scim_headers,
                            json={"Operations": operations})
    assert response.status_code == 400
    with app.app_context():
        assert db.session.get(User, user_id).active is True
        assert Audit.query.filter_by(action="scim update", target="employee").count() == 0


@pytest.mark.parametrize("attributes", [
    {"active": "false"}, {"displayName": []}, {"emails": {}},
    {"emails": [None]}, {"emails": [{"value": 123}]},
])
@pytest.mark.parametrize("method", ["post", "put"])
def test_invalid_attributes_are_rejected(client, app, scim_headers, attributes, method):
    endpoint = "/scim/v2/Users" if method == "post" else f"/scim/v2/Users/{employee_id(app)}"
    response = getattr(client, method)(endpoint, headers=scim_headers, json={
        "userName": "new.person", "emails": [{"value": "new@test.invalid"}], **attributes,
    })
    assert response.status_code == 400


def test_own_email_update_and_pathless_reactivation(client, app, scim_headers):
    user_id = employee_id(app)
    response = client.put(f"/scim/v2/Users/{user_id}", headers=scim_headers,
                          json={"active": False, "emails": [{"value": "employee@test.invalid"}]})
    assert response.status_code == 200
    response = client.patch(f"/scim/v2/Users/{user_id}", headers=scim_headers, json={
        "Operations": [{"op": "replace", "value": {"active": True}}],
    })
    assert response.status_code == 200
    assert response.json["active"] is True


@pytest.mark.parametrize("method", ["get", "put", "patch", "delete"])
def test_provisioning_cannot_access_another_tenant(client, app, scim_headers, method):
    with app.app_context():
        tenant = Tenant(slug="scim-isolation", name="Other tenant")
        db.session.add(tenant)
        db.session.flush()
        user = User(username="other.person", email="other@test.invalid", name="Other Person",
                    password_hash="unused", role="requester", tenant_id=tenant.id)
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    response = getattr(client, method)(f"/scim/v2/Users/{user_id}", headers=scim_headers,
                                      json={"active": False})
    assert response.status_code == 404
    with app.app_context():
        assert db.session.get(User, user_id).active is True


def test_provisioning_requires_authorized_administrator(client, app, scim_headers):
    user_id = employee_id(app)
    assert client.patch(f"/scim/v2/Users/{user_id}", json={"active": False}).status_code == 401
    with app.app_context():
        api_client = APIClient.query.filter_by(name="SCIM regression").one()
        api_client.acting_user_id = user_id
        db.session.commit()
    assert client.delete(f"/scim/v2/Users/{user_id}", headers=scim_headers).status_code == 403
