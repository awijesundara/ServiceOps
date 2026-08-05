import json
import re
from pathlib import Path

from app import (
    APIClient, DiscoveryCandidate, DiscoveryTarget, Notification,
    PasswordResetToken, User, UserSession, create_api_token, db,
)
from serviceops_core.security import verify_password
from tests.test_app import app, client, login


def test_metrics_exposes_operational_signals(client):
    client.get("/health")
    response = client.get("/metrics")
    assert response.status_code == 200
    assert b"serviceops_worker_up" in response.data
    assert b"serviceops_http_requests_total" in response.data
    assert response.headers["Content-Type"].startswith("text/plain")


def test_login_creates_inventory_and_admin_can_revoke_session(client, app):
    login(client)
    client.get("/")
    with app.app_context():
        row = UserSession.query.one()
        record_id = row.id
        assert row.provider == "local"
        assert row.revoked_at is None
    page = client.get("/admin/sessions")
    assert page.status_code == 200
    assert b"This session" in page.data
    response = client.post(f"/sessions/{record_id}/revoke", data={"admin_view": "1"})
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_self_service_password_reset_is_single_use_and_revokes_sessions(client, app):
    login(client, "employee", "Employee123!")
    client.get("/")
    client.post("/logout")
    response = client.post("/forgot-password", data={"identity": "employee"}, follow_redirects=True)
    assert b"If that active local account exists" in response.data
    with app.app_context():
        assert PasswordResetToken.query.count() == 1
        message = Notification.query.filter_by(title="ServiceOps password recovery").one().body
    token = re.search(r"/reset-password/([^\s]+)", message).group(1)
    changed = client.post(
        f"/reset-password/{token}",
        data={"password": "A-New-Stable-Password-2026!", "confirmation": "A-New-Stable-Password-2026!"},
        follow_redirects=True,
    )
    assert b"Password reset" in changed.data
    assert client.get(f"/reset-password/{token}").status_code == 400
    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        assert verify_password(employee.password_hash, "A-New-Stable-Password-2026!")
        assert UserSession.query.filter_by(user_id=employee.id, revoked_at=None).count() == 0


def test_scim_create_and_deactivate_is_tenant_scoped(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        token, prefix, token_hash = create_api_token()
        api_client = APIClient(
            name="SCIM test", token_prefix=prefix, token_hash=token_hash,
            scopes_json=json.dumps(["users:provision"]), acting_user_id=admin.id,
            created_by_id=admin.id, tenant_id=admin.tenant_id,
        )
        db.session.add(api_client)
        db.session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post("/scim/v2/Users", headers=headers, json={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "scim.person", "displayName": "SCIM Person",
        "externalId": "HR-100", "active": True,
        "emails": [{"value": "scim.person@test.invalid", "primary": True}],
    })
    assert created.status_code == 201
    user_id = created.json["id"]
    deactivated = client.patch(f"/scim/v2/Users/{user_id}", headers=headers, json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    })
    assert deactivated.status_code == 200
    with app.app_context():
        assert User.query.filter_by(username="scim.person").one().active is False


def test_discovery_review_has_filter_aware_bulk_selection(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        target = DiscoveryTarget(name="Filtered review", target_type="subnet", address="10.9.0.0/24",
                                 created_by_id=admin.id, tenant_id=admin.tenant_id)
        db.session.add(target)
        db.session.flush()
        db.session.add(DiscoveryCandidate(
            target_id=target.id, host="10.9.0.10", name="edge-switch", ci_class="Network Switch",
            vendor="Cisco", discovery_source="SNMP Discovery", facts={}, tenant_id=admin.tenant_id,
        ))
        db.session.commit()
        target_id = target.id
    login(client)
    page = client.get(f"/cmdb/discovery/{target_id}/review")
    assert page.status_code == 200
    for label in (b"Select filtered", b"Deselect filtered", b"Select every device", b"Deselect every device", b"All vendors"):
        assert label in page.data
    assert b'data-vendor="cisco"' in page.data
    assert b"static/discovery.js" in page.data
    assert b"<script>" not in page.data


def test_discovery_targets_keep_primary_actions_visible(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        target = DiscoveryTarget(name="Core network", target_type="host", address="10.9.0.10",
                                 created_by_id=admin.id, tenant_id=admin.tenant_id)
        db.session.add(target)
        db.session.flush()
        db.session.add(DiscoveryCandidate(
            target_id=target.id, host="10.9.0.10", name="core-switch", ci_class="Network Switch",
            vendor="Cisco", discovery_source="SNMP Discovery", facts={}, tenant_id=admin.tenant_id,
        ))
        db.session.commit()
    login(client)
    page = client.get("/cmdb/discovery")
    assert page.status_code == 200
    for label in (b"Run now", b"View results (1)", b"Delete target"):
        assert label in page.data
    assert b"discovery-target-card" in page.data
    assert b"static/discovery.js" in page.data
    assert b"<script>" not in page.data


def test_lifecycle_invokes_container_helpers_as_modules():
    lifecycle = (Path(__file__).parents[1] / "serviceops").read_text()
    for module in ("tools.admin_recovery", "tools.record_backup_status", "tools.archive_recovery_set"):
        assert f"python -m {module}" in lifecycle
