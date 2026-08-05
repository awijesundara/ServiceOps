import json
import re
from pathlib import Path

from app import (
    APIClient, DiscoveryCandidate, DiscoveryTarget, Notification,
    PasswordResetToken, PerformanceSample, RequestMetricTotal, User,
    UserSession, align_tz, create_api_token, db, now,
    process_performance_sample_schedule,
)
from datetime import timedelta
from serviceops_core.security import verify_password
from tests.test_app import app, client, login


def test_metrics_exposes_operational_signals(client):
    client.get("/health")
    response = client.get("/metrics")
    assert response.status_code == 200
    assert b"serviceops_worker_up" in response.data
    assert b"serviceops_http_requests_total" in response.data
    assert response.headers["Content-Type"].startswith("text/plain")


def test_request_metrics_are_db_backed_not_in_process(client, app):
    # B-285: an in-process Counter() undercounts across Gunicorn's multiple
    # worker processes -- this asserts the fix (a shared DB row) actually
    # accumulates across repeated requests within one test process, which
    # would already have caught the original in-memory-only version too
    # since here it's the same effect a second Gunicorn worker would cause:
    # the count must reflect real accumulated totals, not just "at least 1".
    with app.app_context():
        RequestMetricTotal.query.delete()
        db.session.commit()
    client.get("/health")
    client.get("/health")
    client.get("/health")
    with app.app_context():
        row = RequestMetricTotal.query.filter_by(method="GET", status="200").first()
        assert row is not None
        assert row.request_count >= 3


def test_performance_sample_schedule_is_rate_limited_and_computes_totals(client, app):
    with app.app_context():
        RequestMetricTotal.query.delete()
        PerformanceSample.query.delete()
        db.session.commit()
    client.get("/health")
    client.get("/health")
    with app.app_context():
        assert process_performance_sample_schedule(interval_seconds=60) is True
        # Immediately due again -- must be a no-op until the interval elapses.
        assert process_performance_sample_schedule(interval_seconds=60) is False
        sample = PerformanceSample.query.order_by(PerformanceSample.id.desc()).first()
        assert sample.cumulative_requests >= 2


def test_performance_sample_schedule_prunes_samples_older_than_a_week(client, app):
    with app.app_context():
        PerformanceSample.query.delete()
        db.session.add(PerformanceSample(
            sampled_at=now() - timedelta(days=10), cumulative_requests=1,
            cumulative_errors=0, cumulative_duration_ms=1,
        ))
        db.session.commit()
        assert process_performance_sample_schedule(interval_seconds=60) is True
        remaining = PerformanceSample.query.all()
        cutoff = now() - timedelta(days=7)
        assert all(align_tz(s.sampled_at, cutoff) >= cutoff for s in remaining)


def test_system_health_performance_endpoint_requires_security_administer(client, app):
    login(client)
    with app.app_context():
        PerformanceSample.query.delete()
        first = now() - timedelta(minutes=2)
        db.session.add(PerformanceSample(
            sampled_at=first, cumulative_requests=100, cumulative_errors=1,
            cumulative_duration_ms=5000, worker_healthy=True, deployment_mode="compose",
        ))
        db.session.add(PerformanceSample(
            sampled_at=first + timedelta(minutes=1), cumulative_requests=160,
            cumulative_errors=2, cumulative_duration_ms=8000, worker_healthy=True,
            deployment_mode="compose",
        ))
        db.session.commit()
    response = client.get("/admin/system-health/performance.json")
    assert response.status_code == 200
    payload = response.get_json()
    # deployment_mode reflects the currently-running process's own
    # DEPLOYMENT_MODE env var (live, not historical), so it isn't tied to
    # what a past PerformanceSample happened to record.
    assert "deployment_mode" in payload
    assert len(payload["points"]) == 1
    point = payload["points"][0]
    assert point["requests_per_sec"] == round(60 / 60, 3)
    assert point["avg_latency_ms"] == round(3000 / 60, 2)


def test_system_health_performance_endpoint_denies_requester(client, app):
    from app import User as UserModel
    login(client)
    with app.app_context():
        requester = UserModel.query.filter_by(username="admin").one()
        requester.role = "requester"
        db.session.commit()
    response = client.get("/admin/system-health/performance.json")
    assert response.status_code == 403


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
    assert b"All words can match across different columns" in page.data
    assert b'aria-controls="discovery-device-table"' in page.data
    assert b"static/discovery.js" in page.data
    assert b"<script>" not in page.data

    discovery_script = (Path(__file__).parents[1] / "static" / "discovery.js").read_text()
    assert 'terms.every((term) => searchable.includes(term))' in discovery_script
    assert '["input", "search", "change"]' in discovery_script


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
