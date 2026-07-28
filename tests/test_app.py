import json
import os
import re
import tempfile
from io import BytesIO

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError

from app import (APIClient, APIIdempotencyRecord, Approval, ApprovalChain, Asset, Audit, AuditIntegrityKey, AuditRetentionPolicy, BusinessSchedule, CatalogRequest, CatalogTask, ChangeRevision,
                 ConfigurationItem, EnterpriseRecord, CatalogItem, CatalogItemRouting, DirectoryGroupMapping,
                 DirectoryManagedMembership, ExternalIdentity, Favorite, FileAttachment,
                 GroupMember, IntegrationConnection, IntegrationDelivery, Knowledge,
                 MonitoringEvent, MonitoringSource, Notification, OperationalTask,
                 OutboxEvent, ProblemProfile, RecordLink, ScheduleHoliday, SLADefinition,
                 RequestedItem, PlatformSetting, SupportGroup, TaskHistory, TaskSLA,
                 Tenant, Ticket, TicketAssignmentGroup, User, UserPreference,
                 WorkflowDefinition, WorkflowExecution, WorkflowJob,
                 WorkflowSchedule,
                 audit, create_api_token, create_app, create_notification, db,
                 deploy_workflow_package, process_workflow_jobs,
                 process_workflow_schedules, queue_workflow_event,
                 simulate_workflows,
                 integration_endpoint_valid, integration_endpoint_resolves_safely,
                 is_safe_internal_path, process_outbox,
                 provision_external_user, secret_value, settings_cipher,
                 rotate_audit_integrity_key, tenant_context_id, TenantResolutionError,
                 verify_audit_chain)
from werkzeug.security import generate_password_hash
from serviceops_core.security import role_has_action, validate_policy
from serviceops_core.priority import calculate_priority, validate_priority_policy
from serviceops_core.projections import (
    ProjectionConfigurationError, project_document, validate_projection_policy,
)
from serviceops_core.business_time import add_business_minutes
from serviceops_core.workflow import (
    WorkflowConfigurationError, load_workflow_package, materialize_workflow,
    validate_subflows, validate_workflow,
)
from tools.verify_supply_chain import verify_supply_chain
from datetime import datetime, time, timedelta, timezone


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        employee = User(
            username="employee", name="Test Employee", email="employee@test.invalid",
            password_hash=generate_password_hash("Employee123!"), role="requester",
        )
        manager = User(
            username="database.manager", name="Database Manager",
            email="database.manager@test.invalid",
            password_hash=generate_password_hash("Manager123!"), role="manager",
        )
        db.session.add_all([employee, manager])
        db.session.flush()
        admin = User.query.filter_by(username="admin").one()
        for group in SupportGroup.query.filter_by(group_type="IT Fulfillment").all():
            group.manager_id = manager.id
            db.session.add(GroupMember(group_id=group.id, user_id=manager.id, role="manager"))
            db.session.add(GroupMember(group_id=group.id, user_id=admin.id, role="member"))
        ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
        db.session.add(GroupMember(group_id=ccb.id, user_id=manager.id, role="CCB approver"))
        service_desk = SupportGroup.query.filter_by(name="Service Desk").one()
        db.session.add(GroupMember(group_id=service_desk.id, user_id=manager.id, role="member"))
        catalog_item = CatalogItem(
            name="Laptop computer", category="Hardware", description="Test catalog item.",
            delivery_days=5, approval_required=True,
        )
        db.session.add(catalog_item)
        db.session.flush()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        db.session.add(CatalogItemRouting(
            catalog_item_id=catalog_item.id, support_group_id=windows.id,
            updated_by_id=admin.id,
        ))
        db.session.commit()
    yield app
    os.unlink(path)


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="admin", password="Admin123!"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def group_id(app, name="CoreApps"):
    with app.app_context():
        return SupportGroup.query.filter_by(name=name).one().id


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}
    assert client.get("/live").json == {"status": "alive"}
    assert client.get("/ready").json == {"status": "ready"}


def test_live_api_documentation_matches_supported_contract(client):
    guide = client.get("/api/v1/docs")
    assert guide.status_code == 200
    assert guide.mimetype == "text/markdown"
    assert b"Idempotency-Key" in guide.data
    assert b"tickets:read" in guide.data
    assert b"Current compatibility boundary" in guide.data

    contract = client.get("/api/v1/openapi.json")
    assert contract.status_code == 200
    assert contract.json["openapi"] == "3.1.0"
    paths = contract.json["paths"]
    assert {
        "/openapi.json", "/docs", "/tickets", "/tickets/{number}",
        "/tickets/{number}/workflow-events", "/incidents",
        "/monitoring/{source_id}/events",
    }.issubset(paths)
    assert paths["/docs"]["get"]["security"] == []
    assert paths["/monitoring/{source_id}/events"]["post"]["security"] == [
        {"monitoringToken": []}
    ]
    assert contract.json["components"]["parameters"]["IdempotencyKey"]["required"]


def test_supply_chain_release_and_admission_controls_are_fail_closed():
    evidence = verify_supply_chain()
    assert evidence["valid"]
    assert evidence["action_pins"] >= 7
    assert evidence["kubernetes_digest_enforced"]
    assert evidence["attestation_admission_enabled"]


def test_csrf_protects_login_and_authenticated_mutations():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    csrf_app = create_app({
        "TESTING": True,
        "CSRF_ENABLED": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
    })
    csrf_client = csrf_app.test_client()
    login_page = csrf_client.get("/login")
    token = re.search(
        rb'name="_csrf_token" value="([^"]+)"', login_page.data
    ).group(1).decode()
    assert csrf_client.post("/login", data={
        "username": "admin", "password": "Admin123!",
    }).status_code == 400
    logged_in = csrf_client.post("/login", data={
        "username": "admin", "password": "Admin123!", "_csrf_token": token,
    })
    assert logged_in.status_code == 302
    assert "HttpOnly" in logged_in.headers["Set-Cookie"]
    assert "SameSite=Lax" in logged_in.headers["Set-Cookie"]
    dashboard = csrf_client.get("/")
    authenticated_token = re.search(
        rb'<meta name="csrf-token" content="([^"]+)">', dashboard.data
    ).group(1).decode()
    assert authenticated_token != token
    assert csrf_client.post("/ui/favorite", data={
        "url": "/", "label": "Dashboard",
    }).status_code == 400
    accepted = csrf_client.post(
        "/ui/favorite",
        data={"url": "/", "label": "Dashboard"},
        headers={"X-CSRF-Token": authenticated_token},
    )
    assert accepted.status_code == 200
    os.unlink(path)


def test_migration_baseline_creates_fresh_schema_and_records_revision():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    migrated_app = create_app({
        "TESTING": True,
        "AUTO_MIGRATE_IN_TESTS": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
    })
    with migrated_app.app_context():
        revision = db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
        assert revision == "20260727_0013"
        assert User.query.filter_by(username="admin").one()
    os.unlink(path)


def test_migration_baseline_adopts_existing_schema_without_data_loss():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    database_uri = f"sqlite:///{path}"
    legacy_app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": database_uri,
    })
    with legacy_app.app_context():
        db.session.add(Knowledge(
            title="Preserve during adoption", category="Migration",
            body="Existing operational data must survive.", author_id=1,
        ))
        db.session.commit()
    adopted_app = create_app({
        "TESTING": True,
        "AUTO_MIGRATE_IN_TESTS": True,
        "SQLALCHEMY_DATABASE_URI": database_uri,
    })
    with adopted_app.app_context():
        assert Knowledge.query.filter_by(title="Preserve during adoption").one()
        assert db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == "20260727_0013"
    os.unlink(path)


def test_tenant_migration_is_reversible_and_preserves_records():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    database_uri = f"sqlite:///{path}"
    migrated_app = create_app({
        "TESTING": True,
        "AUTO_MIGRATE_IN_TESTS": True,
        "SQLALCHEMY_DATABASE_URI": database_uri,
    })
    migration_config = AlembicConfig(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "alembic.ini")
    )
    migration_config.set_main_option(
        "script_location",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations"),
    )
    with migrated_app.app_context():
        before = db.session.execute(text("SELECT COUNT(*) FROM user")).scalar_one()
        db.session.remove()
        command.downgrade(migration_config, "20260726_0001")
        downgraded = inspect(db.engine)
        assert "tenant" not in downgraded.get_table_names()
        assert "tenant_id" not in {
            column["name"] for column in downgraded.get_columns("user")
        }
        assert db.session.execute(text("SELECT COUNT(*) FROM user")).scalar_one() == before
        db.session.remove()
        command.upgrade(migration_config, "head")
        upgraded = inspect(db.engine)
        assert "tenant" in upgraded.get_table_names()
        assert "tenant_id" in {
            column["name"] for column in upgraded.get_columns("user")
        }
        assert db.session.execute(text(
            "SELECT COUNT(*) FROM user WHERE tenant_id = 1"
        )).scalar_one() == before
        assert db.session.execute(
            text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "20260727_0013"
    os.unlink(path)


def test_postgres_migration_rehearsal_requires_isolated_database():
    from tools.postgres_migration_rehearsal import (
        digest_rows, validated_rehearsal_database,
    )

    assert validated_rehearsal_database(
        "postgresql+psycopg://user:secret@db/serviceops_migration_rehearsal"
    ) == "serviceops_migration_rehearsal"
    for unsafe_url in (
        "postgresql+psycopg://user:secret@db/serviceops",
        "sqlite:////tmp/serviceops_migration_rehearsal",
    ):
        with pytest.raises(ValueError):
            validated_rehearsal_database(unsafe_url)
    assert digest_rows([(1, "alpha"), (2, "beta")]) == digest_rows(
        [(1, "alpha"), (2, "beta")]
    )


def test_audit_chain_is_correlated_verified_exportable_and_append_only():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    protected_app = create_app({
        "TESTING": True,
        "AUTO_MIGRATE_IN_TESTS": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
    })
    protected_client = protected_app.test_client()
    request_id = "05f1bf47-c849-4e7e-aa77-d1697f9fc71c"
    response = protected_client.post(
        "/login",
        data={"username": "admin", "password": "Admin123!"},
        headers={"X-Request-ID": request_id},
    )
    assert response.status_code == 302
    assert response.headers["X-Request-ID"] == request_id
    with protected_app.app_context():
        row = Audit.query.one()
        assert row.request_id == request_id
        assert row.event_hash
        assert verify_audit_chain(1)["valid"]
        with pytest.raises(DBAPIError, match="append-only"):
            db.session.execute(text(
                "UPDATE audit SET details = 'tampered' WHERE id = :id"
            ), {"id": row.id})
            db.session.commit()
        db.session.rollback()
        with pytest.raises(DBAPIError, match="append-only"):
            db.session.execute(text("DELETE FROM audit WHERE id = :id"), {"id": row.id})
            db.session.commit()
        db.session.rollback()
        assert verify_audit_chain(1)["valid"]
    exported = protected_client.get("/admin/audit/export")
    assert exported.status_code == 200
    assert exported.headers["X-ServiceOps-Audit-Signature"]
    assert exported.json["integrity"]["valid"]
    assert exported.json["events"][0]["request_id"] == request_id
    os.unlink(path)


def test_audit_key_rotation_retention_and_dedicated_siem_delivery(
    monkeypatch, client, app
):
    deliveries = []

    class FakeResponse:
        status_code = 202
        is_redirect = False

    def fake_post(url, json, headers, timeout, allow_redirects=True):
        deliveries.append((url, json, headers, timeout))
        return FakeResponse()

    monkeypatch.setattr("app.requests.post", fake_post)
    monkeypatch.setattr(
        "app.socket.getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        original = Audit.query.order_by(Audit.id).first()
        original_hash = original.event_hash
        original_key_id = original.integrity_key_id
        key = rotate_audit_integrity_key(1, admin.id)
        db.session.commit()
        assert key.active
        assert key.key_id != original_key_id
        assert AuditIntegrityKey.query.filter_by(
            key_id="environment-v1"
        ).one().secret_encrypted
        assert Audit.query.filter_by(
            action="audit key rotate"
        ).one().integrity_key_id == key.key_id
        assert db.session.get(Audit, original.id).event_hash == original_hash
        assert verify_audit_chain(1)["valid"]

        db.session.add_all([
            PlatformSetting(
                key="AUDIT_STREAM_ENABLED", value="true", encrypted=False
            ),
            IntegrationConnection(
                name="Immutable SIEM", kind="siem",
                endpoint="https://siem.example.test/ingest",
                secret_encrypted=settings_cipher().encrypt(b"siem-secret").decode(),
                created_by_id=admin.id,
            ),
            IntegrationConnection(
                name="General webhook", kind="webhook",
                endpoint="https://hooks.example.test/serviceops",
                secret_encrypted=settings_cipher().encrypt(b"hook-secret").decode(),
                created_by_id=admin.id,
            ),
        ])
        audit("security test", "Audit streaming", "SIEM only")
        db.session.commit()
        assert process_outbox() >= 1
        audit_delivery = next(
            item for item in deliveries if "siem.example" in item[0]
        )
        assert audit_delivery[1]["type"] == "audit.created"
        assert audit_delivery[1]["data"]["integrity_key_id"] == key.key_id
        assert not any(
            "hooks.example" in item[0]
            and item[1].get("type") == "audit.created"
            for item in deliveries
        )

    assert client.post("/admin/audit/retention", data={
        "retention_days": "30",
    }).status_code == 400
    saved = client.post("/admin/audit/retention", data={
        "retention_days": "3650",
        "legal_hold": "on",
        "external_export_required": "on",
    })
    assert saved.status_code == 302
    with app.app_context():
        policy = AuditRetentionPolicy.query.one()
        assert policy.retention_days == 3650
        assert policy.legal_hold
        assert policy.external_export_required
        assert verify_audit_chain(1)["valid"]
    exported = client.get("/admin/audit/export")
    assert exported.status_code == 200
    assert exported.headers["X-ServiceOps-Audit-Key-ID"].startswith("audit-")


def test_rest_api_scopes_idempotency_projection_and_pagination(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(
            name="Automation test", token_prefix=prefix, token_hash=token_hash,
            scopes_json='["incidents:create","tickets:read","tickets:update"]',
            acting_user_id=admin.id, created_by_id=admin.id,
        ))
        db.session.commit()
        coreapps = SupportGroup.query.filter_by(name="CoreApps").one()
        coreapps_id = coreapps.id
    headers = {
        "Authorization": f"Bearer {token}",
        "Idempotency-Key": "incident-create-001",
        "X-Request-ID": "bc82da3c-f47f-428e-aefd-60bd0ec706a4",
    }
    body = {
        "title": "API-created outage",
        "description": "Created through the versioned REST contract.",
        "priority": "P2",
        "assignment_group_id": coreapps_id,
    }
    assert client.get("/api/v1/tickets").status_code == 401
    created = client.post("/api/v1/incidents", json=body, headers=headers)
    assert created.status_code == 201
    assert created.headers["X-Request-ID"] == headers["X-Request-ID"]
    number = created.json["data"]["number"]
    assert created.json["data"]["internal"]["assignment_group"]["name"] == "CoreApps"
    replayed = client.post("/api/v1/incidents", json=body, headers=headers)
    assert replayed.status_code == 201
    assert replayed.headers["Idempotency-Replayed"] == "true"
    assert replayed.json == created.json
    conflict = client.post(
        "/api/v1/incidents", json=body | {"title": "Different request"},
        headers=headers,
    )
    assert conflict.status_code == 409
    assert conflict.json["error"]["request_id"]
    listed = client.get(
        "/api/v1/tickets?limit=1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert listed.status_code == 200
    assert len(listed.json["data"]) == 1
    updated = client.patch(
        f"/api/v1/tickets/{number}",
        json={"state": "In Progress"},
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "incident-update-001",
        },
    )
    assert updated.status_code == 200
    assert updated.json["data"]["state"] == "In Progress"
    with app.app_context():
        assert Ticket.query.filter_by(title="API-created outage").count() == 1
        assert APIIdempotencyRecord.query.count() == 2
        assert verify_audit_chain(1)["valid"]


def test_api_client_admin_one_time_secret_and_pwa_privacy(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
    created = client.post("/admin/api-clients", data={
        "name": "One-time secret test",
        "acting_user_id": str(admin_id),
        "scopes": ["tickets:read"],
    }, follow_redirects=True)
    assert created.status_code == 200
    match = re.search(rb"sop_[A-Za-z0-9_-]+", created.data)
    assert match
    token = match.group(0).decode()
    assert token not in "\n".join(created.headers.getlist("Set-Cookie"))
    assert token.encode() not in client.get("/admin/api-clients").data
    assert client.get(
        "/api/v1/tickets", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 200
    assert client.post(
        "/api/v1/incidents",
        json={"title": "Denied", "description": "No scope"},
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "denied-create",
        },
    ).status_code == 403
    manifest = client.get("/manifest.webmanifest")
    assert manifest.status_code == 200
    assert manifest.json["display"] == "standalone"
    worker = client.get("/service-worker.js")
    assert worker.status_code == 200
    assert b"/api/" not in worker.data
    assert b"/ticket/" not in worker.data
    assert b"caches.open" in worker.data


def test_durable_smtp_signed_webhook_and_teams_delivery(monkeypatch, app):
    assert not integration_endpoint_valid("http://hooks.example.test/serviceops")
    assert not integration_endpoint_valid("https://127.0.0.1/hook")
    assert not integration_endpoint_valid("https://169.254.169.254/latest/meta-data")
    assert integration_endpoint_valid("https://hooks.example.test/serviceops")
    smtp_messages = []
    webhook_calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("smtp.example.test", 587, 10)
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def ehlo(self):
            return None
        def starttls(self, context):
            assert context
        def login(self, username, password):
            assert (username, password) == ("mailer", "smtp-secret")
        def send_message(self, message):
            smtp_messages.append(message)

    class FakeResponse:
        status_code = 202
        is_redirect = False

    def fake_post(url, json, headers, timeout, allow_redirects=True):
        webhook_calls.append((url, json, headers, timeout))
        return FakeResponse()

    monkeypatch.setattr("app.smtplib.SMTP", FakeSMTP)
    monkeypatch.setattr("app.requests.post", fake_post)
    monkeypatch.setattr(
        "app.socket.getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        settings = {
            "SMTP_ENABLED": "true", "SMTP_HOST": "smtp.example.test",
            "SMTP_PORT": "587", "SMTP_STARTTLS": "true",
            "SMTP_USERNAME": "mailer", "SMTP_FROM": "serviceops@example.test",
        }
        for key, value in settings.items():
            db.session.add(PlatformSetting(key=key, value=value, encrypted=False))
        db.session.add(PlatformSetting(
            key="SMTP_PASSWORD",
            value=settings_cipher().encrypt(b"smtp-secret").decode(),
            encrypted=True,
        ))
        db.session.add_all([
            IntegrationConnection(
                name="Signed operations webhook", kind="webhook",
                endpoint="https://hooks.example.test/serviceops",
                secret_encrypted=settings_cipher().encrypt(b"signing-secret").decode(),
                created_by_id=admin.id,
            ),
            IntegrationConnection(
                name="Operations Teams", kind="teams",
                endpoint="https://teams.example.test/webhook",
                created_by_id=admin.id,
            ),
        ])
        create_notification(
            admin.id, "Integration test", "Durable delivery body."
        )
        db.session.commit()
        assert process_outbox() == 1
        event = OutboxEvent.query.one()
        assert event.state == "Completed"
        assert IntegrationDelivery.query.filter_by(state="Delivered").count() == 3
        assert len(smtp_messages) == 1
        assert smtp_messages[0]["To"] == admin.email
        signed = next(call for call in webhook_calls if "hooks.example" in call[0])
        assert signed[2]["X-ServiceOps-Signature"].startswith("sha256=")
        assert signed[2]["X-ServiceOps-Event-ID"] == event.event_id
        teams = next(call for call in webhook_calls if "teams.example" in call[0])
        assert teams[1]["text"].startswith("**Integration test**")


def test_monitoring_ingestion_auth_deduplication_and_team_routing(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        unix = SupportGroup.query.filter_by(name="Unix").one()
        token, prefix, token_hash = create_api_token()
        source = MonitoringSource(
            name="Production monitoring", token_prefix=prefix,
            token_hash=token_hash, assignment_group_id=unix.id,
            created_by_id=admin.id,
        )
        db.session.add(source)
        db.session.commit()
        source_id = source.source_id
    payload = {
        "external_id": "alert-9001",
        "severity": "critical",
        "resource": "unix-prod-01",
        "summary": "Filesystem unavailable",
        "observed_value": 100,
    }
    endpoint = f"/api/v1/monitoring/{source_id}/events"
    assert client.post(endpoint, json=payload).status_code == 401
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post(endpoint, json=payload, headers=headers)
    assert created.status_code == 201
    assert not created.json["data"]["deduplicated"]
    replay = client.post(endpoint, json=payload, headers=headers)
    assert replay.status_code == 200
    assert replay.json["data"]["deduplicated"]
    assert replay.json["data"]["record_number"] == created.json["data"]["record_number"]
    with app.app_context():
        assert MonitoringEvent.query.count() == 1
        record = EnterpriseRecord.query.filter_by(domain="event").one()
        assert (record.priority, record.risk) == ("P1", "Critical")
        task = OperationalTask.query.filter_by(parent_id=record.id, task_kind="event").one()
        assert task.assignment_group.name == "Unix"
        assert verify_audit_chain(1)["valid"]


def test_login_and_dashboard(client):
    response = login(client)
    assert response.status_code == 200
    assert b"Recently updated" in response.data


def test_declarative_action_policy_and_requester_field_projection(client, app):
    assert validate_policy()
    assert role_has_action("requester", "comment_public")
    assert not role_has_action("requester", "comment_internal")
    assert not role_has_action("requester", "approve")
    assert role_has_action("admin", "security_administer")
    assert validate_projection_policy()
    assert project_document("ticket", "requester", {
        "id": 1, "number": "INC1", "title": "Visible",
        "internal": {"secret": "must not leak"},
        "unexpected": "must not leak",
    }) == {"id": 1, "number": "INC1", "title": "Visible"}
    with pytest.raises(ProjectionConfigurationError):
        project_document("unregistered_record", "admin", {"id": 1})
    with pytest.raises(ProjectionConfigurationError):
        validate_projection_policy({
            "schema": "serviceops.field-projections.v1",
            "resources": {
                "ticket": {
                    "allowed_fields": ["id"],
                    "audiences": {"requester": ["id", "secret"]},
                }
            },
        })

    login(client, "employee", "Employee123!")
    client.post("/tickets/new/incident", data={
        "title": "Requester projection test",
        "description": "Public incident description",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    client.post("/logout")
    login(client)
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Requester projection test").one()
        ticket_id = ticket.id
    client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress",
        "priority": "P2", "assignee_id": "",
    })
    internal = client.get(f"/ticket/{ticket_id}")
    assert b"Ticket history" in internal.data
    assert b"priority" in internal.data.lower()

    client.post("/logout")
    login(client, "employee", "Employee123!")
    requester = client.get(f"/ticket/{ticket_id}")
    assert requester.status_code == 200
    assert b"Public incident description" in requester.data
    assert b"Ticket history" not in requester.data
    assert b"Major incident coordination" not in requester.data
    assert b"Service level commitments" not in requester.data
    assert b"Approval history" not in requester.data

    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(
            name="Requester projection token",
            token_prefix=prefix,
            token_hash=token_hash,
            scopes_json='["tickets:read"]',
            acting_user_id=employee.id,
            created_by_id=User.query.filter_by(username="admin").one().id,
        ))
        db.session.commit()
    api_record = client.get(
        "/api/v1/tickets", headers={"Authorization": f"Bearer {token}"}
    )
    assert api_record.status_code == 200
    assert api_record.json["data"]
    assert all("internal" not in row for row in api_record.json["data"])


def test_tenant_scope_prevents_cross_tenant_ticket_discovery(client, app):
    with app.app_context():
        other_tenant = Tenant(id=2, slug="other", name="Other organisation")
        other_user = User(
            username="other.agent", name="Other Agent", email="other@test.invalid",
            password_hash=generate_password_hash("OtherTenant123!"),
            role="agent", tenant_id=2,
        )
        db.session.add_all([other_tenant, other_user])
        db.session.flush()
        other_group = SupportGroup(
            name="Other Operations", group_type="IT Fulfillment",
            manager_id=other_user.id, tenant_id=2,
        )
        db.session.add(other_group)
        db.session.flush()
        db.session.add(GroupMember(
            group_id=other_group.id, user_id=other_user.id, role="manager"
        ))
        other_ticket = Ticket(
            number="INC9000001", kind="incident", title="Other tenant outage",
            description="Must not cross the tenant boundary.",
            requester_id=other_user.id, tenant_id=2,
        )
        db.session.add(other_ticket)
        db.session.flush()
        db.session.add(TicketAssignmentGroup(
            ticket_id=other_ticket.id, group_id=other_group.id
        ))
        db.session.add_all([
            Knowledge(
                title="Other tenant runbook", category="Operations",
                body="Must remain private.", author_id=other_user.id, tenant_id=2,
            ),
            Asset(
                asset_tag="OTHER-ASSET-1", name="Other tenant server",
                asset_type="Server", status="In use", tenant_id=2,
            ),
            ConfigurationItem(
                name="other-private-ci", ci_class="Server",
                environment="Production", operational_status="Operational",
                tenant_id=2,
            ),
            CatalogItem(
                name="Other tenant catalog item", category="Private",
                description="Must remain private.", delivery_days=1,
                active=True, tenant_id=2,
            ),
        ])
        db.session.commit()
        other_ticket_id = other_ticket.id
        other_catalog_id = CatalogItem.query.filter_by(
            name="Other tenant catalog item"
        ).one().id

    login(client)
    assert b"INC9000001" not in client.get("/tickets/incident").data
    assert client.get(f"/ticket/{other_ticket_id}").status_code == 404
    assert b"Other tenant runbook" not in client.get("/knowledge").data
    assert b"OTHER-ASSET-1" not in client.get("/assets").data
    assert b"other-private-ci" not in client.get("/cmdb").data
    assert b"Other tenant catalog item" not in client.get("/catalog").data
    assert client.post(
        f"/catalog/{other_catalog_id}/order", data={"details": "Cross tenant"}
    ).status_code == 404
    assert client.get(
        "/ui/search?q=INC9000001", headers={"Accept": "application/json"}
    ).json == {"results": []}
    assert client.get(
        "/ui/search?q=other-private-ci", headers={"Accept": "application/json"}
    ).json == {"results": []}

    client.post("/logout")
    login(client, "other.agent", "OtherTenant123!")
    assert client.get(f"/ticket/{other_ticket_id}").status_code == 200


def test_incident_lifecycle(client, app):
    login(client)
    created = client.post("/tickets/new/incident", data={
        "title": "VPN is unavailable",
        "description": "Connection fails from the remote office.",
        "category": "Network",
        "priority": "P2",
        "group_id": group_id(app, "Network"),
    }, follow_redirects=True)
    assert created.status_code == 200
    assert b"INC0000001" in created.data
    with app.app_context():
        ticket = Ticket.query.one()
        ticket_id = ticket.id
        assert ticket.assignment_group_record.group.name == "Network"
    updated = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P1", "assignee_id": ""
    }, follow_redirects=True)
    assert b"In Progress" in updated.data


def test_only_owning_team_can_operationally_update_ticket(client, app):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        ssd = SupportGroup.query.filter_by(name="SSD").one()
        unix_agent = User(
            username="unix.agent", name="Unix Agent", email="unix.agent@test.invalid",
            password_hash=generate_password_hash("Unix123!"), role="agent",
        )
        ssd_agent = User(
            username="ssd.agent", name="SSD Agent", email="ssd.agent@test.invalid",
            password_hash=generate_password_hash("Ssd12345!"), role="agent",
        )
        db.session.add_all([unix_agent, ssd_agent])
        db.session.flush()
        db.session.add_all([
            GroupMember(group_id=unix.id, user_id=unix_agent.id, role="member"),
            GroupMember(group_id=ssd.id, user_id=ssd_agent.id, role="member"),
        ])
        db.session.commit()
        unix_id, ssd_agent_id = unix.id, ssd_agent.id

    login(client)
    response = client.post("/tickets/new/change", data={
        "title": "Unix-owned protected change",
        "description": "Operational control belongs to Unix.",
        "category": "Software", "priority": "P3", "change_type": "Normal",
        "risk_score": "50", "impact": "Medium", "group_id": unix_id,
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
    })
    assert response.status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Unix-owned protected change").one()
        ticket_id, current_state = ticket.id, ticket.state
    assert client.post(
        f"/ticket/{ticket_id}/attachments",
        data={"file": (BytesIO(b"plan"), "unix-plan.txt")},
        content_type="multipart/form-data",
    ).status_code == 302
    with app.app_context():
        attachment_id = FileAttachment.query.filter_by(ticket_id=ticket_id).one().id

    client.post("/logout")
    login(client, "ssd.agent", "Ssd12345!")
    detail = client.get(f"/ticket/{ticket_id}")
    assert detail.status_code == 200
    assert b"Read only: operational updates are restricted to active members of Unix" in detail.data
    assert b"Save changes" not in detail.data
    assert b"Unix-owned protected change" in client.get("/tickets/change").data
    assert b"Unix-owned protected change" in client.get(
        "/ui/search?q=Unix-owned", headers={"Accept": "application/json"}
    ).data
    assert client.get(f"/attachments/{attachment_id}").status_code == 200
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P1",
        "assignee_id": "",
    }).status_code == 403
    assert client.post(
        f"/task-board/{ticket_id}/move", data={"state": current_state}
    ).status_code == 403
    assert client.post(
        f"/ticket/{ticket_id}/checklist", data={"text": "Unauthorized"}
    ).status_code == 403
    assert client.post(f"/change/{ticket_id}/conflicts").status_code == 403

    client.post("/logout")
    login(client, "unix.agent", "Unix123!")
    owner_detail = client.get(f"/ticket/{ticket_id}")
    assert b"Save changes" in owner_detail.data
    assert b"Unix Agent" in owner_detail.data
    assert b"SSD Agent" not in owner_detail.data
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P2",
        "assignee_id": ssd_agent_id,
    }).status_code == 400
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P2",
        "assignee_id": "",
    }).status_code == 302
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.priority == "P2"
        assert ticket.state == current_state


def test_unrelated_team_cannot_view_or_mutate_catalog_request(client, app):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        unix_agent = User(
            username="unix.catalog", name="Unix Catalog Agent",
            email="unix.catalog@test.invalid",
            password_hash=generate_password_hash("UnixCatalog123!"), role="agent",
        )
        windows_agent = User(
            username="windows.catalog", name="Windows Catalog Agent",
            email="windows.catalog@test.invalid",
            password_hash=generate_password_hash("WindowsCatalog123!"), role="agent",
        )
        db.session.add_all([unix_agent, windows_agent])
        db.session.flush()
        db.session.add_all([
            GroupMember(group_id=unix.id, user_id=unix_agent.id, role="member"),
            GroupMember(group_id=windows.id, user_id=windows_agent.id, role="member"),
        ])
        item = CatalogItem.query.filter_by(name="Laptop computer").one()
        item.approval_required = False
        db.session.commit()
        item_id = item.id

    login(client)
    assert client.post(f"/catalog/{item_id}/order", data={
        "details": "Windows-only fulfillment visibility",
    }).status_code == 302
    with app.app_context():
        req = CatalogRequest.query.one()
        request_id = req.id
        ritm_id = req.items[0].id

    client.post("/logout")
    login(client, "unix.catalog", "UnixCatalog123!")
    assert client.get("/requests").status_code == 200
    assert b"REQ0000001" not in client.get("/requests").data
    assert client.get(f"/request/{request_id}").status_code == 403
    assert client.get(
        "/ui/search?q=REQ0000001", headers={"Accept": "application/json"}
    ).json == {"results": []}
    assert client.post(f"/request/{request_id}/items", data={
        "catalog_item_id": item_id, "details": "Unauthorized extra item",
    }).status_code == 403
    assert client.post(f"/ritm/{ritm_id}/tasks", data={
        "title": "Unauthorized Unix task", "group_id": group_id(app, "Unix"),
        "execution_mode": "Parallel",
    }).status_code == 403

    client.post("/logout")
    login(client, "windows.catalog", "WindowsCatalog123!")
    assert client.get(f"/request/{request_id}").status_code == 200


def test_requester_cannot_create_change(client):
    login(client, "employee", "Employee123!")
    assert client.get("/tickets/new/change").status_code == 403


def test_role_protection(client):
    login(client, "employee", "Employee123!")
    assert client.get("/admin/users").status_code == 403
    assert client.get("/assets").status_code == 403


def test_enterprise_problem_workflow(client, app):
    login(client)
    response = client.post("/module/problem/new", data={
        "record_type": "Root cause analysis",
        "title": "Recurring database latency",
        "description": "Investigate repeated latency during peak usage.",
        "priority": "P2",
        "risk": "High",
        "approval_required": "1",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"PRB0000001" in response.data
    assert b"Awaiting Approval" in response.data
    with app.app_context():
        record = EnterpriseRecord.query.filter_by(domain="problem").one()
        approval = Approval.query.filter_by(enterprise_record_id=record.id).one()
        record_id, approval_id = record.id, approval.id
    decision = client.post(f"/enterprise/{record_id}", data={
        "action": "approve", "approval_id": approval_id, "comments": "Proceed with investigation."
    }, follow_redirects=True)
    assert b"Approved" in decision.data


def test_catalog_request_and_cmdb(client, app):
    login(client, "employee", "Employee123!")
    catalog = client.get("/catalog")
    assert b"Laptop computer" in catalog.data
    ordered = client.post("/catalog/1/order", data={"details": "Laptop for remote work"}, follow_redirects=True)
    assert b"REQ0000001" in ordered.data
    assert b"RITM0000001" in ordered.data
    assert b"Manager approval" in ordered.data
    client.post("/logout")
    login(client)
    assert client.get("/cmdb").status_code == 200


def test_catalog_approval_chain_creates_fulfillment_task(client, app):
    login(client)
    client.post("/catalog/1/order", data={"details": "Engineering laptop"}, follow_redirects=True)
    with app.app_context():
        ritm = RequestedItem.query.one()
        chain = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm.id).one()
        first_vote = chain.gates[0].votes[0]
        ritm_id, first_vote_id = ritm.id, first_vote.id
    client.post(f"/approval-votes/{first_vote_id}/decide",
                data={"decision": "Approved", "comments": "Manager approved."})
    with app.app_context():
        chain = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm_id).one()
        second_vote = chain.gates[1].votes[0]
        second_vote_id = second_vote.id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    client.post(f"/approval-votes/{second_vote_id}/decide",
                data={"decision": "Approved", "comments": "Fulfillment approved."})
    with app.app_context():
        ritm = db.session.get(RequestedItem, ritm_id)
        assert ritm.state == "Approved"
        task = CatalogTask.query.filter_by(requested_item_id=ritm.id).one()
        assert task.assignment_group.name == "Windows"
        assert TaskSLA.query.filter_by(target_type="ritm", target_id=ritm.id).count() == 1


def test_admin_can_route_future_catalog_items_to_any_fulfillment_team(client, app):
    with app.app_context():
        item = CatalogItem(
            name="Database access package", category="Access",
            description="Future catalog routing verification.",
            approval_required=False,
        )
        db.session.add(item)
        db.session.commit()
        item_id = item.id
        database_id = SupportGroup.query.filter_by(name="Database").one().id
    login(client)
    configured = client.post("/itil/administration", data={
        "action": "set_catalog_route",
        "catalog_item_id": item_id,
        "group_id": database_id,
    })
    assert configured.status_code == 302
    ordered = client.post(f"/catalog/{item_id}/order", data={
        "details": "Route this future use case to Database.",
    })
    assert ordered.status_code == 302
    with app.app_context():
        route = CatalogItemRouting.query.filter_by(catalog_item_id=item_id).one()
        task = CatalogTask.query.join(RequestedItem).filter(
            RequestedItem.catalog_item_id == item_id
        ).one()
        assert route.support_group.name == "Database"
        assert task.assignment_group.name == "Database"


def test_admin_can_create_and_edit_catalog_item_with_fulfillment_policy(client, app):
    login(client)
    database_id = group_id(app, "Database")
    created = client.post("/itil/administration", data={
        "action": "create_catalog_item",
        "name": "Managed database account",
        "category": "Access",
        "description": "Provision a governed database account.",
        "delivery_days": "4",
        "group_id": database_id,
        "approval_required": "1",
        "active": "1",
    })
    assert created.status_code == 302
    with app.app_context():
        item = CatalogItem.query.filter_by(name="Managed database account").one()
        item_id = item.id
        assert item.category == "Access"
        assert item.delivery_days == 4
        assert item.approval_required
        assert item.active
        assert item.fulfillment_route.support_group.name == "Database"

    windows_id = group_id(app, "Windows")
    updated = client.post("/itil/administration", data={
        "action": "update_catalog_item",
        "catalog_item_id": item_id,
        "name": "Managed application account",
        "category": "Software",
        "description": "Provision a governed application account.",
        "delivery_days": "2",
        "group_id": windows_id,
    })
    assert updated.status_code == 302
    with app.app_context():
        item = db.session.get(CatalogItem, item_id)
        assert item.name == "Managed application account"
        assert item.delivery_days == 2
        assert not item.approval_required
        assert not item.active
        assert item.fulfillment_route.support_group.name == "Windows"
    assert client.post(f"/catalog/{item_id}/order", data={
        "details": "Inactive items must remain unavailable.",
    }).status_code == 404


def test_catalog_request_visibility_is_limited_to_participants_and_fulfillment_team(client, app):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        unix_user = User(
            username="visibility.unix", name="Visibility Unix",
            email="visibility.unix@test.invalid",
            password_hash=generate_password_hash("UnixVisibility123!"), role="agent",
        )
        windows_user = User(
            username="visibility.windows", name="Visibility Windows",
            email="visibility.windows@test.invalid",
            password_hash=generate_password_hash("WindowsVisibility123!"), role="agent",
        )
        db.session.add_all([unix_user, windows_user])
        db.session.flush()
        db.session.add_all([
            GroupMember(group_id=unix.id, user_id=unix_user.id, role="member"),
            GroupMember(group_id=windows.id, user_id=windows_user.id, role="member"),
        ])
        db.session.commit()

    login(client, "employee", "Employee123!")
    assert client.post("/catalog/1/order", data={
        "details": "Windows-routed laptop request.",
    }).status_code == 302
    with app.app_context():
        req = CatalogRequest.query.one()
        request_id, request_number = req.id, req.number

    client.post("/logout")
    login(client, "visibility.unix", "UnixVisibility123!")
    unix_list = client.get("/requests")
    assert request_number.encode() not in unix_list.data
    assert client.get(f"/request/{request_id}").status_code == 403
    unix_search = client.get(f"/ui/search?q={request_number}", headers={
        "Accept": "application/json",
    })
    assert unix_search.json == {"results": []}

    client.post("/logout")
    login(client, "visibility.windows", "WindowsVisibility123!")
    assert request_number.encode() in client.get("/requests").data
    assert client.get(f"/request/{request_id}").status_code == 200

    client.post("/logout")
    login(client, "employee", "Employee123!")
    assert request_number.encode() in client.get("/requests").data
    assert client.get(f"/request/{request_id}").status_code == 200

    client.post("/logout")
    login(client)
    assert request_number.encode() in client.get("/requests").data


def test_catalog_task_requires_valid_fulfillment_lifecycle(client, app):
    login(client)
    item = None
    with app.app_context():
        item = CatalogItem(
            name="No approval test item", category="Testing",
            description="Workflow transition test", approval_required=False,
        )
        db.session.add(item)
        db.session.commit()
        item_id = item.id
    client.post(f"/catalog/{item_id}/order", data={"details": "Test lifecycle"})
    with app.app_context():
        task_id = CatalogTask.query.one().id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/catalog-task/{task_id}", data={
        "state": "Closed Complete", "work_notes": "Attempted bypass",
    }).status_code == 409
    assert client.post(f"/catalog-task/{task_id}", data={
        "state": "Work in Progress", "work_notes": "Started",
    }).status_code == 302
    assert client.post(f"/catalog-task/{task_id}", data={
        "state": "Closed Complete", "work_notes": "Completed",
    }).status_code == 302


def test_change_has_governance_approval_chain_and_sla(client, app):
    login(client)
    client.post("/tickets/new/change", data={
        "title": "Upgrade database cluster",
        "description": "Apply the approved database release.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "75", "impact": "High",
        "implementation_plan": "Upgrade replicas, then primary.",
        "test_plan": "Run health and transaction tests.",
        "backout_plan": "Restore the previous release.",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="change").one()
        assert ticket.change_governance.risk_score == 75
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).one()
        assert [gate.name for gate in chain.gates] == ["CoreApps manager assessment", "CCB weekly authorization"]
        assert chain.gates[1].mode == "majority"
        assert TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id).count() == 1


def test_change_cannot_bypass_approval_from_detail_or_board(client, app):
    login(client)
    client.post("/tickets/new/change", data={
        "title": "Protected database change",
        "description": "Must complete manager and CCB authorization.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "70", "impact": "High",
        "implementation_plan": "Implement safely.", "test_plan": "Validate safely.",
        "backout_plan": "Back out safely.",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="change").one()
        ticket_id = ticket.id
        first_vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).one().gates[0].votes[0].id
    bypass = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P2",
        "assignee_id": "",
    })
    assert bypass.status_code == 409
    assert client.post(
        f"/task-board/{ticket_id}/move", data={"state": "In Progress"}
    ).status_code == 409
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Awaiting Approval"

    # Platform administrators cannot cast another named approver's vote.
    assert client.post(f"/approval-votes/{first_vote_id}/decide", data={
        "decision": "Approved", "comments": "Unauthorized override",
    }).status_code == 403

    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{first_vote_id}/decide", data={
        "decision": "Approved", "comments": "Manager authorization",
    }).status_code == 302
    with app.app_context():
        chain = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).one()
        ccb_vote_id = chain.gates[1].votes[0].id
    assert client.post(f"/approval-votes/{ccb_vote_id}/decide", data={
        "decision": "Approved", "comments": "CCB authorization",
    }).status_code == 302
    allowed = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P2",
        "assignee_id": "",
    })
    assert allowed.status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "In Progress"


def test_incident_problem_change_and_parent_relationship_network(client, app):
    login(client)
    coreapps_id = group_id(app)
    for title in ("Parent application outage", "Child user report"):
        assert client.post("/tickets/new/incident", data={
            "title": title, "description": "Relationship verification.",
            "category": "Software", "priority": "P2", "group_id": coreapps_id,
        }).status_code == 302
    assert client.post("/module/problem/new", data={
        "record_type": "Root cause analysis",
        "title": "Application outage root cause",
        "description": "Investigate the common cause.",
        "priority": "P2", "risk": "High",
    }).status_code == 302
    assert client.post("/tickets/new/change", data={
        "title": "Permanent application fix",
        "description": "Deploy the permanent correction.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "70", "impact": "High", "group_id": coreapps_id,
        "implementation_plan": "Deploy safely.", "test_plan": "Validate service.",
        "backout_plan": "Restore prior release.",
    }).status_code == 302
    with app.app_context():
        incidents = Ticket.query.filter_by(kind="incident").order_by(Ticket.id).all()
        parent, child = incidents
        problem = EnterpriseRecord.query.filter_by(domain="problem").one()
        change = Ticket.query.filter_by(kind="change").one()
        parent_id, child_id = parent.id, child.id
        problem_number, change_number, parent_number = (
            problem.number, change.number, parent.number
        )
    assert client.post(f"/record/ticket/{child_id}/relationships", data={
        "link_type": "parent_incident", "target_number": parent_number,
    }).status_code == 302
    assert client.post(f"/record/ticket/{parent_id}/relationships", data={
        "link_type": "underlying_problem", "target_number": problem_number,
    }).status_code == 302
    assert client.post(f"/record/ticket/{parent_id}/relationships", data={
        "link_type": "resolution_change", "target_number": change_number,
    }).status_code == 302
    assert client.post(f"/record/ticket/{parent_id}/relationships", data={
        "link_type": "caused_by_change", "target_number": change_number,
    }).status_code == 302
    page = client.get(f"/ticket/{parent_id}")
    assert b"Problem" in page.data
    assert b"Change request" in page.data
    assert b"Caused by change" in page.data
    with app.app_context():
        assert RecordLink.query.count() == 4
        history = TaskHistory.query.filter_by(
            target_type="ticket", target_id=parent_id,
            event="Related record linked",
        ).all()
        assert len(history) == 4


def test_material_change_edit_supersedes_approvals_and_notifies_approvers(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Approved production deployment",
        "description": "Original approved purpose.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "50", "impact": "Medium", "group_id": group_id(app),
        "implementation_plan": "Deploy version one.",
        "test_plan": "Test version one.",
        "backout_plan": "Restore version zero.",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Approved production deployment").one()
        ticket_id = ticket.id
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).one()
        manager_vote_id = chain.gates[0].votes[0].id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{manager_vote_id}/decide", data={
        "decision": "Approved", "comments": "Manager approved v1.",
    }).status_code == 302
    with app.app_context():
        chain = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).order_by(ApprovalChain.id.desc()).first()
        ccb_vote_id = chain.gates[1].votes[0].id
    assert client.post(f"/approval-votes/{ccb_vote_id}/decide", data={
        "decision": "Approved", "comments": "CCB approved v1.",
    }).status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Approved"
        old_chain_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).one().id
        notifications_before = Notification.query.count()
        notification_id_marker = db.session.execute(
            text("SELECT COALESCE(MAX(id), 0) FROM notification")
        ).scalar_one()
    revised = client.post(f"/change/{ticket_id}/plan", data={
        "title": "Approved production deployment",
        "description": "Revised production purpose.",
        "change_type": "Normal", "risk_score": "85", "impact": "High",
        "implementation_plan": "Deploy version two with a new sequence.",
        "test_plan": "Run expanded regression.",
        "backout_plan": "Restore version one.",
        "planned_start": "", "planned_end": "", "ci_id": "",
    })
    assert revised.status_code == 302
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        chains = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).order_by(ApprovalChain.id).all()
        assert ticket.state == "Awaiting Approval"
        assert db.session.get(ApprovalChain, old_chain_id).state == "Superseded"
        assert chains[-1].state == "Running"
        assert ticket.change_revision.revision == 2
        assert Notification.query.count() > notifications_before
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket_id,
            event="Approval restarted",
        ).one()
        new_chain = chains[-1]
        stage1_approver_ids = {vote.approver_id for vote in new_chain.gates[0].votes}
        stage2_approver_ids = {vote.approver_id for vote in new_chain.gates[1].votes}
        # Each stage-1 (owning-team manager) approver gets exactly one
        # reapproval notification -- create_approval_chain() and
        # supersede_change_approval() must not both notify them.
        for approver_id in stage1_approver_ids:
            assert Notification.query.filter(
                Notification.id > notification_id_marker,
                Notification.user_id == approver_id,
                Notification.title == f"Reapproval required: {ticket.number} v2",
            ).count() == 1
        # Stage-2 (CCB) approvers must not be notified at all yet -- their gate
        # has not been activated because stage 1 hasn't approved v2.
        for approver_id in stage2_approver_ids - stage1_approver_ids:
            assert Notification.query.filter(
                Notification.id > notification_id_marker,
                Notification.user_id == approver_id,
            ).count() == 0


def test_required_change_tasks_block_parent_completion(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Task-controlled change",
        "description": "Completion requires its implementation task.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Task-controlled change").one()
        ticket_id = ticket.id
        vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).one().gates[0].votes[0].id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{vote_id}/decide", data={
        "decision": "Approved",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P3",
        "assignee_id": "",
    }).status_code == 302
    assert client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Deploy application package", "task_type": "Implementation",
        "group_id": group_id(app), "required": "1",
        "planned_start": "", "planned_end": "",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "Resolved", "priority": "P3",
        "assignee_id": "",
    }).status_code == 409
    with app.app_context():
        task = OperationalTask.query.filter_by(parent_id=ticket_id).one()
        task_id = task.id
    assert client.post(f"/operational-task/{task_id}", data={
        "state": "Closed Complete", "assignee_id": "",
        "work_notes": "Deployment and validation completed.",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "Resolved", "priority": "P3",
        "assignee_id": "",
    }).status_code == 302


def test_problem_profile_ptask_and_multiple_fix_changes(client, app):
    login(client)
    assert client.post("/module/problem/new", data={
        "record_type": "Root cause analysis", "title": "Recurring capacity failure",
        "description": "Investigate recurring failures.", "priority": "P2", "risk": "High",
    }).status_code == 302
    with app.app_context():
        problem = EnterpriseRecord.query.filter_by(title="Recurring capacity failure").one()
        problem_id = problem.id
    assert client.post(f"/problem/{problem_id}/analysis", data={
        "known_error": "1", "root_cause": "Version 4.2 leaks connections.",
        "workaround": "Restart at 900 sessions.",
        "fix_notes": "Upgrade to version 4.3.", "primary_ci_id": "",
    }).status_code == 302
    assert client.post(f"/problem/{problem_id}/tasks", data={
        "title": "Analyse active sessions", "task_type": "Investigation",
        "group_id": group_id(app, "Database"), "required": "1",
    }).status_code == 302
    with app.app_context():
        profile = ProblemProfile.query.filter_by(enterprise_record_id=problem_id).one()
        assert profile.known_error
        assert "900 sessions" in profile.workaround
        assert OperationalTask.query.filter_by(
            parent_type="enterprise", parent_id=problem_id,
            task_kind="problem",
        ).one().number.startswith("PTASK")


def test_request_supports_multiple_ritms_and_sctasks(client, app):
    login(client)
    with app.app_context():
        primary_item = CatalogItem(
            name="Standard workstation", category="Hardware",
            description="Primary requested item.", approval_required=False,
        )
        second_item = CatalogItem(
            name="VPN access", category="Access",
            description="Additional requested item.", approval_required=False,
        )
        db.session.add_all([primary_item, second_item])
        db.session.commit()
        primary_item_id, second_item_id = primary_item.id, second_item.id
    assert client.post(f"/catalog/{primary_item_id}/order", data={
        "details": "Primary laptop item",
    }).status_code == 302
    with app.app_context():
        req = CatalogRequest.query.one()
        req_id = req.id
    assert client.post(f"/request/{req_id}/items", data={
        "catalog_item_id": second_item_id, "details": "Also provide VPN.",
    }).status_code == 302
    with app.app_context():
        req = db.session.get(CatalogRequest, req_id)
        assert len(req.items) == 2
        first_ritm = req.items[0]
        first_ritm_id = first_ritm.id
    assert client.post(f"/ritm/{first_ritm_id}/tasks", data={
        "title": "Configure endpoint security", "group_id": group_id(app),
        "execution_mode": "Sequential",
    }).status_code == 302
    with app.app_context():
        tasks = CatalogTask.query.filter_by(
            requested_item_id=first_ritm_id
        ).order_by(CatalogTask.id).all()
        assert len(tasks) == 2
        first_task_id, second_task_id = tasks[0].id, tasks[1].id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/catalog-task/{second_task_id}", data={
        "state": "Work in Progress", "work_notes": "Premature start.",
    }).status_code == 409
    assert client.post(f"/catalog-task/{first_task_id}", data={
        "state": "Work in Progress", "work_notes": "Started.",
    }).status_code == 302
    assert client.post(f"/catalog-task/{first_task_id}", data={
        "state": "Closed Complete", "work_notes": "Completed.",
    }).status_code == 302
    with app.app_context():
        assert db.session.get(RequestedItem, first_ritm_id).state != "Closed Complete"
    assert client.post(f"/catalog-task/{second_task_id}", data={
        "state": "Work in Progress", "work_notes": "Started.",
    }).status_code == 302
    assert client.post(f"/catalog-task/{second_task_id}", data={
        "state": "Closed Complete", "work_notes": "Completed.",
    }).status_code == 302
    with app.app_context():
        assert db.session.get(RequestedItem, first_ritm_id).state == "Closed Complete"


def test_major_incident_remains_inc_and_parent_state_sync_is_audited(client, app):
    login(client)
    coreapps_id = group_id(app)
    for title in ("Major parent outage", "Major child report"):
        assert client.post("/tickets/new/incident", data={
            "title": title, "description": "Major incident verification.",
            "category": "Software", "priority": "P1", "group_id": coreapps_id,
        }).status_code == 302
    with app.app_context():
        parent, child = Ticket.query.filter_by(kind="incident").order_by(Ticket.id).all()
        parent_id, child_id, parent_number = parent.id, child.id, parent.number
        db.session.add(PlatformSetting(
            key="SYNC_CHILD_INCIDENT_STATES", value="true", encrypted=False,
        ))
        db.session.commit()
    assert client.post(f"/record/ticket/{child_id}/relationships", data={
        "link_type": "parent_incident", "target_number": parent_number,
    }).status_code == 302
    assert client.post(f"/incident/{parent_id}/major-incident", data={
        "status": "Accepted",
        "business_impact": "All production customers are affected.",
        "communications": "Updates every 30 minutes.",
    }).status_code == 302
    assert client.post(f"/ticket/{parent_id}", data={
        "action": "update", "state": "Pending", "priority": "P1",
        "assignee_id": "",
    }).status_code == 302
    with app.app_context():
        parent = db.session.get(Ticket, parent_id)
        child = db.session.get(Ticket, child_id)
        assert parent.number.startswith("INC")
        assert parent.major_incident_profile.status == "Accepted"
        assert child.state == "Pending"
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=child_id,
            event="State synchronized from parent incident",
        ).one()


def test_enterprise_record_cannot_bypass_requested_approval(client, app):
    login(client)
    client.post("/module/problem/new", data={
        "record_type": "Root cause analysis",
        "title": "Approval protected problem",
        "description": "Do not start before authorization.",
        "priority": "P2", "risk": "High", "approval_required": "1",
    })
    with app.app_context():
        record_id = EnterpriseRecord.query.filter_by(
            title="Approval protected problem"
        ).one().id
    bypass = client.post(f"/enterprise/{record_id}", data={
        "action": "update", "state": "In Progress", "priority": "P2",
        "risk": "High", "assignee_id": "",
    })
    assert bypass.status_code == 409
    with app.app_context():
        assert db.session.get(EnterpriseRecord, record_id).state == "Awaiting Approval"


def test_enterprise_approval_cannot_be_replayed_against_another_record(client, app):
    login(client)
    for title in ("Approval source", "Approval target"):
        assert client.post("/module/problem/new", data={
            "record_type": "Root cause analysis", "title": title,
            "description": "Approval binding verification.",
            "priority": "P2", "risk": "High", "approval_required": "1",
        }).status_code == 302
    with app.app_context():
        source, target = EnterpriseRecord.query.order_by(EnterpriseRecord.id).all()
        source_approval_id = source.approvals[0].id
        target_id = target.id
    assert client.post(f"/enterprise/{target_id}", data={
        "action": "approve", "approval_id": source_approval_id,
        "comments": "Attempted cross-record approval",
    }).status_code == 404
    with app.app_context():
        target = db.session.get(EnterpriseRecord, target_id)
        assert target.state == "Awaiting Approval"
        assert target.approvals[0].state == "Requested"


def test_inactive_catalog_item_cannot_be_ordered_directly(client, app):
    login(client)
    with app.app_context():
        item = CatalogItem.query.filter_by(name="Laptop computer").one()
        item.active = False
        db.session.commit()
        item_id = item.id
    assert client.post(f"/catalog/{item_id}/order", data={"details": "Hidden item"}).status_code == 404
    with app.app_context():
        assert CatalogRequest.query.count() == 0


def test_it_teams_managers_and_ccb_membership(client, app):
    expected = {"CoreApps", "Database", "Network", "Windows", "Unix", "SSD"}
    with app.app_context():
        teams = SupportGroup.query.filter_by(group_type="IT Fulfillment").all()
        assert {team.name for team in teams} == expected
        assert all(team.manager and team.manager.role == "manager" for team in teams)
        assert all(GroupMember.query.filter_by(group_id=team.id, user_id=team.manager_id,
                                               role="manager").one_or_none() for team in teams)
        ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
        ccb_user_ids = {member.user_id for member in ccb.members}
        assert ccb_user_ids == {team.manager_id for team in teams}
        assert {member.role for member in ccb.members} == {"CCB approver"}


def test_team_manager_can_access_management_work(client):
    response = login(client, "database.manager", "Manager123!")
    assert b"Database Manager" in response.data
    assert client.get("/tickets/incident").status_code == 200
    assert client.get("/analytics").status_code == 200
    assert client.get("/admin/users").status_code == 403


def test_unified_search_favorites_and_preferences(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Global search verification", "description": "Searchable record",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    result = client.get("/ui/search?q=Global+search")
    assert b"Global search verification" in result.data
    assert client.post("/ui/favorite", data={"url": "/task-board", "label": "My board"}).json["active"]
    client.post("/preferences", data={
        "theme": "dark", "density": "compact", "font_scale": "115",
        "high_contrast": "1", "reduced_motion": "1", "nav_pinned": "1",
        "start_page": "/task-board",
    })
    with app.app_context():
        assert Favorite.query.filter_by(url="/task-board").one()
        pref = UserPreference.query.one()
        assert (pref.theme, pref.density, pref.font_scale, pref.start_page) == ("light", "compact", 115, "/task-board")


def test_visual_board_checklist_and_attachment(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Workspace interaction test", "description": "Board, checklist, and files",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.one().id
    moved = client.post(f"/task-board/{ticket_id}/move", data={"state": "In Progress"})
    assert moved.json == {"state": "In Progress"}
    client.post(f"/ticket/{ticket_id}/checklist", data={"text": "Validate recovery"})
    uploaded = client.post(f"/ticket/{ticket_id}/attachments",
                           data={"file": (BytesIO(b"evidence"), "evidence.txt")},
                           content_type="multipart/form-data", follow_redirects=True)
    assert b"evidence.txt" in uploaded.data
    with app.app_context():
        assert FileAttachment.query.filter_by(ticket_id=ticket_id).one().size_bytes == 8


def test_visual_board_rejects_invalid_lifecycle_jump(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Strict lifecycle test", "description": "Cannot close from New",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.one().id
    assert client.post(
        f"/task-board/{ticket_id}/move", data={"state": "Closed"}
    ).status_code == 409
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "New"


def test_fresh_install_has_no_reserved_demo_personas(monkeypatch):
    fd, path = tempfile.mkstemp()
    os.close(fd)
    monkeypatch.setenv("DEPLOYMENT_PROFILE", "production")
    production = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
        "DEPLOYMENT_PROFILE": "production",
    })
    with production.app_context():
        assert User.query.filter_by(username="admin", active=True).one()
        assert User.query.filter_by(username="employee").count() == 0
        assert User.query.filter(User.username.like("%.agent"), User.active.is_(True)).count() == 0
        assert User.query.filter(User.username.like("%.manager")).count() == 0
        assert CatalogItem.query.count() == 0
    os.unlink(path)


def test_external_identity_is_stable_and_does_not_enable_local_password(app):
    with app.app_context():
        first = provision_external_user("keycloak", "subject-123", "alice", "Alice", "alice@example.test", "agent")
        db.session.commit()
        first_id = first.id
        second = provision_external_user("keycloak", "subject-123", "alice", "Alice Updated",
                                         "alice@example.test", "manager")
        db.session.commit()
        assert second.id == first_id
        assert second.role == "manager"
        assert ExternalIdentity.query.filter_by(provider="keycloak", subject="subject-123").count() == 1


def test_ldap_group_mapping_synchronizes_team_membership(app):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        db.session.add(DirectoryGroupMapping(
            directory_group="gg_unix", support_group_id=unix.id
        ))
        db.session.commit()
        user = provision_external_user(
            "ldap", "CN=Alice,OU=Users,DC=example,DC=com", "alice", "Alice",
            "alice@example.test", "agent",
            groups=["CN=gg_unix,OU=Groups,DC=example,DC=com"],
        )
        db.session.commit()
        user_id = user.id
        assert GroupMember.query.filter_by(
            user_id=user_id, group_id=unix.id, role="member"
        ).one()
        assert DirectoryManagedMembership.query.filter_by(
            user_id=user_id, group_id=unix.id
        ).one()

        provision_external_user(
            "ldap", "CN=Alice,OU=Users,DC=example,DC=com", "alice", "Alice",
            "alice@example.test", "agent", groups=[],
        )
        db.session.commit()
        assert GroupMember.query.filter_by(user_id=user_id, group_id=unix.id).count() == 0
        assert DirectoryManagedMembership.query.filter_by(
            user_id=user_id, group_id=unix.id
        ).count() == 0


def test_admin_configures_ad_mapping_manager_and_ccb_authority(client, app):
    login(client)
    with app.app_context():
        unix_id = SupportGroup.query.filter_by(name="Unix").one().id
        manager = User.query.filter_by(username="database.manager").one()
        manager_id = manager.id
    assert client.post("/itil/administration", data={
        "action": "add_directory_mapping", "directory_group": "gg_unix",
        "group_id": unix_id,
    }).status_code == 302
    assert client.post("/itil/administration", data={
        "action": "set_manager", "group_id": unix_id, "manager_id": manager_id,
    }).status_code == 302
    assert client.post("/itil/administration", data={
        "action": "set_ccb_authority", "user_id": manager_id, "enabled": "true",
    }).status_code == 302
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
        assert DirectoryGroupMapping.query.filter_by(
            directory_group="gg_unix", support_group_id=unix.id, active=True
        ).one()
        assert unix.manager_id == manager_id
        assert GroupMember.query.filter_by(
            group_id=ccb.id, user_id=manager_id, role="CCB approver"
        ).one()


def test_admin_can_update_live_platform_branding(client, app):
    login(client)
    response = client.post("/admin/settings", data={
        "INSTANCE_NAME": "Operations Hub",
        "COMPANY_NAME": "Example Corporation",
        "SUPPORT_EMAIL": "support@example.test",
        "INSTANCE_TIMEZONE": "Australia/Sydney",
        "BRAND_TEAL": "#124c5a",
        "BRAND_AMBER": "#f4a340",
        "DEFAULT_DENSITY": "comfortable",
        "LOCAL_AUTH_ENABLED": "on",
        "LDAP_USER_FILTER": "(&(objectClass=user)(sAMAccountName={username}))",
        "LDAP_START_TLS": "on",
        "LDAP_VALIDATE_CERT": "on",
        "LDAP_ROLE_MAPPINGS": "{}",
        "KEYCLOAK_ROLE_MAPPINGS": "{}",
        "SESSION_HOURS": "8",
        "MAX_UPLOAD_MB": "20",
        "DEFAULT_TICKET_PRIORITY": "P3",
        "NOTIFICATION_FROM_NAME": "Operations Hub",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"System settings saved" in response.data
    assert b"Operations Hub" in response.data
    with app.app_context():
        assert db.session.get(PlatformSetting, "COMPANY_NAME").value == "Example Corporation"


def test_dark_theme_is_removed(client, app):
    login(client)
    response = client.get("/preferences")
    assert b'value="dark"' not in response.data
    with app.app_context():
        assert all(pref.theme == "light" for pref in UserPreference.query.all())


def test_declarative_priority_matrix_is_complete():
    assert validate_priority_policy()
    assert calculate_priority("Critical", "Critical") == "P1"
    assert calculate_priority("Medium", "Medium") == "P3"
    assert calculate_priority("Low", "Low") == "P4"
    with pytest.raises(ValueError):
        calculate_priority("Unknown", "High")


def test_business_calendar_skips_weekend_and_holiday():
    class Calendar:
        timezone_name = "UTC"
        weekdays = [0, 1, 2, 3, 4]
        start_time = time(9, 0)
        end_time = time(17, 0)

    friday = datetime(2026, 7, 24, 16, 0, tzinfo=timezone.utc)
    assert add_business_minutes(friday, 120, Calendar()) == datetime(
        2026, 7, 27, 10, 0, tzinfo=timezone.utc
    )
    assert add_business_minutes(
        friday, 120, Calendar(), holidays={datetime(2026, 7, 27).date()}
    ) == datetime(2026, 7, 28, 10, 0, tzinfo=timezone.utc)


def test_admin_configures_business_calendar_holiday_and_sla(client, app):
    login(client)
    response = client.post("/itil/administration", data={
        "action": "create_business_schedule", "name": "Sydney business hours",
        "timezone_name": "Australia/Sydney", "start_time": "08:30",
        "end_time": "17:00", "weekdays": ["0", "1", "2", "3", "4"],
    })
    assert response.status_code == 302
    with app.app_context():
        schedule_id = BusinessSchedule.query.filter_by(
            name="Sydney business hours"
        ).one().id
    assert client.post("/itil/administration", data={
        "action": "add_schedule_holiday", "schedule_id": schedule_id,
        "holiday_date": "2026-12-25", "name": "Christmas Day",
    }).status_code == 302
    assert client.post("/itil/administration", data={
        "action": "create_sla_definition", "name": "P2 Sydney resolution",
        "target_type": "ticket", "priority": "P2", "duration_minutes": "480",
        "schedule_id": schedule_id, "pause_states": "Pending,On Hold",
    }).status_code == 302
    with app.app_context():
        assert ScheduleHoliday.query.filter_by(schedule_id=schedule_id).one()
        assert SLADefinition.query.filter_by(
            name="P2 Sydney resolution", schedule_id=schedule_id
        ).one()


def test_workflow_package_rejects_arbitrary_scripts():
    assert load_workflow_package()["schema_version"] == 2
    malicious = {
        "key": "unsafe", "name": "Unsafe", "event": "ticket.state_entry",
        "conditions": [],
        "actions": [{"type": "controlled_script", "code": "import os"}],
    }
    with pytest.raises(WorkflowConfigurationError):
        validate_workflow(malicious)


def test_workflow_simulation_and_durable_idempotent_execution(app):
    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        admin = User.query.filter_by(username="admin").one()
        coreapps = SupportGroup.query.filter_by(name="CoreApps").one()
        ticket = Ticket(
            number="INC0099001", kind="incident", title="Workflow test",
            description="Exercise declarative automation.", state="Resolved",
            priority="P2", impact="High", urgency="High",
            requester_id=employee.id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(TicketAssignmentGroup(
            ticket_id=ticket.id, group_id=coreapps.id
        ))
        context = {
            "number": ticket.number, "kind": "incident", "state": "Resolved",
            "previous_state": "In Progress", "priority": "P2",
            "impact": "High", "urgency": "High", "category": "General",
        }
        preview = simulate_workflows("ticket.state_entry", context, 1)
        assert preview[0]["workflow_key"] == "incident-resolved"
        queue_workflow_event("ticket.state_entry", "ticket", ticket.id, context, 1)
        db.session.commit()
        assert process_workflow_jobs() == 1
        assert WorkflowJob.query.filter_by(state="Completed").count() == 1
        assert WorkflowExecution.query.filter_by(state="Completed").count() == 1
        history_count = TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket.id,
            event="Resolution workflow completed",
        ).count()
        assert history_count == 1
        assert process_workflow_jobs() == 0
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket.id,
            event="Resolution workflow completed",
        ).count() == history_count
        assert admin


def test_admin_can_simulate_and_redeploy_workflows(client, app):
    login(client)
    page = client.get("/admin/workflows")
    assert page.status_code == 200
    assert b"Arbitrary scripts are not supported" in page.data
    simulated = client.post("/admin/workflows", data={
        "action": "simulate", "event_type": "ticket.state_entry",
        "context_json": json.dumps({
            "number": "INC0000001", "kind": "incident", "state": "Resolved",
            "previous_state": "In Progress", "priority": "P2",
            "impact": "High", "urgency": "High", "category": "Software",
        }),
    })
    assert simulated.status_code == 200
    assert b"incident-resolved" in simulated.data
    assert client.post("/admin/workflows", data={"action": "deploy"}).status_code == 302


def test_durable_workflow_wait_resumes_without_replaying_steps(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        employee = User.query.filter_by(username="employee").one()
        coreapps = SupportGroup.query.filter_by(name="CoreApps").one()
        package = {
            "schema_version": 1,
            "workflows": [{
                "key": "manual-wait-test", "name": "Manual wait test",
                "event": "ticket.manual", "rate_limit_per_minute": 10,
                "conditions": [{"field": "kind", "operator": "equals", "value": "incident"}],
                "actions": [
                    {"type": "add_history", "event": "Before durable wait",
                     "details": "First action executed once."},
                    {"type": "wait", "minutes": 1},
                    {"type": "add_history", "event": "After durable wait",
                     "details": "Execution resumed successfully."},
                ],
            }],
        }
        deploy_workflow_package(admin.id, package)
        ticket = Ticket(
            number="INC0099002", kind="incident", title="Wait test",
            description="Durable workflow wait.", requester_id=employee.id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(TicketAssignmentGroup(
            ticket_id=ticket.id, group_id=coreapps.id
        ))
        queue_workflow_event(
            "ticket.manual", "ticket", ticket.id,
            {
                "number": ticket.number, "kind": "incident", "state": "New",
                "previous_state": "New", "priority": "P3", "impact": "Medium",
                "urgency": "Medium", "category": "General",
                "triggered_by": admin.username,
            }, 1,
        )
        db.session.commit()
        assert process_workflow_jobs() == 1
        job = WorkflowJob.query.filter_by(target_id=ticket.id).one()
        execution = WorkflowExecution.query.filter_by(job_id=job.id).one()
        assert job.state == "Waiting"
        assert execution.state == "Waiting"
        assert execution.next_action_index == 2
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket.id, event="Before durable wait"
        ).count() == 1
        job.available_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        execution.resume_at = job.available_at
        db.session.commit()
        assert process_workflow_jobs() == 1
        assert job.state == "Completed"
        assert execution.state == "Completed"
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket.id, event="Before durable wait"
        ).count() == 1
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket.id, event="After durable wait"
        ).count() == 1


def test_subflows_are_materialized_and_cycles_fail_closed():
    subflows = {
        "evidence": [{
            "type": "add_history", "event": "Subflow evidence",
            "details": "Reusable action executed for {number}.",
        }]
    }
    assert validate_subflows(subflows) == subflows
    workflow = {
        "key": "subflow-test", "name": "Subflow test",
        "event": "ticket.manual", "rate_limit_per_minute": 10,
        "conditions": [],
        "actions": [{"type": "run_subflow", "subflow": "evidence"}],
    }
    validate_workflow(workflow, subflows)
    materialized = materialize_workflow(workflow, subflows)
    assert materialized["actions"][0]["type"] == "add_history"
    with pytest.raises(WorkflowConfigurationError, match="cycle"):
        validate_subflows({
            "one": [{"type": "run_subflow", "subflow": "two"}],
            "two": [{"type": "run_subflow", "subflow": "one"}],
        })


def test_due_schedule_emits_once_and_advances_beyond_now(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        employee = User.query.filter_by(username="employee").one()
        ticket = Ticket(
            number="INC0099003", kind="incident", title="Schedule test",
            description="Recurring schedule verification.", requester_id=employee.id,
        )
        db.session.add(ticket)
        db.session.flush()
        schedule = WorkflowSchedule(
            schedule_key="schedule-test", name="Schedule test",
            ticket_id=ticket.id, interval_minutes=60,
            next_run_at=datetime.now(timezone.utc) - timedelta(days=2),
            created_by_id=admin.id,
        )
        db.session.add(schedule)
        db.session.commit()
        assert process_workflow_schedules() == 1
        assert WorkflowJob.query.filter_by(
            target_id=ticket.id, event_type="ticket.scheduled"
        ).count() == 1
        assert schedule.next_run_at > datetime.now(timezone.utc).replace(tzinfo=None)
        assert process_workflow_schedules() == 0


def test_secret_file_takes_precedence_and_rejects_empty(monkeypatch, tmp_path):
    secret_path = tmp_path / "bootstrap-password"
    secret_path.write_text("mounted-secret-value\n", encoding="utf-8")
    monkeypatch.setenv("ADMIN_PASSWORD", "legacy-environment-value")
    monkeypatch.setenv("ADMIN_PASSWORD_FILE", str(secret_path))
    assert secret_value("ADMIN_PASSWORD") == "mounted-secret-value"
    secret_path.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="empty"):
        secret_value("ADMIN_PASSWORD")


def test_password_rotation_invalidates_other_sessions(app):
    first = app.test_client()
    second = app.test_client()
    assert login(first).status_code == 200
    assert login(second).status_code == 200
    response = first.post("/profile/password", data={
        "current_password": "Admin123!",
        "new_password": "NewAdminPassword-2026!",
        "confirm_password": "NewAdminPassword-2026!",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Other browser sessions have been invalidated" in response.data
    assert first.get("/").status_code == 200
    stale = second.get("/", follow_redirects=False)
    assert stale.status_code == 302
    assert stale.headers["Location"].endswith("/login")


def test_tenant_context_fails_closed_when_authenticated_user_has_no_tenant(app):
    from flask_login import login_user

    with app.test_request_context("/"):
        with app.app_context():
            admin = User.query.filter_by(username="admin").one()
            db.session.expunge(admin)
        admin.tenant_id = None  # simulate corrupt data without violating the NOT NULL column
        login_user(admin)
        with pytest.raises(TenantResolutionError):
            tenant_context_id()


def test_preferences_reject_open_redirect_start_page(client, app):
    login(client)
    response = client.post("/preferences", data={
        "density": "comfortable", "font_scale": "100",
        "start_page": "https://evil.example/phish",
    })
    assert response.status_code == 302
    with app.app_context():
        pref = UserPreference.query.filter_by(
            user_id=User.query.filter_by(username="admin").one().id
        ).one()
        assert pref.start_page == "/"

    ok_response = client.post("/preferences", data={
        "density": "comfortable", "font_scale": "100",
        "start_page": "/dashboard",
    })
    assert ok_response.status_code == 302
    with app.app_context():
        pref = UserPreference.query.filter_by(
            user_id=User.query.filter_by(username="admin").one().id
        ).one()
        assert pref.start_page == "/dashboard"


def test_webhook_rejects_hostname_that_resolves_to_private_address(monkeypatch, app):
    with app.app_context():
        assert integration_endpoint_valid("https://hooks.example.test/serviceops")
        monkeypatch.setattr(
            "app.socket.getaddrinfo",
            lambda host, port: [(2, 1, 6, "", ("10.0.0.5", 0))],
        )
        assert not integration_endpoint_resolves_safely("https://hooks.example.test/serviceops")
        monkeypatch.setattr(
            "app.socket.getaddrinfo",
            lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))],
        )
        assert integration_endpoint_resolves_safely("https://hooks.example.test/serviceops")
