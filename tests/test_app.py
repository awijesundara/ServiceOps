import json
import os
import re
import tempfile
import uuid
from io import BytesIO
from urllib.parse import quote

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError

from app import (APIClient, APIIdempotencyRecord, APIRateLimitWindow, Approval, ApprovalChain,
                 ApprovalGate, ApprovalVote, Asset, Audit, AuditIntegrityKey, AuditRetentionPolicy,
                 BusinessSchedule, CatalogRequest, CatalogTask, ChangeGovernance, ChangeOwnership, ChangeRevision,
                 Comment,
                 ChecklistItem, ConfigurationItem, EnterpriseRecord, CatalogItem, CatalogItemRouting, DirectoryGroupMapping,
                 DirectoryManagedMembership, ExternalIdentity, Favorite, FileAttachment,
                 GroupMember, IntegrationConnection, IntegrationDelivery, Knowledge,
                 MonitoringEvent, MonitoringSource, Notification, OperationalTask,
                 OutboxEvent, ProblemProfile, RecordLink, ScheduleHoliday, SLADefinition,
                 RequestedItem, PlatformSetting, ServiceOffering, ServiceOfferingCI, SupportGroup, SupportGroupAlias,
                 TaskCI, TaskHistory, TaskNote, TaskSLA,
                 Tenant, Ticket, TicketAssignmentGroup, User, UserPreference, UserRoleGrant, ManagedRoleGrant,
                 ApplicationLog,
                 create_ticket_with_unique_number, create_with_retry_on_number_collision, next_number,
                 WorkflowDefinition, WorkflowExecution, WorkflowJob,
                 WorkflowSchedule,
                 audit, change_approval_stages, create_api_token, create_app, create_notification, db,
                 deploy_workflow_package, find_and_merge_duplicate_groups, ldap_authenticate,
                 mapped_roles, merge_support_group_into, normalize_environment, now, process_workflow_jobs,
                 recompute_base_role,
                 process_workflow_schedules, queue_workflow_event,
                 scan_attachment, simulate_workflows,
                 integration_endpoint_valid, integration_endpoint_resolves_safely,
                 is_safe_internal_path, process_outbox,
                 provision_external_user, secret_value, settings_cipher, user_is_local,
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
        executive_office = SupportGroup.query.filter_by(name="Executive Office").one()
        executive_office.manager_id = manager.id
        db.session.add(GroupMember(group_id=executive_office.id, user_id=manager.id, role="manager"))
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


def current_migration_head():
    """Computed from the actual migrations directory rather than hardcoded,
    so these tests don't go stale every time a migration is added (see
    CLAUDE.md's standing review note about hardcoded migration-rehearsal
    revision assumptions)."""
    from alembic.script import ScriptDirectory
    config = AlembicConfig(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "alembic.ini")
    )
    config.set_main_option(
        "script_location",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations"),
    )
    return ScriptDirectory.from_config(config).get_current_head()


def group_id(app, name="CoreApps"):
    with app.app_context():
        return SupportGroup.query.filter_by(name=name).one().id


def test_health(client):
    from app import APP_VERSION

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok", "version": APP_VERSION}
    assert client.get("/live").json == {"status": "alive"}
    assert client.get("/ready").json == {"status": "ready"}


def test_live_api_documentation_matches_supported_contract(client):
    guide = client.get("/api/v1/docs")
    assert guide.status_code == 200
    assert b"/api/v1/openapi.json" in guide.data

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
        assert revision == current_migration_head()
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
        ).scalar_one() == current_migration_head()
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
        # Stops short of "head" deliberately: 20260729_0023's upgrade() adds a
        # column with an inline ForeignKey via a plain (non-batched)
        # add_column, which SQLite only accepts on a *first* run — replaying
        # it a second time after a full downgrade-to-genesis hits "No support
        # for ALTER of constraints in SQLite dialect" (batch mode is required
        # for that combination on SQLite; PostgreSQL is unaffected either
        # way). That migration is already deployed, so CLAUDE.md's "never
        # rewrite an already-deployed migration" rule applies — it isn't
        # rewritten here. This test's actual subject (tenant creation
        # reversibility from 20260726_0002) is unaffected by stopping at
        # 20260729_0022; see test_governance_migrations_are_reversible below
        # for round-trip coverage of the migrations added in this pass.
        command.upgrade(migration_config, "20260729_0022")
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
            ).scalar_one() == "20260729_0022"
    os.unlink(path)


def test_governance_migrations_are_reversible():
    """Round-trip coverage for the migrations added in this pass (B-260):
    downgrading past them must cleanly remove the enforced tenant_id columns
    and attachment scan/hash columns, and re-upgrading must restore them,
    ending back at the true migration head."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    migrated_app = create_app({
        "TESTING": True,
        "AUTO_MIGRATE_IN_TESTS": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
    })
    migration_config = AlembicConfig(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "alembic.ini")
    )
    migration_config.set_main_option(
        "script_location",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations"),
    )
    with migrated_app.app_context():
        db.session.remove()
        command.downgrade(migration_config, "20260729_0024")
        downgraded = inspect(db.engine)
        assert "tenant_id" not in {c["name"] for c in downgraded.get_columns("approval_gate")}
        assert "tenant_id" not in {c["name"] for c in downgraded.get_columns("approval_vote")}
        assert "tenant_id" not in {c["name"] for c in downgraded.get_columns("change_governance")}
        assert "sha256" not in {c["name"] for c in downgraded.get_columns("file_attachment")}
        db.session.remove()
        command.upgrade(migration_config, "head")
        upgraded = inspect(db.engine)
        assert "tenant_id" in {c["name"] for c in upgraded.get_columns("approval_gate")}
        assert "tenant_id" in {c["name"] for c in upgraded.get_columns("approval_vote")}
        assert "tenant_id" in {c["name"] for c in upgraded.get_columns("change_governance")}
        assert "sha256" in {c["name"] for c in upgraded.get_columns("file_attachment")}
        assert db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == current_migration_head()
    os.unlink(path)


def test_alias_duplicate_merge_migration_fixes_preexisting_duplicate_team():
    """Rehearses the exact production bug: a "DBA" SupportGroup and a CI
    pointing at it exist from before the "DBA" -> "Database" alias/merge
    migrations (20260731_0031-0033) were introduced. Re-running migrations
    from that point to head must merge "DBA" into "Database" so the CI's
    change approval no longer errors on a managerless team."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    migrated_app = create_app({
        "TESTING": True,
        "AUTO_MIGRATE_IN_TESTS": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
    })
    migration_config = AlembicConfig(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "alembic.ini")
    )
    migration_config.set_main_option(
        "script_location",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations"),
    )
    with migrated_app.app_context():
        db.session.remove()
        command.downgrade(migration_config, "20260730_0029")
        database_group_id = db.session.execute(text(
            "SELECT id FROM support_group WHERE name = 'Database'"
        )).scalar_one()
        db.session.execute(text(
            "INSERT INTO support_group (name, group_type, active, tenant_id) "
            "VALUES ('DBA', 'IT Fulfillment', 1, 1)"
        ))
        dba_group_id = db.session.execute(text(
            "SELECT id FROM support_group WHERE name = 'DBA'"
        )).scalar_one()
        db.session.execute(text(
            "INSERT INTO configuration_item "
            "(name, ci_class, environment, operational_status, lifecycle_state, "
            " business_criticality, discovery_source, attributes, support_group_id, "
            " tenant_id, created_at, updated_at) "
            "VALUES ('doj-pcd3pgs02.dc.japannext.co.jp', 'Server', 'Production', "
            " 'Operational', 'In Use', 'Medium', 'Import', '{}', :group_id, 1, "
            " CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ), {"group_id": dba_group_id})
        db.session.commit()
        db.session.remove()
        # The "DBA" -> "Database" alias itself is seeded by app startup code
        # (seed_itil), not by a migration -- insert it directly once its
        # table exists, mirroring what a real upgrade-then-restart does.
        command.upgrade(migration_config, "20260731_0031")
        db.session.execute(text(
            "INSERT INTO support_group_alias (alias, group_id, tenant_id, created_at) "
            "VALUES ('DBA', :group_id, 1, CURRENT_TIMESTAMP)"
        ), {"group_id": database_group_id})
        db.session.commit()
        db.session.remove()
        command.upgrade(migration_config, "head")
        remaining_dba = db.session.execute(text(
            "SELECT COUNT(*) FROM support_group WHERE name = 'DBA'"
        )).scalar_one()
        assert remaining_dba == 0
        ci_group = db.session.execute(text(
            "SELECT support_group_id FROM configuration_item "
            "WHERE name = 'doj-pcd3pgs02.dc.japannext.co.jp'"
        )).scalar_one()
        assert ci_group == database_group_id
        assert db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == current_migration_head()
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


def test_audit_log_page_paginates_and_defers_integrity_check(client, app):
    login(client)
    default_view = client.get("/admin/audit")
    assert default_view.status_code == 200
    assert b"Not checked this view" in default_view.data
    assert b"Verify integrity now" in default_view.data

    verified_view = client.get("/admin/audit?verify=1")
    assert verified_view.status_code == 200
    assert b"Not checked this view" not in verified_view.data
    assert b"Verified" in verified_view.data or b"FAILED" in verified_view.data

    filtered = client.get("/admin/audit?q=login")
    assert filtered.status_code == 200


def test_ritm_detail_page_shows_approvals_tasks_and_form_responses(client, app):
    login(client, "employee", "Employee123!")
    client.post("/catalog/1/order", data={"details": "Standalone RITM page test"}, follow_redirects=True)
    with app.app_context():
        ritm_id = RequestedItem.query.one().id
    page = client.get(f"/ritm/{ritm_id}")
    assert page.status_code == 200
    assert b"Fulfillment tasks (SCTASK)" in page.data
    assert b"Approvals" in page.data
    assert b"Form Responses" in page.data
    assert b"Standalone RITM page test" in page.data


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
    from app import APP_VERSION
    assert f"serviceops-shell-v{APP_VERSION}".encode() in worker.data
    assert f"/static/itil.css?v={APP_VERSION}".encode() in worker.data
    assert worker.data.index(b"fetch(event.request)") < worker.data.index(
        b"caches.match(event.request)"
    )


def test_durable_smtp_signed_webhook_and_teams_delivery(monkeypatch, app):
    assert not integration_endpoint_valid("http://hooks.example.test/serviceops")
    assert not integration_endpoint_valid("https://127.0.0.1/hook")
    assert not integration_endpoint_valid("https://169.254.169.254/latest/meta-data")
    assert integration_endpoint_valid("https://hooks.example.test/serviceops")
    # Private-network addresses stay rejected by default (webhooks are
    # arbitrary user-supplied targets) but are allowed opt-in for trusted,
    # admin-configured integrations like NetBox that are normally
    # self-hosted internally; loopback/link-local/metadata targets are
    # still rejected either way.
    assert not integration_endpoint_valid("https://10.0.0.5/api")
    assert integration_endpoint_valid("https://10.0.0.5/api", allow_private_network=True)
    assert not integration_endpoint_valid("https://127.0.0.1/hook", allow_private_network=True)
    assert not integration_endpoint_valid("https://169.254.169.254/latest/meta-data", allow_private_network=True)
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
    assert b"Event history" in internal.data
    assert b"priority" in internal.data.lower()

    client.post("/logout")
    login(client, "employee", "Employee123!")
    requester = client.get(f"/ticket/{ticket_id}")
    assert requester.status_code == 200
    assert b"Public incident description" in requester.data
    assert b"Event history" not in requester.data
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
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        offering = ServiceOffering(
            name="Workplace connectivity", owner_id=admin.id,
            support_group_id=group_id(app, "Network"), status="Operational",
        )
        ci = ConfigurationItem(
            name="vpn-gateway-prod", ci_class="Network Appliance",
            environment="Production", owner_id=admin.id,
        )
        db.session.add_all([offering, ci])
        db.session.commit()
        offering_id, ci_id = offering.id, ci.id
    login(client)
    created = client.post("/tickets/new/incident", data={
        "title": "VPN is unavailable",
        "description": "Connection fails from the remote office.",
        "category": "Network",
        "subcategory": "Remote access",
        "contact_type": "Phone",
        "notify": "In-app only",
        "service_offering_id": str(offering_id),
        "ci_id": str(ci_id),
        "impact": "High",
        "urgency": "High",
        "group_id": group_id(app, "Network"),
    }, follow_redirects=True)
    assert created.status_code == 200
    assert b"INC0000001" in created.data
    assert b"Event history" in created.data
    assert b"Remote access" in created.data
    assert b"Workplace connectivity" in created.data
    assert b"vpn-gateway-prod" in created.data
    with app.app_context():
        ticket = Ticket.query.one()
        ticket_id = ticket.id
        assert ticket.assignment_group_record.group.name == "Network"
        assert (ticket.contact_type, ticket.notify, ticket.subcategory) == (
            "Phone", "In-app only", "Remote access",
        )
        assert ticket.service_offering_id == offering_id
        assert TaskCI.query.filter_by(
            target_type="ticket", target_id=ticket.id,
            relationship_role="Primary CI",
        ).one().ci_id == ci_id
    updated = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P2",
        "impact": "High", "urgency": "High", "assignee_id": "",
        "title": "VPN remote access is unavailable",
        "description": "Connection fails from every remote office.",
        "category": "Network", "subcategory": "VPN",
        "contact_type": "Monitoring", "notify": "Email",
        "service_offering_id": str(offering_id), "ci_id": str(ci_id),
    }, follow_redirects=True)
    assert b"In Progress" in updated.data
    assert b"VPN remote access is unavailable" in updated.data
    assert b"Monitoring" in updated.data
    with app.app_context():
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket_id,
            field_name="short description",
        ).one().new_value == "VPN remote access is unavailable"


def test_shared_task_record_and_list_interface(client, app):
    login(client)
    incident_list = client.get("/tickets/incident")
    assert incident_list.status_code == 200
    assert b"list-workspace" in incident_list.data
    assert b"Assignment group" in incident_list.data
    assert b"Page 1 of 1" in incident_list.data

    change = client.post("/tickets/new/change", data={
        "title": "Shared record interface change",
        "description": "Validate the common task-derived record workspace.",
        "category": "Software", "change_type": "Normal",
        "risk_score": "40", "impact": "Medium", "urgency": "Medium",
        "implementation_plan": "Implement the shared interface.",
        "test_plan": "Render and validate the interface.",
        "backout_plan": "Restore the previous templates.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
        "group_id": group_id(app),
    }, follow_redirects=True)
    assert change.status_code == 200
    assert b'id="task-record-form"' in change.data
    assert b"Event history" in change.data

    problem = client.post("/module/problem/new", data={
        "record_type": "Root cause analysis",
        "title": "Shared problem interface",
        "description": "Validate the enterprise task record workspace.",
        "priority": "P3", "risk": "Medium",
    }, follow_redirects=True)
    assert problem.status_code == 200
    assert b'id="enterprise-record-form"' in problem.data
    assert b"Event history" in problem.data

    request_record = client.post("/catalog/1/order", data={
        "details": "Validate the request record workspace.",
    }, follow_redirects=True)
    assert request_record.status_code == 200
    assert b"request-record-shell" in request_record.data
    assert b"Requested items" in request_record.data


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
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
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
    ineligible = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P2",
        "assignee_id": ssd_agent_id,
    }, follow_redirects=True)
    assert ineligible.status_code == 200
    assert ineligible.request.path == f"/ticket/{ticket_id}"
    assert b"The assignee must be an active member of the owning team" in ineligible.data
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P2",
        "assignee_id": "",
    }).status_code == 302
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.priority == "P2"
        assert ticket.state == current_state


def test_previewable_attachment_serves_inline_only_with_view_param(client, app):
    login(client)
    response = client.post("/tickets/new/incident", data={
        "title": "Ticket for attachment preview", "description": "desc",
        "category": "Software", "priority": "P3", "group_id": group_id(app),
    })
    assert response.status_code == 302
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Ticket for attachment preview").one().id
    pdf_bytes = b"%PDF-1.4 fake pdf content"
    upload = client.post(
        f"/ticket/{ticket_id}/attachments",
        data={"file": (BytesIO(pdf_bytes), "report.pdf")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 302
    with app.app_context():
        attachment_id = FileAttachment.query.filter_by(ticket_id=ticket_id).one().id

    forced_download = client.get(f"/attachments/{attachment_id}")
    assert forced_download.status_code == 200
    assert "attachment" in forced_download.headers["Content-Disposition"]

    inline = client.get(f"/attachments/{attachment_id}?view=1")
    assert inline.status_code == 200
    assert "inline" in inline.headers["Content-Disposition"]
    assert inline.data == pdf_bytes


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
    with app.app_context():
        ritm_id = RequestedItem.query.one().id
    ritm_page = client.get(f"/ritm/{ritm_id}")
    assert ritm_page.status_code == 200
    assert b"Manager approval" in ritm_page.data
    client.post("/logout")
    login(client)
    assert client.get("/cmdb").status_code == 200


def test_ci_additional_fields_are_editable_and_exported(client, app):
    login(client)
    client.post("/cmdb/new", data={
        "name": "srv-attrs.example.com", "ci_class": "Server", "environment": "Production",
        "operational_status": "Operational", "attr_key": ["CPUs", "Builder"], "attr_value": ["8", "William Yao"],
    }, follow_redirects=True)
    with app.app_context():
        ci = ConfigurationItem.query.filter_by(name="srv-attrs.example.com").one()
        assert ci.attributes == {"CPUs": "8", "Builder": "William Yao"}
        ci_id = ci.id
    edit_page = client.get(f"/cmdb/{ci_id}/edit")
    assert b"William Yao" in edit_page.data
    client.post(f"/cmdb/{ci_id}/edit", data={
        "name": "srv-attrs.example.com", "ci_class": "Server", "environment": "Production",
        "operational_status": "Operational", "attr_key": ["CPUs", "RAM (GB)"], "attr_value": ["16", "64"],
    }, follow_redirects=True)
    with app.app_context():
        ci = ConfigurationItem.query.filter_by(name="srv-attrs.example.com").one()
        # Builder was dropped, CPUs updated, RAM (GB) added -- the form's
        # submitted rows fully replace the stored attribute set.
        assert ci.attributes == {"CPUs": "16", "RAM (GB)": "64"}
    export = client.get("/cmdb/export.csv")
    rows = export.data.decode().splitlines()
    assert "CPUs" in rows[0] and "RAM (GB)" in rows[0]
    assert "16" in rows[-1] and "64" in rows[-1]


def test_ci_form_rejects_duplicate_hostname_and_serial(client, app):
    login(client)
    client.post("/cmdb/new", data={
        "name": "dup-srv.example.com", "ci_class": "Server", "environment": "Production",
        "operational_status": "Operational", "serial_number": "SN-001",
    }, follow_redirects=True)
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="dup-srv.example.com").count() == 1

    # Same hostname, different case -> rejected, no second row created.
    client.post("/cmdb/new", data={
        "name": "DUP-SRV.example.com", "ci_class": "Server", "environment": "Production",
        "operational_status": "Operational",
    }, follow_redirects=True)
    # Different hostname, same serial -> also rejected.
    client.post("/cmdb/new", data={
        "name": "another-srv.example.com", "ci_class": "Server", "environment": "Production",
        "operational_status": "Operational", "serial_number": "SN-001",
    }, follow_redirects=True)
    with app.app_context():
        assert ConfigurationItem.query.count() == 1


def test_production_management_and_critical_cis_always_require_ccb(client, app):
    """CCB approval is auto-forced (and can't be unchecked) for Production,
    Management-class, or Critical-criticality CIs -- the "always require
    CCB" checkbox is only meaningful as an override for other CIs."""
    login(client)
    client.post("/cmdb/new", data={
        "name": "prod-srv.example.com", "ci_class": "Server", "environment": "Production",
        "operational_status": "Operational",
    }, follow_redirects=True)
    client.post("/cmdb/new", data={
        "name": "mgmt-switch.example.com", "ci_class": "Management Switch", "environment": "Development",
        "operational_status": "Operational",
    }, follow_redirects=True)
    client.post("/cmdb/new", data={
        "name": "critical-app.example.com", "ci_class": "Business Application", "environment": "Staging",
        "operational_status": "Operational", "business_criticality": "Critical",
    }, follow_redirects=True)
    client.post("/cmdb/new", data={
        "name": "dev-box.example.com", "ci_class": "Server", "environment": "Development",
        "operational_status": "Operational",
    }, follow_redirects=True)
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="prod-srv.example.com").one().require_ccb_approval is True
        assert ConfigurationItem.query.filter_by(name="mgmt-switch.example.com").one().require_ccb_approval is True
        assert ConfigurationItem.query.filter_by(name="critical-app.example.com").one().require_ccb_approval is True
        dev_ci = ConfigurationItem.query.filter_by(name="dev-box.example.com").one()
        assert dev_ci.require_ccb_approval is False
        dev_id = dev_ci.id
    # Editing the Dev CI without ticking the override keeps it false...
    client.post(f"/cmdb/{dev_id}/edit", data={
        "name": "dev-box.example.com", "ci_class": "Server", "environment": "Development",
        "operational_status": "Operational",
    }, follow_redirects=True)
    with app.app_context():
        assert ConfigurationItem.query.get(dev_id).require_ccb_approval is False
    # ...but switching its environment to Production forces it on, even
    # without the checkbox being ticked.
    client.post(f"/cmdb/{dev_id}/edit", data={
        "name": "dev-box.example.com", "ci_class": "Server", "environment": "Production",
        "operational_status": "Operational",
    }, follow_redirects=True)
    with app.app_context():
        assert ConfigurationItem.query.get(dev_id).require_ccb_approval is True


def test_environment_synonyms_normalize_to_canonical_label(client, app):
    with app.app_context():
        assert normalize_environment("Prod") == "Production"
        assert normalize_environment("prod") == "Production"
        assert normalize_environment("UAT") == "Staging"
        assert normalize_environment("Dev") == "Development"
        assert normalize_environment("Production") == "Production"
        assert normalize_environment("Some Custom Env") == "Some Custom Env"
    login(client)
    client.post("/cmdb/new", data={
        "name": "prod-alias.example.com", "ci_class": "Server", "environment": "Production",
        "operational_status": "Operational",
    }, follow_redirects=True)
    with app.app_context():
        ci = ConfigurationItem.query.filter_by(name="prod-alias.example.com").one()
        assert ci.environment == "Production"


def test_management_class_synonym_mgmt_triggers_ccb(client, app):
    login(client)
    client.post("/cmdb/new", data={
        "name": "mgmt-abbrev.example.com", "ci_class": "MGMT Console", "environment": "Development",
        "operational_status": "Operational",
    }, follow_redirects=True)
    with app.app_context():
        ci = ConfigurationItem.query.filter_by(name="mgmt-abbrev.example.com").one()
        assert ci.require_ccb_approval is True


def test_adding_alias_for_existing_duplicate_team_merges_it(client, app):
    """This is the exact bug reported in production: a "DBA" SupportGroup
    already existed (predating the alias feature) with a CI pointing at it
    and no manager. Registering the "DBA" -> "Database" alias must not just
    change future lookups -- it must merge the existing duplicate team so
    the CI's change approval resolves to Database's manager instead of
    erroring on "The DBA team requires an active manager."."""
    with app.app_context():
        database_manager_id = User.query.filter_by(username="database.manager").one().id
        database_group = SupportGroup.query.filter_by(name="Database").one()
        dba_group = SupportGroup(name="DBA", group_type="IT Fulfillment", tenant_id=1)
        db.session.add(dba_group)
        db.session.flush()
        ci = ConfigurationItem(
            name="doj-pcd3pgs02.dc.japannext.co.jp", ci_class="Server",
            environment="Production", support_group_id=dba_group.id,
        )
        db.session.add(ci)
        db.session.commit()
        ci_id, dba_id, database_id = ci.id, dba_group.id, database_group.id

    login(client)
    client.post("/itil/administration", data={
        "action": "add_support_group_alias", "alias": "DBA", "group_id": str(database_id),
    }, follow_redirects=True)

    with app.app_context():
        ci = db.session.get(ConfigurationItem, ci_id)
        assert ci.support_group_id == database_id
        assert SupportGroup.query.get(dba_id) is None
        assert SupportGroup.query.filter_by(name="Database").one().manager_id == database_manager_id


def test_spelling_variant_teams_merge_into_one_canonical_group(client, app):
    """"SSD", "SSD Team", "Unix", "Unix Team", "CoreApps", "Core apps",
    "CoreApps team" are all the same team spelled differently -- the
    duplicate-team cleanup must collapse each cluster into one group,
    preferring whichever already has a manager as canonical."""
    with app.app_context():
        ssd = SupportGroup.query.filter_by(name="SSD").one()
        ssd.manager_id = User.query.filter_by(username="database.manager").one().id
        db.session.add(SupportGroup(name="SSD Team", group_type="IT Fulfillment", tenant_id=1))
        db.session.add(SupportGroup(name="Core apps", group_type="IT Fulfillment", tenant_id=1))
        db.session.add(SupportGroup(name="CoreApps team", group_type="IT Fulfillment", tenant_id=1))
        db.session.commit()
        ssd_manager_id = ssd.manager_id

    login(client)
    response = client.post("/itil/administration", data={
        "action": "merge_duplicate_teams",
    }, follow_redirects=True)
    assert response.status_code == 200

    with app.app_context():
        assert SupportGroup.query.filter_by(name="SSD Team").first() is None
        assert SupportGroup.query.filter_by(name="Core apps").first() is None
        assert SupportGroup.query.filter_by(name="CoreApps team").first() is None
        remaining_ssd = SupportGroup.query.filter_by(name="SSD").one()
        assert remaining_ssd.manager_id == ssd_manager_id
        assert SupportGroup.query.filter_by(name="CoreApps").one()


def test_support_group_dedup_key_ignores_case_whitespace_and_team_suffix(app):
    with app.app_context():
        from app import support_group_dedup_key
        assert support_group_dedup_key("CoreApps") == support_group_dedup_key("Core apps")
        assert support_group_dedup_key("CoreApps") == support_group_dedup_key("CoreApps team")
        assert support_group_dedup_key("SSD") == support_group_dedup_key("SSD Team")
        assert support_group_dedup_key("Unix") == support_group_dedup_key("Unix Team")
        assert support_group_dedup_key("DBA") != support_group_dedup_key("Database")


def test_ci_lookup_includes_owning_team_for_ticket_form_confirmation(client, app):
    with app.app_context():
        windows = SupportGroup.query.filter_by(name="Windows").one()
        db.session.add(ConfigurationItem(
            name="lookup-owning-team.example.com", ci_class="Server",
            environment="Production", support_group_id=windows.id,
        ))
        db.session.add(ConfigurationItem(
            name="lookup-no-owner.example.com", ci_class="Server", environment="Production",
        ))
        db.session.commit()
    login(client)
    with_owner = client.get("/internal/lookup/cis?q=lookup-owning-team").get_json()
    assert with_owner[0]["owning_team"] == "Windows"
    without_owner = client.get("/internal/lookup/cis?q=lookup-no-owner").get_json()
    assert without_owner[0]["owning_team"] is None


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
    bypass = client.post(f"/catalog-task/{task_id}", data={
        "state": "Closed Complete", "work_notes": "Attempted bypass",
    }, follow_redirects=True)
    assert bypass.status_code == 200
    assert b"cannot move from" in bypass.data
    assert client.post(f"/catalog-task/{task_id}", data={
        "state": "Work in Progress", "work_notes": "Started",
    }).status_code == 302
    assert client.post(f"/catalog-task/{task_id}", data={
        "state": "Closed Complete", "work_notes": "Completed",
    }).status_code == 302


def test_catalog_task_blocks_production_work_until_linked_change_is_approved(client, app):
    login(client)
    with app.app_context():
        item = CatalogItem(
            name="Change-linked catalog item", category="Testing",
            description="SCTASK linked to a CHG must wait for approval.",
            approval_required=False,
        )
        db.session.add(item)
        db.session.commit()
        item_id = item.id
    client.post(f"/catalog/{item_id}/order", data={"details": "Install production database agent"})
    with app.app_context():
        ritm = RequestedItem.query.join(CatalogItem).filter(CatalogItem.id == item_id).one()
        ritm_id, task_id = ritm.id, ritm.tasks[0].id

    assert client.post("/tickets/new/change", data={
        "title": "Install production database agent",
        "description": "Requested via catalog fulfillment.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        change_ticket = Ticket.query.filter_by(title="Install production database agent").one()
        change_id, change_number = change_ticket.id, change_ticket.number
        vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=change_id
        ).one().gates[0].votes[0].id

    assert client.post(f"/record/ritm/{ritm_id}/relationships", data={
        "link_type": "requested_item_change", "target_number": change_number,
    }).status_code == 302

    client.post("/logout")
    login(client, "database.manager", "Manager123!")

    # Coordination: moving the SCTASK to Pending (tracking the change) is fine.
    coordination = client.post(f"/catalog-task/{task_id}", data={
        "state": "Pending", "work_notes": "Tracking change approval.",
    })
    assert coordination.status_code == 302

    # Production work must wait for the linked change to be approved.
    blocked = client.post(f"/catalog-task/{task_id}", data={
        "state": "Work in Progress", "work_notes": "Attempting production work early.",
    }, follow_redirects=True)
    assert blocked.status_code == 200
    assert b"cannot start production work" in blocked.data
    with app.app_context():
        assert CatalogTask.query.get(task_id).state == "Pending"

    assert client.post(f"/approval-votes/{vote_id}/decide", data={
        "decision": "Approved",
    }).status_code == 302

    unblocked = client.post(f"/catalog-task/{task_id}", data={
        "state": "Work in Progress", "work_notes": "Change approved, proceeding.",
    })
    assert unblocked.status_code == 302
    with app.app_context():
        assert CatalogTask.query.get(task_id).state == "Work in Progress"


def test_catalog_task_detail_page_shows_notes_form_responses_and_siblings(client, app):
    login(client)
    with app.app_context():
        item = CatalogItem(
            name="Detail page test item", category="Testing",
            description="Standalone catalog task page test", approval_required=False,
        )
        db.session.add(item)
        db.session.commit()
        item_id = item.id
    client.post("/logout")
    login(client, "employee", "Employee123!")
    client.post(f"/catalog/{item_id}/order", data={"details": "Needs a laptop"})
    client.post("/logout")
    login(client)
    with app.app_context():
        ritm = RequestedItem.query.join(CatalogItem).filter(CatalogItem.id == item_id).one()
        ritm_id = ritm.id
        first_task_id = ritm.tasks[0].id
        sibling = CatalogTask(
            number="TASKSIB0001", requested_item_id=ritm_id, title="Sibling task",
            assignment_group_id=RequestedItem.query.get(ritm_id).tasks[0].assignment_group_id,
        )
        db.session.add(sibling)
        db.session.commit()

    client.post("/logout")
    login(client, "database.manager", "Manager123!")

    page = client.get(f"/catalog-task/{first_task_id}")
    assert page.status_code == 200
    assert b"Activity / Worknotes" in page.data
    assert b"RITM Comments (Customer Visible)" in page.data
    assert b"Form Responses" in page.data
    assert b"Needs a laptop" in page.data
    assert b"Sibling task" in page.data

    internal_note = client.post(f"/catalog-task/{first_task_id}/notes", data={
        "visibility": "internal", "body": "Internal-only work note",
    }, follow_redirects=True)
    assert b"Internal-only work note" in internal_note.data

    customer_note = client.post(f"/catalog-task/{first_task_id}/notes", data={
        "visibility": "customer", "body": "Your laptop is being prepared",
    }, follow_redirects=True)
    assert b"Your laptop is being prepared" in customer_note.data

    client.post("/logout")
    login(client, "employee", "Employee123!")
    requester_view = client.get(f"/catalog-task/{first_task_id}")
    assert requester_view.status_code == 200
    assert b"Your laptop is being prepared" in requester_view.data
    assert b"Internal-only work note" not in requester_view.data
    with app.app_context():
        assert Notification.query.filter(
            Notification.body.contains("Your laptop is being prepared")
        ).count() == 1


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
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="change").one()
        assert ticket.change_governance.risk_score == 75
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).one()
        assert [gate.name for gate in chain.gates] == [
            "CoreApps manager assessment", "CCB authorization", "Executive (CEO) approval",
        ]
        assert chain.gates[1].mode == "any"
        assert TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id).count() == 1


def test_change_creation_links_multiple_configuration_items(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        primary_ci = ConfigurationItem(name="app-server-01", ci_class="Server", environment="Production", owner_id=admin.id)
        extra_ci_a = ConfigurationItem(name="lb-01", ci_class="Network Appliance", environment="Production", owner_id=admin.id)
        extra_ci_b = ConfigurationItem(name="db-01", ci_class="Database", environment="Production", owner_id=admin.id)
        db.session.add_all([primary_ci, extra_ci_a, extra_ci_b])
        db.session.commit()
        primary_ci_id, extra_ci_a_id, extra_ci_b_id = primary_ci.id, extra_ci_a.id, extra_ci_b.id
    response = client.post("/tickets/new/change", data={
        "title": "Multi-CI maintenance window",
        "description": "Coordinated maintenance across app, load balancer, and database tiers.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "impact": "Medium",
        "implementation_plan": "Patch each tier in sequence.",
        "test_plan": "Run smoke tests after each tier.",
        "backout_plan": "Roll back the most recently patched tier.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
        "group_id": group_id(app),
        "ci_id": str(primary_ci_id),
        "additional_ci_ids": [str(extra_ci_a_id), str(extra_ci_b_id)],
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="change").one()
        assert ticket.change_governance.ci_id == primary_ci_id
        affected = {
            link.ci_id for link in TaskCI.query.filter_by(
                target_type="ticket", target_id=ticket.id, relationship_role="Affected CI",
            ).all()
        }
        assert affected == {extra_ci_a_id, extra_ci_b_id}


def test_change_cannot_bypass_approval_from_detail_or_board(client, app):
    login(client)
    client.post("/tickets/new/change", data={
        "title": "Protected database change",
        "description": "Must complete manager and CCB authorization.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "70", "impact": "High",
        "implementation_plan": "Implement safely.", "test_plan": "Validate safely.",
        "backout_plan": "Back out safely.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="change").one()
        ticket_id = ticket.id
        first_vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket.id
        ).one().gates[0].votes[0].id
    # B-254: ticket_detail's "update" action redisplays the ticket with a
    # flashed error (302) instead of aborting with a bare 409, so a rejected
    # in-place edit doesn't lose the user's other typed field values. The
    # transition is still refused either way — that's what's under test.
    bypass = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P2",
        "assignee_id": "",
    }, follow_redirects=True)
    assert bypass.status_code == 200
    assert b"cannot move from" in bypass.data.lower()
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
    with app.app_context():
        chain = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).one()
        executive_vote_id = chain.gates[2].votes[0].id
    assert client.post(f"/approval-votes/{executive_vote_id}/decide", data={
        "decision": "Approved", "comments": "Executive authorization",
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
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
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
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
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
        chain = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).order_by(ApprovalChain.id.desc()).first()
        executive_vote_id = chain.gates[2].votes[0].id
    assert client.post(f"/approval-votes/{executive_vote_id}/decide", data={
        "decision": "Approved", "comments": "Executive approved v1.",
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
        "planned_start": "2026-08-02T09:00", "planned_end": "2026-08-02T17:00", "ci_id": "",
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
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
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
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        # Adding a change task after the change was already approved is a
        # material change: it must supersede the prior approval and require
        # a fresh reapproval cycle before the change can complete again.
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.state == "Awaiting Approval"
        new_chain = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id, state="Running"
        ).one()
        new_vote_id = new_chain.gates[0].votes[0].id
    assert client.post(f"/approval-votes/{new_vote_id}/decide", data={
        "decision": "Approved",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P3",
        "assignee_id": "",
    }).status_code == 302
    # B-254: same flash-and-redisplay pattern as the approval-bypass case
    # above, this time for the required-task-incomplete guard in transition_ticket.
    blocked = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "Resolved", "priority": "P3",
        "assignee_id": "",
    }, follow_redirects=True)
    assert blocked.status_code == 200
    assert b"remains" in blocked.data.lower()
    with app.app_context():
        # The change's auto-created "Implementation" task (from creation) and
        # the manually added task above are both required and must each close
        # before the parent change can resolve.
        task_ids = [
            task.id for task in
            OperationalTask.query.filter_by(parent_id=ticket_id).order_by(OperationalTask.id).all()
        ]
    for task_id in task_ids:
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
    premature = client.post(f"/catalog-task/{second_task_id}", data={
        "state": "Work in Progress", "work_notes": "Premature start.",
    }, follow_redirects=True)
    assert premature.status_code == 200
    assert b"cannot start until predecessor" in premature.data
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
    }, follow_redirects=True)
    assert bypass.status_code == 200
    assert b"cannot move from Awaiting Approval to In Progress" in bypass.data
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
    navigation_result = client.get("/ui/search?q=cmdb")
    assert b"CMDB and service map" in navigation_result.data
    assert b"Navigation" in navigation_result.data
    user_result = client.get("/ui/search?q=System+Administrator")
    assert b"User" in user_result.data
    assert b"admin" in user_result.data
    assert client.post("/ui/favorite", data={"url": "/task-board", "label": "My board"}).json["active"]
    client.post("/preferences", data={
        "theme": "dark", "density": "compact", "font_scale": "115",
        "high_contrast": "1", "reduced_motion": "1", "nav_pinned": "1",
        "accessible_tooltips": "1", "data_patterns": "1",
        "compact_dates": "1", "keyboard_shortcuts": "1",
        "date_time_display": "relative",
        "start_page": "/task-board",
    })
    with app.app_context():
        assert Favorite.query.filter_by(url="/task-board").one()
        pref = UserPreference.query.one()
        assert (pref.theme, pref.density, pref.font_scale, pref.start_page) == ("light", "compact", 115, "/task-board")
        assert (pref.accessible_tooltips, pref.data_patterns, pref.compact_dates) == (True, True, True)
        assert (pref.keyboard_shortcuts, pref.date_time_display) == (True, "relative")


def test_profile_and_user_administration_are_tenant_and_role_governed(client, app):
    login(client, "employee", "Employee123!")
    assert client.get("/profile").status_code == 200
    assert client.get("/admin").status_code == 403
    assert client.get("/admin/users").status_code == 403
    response = client.post("/profile", data={
        "name": "Updated Employee", "email": "employee@test.invalid",
        "title": "Analyst", "business_phone": "02 5550 0100",
        "mobile_phone": "0400 000 001", "timezone": "Australia/Sydney",
        "date_format": "day_first",
        "role": "admin", "active": "1", "department": "Security",
    })
    assert response.status_code == 302
    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        assert employee.name == "Updated Employee"
        assert employee.title == "Analyst"
        assert employee.timezone == "Australia/Sydney"
        assert employee.role == "requester"
        assert employee.department == ""

    client.post("/logout")
    login(client)
    employee_id = None
    with app.app_context():
        employee_id = User.query.filter_by(username="employee").one().id
    assert client.get("/admin").status_code == 200
    assert b"Users and access" in client.get("/admin").data
    assert b"Updated Employee" in client.get("/admin/users?q=Updated+Employee").data
    response = client.post(f"/admin/users/{employee_id}", data={
        "name": "Governed Employee", "email": "employee@test.invalid",
        "granted_roles": ["agent"], "active": "1", "title": "Support analyst",
        "department": "Service Desk", "business_phone": "", "mobile_phone": "",
        "timezone": "UTC", "date_format": "system",
        "calendar_integration": "None",
    })
    assert response.status_code == 302
    with app.app_context():
        employee = db.session.get(User, employee_id)
        assert (employee.name, employee.role, employee.department) == (
            "Governed Employee", "agent", "Service Desk"
        )


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


def test_oversized_attachment_redirects_with_friendly_message(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Oversized upload test", "description": "Exceeds the configured limit",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Oversized upload test").one().id
        max_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    oversized = client.post(
        f"/ticket/{ticket_id}/attachments",
        data={"file": (BytesIO(b"x" * (app.config["MAX_CONTENT_LENGTH"] + 1)), "too-big.bin")},
        content_type="multipart/form-data", follow_redirects=True,
        headers={"Referer": f"http://localhost/ticket/{ticket_id}"},
    )
    assert oversized.status_code == 200
    assert f"maximum upload size is {max_mb} MB".encode() in oversized.data
    assert oversized.request.path == f"/ticket/{ticket_id}"
    with app.app_context():
        assert FileAttachment.query.filter_by(ticket_id=ticket_id).count() == 0


def test_priority_override_rejection_stays_on_ticket_page(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Priority override test", "description": "Needs an override",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Priority override test").one()
        ticket_id, current_state = ticket.id, ticket.state

    too_short = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P1",
        "impact": "Low", "urgency": "Low", "assignee_id": "",
        "priority_override_reason": "too short",
    }, follow_redirects=True)
    assert too_short.status_code == 200
    assert too_short.request.path == f"/ticket/{ticket_id}"
    assert b"Only a manager or administrator may override calculated priority" in too_short.data
    with app.app_context():
        assert Ticket.query.get(ticket_id).priority_overridden is False

    accepted = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": current_state, "priority": "P1",
        "impact": "Low", "urgency": "Low", "assignee_id": "",
        "priority_override_reason": "Customer executive escalation, needs immediate handling",
    }, follow_redirects=True)
    assert accepted.status_code == 200
    assert b"Priority override reason recorded" in accepted.data
    assert b"Customer executive escalation" in accepted.data
    with app.app_context():
        ticket = Ticket.query.get(ticket_id)
        assert ticket.priority_overridden is True
        assert ticket.priority_override_reason == "Customer executive escalation, needs immediate handling"


def test_resolved_ticket_locks_edits_but_allows_comments_and_reopen(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Lock after resolve test", "description": "Should lock once resolved",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Lock after resolve test").one().id

    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "Resolved", "priority": "P3", "assignee_id": "",
    }).status_code == 302
    with app.app_context():
        assert Ticket.query.get(ticket_id).state == "Resolved"

    blocked_update = client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "Resolved", "priority": "P1", "assignee_id": "",
    }, follow_redirects=True)
    assert blocked_update.status_code == 200
    assert b"is Resolved and locked" in blocked_update.data
    with app.app_context():
        assert Ticket.query.get(ticket_id).priority == "P3"

    blocked_checklist = client.post(f"/ticket/{ticket_id}/checklist", data={
        "text": "Should not be added",
    }, follow_redirects=True)
    assert b"is Resolved and locked" in blocked_checklist.data
    with app.app_context():
        assert ChecklistItem.query.filter_by(ticket_id=ticket_id).count() == 0

    commented = client.post(f"/ticket/{ticket_id}", data={
        "action": "comment", "body": "Still allowed after resolution",
    }, follow_redirects=True)
    assert commented.status_code == 200
    assert b"Still allowed after resolution" in commented.data

    reopened = client.post(f"/ticket/{ticket_id}", data={
        "action": "reopen",
    }, follow_redirects=True)
    assert reopened.status_code == 200
    assert b"reopened" in reopened.data.lower()
    with app.app_context():
        assert Ticket.query.get(ticket_id).state == "In Progress"

    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P1", "assignee_id": "",
    }).status_code == 302
    with app.app_context():
        assert Ticket.query.get(ticket_id).priority == "P1"


def test_org_chart_reflects_manager_assignment_and_blocks_cycles(client, app):
    login(client)
    with app.app_context():
        tenant_id = User.query.filter_by(username="admin").one().tenant_id
        exec_user = User(
            username="org.exec", name="Org Exec", email="org.exec@example.com",
            password_hash=generate_password_hash("Exec12345!"), role="manager",
            tenant_id=tenant_id, title="VP",
        )
        lead_user = User(
            username="org.lead", name="Org Lead", email="org.lead@example.com",
            password_hash=generate_password_hash("Lead12345!"), role="agent",
            tenant_id=tenant_id, title="Team Lead",
        )
        db.session.add_all([exec_user, lead_user])
        db.session.commit()
        exec_id, lead_id = exec_user.id, lead_user.id

    assert client.post(f"/admin/users/{lead_id}", data={
        "name": "Org Lead", "email": "org.lead@example.com", "granted_roles": ["agent"],
        "active": "1", "manager_id": str(exec_id),
    }).status_code == 302

    with app.app_context():
        assert User.query.get(lead_id).manager_id == exec_id

    chart = client.get("/org-chart")
    assert chart.status_code == 200
    assert b"Org Exec" in chart.data
    assert b"Org Lead" in chart.data

    cycle = client.post(f"/admin/users/{exec_id}", data={
        "name": "Org Exec", "email": "org.exec@example.com", "granted_roles": ["manager"],
        "active": "1", "manager_id": str(lead_id),
    }, follow_redirects=True)
    assert cycle.status_code == 200
    assert b"reporting-line loop" in cycle.data
    with app.app_context():
        assert User.query.get(exec_id).manager_id is None

    self_manage = client.post(f"/admin/users/{exec_id}", data={
        "name": "Org Exec", "email": "org.exec@example.com", "granted_roles": ["manager"],
        "active": "1", "manager_id": str(exec_id),
    }, follow_redirects=True)
    assert b"cannot be their own manager" in self_manage.data


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


def test_task_board_drops_stale_resolved_and_closed_cards(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Old closed ticket", "description": "Should roll off the board",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    client.post("/tickets/new/incident", data={
        "title": "Recently closed ticket", "description": "Still on the board",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    with app.app_context():
        old = Ticket.query.filter_by(title="Old closed ticket").one()
        recent = Ticket.query.filter_by(title="Recently closed ticket").one()
        old.state = recent.state = "Closed"
        db.session.commit()
        old.updated_at = now() - timedelta(days=45)
        recent.updated_at = now() - timedelta(days=5)
        db.session.commit()

    board = client.get("/task-board")
    assert b"Old closed ticket" not in board.data
    assert b"Recently closed ticket" in board.data


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
        # B-253 deliberately seeds the two governed default catalog items
        # CLAUDE.md itself requires ("Software Request -> Windows", "Laptop
        # Request -> Windows") on every fresh install — these are declared
        # product defaults, not demo/sample data, so a fresh production
        # install should have exactly these two and nothing else.
        seeded_names = {item.name for item in CatalogItem.query.all()}
        assert seeded_names == {"Software Request", "Laptop Request"}
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


def test_keycloak_provisioning_applies_mapped_profile_attrs(app):
    with app.app_context():
        user = provision_external_user(
            "keycloak", "subject-456", "bob", "Bob", "bob@example.test", "agent",
            profile_attrs={
                "title": "Site Reliability Engineer", "department": "Platform Engineering",
                "employee_id": "E4821", "business_phone": "+1-555-0100",
                "mobile_phone": "+1-555-0199", "location": "Austin HQ",
            },
        )
        db.session.commit()
        assert user.title == "Site Reliability Engineer"
        assert user.department == "Platform Engineering"
        assert user.employee_id == "E4821"
        assert user.business_phone == "+1-555-0100"
        assert user.mobile_phone == "+1-555-0199"
        assert user.location == "Austin HQ"
        # A later login with a sparser claim set must never null out
        # already-known profile data.
        relogged = provision_external_user(
            "keycloak", "subject-456", "bob", "Bob", "bob@example.test", "agent",
            profile_attrs={"title": "Senior Site Reliability Engineer"},
        )
        db.session.commit()
        assert relogged.title == "Senior Site Reliability Engineer"
        assert relogged.department == "Platform Engineering"
        assert relogged.location == "Austin HQ"


def test_manual_role_grant_survives_directory_login(app):
    """An admin directly granting a user an extra role (e.g. admin, via a
    UserRoleGrant with no ManagedRoleGrant backing) must survive that
    user's next LDAP login -- directory sync only reconciles roles it
    itself granted (source="directory"), never a manual grant."""
    with app.app_context():
        user = provision_external_user(
            "ldap", "CN=Alice,OU=Users,DC=example,DC=com", "alice", "Alice",
            "alice@example.test", "agent",
        )
        db.session.commit()
        user_id = user.id

        # Manual admin grant, exactly as user_edit's POST handler does
        # (which also calls recompute_base_role() after the grant loop).
        db.session.add(UserRoleGrant(user_id=user.id, role="admin"))
        recompute_base_role(user)
        db.session.commit()
        assert set(user.granted_roles) == {"agent", "admin"}
        assert user.role == "admin"  # highest granted

        # Directory still only maps this user to "agent" -- the manual
        # "admin" grant has no ManagedRoleGrant row, so it's never touched.
        relogged = provision_external_user(
            "ldap", "CN=Alice,OU=Users,DC=example,DC=com", "alice", "Alice",
            "alice@example.test", "agent",
        )
        db.session.commit()
        assert relogged.id == user_id
        assert set(relogged.granted_roles) == {"agent", "admin"}


def test_directory_group_can_grant_multiple_roles_at_once(app):
    """A user matching two configured AD-group mappings (one granting
    manager, one granting admin) holds both roles simultaneously, and losing
    one group on a later login only revokes that one grant."""
    with app.app_context():
        row = db.session.get(PlatformSetting, "LDAP_ROLE_MAPPINGS")
        mapping = json.dumps({"gg_managers": "manager", "gg_admins": "admin"})
        if row:
            row.value = mapping
        else:
            db.session.add(PlatformSetting(key="LDAP_ROLE_MAPPINGS", value=mapping, encrypted=False))
        db.session.commit()

        user = provision_external_user(
            "ldap", "CN=Bob,OU=Users,DC=example,DC=com", "bob", "Bob",
            "bob@example.test",
            mapped_roles(
                ["CN=gg_managers,OU=Groups,DC=example,DC=com", "CN=gg_admins,OU=Groups,DC=example,DC=com"],
                "LDAP_ROLE_MAPPINGS",
            ),
        )
        db.session.commit()
        assert set(user.granted_roles) == {"manager", "admin"}
        assert user.role == "admin"

        # Next login: no longer in gg_admins -- only the directory-sourced
        # "admin" grant is revoked, "manager" (still matched) stays.
        relogged = provision_external_user(
            "ldap", "CN=Bob,OU=Users,DC=example,DC=com", "bob", "Bob",
            "bob@example.test",
            mapped_roles(["CN=gg_managers,OU=Groups,DC=example,DC=com"], "LDAP_ROLE_MAPPINGS"),
        )
        db.session.commit()
        assert set(relogged.granted_roles) == {"manager"}
        assert relogged.role == "manager"


def test_effective_role_toggle_is_a_real_demotion(app, client):
    """A user holding both admin and requester can switch which one they're
    acting as, and the switch actually changes what @roles(...) authorizes
    for the rest of that session -- not just a UI label."""
    with app.app_context():
        user = User(
            username="dualrole", name="Dual Role", email="dualrole@test.invalid",
            password_hash=generate_password_hash("DualRole123!"), role="admin",
        )
        db.session.add(user)
        db.session.flush()
        db.session.add(UserRoleGrant(user_id=user.id, role="admin"))
        db.session.add(UserRoleGrant(user_id=user.id, role="requester"))
        db.session.commit()

    login(client, "dualrole", "DualRole123!")
    assert client.get("/admin").status_code == 200

    switched = client.post("/session/acting-role", data={"role": "requester"})
    assert switched.status_code == 302
    # Now genuinely demoted: the same account is blocked from an admin route.
    assert client.get("/admin").status_code == 403

    switch_back = client.post("/session/acting-role", data={"role": "admin"})
    assert switch_back.status_code == 302
    assert client.get("/admin").status_code == 200

    # Cannot switch to a role never granted.
    assert client.post("/session/acting-role", data={"role": "superadmin"}).status_code == 403


def test_superadmin_bypasses_any_roles_gate_but_plain_admin_cannot_reach_platform_tenants(app, client):
    with app.app_context():
        user = User(
            username="theceo", name="The CEO", email="theceo@test.invalid",
            password_hash=generate_password_hash("TheCeo123!"), role="superadmin",
        )
        db.session.add(user)
        db.session.flush()
        db.session.add(UserRoleGrant(user_id=user.id, role="superadmin"))
        db.session.commit()

    login(client, "theceo", "TheCeo123!")
    # superadmin satisfies @roles("admin") without "superadmin" needing to be
    # listed at every one of those call sites.
    assert client.get("/admin").status_code == 200
    assert client.get("/platform/tenants").status_code == 200
    client.post("/logout")

    # A plain admin (the shared fixture's default admin account) cannot.
    login(client)
    assert client.get("/platform/tenants").status_code == 403


def test_user_edit_active_toggle_and_calendar_integration_are_independent_controls(client, app):
    """Regression for a reported UI bug: the "Active" switch was an invalid
    nested <label> (a .switch label inside the field's own label), and its
    checkbox used position:absolute with no positioned ancestor -- with
    nothing containing it, the invisible-but-clickable checkbox could render
    on top of unrelated controls (here, the neighboring Calendar integration
    dropdown), so clicking that dropdown silently toggled Active instead.
    Assert the fixed structure: no nested <label> tags, and the Active
    checkbox is addressed via a plain id/for association."""
    login(client)
    response = client.get("/admin/users/1")
    assert response.status_code == 200
    html = response.data.decode()
    assert '<label class="switch">' not in html
    assert 'id="active-toggle"' in html
    assert 'for="active-toggle"' in html
    assert html.count("<label") == html.count("</label>")


def test_user_edit_granted_roles_checkboxes_are_not_wrapped_in_one_label(client, app):
    """Regression for a reported UI bug: clicking anywhere in the "Granted
    roles" field area (its heading, the info-tip, whitespace between
    checkboxes) always toggled "requester" specifically, regardless of which
    role checkbox the user meant to click. Root cause: every role checkbox
    was already correctly wrapped in its own <label class="check">, but the
    whole group was ALSO wrapped in one outer <label> -- an invalid nested
    label. Per standard label-activation behavior, clicking anywhere inside
    an outer label that isn't a more specific interactive descendant
    activates the FIRST labelable descendant in tree order, which is
    "requester" (the first role rendered). Fixed by making the outer
    wrapper a plain <div>, not a <label>, so only a direct click on a
    specific role's own <label class="check"> activates that role."""
    login(client)
    response = client.get("/admin/users/1")
    assert response.status_code == 200
    html = response.data.decode()
    assert '<div class="wide field-group">' in html
    assert '<label class="wide">' not in html
    assert html.count("<label") == html.count("</label>")


def test_user_edit_grants_and_revokes_multiple_roles(client, app):
    with app.app_context():
        target = User(
            username="multirole", name="Multi Role", email="multirole@test.invalid",
            password_hash=generate_password_hash("MultiRole123!"), role="agent",
        )
        db.session.add(target)
        db.session.flush()
        db.session.add(UserRoleGrant(user_id=target.id, role="agent"))
        db.session.commit()
        target_id = target.id

    login(client)
    resp = client.post(f"/admin/users/{target_id}", data={
        "name": "Multi Role", "email": "multirole@test.invalid",
        "granted_roles": ["agent", "manager"], "active": "on",
        "timezone": "Asia/Tokyo", "date_format": "system",
    })
    assert resp.status_code == 302
    with app.app_context():
        target = db.session.get(User, target_id)
        assert set(target.granted_roles) == {"agent", "manager"}
        assert target.role == "manager"

    # A plain admin cannot grant superadmin to someone else.
    resp = client.post(f"/admin/users/{target_id}", data={
        "name": "Multi Role", "email": "multirole@test.invalid",
        "granted_roles": ["agent", "manager", "superadmin"], "active": "on",
        "timezone": "Asia/Tokyo", "date_format": "system",
    })
    assert resp.status_code == 302
    with app.app_context():
        target = db.session.get(User, target_id)
        assert "superadmin" not in target.granted_roles


def test_ticket_creation_survives_a_racing_duplicate_number(app):
    """next_number() derives a ticket's number from MAX(Ticket.id) with no
    locking, so two near-simultaneous ticket creations can compute the
    identical number before either commits -- Ticket.number is unique=True,
    so this previously surfaced as a raw IntegrityError/500 instead of the
    second creator just getting the next available number. Simulate the
    race directly: pre-insert a ticket at the number next_number() would
    compute, then create_ticket_with_unique_number() must still succeed
    (with a different number) instead of raising."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        colliding_number = next_number("incident")
        db.session.add(Ticket(
            number=colliding_number, kind="incident", title="Racing ticket",
            description="Occupies the number the next call would compute.",
            category="Software", priority="P3", state="New", requester_id=admin.id,
        ))
        db.session.commit()

        ticket = create_ticket_with_unique_number(
            "incident", title="Should not collide", description="Retry must recover.",
            category="Software", priority="P3", requester_id=admin.id,
        )
        db.session.commit()
        assert ticket.number != colliding_number
        assert ticket.number.startswith("INC")
        assert Ticket.query.filter_by(number=ticket.number).count() == 1


def test_create_with_retry_gives_up_after_persistent_collisions(app):
    """If every retry attempt keeps colliding, fail closed with a clear 409
    instead of retrying forever or letting a raw IntegrityError escape."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        fixed_number = next_number("incident")

        def build_always_colliding():
            ticket = Ticket(
                number=fixed_number, kind="incident", title="Always collides",
                description="Never a fresh number.", category="Software",
                priority="P3", state="New", requester_id=admin.id,
            )
            db.session.add(ticket)
            return ticket

        db.session.add(Ticket(
            number=fixed_number, kind="incident", title="Blocks the number",
            description="Pre-existing.", category="Software", priority="P3",
            state="New", requester_id=admin.id,
        ))
        db.session.commit()

        with pytest.raises(Exception) as excinfo:
            create_with_retry_on_number_collision(build_always_colliding, attempts=3)
        assert getattr(excinfo.value, "code", None) == 409


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


def test_ldap_login_adopts_a_preexisting_account_by_email_instead_of_duplicating_it(app):
    """A user auto-created by an external bulk import (e.g.
    serviceops_core/rt_import.py matching an RT Requestor by email) has no
    ExternalIdentity yet. Their first real LDAP login must adopt that
    existing account -- and pick up its team memberships via
    sync_directory_team_memberships -- rather than creating a second,
    disconnected account with a suffixed username that never gets any team
    assignment."""
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        db.session.add(DirectoryGroupMapping(directory_group="gg_unix", support_group_id=unix.id))
        preexisting = User(
            username="bob", name="Bob", email="bob@example.test",
            password_hash=generate_password_hash(uuid.uuid4().hex), role="requester",
        )
        db.session.add(preexisting)
        db.session.commit()
        preexisting_id = preexisting.id

        user = provision_external_user(
            "ldap", "CN=Bob,OU=Users,DC=example,DC=com", "bob", "Bob",
            "bob@example.test", "agent",
            groups=["CN=gg_unix,OU=Groups,DC=example,DC=com"],
        )
        db.session.commit()

        assert user.id == preexisting_id
        assert User.query.filter_by(username="bob").count() == 1
        assert ExternalIdentity.query.filter_by(provider="ldap", user_id=preexisting_id).count() == 1
        assert GroupMember.query.filter_by(user_id=preexisting_id, group_id=unix.id).count() == 1


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


def test_administration_is_one_hub_with_clear_child_areas(client):
    login(client)
    home = client.get("/admin")
    assert home.status_code == 200
    assert b"Platform settings" in home.data
    assert b"Service delivery and governance" in home.data
    assert b"Automation rules" in home.data
    assert b"Rules that react to ticket changes" in home.data
    assert b"CMDB and service map" not in home.data
    assert b"Reporting and analytics" not in home.data

    sidebar = home.data.split(b'<aside class="sidebar">', 1)[1].split(b"</aside>", 1)[0]
    assert b"Dashboard" in sidebar
    assert b"Incidents" in sidebar
    assert b"Service requests" in sidebar
    assert b"Service catalog" in sidebar
    assert b"Knowledge" in sidebar
    assert b"All workspaces" in sidebar
    assert b"OPERATIONS" in sidebar
    assert b"Administration home" in sidebar
    assert b"Service operations settings" not in sidebar
    assert b"System settings" not in sidebar
    assert b">Workflows<" not in sidebar

    header = home.data.split(b'<header class="unified-nav">', 1)[1].split(b"</header>", 1)[0]
    assert b"Search ServiceOps" in header
    assert b"contextual-app-pill" not in header
    assert b"Default update set" not in header
    assert b'data-platform-drawer=' not in home.data

    settings = client.get("/admin/settings")
    assert b"Administration home" in settings.data
    assert b'aria-label="Administration breadcrumb"' in settings.data
    assert settings.data.count(b'aria-label="Administration breadcrumb"') == 1
    assert b"ADMINISTRATION HOME / PLATFORM SETTINGS" not in settings.data
    assert b'href="#settings-branding"' in settings.data
    assert b"Identity and experience" in settings.data
    assert b"organization identity and branding" in settings.data
    assert b"NetBox and RT connections" in settings.data
    assert b"Ticket, team, change, service, and SLA policies" in settings.data
    assert b"Protection and behavior" in settings.data
    assert b"Sign-in and directory" in settings.data
    assert b"Change freeze message" not in settings.data
    assert b'id="settings-change_approval_policy"' not in settings.data
    assert b"Change approval policy" not in settings.data
    assert b'id="settings-ticket_behavior"' not in settings.data
    assert b"Default ticket priority" not in settings.data
    assert b"Runtime environment" in settings.data
    assert b"Application replicas" in settings.data
    assert b"1 (local Compose default)" in settings.data

    automation = client.get("/admin/workflows")
    assert b"Automation rules" in automation.data
    assert b"When</b> an event occurs" in automation.data
    assert b"Technical execution evidence" in automation.data

    users_page = client.get("/admin/users")
    assert users_page.data.count(b'aria-label="Administration breadcrumb"') == 1
    assert b'class="button" href="/admin">Administration home</a>' not in users_page.data
    new_user = client.get("/admin/users/new")
    assert b"Administration home" in new_user.data
    assert b"Users and access" in new_user.data

    governance = client.get("/itil/administration")
    assert governance.status_code == 200
    expected_section_order = [
        b'id="ticket-defaults"', b'id="catalog"', b'id="directory-mapping"', b'id="team-aliases"',
        b'id="ldap-sync"', b'id="team-managers"', b'id="governance-groups"',
        b'id="change-approval-policy"', b'id="ccb"', b'id="change-freeze"',
        b'id="service-offerings"', b'id="sla"',
    ]
    positions = [governance.data.index(marker) for marker in expected_section_order]
    assert positions == sorted(positions)
    assert governance.data.count(b'id="governance-groups"') == 1
    assert governance.data.count(b'id="service-offerings"') == 1
    assert b"Production" in governance.data

    response = client.post("/itil/administration", data={
        "action": "set_change_approval_policy",
        "ccb_required_environments": "Production, Staging, production",
    })
    assert response.status_code == 302
    updated = client.get("/itil/administration")
    assert b'value="Production, Staging"' in updated.data

    response = client.post("/itil/administration", data={
        "action": "set_ticket_defaults",
        "default_ticket_priority": "P2",
        "sync_child_incident_states": "on",
    })
    assert response.status_code == 302
    updated = client.get("/itil/administration")
    assert b'<option value="P2" selected>P2</option>' in updated.data
    assert b'name="sync_child_incident_states" checked' in updated.data


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
    assert b"Platform settings saved" in response.data
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
    assert b"They cannot run arbitrary scripts" in page.data
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


def test_knowledge_publish_updated_version_archives_previous(client, app):
    login(client)
    assert client.post("/knowledge/new", data={
        "title": "Reset a locked account", "category": "Access",
        "body": "Original steps.",
    }).status_code == 302
    with app.app_context():
        article = Knowledge.query.filter_by(title="Reset a locked account").one()
        article_id = article.id
    detail = client.get(f"/knowledge/{article_id}")
    assert b"Original steps." in detail.data
    assert client.post(f"/knowledge/{article_id}/edit", data={
        "title": "Reset a locked account", "category": "Access",
        "body": "Updated steps with MFA re-enrollment.",
    }).status_code == 302
    with app.app_context():
        original = db.session.get(Knowledge, article_id)
        assert original.archived is True
        assert original.published is False
        new_version = db.session.get(Knowledge, original.superseded_by_id)
        assert new_version.body == "Updated steps with MFA re-enrollment."
        assert new_version.published is True
        assert new_version.archived is False
        new_version_id = new_version.id
    listing = client.get("/knowledge")
    assert b"Updated steps with MFA re-enrollment." in listing.data
    assert listing.data.count(b"Reset a locked account") == 1
    with app.app_context():
        assert Knowledge.query.filter_by(archived=True).count() == 1
    archived_detail = client.get(f"/knowledge/{article_id}")
    assert b"archived" in archived_detail.data.lower()
    assert client.get(f"/knowledge/{new_version_id}").status_code == 200


def test_knowledge_archive_without_new_version_hides_from_search(client, app):
    login(client)
    assert client.post("/knowledge/new", data={
        "title": "Deprecated VPN setup", "category": "Network",
        "body": "This process no longer applies.",
    }).status_code == 302
    with app.app_context():
        article_id = Knowledge.query.filter_by(title="Deprecated VPN setup").one().id
    assert client.post(f"/knowledge/{article_id}/archive").status_code == 302
    assert b"Deprecated VPN setup" not in client.get("/knowledge").data
    with app.app_context():
        article = db.session.get(Knowledge, article_id)
        assert article.archived is True
        assert article.published is False
        assert article.superseded_by_id is None


def test_change_requires_planned_dates_at_creation_and_edit(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Missing schedule change", "description": "No planned window supplied.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
    }).status_code == 400
    assert client.post("/tickets/new/change", data={
        "title": "Backwards schedule change", "description": "End before start.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T17:00", "planned_end": "2026-08-01T09:00",
    }).status_code == 400
    assert client.post("/tickets/new/change", data={
        "title": "Well-scheduled change", "description": "Has a valid window.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Well-scheduled change").one().id
    plan_edit = client.post(f"/change/{ticket_id}/plan", data={
        "title": "Well-scheduled change", "description": "Has a valid window.",
        "change_type": "Standard", "risk_score": "25", "impact": "Low",
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.", "planned_start": "", "planned_end": "",
    }, follow_redirects=True)
    assert plan_edit.status_code == 200
    assert b"Planned start and planned end are required" in plan_edit.data


def test_change_task_requires_dates_within_parent_window(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Windowed change", "description": "Has a bounded change window.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Windowed change").one().id
    assert client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Planning session", "task_type": "Planning",
        "group_id": group_id(app), "required": "",
    }).status_code == 400
    assert client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Out of window task", "task_type": "Planning",
        "group_id": group_id(app), "required": "",
        "planned_start": "2026-07-31T09:00", "planned_end": "2026-07-31T17:00",
    }).status_code == 409
    assert client.post(f"/change/{ticket_id}/tasks", data={
        "title": "In window task", "task_type": "Planning",
        "group_id": group_id(app), "required": "",
        "planned_start": "2026-08-01T10:00", "planned_end": "2026-08-01T11:00",
    }).status_code == 302


def test_change_task_unlocking_model_gates_implementation_and_review(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Gated implementation change",
        "description": "Implementation and review must stay Pending until approved/complete.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Gated implementation change").one()
        ticket_id = ticket.id
        implementation_task = OperationalTask.query.filter_by(
            parent_id=ticket_id, task_type="Implementation",
        ).one()
        assert implementation_task.state == "Pending"
        implementation_task_id = implementation_task.id

    # A Planning task can proceed before approval.
    plan_added = client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Draft rollout plan", "task_type": "Planning",
        "group_id": group_id(app), "required": "",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T09:30",
    })
    assert plan_added.status_code == 302
    with app.app_context():
        plan_task_id = OperationalTask.query.filter_by(
            parent_id=ticket_id, task_type="Planning",
        ).one().id
        vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id, state="Running",
        ).one().gates[0].votes[0].id
    plan_open = client.post(f"/operational-task/{plan_task_id}", data={
        "state": "Work in Progress", "assignee_id": "", "work_notes": "Started planning.",
    })
    assert plan_open.status_code == 302

    # Implementation must stay Pending until the change is fully approved.
    blocked = client.post(f"/operational-task/{implementation_task_id}", data={
        "state": "Work in Progress", "assignee_id": "", "work_notes": "Attempted early start.",
    }, follow_redirects=True)
    assert blocked.status_code == 200
    assert b"must stay Pending until" in blocked.data
    with app.app_context():
        assert OperationalTask.query.get(implementation_task_id).state == "Pending"

    # The state dropdown itself must be disabled while gated, with an explanatory note.
    gated_page = client.get(f"/operational-task/{implementation_task_id}")
    assert gated_page.status_code == 200
    import re as _re
    select_html = _re.search(rb'<select name="state".*?</select>', gated_page.data, _re.S).group(0)
    assert b"Work in Progress" not in select_html
    assert b"field-gate-note" in gated_page.data
    assert b"must stay Pending until" in gated_page.data

    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{vote_id}/decide", data={
        "decision": "Approved",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P3", "assignee_id": "",
    }).status_code == 302

    # Now that the change is approved, Implementation can proceed.
    unblocked = client.post(f"/operational-task/{implementation_task_id}", data={
        "state": "Work in Progress", "assignee_id": "", "work_notes": "Approved, starting work.",
    })
    assert unblocked.status_code == 302
    with app.app_context():
        assert OperationalTask.query.get(implementation_task_id).state == "Work in Progress"

    # Review is added and must stay Pending until implementation is closed.
    review_added = client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Post-implementation review", "task_type": "Review",
        "group_id": group_id(app), "required": "1",
        "planned_start": "2026-08-01T16:30", "planned_end": "2026-08-01T17:00",
    })
    assert review_added.status_code == 302
    with app.app_context():
        # Adding a task after In Progress supersedes approval again; re-approve
        # so the implementation task can be closed in this test.
        new_vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id, state="Running"
        ).one().gates[0].votes[0].id
        review_task_id = OperationalTask.query.filter_by(
            parent_id=ticket_id, task_type="Review",
        ).one().id
    assert client.post(f"/approval-votes/{new_vote_id}/decide", data={
        "decision": "Approved",
    }).status_code == 302
    assert client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "In Progress", "priority": "P3", "assignee_id": "",
    }).status_code == 302

    review_blocked = client.post(f"/operational-task/{review_task_id}", data={
        "state": "Work in Progress", "assignee_id": "", "work_notes": "Too early.",
    }, follow_redirects=True)
    assert review_blocked.status_code == 200
    assert b"must stay Pending until all required" in review_blocked.data

    assert client.post(f"/operational-task/{implementation_task_id}", data={
        "state": "Closed Complete", "assignee_id": "", "work_notes": "Deployed.",
    }).status_code == 302

    review_open = client.post(f"/operational-task/{review_task_id}", data={
        "state": "Work in Progress", "assignee_id": "", "work_notes": "Starting review.",
    })
    assert review_open.status_code == 302
    with app.app_context():
        assert OperationalTask.query.get(review_task_id).state == "Work in Progress"


def test_operational_task_detail_shows_activity_notes_and_siblings(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Note visibility change", "description": "Verifies CTASK activity tab.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Note visibility change").one().id
    assert client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Second task", "task_type": "Planning",
        "group_id": group_id(app), "required": "",
        "planned_start": "2026-08-01T10:00", "planned_end": "2026-08-01T11:00",
    }).status_code == 302
    with app.app_context():
        tasks = OperationalTask.query.filter_by(parent_id=ticket_id).order_by(OperationalTask.id).all()
        first_task_id, second_task_id = tasks[0].id, tasks[1].id

    page = client.get(f"/operational-task/{first_task_id}")
    assert page.status_code == 200
    assert b"Activity / Worknotes" in page.data
    assert b"Sibling tasks" in page.data
    assert b"Second task" in page.data

    posted = client.post(f"/operational-task/{first_task_id}/notes", data={
        "body": "Coordinating with the network team before starting.",
    }, follow_redirects=True)
    assert posted.status_code == 200
    assert b"Coordinating with the network team before starting." in posted.data
    with app.app_context():
        assert TaskNote.query.filter_by(target_type="operational_task", target_id=first_task_id).count() == 1


def test_change_creation_blocks_on_open_incident_conflict(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ci = ConfigurationItem(
            name="shared-app-server", ci_class="Server",
            environment="Production", owner_id=admin.id,
        )
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    login(client)
    assert client.post("/tickets/new/incident", data={
        "title": "Shared server degraded", "description": "Ongoing incident on the CI.",
        "category": "Software", "priority": "P2", "group_id": group_id(app),
        "ci_id": str(ci_id),
    }).status_code == 302
    blocked = client.post("/tickets/new/change", data={
        "title": "Change during open incident", "description": "Should be blocked.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.", "ci_id": str(ci_id),
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    })
    assert blocked.status_code == 400
    assert b"open incident" in blocked.data.lower()
    with app.app_context():
        assert Ticket.query.filter_by(title="Change during open incident").first() is None


def test_change_creation_blocks_on_overlapping_change_conflict(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ci = ConfigurationItem(
            name="second-app-server", ci_class="Server",
            environment="Production", owner_id=admin.id,
        )
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "First maintenance window", "description": "First change on the CI.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.", "ci_id": str(ci_id),
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        first = Ticket.query.filter_by(title="First maintenance window").one()
        assert first.change_governance.conflict_status == "No conflict"
        first_number = first.number
    blocked = client.post("/tickets/new/change", data={
        "title": "Second overlapping window", "description": "Overlaps the first change.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.", "ci_id": str(ci_id),
        "planned_start": "2026-08-01T12:00", "planned_end": "2026-08-01T18:00",
    })
    assert blocked.status_code == 400
    assert b"overlapping change" in blocked.data.lower()
    assert first_number.encode() in blocked.data
    with app.app_context():
        assert Ticket.query.filter_by(title="Second overlapping window").first() is None


def test_adding_change_task_after_approval_forces_reapproval(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Approved then rescoped change", "description": "Gets a task added post-approval.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Approved then rescoped change").one()
        ticket_id = ticket.id
        vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).one().gates[0].votes[0].id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{vote_id}/decide", data={
        "decision": "Approved",
    }).status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Approved"
    assert client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Extra validation step", "task_type": "Testing",
        "group_id": group_id(app), "required": "",
        "planned_start": "2026-08-01T10:00", "planned_end": "2026-08-01T11:00",
    }).status_code == 302
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.state == "Awaiting Approval"
        chains = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).order_by(ApprovalChain.id).all()
        assert len(chains) == 2
        assert chains[0].state == "Superseded"
        assert chains[1].state == "Running"
        assert TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket_id, event="Approval restarted",
        ).one()


def test_governance_tables_carry_their_own_enforced_tenant_id(client, app):
    """B-260: approval_gate/approval_vote/change_governance previously relied
    entirely on joining back through approval_chain/ticket for tenant
    scoping; each now carries its own enforced tenant_id column."""
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Tenant-scoped governance check", "description": "Verifies own tenant_id columns.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Tenant-scoped governance check").one()
        expected_tenant_id = ticket.tenant_id
        governance = ChangeGovernance.query.filter_by(ticket_id=ticket.id).one()
        assert governance.tenant_id == expected_tenant_id
        gate = ApprovalGate.query.join(ApprovalChain).filter(
            ApprovalChain.target_type == "ticket", ApprovalChain.target_id == ticket.id,
        ).one()
        assert gate.tenant_id == expected_tenant_id
        vote = ApprovalVote.query.filter_by(gate_id=gate.id).one()
        assert vote.tenant_id == expected_tenant_id


def test_ci_addition_after_approval_forces_reapproval(client, app):
    """B-258 fix #1: adding an Affected CI/Impacted service to an
    already-approved change is a material change and must invalidate the
    current approval chain, the same as team/plan/task edits already do."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ci = ConfigurationItem(
            name="reapproval-ci", ci_class="Server", environment="Production", owner_id=admin.id,
        )
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Approved then CI-swapped change", "description": "Gets a CI added post-approval.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Approved then CI-swapped change").one()
        ticket_id = ticket.id
        vote_id = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).one().gates[0].votes[0].id
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.post(f"/approval-votes/{vote_id}/decide", data={
        "decision": "Approved",
    }).status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Approved"
    assert client.post(f"/record/ticket/{ticket_id}/configuration-items", data={
        "ci_id": str(ci_id), "relationship_role": "Affected CI",
    }).status_code == 302
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.state == "Awaiting Approval"
        chains = ApprovalChain.query.filter_by(
            target_type="ticket", target_id=ticket_id
        ).order_by(ApprovalChain.id).all()
        assert len(chains) == 2
        assert chains[0].state == "Superseded"
        assert chains[1].state == "Running"


def test_emergency_change_uses_expedited_single_approver_ccb_stage(app):
    """B-258 fix #2: Emergency changes get a distinct, faster CCB gate (any
    one active CCB approver) instead of falling through to the same
    full-board majority gate Normal changes use — but CCB authorization
    itself is never skipped."""
    with app.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        ticket = Ticket(
            kind="change", number="CHG0000901", title="Emergency patch",
            description="Test emergency change.", category="Software",
            priority="P2", state="New", requester_id=manager.id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=windows.id))
        db.session.add(ChangeGovernance(
            ticket_id=ticket.id, change_type="Emergency", risk_score=80, impact="High",
            implementation_plan="Patch now.", test_plan="Smoke test.", backout_plan="Roll back.",
        ))
        db.session.commit()
        stages = change_approval_stages(ticket)
        names = [stage["name"] for stage in stages]
        assert "Emergency CCB authorization (expedited)" in names
        emergency_stage = next(s for s in stages if s["name"] == "Emergency CCB authorization (expedited)")
        assert emergency_stage["mode"] == "any"


def test_ccb_required_false_skips_ccb_gate_for_normal_change(app):
    """B-258 fix #5: ChangeGovernance.ccb_required is now actually read by
    change_approval_stages instead of being a column nothing consulted."""
    with app.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        ticket = Ticket(
            kind="change", number="CHG0000902", title="CCB-exempt normal change",
            description="Test ccb_required=False path.", category="Software",
            priority="P3", state="New", requester_id=manager.id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=windows.id))
        db.session.add(ChangeGovernance(
            ticket_id=ticket.id, change_type="Normal", risk_score=20, impact="Low",
            implementation_plan="Implement.", test_plan="Test.", backout_plan="Back out.",
            ccb_required=False,
        ))
        db.session.commit()
        stages = change_approval_stages(ticket)
        assert all("CCB" not in stage["name"] for stage in stages)


def test_change_gets_ci_owner_manager_approval_when_different_from_assignment_group(client, app):
    """The change is assigned to the executing team (e.g. Unix) but the CI
    it targets is owned by a different team (e.g. DBA) — that team's manager
    must also approve, not just the executing team's manager."""
    with app.app_context():
        database = SupportGroup.query.filter_by(name="Database").one()
        ci = ConfigurationItem(
            name="dci2bo03.dc.japannext.co.jp", ci_class="Server",
            environment="Production", support_group_id=database.id,
        )
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    login(client)
    client.post("/tickets/new/change", data={
        "title": "Patch the DB host", "description": "Apply a patch.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "60", "impact": "High",
        "implementation_plan": "Patch it.", "test_plan": "Verify it.",
        "backout_plan": "Roll back.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
        "group_id": group_id(app, "Unix"), "ci_id": str(ci_id),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(kind="change").one()
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).one()
        names = [gate.name for gate in chain.gates]
        assert "Unix manager assessment" in names
        assert "Database manager assessment (CI owner)" in names


def test_change_requires_every_service_co_owner_team_manager_approval(app):
    """The change's CI backs a business service that's also backed by CIs
    owned by two other teams -- each of those teams' managers must approve
    too, not just the executing team and the change's own CI owner."""
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        database = SupportGroup.query.filter_by(name="Database").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        manager = User.query.filter_by(username="database.manager").one()
        # The shared fixture already makes `manager` the manager of every
        # IT Fulfillment team (including Network) -- no extra setup needed.
        network = SupportGroup.query.filter_by(name="Network").one()

        primary_ci = ConfigurationItem(
            name="lb-primary", ci_class="Server", environment="Production",
            support_group_id=network.id,
        )
        sibling_ci = ConfigurationItem(
            name="app-server-01", ci_class="Server", environment="Production",
            support_group_id=database.id,
        )
        db.session.add_all([primary_ci, sibling_ci])
        db.session.flush()
        offering = ServiceOffering(name="Checkout Service", owner_id=manager.id)
        db.session.add(offering)
        db.session.flush()
        db.session.add_all([
            ServiceOfferingCI(service_offering_id=offering.id, ci_id=primary_ci.id),
            ServiceOfferingCI(service_offering_id=offering.id, ci_id=sibling_ci.id),
        ])
        ticket = Ticket(
            kind="change", number="CHG0000950", title="Load balancer change",
            description="Test multi-team service co-ownership approval.", category="Software",
            priority="P3", state="New", requester_id=manager.id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=unix.id))
        db.session.add(ChangeGovernance(
            ticket_id=ticket.id, change_type="Normal", risk_score=40, impact="Medium",
            implementation_plan="Implement.", test_plan="Test.", backout_plan="Back out.",
            ci_id=primary_ci.id,
        ))
        db.session.commit()
        stages = change_approval_stages(ticket)
        names = [stage["name"] for stage in stages]
        assert "Unix manager assessment" in names
        assert "Network manager assessment (CI owner)" in names
        assert "Database manager assessment (service co-owner)" in names
        assert "Executive (CEO) approval" in names
        ccb_stage = next(stage for stage in stages if "CCB" in stage["name"])
        assert ccb_stage["mode"] == "any"


def test_change_blocked_when_executive_approver_not_configured(app):
    with app.app_context():
        executive_office = SupportGroup.query.filter_by(name="Executive Office").one()
        executive_office.manager_id = None
        db.session.commit()
        manager = User.query.filter_by(username="database.manager").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        ticket = Ticket(
            kind="change", number="CHG0000951", title="Needs executive approval",
            description="Test executive approver enforcement.", category="Software",
            priority="P3", state="New", requester_id=manager.id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=windows.id))
        db.session.add(ChangeGovernance(
            ticket_id=ticket.id, change_type="Normal", risk_score=40, impact="Medium",
            implementation_plan="Implement.", test_plan="Test.", backout_plan="Back out.",
        ))
        db.session.commit()
        with pytest.raises(Exception):
            change_approval_stages(ticket)


def test_ccb_only_required_for_environments_in_setting_by_default(app):
    """Only Production (the default CCB_REQUIRED_ENVIRONMENTS) goes to CCB;
    a Normal change against a Development CI should skip the CCB gate."""
    with app.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        ci = ConfigurationItem(name="dev-box-01", ci_class="Server", environment="Development")
        db.session.add(ci)
        db.session.flush()
        ticket = Ticket(
            kind="change", number="CHG0000903", title="Dev change",
            description="Test environment-based CCB gating.", category="Software",
            priority="P3", state="New", requester_id=manager.id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=windows.id))
        db.session.add(ChangeGovernance(
            ticket_id=ticket.id, change_type="Normal", risk_score=20, impact="Low",
            implementation_plan="Implement.", test_plan="Test.", backout_plan="Back out.",
            ci_id=ci.id,
        ))
        db.session.commit()
        stages = change_approval_stages(ticket)
        assert all("CCB" not in stage["name"] for stage in stages)


def test_ci_require_ccb_approval_override_forces_ccb_for_non_production(app):
    """The per-CI 'always require CCB' override forces the CCB gate even for
    an environment that isn't in CCB_REQUIRED_ENVIRONMENTS (custom cases like
    a business-critical UAT box)."""
    with app.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        ci = ConfigurationItem(
            name="uat-critical-01", ci_class="Server", environment="Staging",
            require_ccb_approval=True,
        )
        db.session.add(ci)
        db.session.flush()
        ticket = Ticket(
            kind="change", number="CHG0000904", title="UAT change",
            description="Test per-CI CCB override.", category="Software",
            priority="P3", state="New", requester_id=manager.id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=windows.id))
        db.session.add(ChangeGovernance(
            ticket_id=ticket.id, change_type="Normal", risk_score=20, impact="Low",
            implementation_plan="Implement.", test_plan="Test.", backout_plan="Back out.",
            ci_id=ci.id,
        ))
        db.session.commit()
        stages = change_approval_stages(ticket)
        assert any("CCB" in stage["name"] for stage in stages)


def test_ldap_bind_password_decrypt_failure_refuses_anonymous_fallback(app):
    """B-258 fix #3: if the configured LDAP bind password can't be
    decrypted (e.g. SETTINGS_ENCRYPTION_KEY rotated), authentication must
    abort rather than silently degrading a configured bind to anonymous."""
    with app.app_context():
        db.session.add(PlatformSetting(key="LDAP_ENABLED", value="true", encrypted=False))
        db.session.add(PlatformSetting(key="LDAP_SERVER_URI", value="ldap://ldap.example.test", encrypted=False))
        db.session.add(PlatformSetting(key="LDAP_BIND_DN", value="cn=svc,dc=example,dc=test", encrypted=False))
        db.session.add(PlatformSetting(
            key="LDAP_BIND_PASSWORD", value="not-a-real-fernet-token", encrypted=True,
        ))
        db.session.commit()
        assert ldap_authenticate("someuser", "somepassword") is None


def test_api_rate_limit_returns_429_with_retry_after(client, app):
    """B-258 fix #4: /api/v1/* previously had no request-rate protection."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(
            name="Rate limit test", token_prefix=prefix, token_hash=token_hash,
            scopes_json='["tickets:read"]', acting_user_id=admin.id, created_by_id=admin.id,
        ))
        db.session.add(PlatformSetting(key="API_RATE_LIMIT_PER_MINUTE", value="3", encrypted=False))
        db.session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    statuses = [client.get("/api/v1/tickets", headers=headers).status_code for _ in range(5)]
    assert statuses[:3] == [200, 200, 200]
    assert 429 in statuses
    limited = client.get("/api/v1/tickets", headers=headers)
    assert limited.status_code == 429
    assert "Retry-After" in limited.headers
    with app.app_context():
        assert APIRateLimitWindow.query.count() >= 1


def test_infected_attachment_is_rejected_and_clean_attachment_gets_sha256(client, app, monkeypatch):
    """B-258 fix #6 plus B-260's addition of a scan/hash pipeline: a positive
    scan result must delete the file and create no attachment row; a clean
    result must persist a sha256 hash alongside it."""
    login(client)
    assert client.post("/tickets/new/incident", data={
        "title": "Attachment scan test", "description": "For scan/hash coverage.",
        "category": "Software", "priority": "P3", "group_id": group_id(app),
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Attachment scan test").one()
        ticket_id = ticket.id

    monkeypatch.setattr("app.scan_attachment", lambda path: "infected")
    blocked = client.post(
        f"/ticket/{ticket_id}/attachments",
        data={"file": (BytesIO(b"\xff\xd8\xffnot really a virus"), "payload.jpg")},
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert blocked.status_code == 200
    assert b"rejected by malware scanning" in blocked.data
    with app.app_context():
        assert FileAttachment.query.filter_by(ticket_id=ticket_id).count() == 0

    monkeypatch.setattr("app.scan_attachment", lambda path: "clean")
    accepted = client.post(
        f"/ticket/{ticket_id}/attachments",
        data={"file": (BytesIO(b"\xff\xd8\xffa real-looking jpeg"), "photo.jpg")},
        content_type="multipart/form-data",
    )
    assert accepted.status_code == 302
    with app.app_context():
        attachment = FileAttachment.query.filter_by(ticket_id=ticket_id).one()
        assert attachment.scan_status == "clean"
        assert len(attachment.sha256) == 64


def test_scan_attachment_reports_not_scanned_when_unconfigured(app, tmp_path):
    """No ClamAV configured is the out-of-the-box state for most deployments;
    the adapter must say so honestly rather than silently claiming clean."""
    with app.app_context():
        sample = tmp_path / "sample.txt"
        sample.write_text("hello")
        assert scan_attachment(str(sample)) == "not_scanned"


def test_ticket_detail_pages_show_ci_owning_team(client, app):
    """CMDB owning-team context must be visible on the ticket body itself
    (not just the picker while filling the form), for changes, incidents,
    and enterprise records alike."""
    with app.app_context():
        windows = SupportGroup.query.filter_by(name="Windows").one()
        ci = ConfigurationItem(
            name="detail-owning-team.example.com", ci_class="Server",
            environment="Production", support_group_id=windows.id,
        )
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    login(client)

    change = client.post("/tickets/new/change", data={
        "title": "Owning team visibility check",
        "description": "Confirm the CI owning team renders on the change body.",
        "category": "Software", "change_type": "Normal",
        "risk_score": "10", "impact": "Low", "urgency": "Low",
        "implementation_plan": "n/a", "test_plan": "n/a", "backout_plan": "n/a",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
        "group_id": group_id(app), "ci_id": str(ci_id),
    }, follow_redirects=True)
    assert change.status_code == 200
    assert b"CI owning team" in change.data
    assert b"Windows" in change.data

    incident = client.post("/tickets/new/incident", data={
        "title": "Owning team visibility on incident",
        "description": "Confirm the CI owning team renders on the incident body.",
        "category": "Network", "contact_type": "Phone", "notify": "Email",
        "impact": "Low", "urgency": "Low", "ci_id": str(ci_id),
        "group_id": group_id(app, "Network"),
    }, follow_redirects=True)
    assert incident.status_code == 200
    assert b'data-owning-team="Windows"' in incident.data


def test_comment_with_attachment_links_file_to_the_note(client, app):
    """A work note posted with a file should attach it to that comment
    directly, not just to the ticket's separate Attachments panel."""
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Comment attachment test", "description": "Attach a file to a work note",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Comment attachment test").one().id
    posted = client.post(f"/ticket/{ticket_id}", data={
        "action": "comment", "body": "See the attached log.",
        "file": (BytesIO(b"evidence bytes"), "evidence.log"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert posted.status_code == 200
    assert b"evidence.log" in posted.data
    with app.app_context():
        comment = Comment.query.filter_by(ticket_id=ticket_id).one()
        attachment = FileAttachment.query.filter_by(ticket_id=ticket_id).one()
        assert attachment.comment_id == comment.id
        assert attachment.original_name == "evidence.log"


def test_comment_without_file_does_not_touch_attachments(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Plain comment test", "description": "No file this time",
        "category": "Software", "priority": "P3",
        "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Plain comment test").one().id
    client.post(f"/ticket/{ticket_id}", data={
        "action": "comment", "body": "Just a note, no file.",
    }, follow_redirects=True)
    with app.app_context():
        assert FileAttachment.query.filter_by(ticket_id=ticket_id).count() == 0


def test_ticket_list_filters_by_priority_category_and_assignment_group(client, app):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "Unix disk cleanup", "description": "Filter target A",
        "category": "Hardware", "impact": "Critical", "urgency": "Critical",
        "group_id": group_id(app, "Unix"),
    })
    client.post("/tickets/new/incident", data={
        "title": "Windows login issue", "description": "Filter target B",
        "category": "Access", "impact": "Medium", "urgency": "Medium",
        "group_id": group_id(app, "Windows"),
    })

    def filter_url(conditions):
        return "/tickets/incident?filter=" + quote(json.dumps(conditions))

    by_priority = client.get(filter_url([{"field": "priority", "op": "eq", "value": "P1"}]))
    assert b"Unix disk cleanup" in by_priority.data
    assert b"Windows login issue" not in by_priority.data
    assert b"Priority is P1" in by_priority.data

    by_category = client.get(filter_url([{"field": "category", "op": "eq", "value": "Access"}]))
    assert b"Windows login issue" in by_category.data
    assert b"Unix disk cleanup" not in by_category.data

    with app.app_context():
        unix_id = SupportGroup.query.filter_by(name="Unix").one().id
    by_group = client.get(filter_url([{"field": "group", "op": "eq", "value": str(unix_id)}]))
    assert b"Unix disk cleanup" in by_group.data
    assert b"Windows login issue" not in by_group.data
    assert b"Assignment group is Unix" in by_group.data

    combined = client.get(filter_url([
        {"field": "priority", "op": "eq", "value": "P1"},
        {"field": "category", "op": "eq", "value": "Hardware"},
    ]))
    assert b"Unix disk cleanup" in combined.data
    assert b"Windows login issue" not in combined.data
    mismatched = client.get(filter_url([
        {"field": "priority", "op": "eq", "value": "P1"},
        {"field": "category", "op": "eq", "value": "Access"},
    ]))
    assert b"Unix disk cleanup" not in mismatched.data
    assert b"Windows login issue" not in mismatched.data

    contains = client.get(filter_url([{"field": "title", "op": "contains", "value": "disk"}]))
    assert b"Unix disk cleanup" in contains.data
    assert b"Windows login issue" not in contains.data


def test_module_records_list_supports_servicenow_style_filter(client, app):
    login(client)
    client.post("/module/problem/new", data={
        "record_type": "Root cause analysis",
        "title": "Filterable problem A", "description": "For filter coverage",
        "priority": "P1", "risk": "High",
    }, follow_redirects=True)
    client.post("/module/problem/new", data={
        "record_type": "Root cause analysis",
        "title": "Filterable problem B", "description": "For filter coverage",
        "priority": "P3", "risk": "Low",
    }, follow_redirects=True)

    filtered = client.get(
        "/module/problem?filter=" + quote(json.dumps(
            [{"field": "priority", "op": "eq", "value": "P1"}]
        ))
    )
    assert b"Filterable problem A" in filtered.data
    assert b"Filterable problem B" not in filtered.data
    assert b"Priority is P1" in filtered.data


def test_change_password_is_local_users_only(client, app):
    """Externally-provisioned (LDAP/SSO) accounts have no usable local
    password -- provision_external_user() stamps a random, never-shared
    hash -- so the in-app change-password flow must be hidden and blocked
    for them, while local accounts keep full access to it."""
    with app.app_context():
        external_user = provision_external_user(
            "ldap", "cn=bob,dc=example,dc=test", "bob", "Bob External",
            "bob@example.test", "agent",
        )
        db.session.commit()
        external_id = external_user.id
        assert user_is_local(external_user) is False
        admin = User.query.filter_by(username="admin").one()
        assert user_is_local(admin) is True

    with client.session_transaction() as sess:
        sess["_user_id"] = str(external_id)
        sess["_fresh"] = True
        sess["_auth_version"] = 1
    blocked = client.get("/profile/password")
    assert blocked.status_code == 403
    own_profile = client.get("/profile")
    assert b"Change password" not in own_profile.data
    client.get("/logout")

    login(client)
    allowed = client.get("/profile/password")
    assert allowed.status_code == 200
    own_admin_profile = client.get("/profile")
    assert b"Change password" in own_admin_profile.data


def test_cmdb_list_supports_servicenow_style_filter(client, app):
    with app.app_context():
        windows = SupportGroup.query.filter_by(name="Windows").one()
        db.session.add(ConfigurationItem(
            name="cmdb-filter-prod.example.com", ci_class="Server",
            environment="Production", business_criticality="Critical",
            support_group_id=windows.id,
        ))
        db.session.add(ConfigurationItem(
            name="cmdb-filter-dev.example.com", ci_class="Server",
            environment="Development", business_criticality="Low",
        ))
        db.session.commit()
        windows_id = windows.id
    login(client)

    by_env = client.get("/cmdb?filter=" + quote(json.dumps(
        [{"field": "environment", "op": "eq", "value": "Production"}]
    )))
    assert b"cmdb-filter-prod.example.com" in by_env.data
    assert b"cmdb-filter-dev.example.com" not in by_env.data
    assert b"Environment is Production" in by_env.data

    by_team = client.get("/cmdb?filter=" + quote(json.dumps(
        [{"field": "support_group_id", "op": "eq", "value": str(windows_id)}]
    )))
    assert b"cmdb-filter-prod.example.com" in by_team.data
    assert b"cmdb-filter-dev.example.com" not in by_team.data
    assert b"Owning team is Windows" in by_team.data


def test_users_list_supports_servicenow_style_filter(client, app):
    login(client)
    with app.app_context():
        db.session.add(User(
            username="filter.manager", name="Filter Manager", email="filter.manager@test.invalid",
            password_hash=generate_password_hash("Manager123!"), role="manager", department="Ops",
        ))
        db.session.commit()

    filtered = client.get("/admin/users?filter=" + quote(json.dumps(
        [{"field": "role", "op": "eq", "value": "manager"}]
    )))
    assert b"filter.manager" in filtered.data
    assert b"Role is manager" in filtered.data


def test_assets_list_supports_servicenow_style_filter(client, app):
    login(client)
    with app.app_context():
        db.session.add(Asset(asset_tag="AST-100", name="Filter laptop", asset_type="Laptop", status="In use"))
        db.session.add(Asset(asset_tag="AST-101", name="Filter server", asset_type="Server", status="Retired"))
        db.session.commit()

    filtered = client.get("/assets?filter=" + quote(json.dumps(
        [{"field": "status", "op": "eq", "value": "Retired"}]
    )))
    assert b"AST-101" in filtered.data
    assert b"AST-100" not in filtered.data
    assert b"Status is Retired" in filtered.data


def test_module_records_searchable_by_imported_source_ticket_number(client, app):
    """RT (or any future external source) imports stamp external_id on the
    EnterpriseRecord -- staff who only know the original RT ticket number
    must still be able to find the record by it."""
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(EnterpriseRecord(
            number="EVT0009999", domain="event", record_type="RT Ticket",
            title="Imported from RT", description="Imported from RT",
            requester_id=admin.id, external_source="rt", external_id="48055",
        ))
        db.session.commit()

    found = client.get("/module/event?q=48055")
    assert b"Imported from RT" in found.data
    with app.app_context():
        detail_id = EnterpriseRecord.query.filter_by(external_id="48055").one().id
    detail = client.get(f"/enterprise/{detail_id}")
    assert b"RT #48055" in detail.data


def test_unhandled_exception_is_logged_and_shows_error_page_not_a_raw_500(client, app):
    """"Every error must be recorded": an unhandled exception in a route
    must (a) never leak a raw Werkzeug traceback page to the user, and (b)
    be persisted to ApplicationLog by the DatabaseLogHandler attached to
    app.logger, visible on System Health without shell access."""
    login(client)
    with app.app_context():
        before = ApplicationLog.query.count()

    # tenant_context_id() is patched to explode on its first call only --
    # the cleanest way to force a genuine unhandled exception through a
    # real authenticated route without adding a test-only crash endpoint to
    # production code. Only the first call because error.html's own
    # rendering goes through ui_context(), which also calls
    # tenant_context_id() (via tenant_query) -- a patch that always raises
    # would break the error page's own rendering too, not just the route
    # that crashed.
    import app as app_module
    original = app_module.tenant_context_id
    state = {"calls": 0}

    def flaky():
        state["calls"] += 1
        if state["calls"] == 1:
            raise RuntimeError("forced crash for test")
        return original()

    app_module.tenant_context_id = flaky
    try:
        response = client.get("/tickets/incident")
    finally:
        app_module.tenant_context_id = original

    assert response.status_code == 500
    assert b"unexpected error occurred" in response.data
    assert b"Traceback" not in response.data
    with app.app_context():
        after = ApplicationLog.query.count()
        assert after == before + 1
        row = ApplicationLog.query.order_by(ApplicationLog.id.desc()).first()
        assert row.level == "ERROR"
        assert "forced crash for test" in row.traceback
        assert row.path == "/tickets/incident"


def test_system_health_shows_active_users_and_recorded_errors(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(ApplicationLog(
            level="ERROR", message="Something broke in a background job",
            path="/some/path", method="GET", tenant_id=admin.tenant_id,
        ))
        db.session.commit()

    response = client.get("/admin/system-health")
    assert response.status_code == 200
    assert b"Something broke in a background job" in response.data
    assert b"Currently active users" in response.data
    # The logged-in admin making this very request updates their own
    # last_seen_at via track_last_seen before the route runs.
    assert b"admin" in response.data


def test_system_health_is_admin_only(client):
    login(client, "employee", "Employee123!")
    assert client.get("/admin/system-health").status_code == 403


def test_system_health_log_viewer_handles_missing_log_dir_gracefully(client):
    login(client)
    response = client.get("/admin/system-health/logs")
    assert response.status_code == 200
    assert b"No detailed log file is available" in response.data


def test_system_health_errors_export_csv_and_json(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(ApplicationLog(
            level="ERROR", message="Export me please", logger_name="app",
            path="/exportable/path", method="GET", tenant_id=admin.tenant_id,
        ))
        db.session.commit()

    csv_response = client.get("/admin/system-health/errors/export?format=csv")
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"
    assert b"Export me please" in csv_response.data
    assert "attachment" in csv_response.headers["Content-Disposition"]

    json_response = client.get("/admin/system-health/errors/export?format=json")
    assert json_response.status_code == 200
    assert json_response.mimetype == "application/json"
    payload = json.loads(json_response.data)
    assert any(row["message"] == "Export me please" for row in payload)

    ndjson_response = client.get("/admin/system-health/errors/export?format=ndjson")
    assert ndjson_response.status_code == 200
    assert ndjson_response.mimetype == "application/x-ndjson"

    txt_response = client.get("/admin/system-health/errors/export?format=txt")
    assert txt_response.status_code == 200
    assert txt_response.mimetype == "text/plain"
    assert b"Export me please" in txt_response.data


def test_system_health_errors_export_is_admin_only(client):
    login(client, "employee", "Employee123!")
    assert client.get("/admin/system-health/errors/export").status_code == 403


def test_system_health_error_filters_narrow_results(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(ApplicationLog(
            level="ERROR", message="alpha failure", logger_name="app.alpha",
            path="/alpha", method="GET", tenant_id=admin.tenant_id,
        ))
        db.session.add(ApplicationLog(
            level="WARNING", message="beta warning", logger_name="app.beta",
            path="/beta", method="POST", tenant_id=admin.tenant_id,
        ))
        db.session.commit()

    only_alpha = client.get("/admin/system-health?logger=alpha")
    assert b"alpha failure" in only_alpha.data
    assert b"beta warning" not in only_alpha.data

    only_beta_path = client.get("/admin/system-health?path=/beta")
    assert b"beta warning" in only_beta_path.data
    assert b"alpha failure" not in only_beta_path.data

    level_only_warning = client.get("/admin/system-health?level=WARNING")
    assert b"beta warning" in level_only_warning.data
    assert b"alpha failure" not in level_only_warning.data


def test_system_health_log_file_export_and_filters(client, tmp_path, monkeypatch):
    login(client)
    log_file = tmp_path / "serviceops.json.log"
    log_file.write_text(
        json.dumps({
            "timestamp": "2026-08-04T00:00:00+00:00", "level": "INFO", "logger": "serviceops.request",
            "message": "request completed", "path": "/tickets", "method": "GET", "status_code": 200,
        }) + "\n" +
        json.dumps({
            "timestamp": "2026-08-04T00:05:00+00:00", "level": "ERROR", "logger": "app",
            "message": "boom", "path": "/tickets/new", "method": "POST", "status_code": 500,
        }) + "\n"
    )
    monkeypatch.setenv("LOG_DIR", str(tmp_path))

    all_lines = client.get("/admin/system-health/logs")
    assert all_lines.status_code == 200
    assert b"request completed" in all_lines.data
    assert b"boom" in all_lines.data

    only_errors = client.get("/admin/system-health/logs?level=ERROR")
    assert b"boom" in only_errors.data
    assert b"request completed" not in only_errors.data

    only_post = client.get("/admin/system-health/logs?method=POST")
    assert b"boom" in only_post.data
    assert b"request completed" not in only_post.data

    export_response = client.get("/admin/system-health/logs/export?format=ndjson")
    assert export_response.status_code == 200
    assert export_response.mimetype == "application/x-ndjson"
    assert b"boom" in export_response.data

    export_csv = client.get("/admin/system-health/logs/export?format=csv&level=ERROR")
    assert export_csv.status_code == 200
    assert b"boom" in export_csv.data
    assert b"request completed" not in export_csv.data


def test_system_health_log_file_export_is_admin_only(client):
    login(client, "employee", "Employee123!")
    assert client.get("/admin/system-health/logs/export").status_code == 403


def test_sign_out_button_is_clearly_labeled(client):
    login(client)
    response = client.get("/")
    assert b"Sign out" in response.data


def test_role_switcher_shown_only_for_multi_role_users(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(UserRoleGrant(user_id=admin.id, role="agent"))
        db.session.commit()

    login(client)
    response = client.get("/")
    assert b"Switch your active role" in response.data
    assert b"Acting as" in response.data
    assert b"Admin</strong>" in response.data
