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
                 ClientContact, ClientOrganization, ClientOrganizationAccess, ClientCustomFieldDefinition,
                 ClientView, ClientMacro, ClientTrigger, ClientMailbox, ClientTicket, ClientTicketMessage,
                 Comment,
                 ChecklistItem, CIRelationship, CiClassPermission, ConfigurationItem, DiscoveryCandidate, DiscoveryTarget,
                 EnterpriseRecord, CatalogItem,
                 CatalogItemRouting, DirectoryGroupMapping,
                 DirectoryManagedMembership, ExternalIdentity, Favorite, FileAttachment,
                 GroupMember, IntegrationConnection, IntegrationDelivery, Knowledge,
                 MonitoringEvent, MonitoringSource, Notification, MobilePushDevice, OperationalTask,
                 OutboxEvent, ProblemProfile, Rack, RecordLink, RolePolicyOverride, ScheduleHoliday, SLADefinition,
                 RequestedItem, PlatformSetting, ServiceOffering, ServiceOfferingCI, SupportGroup, SupportGroupAlias,
                 TaskCI, TaskHistory, TaskNote, TaskSLA,
                 Tenant, Ticket, TicketAssignmentGroup, User, UserPreference, UserRoleGrant, ManagedRoleGrant,
                 ApplicationLog,
                 PasskeyChallenge, PasskeyCredential,
                 create_ticket_with_unique_number, create_with_retry_on_number_collision, next_number,
                 WorkflowDefinition, WorkflowExecution, WorkflowJob,
                 WorkflowSchedule,
                 audit, change_approval_stages, create_api_token, create_app, create_notification, db,
                 deploy_workflow_package, find_and_merge_duplicate_groups, ldap_authenticate,
                 mapped_roles, merge_support_group_into, normalize_environment, now, process_discovery_schedule,
                 process_client_escalation_policies,
                 process_workflow_jobs,
                 recompute_base_role,
                 process_workflow_schedules, queue_workflow_event,
                 scan_attachment, simulate_workflows,
                 integration_endpoint_valid, integration_endpoint_resolves_safely,
                 is_safe_internal_path, process_outbox,
                 provision_external_user, secret_value, settings_cipher, user_is_local,
                 rotate_audit_integrity_key, tenant_context_id, TenantResolutionError,
                 user_can_manage_ticket, user_in_group, user_can_manage_ritm,
                 verify_audit_chain)
from werkzeug.security import generate_password_hash
from serviceops_core.security import role_has_action, validate_policy
from serviceops_core.ci_class_policy import managed_ci_classes
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
    readiness = client.get("/ready")
    assert readiness.status_code == 503
    assert readiness.json["status"] == "not_ready"
    assert readiness.json["checks"]["database"]["ok"] is True


def test_health_degrades_gracefully_on_a_database_outage(client, app, monkeypatch):
    """Found via real failure-injection load testing (B-071): a database
    outage previously made /health raise an unhandled OperationalError into
    a generic 500 rather than a clean, structured unhealthy response --
    noisy (a full stack trace logged on every poll) and indistinguishable
    from a real application bug on the same endpoint Docker's own container
    healthcheck polls (see compose.yaml)."""
    from app import APP_VERSION, db

    def broken_execute(*args, **kwargs):
        raise Exception("simulated database outage")

    with app.app_context():
        monkeypatch.setattr(db.session, "execute", broken_execute)
        response = client.get("/health")
    assert response.status_code == 503
    assert response.json == {"status": "unhealthy", "version": APP_VERSION}


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


def test_no_template_uses_an_inline_event_handler_blocked_by_csp():
    """Regression test for a real bug found during live verification: a
    confirmation dialog on a delete/destructive form used an inline
    onsubmit="return confirm(...)" attribute, which this app's own CSP
    (script-src 'self', no 'unsafe-inline') silently blocks -- the browser
    just submits the form immediately with no prompt, exactly the same
    class of bug the print-button fix (see platform.js's data-print-page
    listener) already fixed once for a different attribute. Confirmation
    prompts must use the data-confirm attribute (handled by a delegated
    listener in platform.js, or the button+formaction variant in
    discovery.js) instead. This scans every shipped template so a future
    inline handler is caught here rather than only by a live browser check."""
    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    offenders = []
    inline_handler = re.compile(r'\bon[a-z]+\s*=\s*["\']', re.IGNORECASE)
    for name in os.listdir(templates_dir):
        if not name.endswith(".html"):
            continue
        with open(os.path.join(templates_dir, name), encoding="utf-8") as handle:
            content = handle.read()
        if inline_handler.search(content):
            offenders.append(name)
    assert offenders == []


def test_csrf_token_survives_a_validation_error_resubmit_on_the_same_page():
    """Regression test for a real reported bug: a form that re-renders
    itself with a 4xx status on server-side validation failure (e.g. a
    change rejected for falling inside a freeze window) previously came
    back with NO _csrf_token field at all -- inject_csrf only ever embedded
    one into responses with status_code < 400. A user who edited the form
    and resubmitted from that same error page (without a fresh page load)
    then hit "The security token is missing or expired," even though
    nothing about their session had actually changed. The fix: inject_csrf
    no longer gates on status code."""
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
    csrf_client.post("/login", data={
        "username": "admin", "password": "Admin123!", "_csrf_token": token,
    })
    group = group_id(csrf_app, "Network")
    invalid_submit = csrf_client.post("/tickets/new/incident", data={
        "title": "Test incident", "description": "x", "category": "Network",
        "subcategory": "x", "contact_type": "Not-a-real-contact-type",
        "notify": "Email", "impact": "High", "urgency": "High", "group_id": str(group),
    }, headers={"X-CSRF-Token": token})
    assert invalid_submit.status_code == 400
    retry_token_match = re.search(
        rb'name="_csrf_token" value="([^"]+)"', invalid_submit.data
    )
    assert retry_token_match is not None, (
        "the re-rendered error page must embed a usable CSRF token so the "
        "user's very next resubmit from the same page doesn't fail"
    )
    retry_token = retry_token_match.group(1).decode()
    fixed_submit = csrf_client.post("/tickets/new/incident", data={
        "title": "Test incident", "description": "x", "category": "Network",
        "subcategory": "x", "contact_type": "Self-service",
        "notify": "Email", "impact": "High", "urgency": "High", "group_id": str(group),
        "_csrf_token": retry_token,
    })
    assert fixed_submit.status_code == 302
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


def test_session_hours_setting_actually_controls_session_lifetime():
    """Real bug found during a misleading-UI audit: SESSION_HOURS was
    defined and shown as an editable "Session lifetime in hours" setting
    on Platform Settings, but nothing ever read it -- session lifetime
    was purely env-var driven (SESSION_LIFETIME_MINUTES), so saving this
    setting had zero effect. Verifies the fix across a real create_app()
    boot, not just a unit-level check, since the wiring lives in create_app()'s
    post-migration settings re-read."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    database_uri = f"sqlite:///{path}"
    first_app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": database_uri})
    with first_app.app_context():
        db.session.add(PlatformSetting(key="SESSION_HOURS", value="2", encrypted=False))
        db.session.commit()

    second_app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": database_uri})
    assert second_app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(hours=2)
    os.unlink(path)


def test_default_density_setting_applies_to_new_user_preferences(client, app):
    """Companion finding from the same audit: DEFAULT_DENSITY was shown as
    configurable but every new UserPreference row got "comfortable" from
    the model column's own hardcoded default regardless of this setting."""
    with app.app_context():
        db.session.add(PlatformSetting(key="DEFAULT_DENSITY", value="compact", encrypted=False))
        db.session.commit()
    login(client, username="employee", password="Employee123!")
    client.get("/")  # triggers ui_context()'s lazy UserPreference creation
    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        pref = UserPreference.query.filter_by(user_id=employee.id).one()
        assert pref.density == "compact"


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


def test_audit_verify_degrades_gracefully_when_a_signing_key_is_undecryptable(client, app):
    """Found via a real recovery-rehearsal run against a long-lived dev
    database (B-009/B-004): an audit event signed under a key whose
    secret_encrypted no longer decrypts with the current
    SETTINGS_ENCRYPTION_KEY (e.g. the environment's encryption key was
    regenerated at some point, an unrecoverable but real condition) used to
    crash /admin/audit?verify=1 and the recovery_verify.py CLI entirely
    with an unhandled cryptography.fernet.InvalidToken. It must instead be
    reported as an unverified/invalid chain -- correct tamper-evidence
    semantics -- not silently ignored and not a 500."""
    from cryptography.fernet import Fernet as _Fernet

    login(client)  # writes an audit event signed under the environment-v1 key
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        # Rotating persists an "environment-v1" AuditIntegrityKey row for
        # the first time (previously it only existed as an env-var fallback,
        # never stored) -- needed so there's a real row to corrupt below.
        rotate_audit_integrity_key(admin.tenant_id, admin.id)
        db.session.commit()
        row = AuditIntegrityKey.query.filter_by(
            tenant_id=admin.tenant_id, key_id="environment-v1"
        ).one()
        # Encrypted under a different, unrelated key -- simulates the real
        # condition found in the rehearsal: the current SETTINGS_ENCRYPTION_KEY
        # no longer matches whatever key this row was actually encrypted under.
        row.secret_encrypted = _Fernet(_Fernet.generate_key()).encrypt(b"wrong-key-entirely").decode()
        db.session.commit()
        tenant_id = admin.tenant_id

    response = client.get("/admin/audit?verify=1")
    assert response.status_code == 200
    assert b"FAILED" in response.data
    with app.app_context():
        result = verify_audit_chain(tenant_id)
        assert result["valid"] is False
        assert "could not be decrypted" in result["reason"]


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


def test_mobile_user_authentication_audit_attribution_and_revocation(client, app):
    mobile_headers = {
        "X-ServiceOps-App-Version": "1.1.0",
        "X-ServiceOps-App-Build": "42",
        "X-ServiceOps-Platform": "iOS",
        "X-ServiceOps-Device": "iPhone17,1",
    }
    missing_metadata = client.post("/api/v1/auth/mobile/login", json={
        "username": "admin", "password": "Admin123!", "provider": "local",
    })
    assert missing_metadata.status_code == 400
    signed_in = client.post("/api/v1/auth/mobile/login", headers=mobile_headers, json={
        "username": "admin", "password": "Admin123!", "provider": "local",
    })
    assert signed_in.status_code == 200
    assert signed_in.json["access_token"].startswith("som_")
    assert signed_in.json["refresh_token"].startswith("sor_")
    access = signed_in.json["access_token"]
    listed = client.get("/api/v1/tickets", headers={"Authorization": f"Bearer {access}"})
    assert listed.status_code == 200
    with app.app_context():
        login_audit = Audit.query.filter_by(action="mobile login").one()
        assert login_audit.user.username == "admin"
        assert "channel=mobile" in login_audit.details
        assert "app_version=1.1.0" in login_audit.details
        assert "app_build=42" in login_audit.details
        assert "device=iPhone17,1" in login_audit.details
    refreshed = client.post("/api/v1/auth/mobile/refresh", json={
        "refresh_token": signed_in.json["refresh_token"],
    })
    assert refreshed.status_code == 200
    assert client.get("/api/v1/tickets", headers={"Authorization": f"Bearer {access}"}).status_code == 401
    new_access = refreshed.json["access_token"]
    assert client.post("/api/v1/auth/mobile/logout", headers={
        "Authorization": f"Bearer {new_access}",
    }).status_code == 204
    assert client.get("/api/v1/tickets", headers={"Authorization": f"Bearer {new_access}"}).status_code == 401


def test_mobile_ticket_attachments_list_metadata_download_and_tenant_isolation(client, app):
    mobile_headers = {
        "X-ServiceOps-App-Version": "1.3.2", "X-ServiceOps-App-Build": "8",
        "X-ServiceOps-Platform": "iOS", "X-ServiceOps-Device": "iPhone17,1",
    }
    signed_in = client.post("/api/v1/auth/mobile/login", headers=mobile_headers, json={
        "username": "admin", "password": "Admin123!", "provider": "local",
    })
    assert signed_in.status_code == 200
    headers = {"Authorization": f"Bearer {signed_in.json['access_token']}"}
    content = b"%PDF-1.4\nServiceOps mobile attachment test\n%%EOF\n"
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ticket = Ticket(
            number="INC9999997", kind="incident", title="Mobile attachment ticket",
            description="Attachment API contract test", category="Software",
            priority="P3", state="New", requester_id=admin.id, tenant_id=admin.tenant_id,
        )
        db.session.add(ticket)
        db.session.flush()
        stored_name = f"mobile-{uuid.uuid4().hex}.pdf"
        with open(os.path.join(app.config["UPLOAD_FOLDER"], stored_name), "wb") as handle:
            handle.write(content)
        attachment = FileAttachment(
            ticket_id=ticket.id, uploaded_by_id=admin.id,
            original_name="change-plan.pdf", stored_name=stored_name,
            mime_type="application/pdf", size_bytes=len(content),
            scan_status="clean", tenant_id=ticket.tenant_id,
        )
        db.session.add(attachment)
        db.session.commit()
        number, attachment_id = ticket.number, attachment.id

        other_tenant = Tenant(slug="attachment-isolation", name="Attachment isolation tenant")
        db.session.add(other_tenant)
        db.session.flush()
        other_user = User(
            username="attachment.other", name="Other tenant user",
            email="attachment.other@test.invalid", password_hash=generate_password_hash("Other123!"),
            role="admin", tenant_id=other_tenant.id,
        )
        db.session.add(other_user)
        db.session.flush()
        hidden_ticket = Ticket(
            number="INC9999998", kind="incident", title="Hidden attachment ticket",
            description="Must remain tenant isolated", requester_id=other_user.id,
            tenant_id=other_tenant.id,
        )
        db.session.add(hidden_ticket)
        db.session.commit()

    assert client.get(f"/api/v1/tickets/{number}/attachments").status_code == 401
    listed = client.get(f"/api/v1/tickets/{number}/attachments", headers=headers)
    assert listed.status_code == 200
    assert listed.json["meta"]["count"] == 1
    metadata = listed.json["data"][0]
    assert metadata == {
        "id": attachment_id,
        "fileName": "change-plan.pdf",
        "contentType": "application/pdf",
        "byteSize": len(content),
        "createdAt": metadata["createdAt"],
        "downloadURL": f"/api/v1/tickets/{number}/attachments/{attachment_id}/download",
    }
    ticket_payload = client.get(f"/api/v1/tickets/{number}", headers=headers)
    assert ticket_payload.json["data"]["attachments"] == [metadata]
    alias = client.get(f"/api/v1/mobile/tickets/{number}/attachments", headers=headers)
    assert alias.json["data"] == [metadata]

    downloaded = client.get(metadata["downloadURL"], headers=headers)
    assert downloaded.status_code == 200
    assert downloaded.data == content
    assert downloaded.mimetype == "application/pdf"
    assert "inline" in downloaded.headers["Content-Disposition"]
    assert downloaded.headers["Cache-Control"] == "private, no-store"
    assert client.get(
        f"/api/v1/tickets/{number}/attachments/{attachment_id + 1000}/download", headers=headers,
    ).status_code == 404
    assert client.get("/api/v1/tickets/INC9999998/attachments", headers=headers).status_code == 404


def test_mobile_app_users_appear_in_system_health_active_users(client, app):
    """User-reported: the iOS app's users never showed up on System Health
    -> Active users. Confirmed root cause: authenticate_api_request()
    (the bearer-token path every /api/v1/ mobile request goes through)
    never touched User.last_seen_at -- only the browser-session
    track_last_seen() hook did, and mobile auth never calls
    Flask-Login's login_user(), so current_user.is_authenticated was
    always False for mobile requests and that hook never ran either."""
    mobile_headers = {
        "X-ServiceOps-App-Version": "1.1.0", "X-ServiceOps-App-Build": "42",
        "X-ServiceOps-Platform": "iOS", "X-ServiceOps-Device": "iPhone17,1",
    }
    signed_in = client.post("/api/v1/auth/mobile/login", headers=mobile_headers, json={
        "username": "admin", "password": "Admin123!", "provider": "local",
    })
    access = signed_in.json["access_token"]
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        assert admin.last_seen_at is None

    assert client.get("/api/v1/tickets", headers={"Authorization": f"Bearer {access}"}).status_code == 200
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        assert admin.last_seen_at is not None

    login(client)
    health = client.get("/admin/system-health")
    assert health.status_code == 200
    assert b"System Administrator" in health.data
    assert b">Mobile<" in health.data


def test_mobile_workspace_push_inbox_knowledge_and_cmdb_are_user_scoped(client, app):
    mobile_headers = {
        "X-ServiceOps-App-Version": "1.3.0", "X-ServiceOps-App-Build": "5",
        "X-ServiceOps-Platform": "iOS", "X-ServiceOps-Device": "iPhone17,1",
    }
    signed_in = client.post("/api/v1/auth/mobile/login", headers=mobile_headers, json={
        "username": "admin", "password": "Admin123!", "provider": "local",
    })
    assert signed_in.status_code == 200
    headers = {"Authorization": f"Bearer {signed_in.json['access_token']}"}
    bootstrap = client.get("/api/v1/mobile/bootstrap", headers=headers)
    assert bootstrap.status_code == 200
    assert bootstrap.json["data"]["user"]["username"] == "admin"
    assert bootstrap.json["data"]["assignment_groups"]

    token = "ab" * 32
    registered = client.post("/api/v1/mobile/push-devices", headers=headers, json={
        "token": token, "device_id": "test-device", "environment": "sandbox",
    })
    assert registered.status_code == 201
    with app.app_context():
        device = MobilePushDevice.query.one()
        assert device.token_hash != token
        assert settings_cipher().decrypt(device.token_encrypted.encode()).decode() == token
        admin = User.query.filter_by(username="admin").one()
        create_notification(admin.id, "Mobile test", "Open the record", admin.tenant_id,
                            target_type="ticket", target_id=1)
        db.session.commit()

    inbox = client.get("/api/v1/mobile/notifications", headers=headers)
    assert inbox.status_code == 200
    notification_id = inbox.json["data"][0]["id"]
    assert client.post(f"/api/v1/mobile/notifications/{notification_id}/read", headers=headers).status_code == 200
    assert client.get("/api/v1/mobile/knowledge?q=VPN", headers=headers).status_code == 200
    assert client.get("/api/v1/mobile/cmdb?q=core", headers=headers).status_code == 200
    assert client.delete("/api/v1/mobile/push-devices/test-device", headers=headers).status_code == 204
    with app.app_context():
        assert MobilePushDevice.query.one().enabled is False


def test_passkey_options_require_https_configuration(client):
    response = client.post("/api/v1/auth/passkeys/authenticate/options")
    assert response.status_code == 503
    assert "HTTPS" in response.get_data(as_text=True)


def test_passkey_authentication_is_user_attributed_and_challenge_is_single_use(client, app, monkeypatch):
    import base64
    from types import SimpleNamespace
    import app as app_module

    monkeypatch.setenv("WEBAUTHN_RP_ID", "serviceops.example.com")
    monkeypatch.setenv("WEBAUTHN_ORIGIN", "https://serviceops.example.com")
    mobile_headers = {
        "X-ServiceOps-App-Version": "1.2.0",
        "X-ServiceOps-App-Build": "50",
        "X-ServiceOps-Platform": "iOS",
        "X-ServiceOps-Device": "iPhone17,1",
    }
    credential_id = b"test-passkey-credential"
    encoded_id = base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode()
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(PasskeyCredential(
            credential_id=credential_id, public_key=b"test-public-key", sign_count=1,
            name="Test passkey", user_id=admin.id, tenant_id=admin.tenant_id,
        ))
        db.session.commit()

    options = client.post("/api/v1/auth/passkeys/authenticate/options")
    assert options.status_code == 200
    challenge_id = options.json["challenge_id"]
    monkeypatch.setattr(
        app_module, "verify_passkey_authentication",
        lambda **kwargs: SimpleNamespace(new_sign_count=2),
    )
    payload = {
        "challenge_id": challenge_id,
        "credential": {"id": encoded_id, "rawId": encoded_id, "type": "public-key", "response": {}},
    }
    signed_in = client.post(
        "/api/v1/auth/passkeys/authenticate/complete", headers=mobile_headers, json=payload,
    )
    assert signed_in.status_code == 200
    assert signed_in.json["access_token"].startswith("som_")
    assert client.post(
        "/api/v1/auth/passkeys/authenticate/complete", headers=mobile_headers, json=payload,
    ).status_code == 400
    with app.app_context():
        credential = PasskeyCredential.query.filter_by(credential_id=credential_id).one()
        passkey_id = credential.id
        assert credential.sign_count == 2
        assert PasskeyChallenge.query.filter_by(id=challenge_id).first() is None
        audit_row = Audit.query.filter_by(action="mobile login").one()
        assert audit_row.user.username == "admin"
        assert "authentication=passkey" in audit_row.details
    bearer = {"Authorization": f"Bearer {signed_in.json['access_token']}"}
    listed = client.get("/api/v1/auth/passkeys", headers=bearer)
    assert listed.status_code == 200
    assert listed.json["data"][0]["name"] == "Test passkey"
    assert client.delete(f"/api/v1/auth/passkeys/{passkey_id}", headers=bearer).status_code == 204
    assert client.get("/api/v1/auth/passkeys", headers=bearer).json["data"] == []
    with app.app_context():
        assert PasskeyCredential.query.filter_by(id=passkey_id).first() is None
        assert Audit.query.filter_by(action="passkey revoked").one().user.username == "admin"


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
    assert {icon["sizes"] for icon in manifest.json["icons"]} == {"192x192", "512x512"}
    assert all("serviceops-icon" in icon["src"] for icon in manifest.json["icons"])
    worker = client.get("/service-worker.js")
    assert worker.status_code == 200
    assert b"/api/" not in worker.data
    assert b"/ticket/" not in worker.data
    assert b"caches.open" in worker.data
    from app import APP_VERSION
    assert f"serviceops-shell-v{APP_VERSION}".encode() in worker.data
    assert f"/static/itil.css?v={APP_VERSION}".encode() in worker.data
    assert f"/static/icons/serviceops-icon-192.png?v={APP_VERSION}".encode() in worker.data
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
    assert b'<a class="skip-link" href="#main-content">' in response.data
    assert b'<main id="main-content" tabindex="-1"' in response.data
    assert b'aria-expanded="true"' in response.data
    assert b'aria-modal="true" aria-labelledby="ci-browser-title"' in response.data


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
            group_id=other_group.id, user_id=other_user.id, role="manager", tenant_id=2,
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


def test_dependent_tables_carry_their_own_tenant_id_and_stay_isolated(client, app):
    """Comment/GroupMember/CatalogItemRouting/RequestedItem/CatalogTask/
    FileAttachment/the legacy Approval model previously had no tenant_id of
    their own and relied entirely on every query site remembering to join
    back to their tenant-owning parent -- this exercises both halves of the
    fix: the column is populated correctly on creation, and the two real
    cross-tenant authorization gaps found while auditing this (admin's
    unconditional bypass in user_can_manage_ticket/user_can_manage_ritm/
    user_in_group/user_can_manage_enterprise_record not checking tenant)
    are actually closed."""
    with app.app_context():
        other_tenant = Tenant(id=2, slug="other2", name="Other organisation 2")
        other_user = User(
            username="other.admin", name="Other Admin", email="otheradmin@test.invalid",
            password_hash=generate_password_hash("OtherTenant123!"),
            role="admin", tenant_id=2,
        )
        db.session.add_all([other_tenant, other_user])
        db.session.flush()
        other_group = SupportGroup(
            name="Other Fulfillment", group_type="IT Fulfillment", tenant_id=2,
        )
        db.session.add(other_group)
        db.session.flush()
        other_ticket = Ticket(
            number="INC9000002", kind="incident", title="Other tenant ticket for comments",
            description="x", requester_id=other_user.id, tenant_id=2,
        )
        db.session.add(other_ticket)
        db.session.flush()
        other_comment = Comment(
            ticket_id=other_ticket.id, user_id=other_user.id, body="Private comment",
            tenant_id=2,
        )
        other_item = CatalogItem(
            name="Other tenant private item", category="Private",
            description="x", delivery_days=1, active=True, tenant_id=2,
        )
        db.session.add_all([other_comment, other_item])
        db.session.flush()
        other_routing = CatalogItemRouting(
            catalog_item_id=other_item.id, support_group_id=other_group.id, tenant_id=2,
        )
        other_request = CatalogRequest(
            number="REQ9000002", requested_by_id=other_user.id, requested_for_id=other_user.id,
            tenant_id=2,
        )
        db.session.add_all([other_routing, other_request])
        db.session.flush()
        other_ritm = RequestedItem(
            number="RITM9000002", request_id=other_request.id, catalog_item_id=other_item.id,
            tenant_id=2,
        )
        db.session.add(other_ritm)
        db.session.flush()
        other_task = CatalogTask(
            number="SCTASK9000002", requested_item_id=other_ritm.id, title="Fulfill",
            assignment_group_id=other_group.id, tenant_id=2,
        )
        other_attachment = FileAttachment(
            ticket_id=other_ticket.id, uploaded_by_id=other_user.id,
            original_name="secret.txt", stored_name="secret-stored.txt",
            size_bytes=3, tenant_id=2,
        )
        db.session.add_all([other_task, other_attachment])
        db.session.commit()

        assert other_comment.tenant_id == 2
        assert other_routing.tenant_id == 2
        assert other_ritm.tenant_id == 2
        assert other_task.tenant_id == 2
        assert other_attachment.tenant_id == 2

        other_group_id = other_group.id
        other_ritm_id = other_ritm.id
        other_task_id = other_task.id
        admin = User.query.filter_by(username="admin").one()
        # admin here is tenant 1 -- these authorization helpers must reject
        # managing tenant 2's records even though the role check alone
        # (role == "admin") would otherwise short-circuit to True.
        assert user_can_manage_ticket(admin, other_ticket) is False
        assert user_in_group(admin, other_group) is False
        assert user_can_manage_ritm(admin, other_ritm) is False

    login(client)
    # A tenant-1 admin must not be able to add a catalog task to tenant 2's
    # RITM, or update/view tenant 2's catalog task, by guessing ids.
    assert client.post(f"/ritm/{other_ritm_id}/tasks", data={
        "title": "Cross-tenant task", "group_id": str(other_group_id),
    }).status_code == 403
    assert client.get(f"/catalog-task/{other_task_id}").status_code == 403
    assert client.post(f"/catalog-task/{other_task_id}", data={
        "state": "In Progress",
    }).status_code == 403


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


def test_ci_edit_preserves_discovered_attributes_not_shown_in_the_editable_form(client, app):
    # B-287: interfaces/lldp_neighbors/etc. moved out of the editable
    # "Additional imported fields" rows into their own read-only panel
    # (ci_form.html) -- but the CI edit POST handler must still merge them
    # back into ci.attributes rather than silently wiping them out just
    # because they're no longer submitted as attr_key/attr_value pairs.
    login(client)
    with app.app_context():
        ci = ConfigurationItem(
            name="switch-01", ci_class="Network Switch", tenant_id=1,
            discovery_source="SNMP Discovery",
            attributes={
                "sys_descr": "Arista EOS", "interfaces": [{"index": "1", "descr": "Eth1"}],
                "lldp_neighbors": [{"neighbor_name": "switch-02", "neighbor_port": "Eth2"}],
                "cpu_notes": "dual-socket",
            },
        )
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id

    client.post(f"/cmdb/{ci_id}/edit", data={
        "name": "switch-01", "ci_class": "Network Switch", "environment": "Production",
        "operational_status": "Operational",
        "attr_key": ["cpu_notes"], "attr_value": ["dual-socket, upgraded"],
    }, follow_redirects=True)

    with app.app_context():
        ci = db.session.get(ConfigurationItem, ci_id)
        assert ci.attributes["sys_descr"] == "Arista EOS"
        assert ci.attributes["interfaces"] == [{"index": "1", "descr": "Eth1"}]
        assert ci.attributes["lldp_neighbors"] == [{"neighbor_name": "switch-02", "neighbor_port": "Eth2"}]
        assert ci.attributes["cpu_notes"] == "dual-socket, upgraded"


def test_ci_edit_detail_page_shows_discovered_interfaces_and_lldp_table(client, app):
    login(client)
    with app.app_context():
        neighbor = ConfigurationItem(
            name="switch-02", ci_class="Network Switch", tenant_id=1,
            discovery_source="SNMP Discovery",
        )
        db.session.add(neighbor)
        db.session.commit()
        ci = ConfigurationItem(
            name="switch-01", ci_class="Network Switch", tenant_id=1,
            discovery_source="SNMP Discovery",
            attributes={
                "sys_descr": "Arista EOS",
                "interfaces": [{"index": "1", "descr": "Eth1", "mac_address": "aa:bb:cc:dd:ee:01"}],
                "lldp_neighbors": [{"neighbor_name": "switch-02", "neighbor_port": "Eth2"}],
            },
        )
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id

    page = client.get(f"/cmdb/{ci_id}/edit")
    assert page.status_code == 200
    assert b"Arista EOS" in page.data
    assert b"Eth1" in page.data
    assert b"aa:bb:cc:dd:ee:01" in page.data
    # The raw dict/list string must never leak into a plain text input.
    assert b"[{&#39;index&#39;" not in page.data and b"[{'index'" not in page.data
    assert b"switch-02" in page.data


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
        "ci_id": [str(primary_ci_id), str(extra_ci_a_id), str(extra_ci_b_id)],
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


def test_ticket_ci_link_accepts_multiple_cis_in_one_submit(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ci_a = ConfigurationItem(name="web-01", ci_class="Server", environment="Production", owner_id=admin.id)
        ci_b = ConfigurationItem(name="web-02", ci_class="Server", environment="Production", owner_id=admin.id)
        db.session.add_all([ci_a, ci_b])
        db.session.commit()
        ci_a_id, ci_b_id = ci_a.id, ci_b.id
    client.post("/tickets/new/incident", data={
        "title": "Web tier degraded", "description": "Both web servers throwing 500s.",
        "impact": "High", "urgency": "High", "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(kind="incident").one().id
    response = client.post(f"/record/ticket/{ticket_id}/configuration-items", data={
        "relationship_role": "Affected CI",
        "ci_id": [str(ci_a_id), str(ci_b_id), str(ci_a_id)],
    })
    assert response.status_code == 302
    with app.app_context():
        linked = {
            link.ci_id for link in TaskCI.query.filter_by(
                target_type="ticket", target_id=ticket_id, relationship_role="Affected CI",
            ).all()
        }
        assert linked == {ci_a_id, ci_b_id}
        history = TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket_id, event="Configuration item linked",
        ).all()
        assert len(history) == 1
        assert "web-01" in history[0].details and "web-02" in history[0].details


def test_ticket_primary_ci_link_stays_single_even_with_multiple_submitted(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ci_a = ConfigurationItem(name="db-primary", ci_class="Database", environment="Production", owner_id=admin.id)
        ci_b = ConfigurationItem(name="db-replica", ci_class="Database", environment="Production", owner_id=admin.id)
        db.session.add_all([ci_a, ci_b])
        db.session.commit()
        ci_a_id, ci_b_id = ci_a.id, ci_b.id
    client.post("/tickets/new/incident", data={
        "title": "Database failover", "description": "Primary database unresponsive.",
        "impact": "High", "urgency": "High", "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(kind="incident").one().id
    client.post(f"/record/ticket/{ticket_id}/configuration-items", data={
        "relationship_role": "Primary CI",
        "ci_id": [str(ci_a_id), str(ci_b_id)],
    })
    with app.app_context():
        primary = TaskCI.query.filter_by(
            target_type="ticket", target_id=ticket_id, relationship_role="Primary CI",
        ).all()
        assert [link.ci_id for link in primary] == [ci_a_id]


def test_ticket_ci_link_rejects_empty_selection(client, app):
    login(client)
    client.post("/tickets/new/incident", data={
        "title": "No CI picked", "description": "Submitting the link form empty must 400.",
        "impact": "Low", "urgency": "Low", "group_id": group_id(app),
    })
    with app.app_context():
        ticket_id = Ticket.query.filter_by(kind="incident").one().id
    response = client.post(f"/record/ticket/{ticket_id}/configuration-items", data={
        "relationship_role": "Affected CI",
    })
    assert response.status_code == 400


def test_service_ci_mapping_links_multiple_cis_in_one_submit(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        service = ServiceOffering(
            name="Payments", owner_id=admin_id, criticality="Critical",
            status="Operational", tenant_id=1,
        )
        ci_a = ConfigurationItem(name="pay-app-01", ci_class="Server", tenant_id=1)
        ci_b = ConfigurationItem(name="pay-db-01", ci_class="Database", tenant_id=1)
        db.session.add_all([service, ci_a, ci_b])
        db.session.commit()
        service_id, ci_a_id, ci_b_id = service.id, ci_a.id, ci_b.id
    response = client.post("/itil/administration", data={
        "action": "link_service_ci", "service_offering_id": str(service_id),
        "relationship_role": "Supporting", "ci_id": [str(ci_a_id), str(ci_b_id)],
    })
    assert response.status_code == 302
    with app.app_context():
        linked = {
            link.ci_id for link in ServiceOfferingCI.query.filter_by(
                service_offering_id=service_id,
            ).all()
        }
        assert linked == {ci_a_id, ci_b_id}


def test_ci_relationship_add_links_multiple_children_in_one_submit(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        parent = ConfigurationItem(name="esx-host-01", ci_class="Server", owner_id=admin.id)
        vm_a = ConfigurationItem(name="vm-app-01", ci_class="Virtual Machine", owner_id=admin.id)
        vm_b = ConfigurationItem(name="vm-app-02", ci_class="Virtual Machine", owner_id=admin.id)
        db.session.add_all([parent, vm_a, vm_b])
        db.session.commit()
        parent_id, vm_a_id, vm_b_id = parent.id, vm_a.id, vm_b.id
    response = client.post("/cmdb/relationships", data={
        "parent_id": str(parent_id), "relationship_type": "Depends on",
        "child_id": [str(vm_a_id), str(vm_b_id)],
    })
    assert response.status_code == 302
    with app.app_context():
        children = {
            rel.child_id for rel in CIRelationship.query.filter_by(parent_id=parent_id).all()
        }
        assert children == {vm_a_id, vm_b_id}
        # Self-reference must still be rejected even inside a batch.
    response = client.post("/cmdb/relationships", data={
        "parent_id": str(parent_id), "relationship_type": "Depends on",
        "child_id": [str(parent_id)],
    })
    assert response.status_code == 400


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
    mobile_result = client.get("/ui/search?q=iphone")
    assert b"ServiceOps mobile" in mobile_result.data
    # Sub-sections within admin pages (e.g. "Security and limits" inside
    # Platform settings) previously had no search entry at all -- only the
    # page itself was indexed.
    security_result = client.get("/ui/search?q=security", headers={"Accept": "application/json"}).json["results"]
    assert any(row["label"] == "Security and limits" and "/admin/settings/security" in row["url"] for row in security_result)
    freeze_result = client.get("/ui/search?q=freeze+windows", headers={"Accept": "application/json"}).json["results"]
    assert any(row["label"] == "Change freeze windows" for row in freeze_result)
    user_result = client.get("/ui/search?q=System+Administrator")
    assert b"User" in user_result.data
    assert b"admin" in user_result.data
    favorite_ack = client.post("/ui/favorite", data={"url": "/task-board", "label": "My board"}).json
    assert favorite_ack["active"]
    assert (favorite_ack["url"], favorite_ack["label"]) == ("/task-board", "My board")
    history_response = client.post("/ui/history", data={"url": "/task-board", "label": "My board"})
    assert history_response.status_code == 200
    assert (history_response.json["url"], history_response.json["label"]) == ("/task-board", "My board")
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


def test_mobile_app_page_is_authenticated_searchable_and_actionable(client):
    assert client.get("/mobile-app").status_code == 302
    login(client)
    response = client.get("/mobile-app")
    assert response.status_code == 200
    assert b"ServiceOps mobile" in response.data
    assert b"ServiceOps_iOS" in response.data
    assert b"iOS 1.3.2 (8)" in response.data
    assert b"wijesundara.com.ServiceOps" in response.data


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
    assert b"People and access" in client.get("/admin").data
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


def test_editing_roles_does_not_silently_drop_a_role_with_no_backing_grant_row(client, app):
    """Real bug found live: an account whose role was ever set through a
    path other than the normal create-user route (older data, an import, a
    fixture script) can end up with User.role set but no actual
    UserRoleGrant row for it -- User.granted_roles defensively merges
    User.role into the set anyway, so the edit form correctly shows that
    role as checked. But the edit route used to only INSERT a grant row
    when a role went from unchecked to checked, and DELETE one when it
    went from checked to unchecked -- if the role stayed checked (held via
    the column, not a row) across an edit that granted a *different*
    additional role, recompute_base_role() (which only trusts real
    UserRoleGrant rows) would silently drop it, even though the admin
    never unchecked it and the redirect showed no error."""
    with app.app_context():
        legacy_user = User(
            username="legacy.import", name="Legacy Import", email="legacy@test.invalid",
            password_hash=generate_password_hash(uuid.uuid4().hex), role="agent",
        )
        db.session.add(legacy_user)
        db.session.commit()
        legacy_id = legacy_user.id
        # Simulate the gap directly: no UserRoleGrant row for "agent" exists,
        # only the User.role column -- exactly what an older import/fixture
        # path could have left behind.
        assert UserRoleGrant.query.filter_by(user_id=legacy_id, role="agent").first() is None

    login(client)
    response = client.post(f"/admin/users/{legacy_id}", data={
        "name": "Legacy Import", "email": "legacy@test.invalid",
        "granted_roles": ["agent", "manager"], "active": "1",
        "title": "", "department": "", "business_phone": "", "mobile_phone": "",
        "timezone": "UTC", "date_format": "system", "calendar_integration": "None",
    })
    assert response.status_code == 302
    with app.app_context():
        legacy_user = db.session.get(User, legacy_id)
        assert set(legacy_user.granted_roles) == {"agent", "manager"}
        assert UserRoleGrant.query.filter_by(user_id=legacy_id, role="agent").first() is not None
        assert UserRoleGrant.query.filter_by(user_id=legacy_id, role="manager").first() is not None


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


def test_ad_ldap_config_group_mapping_and_sync_are_all_on_one_page(client):
    """B-322: user-reported that AD-related configuration was split
    between Platform settings (connection fields) and Service delivery &
    governance (group mapping, directory sync) -- all three now render on
    the single Sign-in and directory settings page."""
    login(client)
    page = client.get("/admin/settings/sign_in_and_directory")
    assert page.status_code == 200
    assert b"AD group" in page.data
    assert b"Directory synchronization" in page.data
    assert b"add_directory_mapping" in page.data
    # LDAP is off by default in this fixture, so the sync trigger itself
    # is hidden behind a "turn it on first" notice rather than rendered.
    assert b"AD/LDAP is not enabled" in page.data
    assert client.post("/admin/settings/sign_in_and_directory", data={
        "LOCAL_AUTH_ENABLED": "on", "LDAP_ENABLED": "on",
    }, headers={"Referer": "http://localhost/admin/settings/sign_in_and_directory"}).status_code == 302
    page = client.get("/admin/settings/sign_in_and_directory")
    assert b"sync_directory" in page.data
    # Old, now-superseded governance URLs redirect here instead of 404ing.
    assert client.get("/service-operations/settings/directory-mapping").headers["Location"].endswith(
        "/admin/settings/sign_in_and_directory")
    assert client.get("/service-operations/settings/ldap-sync").headers["Location"].endswith(
        "/admin/settings/sign_in_and_directory")


def test_governance_groups_shows_member_names_and_supports_manual_add_remove(client, app):
    """B-322: user asked to see member usernames per governance group and
    to be able to configure membership manually (not only via AD group
    sync) -- "give the admin full liberty." """
    login(client)
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        unix_id = unix.id
        employee = User.query.filter_by(username="employee").one()
        employee_id = employee.id
    page = client.get("/service-operations/settings/governance-groups")
    assert page.status_code == 200
    assert b"add_group_member" in page.data

    response = client.post("/itil/administration", data={
        "action": "add_group_member", "group_id": unix_id, "user_id": employee_id,
    })
    assert response.status_code == 302
    with app.app_context():
        membership = GroupMember.query.filter_by(group_id=unix_id, user_id=employee_id).one()
        member_id = membership.id
        assert membership.role == "member"

    page = client.get("/service-operations/settings/governance-groups")
    assert b"employee" in page.data
    assert b"Manual" in page.data

    response = client.post("/itil/administration", data={
        "action": "remove_group_member", "member_id": member_id,
    })
    assert response.status_code == 302
    with app.app_context():
        assert GroupMember.query.filter_by(group_id=unix_id, user_id=employee_id).first() is None


def test_rt_connection_settings_render_on_the_rt_import_page(client):
    """B-322: user-reported RT connection settings and the RT import tool
    were on two different pages -- now both live on /tickets/import/rt."""
    login(client)
    page = client.get("/tickets/import/rt")
    assert page.status_code == 200
    assert b"Connection settings" in page.data
    assert b'action="/admin/settings/request_tracker_connection"' in page.data
    response = client.post("/admin/settings/request_tracker_connection", data={
        "RT_ENABLED": "on", "RT_BASE_URL": "https://rt.example.test",
    }, headers={"Referer": "http://localhost/tickets/import/rt"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Platform settings saved" in response.data
    assert b"Import tickets" in response.data


def test_automation_rules_and_scheduled_automation_are_separate_pages(client):
    """B-322: user-reported the two Quick Find cards "Automation rules"
    and "Scheduled automation" landed on the exact same page -- they're
    now genuinely separate URLs."""
    login(client)
    rules = client.get("/admin/workflows")
    assert rules.status_code == 200
    assert b"Published automation rules" in rules.data
    assert b"Add a schedule" not in rules.data
    scheduled = client.get("/admin/workflows/scheduled")
    assert scheduled.status_code == 200
    assert b"Add a schedule" in scheduled.data
    assert b"Published automation rules" not in scheduled.data
    home = client.get("/admin")
    assert b'href="/admin/workflows"' in home.data
    assert b'href="/admin/workflows/scheduled"' in home.data


def test_administration_is_one_hub_with_clear_child_areas(client):
    login(client)
    home = client.get("/admin")
    assert home.status_code == 200
    assert b"Platform settings" in home.data
    assert b"Service configuration" in home.data
    assert b"Automation rules" in home.data
    assert b"Rules that react to ticket changes" in home.data
    assert b"CMDB and service map" not in home.data
    assert b"Reporting and analytics" not in home.data

    sidebar = home.data.split(b'<aside class="sidebar">', 1)[1].split(b"</aside>", 1)[0]
    assert b">Home<" in sidebar
    assert b"Incidents" in sidebar
    assert b"Service requests" in sidebar
    assert b"Service catalog" in sidebar
    assert b"Knowledge" in sidebar
    assert b"All workspaces" in sidebar
    assert b">Operations<" in sidebar
    assert b'aria-label="Find a menu item"' in sidebar
    assert b">Management<" in sidebar
    assert b">Administration<" in sidebar
    assert b">User management<" in sidebar
    assert b">Users<" in sidebar
    assert b"Groups, teams &amp; access" in sidebar
    assert b"Roles &amp; permissions" in sidebar
    assert b"Active sessions" in sidebar
    assert b'class="nav-group nav-group-admin" open' in sidebar
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
    # B-320: Platform settings is now an index of isolated pages, not a
    # single scrolling/anchored mega-page.
    assert b'href="/admin/settings/organization"' in settings.data
    assert b"Identity and experience" in settings.data
    assert b"Protection and behavior" in settings.data
    assert b"Sign-in and directory" in settings.data
    assert b"Change approval policy" not in settings.data
    assert b"Default ticket priority" not in settings.data
    assert b"Runtime environment" in settings.data

    infrastructure = client.get("/admin/settings/infrastructure")
    assert b"Application replicas" in infrastructure.data
    assert b"1 (local Compose default)" in infrastructure.data

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
    # B-320: Service delivery and governance is likewise an index of
    # genuinely isolated pages, not one long mega-page.
    for section in ("ticket-defaults", "catalog", "team-aliases",
                    "team-managers", "governance-groups",
                    "change-approval-policy", "ccb", "change-freeze",
                    "service-offerings", "sla"):
        assert f'/service-operations/settings/{section}"'.encode() in governance.data
    # B-322: AD group mapping and directory sync moved onto the Sign-in and
    # directory settings page, so they're no longer separate governance
    # sections; old bookmarked URLs redirect there instead of 404ing.
    assert b"directory-mapping" not in governance.data
    assert b"ldap-sync" not in governance.data
    redirected = client.get("/service-operations/settings/directory-mapping")
    assert redirected.status_code == 302
    assert redirected.headers["Location"].endswith("/admin/settings/sign_in_and_directory")
    redirected = client.get("/service-operations/settings/ldap-sync")
    assert redirected.status_code == 302
    assert redirected.headers["Location"].endswith("/admin/settings/sign_in_and_directory")

    change_approval_page = client.get("/service-operations/settings/change-approval-policy")
    assert change_approval_page.status_code == 200
    assert b"Production" in change_approval_page.data
    ticket_defaults_page = client.get("/service-operations/settings/ticket-defaults")
    assert b"Change approval policy" not in ticket_defaults_page.data

    response = client.post("/itil/administration", data={
        "action": "set_change_approval_policy",
        "ccb_required_environments": "Production, Staging, production",
    })
    assert response.status_code == 302
    updated = client.get("/service-operations/settings/change-approval-policy")
    assert b'value="Production, Staging"' in updated.data

    response = client.post("/itil/administration", data={
        "action": "set_ticket_defaults",
        "default_ticket_priority": "P2",
        "sync_child_incident_states": "on",
    })
    assert response.status_code == 302
    updated = client.get("/service-operations/settings/ticket-defaults")
    assert b'<option value="P2" selected>P2</option>' in updated.data
    assert b'name="sync_child_incident_states" checked' in updated.data


def test_client_management_is_sysops_gated_and_supports_customer_ticket_workflow(app, client):
    login(client, "employee", "Employee123!")
    assert client.get("/client-management").status_code == 403
    client.post("/logout")

    login(client, "database.manager", "Manager123!")
    assert client.get("/client-management").status_code == 403
    client.post("/logout")

    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        manager = User.query.filter_by(username="database.manager").one()
        db.session.add(GroupMember(group_id=sysops.id, user_id=manager.id, role="member"))
        db.session.commit()

    login(client, "database.manager", "Manager123!")
    home = client.get("/client-management")
    assert home.status_code == 200
    assert b"External customer conversations" in home.data
    assert b"Client management" in home.data

    response = client.post("/client-management/organizations", data={
        "name": "Example Client", "domain": "example.invalid", "external_id": "CRM-100",
        "notes": "Priority customer",
    })
    assert response.status_code == 302
    with app.app_context():
        organization_id = ClientOrganization.query.filter_by(name="Example Client").one().id

    response = client.post("/client-management/contacts", data={
        "organization_id": organization_id, "name": "Jane Customer",
        "email": "jane@example.invalid", "phone": "+81 00 0000 0000",
        "job_title": "Operations lead", "preferred_language": "English",
    })
    assert response.status_code == 302
    with app.app_context():
        contact_id = ClientContact.query.filter_by(email="jane@example.invalid").one().id

    response = client.post("/client-management/tickets/new", data={
        "contact_id": contact_id, "subject": "Cannot access client portal",
        "description": "The customer receives an access denied response.",
        "ticket_type": "Incident", "priority": "High", "channel": "Email",
        "tags": "portal, access",
    })
    assert response.status_code == 302
    with app.app_context():
        ticket = ClientTicket.query.filter_by(subject="Cannot access client portal").one()
        ticket_id = ticket.id
        assert ticket.number.startswith("CXT")
        assert ticket.support_group.name == "SysOps"
        assert ticket.tenant_id == 1
        assert len(ticket.messages) == 1

    detail = client.get(f"/client-management/tickets/{ticket_id}")
    assert detail.status_code == 200
    assert b"Jane Customer" in detail.data
    assert b"Public reply" in detail.data
    response = client.post(f"/client-management/tickets/{ticket_id}", data={
        "action": "reply", "visibility": "internal", "body": "Checking the identity provider logs.",
    })
    assert response.status_code == 302
    response = client.post(f"/client-management/tickets/{ticket_id}", data={
        "action": "update", "status": "Pending", "priority": "Urgent",
        "ticket_type": "Incident", "assignee_id": "", "tags": "portal, access, waiting",
    })
    assert response.status_code == 302
    search = client.get("/client-management/tickets?q=Jane+Customer")
    assert b"Cannot access client portal" in search.data
    global_search = client.get("/ui/search?q=Example+Client")
    assert b"Customer ticket" in global_search.data
    with app.app_context():
        ticket = db.session.get(ClientTicket, ticket_id)
        assert ticket.status == "Pending"
        assert ticket.priority == "Urgent"
        assert ClientTicketMessage.query.filter_by(
            client_ticket_id=ticket_id, visibility="internal"
        ).count() == 2  # internal note plus status event


def test_client_management_direct_records_are_tenant_isolated(app, client):
    login(client)
    with app.app_context():
        db.session.add(Tenant(id=2, slug="client-two", name="Client Tenant Two"))
        db.session.flush()
        admin = User.query.filter_by(username="admin").one()
        group = SupportGroup(name="SysOps", group_type="Client Support", tenant_id=2)
        organization = ClientOrganization(name="Other Tenant Client", tenant_id=2)
        db.session.add_all([group, organization])
        db.session.flush()
        contact = ClientContact(
            tenant_id=2, organization_id=organization.id, name="Other Contact",
            email="other@tenant-two.invalid",
        )
        db.session.add(contact)
        db.session.flush()
        ticket = ClientTicket(
            tenant_id=2, number="CXT9000001", subject="Other tenant ticket",
            description="Must not be visible", contact_id=contact.id,
            organization_id=organization.id, support_group_id=group.id,
            created_by_id=admin.id,
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id
    assert client.get(f"/client-management/tickets/{ticket_id}").status_code == 404
    assert b"Other tenant ticket" not in client.get("/client-management/tickets").data


def test_client_organization_restricted_visibility_defaults_open_and_is_opt_in(app, client):
    """Regression/behavior test for Client Management phase 1: restricted_visibility
    defaults False, so every existing org stays visible to every SysOps
    member exactly as before this column existed -- restricting is an
    explicit admin action, not a default."""
    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        agent = User.query.filter_by(username="employee").one()
        db.session.add(GroupMember(group_id=sysops.id, user_id=agent.id, role="member", tenant_id=1))
        organization = ClientOrganization(tenant_id=1, name="Default Visibility Client")
        db.session.add(organization)
        db.session.commit()
        assert organization.restricted_visibility is False
        organization_id = organization.id
    login(client, "employee", "Employee123!")
    assert b"Default Visibility Client" in client.get("/client-management/organizations").data
    assert client.get(f"/client-management/organizations/{organization_id}").status_code == 200


def test_client_organization_restricted_visibility_blocks_ungranted_sysops_members(app, client):
    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        granted_agent = User.query.filter_by(username="database.manager").one()
        blocked_agent = User.query.filter_by(username="employee").one()
        db.session.add_all([
            GroupMember(group_id=sysops.id, user_id=granted_agent.id, role="member", tenant_id=1),
            GroupMember(group_id=sysops.id, user_id=blocked_agent.id, role="member", tenant_id=1),
        ])
        organization = ClientOrganization(tenant_id=1, name="Restricted Client", restricted_visibility=True)
        db.session.add(organization)
        db.session.commit()
        organization_id = organization.id
        granted_agent_id = granted_agent.id

    login(client)
    assert client.post(f"/client-management/organizations/{organization_id}", data={
        "action": "add_grant", "grantee": f"user:{granted_agent_id}",
    }).status_code == 302
    client.post("/logout")

    login(client, "database.manager", "Manager123!")
    assert client.get(f"/client-management/organizations/{organization_id}").status_code == 200
    assert b"Restricted Client" in client.get("/client-management/organizations").data
    client.post("/logout")

    login(client, "employee", "Employee123!")
    assert client.get(f"/client-management/organizations/{organization_id}").status_code == 404
    assert b"Restricted Client" not in client.get("/client-management/organizations").data
    search_results = client.get(
        "/ui/search?q=Restricted+Client", headers={"Accept": "application/json"}
    ).json["results"]
    assert not any(row["type"] == "Client organization" for row in search_results)
    client.post("/logout")

    login(client)
    with app.app_context():
        grant = ClientOrganizationAccess.query.filter_by(organization_id=organization_id).one()
        grant_id = grant.id
    assert client.post(f"/client-management/organizations/{organization_id}", data={
        "action": "remove_grant", "grant_id": grant_id,
    }).status_code == 302
    with app.app_context():
        assert ClientOrganizationAccess.query.filter_by(organization_id=organization_id).count() == 0


def test_client_organization_visibility_toggle_and_grants_require_admin(app, client):
    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        manager = User.query.filter_by(username="database.manager").one()
        db.session.add(GroupMember(group_id=sysops.id, user_id=manager.id, role="manager", tenant_id=1))
        organization = ClientOrganization(tenant_id=1, name="Manager Visible Client")
        db.session.add(organization)
        db.session.commit()
        organization_id = organization.id

    login(client, "database.manager", "Manager123!")
    assert client.post(f"/client-management/organizations/{organization_id}", data={
        "action": "toggle_restricted",
    }).status_code == 403
    with app.app_context():
        assert db.session.get(ClientOrganization, organization_id).restricted_visibility is False


def test_client_custom_field_definition_required_on_ticket_and_org_override(app, client):
    """Regression coverage for Client Management phase 2: a tenant-wide
    required custom field blocks ticket creation until filled in, its value
    round-trips, and a per-organization override can make an
    otherwise-optional field required (or hide a field) for that org's
    tickets specifically without affecting any other organization."""
    login(client)
    assert client.post("/client-management/custom-fields", data={
        "action": "create", "entity_type": "client_ticket", "key": "account_tier",
        "label": "Account tier", "field_type": "select", "options": "Bronze\nSilver\nGold",
        "required": "on",
    }).status_code == 302
    assert client.post("/client-management/custom-fields", data={
        "action": "create", "entity_type": "organization", "key": "renewal_date",
        "label": "Renewal date", "field_type": "date",
    }).status_code == 302

    org_resp = client.post("/client-management/organizations", data={"name": "Custom Field Client"})
    assert org_resp.status_code == 302
    with app.app_context():
        organization_id = ClientOrganization.query.filter_by(name="Custom Field Client").one().id
    contact_resp = client.post("/client-management/contacts", data={
        "organization_id": organization_id, "name": "Field Test Contact",
        "email": "fieldtest@example.invalid",
    })
    assert contact_resp.status_code == 302
    with app.app_context():
        contact_id = ClientContact.query.filter_by(email="fieldtest@example.invalid").one().id

    missing_required = client.post("/client-management/tickets/new", data={
        "contact_id": contact_id, "subject": "No tier set", "description": "Should be rejected.",
    }, follow_redirects=True)
    assert missing_required.status_code == 200
    assert b"Account tier is required" in missing_required.data
    with app.app_context():
        assert ClientTicket.query.filter_by(subject="No tier set").first() is None

    created = client.post("/client-management/tickets/new", data={
        "contact_id": contact_id, "subject": "Tier set", "description": "Should succeed.",
        "custom__account_tier": "Gold",
    })
    assert created.status_code == 302
    with app.app_context():
        ticket = ClientTicket.query.filter_by(subject="Tier set").one()
        assert ticket.custom_fields == {"account_tier": "Gold"}
        organization_id = ticket.organization_id

    org_field_response = client.post(f"/client-management/organizations/{organization_id}", data={
        "action": "update_custom_fields", "custom__renewal_date": "2027-01-15",
    })
    assert org_field_response.status_code == 302
    with app.app_context():
        assert db.session.get(ClientOrganization, organization_id).custom_fields == {"renewal_date": "2027-01-15"}

    override_response = client.post(f"/client-management/organizations/{organization_id}", data={
        "action": "update_field_overrides",
    })
    assert override_response.status_code == 302
    with app.app_context():
        organization = db.session.get(ClientOrganization, organization_id)
        assert organization.settings["custom_field_overrides"]["account_tier"] == {
            "visible": False, "required": False,
        }

    hidden_field_form = client.get("/client-management/tickets/new")
    assert hidden_field_form.status_code == 200

    other_org_resp = client.post("/client-management/organizations", data={"name": "Unaffected Client"})
    assert other_org_resp.status_code == 302
    with app.app_context():
        other_organization = ClientOrganization.query.filter_by(name="Unaffected Client").one()
        assert other_organization.settings == {}


def test_client_saved_view_filters_tickets_and_sharing_and_delete_permissions(app, client):
    """Regression coverage for Client Management phase 3: a saved view's
    stored filter conditions actually narrow the ticket list the same way
    the ad-hoc filter bar does (same apply_filter_conditions() engine,
    confirming the reuse rather than a parallel bespoke implementation),
    an unshared view is private to its creator, a shared view is visible
    tenant-wide, and only the view's own creator or an admin can delete it."""
    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        manager = User.query.filter_by(username="database.manager").one()
        db.session.add(GroupMember(group_id=sysops.id, user_id=manager.id, role="member", tenant_id=1))
        db.session.commit()

    login(client)
    client.post("/client-management/organizations", data={"name": "View Test Client"})
    with app.app_context():
        organization_id = ClientOrganization.query.filter_by(name="View Test Client").one().id
    client.post("/client-management/contacts", data={
        "organization_id": organization_id, "name": "View Test Contact", "email": "viewtest@example.invalid",
    })
    with app.app_context():
        contact_id = ClientContact.query.filter_by(email="viewtest@example.invalid").one().id
    for subject, priority in [("Urgent one", "Urgent"), ("Normal one", "Normal")]:
        assert client.post("/client-management/tickets/new", data={
            "contact_id": contact_id, "subject": subject, "description": "x", "priority": priority,
        }).status_code == 302

    import json as _json
    conditions = _json.dumps([{"field": "priority", "op": "eq", "value": "Urgent"}])
    saved = client.post("/client-management/views", data={
        "name": "Urgent only", "conditions_json": conditions, "sort_field": "updated", "sort_dir": "desc",
    })
    assert saved.status_code == 302
    with app.app_context():
        view = ClientView.query.filter_by(name="Urgent only").one()
        assert view.shared is False
        view_id = view.id

    filtered = client.get(f"/client-management/tickets?view_id={view_id}")
    assert filtered.status_code == 200
    assert b"Urgent one" in filtered.data
    assert b"Normal one" not in filtered.data

    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    unshared_check = client.get(f"/client-management/tickets?view_id={view_id}")
    assert b"Urgent only" not in unshared_check.data
    assert client.post(f"/client-management/views/{view_id}/delete").status_code == 403
    client.post("/logout")

    login(client)
    shared = client.post("/client-management/views", data={
        "name": "Shared urgent view", "conditions_json": conditions, "shared": "on",
    })
    assert shared.status_code == 302
    with app.app_context():
        shared_view_id = ClientView.query.filter_by(name="Shared urgent view").one().id
    client.post("/logout")

    login(client, "database.manager", "Manager123!")
    shared_visible = client.get("/client-management/tickets")
    assert b"Shared urgent view" in shared_visible.data
    # Manager is neither the creator nor an admin, so still can't delete it.
    assert client.post(f"/client-management/views/{shared_view_id}/delete").status_code == 403
    client.post("/logout")

    login(client)
    assert client.post(f"/client-management/views/{view_id}/delete").status_code == 302
    with app.app_context():
        assert db.session.get(ClientView, view_id) is None
        assert db.session.get(ClientView, shared_view_id) is not None


def test_client_macro_applies_field_changes_and_canned_reply(app, client):
    """Regression coverage for Client Management phase 4: applying a macro
    changes exactly the fields it specifies, leaves others untouched, posts
    its canned reply as a real message, and requires admin to create."""
    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        manager = User.query.filter_by(username="database.manager").one()
        db.session.add(GroupMember(group_id=sysops.id, user_id=manager.id, role="member", tenant_id=1))
        db.session.commit()

    login(client, "database.manager", "Manager123!")
    assert client.post("/client-management/macros", data={
        "action": "create", "name": "Escalate and reply",
    }).status_code == 403
    client.post("/logout")

    login(client)
    assert client.post("/client-management/macros", data={
        "action": "create", "name": "Escalate and reply", "macro_priority": "Urgent",
        "reply_body": "We've escalated this to our senior team.", "reply_visibility": "public",
    }).status_code == 302
    with app.app_context():
        macro = ClientMacro.query.filter_by(name="Escalate and reply").one()
        macro_id = macro.id
        assert json.loads(macro.actions_json) == {"priority": "Urgent"}

    client.post("/client-management/organizations", data={"name": "Macro Test Client"})
    with app.app_context():
        organization_id = ClientOrganization.query.filter_by(name="Macro Test Client").one().id
    client.post("/client-management/contacts", data={
        "organization_id": organization_id, "name": "Macro Test Contact", "email": "macrotest@example.invalid",
    })
    with app.app_context():
        contact_id = ClientContact.query.filter_by(email="macrotest@example.invalid").one().id
    client.post("/client-management/tickets/new", data={
        "contact_id": contact_id, "subject": "Macro target ticket", "description": "x",
        "priority": "Normal", "ticket_type": "Question",
    })
    with app.app_context():
        ticket = ClientTicket.query.filter_by(subject="Macro target ticket").one()
        ticket_id = ticket.id
        assert ticket.priority == "Normal"

    applied = client.post(f"/client-management/tickets/{ticket_id}", data={
        "action": "apply_macro", "macro_id": macro_id,
    })
    assert applied.status_code == 302
    with app.app_context():
        ticket = db.session.get(ClientTicket, ticket_id)
        assert ticket.priority == "Urgent"
        assert ticket.ticket_type == "Question"  # untouched -- macro didn't specify it
        reply = ClientTicketMessage.query.filter_by(
            client_ticket_id=ticket_id, body="We've escalated this to our senior team.",
        ).one()
        assert reply.visibility == "public"

    assert client.post("/client-management/macros", data={
        "action": "toggle_active", "macro_id": macro_id,
    }).status_code == 302
    with app.app_context():
        assert db.session.get(ClientMacro, macro_id).active is False
    disabled_apply = client.post(f"/client-management/tickets/{ticket_id}", data={
        "action": "apply_macro", "macro_id": macro_id,
    })
    assert disabled_apply.status_code == 404


def test_client_ticket_sla_prefers_organization_override_over_tenant_default(app, client):
    """Regression coverage for Client Management phase 5: a client_ticket
    SLA definition scoped to a specific organization overrides the
    tenant-wide default for the same priority on that organization's
    tickets, while a different organization still gets the tenant-wide
    default -- confirming attach_slas()'s preference logic actually works,
    not just that both kinds of row can be created. Also confirms sync_slas
    marks the SLA Completed when a customer ticket reaches "Solved" (a
    client-ticket-specific terminal state ITIL tickets don't use)."""
    login(client)
    client.post("/client-management/organizations", data={"name": "VIP SLA Client"})
    client.post("/client-management/organizations", data={"name": "Standard SLA Client"})
    with app.app_context():
        vip_org = ClientOrganization.query.filter_by(name="VIP SLA Client").one()
        standard_org = ClientOrganization.query.filter_by(name="Standard SLA Client").one()
        vip_org_id, standard_org_id = vip_org.id, standard_org.id

    assert client.post("/itil/administration", data={
        "action": "create_sla_definition", "name": "Customer Urgent -- tenant default",
        "target_type": "client_ticket", "priority": "Urgent", "duration_minutes": "240",
        "pause_states": "Pending,On-hold",
    }).status_code == 302
    assert client.post("/itil/administration", data={
        "action": "create_sla_definition", "name": "Customer Urgent -- VIP override",
        "target_type": "client_ticket", "priority": "Urgent", "duration_minutes": "30",
        "pause_states": "Pending,On-hold", "client_organization_id": str(vip_org_id),
    }).status_code == 302
    with app.app_context():
        default_def = SLADefinition.query.filter_by(name="Customer Urgent -- tenant default").one()
        override_def = SLADefinition.query.filter_by(name="Customer Urgent -- VIP override").one()
        assert override_def.client_organization_id == vip_org_id

    for org_id, org_name in [(vip_org_id, "VIP"), (standard_org_id, "Standard")]:
        client.post("/client-management/contacts", data={
            "organization_id": org_id, "name": f"{org_name} Contact",
            "email": f"{org_name.lower()}@example.invalid",
        })
    with app.app_context():
        vip_contact_id = ClientContact.query.filter_by(email="vip@example.invalid").one().id
        standard_contact_id = ClientContact.query.filter_by(email="standard@example.invalid").one().id

    client.post("/client-management/tickets/new", data={
        "contact_id": vip_contact_id, "subject": "VIP urgent issue", "description": "x", "priority": "Urgent",
    })
    client.post("/client-management/tickets/new", data={
        "contact_id": standard_contact_id, "subject": "Standard urgent issue", "description": "x", "priority": "Urgent",
    })
    with app.app_context():
        vip_ticket = ClientTicket.query.filter_by(subject="VIP urgent issue").one()
        standard_ticket = ClientTicket.query.filter_by(subject="Standard urgent issue").one()
        vip_sla = TaskSLA.query.filter_by(target_type="client_ticket", target_id=vip_ticket.id).one()
        standard_sla = TaskSLA.query.filter_by(target_type="client_ticket", target_id=standard_ticket.id).one()
        assert vip_sla.definition_id == override_def.id
        assert standard_sla.definition_id == default_def.id
        vip_ticket_id = vip_ticket.id

    solved = client.post(f"/client-management/tickets/{vip_ticket_id}", data={
        "action": "update", "status": "Solved", "priority": "Urgent", "ticket_type": "Question",
        "assignee_id": "", "tags": "",
    })
    assert solved.status_code == 302
    with app.app_context():
        assert db.session.get(TaskSLA, vip_sla.id).stage == "Completed"


def test_client_trigger_fires_matching_condition_and_skips_non_matching(app, client):
    """Regression coverage for Client Management phase 6: a trigger whose
    condition matches the just-created ticket applies its action (and logs
    an internal "Automation triggered" note); a ticket that doesn't match
    the condition is left untouched by that same trigger. Also confirms
    trigger management requires admin."""
    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        manager = User.query.filter_by(username="database.manager").one()
        db.session.add(GroupMember(group_id=sysops.id, user_id=manager.id, role="member", tenant_id=1))
        db.session.commit()

    login(client, "database.manager", "Manager123!")
    assert client.post("/client-management/triggers", data={
        "action": "create", "name": "Auto-escalate urgent",
    }).status_code == 403
    client.post("/logout")

    login(client)
    assert client.post("/client-management/triggers", data={
        "action": "create", "name": "Auto-escalate urgent", "event": "created",
        "condition_field": "priority", "condition_op": "eq", "condition_value": "Urgent",
        "action_type": "add_tag", "action_value": "escalated",
    }).status_code == 302
    with app.app_context():
        trigger = ClientTrigger.query.filter_by(name="Auto-escalate urgent").one()
        assert trigger.active is True

    client.post("/client-management/organizations", data={"name": "Trigger Test Client"})
    with app.app_context():
        organization_id = ClientOrganization.query.filter_by(name="Trigger Test Client").one().id
    client.post("/client-management/contacts", data={
        "organization_id": organization_id, "name": "Trigger Test Contact", "email": "triggertest@example.invalid",
    })
    with app.app_context():
        contact_id = ClientContact.query.filter_by(email="triggertest@example.invalid").one().id

    client.post("/client-management/tickets/new", data={
        "contact_id": contact_id, "subject": "Urgent trigger match", "description": "x", "priority": "Urgent",
    })
    client.post("/client-management/tickets/new", data={
        "contact_id": contact_id, "subject": "Normal no trigger", "description": "x", "priority": "Normal",
    })
    with app.app_context():
        matched = ClientTicket.query.filter_by(subject="Urgent trigger match").one()
        unmatched = ClientTicket.query.filter_by(subject="Normal no trigger").one()
        assert "escalated" in matched.tags
        assert "escalated" not in unmatched.tags
        assert ClientTicketMessage.query.filter_by(
            client_ticket_id=matched.id, event_type="automation",
        ).first() is not None
        assert ClientTicketMessage.query.filter_by(
            client_ticket_id=unmatched.id, event_type="automation",
        ).first() is None

    assert client.post("/client-management/triggers", data={
        "action": "toggle_active", "trigger_id": trigger.id,
    }).status_code == 302
    with app.app_context():
        assert db.session.get(ClientTrigger, trigger.id).active is False
    client.post("/client-management/tickets/new", data={
        "contact_id": contact_id, "subject": "Urgent but trigger disabled", "description": "x", "priority": "Urgent",
    })
    with app.app_context():
        disabled_case = ClientTicket.query.filter_by(subject="Urgent but trigger disabled").one()
        assert "escalated" not in disabled_case.tags


def test_client_organization_branding_and_escalation_policy(app, client):
    """Regression coverage for Client Management phase 7: branding saves to
    the organization's settings JSON and renders on its tickets; an
    escalation policy reassigns an old open ticket to the configured team,
    posts an internal note, notifies the manager, and does so only once
    (idempotent via the auto-escalated tag) -- a second run doesn't
    re-escalate or re-notify. A policy-free organization is left untouched."""
    login(client)
    client.post("/client-management/organizations", data={"name": "Escalation Test Client"})
    client.post("/client-management/organizations", data={"name": "No Policy Client"})
    with app.app_context():
        escalation_org = ClientOrganization.query.filter_by(name="Escalation Test Client").one()
        no_policy_org = ClientOrganization.query.filter_by(name="No Policy Client").one()
        escalation_org_id, no_policy_org_id = escalation_org.id, no_policy_org.id
        network_group = SupportGroup.query.filter_by(name="Network", tenant_id=1).one()
        network_group_id = network_group.id
        admin = User.query.filter_by(username="admin").one()
        admin_id = admin.id
        network_group.manager_id = admin.id
        db.session.commit()

    branding_resp = client.post(f"/client-management/organizations/{escalation_org_id}", data={
        "action": "update_branding", "display_name": "Escalation Test Co.", "color": "#ff0000",
    })
    assert branding_resp.status_code == 302
    with app.app_context():
        assert db.session.get(ClientOrganization, escalation_org_id).settings["branding"] == {
            "display_name": "Escalation Test Co.", "color": "#ff0000",
        }

    policy_resp = client.post(f"/client-management/organizations/{escalation_org_id}", data={
        "action": "update_notification_policy", "escalation_hours": "1", "escalation_group_id": str(network_group_id),
    })
    assert policy_resp.status_code == 302

    client.post("/client-management/contacts", data={
        "organization_id": escalation_org_id, "name": "Escalation Contact", "email": "escalation@example.invalid",
    })
    client.post("/client-management/contacts", data={
        "organization_id": no_policy_org_id, "name": "No Policy Contact", "email": "nopolicy@example.invalid",
    })
    with app.app_context():
        escalation_contact_id = ClientContact.query.filter_by(email="escalation@example.invalid").one().id
        no_policy_contact_id = ClientContact.query.filter_by(email="nopolicy@example.invalid").one().id

    client.post("/client-management/tickets/new", data={
        "contact_id": escalation_contact_id, "subject": "Old ticket to escalate", "description": "x",
    })
    client.post("/client-management/tickets/new", data={
        "contact_id": no_policy_contact_id, "subject": "Old ticket, no policy configured", "description": "x",
    })
    with app.app_context():
        escalation_ticket = ClientTicket.query.filter_by(subject="Old ticket to escalate").one()
        no_policy_ticket = ClientTicket.query.filter_by(subject="Old ticket, no policy configured").one()
        escalation_ticket_id, no_policy_ticket_id = escalation_ticket.id, no_policy_ticket.id
        original_group_id = escalation_ticket.support_group_id
        # Backdate creation past the 1-hour escalation threshold.
        escalation_ticket.created_at = now() - timedelta(hours=2)
        no_policy_ticket.created_at = now() - timedelta(hours=2)
        db.session.commit()

        processed = process_client_escalation_policies()
        assert processed == 1

        escalated = db.session.get(ClientTicket, escalation_ticket_id)
        assert escalated.support_group_id == network_group_id
        assert escalated.support_group_id != original_group_id
        assert "auto-escalated" in escalated.tags
        assert ClientTicketMessage.query.filter_by(
            client_ticket_id=escalation_ticket_id, event_type="escalation",
        ).count() == 1
        assert Notification.query.filter_by(
            user_id=admin_id, target_type="client_ticket", target_id=escalation_ticket_id,
        ).count() == 1

        untouched = db.session.get(ClientTicket, no_policy_ticket_id)
        assert untouched.support_group_id != network_group_id
        assert "auto-escalated" not in untouched.tags

        # Idempotent: running again must not re-escalate or re-notify.
        again = process_client_escalation_policies()
        assert again == 0
        assert ClientTicketMessage.query.filter_by(
            client_ticket_id=escalation_ticket_id, event_type="escalation",
        ).count() == 1
        assert Notification.query.filter_by(
            user_id=admin_id, target_type="client_ticket", target_id=escalation_ticket_id,
        ).count() == 1

    ticket_page = client.get(f"/client-management/tickets/{escalation_ticket_id}")
    assert b"Escalation Test Co." in ticket_page.data


def test_client_mailbox_admin_requires_admin_and_is_tenant_isolated(app, client):
    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        manager = User.query.filter_by(username="database.manager").one()
        db.session.add(GroupMember(group_id=sysops.id, user_id=manager.id, role="member", tenant_id=1))
        db.session.commit()

    login(client, "database.manager", "Manager123!")
    assert client.post("/client-management/mailboxes", data={
        "action": "create", "name": "Support", "imap_host": "imap.example.test",
        "smtp_host": "smtp.example.test", "from_address": "support@example.test",
    }).status_code == 403
    client.post("/logout")

    login(client)
    assert client.post("/client-management/mailboxes", data={
        "action": "create", "name": "Support", "imap_host": "imap.example.test",
        "imap_port": "993", "imap_use_ssl": "on", "imap_username": "support@example.test",
        "imap_password": "secret-imap-pw", "smtp_host": "smtp.example.test", "smtp_port": "587",
        "smtp_use_tls": "on", "from_address": "support@example.test", "from_name": "Example Support",
    }).status_code == 302
    with app.app_context():
        mailbox = ClientMailbox.query.filter_by(name="Support").one()
        mailbox_id = mailbox.id
        # Password round-trips through the encrypted column, never stored plaintext.
        assert mailbox.imap_password == "secret-imap-pw"
        assert mailbox.imap_password_encrypted != "secret-imap-pw"

    with app.app_context():
        db.session.add(Tenant(id=2, slug="mailbox-other", name="Other Tenant"))
        db.session.commit()
        other_mailbox = ClientMailbox(
            tenant_id=2, name="Other Tenant Mailbox", imap_host="x", smtp_host="x", from_address="x@x.test",
        )
        db.session.add(other_mailbox)
        db.session.commit()
        other_mailbox_id = other_mailbox.id

    listing = client.get("/client-management/mailboxes")
    assert b"Other Tenant Mailbox" not in listing.data
    assert client.post("/client-management/mailboxes", data={
        "action": "toggle_active", "mailbox_id": other_mailbox_id,
    }).status_code == 404

    assert client.post("/client-management/mailboxes", data={
        "action": "toggle_active", "mailbox_id": mailbox_id,
    }).status_code == 302
    with app.app_context():
        assert db.session.get(ClientMailbox, mailbox_id).active is False


class _FakeIMAPConnection:
    """A minimal stand-in for imaplib.IMAP4_SSL exercising exactly the
    calls _poll_client_mailbox() makes, so the full inbound pipeline
    (parsing, threading, contact/org auto-creation, attachment save, SLA/
    trigger evaluation) is tested against real ClientTicketMessage
    construction and real DB writes -- without real network I/O. Real
    protocol-level IMAP/SMTP behavior is covered separately by a live
    GreenMail end-to-end pass, not by this mock."""

    def __init__(self, raw_messages):
        self._raw_messages = {str(i + 1).encode(): raw for i, raw in enumerate(raw_messages)}
        self.stored_flags = {}

    def login(self, username, password):
        return "OK", []

    def select(self, folder):
        return "OK", []

    def search(self, charset, criteria):
        return "OK", [b" ".join(self._raw_messages.keys())]

    def fetch(self, num, parts):
        raw = self._raw_messages[num]
        return "OK", [(b"1 (RFC822 {%d})" % len(raw), raw)]

    def store(self, num, flag_op, flags):
        self.stored_flags[num] = flags
        return "OK", []

    def logout(self):
        return "BYE", []


def test_client_email_inbox_creates_ticket_and_auto_creates_contact_and_org(app, client, monkeypatch):
    """Regression coverage for the Client Management email channel: a real
    inbound email from an unrecognized corporate-domain sender auto-creates
    both the ClientContact and a matching ClientOrganization (by domain),
    creates a new ClientTicket, attaches an SLA and evaluates triggers
    exactly like a manually-created ticket, and marks the message seen."""
    from email.message import EmailMessage as _EmailMessage
    import app as app_module

    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        mailbox = ClientMailbox(
            tenant_id=1, name="Inbound Test", imap_host="imap.example.test",
            smtp_host="smtp.example.test", from_address="support@ourcompany.test",
            created_by_id=admin.id,
        )
        db.session.add(mailbox)
        db.session.commit()
        mailbox_id = mailbox.id

    raw = _EmailMessage()
    raw["From"] = "New Customer <newcustomer@realcompany.test>"
    raw["To"] = "support@ourcompany.test"
    raw["Subject"] = "Can't access my account"
    raw["Message-ID"] = "<inbound-1@realcompany.test>"
    raw.set_content("Please help, I can't log in.")

    fake_connection = _FakeIMAPConnection([raw.as_bytes()])
    monkeypatch.setattr(app_module.imaplib, "IMAP4_SSL", lambda host, port: fake_connection)

    with app.app_context():
        mailbox = db.session.get(ClientMailbox, mailbox_id)
        processed = app_module._poll_client_mailbox(mailbox)
        assert processed == 1
        assert fake_connection.stored_flags[b"1"] == "\\Seen"

        ticket = ClientTicket.query.filter_by(subject="Can't access my account").one()
        assert ticket.channel == "Email"
        assert ticket.contact.email == "newcustomer@realcompany.test"
        assert ticket.organization.domain == "realcompany.test"
        inbound_message = ClientTicketMessage.query.filter_by(client_ticket_id=ticket.id).one()
        assert inbound_message.author_id is None
        assert inbound_message.message_id == "<inbound-1@realcompany.test>"
        assert db.session.get(ClientMailbox, mailbox_id).last_poll_status == "ok"

    detail = client.get(f"/client-management/tickets/{ticket.id}")
    assert detail.status_code == 200
    assert b"(via email)" in detail.data


def test_client_email_inbox_threads_reply_by_message_id_not_new_ticket(app, client, monkeypatch):
    """A reply email whose In-Reply-To references an already-known
    Message-ID must thread into the SAME ticket, not create a second one --
    the core "don't duplicate on every reply" requirement of any email
    channel."""
    from email.message import EmailMessage as _EmailMessage
    import app as app_module

    login(client)
    client.post("/client-management/organizations", data={"name": "Thread Test Co", "domain": "threadtest.test"})
    with app.app_context():
        organization = ClientOrganization.query.filter_by(name="Thread Test Co").one()
        organization_id = organization.id
        admin = User.query.filter_by(username="admin").one()
        mailbox = ClientMailbox(
            tenant_id=1, name="Thread Test Mailbox", imap_host="imap.example.test",
            smtp_host="smtp.example.test", from_address="support@ourcompany.test",
            created_by_id=admin.id,
        )
        db.session.add(mailbox)
        db.session.commit()
        mailbox_id = mailbox.id
    client.post("/client-management/contacts", data={
        "organization_id": organization_id, "name": "Thread Contact", "email": "thread@threadtest.test",
    })
    with app.app_context():
        contact = ClientContact.query.filter_by(email="thread@threadtest.test").one()
        contact_id = contact.id

    first = _EmailMessage()
    first["From"] = "thread@threadtest.test"
    first["Subject"] = "Billing question"
    first["Message-ID"] = "<first@threadtest.test>"
    first.set_content("Why was I charged twice?")
    reply = _EmailMessage()
    reply["From"] = "thread@threadtest.test"
    reply["Subject"] = "Re: Billing question"
    reply["Message-ID"] = "<reply@threadtest.test>"
    reply["In-Reply-To"] = "<first@threadtest.test>"
    reply.set_content("Following up on this.")

    with app.app_context():
        mailbox = db.session.get(ClientMailbox, mailbox_id)
        fake_connection = _FakeIMAPConnection([first.as_bytes()])
        monkeypatch.setattr(app_module.imaplib, "IMAP4_SSL", lambda host, port: fake_connection)
        app_module._poll_client_mailbox(mailbox)
        assert ClientTicket.query.filter_by(contact_id=contact_id).count() == 1

        fake_connection_2 = _FakeIMAPConnection([reply.as_bytes()])
        monkeypatch.setattr(app_module.imaplib, "IMAP4_SSL", lambda host, port: fake_connection_2)
        app_module._poll_client_mailbox(mailbox)
        tickets = ClientTicket.query.filter_by(contact_id=contact_id).all()
        assert len(tickets) == 1, "the reply must thread into the existing ticket, not create a new one"
        assert ClientTicketMessage.query.filter_by(client_ticket_id=tickets[0].id).count() == 2


def test_client_email_inbox_skips_auto_generated_mail(app, client, monkeypatch):
    """An autoresponder/out-of-office reply must never become a ticket --
    the primary mail-loop defense."""
    from email.message import EmailMessage as _EmailMessage
    import app as app_module

    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        mailbox = ClientMailbox(
            tenant_id=1, name="Loop Test Mailbox", imap_host="imap.example.test",
            smtp_host="smtp.example.test", from_address="support@ourcompany.test",
            created_by_id=admin.id,
        )
        db.session.add(mailbox)
        db.session.commit()
        mailbox_id = mailbox.id

    autoreply = _EmailMessage()
    autoreply["From"] = "outofoffice@somesender.test"
    autoreply["Subject"] = "Automatic reply: Out of office"
    autoreply["Message-ID"] = "<autoreply@somesender.test>"
    autoreply["Auto-Submitted"] = "auto-replied"
    autoreply.set_content("I am currently out of the office.")

    with app.app_context():
        mailbox = db.session.get(ClientMailbox, mailbox_id)
        fake_connection = _FakeIMAPConnection([autoreply.as_bytes()])
        monkeypatch.setattr(app_module.imaplib, "IMAP4_SSL", lambda host, port: fake_connection)
        processed = app_module._poll_client_mailbox(mailbox)
        assert processed == 0
        assert ClientTicket.query.filter_by(tenant_id=1, subject="Automatic reply: Out of office").first() is None


def test_deliver_client_email_reply_sends_via_smtp_and_stores_message_id(app, client, monkeypatch):
    import app as app_module

    login(client)
    client.post("/client-management/organizations", data={"name": "Outbound Test Co"})
    with app.app_context():
        organization_id = ClientOrganization.query.filter_by(name="Outbound Test Co").one().id
        admin = User.query.filter_by(username="admin").one()
        mailbox = ClientMailbox(
            tenant_id=1, name="Outbound Test Mailbox", imap_host="imap.example.test",
            smtp_host="smtp.example.test", smtp_port=587, smtp_use_tls=True,
            from_address="support@ourcompany.test", from_name="Our Company Support",
            active=True, created_by_id=admin.id,
        )
        db.session.add(mailbox)
        db.session.commit()
    client.post("/client-management/contacts", data={
        "organization_id": organization_id, "name": "Outbound Contact", "email": "outbound@example.test",
    })
    with app.app_context():
        contact_id = ClientContact.query.filter_by(email="outbound@example.test").one().id
    client.post("/client-management/tickets/new", data={
        "contact_id": contact_id, "subject": "Need help", "description": "x",
    })
    with app.app_context():
        ticket_id = ClientTicket.query.filter_by(subject="Need help").one().id

    sent_messages = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("smtp.example.test", 587)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def ehlo(self):
            return None
        def starttls(self, context):
            assert context
        def login(self, username, password):
            pass
        def send_message(self, message):
            sent_messages.append(message)

    monkeypatch.setattr(app_module.smtplib, "SMTP", FakeSMTP)

    reply_response = client.post(f"/client-management/tickets/{ticket_id}", data={
        "action": "reply", "visibility": "public", "body": "We're looking into this now.",
    })
    assert reply_response.status_code == 302
    assert len(sent_messages) == 1
    outbound = sent_messages[0]
    assert outbound["To"] == "outbound@example.test"
    assert "Message-ID" in outbound
    assert outbound["Auto-Submitted"] == "no"
    with app.app_context():
        message = ClientTicketMessage.query.filter_by(
            client_ticket_id=ticket_id, body="We're looking into this now.",
        ).one()
        assert message.message_id == outbound["Message-ID"]


def test_admin_can_update_live_platform_branding(client, app):
    """B-320: Platform settings are decentralized into one isolated page
    per category, so saving spans one POST per category instead of one
    giant form. Each category's own isolated page is exercised here."""
    login(client)
    response = client.post("/admin/settings/organization", data={
        "INSTANCE_NAME": "Operations Hub",
        "COMPANY_NAME": "Example Corporation",
        "SUPPORT_EMAIL": "support@example.test",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Platform settings saved" in response.data
    assert b"Operations Hub" in response.data
    with app.app_context():
        assert db.session.get(PlatformSetting, "COMPANY_NAME").value == "Example Corporation"

    response = client.post("/admin/settings/appearance", data={
        "BRAND_TEAL": "#124c5a", "BRAND_AMBER": "#f4a340", "DEFAULT_DENSITY": "comfortable",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Platform settings saved" in response.data

    response = client.post("/admin/settings/sign_in_and_directory", data={
        "LOCAL_AUTH_ENABLED": "on",
        "LDAP_USER_FILTER": "(&(objectClass=user)(sAMAccountName={username}))",
        "LDAP_START_TLS": "on",
        "LDAP_VALIDATE_CERT": "on",
        "LDAP_ROLE_MAPPINGS": "{}",
        "KEYCLOAK_ROLE_MAPPINGS": "{}",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Platform settings saved" in response.data

    response = client.post("/admin/settings/security", data={
        "SESSION_HOURS": "8", "MAX_UPLOAD_MB": "20",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Platform settings saved" in response.data


def test_settings_category_page_does_not_trigger_auth_method_check_for_other_categories(client):
    """B-320: the "at least one authentication method must remain
    enabled" validation used to run unconditionally on every save because
    every setting lived on one shared form; split across isolated pages,
    saving e.g. Organization submits none of the three auth fields and
    must not spuriously fail that check."""
    login(client)
    response = client.post("/admin/settings/organization", data={
        "INSTANCE_NAME": "Operations Hub",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"At least one authentication method must remain enabled" not in response.data
    assert b"Platform settings saved" in response.data


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


def test_conflict_detection_completed_history_only_logged_when_a_conflict_is_found(client, app):
    """Regression test: a user flagged the ticket timeline showing a
    "Conflict detection completed / No conflict" entry on every single
    change -- clutter with nothing actionable in it, unlike this
    codebase's existing convention (e.g. the SLA-breach scan only logs a
    "breached" entry, never one for every non-breaching pass)."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ci = ConfigurationItem(
            name="uncontested-server", ci_class="Server",
            environment="Production", owner_id=admin.id,
        )
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    login(client)
    created = client.post("/tickets/new/change", data={
        "title": "Routine, uncontested change", "description": "No overlapping work.",
        "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "10", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.",
        "backout_plan": "Back out.", "ci_id": str(ci_id),
        "planned_start": "2026-09-01T09:00", "planned_end": "2026-09-01T17:00",
    }, follow_redirects=True)
    assert created.status_code == 200
    assert b"Conflict detection completed" not in created.data
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Routine, uncontested change").one()
        assert ticket.change_governance.conflict_status == "No conflict"
        assert not TaskHistory.query.filter_by(
            target_type="ticket", target_id=ticket.id, event="Conflict detection completed",
        ).first()


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


def test_ldap_login_accepts_upn_and_down_level_forms_not_just_bare_username(app, monkeypatch):
    """Reported bug: a user typing "jsmith@company.com" or "CORP\\jsmith"
    (the two other Windows-standard login forms, alongside the bare
    "jsmith") got rejected, because the default LDAP_USER_FILTER matches
    sAMAccountName, which only ever holds the bare form. ldap_authenticate
    must strip a UPN suffix/down-level prefix and retry with the bare form
    before giving up."""
    import app as app_module

    class FakeEntry:
        def __init__(self, dn):
            self.entry_dn = dn
            self.entry_attributes_as_dict = {}

    class FakeServiceConn:
        """Simulates an AD directory where sAMAccountName=jsmith is the
        only attribute the (default) filter ever matches against."""
        def __init__(self):
            self.entries = []

        def search(self, base_dn, search_filter, search_scope=None, attributes=None, size_limit=None):
            if "sAMAccountName=jsmith)" in search_filter:
                self.entries = [FakeEntry("CN=Jane Smith,OU=Users,DC=example,DC=com")]
                return True
            self.entries = []
            return False

        def unbind(self):
            pass

    class FakeUserConn:
        def __init__(self, server, user, password, auto_bind):
            self.bound = password == "correct-horse"

        def open(self):
            pass

        def start_tls(self):
            return True

        def bind(self):
            return self.bound

        def unbind(self):
            pass

    class FakeServer:
        ssl = False

    fake_service = FakeServiceConn()
    monkeypatch.setattr(
        app_module, "ldap_server_and_service_connection",
        lambda: (FakeServer(), fake_service),
    )
    monkeypatch.setattr(app_module, "Connection", FakeUserConn)

    with app.app_context():
        db.session.add(PlatformSetting(key="LDAP_ENABLED", value="true", encrypted=False))
        db.session.commit()

        for typed_username in ("jsmith", "jsmith@company.com", "CORP\\jsmith"):
            result = ldap_authenticate(typed_username, "correct-horse")
            assert result is not None, f"login failed for {typed_username!r}"

        # Wrong password still fails regardless of which form was typed.
        assert ldap_authenticate("jsmith@company.com", "wrong-password") is None
        # An account that genuinely doesn't exist under any form still fails.
        assert ldap_authenticate("nosuchuser@company.com", "correct-horse") is None


def test_login_forgot_password_link_hidden_by_default_when_ldap_also_enabled(client, app):
    """"Forgot your password?" only applies to a local account; when both
    local and AD/LDAP sign-in are available, the AD/LDAP provider is the
    default selection, so the link must start hidden (JS then toggles it
    live as the user changes the dropdown -- see static/platform.js)."""
    with app.app_context():
        db.session.add(PlatformSetting(key="LDAP_ENABLED", value="true", encrypted=False))
        db.session.add(PlatformSetting(key="LDAP_SERVER_URI", value="ldap://ldap.example.test", encrypted=False))
        db.session.commit()
    page = client.get("/login")
    assert b'data-auth-provider-select' in page.data
    assert b'data-forgot-password-link hidden' in page.data


def test_login_username_placeholder_derives_domain_from_ldap_base_dn(client, app):
    """The username field's ghost text should show the site's real UPN-style
    domain, derived from LDAP_BASE_DN's DC= components, not a generic
    placeholder -- and must fall back cleanly when LDAP is off or the base
    DN isn't configured yet."""
    with app.app_context():
        db.session.add(PlatformSetting(key="LDAP_ENABLED", value="true", encrypted=False))
        db.session.add(PlatformSetting(
            key="LDAP_BASE_DN", value="OU=Users,DC=corp,DC=example,DC=com", encrypted=False,
        ))
        db.session.commit()
    page = client.get("/login")
    assert b'placeholder="jsmith or jsmith@corp.example.com"' in page.data
    assert b'data-ldap-placeholder="jsmith or jsmith@corp.example.com"' in page.data

    with app.app_context():
        PlatformSetting.query.filter_by(key="LDAP_BASE_DN").delete()
        db.session.commit()
    page = client.get("/login")
    assert b'placeholder="jsmith"' in page.data

    with app.app_context():
        PlatformSetting.query.filter_by(key="LDAP_ENABLED").delete()
        db.session.add(PlatformSetting(key="LDAP_ENABLED", value="false", encrypted=False))
        db.session.commit()
    page = client.get("/login")
    assert b'placeholder="Username"' in page.data


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


def test_ticket_attachment_upload_degrades_gracefully_on_object_storage_outage(client, app, monkeypatch):
    """Found via real failure-injection testing against a disposable MinIO
    backend (B-052): an object-storage outage previously crashed this into
    a generic 500 and, worse, leaked the local temp file forever since the
    cleanup line was never reached. Now returns a clean, user-facing error
    and always removes the local temp file regardless of outcome."""
    login(client)
    assert client.post("/tickets/new/incident", data={
        "title": "Object storage outage test", "description": "For failure-injection coverage.",
        "category": "Software", "priority": "P3", "group_id": group_id(app),
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Object storage outage test").one()
        ticket_id = ticket.id

    class BrokenS3Client:
        def upload_file(self, *args, **kwargs):
            raise Exception("simulated object storage outage")

    monkeypatch.setattr("app.object_storage_enabled", lambda: True)
    monkeypatch.setattr("app.object_storage_client", lambda: BrokenS3Client())
    monkeypatch.setenv("OBJECT_STORAGE_BUCKET", "test-bucket")

    with app.app_context():
        upload_folder = app.config["UPLOAD_FOLDER"]
        before = set(os.listdir(upload_folder))

    response = client.post(
        f"/ticket/{ticket_id}/attachments",
        data={"file": (BytesIO(b"\xff\xd8\xffa real-looking jpeg"), "photo.jpg")},
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"temporarily unavailable" in response.data
    with app.app_context():
        assert FileAttachment.query.filter_by(ticket_id=ticket_id).count() == 0
        after = set(os.listdir(upload_folder))
        assert after == before  # no orphaned local temp file


def test_attachment_download_degrades_gracefully_on_object_storage_outage(client, app, monkeypatch):
    login(client)
    assert client.post("/tickets/new/incident", data={
        "title": "Object storage download outage test", "description": "For failure-injection coverage.",
        "category": "Software", "priority": "P3", "group_id": group_id(app),
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Object storage download outage test").one()
        ticket_id = ticket.id
        attachment = FileAttachment(
            ticket_id=ticket_id, uploaded_by_id=User.query.filter_by(username="admin").one().id,
            original_name="photo.jpg", stored_name="does-not-matter.jpg",
            mime_type="image/jpeg", size_bytes=10, sha256="x" * 64, scan_status="clean",
        )
        db.session.add(attachment)
        db.session.commit()
        attachment_id = attachment.id

    class BrokenS3Client:
        def get_object(self, *args, **kwargs):
            raise Exception("simulated object storage outage")

    monkeypatch.setattr("app.object_storage_enabled", lambda: True)
    monkeypatch.setattr("app.object_storage_client", lambda: BrokenS3Client())
    monkeypatch.setenv("OBJECT_STORAGE_BUCKET", "test-bucket")

    response = client.get(f"/attachments/{attachment_id}")
    assert response.status_code == 503


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


def test_cmdb_unmanaged_ci_class_visible_to_every_role(client, app):
    # B-288: the single most important test in this feature -- a CI class
    # with zero configured CiClassPermission rows must be exactly as visible
    # as before this feature existed, to every role that could see CMDB at
    # all pre-feature.
    with app.app_context():
        db.session.add(ConfigurationItem(name="unmanaged-srv.example.com", ci_class="Server"))
        db.session.commit()
    for username, password in (("admin", "Admin123!"), ("database.manager", "Manager123!")):
        login(client, username, password)
        page = client.get("/cmdb")
        assert b"unmanaged-srv.example.com" in page.data
        client.post("/logout")


def test_cmdb_managed_class_read_requires_explicit_grant(client, app):
    with app.app_context():
        unix_agent = User(
            username="ci-perm-agent", name="CI Perm Agent", email="ci-perm-agent@test.invalid",
            password_hash=generate_password_hash("Agent123!"), role="agent",
        )
        db.session.add(unix_agent)
        db.session.add(ConfigurationItem(name="managed-printer-01", ci_class="Printer"))
        db.session.add(CiClassPermission(
            tenant_id=1, ci_class="Printer", role="agent", can_read=True,
        ))
        db.session.commit()

    login(client, "ci-perm-agent", "Agent123!")
    granted = client.get("/cmdb")
    assert b"managed-printer-01" in granted.data
    client.post("/logout")

    login(client, "database.manager", "Manager123!")
    denied = client.get("/cmdb")
    assert b"managed-printer-01" not in denied.data


def test_cmdb_export_csv_respects_class_read_filter(client, app):
    with app.app_context():
        db.session.add(ConfigurationItem(name="export-hidden-01", ci_class="Consumable"))
        db.session.add(CiClassPermission(
            tenant_id=1, ci_class="Consumable", role="admin", can_read=False,
        ))
        db.session.commit()
    login(client)
    csv = client.get("/cmdb/export.csv")
    assert b"export-hidden-01" not in csv.data


def test_cmdb_topology_respects_class_read_filter(client, app):
    with app.app_context():
        db.session.add(ConfigurationItem(name="topology-hidden-01", ci_class="Consumable"))
        db.session.add(CiClassPermission(
            tenant_id=1, ci_class="Consumable", role="admin", can_read=False,
        ))
        db.session.commit()
    login(client)
    page = client.get("/cmdb/topology")
    assert b"topology-hidden-01" not in page.data


def test_cmdb_permissions_route_requires_admin(client, app):
    login(client, "employee", "Employee123!")
    assert client.get("/cmdb/permissions").status_code == 403
    assert client.post("/cmdb/permissions", data={}).status_code == 403
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert client.get("/cmdb/permissions").status_code == 403


def test_cmdb_permissions_grid_upserts_rows_and_audits(client, app):
    with app.app_context():
        db.session.add(ConfigurationItem(name="grid-test-01", ci_class="Router"))
        db.session.commit()
    login(client)
    response = client.post("/cmdb/permissions", data={
        "ci_class": ["Router"],
        "read__Router__agent": "on",
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        row = CiClassPermission.query.filter_by(tenant_id=1, ci_class="Router", role="agent").one()
        assert row.can_read is True
        no_grant_row = CiClassPermission.query.filter_by(
            tenant_id=1, ci_class="Router", role="manager",
        ).first()
        assert no_grant_row is None or no_grant_row.can_read is False
        assert Audit.query.filter_by(action="configure", target="CI class permission").count() == 1


def test_cmdb_permissions_add_new_class_marks_it_managed(client, app):
    login(client)
    client.post("/cmdb/permissions", data={"new_class": "Simcard"}, follow_redirects=True)
    with app.app_context():
        assert managed_ci_classes(1) >= {"Simcard"}


def test_cmdb_admin_create_is_always_allowed_regardless_of_class_permissions(client, app):
    # admin (and superadmin) always pass every CiClassPermission check --
    # this table only ever grants agent/manager capability they didn't have,
    # never restricts admin's pre-existing full CMDB access.
    with app.app_context():
        db.session.add(CiClassPermission(
            tenant_id=1, ci_class="Server", role="admin", can_read=False,
        ))
        db.session.commit()
    login(client)
    created = client.post("/cmdb/new", data={
        "name": "still-creatable.example.com", "ci_class": "Server",
        "environment": "Production", "operational_status": "Operational",
    }, follow_redirects=True)
    assert created.status_code == 200
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="still-creatable.example.com").count() == 1


def test_cmdb_agent_denied_create_without_explicit_grant(client, app):
    # B-291 (reopened per user request to match GLPI): agent/manager now
    # reach the CMDB create/update routes at all (previously admin-only),
    # but must never gain write access anyone didn't explicitly grant --
    # the default for create/update/delete is closed, unlike read.
    with app.app_context():
        agent = User(
            username="ci-perm-create-agent", name="CI Perm Create Agent",
            email="ci-perm-create-agent@test.invalid",
            password_hash=generate_password_hash("Agent123!"), role="agent",
        )
        db.session.add(agent)
        db.session.commit()
    login(client, "ci-perm-create-agent", "Agent123!")
    response = client.post("/cmdb/new", data={
        "name": "denied-create.example.com", "ci_class": "Server",
        "environment": "Production", "operational_status": "Operational",
    })
    assert response.status_code == 403
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="denied-create.example.com").count() == 0


def test_cmdb_agent_can_create_with_explicit_grant(client, app):
    with app.app_context():
        agent = User(
            username="ci-perm-create-agent2", name="CI Perm Create Agent 2",
            email="ci-perm-create-agent2@test.invalid",
            password_hash=generate_password_hash("Agent123!"), role="agent",
        )
        db.session.add(agent)
        db.session.add(CiClassPermission(tenant_id=1, ci_class="Server", role="agent", can_create=True))
        db.session.commit()
    login(client, "ci-perm-create-agent2", "Agent123!")
    response = client.post("/cmdb/new", data={
        "name": "granted-create.example.com", "ci_class": "Server",
        "environment": "Production", "operational_status": "Operational",
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="granted-create.example.com").count() == 1


def test_cmdb_manager_denied_update_without_explicit_grant(client, app):
    with app.app_context():
        db.session.add(ConfigurationItem(name="update-target-01", ci_class="Printer", tenant_id=1))
        db.session.commit()
        ci_id = ConfigurationItem.query.filter_by(name="update-target-01").one().id
    login(client, "database.manager", "Manager123!")
    get_response = client.get(f"/cmdb/{ci_id}/edit")
    assert get_response.status_code == 403
    post_response = client.post(f"/cmdb/{ci_id}/edit", data={
        "name": "update-target-01", "ci_class": "Printer",
        "environment": "Production", "operational_status": "Operational",
    })
    assert post_response.status_code == 403


def test_cmdb_manager_can_update_with_explicit_grant(client, app):
    with app.app_context():
        db.session.add(ConfigurationItem(name="update-target-02", ci_class="Printer", tenant_id=1))
        db.session.add(CiClassPermission(tenant_id=1, ci_class="Printer", role="manager", can_update=True))
        db.session.commit()
        ci_id = ConfigurationItem.query.filter_by(name="update-target-02").one().id
    login(client, "database.manager", "Manager123!")
    response = client.post(f"/cmdb/{ci_id}/edit", data={
        "name": "update-target-02-renamed", "ci_class": "Printer",
        "environment": "Production", "operational_status": "Operational",
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(ConfigurationItem, ci_id).name == "update-target-02-renamed"


def test_cmdb_relationship_add_requires_update_grant_on_both_endpoints(client, app):
    with app.app_context():
        db.session.add(ConfigurationItem(name="rel-parent", ci_class="Server", tenant_id=1))
        db.session.add(ConfigurationItem(name="rel-child", ci_class="Switch", tenant_id=1))
        # Manager is granted update on the parent's class but not the child's.
        db.session.add(CiClassPermission(tenant_id=1, ci_class="Server", role="manager", can_update=True))
        db.session.commit()
        parent_id = ConfigurationItem.query.filter_by(name="rel-parent").one().id
        child_id = ConfigurationItem.query.filter_by(name="rel-child").one().id
    login(client, "database.manager", "Manager123!")
    response = client.post("/cmdb/relationships", data={
        "parent_id": str(parent_id), "relationship_type": "Depends on", "child_id": str(child_id),
    })
    assert response.status_code == 403
    with app.app_context():
        assert CIRelationship.query.count() == 0


def test_cmdb_permissions_grid_saves_crud_columns(client, app):
    with app.app_context():
        db.session.add(ConfigurationItem(name="grid-crud-test", ci_class="Router", tenant_id=1))
        db.session.commit()
    login(client)
    client.post("/cmdb/permissions", data={
        "ci_class": ["Router"],
        "read__Router__agent": "on", "create__Router__agent": "on",
        "update__Router__agent": "on", "delete__Router__agent": "on",
    }, follow_redirects=True)
    with app.app_context():
        row = CiClassPermission.query.filter_by(tenant_id=1, ci_class="Router", role="agent").one()
        assert row.can_read and row.can_create and row.can_update and row.can_delete


def test_cmdb_discovery_target_stores_community_encrypted_not_plaintext(client, app):
    login(client)
    response = client.post("/cmdb/discovery", data={
        "name": "Core switch", "target_type": "host", "address": "10.0.0.1",
        "snmp_version": "2c", "snmp_port": "161", "community": "s3cr3t-community",
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        target = DiscoveryTarget.query.filter_by(name="Core switch").one()
        assert target.community_encrypted is not None
        assert "s3cr3t-community" not in target.community_encrypted
        assert target.community == "s3cr3t-community"


def test_cmdb_discovery_rejects_invalid_address(client, app):
    login(client)
    client.post("/cmdb/discovery", data={
        "name": "Bad target", "target_type": "subnet", "address": "not-a-cidr",
        "snmp_version": "2c", "snmp_port": "161", "community": "public",
    })
    with app.app_context():
        assert DiscoveryTarget.query.filter_by(name="Bad target").count() == 0


def test_cmdb_discovery_requires_security_administer(client, app):
    login(client, "employee", "Employee123!")
    assert client.get("/cmdb/discovery").status_code == 403
    assert client.post("/cmdb/discovery", data={
        "name": "x", "target_type": "host", "address": "10.0.0.1", "community": "public",
    }).status_code == 403


def test_cmdb_discovery_run_stages_candidates_without_creating_a_ci(client, app, monkeypatch):
    """Discovery runs -- manual or scheduled -- never create a CI by
    themselves anymore; a run only stages a DiscoveryCandidate row for
    administrator review (see test_cmdb_discovery_review_add_selected_*
    below for the actual import step)."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        target = DiscoveryTarget(
            name="Mocked switch", target_type="host", address="10.0.0.9",
            created_by_id=admin.id,
        )
        target.community = "public"
        db.session.add(target)
        db.session.commit()
        target_id = target.id

    def fake_discover_host(host, community, port=161, version="2c", timeout=2):
        assert host == "10.0.0.9"
        assert community == "public"
        return {
            "host": host, "sys_name": "mocked-switch-1", "sys_descr": "Cisco IOS",
            "sys_object_id": "1.3.6.1.4.1.9.1.1", "sys_uptime": "1", "vendor": "Cisco",
            "ci_class": "Network Switch", "interfaces": [], "arp_entries": [], "lldp_neighbors": [],
        }
    monkeypatch.setattr("serviceops_core.network_discovery.discover_host", fake_discover_host)

    login(client)
    response = client.post(f"/cmdb/discovery/{target_id}/run", follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        target = db.session.get(DiscoveryTarget, target_id)
        assert target.last_run_status == "ok"
        assert target.last_run_at is not None
        assert ConfigurationItem.query.filter_by(ip_address="10.0.0.9").count() == 0
        candidate = DiscoveryCandidate.query.filter_by(target_id=target_id).one()
        assert candidate.name == "mocked-switch-1"
        assert candidate.discovery_source == "SNMP Discovery"
        assert candidate.vendor == "Cisco"
        assert candidate.facts["sys_descr"] == "Cisco IOS"


def _stage_candidate(app, target_id, tenant_id, host="10.0.0.9", name="mocked-switch-1"):
    with app.app_context():
        candidate = DiscoveryCandidate(
            target_id=target_id, host=host, name=name, ci_class="Network Switch", vendor="Cisco",
            discovery_source="SNMP Discovery", tenant_id=tenant_id,
            facts={
                "host": host, "sys_name": name, "sys_descr": "Cisco IOS", "sys_object_id": "1.3.6.1.4.1.9.1.1",
                "sys_uptime": "1", "vendor": "Cisco", "ci_class": "Network Switch",
                "interfaces": [], "arp_entries": [], "lldp_neighbors": [],
                "discovery_source": "SNMP Discovery",
            },
        )
        db.session.add(candidate)
        db.session.commit()
        return candidate.id


def test_cmdb_discovery_review_add_selected_creates_only_checked_cis(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        target = DiscoveryTarget(name="Review target", target_type="subnet", address="10.0.0.0/24", created_by_id=admin.id)
        db.session.add(target)
        db.session.commit()
        target_id, tenant_id = target.id, target.tenant_id
    keep_id = _stage_candidate(app, target_id, tenant_id, host="10.0.0.9", name="keep-me")
    skip_id = _stage_candidate(app, target_id, tenant_id, host="10.0.0.10", name="skip-me")

    login(client)
    response = client.post(f"/cmdb/discovery/{target_id}/import", data={"candidate_id": [str(keep_id)]}, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert ConfigurationItem.query.filter_by(ip_address="10.0.0.9").count() == 1
        assert ConfigurationItem.query.filter_by(ip_address="10.0.0.10").count() == 0
        assert db.session.get(DiscoveryCandidate, keep_id) is None
        assert db.session.get(DiscoveryCandidate, skip_id) is not None  # left pending, not discarded


def test_cmdb_discovery_review_add_all_creates_every_candidate(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        target = DiscoveryTarget(name="Add all target", target_type="subnet", address="10.0.1.0/24", created_by_id=admin.id)
        db.session.add(target)
        db.session.commit()
        target_id, tenant_id = target.id, target.tenant_id
    _stage_candidate(app, target_id, tenant_id, host="10.0.1.9", name="host-a")
    _stage_candidate(app, target_id, tenant_id, host="10.0.1.10", name="host-b")

    login(client)
    response = client.post(f"/cmdb/discovery/{target_id}/import", data={"select_all": "1"}, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert ConfigurationItem.query.filter_by(ip_address="10.0.1.9").count() == 1
        assert ConfigurationItem.query.filter_by(ip_address="10.0.1.10").count() == 1
        assert DiscoveryCandidate.query.filter_by(target_id=target_id).count() == 0


def test_cmdb_discovery_review_discard_creates_nothing(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        target = DiscoveryTarget(name="Discard target", target_type="subnet", address="10.0.2.0/24", created_by_id=admin.id)
        db.session.add(target)
        db.session.commit()
        target_id, tenant_id = target.id, target.tenant_id
    _stage_candidate(app, target_id, tenant_id, host="10.0.2.9", name="never-added")

    login(client)
    response = client.post(f"/cmdb/discovery/{target_id}/discard", follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert ConfigurationItem.query.filter_by(ip_address="10.0.2.9").count() == 0
        assert DiscoveryCandidate.query.filter_by(target_id=target_id).count() == 0


def test_cmdb_discovery_review_requires_security_administer(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        target = DiscoveryTarget(name="Locked target", target_type="host", address="10.0.3.1", created_by_id=admin.id)
        db.session.add(target)
        db.session.commit()
        target_id = target.id

    login(client, "employee", "Employee123!")
    assert client.get(f"/cmdb/discovery/{target_id}/review").status_code == 403
    assert client.post(f"/cmdb/discovery/{target_id}/import", data={"select_all": "1"}).status_code == 403
    assert client.post(f"/cmdb/discovery/{target_id}/discard").status_code == 403


def test_cmdb_discovery_run_survives_snmp_failure(client, app, monkeypatch):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        target = DiscoveryTarget(name="Unreachable", target_type="host", address="10.0.0.250", created_by_id=admin.id)
        target.community = "public"
        db.session.add(target)
        db.session.commit()
        target_id = target.id

    def raising_discover_host(*args, **kwargs):
        raise ConnectionError("simulated network failure")
    monkeypatch.setattr("serviceops_core.network_discovery.discover_host", raising_discover_host)

    login(client)
    response = client.post(f"/cmdb/discovery/{target_id}/run", follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        target = db.session.get(DiscoveryTarget, target_id)
        assert target.last_run_status == "failed"
        assert "simulated network failure" in target.last_run_summary


def test_cmdb_discovery_target_is_tenant_scoped(client, app):
    with app.app_context():
        second_tenant = Tenant(id=2, slug="other-tenant", name="Other Tenant", active=True)
        db.session.add(second_tenant)
        admin = User.query.filter_by(username="admin").one()
        other_target = DiscoveryTarget(
            name="Other tenant target", target_type="host", address="10.0.0.1",
            created_by_id=admin.id, tenant_id=2,
        )
        db.session.add(other_target)
        db.session.commit()
        other_target_id = other_target.id

    login(client)
    assert client.post(f"/cmdb/discovery/{other_target_id}/run").status_code == 404
    assert client.post(f"/cmdb/discovery/{other_target_id}/delete").status_code == 404


def test_cmdb_discovery_schedule_skips_targets_not_yet_due(app, monkeypatch):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        due = DiscoveryTarget(
            name="Due target", target_type="host", address="10.0.0.11",
            created_by_id=admin.id, schedule_enabled=True, schedule_interval_minutes=5,
            last_run_at=now() - timedelta(minutes=10),
        )
        not_due = DiscoveryTarget(
            name="Not due target", target_type="host", address="10.0.0.12",
            created_by_id=admin.id, schedule_enabled=True, schedule_interval_minutes=60,
            last_run_at=now() - timedelta(minutes=5),
        )
        disabled = DiscoveryTarget(
            name="Disabled target", target_type="host", address="10.0.0.13",
            created_by_id=admin.id, schedule_enabled=False,
        )
        db.session.add_all([due, not_due, disabled])
        db.session.commit()
        due_id = due.id

    calls = []

    def fake_discover_host(host, community, port=161, version="2c", timeout=2):
        calls.append(host)
        return None
    monkeypatch.setattr("serviceops_core.network_discovery.discover_host", fake_discover_host)
    monkeypatch.setattr("serviceops_core.network_discovery.tcp_liveness_probe", lambda *a, **k: False)

    with app.app_context():
        processed = process_discovery_schedule()
        assert processed == 1
        assert calls == ["10.0.0.11"]
        assert DiscoveryCandidate.query.filter_by(target_id=due_id).count() == 0


def test_cmdb_topology_renders_nodes_and_edges(client, app):
    with app.app_context():
        parent = ConfigurationItem(name="topo-parent", ci_class="Server")
        child = ConfigurationItem(name="topo-child", ci_class="Server")
        db.session.add_all([parent, child])
        db.session.flush()
        db.session.add(CIRelationship(parent_id=parent.id, child_id=child.id, relationship_type="Connects to"))
        db.session.commit()
    login(client)
    response = client.get("/cmdb/topology")
    assert response.status_code == 200
    assert b"topo-parent" in response.data
    assert b"topo-child" in response.data
    # B-289: the graph payload moved from an inline <script> (silently
    # blocked by this app's script-src 'self' CSP -- the same class of bug
    # fixed for /api/v1/docs in B-276, confirmed here it was never actually
    # reaching the browser) into a data-* attribute the external JS file reads.
    assert b"<script>window.CMDB_TOPOLOGY_GRAPH" not in response.data
    assert b'data-graph="' in response.data


def test_cmdb_topology_excludes_virtual_machines(client, app):
    with app.app_context():
        db.session.add(ConfigurationItem(name="topo-physical-host", ci_class="Server"))
        db.session.add(ConfigurationItem(name="topo-a-vm", ci_class="Virtual Machine"))
        db.session.commit()
    login(client)
    response = client.get("/cmdb/topology")
    assert response.status_code == 200
    assert b"topo-physical-host" in response.data


def test_rack_list_shows_space_used_when_a_ci_has_no_height_set(client, app):
    """A CI placed in a rack with the Height (U) field left blank stores
    rack_u_height=NULL; SUM() over an all-NULL group returns SQL NULL, not
    0, which previously crashed rack_list()'s "used / rack.u_height"
    division outright (found via live browser verification, not a test)."""
    with app.app_context():
        rack = Rack(tenant_id=1, name="rack-no-height-test", u_height=42)
        db.session.add(rack)
        db.session.flush()
        db.session.add(ConfigurationItem(
            name="rack-no-height-ci", ci_class="Server", rack_id=rack.id,
            rack_position=1, rack_u_height=None,
        ))
        db.session.commit()
    login(client)
    response = client.get("/cmdb/racks")
    assert response.status_code == 200
    assert b"rack-no-height-test" in response.data


def test_rack_list_requires_agent_and_write_requires_admin(client, app):
    login(client, "employee", "Employee123!")
    assert client.get("/cmdb/racks").status_code == 403
    client.post("/logout")

    login(client, "database.manager", "Manager123!")
    assert client.get("/cmdb/racks").status_code == 200
    assert client.post("/cmdb/racks", data={"name": "rack-manager-attempt"}).status_code == 403
    client.post("/logout")

    login(client)
    response = client.post("/cmdb/racks", data={"name": "rack-test-01", "site": "CC1", "u_height": "42"})
    assert response.status_code == 302
    with app.app_context():
        rack = Rack.query.filter_by(name="rack-test-01").one()
        assert (rack.site, rack.u_height, rack.tenant_id) == ("CC1", 42, 1)


def test_rack_delete_blocked_while_ci_still_mounted(client, app):
    login(client)
    with app.app_context():
        rack = Rack(tenant_id=1, name="rack-delete-test", u_height=42)
        db.session.add(rack)
        db.session.flush()
        db.session.add(ConfigurationItem(
            name="rack-delete-ci", ci_class="Server", rack_id=rack.id, rack_position=1, rack_u_height=1,
        ))
        db.session.commit()
        rack_id = rack.id
    response = client.post(f"/cmdb/racks/{rack_id}/delete", follow_redirects=True)
    assert response.status_code == 200
    assert b"still mounted" in response.data
    with app.app_context():
        assert db.session.get(Rack, rack_id) is not None

    with app.app_context():
        ConfigurationItem.query.filter_by(name="rack-delete-ci").update({"rack_id": None})
        db.session.commit()
    response = client.post(f"/cmdb/racks/{rack_id}/delete", follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(Rack, rack_id) is None


def test_rack_elevation_places_devices_and_respects_class_read_permission(client, app):
    with app.app_context():
        rack = Rack(tenant_id=1, name="rack-elevation-test", u_height=42)
        db.session.add(rack)
        db.session.flush()
        db.session.add(ConfigurationItem(
            name="rack-elevation-visible", ci_class="Server", rack_id=rack.id,
            rack_position=10, rack_u_height=2, rack_face="front",
        ))
        db.session.add(ConfigurationItem(
            name="rack-elevation-hidden", ci_class="Consumable", rack_id=rack.id,
            rack_position=20, rack_u_height=1, rack_face="front",
        ))
        db.session.add(CiClassPermission(tenant_id=1, ci_class="Consumable", role="admin", can_read=False))
        db.session.commit()
        rack_id = rack.id
    login(client)
    response = client.get(f"/cmdb/racks/{rack_id}")
    assert response.status_code == 200
    assert b"rack-elevation-visible" in response.data
    assert b"rack-elevation-hidden" not in response.data


def test_rack_elevation_highlight_param_and_embed_route(client, app):
    with app.app_context():
        rack = Rack(tenant_id=1, name="rack-highlight-test", u_height=42)
        db.session.add(rack)
        db.session.flush()
        ci = ConfigurationItem(
            name="rack-highlight-ci", ci_class="Server", rack_id=rack.id,
            rack_position=10, rack_u_height=2, rack_face="front",
        )
        db.session.add(ci)
        db.session.commit()
        rack_id, ci_id = rack.id, ci.id
    login(client)
    response = client.get(f"/cmdb/racks/{rack_id}?highlight={ci_id}")
    assert response.status_code == 200
    # The JSON payload is embedded via an HTML data-* attribute (escaped by
    # Jinja autoescaping, e.g. '"' -> '&#34;'), so check for the un-escaped
    # substrings rather than a literal JSON snippet -- see B-292/B-289 for
    # the same lesson learned with the topology graph payload.
    assert b"highlight_ci_id" in response.data
    assert str(ci_id).encode() in response.data

    embed_response = client.get(f"/cmdb/racks/{rack_id}/embed?highlight={ci_id}")
    assert embed_response.status_code == 200
    assert b"rack-highlight-ci" in embed_response.data
    assert b"<html" in embed_response.data
    assert b"sidebar" not in embed_response.data


def test_ci_form_shows_embedded_rack_preview_when_placed(client, app):
    with app.app_context():
        rack = Rack(tenant_id=1, name="rack-preview-test", u_height=42)
        db.session.add(rack)
        db.session.flush()
        ci = ConfigurationItem(
            name="rack-preview-ci", ci_class="Server", rack_id=rack.id,
            rack_position=3, rack_u_height=1, rack_face="front",
        )
        db.session.add(ci)
        db.session.commit()
        rack_id, ci_id = rack.id, ci.id
        unracked = ConfigurationItem(name="rack-preview-unracked", ci_class="Server")
        db.session.add(unracked)
        db.session.commit()
        unracked_id = unracked.id
    login(client)
    placed_page = client.get(f"/cmdb/{ci_id}/edit")
    assert f'/cmdb/racks/{rack_id}/embed?highlight={ci_id}'.encode() in placed_page.data

    unracked_page = client.get(f"/cmdb/{unracked_id}/edit")
    assert b"Rack &amp; network placement" not in unracked_page.data
    assert b"/embed?highlight=" not in unracked_page.data


def test_ci_detail_shows_switch_and_server_network_connections(client, app):
    """A switch's CI page lists every server plugged into it, and a
    server's page shows the switch it connects to -- both directions of
    the same "Connects to" CIRelationship, with port labels."""
    with app.app_context():
        switch = ConfigurationItem(name="net-conn-switch", ci_class="Switch")
        server = ConfigurationItem(name="net-conn-server", ci_class="Server")
        hidden_class_server = ConfigurationItem(name="net-conn-hidden", ci_class="Consumable")
        db.session.add_all([switch, server, hidden_class_server])
        db.session.flush()
        db.session.add(CIRelationship(
            parent_id=switch.id, child_id=server.id, relationship_type="Connects to",
            label="Ethernet51 <-> eth0",
        ))
        db.session.add(CIRelationship(
            parent_id=switch.id, child_id=hidden_class_server.id, relationship_type="Connects to",
            label="Ethernet52 <-> eth0",
        ))
        db.session.add(CiClassPermission(tenant_id=1, ci_class="Consumable", role="admin", can_read=False))
        db.session.commit()
        switch_id, server_id = switch.id, server.id

    login(client)
    switch_page = client.get(f"/cmdb/{switch_id}/edit")
    assert b"Connected servers" in switch_page.data
    assert b"net-conn-server" in switch_page.data
    assert b"Ethernet51" in switch_page.data
    # A class this admin has explicitly had read access revoked for must
    # not leak through the connections list either.
    assert b"net-conn-hidden" not in switch_page.data

    server_page = client.get(f"/cmdb/{server_id}/edit")
    assert b"Connects to" in server_page.data
    assert b"net-conn-switch" in server_page.data
    assert b"eth0" in server_page.data


def test_ci_form_round_trips_manual_rack_placement(client, app):
    with app.app_context():
        rack = Rack(tenant_id=1, name="rack-manual-place", u_height=42)
        db.session.add(rack)
        db.session.commit()
        rack_id = rack.id
    login(client)
    response = client.post("/cmdb/new", data={
        "name": "manual-rack-ci", "ci_class": "Server", "environment": "Production",
        "operational_status": "Operational", "rack_id": str(rack_id),
        "rack_position": "5.5", "rack_u_height": "2", "rack_face": "rear",
    })
    assert response.status_code == 302
    with app.app_context():
        ci = ConfigurationItem.query.filter_by(name="manual-rack-ci").one()
        assert ci.rack_id == rack_id
        assert ci.rack_position == 5.5
        assert ci.rack_u_height == 2
        assert ci.rack_face == "rear"
        ci_id = ci.id

    cmdb_page = client.get("/cmdb?q=manual-rack-ci")
    assert f'href="/cmdb/{ci_id}/edit"'.encode() in cmdb_page.data

    detail_page = client.get(f"/cmdb/{ci_id}/edit")
    assert f'href="/cmdb/racks/{rack_id}?highlight={ci_id}"'.encode() in detail_page.data
    assert b"rack-manual-place" in detail_page.data


def test_cmdb_network_info_resolves_hostname_and_ip(client, app, monkeypatch):
    with app.app_context():
        ci = ConfigurationItem(name="dns-test-host", ci_class="Server", ip_address="203.0.113.5")
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id

    monkeypatch.setattr(
        "serviceops_core.dns_lookup.socket.gethostbyaddr",
        lambda ip: ("dns-test-host.example.com", [], [ip]),
    )
    monkeypatch.setattr(
        "serviceops_core.dns_lookup.socket.getaddrinfo",
        lambda host, port: [(None, None, None, None, ("203.0.113.5", 0))],
    )
    login(client)
    response = client.get(f"/cmdb/{ci_id}/network-info")
    assert response.status_code == 200
    body = response.get_json()
    assert body["addresses"] == [{"ip": "203.0.113.5", "hostname": "dns-test-host.example.com"}]
    assert body["hostnames"] == [{"hostname": "dns-test-host", "ips": ["203.0.113.5"]}]


def test_cmdb_network_info_degrades_gracefully_when_dns_fails(client, app, monkeypatch):
    with app.app_context():
        ci = ConfigurationItem(name="dns-fail-host", ci_class="Server", ip_address="203.0.113.6")
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id

    def raise_os_error(*args, **kwargs):
        raise OSError("no PTR record")

    monkeypatch.setattr("serviceops_core.dns_lookup.socket.gethostbyaddr", raise_os_error)
    monkeypatch.setattr("serviceops_core.dns_lookup.socket.getaddrinfo", raise_os_error)
    login(client)
    response = client.get(f"/cmdb/{ci_id}/network-info")
    assert response.status_code == 200
    body = response.get_json()
    assert body["addresses"] == [{"ip": "203.0.113.6", "hostname": ""}]
    assert body["hostnames"] == [{"hostname": "dns-fail-host", "ips": []}]


def test_cmdb_network_info_respects_class_read_permission(client, app):
    with app.app_context():
        ci = ConfigurationItem(name="dns-restricted-host", ci_class="Consumable", ip_address="203.0.113.7")
        db.session.add(ci)
        db.session.add(CiClassPermission(tenant_id=1, ci_class="Consumable", role="admin", can_read=False))
        db.session.commit()
        ci_id = ci.id
    login(client)
    assert client.get(f"/cmdb/{ci_id}/network-info").status_code == 403


def test_admin_home_is_a_searchable_index_that_surfaces_deeply_nested_components(client):
    """User-reported: small components like "LDAP directory sync" (a
    sub-section deep inside the Service delivery & governance mega-page)
    had no menu entry or way to find them except already knowing where to
    look. Administration home is now a comprehensive, live-searchable
    index -- every meaningful admin capability gets its own card with a
    direct deep link (existing in-page anchors, not new/duplicated ones),
    including ones nested inside other pages."""
    login(client)
    page = client.get("/admin")
    assert page.status_code == 200
    assert b"data-admin-quick-find" in page.data
    # The exact reported example: findable, and deep-linked to its own
    # isolated page. B-322: LDAP directory sync moved onto the Sign-in and
    # directory settings page, together with the rest of the AD/LDAP
    # config it was previously split apart from.
    assert b"/admin/settings/sign_in_and_directory" in page.data
    assert b"Sign-in &amp; directory" in page.data
    assert b'data-keywords="sign in login ldap keycloak' in page.data
    # A sample of other previously-hard-to-find components, each a real
    # card with a real deep link to its own isolated settings page.
    assert b"/service-operations/settings/change-freeze" in page.data
    assert b"/service-operations/settings/sla" in page.data
    assert b'href="/admin/settings/security"' in page.data


def test_admin_home_has_no_duplicate_card_destinations(client):
    """User-reported: 'duplicate links here and there' in the admin
    section -- confirmed for real: admin_access.html previously had two
    separate cards ("Groups & teams" and "Client management access")
    both pointing at the exact same itil_admin#team-managers destination,
    and admin_home.html separately had both a "Groups & teams" card
    (routed through the admin_access hub as an extra hop) and a "Team
    ownership" card pointing directly at the same underlying page --
    genuinely overlapping, not just superficially similar. Every card's
    href on both pages must now be unique."""
    login(client)
    for path in ("/admin", "/admin/access"):
        page = client.get(path)
        hrefs = re.findall(rb'class="admin-capability-card"[^>]*href="([^"]+)"', page.data)
        assert hrefs, f"no capability cards found on {path}"
        assert len(hrefs) == len(set(hrefs)), (
            f"duplicate card destination(s) on {path}: "
            f"{[h for h in hrefs if hrefs.count(h) > 1]}"
        )


def test_settings_pages_are_decentralized_into_isolated_pages(client):
    """User-reported (B-320): even correctly-working client-side tabs
    within one mega-page were rejected outright -- "this is duplicated or
    when i click on the icon on multiple things, comes to this same
    place. we need to decentralized each section into isolated settings
    pages." Platform settings and Service delivery & governance are now
    index/card pages linking to genuinely separate URLs; each isolated
    page renders only its own category's fields, not any other
    category's."""
    login(client)
    index = client.get("/admin/settings")
    assert index.status_code == 200
    assert b"/admin/settings/security" in index.data
    assert b"/admin/settings/organization" in index.data

    security = client.get("/admin/settings/security")
    assert security.status_code == 200
    assert b"MFA" in security.data or b"Security" in security.data
    assert b"COMPANY_NAME" not in security.data

    organization = client.get("/admin/settings/organization")
    assert organization.status_code == 200
    assert b"security" not in organization.data.lower() or b"Security and limits" not in organization.data

    governance_index = client.get("/service-operations/settings")
    assert governance_index.status_code == 200
    assert b"/service-operations/settings/sla" in governance_index.data

    sla = client.get("/service-operations/settings/sla")
    assert sla.status_code == 200
    assert b"business calendar" in sla.data.lower()
    assert b"Change freeze window" not in sla.data

    freeze = client.get("/service-operations/settings/change-freeze")
    assert freeze.status_code == 200
    assert b"freeze" in freeze.data.lower()
    assert b"Add business schedule" not in freeze.data

    assert client.get("/service-operations/settings/not-a-real-section").status_code == 404
    assert client.get("/admin/settings/not-a-real-category").status_code == 404


def test_admin_access_hub_requires_admin(client):
    login(client, "employee", "Employee123!")
    assert client.get("/admin/access").status_code == 403
    client.post("/logout")
    login(client)
    assert client.get("/admin/access").status_code == 200


def test_admin_roles_page_shows_policy_and_requires_admin(client):
    login(client, "database.manager", "Manager123!")
    assert client.get("/admin/roles").status_code == 403
    client.post("/logout")
    login(client)
    response = client.get("/admin/roles")
    assert response.status_code == 200
    assert b"Agent" in response.data
    assert b"security_administer" in response.data


def test_admin_roles_save_creates_override_and_takes_effect(client, app):
    """Revoking an action a role's baseline grants must actually change
    what that role can do, not just what the grid displays -- verified
    against a real @require_action-gated route (comment_internal)."""
    login(client)
    get_page = client.get("/admin/roles")
    assert b'name="grant__agent__comment_internal" checked' in get_page.data

    form_data = {"action": "save"}
    with app.app_context():
        from serviceops_core.security import load_policy
        policy = load_policy()
        for role in ("requester", "agent", "manager", "admin"):
            for act in policy["actions"]:
                if act in policy["roles"].get(role, ()) and not (role == "agent" and act == "comment_internal"):
                    form_data[f"grant__{role}__{act}"] = "on"
    response = client.post("/admin/roles", data=form_data)
    assert response.status_code == 302
    with app.app_context():
        override = RolePolicyOverride.query.filter_by(tenant_id=1, role="agent", action="comment_internal").one()
        assert override.is_granted is False

    page_after = client.get("/admin/roles")
    assert b'name="grant__agent__comment_internal" checked' not in page_after.data


def test_admin_roles_page_hides_admin_panel_gated_actions_for_non_admin_roles(client, app):
    """User-reported: granting agent/manager 'administer', 'security_administer',
    or 'platform_administer' via this page did nothing -- every admin panel
    route is gated by @roles('admin')/@roles('superadmin'), a hardcoded
    check independent of this action-based policy, so those two actions
    can never take effect for a non-admin role. The page must not offer
    them as if they would. security_administer is the one exception (it
    also independently governs CMDB Discovery access with no role gate),
    so it must stay editable for agent/manager."""
    login(client)
    page = client.get("/admin/roles")
    assert b'name="grant__agent__administer"' not in page.data
    assert b'name="grant__manager__administer"' not in page.data
    assert b'name="grant__agent__platform_administer"' not in page.data
    assert b'name="grant__manager__platform_administer"' not in page.data
    assert b'name="grant__admin__administer"' in page.data
    assert b'name="grant__agent__security_administer"' in page.data
    assert b'name="grant__manager__security_administer"' in page.data


def test_admin_roles_page_marks_unenforced_actions_and_never_saves_overrides_for_them(client, app):
    """Full audit finding: delete/purge/approve/accept/close/reopen/
    delegate/relate/discover/read are never checked by any route or
    inline effective_role_has_action() call, for any role -- real
    authorization for those operations happens through separate,
    hardcoded @roles(...) + team-membership rules instead. The page must
    not present them as editable controls, and a save must never create
    a bogus override for one even when its checkbox is (necessarily)
    absent from the submitted form, which would otherwise be
    misread as "explicitly revoke this role's baseline grant"."""
    login(client)
    page = client.get("/admin/roles")
    assert b'name="grant__manager__approve"' not in page.data
    assert b'name="grant__agent__reopen"' not in page.data
    assert b"not yet enforced" in page.data

    # manager's baseline includes "approve" -- saving the form (with no
    # grant__manager__approve field submitted at all, since it's hidden)
    # must not create an override that revokes it.
    with app.app_context():
        from serviceops_core.security import load_policy
        policy = load_policy()
        assert "approve" in policy["roles"]["manager"]

    form_data = {"action": "save"}
    with app.app_context():
        for role in ("requester", "agent", "manager", "admin"):
            for act in policy["actions"]:
                if act in policy["roles"].get(role, ()):
                    form_data[f"grant__{role}__{act}"] = "on"
    response = client.post("/admin/roles", data=form_data)
    assert response.status_code == 302
    with app.app_context():
        assert RolePolicyOverride.query.filter_by(
            tenant_id=1, role="manager", action="approve",
        ).first() is None


def test_admin_roles_reset_removes_overrides_and_restores_baseline(client, app):
    with app.app_context():
        db.session.add(RolePolicyOverride(tenant_id=1, role="agent", action="comment_internal", is_granted=False))
        db.session.commit()
    login(client)
    response = client.post("/admin/roles", data={"action": "reset", "role": "agent"})
    assert response.status_code == 302
    with app.app_context():
        assert RolePolicyOverride.query.filter_by(tenant_id=1, role="agent").count() == 0

    # superadmin must never be resettable/overridable through this route.
    assert client.post("/admin/roles", data={"action": "reset", "role": "superadmin"}).status_code == 400


def test_admin_roles_override_is_tenant_scoped(client, app):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="roles-test-tenant-2", name="Roles Test Tenant 2"))
        db.session.add(RolePolicyOverride(tenant_id=2, role="agent", action="comment_internal", is_granted=False))
        db.session.commit()
    login(client)
    # Tenant 1's admin session must see tenant 1's (unmodified) grid, not
    # tenant 2's override.
    page = client.get("/admin/roles")
    assert b'name="grant__agent__comment_internal" checked' in page.data


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
