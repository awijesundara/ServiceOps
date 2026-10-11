"""Review fixes 2026-10-11: Chat escalation governance, enterprise update
validation, LDAP username adoption, backup-code shape, tenant-wide approval
group uniqueness and Cloudflare Access key rotation."""
import pytest
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

import app as app_module
from app import (
    ApprovalAuthorityGroup, ApprovalChain, EnterpriseRecord, SupportGroup, Tenant, Ticket,
    TicketAssignmentGroup, User, db, google_chat_handle_command, provision_external_user,
    ticket_owning_group,
)
from serviceops_core.security import consume_backup_code, hash_backup_code
from tests.test_app import app, client, group_id, login  # noqa: F401 - pytest fixtures and helpers


# --- Google Chat /escalate ------------------------------------------------------------


def test_chat_escalation_of_a_change_supersedes_its_approvals(client, app):
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Chat escalated change", "description": "Purpose.",
        "category": "Software", "priority": "P2", "change_type": "Normal",
        "risk_score": "50", "impact": "Medium", "group_id": group_id(app),
        "implementation_plan": "Deploy.", "test_plan": "Test.", "backout_plan": "Restore.",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00",
    }).status_code == 302
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Chat escalated change").one()
        old_chain_id = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id).one().id
        admin = User.query.filter_by(username="admin").one()
        reply = google_chat_handle_command("escalate", "Database", ticket, admin)
        db.session.commit()
        assert reply == f"{ticket.number} escalated to Database."
        assert ticket_owning_group(ticket).name == "Database"
        assert db.session.get(ApprovalChain, old_chain_id).state == "Superseded"
        assert ticket.change_revision.revision == 2


def test_chat_escalation_refuses_governance_groups(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        if not SupportGroup.query.filter_by(name="Executive Office", tenant_id=admin.tenant_id).first():
            db.session.add(SupportGroup(name="Executive Office", group_type="Executive", tenant_id=admin.tenant_id))
        ticket = Ticket(number="INC9998001", kind="incident", title="x", description="x",
                        category="Software", priority="P3", state="New",
                        requester_id=admin.id, tenant_id=admin.tenant_id)
        db.session.add(ticket)
        db.session.flush()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=windows.id))
        db.session.commit()
        assert "No active team" in google_chat_handle_command("escalate", "Executive Office", ticket, admin)
        assert ticket_owning_group(ticket).id == windows.id


# --- Enterprise record update ---------------------------------------------------------


def enterprise_record(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        record = EnterpriseRecord(
            number="EVT0009401", domain="event", record_type="Event", title="Disk", description="x",
            requester_id=admin.id, support_group_id=group_id(app), tenant_id=admin.tenant_id,
        )
        db.session.add(record)
        db.session.commit()
        return record.id


def update(client, record_id, **fields):
    data = {"action": "update", "state": "In Progress", "priority": "P3", "risk": "Medium"}
    data.update(fields)
    return client.post(f"/enterprise/{record_id}", data=data)


def test_enterprise_update_rejects_malformed_and_cross_tenant_assignees(client, app):
    record_id = enterprise_record(app)
    with app.app_context():
        other = Tenant(slug="enterprise-assignee", name="Other organisation")
        db.session.add(other)
        db.session.flush()
        outsider = User(username="other.agent", name="Other Agent", email="other.agent@test.invalid",
                        password_hash=generate_password_hash("Passw0rd!x"), role="agent", tenant_id=other.id)
        employee = User.query.filter_by(username="employee").one()
        db.session.add(outsider)
        db.session.commit()
        outsider_id, employee_id = outsider.id, employee.id
    login(client)
    for value in ("abc", "1.5", str(outsider_id), str(employee_id), "999999"):
        assert update(client, record_id, assignee_id=value).status_code == 400, value
    with app.app_context():
        record = db.session.get(EnterpriseRecord, record_id)
        assert record.assignee_id is None and record.state != "In Progress"


def test_enterprise_update_validates_priority_and_risk_and_accepts_good_input(client, app):
    record_id = enterprise_record(app)
    login(client)
    assert update(client, record_id, priority="P9").status_code == 400
    assert update(client, record_id, risk="Catastrophic").status_code == 400
    with app.app_context():
        agent_id = User.query.filter_by(username="database.manager").one().id
    assert update(client, record_id, priority="P2", risk="High", assignee_id=str(agent_id)).status_code == 302
    with app.app_context():
        record = db.session.get(EnterpriseRecord, record_id)
        assert (record.priority, record.risk, record.assignee_id, record.state) == ("P2", "High", agent_id, "In Progress")


def test_enterprise_form_posts_canonical_values_and_lists_only_same_tenant_agents(client, app):
    record_id = enterprise_record(app)
    login(client)
    page = client.get(f"/enterprise/{record_id}").get_data(as_text=True)
    assert '<option value="P3"' in page and '<option value="Medium"' in page
    assert "Employee" not in page.split('name="assignee_id"', 1)[1].split("</select>", 1)[0]


# --- LDAP username adoption -----------------------------------------------------------


def test_ldap_username_match_never_adopts_an_administrator(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        user = provision_external_user("ldap", "CN=admin,DC=corp,DC=example", "admin", "Directory Admin",
                                       "someone.else@corp.example", {"requester": None})
        db.session.commit()
        assert user.id != admin.id and user.username == "admin-2"
        assert user.effective_role == "requester"


def test_ldap_username_match_still_adopts_an_imported_placeholder(app):
    with app.app_context():
        placeholder = User(username="jsmith", name="J Smith", email="jsmith@rt-import.invalid",
                           password_hash=generate_password_hash("x" * 20), role="requester")
        db.session.add(placeholder)
        db.session.commit()
        user = provision_external_user("ldap", "CN=jsmith,DC=corp,DC=example", "jsmith", "John Smith",
                                       "", {"requester": None})
        assert user.id == placeholder.id


# --- Backup codes ----------------------------------------------------------------------


def test_backup_code_shape_is_checked_before_any_hash(monkeypatch):
    stored = [hash_backup_code("ab12cd34ef")]
    calls = []
    monkeypatch.setattr("serviceops_core.security.verify_password", lambda *a: calls.append(a) or False)
    for attempt in ("123456", "ab12cd34e", "ab12cd34efg", "zz12cd34ef", ""):
        assert consume_backup_code(stored, attempt) is None
    assert calls == []


# --- Tenant-wide approval group uniqueness ---------------------------------------------


def test_tenant_wide_authority_cannot_link_the_same_group_twice(app):
    with app.app_context():
        group = SupportGroup.query.filter_by(name="Database").one()
        for _ in range(2):
            db.session.add(ApprovalAuthorityGroup(tenant_id=group.tenant_id, authority="ccb", group_id=group.id))
        with pytest.raises(IntegrityError):
            db.session.flush()
        db.session.rollback()
        team = SupportGroup.query.filter_by(name="Windows").one()
        # Per-team links stay independent of the tenant-wide one.
        db.session.add(ApprovalAuthorityGroup(tenant_id=group.tenant_id, authority="team_manager",
                                              subject_group_id=team.id, group_id=group.id))
        db.session.add(ApprovalAuthorityGroup(tenant_id=group.tenant_id, authority="team_manager",
                                              group_id=group.id))
        db.session.flush()


# --- Cloudflare Access key rotation ------------------------------------------------------


def test_access_keys_refresh_once_when_a_token_does_not_verify(app, monkeypatch):
    from serviceops_core import external_identity
    fetches = []

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"keys": []}

    monkeypatch.setattr(external_identity.requests, "get", lambda *a, **k: fetches.append(1) or Response())
    monkeypatch.setattr(external_identity.KeySet, "import_key_set", staticmethod(lambda data: object()))
    cache = external_identity._cloudflare_access_jwks_cache
    with app.app_context():
        app.config.update(CLOUDFLARE_ACCESS_TEAM_DOMAIN="team.example", CLOUDFLARE_ACCESS_AUD="aud")
        try:
            cache.update(key_set=object(), fetched_at=external_identity.time_module.monotonic() - 600)
            assert external_identity.verify_cloudflare_access_jwt("not-a-jwt") is None
            assert len(fetches) == 1  # stale enough: one refetch
            assert external_identity.verify_cloudflare_access_jwt("not-a-jwt") is None
            assert len(fetches) == 1  # fetched under a minute ago: no second request
        finally:
            cache.update(key_set=None, fetched_at=0.0)
            app.config.update(CLOUDFLARE_ACCESS_TEAM_DOMAIN="", CLOUDFLARE_ACCESS_AUD="")
