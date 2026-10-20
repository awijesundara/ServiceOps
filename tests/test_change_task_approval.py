"""A change task assigned to another team needs that team's lead to approve the change."""
from werkzeug.security import generate_password_hash

from app import ApprovalChain, OperationalTask, SupportGroup, Ticket, User, db
from serviceops_core import approval_policies
from tests.test_app import app, client, group_id, login  # noqa: F401

WINDOW = {"planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00"}


def _network_lead(app, with_manager=True):
    with app.app_context():
        network = SupportGroup.query.filter_by(name="Network").one()
        lead = User(username="network.lead", name="Network Lead", email="network.lead@test.invalid",
                    role="manager", password_hash=generate_password_hash("NetworkLead123!"))
        db.session.add(lead)
        db.session.flush()
        network.manager_id = lead.id if with_manager else None
        db.session.commit()
        return network.id, lead.id


def _change(client, app, title):
    assert client.post("/tickets/new/change", data={
        "title": title, "description": "Cross-team work.", "category": "Software", "priority": "P3",
        "change_type": "Standard", "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "Implement.", "test_plan": "Test.", "backout_plan": "Back out.", **WINDOW,
    }).status_code == 302
    with app.app_context():
        return Ticket.query.filter_by(title=title).one().id


def _add_task(client, ticket_id, group, task_type="Implementation", title="Network cut-over"):
    return client.post(f"/change/{ticket_id}/tasks", data={
        "title": title, "task_type": task_type, "group_id": group, "required": "1",
        "planned_start": "2026-08-01T10:00", "planned_end": "2026-08-01T11:00",
    })


def _running_chain(app, ticket_id):
    with app.app_context():
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket_id, state="Running").one()
        return [(gate.name, sorted(vote.approver_id for vote in gate.votes)) for gate in chain.gates]


def test_a_task_for_another_team_asks_that_team_lead_to_approve(client, app):
    network_id, lead_id = _network_lead(app)
    login(client)
    ticket_id = _change(client, app, "Cross-team cut-over")
    assert _add_task(client, ticket_id, network_id).status_code == 302
    gates = _running_chain(app, ticket_id)
    # The lead decides in the same parallel step as the owning team's manager.
    assert any("Network manager approval (change task)" in name and lead_id in ids for name, ids in gates)
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Awaiting Approval"
        network_task = OperationalTask.query.filter_by(parent_id=ticket_id, assignment_group_id=network_id).one()
        task_id = network_task.id
        owning = [vote for gate in ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket_id,
                                                                 state="Running").one().gates
                  for vote in gate.votes if vote.approver_id != lead_id]
        owning_ids = {(vote.id, vote.approver.username) for vote in owning}
    # The Network implementation task cannot start before its lead has approved.
    client.post("/logout")
    for vote_id, username in owning_ids:
        login(client, username, "Manager123!")
        assert client.post(f"/approval-votes/{vote_id}/decide", data={"decision": "Approved"}).status_code == 302
        client.post("/logout")
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Awaiting Approval"
        vote = next(v for gate in ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket_id,
                                                                state="Running").one().gates
                    for v in gate.votes if v.approver_id == lead_id)
        vote_id = vote.id
    login(client, "network.lead", "NetworkLead123!")
    assert client.post(f"/approval-votes/{vote_id}/decide", data={"decision": "Approved"}).status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Approved"
        assert db.session.get(OperationalTask, task_id).state == "Pending"


def test_a_task_for_the_owning_team_adds_no_extra_approval(client, app):
    login(client)
    ticket_id = _change(client, app, "Same-team task")
    assert _add_task(client, ticket_id, group_id(app), task_type="Testing", title="Smoke test").status_code == 302
    assert not any("(change task)" in name for name, _ in _running_chain(app, ticket_id))


def test_a_team_without_a_lead_cannot_be_given_a_task_silently(client, app):
    network_id, _ = _network_lead(app, with_manager=False)
    login(client)
    ticket_id = _change(client, app, "Leaderless team task")
    response = _add_task(client, ticket_id, network_id)
    assert response.status_code == 409
    assert b"assigned a change task" in response.data and b"manager or approval group" in response.data
    with app.app_context():
        assert OperationalTask.query.filter_by(parent_id=ticket_id, assignment_group_id=network_id).count() == 0


def test_cancelled_tasks_do_not_pull_their_team_into_approval(client, app):
    network_id, _ = _network_lead(app)
    login(client)
    ticket_id = _change(client, app, "Cancelled cross-team task")
    _add_task(client, ticket_id, network_id)
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        OperationalTask.query.filter_by(parent_id=ticket_id, assignment_group_id=network_id).one().state = "Cancelled"
        db.session.flush()
        from app import change_task_groups
        assert network_id not in {group.id for group in change_task_groups(ticket)}


def test_the_default_change_policy_includes_the_task_team_stage(app):
    with app.app_context():
        tenant_id = User.query.filter_by(username="admin").one().tenant_id
        policy = approval_policies.default_policy(tenant_id, "change")
        sources = [stage.source for stage in policy.stages]
        assert sources.index("task_team_managers") == sources.index("service_coowner_team_managers") + 1
        assert sources.index("task_team_managers") < min(i for i, s in enumerate(sources) if s == "group")
        assert "task_team_managers" in approval_policies.SOURCES


def test_migration_adds_the_stage_to_existing_change_policies(app):
    import importlib.util
    from pathlib import Path
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from serviceops_models import ApprovalPolicyStage
    path = Path(__file__).resolve().parents[1] / "migrations/versions/20261020_0135_change_task_team_approval.py"
    spec = importlib.util.spec_from_file_location("migration_0135", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with app.app_context():
        tenant_id = User.query.filter_by(username="admin").one().tenant_id
        policy = approval_policies.default_policy(tenant_id, "change")
        # Simulate an installation created before this stage existed.
        stage = next(s for s in policy.stages if s.source == "task_team_managers")
        removed_at = stage.position
        db.session.delete(stage)
        for later in policy.stages:
            if later.position > removed_at:
                later.position -= 1
        db.session.commit()
        before = [s.source for s in ApprovalPolicyStage.query.filter_by(policy_id=policy.id).order_by("position")]
        with db.engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                migration.upgrade()  # idempotent
        db.session.expire_all()
        after = [s.source for s in ApprovalPolicyStage.query.filter_by(policy_id=policy.id).order_by("position")]
        assert "task_team_managers" not in before and after.count("task_team_managers") == 1
        assert after.index("task_team_managers") == after.index("service_coowner_team_managers") + 1
        assert [s for s in after if s != "task_team_managers"] == before
        positions = [s.position for s in ApprovalPolicyStage.query.filter_by(policy_id=policy.id)]
        assert sorted(positions) == list(range(len(positions)))
        with db.engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                migration.downgrade()
        db.session.expire_all()
        assert [s.source for s in ApprovalPolicyStage.query.filter_by(policy_id=policy.id).order_by("position")] == before
