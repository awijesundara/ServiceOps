"""A change's CI owners approve it: every different owner once, however many of
its CIs they own, and nobody is asked twice."""
from werkzeug.security import generate_password_hash

from app import (ApprovalChain, ChangeGovernance, ChangeOwnership, ConfigurationItem, SupportGroup,
                 TaskCI, Ticket, User, change_approval_stages, db)
from tests.test_app import app, client, group_id, login  # noqa: F401


def _person(username, role="agent"):
    user = User(username=username, name=username.replace(".", " ").title(), email=f"{username}@test.invalid",
                password_hash=generate_password_hash("Owner123!x"), role=role)
    db.session.add(user)
    db.session.flush()
    return user


def _change(cis, requester, owning="Unix"):
    ticket = Ticket(kind="change", number=f"CHG77{Ticket.query.count():05d}", title="Owner check", description="x",
                    category="Software", priority="P3", state="New", requester_id=requester.id)
    db.session.add(ticket)
    db.session.flush()
    db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=SupportGroup.query.filter_by(name=owning).one().id))
    db.session.add(ChangeGovernance(ticket_id=ticket.id, change_type="Standard", risk_score=10, impact="Low",
                                    implementation_plan="i", test_plan="t", backout_plan="b", ci_id=cis[0].id))
    for ci in cis[1:]:
        db.session.add(TaskCI(target_type="ticket", target_id=ticket.id, ci_id=ci.id, relationship_role="Affected CI"))
    db.session.flush()
    return ticket


def _owner_stage(stages):
    return next((stage for stage in stages if "CI owner approval" in stage["name"]), None)


def test_different_owners_each_approve_and_one_owner_is_asked_once(app):
    with app.app_context():
        requester = User.query.filter_by(username="admin").one()
        alice, bob = _person("alice.owner"), _person("bob.owner")
        cis = [ConfigurationItem(name=f"ci-{i}", ci_class="Server", owner_id=owner.id)
               for i, owner in enumerate([alice, alice, bob, alice])]
        db.session.add_all(cis)
        db.session.flush()
        stage = _owner_stage(change_approval_stages(_change(cis, requester)))
        assert stage["approver_ids"] == sorted([alice.id, bob.id]) and stage["mode"] == "all"
        # One owner for every CI: a single request to that person.
        same = [ConfigurationItem(name=f"same-{i}", ci_class="Server", owner_id=alice.id) for i in range(3)]
        db.session.add_all(same)
        db.session.flush()
        stage = _owner_stage(change_approval_stages(_change(same, requester)))
        assert stage["approver_ids"] == [alice.id]


def test_owner_who_raised_the_change_or_already_approves_is_not_asked_again(app):
    with app.app_context():
        alice = _person("alice.author")
        manager = User.query.filter_by(username="database.manager").one()  # manages every IT team in the fixture
        cis = [ConfigurationItem(name="authored-1", ci_class="Server", owner_id=alice.id),
               ConfigurationItem(name="managed-1", ci_class="Server", owner_id=manager.id)]
        db.session.add_all(cis)
        db.session.flush()
        stages = change_approval_stages(_change(cis, alice))
        assert _owner_stage(stages) is None or alice.id not in _owner_stage(stages)["approver_ids"]
        # The manager approves the owning team already; their CI-owner request folds into that stage.
        team_stage = next(stage for stage in stages if stage["name"].startswith("Unix manager assessment"))
        assert "CI owner approval" in team_stage["name"]
        assert sum(manager.id in stage["approver_ids"] for stage in stages
                   if "manager assessment" in stage["name"] or "CI owner" in stage["name"]) == 1


def test_inactive_or_missing_owners_add_no_stage(app):
    with app.app_context():
        requester = User.query.filter_by(username="admin").one()
        gone = _person("gone.owner")
        gone.active = False
        cis = [ConfigurationItem(name="ownerless", ci_class="Server"),
               ConfigurationItem(name="gone-owned", ci_class="Server", owner_id=gone.id)]
        db.session.add_all(cis)
        db.session.flush()
        assert _owner_stage(change_approval_stages(_change(cis, requester))) is None


def test_adding_a_ci_later_asks_its_owner(client, app):
    with app.app_context():
        carol = _person("carol.owner")
        first = ConfigurationItem(name="first-ci", ci_class="Server", owner_id=carol.id)
        later_owner = _person("dave.owner")
        later = ConfigurationItem(name="later-ci", ci_class="Server", owner_id=later_owner.id)
        db.session.add_all([first, later])
        db.session.commit()
        first_id, later_id, carol_id, dave_id = first.id, later.id, carol.id, later_owner.id
    login(client)
    assert client.post("/tickets/new/change", data={
        "title": "Owner growth", "description": "x", "category": "Software", "priority": "P3",
        "change_type": "Standard", "risk_score": "20", "impact": "Low", "group_id": group_id(app, "Unix"),
        "implementation_plan": "i", "test_plan": "t", "backout_plan": "b",
        "planned_start": "2026-12-01T09:00", "planned_end": "2026-12-01T10:00", "ci_id": str(first_id),
    }).status_code == 302
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Owner growth").one().id
    assert client.post(f"/record/ticket/{ticket_id}/configuration-items",
                       data={"relationship_role": "Affected CI", "ci_id": str(later_id)}).status_code == 302
    with app.app_context():
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket_id, state="Running").one()
        owner_gate = next(gate for gate in chain.gates if "CI owner approval" in gate.name)
        assert sorted(vote.approver_id for vote in owner_gate.votes) == sorted([carol_id, dave_id])


def test_the_default_change_policy_has_the_owner_stage_once_after_the_ci_teams(app):
    from serviceops_core import approval_policies
    with app.app_context():
        policy = approval_policies.default_policy(1, "change")
        sources = [stage.source for stage in policy.stages]
        assert sources.count("ci_owners") == 1
        assert sources.index("ci_owners") == sources.index("ci_owner_team_managers") + 1
