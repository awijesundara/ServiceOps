"""Groups as approvers (serviceops_core/approval_groups.py): CCB, executive,
team manager assessment and enterprise record approval accept teams whose
active members become approvers alongside the named users."""
import os
import re
import tempfile

import pytest
from werkzeug.security import generate_password_hash

from app import (Approval, ApprovalAuthorityGroup, Audit, ChangeGovernance, ChangeOwnership, EnterpriseRecord,
                 GroupMember, SupportGroup, Tenant, Ticket, User, change_approval_stages, create_app, db)
from serviceops_core.approval_groups import set_authority_groups
import app as core


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        tenant = admin.tenant_id

        def user(username, role="agent", active=True):
            row = User(username=username, name=username.replace(".", " ").title(), email=f"{username}@test.invalid",
                       role=role, active=active, password_hash=generate_password_hash("Password123!"), tenant_id=tenant)
            db.session.add(row)
            db.session.flush()
            return row

        def team(name, *members, manager=None):
            group = SupportGroup(name=name, group_type="IT Fulfillment", tenant_id=tenant,
                                 manager_id=manager.id if manager else None)
            db.session.add(group)
            db.session.flush()
            for member in members:
                db.session.add(GroupMember(group_id=group.id, user_id=member.id, role="member", tenant_id=tenant))
            return group

        ccb_person = user("ccb.person", "manager")
        board_a, board_b, board_gone = user("board.a"), user("board.b"), user("board.gone", active=False)
        ceo, cfo = user("ceo.person", "manager"), user("cfo.person", "manager")
        unix_lead = user("unix.lead", "manager")
        unix_a, unix_b = user("unix.a"), user("unix.b")
        reviewer_a, reviewer_b = user("reviewer.a"), user("reviewer.b")
        requester = user("change.requester")
        ccb = SupportGroup.query.filter_by(name="Change Control Board", tenant_id=tenant).one()
        db.session.add(GroupMember(group_id=ccb.id, user_id=ccb_person.id, role="CCB approver", tenant_id=tenant))
        executive = SupportGroup.query.filter_by(name="Executive Office", tenant_id=tenant).one()
        executive.manager_id = ceo.id
        executive.approval_mode = "all"
        groups = {
            "board": team("Change Board Delegates", board_a, board_b, board_gone),
            "leadership": team("Leadership Team", cfo),
            "unix": team("Unix Ops", unix_a, unix_b, manager=unix_lead),
            "storage": team("Storage Ops"),
            "reviewers": team("Record Reviewers", reviewer_a, reviewer_b, requester),
        }
        db.session.commit()
        app.config["IDS"] = {"tenant": tenant, "admin": admin.id, "ccb_person": ccb_person.id,
                             "board_a": board_a.id, "board_b": board_b.id, "board_gone": board_gone.id,
                             "ceo": ceo.id, "cfo": cfo.id, "unix_lead": unix_lead.id, "unix_a": unix_a.id,
                             "unix_b": unix_b.id, "reviewer_a": reviewer_a.id, "reviewer_b": reviewer_b.id,
                             "requester": requester.id, **{f"group_{k}": v.id for k, v in groups.items()}}
    yield app
    os.unlink(path)


@pytest.fixture()
def client(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "Admin123!"})
    return client


def link(app, authority, *group_keys, subject=None):
    ids = app.config["IDS"]
    with app.app_context():
        set_authority_groups(ids["tenant"], authority, [ids[f"group_{key}"] for key in group_keys],
                             core.team_groups(ids["tenant"]),
                             subject_group_id=ids[f"group_{subject}"] if subject else None)
        db.session.commit()


def change(app, owner="unix", change_type="Normal"):
    ids = app.config["IDS"]
    ticket = Ticket(kind="change", number=f"CHG09{len(Ticket.query.all()):05d}", title="Patch", description="Patch.",
                    category="Software", priority="P3", state="New", requester_id=ids["requester"],
                    tenant_id=ids["tenant"])
    db.session.add(ticket)
    db.session.flush()
    db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=ids[f"group_{owner}"]))
    db.session.add(ChangeGovernance(ticket_id=ticket.id, change_type=change_type, risk_score=40, impact="Medium",
                                    implementation_plan="Do.", test_plan="Test.", backout_plan="Undo."))
    db.session.commit()
    return ticket


def stage(stages, prefix):
    return next(s for s in stages if s["name"].startswith(prefix))


def test_ccb_groups_add_their_active_members_to_the_ccb_gate(app):
    link(app, "ccb", "board")
    ids = app.config["IDS"]
    with app.app_context():
        ccb = stage(change_approval_stages(change(app)), "CCB authorization")
        assert ccb["mode"] == "any"
        assert ccb["approver_ids"] == sorted([ids["ccb_person"], ids["board_a"], ids["board_b"]])


def test_executive_groups_join_the_executive_rule(app):
    link(app, "executive", "leadership")
    ids = app.config["IDS"]
    with app.app_context():
        executive = stage(change_approval_stages(change(app)), "Executive (CEO) approval")
        assert executive["mode"] == "all"
        assert executive["approver_ids"] == sorted([ids["ceo"], ids["cfo"]])


def test_team_approval_group_lets_the_manager_or_any_member_approve(app):
    ids = app.config["IDS"]
    with app.app_context():
        assert stage(change_approval_stages(change(app)), "Unix Ops manager")["approver_ids"] == [ids["unix_lead"]]
    link(app, "team_manager", "unix", subject="unix")
    with app.app_context():
        owner = stage(change_approval_stages(change(app)), "Unix Ops manager")
        assert owner["mode"] == "any"
        assert owner["approver_ids"] == sorted([ids["unix_lead"], ids["unix_a"], ids["unix_b"]])


def test_a_team_without_a_manager_needs_an_approval_group(app):
    with app.app_context():
        with pytest.raises(Exception) as error:
            change_approval_stages(change(app, owner="storage"))
        assert "manager or approval group" in str(error.value.description)
    link(app, "team_manager", "reviewers", subject="storage")
    ids = app.config["IDS"]
    with app.app_context():
        owner = stage(change_approval_stages(change(app, owner="storage")), "Storage Ops manager")
        assert set(owner["approver_ids"]) == {ids["reviewer_a"], ids["reviewer_b"], ids["requester"]}


def test_record_approval_goes_to_the_group_and_one_decision_settles_it(app, client):
    link(app, "enterprise", "reviewers")
    ids = app.config["IDS"]
    client.post("/logout")
    client.post("/login", data={"username": "change.requester", "password": "Password123!"})
    response = client.post("/module/problem/new", data={
        "record_type": "Problem", "title": "Repeated disk alerts", "description": "Investigate.",
        "approval_required": "on",
    })
    assert response.status_code in (302, 303)
    with app.app_context():
        record = EnterpriseRecord.query.filter_by(title="Repeated disk alerts").one()
        approvals = Approval.query.filter_by(enterprise_record_id=record.id).all()
        # The requester is never asked to approve their own record.
        assert sorted(a.approver_id for a in approvals) == sorted([ids["reviewer_a"], ids["reviewer_b"]])
        mine = next(a for a in approvals if a.approver_id == ids["reviewer_a"])
        record_id, approval_id = record.id, mine.id
    client.post("/logout")
    client.post("/login", data={"username": "reviewer.a", "password": "Password123!"})
    client.post(f"/enterprise/{record_id}", data={"action": "approve", "approval_id": approval_id, "comments": "OK"})
    with app.app_context():
        states = {a.approver_id: a.state for a in Approval.query.filter_by(enterprise_record_id=record_id)}
        assert states == {ids["reviewer_a"]: "Approved", ids["reviewer_b"]: "No Longer Required"}
        assert db.session.get(EnterpriseRecord, record_id).state == "Approved"


def test_admin_adds_and_removes_groups_from_a_dropdown(app, client):
    ids = app.config["IDS"]
    url = "/service-operations/settings"
    page = client.get(f"{url}/ccb").get_data(as_text=True)
    assert "CCB approver groups" in page and "No groups added." in page
    # The form must post to the settings handler (a macro cannot see template-level variables).
    assert re.search(r'<form method="post" action="/service-operations/settings" class="inline-form approval-group-add">', page)
    for key in ("board", "leadership"):
        response = client.post(url, data={"action": "add_approval_group", "authority": "ccb",
                                          "group_id": ids[f"group_{key}"]},
                               headers={"Referer": f"http://localhost{url}/ccb"})
        assert response.status_code in (302, 303)
        assert response.headers["Location"].endswith("/service-operations/settings/ccb")
    page = client.get(f"{url}/ccb").get_data(as_text=True)
    added = page[page.index("approval-group-list"):page.index("approval-group-add")]
    assert "Change Board Delegates" in added and "Leadership Team" in added
    dropdown = page[page.index("approval-group-add"):]
    dropdown = dropdown[:dropdown.index("</select>")]
    assert "Change Board Delegates" not in dropdown and "Unix Ops" in dropdown
    client.post(url, data={"action": "remove_approval_group", "authority": "ccb", "group_id": ids["group_board"]})
    with app.app_context():
        assert [row.group_id for row in ApprovalAuthorityGroup.query.filter_by(authority="ccb")] == [ids["group_leadership"]]
        assert Audit.query.filter(Audit.target == "CCB approval groups").count() == 3


def test_governance_foreign_and_unknown_groups_are_refused(app, client):
    ids = app.config["IDS"]
    url = "/service-operations/settings"
    with app.app_context():
        governance = SupportGroup.query.filter_by(name="Change Control Board").one().id
        other_tenant = Tenant(name="Other", slug="other-approvals")
        db.session.add(other_tenant)
        db.session.flush()
        foreign = SupportGroup(name="Foreign Team", group_type="IT Fulfillment", tenant_id=other_tenant.id)
        db.session.add(foreign)
        db.session.commit()
        foreign_id = foreign.id
    for bad in (governance, foreign_id, 0):
        assert client.post(url, data={"action": "add_approval_group", "authority": "ccb",
                                      "group_id": bad}).status_code == 400
    for authority in ("nobody", "team_manager"):
        assert client.post(url, data={"action": "add_approval_group", "authority": authority,
                                      "group_id": ids["group_board"]}).status_code == 400
    with app.app_context():
        assert ApprovalAuthorityGroup.query.count() == 0


def test_team_manager_groups_are_set_per_team_from_the_team_managers_page(app, client):
    ids = app.config["IDS"]
    page = client.get("/service-operations/settings/team-managers").get_data(as_text=True)
    assert "Approval group" in page and "Manager only" in page
    client.post("/service-operations/settings", data={"action": "set_approval_groups", "authority": "team_manager",
                                                   "subject_group_id": ids["group_storage"],
                                                   "group_ids": [ids["group_reviewers"]]})
    with app.app_context():
        row = ApprovalAuthorityGroup.query.filter_by(authority="team_manager").one()
        assert (row.subject_group_id, row.group_id) == (ids["group_storage"], ids["group_reviewers"])


def test_membership_changes_do_not_rewrite_an_open_approval(app):
    link(app, "ccb", "board")
    ids = app.config["IDS"]
    with app.app_context():
        frozen = stage(change_approval_stages(change(app)), "CCB authorization")["approver_ids"]
        GroupMember.query.filter_by(group_id=ids["group_board"], user_id=ids["board_b"]).delete()
        db.session.commit()
        assert ids["board_b"] in frozen
        later = stage(change_approval_stages(change(app)), "CCB authorization")["approver_ids"]
        assert ids["board_b"] not in later
