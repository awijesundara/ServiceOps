"""When a record ends without its work being done -- a change cancelled,
deleted or rejected, an incident or problem closed -- its unfinished tasks are
cancelled with it and leave everyone's work queue."""
import importlib

from app import (ApprovalChain, EnterpriseRecord, Notification, OperationalTask, TaskHistory, Ticket, User, db)
from tests.test_app import app, client, group_id, login  # noqa: F401
from tests.test_incident_hierarchy import RecordForm, _incident, _update
from tests.test_user_time import _change


def _ctask(client, app, ticket_id, title="Patch hosts"):
    assert client.post(f"/change/{ticket_id}/tasks", data={
        "title": title, "task_type": "Planning", "group_id": group_id(app, "Unix"),
        "planned_start": "2026-12-01T10:00", "planned_end": "2026-12-01T11:00"}).status_code == 302
    with app.app_context():
        task = OperationalTask.query.filter_by(parent_id=ticket_id, task_kind="change", title=title).one()
        admin = User.query.filter_by(username="admin").one()
        task.assignee_id = admin.id
        db.session.commit()
        return task.id


def _update_change(client, ticket_id, **changes):
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    form = RecordForm()
    form.feed(page.replace('id="task-record-form"', 'id="incident-record-form"'))
    return client.post(f"/ticket/{ticket_id}", data={**form.fields, **changes})


def _states(app, ticket_id, parent_type="ticket"):
    with app.app_context():
        return {t.state for t in OperationalTask.query.filter_by(parent_type=parent_type, parent_id=ticket_id)}


def test_cancelling_a_change_cancels_its_tasks_and_clears_my_work(client, app):
    login(client)
    ticket_id = _change(client, app, title="Cancel me")
    task_id = _ctask(client, app, ticket_id)
    assert "Patch hosts" in client.get("/work/tasks").get_data(as_text=True)
    assert _update_change(client, ticket_id, state="Cancelled").status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Cancelled"
        assert db.session.get(OperationalTask, task_id).state == "Cancelled"
        assert TaskHistory.query.filter_by(target_type="ticket", target_id=ticket_id, event="Tasks cancelled").count() == 1
        assert Notification.query.filter(Notification.target_type == "operational_task",
                                         Notification.target_id == task_id).count() == 1
    assert _states(app, ticket_id) == {"Cancelled"}
    assert "Patch hosts" not in client.get("/work/tasks").get_data(as_text=True)


def test_deleting_a_change_cancels_its_tasks(client, app):
    login(client)
    ticket_id = _change(client, app, title="Delete me")
    _ctask(client, app, ticket_id)
    assert client.post(f"/change/{ticket_id}/delete").status_code == 302
    assert _states(app, ticket_id) == {"Cancelled"}
    assert "Patch hosts" not in client.get("/work/tasks").get_data(as_text=True)


def test_a_rejected_change_cancels_its_tasks(client, app):
    login(client)
    ticket_id = _change(client, app, title="Reject me")
    _ctask(client, app, ticket_id)
    with app.app_context():
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket_id).order_by(
            ApprovalChain.id.desc()).first()
        vote = next(v for g in chain.gates for v in g.votes if v.state == "Requested")
        approver = db.session.get(User, vote.approver_id)
        vote_id, username = vote.id, approver.username
    client.get("/logout")
    password = {"admin": "Admin123!", "database.manager": "Manager123!"}[username]
    login(client, username, password)
    client.post(f"/approval-votes/{vote_id}/decide", data={"decision": "Rejected", "comments": "No"})
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Rejected"
    assert _states(app, ticket_id) == {"Cancelled"}


def test_finished_tasks_keep_their_outcome(client, app):
    login(client)
    ticket_id = _change(client, app, title="Partly done")
    done_id = _ctask(client, app, ticket_id, "Plan it")
    client.post(f"/operational-task/{done_id}", data={"state": "Closed Complete", "assignee_id": ""})
    _ctask(client, app, ticket_id, "Never started")
    _update_change(client, ticket_id, state="Cancelled")
    with app.app_context():
        assert db.session.get(OperationalTask, done_id).state == "Closed Complete"
    assert _states(app, ticket_id) == {"Closed Complete", "Cancelled"}


def test_closing_an_incident_cancels_optional_tasks(client, app):
    login(client)
    _, ticket_id, _ = _incident(client, app, "Printer jam")
    client.post(f"/incident/{ticket_id}/tasks", data={"title": "Check spare", "group_id": group_id(app)})
    assert _update(client, ticket_id, state="Cancelled").status_code == 302
    assert _states(app, ticket_id) == {"Cancelled"}


def test_closing_a_problem_cancels_optional_tasks(client, app):
    login(client)
    client.post("/module/problem/new", data={"record_type": "Root cause analysis", "title": "Recurring DB locks",
                                             "description": "x", "priority": "P3", "risk": "Medium"})
    with app.app_context():
        record_id = EnterpriseRecord.query.filter_by(title="Recurring DB locks").one().id
    client.post(f"/problem/{record_id}/tasks", data={"title": "Collect traces", "group_id": group_id(app)})
    assert _states(app, record_id, "enterprise") == {"Open"}
    client.post(f"/enterprise/{record_id}", data={"action": "update", "state": "Closed", "priority": "P3",
                                                   "risk": "Medium", "assignee_id": ""})
    with app.app_context():
        assert db.session.get(EnterpriseRecord, record_id).state == "Closed"
    assert _states(app, record_id, "enterprise") == {"Cancelled"}


def test_migration_cancels_tasks_left_behind(client, app):
    login(client)
    ticket_id = _change(client, app, title="Cancelled before the fix")
    task_id = _ctask(client, app, ticket_id)
    with app.app_context():
        db.session.get(Ticket, ticket_id).state = "Cancelled"  # as older releases left it
        db.session.commit()
        migration = importlib.import_module("migrations.versions.20261021_0141_cancel_orphaned_tasks")
        from alembic.operations import Operations
        from alembic.runtime.migration import MigrationContext
        with db.engine.begin() as connection:
            migration.op._proxy = Operations(MigrationContext.configure(connection))
            migration.upgrade()
        db.session.expire_all()
        assert db.session.get(OperationalTask, task_id).state == "Cancelled"
        assert TaskHistory.query.filter_by(target_type="ticket", target_id=ticket_id, event="Tasks cancelled").count() == 1


def test_state_menus_submit_english_values_in_japanese(client, app):
    from app import UserPreference
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(UserPreference(user_id=admin.id, language="ja"))
        db.session.commit()
    login(client)
    ticket_id = _change(client, app, title="Japanese cancel")
    _ctask(client, app, ticket_id)
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert 'option value="Cancelled"' in page
    assert _update_change(client, ticket_id, state="Cancelled").status_code == 302
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Cancelled"
    assert _states(app, ticket_id) == {"Cancelled"}


def test_one_rejection_releases_every_other_approver(client, app):
    from app import ApprovalVote, TaskSLA
    login(client)
    ticket_id = _change(client, app, title="Two approvers")
    with app.app_context():
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket_id).one()
        deciding = next(v for g in chain.gates for v in g.votes if v.state == "Requested")
        # A second person asked in the same step, and one waiting for a later step.
        employee = User.query.filter_by(username="employee").one()
        db.session.add(ApprovalVote(gate_id=deciding.gate_id, approver_id=employee.id, state="Requested"))
        later = [g for g in chain.gates if g.sequence > deciding.gate.sequence]
        if later:
            db.session.add(ApprovalVote(gate_id=later[0].id, approver_id=employee.id, state="Not Requested"))
        db.session.commit()
        votes = [v for g in chain.gates for v in g.votes]
        username = db.session.get(User, deciding.approver_id).username
        vote_id, others = deciding.id, [v.id for v in votes if v.id != deciding.id]
        assert others, "the change should ask more than one approver"
    client.get("/logout")
    login(client, username, {"admin": "Admin123!", "database.manager": "Manager123!"}[username])
    client.post(f"/approval-votes/{vote_id}/decide", data={"decision": "Rejected", "comments": "Too risky"})
    with app.app_context():
        assert all(db.session.get(ApprovalVote, i).state == "No Longer Required" for i in others)
        assert all(s.stage in ("Cancelled", "Completed")
                   for s in TaskSLA.query.filter_by(target_type="ticket", target_id=ticket_id))


def _catalog_order(client, app, name, approval_required):
    from app import CatalogItem, RequestedItem
    with app.app_context():
        item = CatalogItem(name=name, category="Hardware", description="x", approval_required=approval_required)
        db.session.add(item)
        db.session.commit()
        item_id = item.id
    client.post(f"/catalog/{item_id}/order", data={"details": "x"})
    with app.app_context():
        return RequestedItem.query.filter_by(catalog_item_id=item_id).one().id


def test_a_rejected_catalog_item_closes_its_request(client, app):
    from app import CatalogRequest, RequestedItem
    login(client, "employee", "Employee123!")
    ritm_id = _catalog_order(client, app, "Monitor", True)
    with app.app_context():
        chain = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm_id).one()
        manager = User.query.filter_by(username="database.manager").one()
        vote_id = next(v.id for g in chain.gates for v in g.votes if v.approver_id == manager.id and v.state == "Requested")
    client.get("/logout")
    login(client, "database.manager", "Manager123!")
    client.post(f"/approval-votes/{vote_id}/decide", data={"decision": "Rejected"})
    with app.app_context():
        ritm = db.session.get(RequestedItem, ritm_id)
        assert ritm.state == "Rejected"
        assert db.session.get(CatalogRequest, ritm.request_id).state == "Closed Incomplete"


def test_one_incomplete_item_does_not_close_a_request_with_open_items(client, app):
    from app import CatalogItem, CatalogRequest, CatalogTask, RequestedItem
    login(client, "employee", "Employee123!")
    first = _catalog_order(client, app, "Keyboard", False)
    with app.app_context():
        request_id = db.session.get(RequestedItem, first).request_id
        other = RequestedItem(number="RITM9999999", request_id=request_id,
                              catalog_item_id=CatalogItem.query.filter_by(name="Keyboard").one().id,
                              state="Open", stage="Fulfillment", variables_json="{}",
                              tenant_id=db.session.get(CatalogRequest, request_id).tenant_id)
        db.session.add(other)
        db.session.commit()
        task_id = CatalogTask.query.filter_by(requested_item_id=first).first().id
    client.get("/logout")
    login(client)
    client.post(f"/catalog-task/{task_id}", data={"state": "Closed Incomplete", "work_notes": "Out of stock"})
    with app.app_context():
        assert db.session.get(RequestedItem, first).state == "Closed Incomplete"
        assert db.session.get(CatalogRequest, request_id).state not in ("Closed Incomplete", "Closed Complete")
