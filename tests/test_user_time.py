"""Date-times are typed and shown in each person's own time zone and stored in
UTC; a change's tasks stay inside its planned window as the person sees it."""
from datetime import datetime, timezone

from app import (ChangeFreezeWindow, ChangeGovernance, EnterpriseRecord, OperationalTask, Ticket, User, db)
from tests.test_app import app, client, group_id, login  # noqa: F401

UTC = timezone.utc


def _tokyo(app):
    with app.app_context():
        User.query.filter_by(username="admin").one().timezone = "Asia/Tokyo"
        db.session.commit()


def _change(client, app, start="2026-12-01T09:00", end="2026-12-01T17:00", title="Tokyo window"):
    response = client.post("/tickets/new/change", data={
        "title": title, "description": "x", "category": "Software", "priority": "P3",
        "change_type": "Standard", "risk_score": "20", "impact": "Low", "group_id": group_id(app, "Unix"),
        "implementation_plan": "i", "test_plan": "t", "backout_plan": "b",
        "planned_start": start, "planned_end": end})
    assert response.status_code == 302, response.get_data(as_text=True)[:500]
    with app.app_context():
        return Ticket.query.filter_by(title=title).one().id


def _utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def test_change_window_is_typed_and_shown_in_the_persons_zone(client, app):
    _tokyo(app)
    login(client)
    ticket_id = _change(client, app)
    with app.app_context():
        governance = ChangeGovernance.query.filter_by(ticket_id=ticket_id).one()
        # 09:00-17:00 in Tokyo is 00:00-08:00 UTC.
        assert _utc(governance.planned_start) == datetime(2026, 12, 1, 0, 0, tzinfo=UTC)
        assert _utc(governance.planned_end) == datetime(2026, 12, 1, 8, 0, tzinfo=UTC)
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "Planned start (JST)" in page and "(UTC)" not in page
    assert 'name="planned_start" value="2026-12-01T09:00"' in page


def test_change_tasks_default_to_and_stay_inside_the_window(client, app):
    _tokyo(app)
    login(client)
    ticket_id = _change(client, app)
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert 'min="2026-12-01T09:00" max="2026-12-01T17:00"' in page
    assert "Dec 01, 09:00" in page and "17:00 JST" in page
    task = lambda start, end: client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Patch", "task_type": "Implementation", "group_id": group_id(app, "Unix"),
        "planned_start": start, "planned_end": end})
    # Inside the window as the person sees it: accepted.
    assert task("2026-12-01T10:00", "2026-12-01T12:00").status_code == 302
    with app.app_context():
        created = OperationalTask.query.filter_by(parent_id=ticket_id, task_kind="change", title="Patch").one()
        assert _utc(created.planned_start) == datetime(2026, 12, 1, 1, 0, tzinfo=UTC)
    # Outside it: refused, and the message shows the window in the person's own time.
    refused = task("2026-12-01T16:00", "2026-12-01T18:00")
    assert refused.status_code == 409
    text = refused.get_data(as_text=True)
    assert "2026-12-01 09:00 JST" in text and "2026-12-01 17:00 JST" in text
    assert task("not a date", "2026-12-01T12:00").status_code == 400
    # Task types submit their English value whatever the display language.
    assert 'option value="Implementation"' in page


def test_revising_the_window_cannot_strand_tasks_or_enter_a_freeze(client, app):
    _tokyo(app)
    login(client)
    ticket_id = _change(client, app)
    assert client.post(f"/change/{ticket_id}/tasks", data={
        "title": "Late task", "task_type": "Implementation", "group_id": group_id(app, "Unix"),
        "planned_start": "2026-12-01T15:00", "planned_end": "2026-12-01T17:00"}).status_code == 302
    revise = lambda start, end, **extra: client.post(f"/change/{ticket_id}/plan", data={
        "title": "Tokyo window", "description": "x", "change_type": "Standard", "impact": "Low",
        "implementation_plan": "i", "test_plan": "t", "backout_plan": "b",
        "planned_start": start, "planned_end": end, **extra}, follow_redirects=True)
    stranded = revise("2026-12-01T09:00", "2026-12-01T14:00").get_data(as_text=True)
    assert "would fall outside the new window" in stranded and "CTASK" in stranded
    with app.app_context():
        governance = ChangeGovernance.query.filter_by(ticket_id=ticket_id).one()
        assert _utc(governance.planned_end) == datetime(2026, 12, 1, 8, 0, tzinfo=UTC)  # unchanged
        db.session.add(ChangeFreezeWindow(title="Year end", starts_at=datetime(2026, 12, 2, 0, 0, tzinfo=UTC),
                                          ends_at=datetime(2026, 12, 3, 0, 0, tzinfo=UTC)))
        db.session.commit()
    frozen = revise("2026-12-01T09:00", "2026-12-02T18:00").get_data(as_text=True)
    assert "Year end" in frozen and "JST" in frozen
    # A wider window that keeps the task and avoids the freeze is accepted.
    assert "Change plan revised" in revise("2026-12-01T08:00", "2026-12-01T18:00").get_data(as_text=True)


def test_other_date_time_fields_use_the_persons_zone(client, app):
    _tokyo(app)
    login(client)
    response = client.post("/module/problem/new", data={
        "record_type": "Root cause analysis", "title": "Zoned due date", "description": "x",
        "priority": "P3", "risk": "Medium", "due_at": "2026-12-05T09:00"})
    assert response.status_code == 302
    with app.app_context():
        record = EnterpriseRecord.query.filter_by(title="Zoned due date").one()
        assert _utc(record.due_at) == datetime(2026, 12, 5, 0, 0, tzinfo=UTC)
    client.post("/tickets/new/incident", data={"title": "Zoned task", "description": "x", "category": "Software",
                                               "group_id": group_id(app)})
    with app.app_context():
        incident_id = Ticket.query.filter_by(title="Zoned task").one().id
    assert client.post(f"/incident/{incident_id}/tasks", data={
        "title": "Check", "group_id": group_id(app), "due_at": "2026-12-05T18:00"}).status_code == 302
    with app.app_context():
        task = OperationalTask.query.filter_by(parent_id=incident_id, task_kind="incident").one()
        assert _utc(task.planned_end) == datetime(2026, 12, 5, 9, 0, tzinfo=UTC)
    assert "Due (JST)" in client.get(f"/ticket/{incident_id}").get_data(as_text=True)


def test_people_set_to_utc_type_and_see_utc(client, app):
    with app.app_context():
        User.query.filter_by(username="admin").one().timezone = "UTC"
        db.session.commit()
    login(client)
    ticket_id = _change(client, app, title="UTC window")
    with app.app_context():
        governance = ChangeGovernance.query.filter_by(ticket_id=ticket_id).one()
        assert _utc(governance.planned_start) == datetime(2026, 12, 1, 9, 0, tzinfo=UTC)
    assert "Planned start (UTC)" in client.get(f"/ticket/{ticket_id}").get_data(as_text=True)


def test_tasks_covering_the_whole_window_move_with_it(client, app):
    _tokyo(app)
    login(client)
    ticket_id = _change(client, app, title="Moving window")
    response = client.post(f"/change/{ticket_id}/plan", data={
        "title": "Moving window", "description": "x", "change_type": "Standard", "impact": "Low",
        "implementation_plan": "i", "test_plan": "t", "backout_plan": "b",
        "planned_start": "2026-12-02T09:00", "planned_end": "2026-12-02T17:00"}, follow_redirects=True)
    assert "Change plan revised" in response.get_data(as_text=True)
    with app.app_context():
        task = OperationalTask.query.filter_by(parent_id=ticket_id, task_kind="change", title="Implementation").one()
        assert (_utc(task.planned_start), _utc(task.planned_end)) == (
            datetime(2026, 12, 2, 0, 0, tzinfo=UTC), datetime(2026, 12, 2, 8, 0, tzinfo=UTC))
