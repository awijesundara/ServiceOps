"""B-464: personal and group dashboards."""
import json

from werkzeug.security import generate_password_hash

from app import (Dashboard, DashboardHome, DashboardWidget, GroupMember, PlatformSetting, SupportGroup, Tenant,
                 Ticket, TicketAssignmentGroup, User, UserWorkspaceLayout, db)
from serviceops_core import dashboards as boards
from tests.test_app import app, client, login  # noqa: F401


def _database_member(app):
    with app.app_context():
        group = SupportGroup.query.filter_by(name="Database").one()
        member = User(username="db.member", name="Db Member", email="db.member@test.invalid", role="agent",
                      password_hash=generate_password_hash("DbMember123!"))
        db.session.add(member)
        db.session.flush()
        db.session.add(GroupMember(group_id=group.id, user_id=member.id))
        db.session.commit()
        return group.id, member.id


def _team_dashboard(client, group_id, name="Database ops"):
    response = client.post("/dashboards", data={"name": name, "group_id": group_id, "start": "suggested"})
    assert response.status_code == 302
    return int(response.headers["Location"].split("/dashboards/")[1].split("?")[0])


def test_first_visit_creates_a_personal_dashboard_with_suggested_widgets(client, app):
    login(client)
    response = client.get("/dashboards", follow_redirects=True)
    assert response.status_code == 200 and b"My dashboard" in response.data
    with app.app_context():
        dashboard = Dashboard.query.filter_by(scope="personal").one()
        assert [w.widget_key for w in dashboard.widgets] == [key for key, _, _ in boards.DEFAULT_PERSONAL]
    assert client.get("/workspace").headers["Location"].endswith("/dashboards")


def test_a_my_workspace_layout_becomes_the_first_dashboard(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(UserWorkspaceLayout(user_id=admin.id, tenant_id=admin.tenant_id, layout_json=[
            {"widget_key": "sla_at_risk", "span": 2}, {"widget_key": "favorites", "span": 1},
            {"widget_key": "gone_widget", "span": 1}]))
        db.session.commit()
    login(client)
    client.get("/dashboards")
    with app.app_context():
        widgets = Dashboard.query.filter_by(scope="personal").one().widgets
        assert [(w.widget_key, json.loads(w.options_json).get("show")) for w in widgets] == [
            ("ticket_list", "at_risk"), ("favorites", None)]


def _seed_tickets(app, group_id):
    """Open and resolved tickets, assigned and not, so lists and charts have rows."""
    from datetime import timedelta
    from app import now
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        for index, (state, priority, assignee) in enumerate((("New", "P1", None), ("In Progress", "P2", admin.id),
                                                              ("Pending", "P3", admin.id), ("Resolved", "P4", admin.id))):
            ticket = Ticket(number=f"INC94000{index:02d}", kind="incident", title=f"Seed {index}", description="d",
                            state=state, priority=priority, category="Software", requester_id=admin.id,
                            assignee_id=assignee, created_at=now() - timedelta(days=index),
                            resolved_at=now() if state == "Resolved" else None)
            db.session.add(ticket)
            db.session.flush()
            db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=group_id))
        db.session.commit()


def test_every_widget_renders_with_every_option_on_personal_and_team_dashboards(client, app):
    group_id, _ = _database_member(app)
    _seed_tickets(app, group_id)
    login(client)
    personal = client.post("/dashboards", data={"name": "Everything", "start": "empty"})
    personal_id = int(personal.headers["Location"].split("/dashboards/")[1].split("?")[0])
    team_id = _team_dashboard(client, group_id)
    for dashboard_id, scope in ((personal_id, "personal"), (team_id, "group")):
        for key, spec in boards.catalog(scope).items():
            assert client.post(f"/dashboards/{dashboard_id}/widgets", data={"widget_key": key}).status_code == 302
            with app.app_context():
                widget = DashboardWidget.query.filter_by(dashboard_id=dashboard_id, widget_key=key) \
                    .order_by(DashboardWidget.id.desc()).first()
                widget_id = widget.id
            variants = [{}]
            for name, option in spec["options"].items():
                if option["type"] == "choice":
                    variants += [{f"opt_{name}": value} for value, _ in option["choices"]]
            variants.append({"opt_text": "On call: Database team\n\nRota on the wiki",
                             "opt_links": "Changes | /tickets/change\nEvil | https://evil.example"})
            for form in variants:
                response = client.post(f"/dashboards/{dashboard_id}/widgets/{widget_id}",
                                        data={"title": f"{key} test", "span": "2", **form})
                assert response.status_code == 302, (key, form)
                page = client.get(f"/dashboards/{dashboard_id}?edit=1")
                assert page.status_code == 200, (key, form, scope)
            assert client.get(f"/dashboards/{dashboard_id}").status_code == 200
    page = client.get(f"/dashboards/{personal_id}").get_data(as_text=True)
    assert "https://evil.example" not in page and 'href="/tickets/change"' in page


def test_team_dashboards_are_for_members_and_edited_by_the_manager(client, app):
    group_id, member_id = _database_member(app)
    login(client, "database.manager", "Manager123!")
    dashboard_id = _team_dashboard(client, group_id)
    client.post("/logout")

    login(client, "db.member", "DbMember123!")
    assert client.get(f"/dashboards/{dashboard_id}").status_code == 200
    assert b"Customize" not in client.get(f"/dashboards/{dashboard_id}").data
    assert client.post(f"/dashboards/{dashboard_id}/settings", data={"name": "Mine now"}).status_code == 403
    assert client.post(f"/dashboards/{dashboard_id}/widgets", data={"widget_key": "note"}).status_code == 403
    assert client.post(f"/dashboards/{dashboard_id}/delete").status_code == 403
    assert client.post("/dashboards", data={"name": "Sneaky", "group_id": group_id}).status_code == 403
    copy = client.post(f"/dashboards/{dashboard_id}/copy")
    assert copy.status_code == 302
    with app.app_context():
        mine = Dashboard.query.filter(Dashboard.owner_id == member_id, Dashboard.name.like("Database ops%")).one()
        assert mine.scope == "personal" and len(mine.widgets) == len(boards.DEFAULT_GROUP)
    client.post("/logout")

    login(client, "employee", "Employee123!")
    assert client.get(f"/dashboards/{dashboard_id}").status_code == 404
    assert client.post(f"/dashboards/{dashboard_id}/copy").status_code == 404


def test_people_scoped_options_become_team_scoped_on_a_shared_dashboard(client, app):
    group_id, _ = _database_member(app)
    login(client, "database.manager", "Manager123!")
    dashboard_id = _team_dashboard(client, group_id)
    with app.app_context():
        widget_id = DashboardWidget.query.filter_by(dashboard_id=dashboard_id, widget_key="ticket_list").first().id
    client.post(f"/dashboards/{dashboard_id}/widgets/{widget_id}", data={"opt_scope": "mine"})
    with app.app_context():
        assert json.loads(db.session.get(DashboardWidget, widget_id).options_json)["scope"] == "team"


def test_team_widgets_show_only_the_teams_tickets_the_viewer_may_see(client, app):
    group_id, member_id = _database_member(app)
    with app.app_context():
        requester = User.query.filter_by(username="employee").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        for number, team in (("INC9300001", group_id), ("INC9300002", windows.id)):
            ticket = Ticket(number=number, kind="incident", title=f"Ticket {number}", description="d",
                            state="New", requester_id=requester.id)
            db.session.add(ticket)
            db.session.flush()
            db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=team))
        db.session.commit()
        member = db.session.get(User, member_id)
        team = db.session.get(SupportGroup, group_id)
        with app.test_request_context("/"):
            data = boards._ticket_list(member, {"scope": "team", "kind": "incident", "show": "open"}, team)
        numbers = {t.number for t in data["tickets"]}
        assert "INC9300001" in numbers and "INC9300002" not in numbers
        assert all(t.id in {row.id for row in __import__("app").visible_ticket_query(member)} for t in data["tickets"])


def test_drag_order_home_and_fallback(client, app):
    login(client)
    client.get("/dashboards")
    with app.app_context():
        dashboard = Dashboard.query.filter_by(scope="personal").one()
        dashboard_id, ids = dashboard.id, [w.id for w in dashboard.widgets]
    response = client.post(f"/dashboards/{dashboard_id}/layout", json={"order": list(reversed(ids)) + [999999]})
    assert response.status_code == 200 and response.get_json()["order"] == list(reversed(ids))
    assert client.post(f"/dashboards/{dashboard_id}/layout", json={"order": "nope"}).status_code == 400
    second = client.post("/dashboards", data={"name": "Second", "start": "empty"})
    second_id = int(second.headers["Location"].split("/dashboards/")[1].split("?")[0])
    client.post(f"/dashboards/{second_id}/home")
    assert client.get("/dashboards").headers["Location"].endswith(f"/dashboards/{second_id}")
    client.post(f"/dashboards/{second_id}/delete")
    with app.app_context():
        assert DashboardHome.query.count() == 0
    assert client.get("/dashboards").headers["Location"].endswith(f"/dashboards/{dashboard_id}")


def test_dashboards_never_cross_tenants(client, app):
    with app.app_context():
        other = Tenant(slug="dash-other", name="Other")
        db.session.add(other)
        db.session.flush()
        foreign = Dashboard(tenant_id=other.id, scope="personal", owner_id=None, name="Foreign", description="",
                            position=0)
        db.session.add(foreign)
        db.session.commit()
        foreign_id = foreign.id
    login(client)
    assert client.get(f"/dashboards/{foreign_id}").status_code == 404
    assert client.post(f"/dashboards/{foreign_id}/copy").status_code == 404
    assert client.post(f"/dashboards/{foreign_id}/layout", json={"order": []}).status_code == 404


def test_an_administrator_can_turn_a_widget_off_everywhere(client, app):
    login(client)
    client.get("/dashboards")
    with app.app_context():
        db.session.merge(PlatformSetting(key="DASHBOARD_WIDGET_APPROVALS_ENABLED", value="false"))
        db.session.commit()
        dashboard_id = Dashboard.query.filter_by(scope="personal").one().id
    page = client.get(f"/dashboards/{dashboard_id}?edit=1").get_data(as_text=True)
    assert "Approvals awaiting me" not in page
    assert client.post(f"/dashboards/{dashboard_id}/widgets", data={"widget_key": "approvals"}).status_code == 400


def _reconcile_world(app):
    """Team and other-team incidents and changes, assigned and not, P1 and P4,
    and one ticket with two at-risk and one with two breached SLAs."""
    from datetime import timedelta
    from app import ChangeOwnership, SLADefinition, TaskSLA, now
    group_id, member_id = _database_member(app)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        definition = SLADefinition(name="Resolve", target_type="ticket", duration_minutes=60, tenant_id=admin.tenant_id)
        db.session.add(definition)
        db.session.flush()
        rows = [("incident", group_id, member_id, "P1"), ("incident", group_id, None, "P4"),
                ("incident", windows.id, member_id, "P2"), ("change", group_id, member_id, "P3"),
                ("change", group_id, None, "P1"), ("change", windows.id, None, "P4"),
                ("incident", group_id, member_id, "P3")]
        tickets = []
        for index, (kind, team, assignee, priority) in enumerate(rows):
            ticket = Ticket(number=f"{'INC' if kind == 'incident' else 'CHG'}95000{index:02d}", kind=kind,
                            title=f"Reconcile {index}", description="d", state="New", priority=priority,
                            category="Software", requester_id=admin.id, assignee_id=assignee)
            db.session.add(ticket)
            db.session.flush()
            db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=team) if kind == "change"
                           else TicketAssignmentGroup(ticket_id=ticket.id, group_id=team))
            tickets.append(ticket)
        for ticket, breached in ((tickets[0], False), (tickets[0], False), (tickets[6], True), (tickets[6], True)):
            db.session.add(TaskSLA(definition_id=definition.id, target_type="ticket", target_id=ticket.id,
                                   breach_at=now() + (timedelta(minutes=-5) if breached else timedelta(hours=1)),
                                   breached=breached))
        db.session.commit()
    return group_id


def _list_total(client, url):
    import re
    page = client.get(url).get_data(as_text=True)
    return int(re.search(r"([\d,]+) records?\b", page).group(1).replace(",", ""))


def test_every_dashboard_number_matches_the_list_it_opens(client, app):
    """The count a widget shows is exactly what its link lists: tiles, list
    widgets, chart bars and workload, for every scope and record kind."""
    import itertools
    from flask_login import login_user
    group_id = _reconcile_world(app)
    login(client, "db.member", "DbMember123!")
    checked = 0
    with app.test_request_context("/"):
        member = User.query.filter_by(username="db.member").one()
        login_user(member)
        team = db.session.get(SupportGroup, group_id)
        for scope, kind in itertools.product(("mine", "team", "visible"), ("incident", "change", "all")):
            opts = {"scope": scope, "kind": kind}
            cases = [(t["count"], t["url"]) for t in boards._ticket_counts(member, opts, team)["tiles"]]
            for by in ("priority", "state", "category", "assignee"):
                data = boards._ticket_chart(member, dict(opts, group_by=by), team)
                cases += [(b["count"], b["url"]) for b in data["bars"] if b["url"]] + [(data["total"], data["url"])]
                assert data["total"] == sum(b["count"] for b in data["bars"])
            for show in ("open", "unassigned", "at_risk", "breached"):
                data = boards._ticket_list(member, dict(opts, show=show, limit=20), team)
                cases.append((len(data["tickets"]), data["url"]))
            for count, url in cases:
                assert _list_total(client, url) == count, (scope, kind, url)
                checked += 1
        for row in boards._team_workload(member, {}, team)["members"]:
            assert _list_total(client, row["url"]) == row["tickets"]
            checked += 1
    assert checked > 100


def test_manager_portal_counts_tickets_not_slas(client, app):
    """Two running SLAs on one ticket count it once, as the list does."""
    from flask_login import login_user
    from serviceops_core.web.common import manager_portal_context, ticket_list_url
    group_id = _reconcile_world(app)
    login(client)
    with app.test_request_context("/"):
        login_user(User.query.filter_by(username="admin").one())
        teams, members = manager_portal_context()
        rows = members[group_id]
        member = next(m for m in rows if m["user"].username == "db.member")
        assert member["sla_at_risk"] == 1 and member["sla_breached"] == 1
        for metric, extra in (("sla_at_risk", {"sla": "at_risk"}), ("sla_breached", {"sla": "breached"})):
            url = ticket_list_url("incident", member["user"].id, **extra)
            assert _list_total(client, url) == member["by_kind"][metric]["incident"]
