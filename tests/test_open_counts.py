"""Open counts: every home tile and dashboard number counts unfinished work only
(never resolved, closed, cancelled or rejected), and opens a list with exactly
that many records."""
import re
from html import unescape

from app import CatalogRequest, Ticket, User, db
from serviceops_core import dashboards
from serviceops_core.task_lifecycle import FINISHED_TICKET_STATES, TICKET_TRANSITIONS
from tests.test_app import app, client, group_id, login  # noqa: F401
from tests.test_incident_hierarchy import _incident

INCIDENT_STATES = ("New", "In Progress", "Pending", "Resolved", "Closed", "Cancelled")


def _seed(client, app):
    login(client)
    ids = {}
    for state in INCIDENT_STATES:
        _, ticket_id, _ = _incident(client, app, f"Incident {state}")
        ids[state] = ticket_id
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        for state, ticket_id in ids.items():
            ticket = db.session.get(Ticket, ticket_id)
            ticket.state, ticket.assignee_id = state, admin.id
        for number, state in (("CHG9000001", "New"), ("CHG9000002", "Rejected"), ("CHG9000003", "Closed"),
                              ("CHG9000004", "Resolved")):
            db.session.add(Ticket(number=number, kind="change", title=f"Change {state}", description="x",
                                  state=state, priority="P3", requester_id=admin.id, assignee_id=admin.id))
        for number, state in (("REQ9000001", "Open"), ("REQ9000002", "Closed Complete"),
                              ("REQ9000003", "Closed Incomplete"), ("REQ9000004", "Cancelled")):
            db.session.add(CatalogRequest(number=number, state=state, requested_by_id=admin.id,
                                          requested_for_id=admin.id))
        db.session.commit()


def _tiles(html):
    return {unescape(label): (unescape(href), int(count)) for href, label, count in re.findall(
        r'<a href="([^"]+)"[^>]*><span>([^<]+)</span><strong>(\d+)</strong>', html)}


def _list_total(client, href):
    page = client.get(href).get_data(as_text=True)
    return int(re.search(r"<small>(\d+) records?</small>", page).group(1))


def test_finished_states_are_exactly_the_states_that_move_nowhere_new():
    for state in FINISHED_TICKET_STATES:
        assert "New" not in TICKET_TRANSITIONS.get(state, ()) and "Pending" not in TICKET_TRANSITIONS.get(state, ())
    assert {"Resolved", "Closed", "Cancelled", "Rejected"} == set(FINISHED_TICKET_STATES)


def test_home_tiles_count_open_records_and_open_matching_lists(client, app):
    _seed(client, app)
    tiles = _tiles(client.get("/").get_data(as_text=True))
    assert tiles["Open incidents"][1] == 3  # New, In Progress, Pending
    assert tiles["Open changes"][1] == 1    # not Rejected, Closed or Resolved
    assert tiles["Open requests"][1] == 1
    assert tiles["Open work"][1] == 5
    for label in ("Open incidents", "Open changes", "Open requests"):
        href, count = tiles[label]
        assert _list_total(client, href) == count, label
    open_work = client.get(tiles["Open work"][0]).get_data(as_text=True)
    for state in ("Resolved", "Closed", "Cancelled"):
        assert f"Incident {state}" not in open_work
    assert "Change Rejected" not in open_work and "Incident Pending" in open_work


def test_requests_list_open_only_keeps_the_filter_while_paging_and_exporting(client, app):
    _seed(client, app)
    page = client.get("/requests?open=1").get_data(as_text=True)
    assert "REQ9000001" in page and "REQ9000002" not in page and "REQ9000004" not in page
    assert "Show all requests" in page and 'name="open" value="1"' in page
    assert re.search(r'href="/requests/export\.csv\?[^"]*open=1"', page)
    export = client.get("/requests/export.csv?open=1").get_data(as_text=True)
    assert "REQ9000001" in export and "REQ9000003" not in export
    everything = client.get("/requests").get_data(as_text=True)
    assert "REQ9000004" in everything and "Open only" in everything


def test_dashboard_widgets_never_count_finished_tickets(client, app):
    _seed(client, app)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        with app.test_request_context():
            counts = dashboards._ticket_counts(admin, {"scope": "mine", "kind": "all"}, None)
            listed = dashboards._ticket_list(admin, {"scope": "mine", "kind": "all", "show": "open", "limit": 50}, None)
            chart = dashboards._ticket_chart(admin, {"scope": "mine", "kind": "all", "group_by": "state"}, None)
    assert counts["tiles"][0]["count"] == 4  # three open incidents and one open change
    assert {t.state for t in listed["tickets"]} == {"New", "In Progress", "Pending"}
    assert {bar["label"] for bar in chart["bars"]}.isdisjoint(FINISHED_TICKET_STATES)
    assert chart["total"] == 4
