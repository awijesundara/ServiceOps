"""The dashboard's ticket counts come from one grouped query; they must match
a direct count of the tickets the user can see (perf review 2026-10-12)."""
from flask import template_rendered

from app import Ticket, User, create_ticket_with_unique_number, db, visible_ticket_query
from tests.test_app import app, client, login  # noqa: F401


def test_dashboard_counts_match_the_visible_tickets(app, client):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        for kind, priority, state in [("incident", "P1", "New"), ("incident", "P1", "Closed"),
                                      ("incident", "P2", "In Progress"), ("incident", "P3", "New"),
                                      ("change", "P2", "New"), ("change", "P1", "Closed")]:
            ticket = create_ticket_with_unique_number(kind, title=f"{kind} {priority} {state}",
                                                      description="count check", priority=priority,
                                                      requester_id=admin.id)
            ticket.state = state
        db.session.commit()
        rows = visible_ticket_query(admin).with_entities(Ticket.kind, Ticket.priority, Ticket.state).all()
        open_rows = [r for r in rows if r.state not in ("Resolved", "Closed", "Cancelled")]
        expected = {
            "incident": sum(r.kind == "incident" for r in rows),
            "change": sum(r.kind == "change" for r in rows),
            "p1": sum(r.kind == "incident" and r.priority == "P1" for r in open_rows),
            "p2": sum(r.kind == "incident" and r.priority == "P2" for r in open_rows),
            "open_tickets": len(open_rows),
        }
    captured = []

    def record(sender, template, context, **extra):  # signals hold receivers weakly
        captured.append(context)
    template_rendered.connect(record, app)
    login(client)
    assert client.get("/").status_code == 200
    context = next(c for c in captured if "incident_priority_counts" in c)
    assert context["counts"]["incident"] == expected["incident"]
    assert context["counts"]["change"] == expected["change"]
    assert context["incident_priority_counts"] == {"p1": expected["p1"], "p2": expected["p2"]}
    assert context["open_count"] - expected["open_tickets"] >= 0  # plus open catalog requests
    assert expected["p1"] >= 1 and expected["p2"] >= 1


def test_dashboard_never_fetches_every_ticket(app, client, monkeypatch):
    from sqlalchemy.orm import Query
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        for index in range(300):
            create_ticket_with_unique_number("incident", title=f"bulk {index}", description="bulk",
                                             priority="P3", requester_id=admin.id)
        db.session.commit()
    largest = []
    original_all = Query.all

    def counting_all(self):
        result = original_all(self)
        largest.append(len(result))
        return result
    monkeypatch.setattr(Query, "all", counting_all)
    login(client)
    assert client.get("/").status_code == 200
    # 300+ visible tickets, yet no dashboard query returns more than a page of rows.
    assert largest and max(largest) <= 50, max(largest)
