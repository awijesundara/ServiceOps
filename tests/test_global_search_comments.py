"""Global search finds tickets by their comments, numbers and words in any
order, and never reveals tickets the user cannot see (B-442)."""
from app import Comment, User, create_ticket_with_unique_number, db
from tests.test_app import app, client, login  # noqa: F401


def _results(client, q):
    return client.get("/ui/search", query_string={"q": q}, headers={"Accept": "application/json"}).json["results"]


def test_search_matches_comments_numbers_and_respects_visibility(app, client):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        employee = User.query.filter_by(username="employee").one()
        mine = create_ticket_with_unique_number("incident", title="Laptop slow", description="x",
                                                priority="P3", requester_id=employee.id)
        other = create_ticket_with_unique_number("incident", title="Unrelated", description="x",
                                                 priority="P3", requester_id=admin.id)
        db.session.flush()
        db.session.add_all([
            Comment(ticket_id=mine.id, user_id=employee.id, body="Fan noise after the firmware update",
                    tenant_id=employee.tenant_id),
            Comment(ticket_id=other.id, user_id=admin.id, body="Fan noise after the firmware update",
                    tenant_id=admin.tenant_id),
        ])
        db.session.commit()
        mine_number, other_number = mine.number, other.number
    login(client)
    labels = " ".join(r["label"] for r in _results(client, "firmware update"))
    assert mine_number in labels and other_number in labels  # matched through comments
    assert mine_number in " ".join(r["label"] for r in _results(client, mine_number))
    assert mine_number in " ".join(r["label"] for r in _results(client, "slow laptop"))  # any word order
    client.get("/logout")
    login(client, "employee", "Employee123!")
    labels = " ".join(r["label"] for r in _results(client, "firmware update"))
    assert mine_number in labels and other_number not in labels
