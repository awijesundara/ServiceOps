"""A catalog request from order to delivery: the approver sees what was asked
for, is told the decision was recorded, the fulfiller can finish a quick task
straight from Open, and the person it is for hears at each step."""
from app import ApprovalChain, CatalogItem, CatalogTask, Notification, RequestedItem, User, db
from tests.test_app import app, client, login  # noqa: F401


def _order(client, app):
    with app.app_context():
        item = CatalogItem(name="Laptop", category="Hardware", description="x", approval_required=True)
        db.session.add(item)
        db.session.commit()
        item_id = item.id
    login(client, "employee", "Employee123!")
    client.post(f"/catalog/{item_id}/order", data={"details": "14-inch, Japanese keyboard"})
    client.get("/logout")
    with app.app_context():
        ritm = RequestedItem.query.filter_by(catalog_item_id=item_id).one()
        chain = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm.id).one()
        manager = User.query.filter_by(username="database.manager").one()
        vote = next(v for g in chain.gates for v in g.votes if v.approver_id == manager.id and v.state == "Requested")
        employee_id = User.query.filter_by(username="employee").one().id
        return ritm.id, vote.id, employee_id


def _titles(app, user_id):
    with app.app_context():
        return [n.title for n in Notification.query.filter_by(user_id=user_id)]


def test_laptop_request_from_approval_to_delivery(client, app):
    ritm_id, vote_id, employee_id = _order(client, app)
    login(client, "database.manager", "Manager123!")
    assert "14-inch, Japanese keyboard" in client.get("/approval-chains").get_data(as_text=True)
    decided = client.post(f"/approval-votes/{vote_id}/decide", data={"decision": "Approved"}, follow_redirects=True)
    assert "You approved" in decided.get_data(as_text=True)
    assert any("was approved" in t for t in _titles(app, employee_id))
    client.get("/logout")
    login(client)
    with app.app_context():
        task_id = CatalogTask.query.filter_by(requested_item_id=ritm_id).first().id
    page = client.get(f"/catalog-task/{task_id}").get_data(as_text=True)
    assert "14-inch, Japanese keyboard" in page and 'value="Closed Complete"' in page
    client.post(f"/catalog-task/{task_id}", data={"state": "Closed Complete", "work_notes": "Delivered"})
    with app.app_context():
        assert db.session.get(CatalogTask, task_id).state == "Closed Complete"
        assert db.session.get(RequestedItem, ritm_id).state == "Closed Complete"
    assert any("is ready" in t for t in _titles(app, employee_id))


def test_rejection_reaches_the_person(client, app):
    _, vote_id, employee_id = _order(client, app)
    login(client, "database.manager", "Manager123!")
    decided = client.post(f"/approval-votes/{vote_id}/decide", data={"decision": "Rejected", "comments": "Budget"},
                          follow_redirects=True)
    assert "You rejected" in decided.get_data(as_text=True)
    assert any("was not approved" in t for t in _titles(app, employee_id))
