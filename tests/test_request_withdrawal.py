"""B-461: requesters withdraw catalog requests -- approval chains stop,
fulfilment tasks are skipped, the REQ settles, outsiders are refused."""
from app import ApprovalChain, CatalogItem, CatalogRequest, CatalogTask, Notification, RequestedItem, TaskHistory, db
from tests.test_app import app, client, login


def _order(client, app, approval_required=True, name="Withdrawable item"):
    with app.app_context():
        item = CatalogItem(name=name, category="Access", description="x", approval_required=approval_required)
        db.session.add(item)
        db.session.commit()
        item_id = item.id
    login(client, "employee", "Employee123!")
    client.post(f"/catalog/{item_id}/order", data={"details": "Please"}, follow_redirects=True)
    with app.app_context():
        ritm = RequestedItem.query.filter_by(catalog_item_id=item_id).one()
        return ritm.id, ritm.request_id


def test_requester_withdraws_an_item_awaiting_approval(client, app):
    ritm_id, request_id = _order(client, app)
    with app.app_context():
        chain = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm_id).one()
        approver_ids = {vote.approver_id for gate in chain.gates for vote in gate.votes if vote.state == "Requested"}
        assert approver_ids
    page = client.get(f"/ritm/{ritm_id}")
    assert b"withdraw-panel" in page.data
    assert client.post(f"/ritm/{ritm_id}/withdraw", data={"reason": "No longer needed"}).status_code == 302
    with app.app_context():
        ritm = db.session.get(RequestedItem, ritm_id)
        chain = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm_id).one()
        assert ritm.state == "Cancelled"
        assert chain.state == "Cancelled"
        assert all(vote.state in ("No Longer Required", "Not Requested", "Approved")
                   for gate in chain.gates for vote in gate.votes)
        assert db.session.get(CatalogRequest, request_id).state == "Cancelled"
        assert TaskHistory.query.filter_by(target_type="ritm", target_id=ritm_id, event="Request withdrawn").count() == 1
        for approver_id in approver_ids:
            assert Notification.query.filter(Notification.user_id == approver_id,
                                             Notification.title.contains("withdrawn")).count() == 1
    assert b"withdraw-panel" not in client.get(f"/ritm/{ritm_id}").data
    # A second withdrawal of a closed item is refused.
    client.post(f"/ritm/{ritm_id}/withdraw", data={"reason": "again"})
    with app.app_context():
        assert TaskHistory.query.filter_by(target_type="ritm", target_id=ritm_id, event="Request withdrawn").count() == 1


def test_withdrawing_the_request_skips_open_fulfilment_tasks(client, app):
    ritm_id, request_id = _order(client, app, approval_required=False, name="No approval item")
    with app.app_context():
        assert CatalogTask.query.filter_by(requested_item_id=ritm_id).count() >= 1
    assert client.post(f"/request/{request_id}/withdraw", data={"reason": "Ordered by mistake"}).status_code == 302
    with app.app_context():
        assert {task.state for task in CatalogTask.query.filter_by(requested_item_id=ritm_id)} == {"Closed Skipped"}
        assert db.session.get(RequestedItem, ritm_id).state == "Cancelled"
        assert db.session.get(CatalogRequest, request_id).state == "Cancelled"


def test_withdrawal_needs_a_reason(client, app):
    ritm_id, _ = _order(client, app)
    client.post(f"/ritm/{ritm_id}/withdraw", data={"reason": "  "})
    with app.app_context():
        assert db.session.get(RequestedItem, ritm_id).state != "Cancelled"


def test_only_the_requester_or_an_administrator_can_withdraw(client, app):
    """The line manager approving the item can see it but not withdraw it."""
    ritm_id, request_id = _order(client, app)
    client.post("/logout")
    login(client, "database.manager", "Manager123!")
    assert b"withdraw-panel" not in client.get(f"/ritm/{ritm_id}").data
    assert client.post(f"/ritm/{ritm_id}/withdraw", data={"reason": "Not mine"}).status_code in (302, 403)
    assert client.post(f"/request/{request_id}/withdraw", data={"reason": "Not mine"}).status_code in (302, 403)
    with app.app_context():
        assert db.session.get(RequestedItem, ritm_id).state != "Cancelled"
    client.post("/logout")
    login(client)
    assert client.post(f"/request/{request_id}/withdraw", data={"reason": "Admin clean-up"}).status_code == 302
    with app.app_context():
        assert db.session.get(RequestedItem, ritm_id).state == "Cancelled"
