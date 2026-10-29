"""A Resolved change shows the missing post-implementation review up front and can be reviewed and closed in one step."""
from app import ApprovalChain, ChangePostImplementationReview, Ticket, User, db
from tests.test_app import app, client, login  # noqa: F401


def _resolved_change(app, number="CHG0009801"):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        ticket = Ticket(number=number, kind="change", title="New change", description="test", category="Software",
                        priority="P3", impact="Medium", urgency="Medium", requester_id=admin.id, state="Resolved", tenant_id=1)
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ApprovalChain(name="CAB", target_type="ticket", target_id=ticket.id, state="Approved", tenant_id=1))
        db.session.commit()
        return ticket.id


def test_resolved_change_without_review_shows_the_step_and_closes_in_one_go(client, app):
    ticket_id = _resolved_change(app)
    login(client)
    page = client.get(f"/ticket/{ticket_id}").data.decode()
    assert 'id="change-review"' in page
    assert "One step before closing: post-implementation review" in page
    assert 'href="#change-review"' in page, "Close leads to the missing step instead of an error"
    response = client.post(f"/change/{ticket_id}/pir", data={
        "outcome": "Successful", "summary": "Deployed as planned.", "then_close": "1"})
    assert response.status_code == 302
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        assert ticket.state == "Closed"
        assert ChangePostImplementationReview.query.filter_by(ticket_id=ticket_id).one().outcome == "Successful"
    assert 'id="change-review"' not in client.get(f"/ticket/{ticket_id}").data.decode()


def test_review_only_keeps_the_change_resolved_and_enables_close(client, app):
    ticket_id = _resolved_change(app, "CHG0009802")
    login(client)
    client.post(f"/change/{ticket_id}/pir", data={"outcome": "Successful", "summary": "Fine."})
    with app.app_context():
        assert db.session.get(Ticket, ticket_id).state == "Resolved"
    page = client.get(f"/ticket/{ticket_id}").data.decode()
    assert 'id="change-review"' not in page and 'form="ticket-close-form"' in page


def test_a_refused_close_still_keeps_the_review_and_explains_why(client, app):
    ticket_id = _resolved_change(app, "CHG0009803")
    with app.app_context():
        ApprovalChain.query.filter_by(target_id=ticket_id).delete()
        db.session.commit()
    login(client)
    page = client.post(f"/change/{ticket_id}/pir", data={"outcome": "Successful", "summary": "x", "then_close": "1"},
                       follow_redirects=True).data.decode()
    assert "Review saved, but CHG0009803 could not be closed" in page
    with app.app_context():
        assert ChangePostImplementationReview.query.filter_by(ticket_id=ticket_id).count() == 1


def test_the_record_update_button_saves_a_review_typed_in_the_review_form(client, app):
    ticket_id = _resolved_change(app, "CHG0009804")
    with app.app_context():
        db.session.get(Ticket, ticket_id).state = "Review"
        db.session.commit()
    login(client)
    page = client.get(f"/ticket/{ticket_id}").data.decode()
    assert 'form="task-record-form"' in page
    client.post(f"/ticket/{ticket_id}", data={
        "action": "update", "state": "Review", "impact": "Medium", "urgency": "Medium", "priority": "P3",
        "pir_outcome": "Successful", "pir_summary": "Typed below, saved with Update."})
    with app.app_context():
        review = ChangePostImplementationReview.query.filter_by(ticket_id=ticket_id).one()
        assert review.summary == "Typed below, saved with Update."
