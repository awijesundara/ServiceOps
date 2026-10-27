"""Dependent records take tenant_id from their parent, whoever (or whatever) writes them."""
from datetime import timedelta

from app import (CatalogRequest, ChecklistItem, MajorIncidentProfile, OperationalTask, RequestedItem, SLADefinition,
                 SupportGroup, TaskHistory, TaskNote, TaskSLA, Tenant, Ticket, TicketAssignmentGroup, User,
                 UserPreference, db, now)
from serviceops_core.dependent_tenancy import DIRECT_PARENTS, POLYMORPHIC_PARENTS, RECORD_TYPES
from tests.test_app import app, client, login  # noqa: F401


def other_tenant_ticket():
    tenant = Tenant.query.filter(Tenant.id != 1).first()
    if tenant is None:
        tenant = Tenant(name="Second org", slug="second-org")
        db.session.add(tenant)
        db.session.flush()
    requester = User(username="t2.requester", name="T2", email="t2@example.com", password_hash="x",
                     role="requester", tenant_id=tenant.id)
    db.session.add(requester)
    db.session.flush()
    ticket = Ticket(number="INC0077777", kind="incident", title="Other tenant", description="x",
                    requester_id=requester.id, tenant_id=tenant.id, state="New", priority="P3")
    group = SupportGroup(name="T2 Ops", tenant_id=tenant.id)
    db.session.add_all([ticket, group])
    db.session.flush()
    return tenant.id, ticket, requester, group


def test_background_writes_take_the_parent_tenant(app):
    # No request and no signed-in user, as in a worker.
    with app.app_context():
        tenant_id, ticket, requester, group = other_tenant_ticket()
        rows = [
            OperationalTask(number="CTASK0077777", parent_type="ticket", parent_id=ticket.id, task_kind="change",
                            task_type="Implementation", title="Do it", state="Open", assignment_group_id=group.id),
            TaskHistory(target_type="ticket", target_id=ticket.id, event="Created"),
            ChecklistItem(ticket_id=ticket.id, text="Step"),
            TicketAssignmentGroup(ticket_id=ticket.id, group_id=group.id),
            MajorIncidentProfile(ticket_id=ticket.id),
            UserPreference(user_id=requester.id),
        ]
        db.session.add_all(rows)
        db.session.flush()
        assert {type(row).__name__: row.tenant_id for row in rows} == {type(row).__name__: tenant_id for row in rows}
        # A note on a task resolves through the task's own tenant.
        note = TaskNote(target_type="operational_task", target_id=rows[0].id, user_id=requester.id, body="n")
        db.session.add(note)
        db.session.flush()
        assert note.tenant_id == tenant_id
        db.session.rollback()


def test_parent_tenant_wins_over_the_signed_in_user(app, client):
    login(client)  # tenant 1 administrator
    with app.test_request_context():
        from flask_login import login_user
        login_user(User.query.filter_by(username="admin").one())
        tenant_id, ticket, _, _ = other_tenant_ticket()
        definition = SLADefinition(name="T2 response", target_type="ticket", priority="P3", duration_minutes=60,
                                   tenant_id=tenant_id)
        db.session.add(definition)
        db.session.flush()
        sla = TaskSLA(definition_id=definition.id, target_type="ticket", target_id=ticket.id,
                      breach_at=now() + timedelta(hours=1))
        history = TaskHistory(target_type="ticket", target_id=ticket.id, event="Viewed")
        db.session.add_all([sla, history])
        db.session.flush()
        assert sla.tenant_id == history.tenant_id == tenant_id != 1
        db.session.rollback()


def test_request_item_children_resolve(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        request = CatalogRequest(number="REQ0077777", requested_by_id=admin.id, requested_for_id=admin.id, tenant_id=1)
        db.session.add(request)
        db.session.flush()
        history = TaskHistory(target_type="request", target_id=request.id, event="Submitted")
        db.session.add(history)
        db.session.flush()
        assert history.tenant_id == 1
        db.session.rollback()


def test_every_mapped_parent_has_a_tenant_column():
    for _, parent in DIRECT_PARENTS.values():
        assert "tenant_id" in parent.__table__.c, parent
    for model in RECORD_TYPES.values():
        assert "tenant_id" in model.__table__.c, model
    for model in (*DIRECT_PARENTS, *POLYMORPHIC_PARENTS):
        assert "tenant_id" in model.__table__.c, model
    assert RequestedItem in RECORD_TYPES.values()


def test_parent_added_in_the_same_flush(app):
    # The child is linked through the relationship, so its foreign key is unset until insert.
    with app.app_context():
        tenant_id, ticket, requester, _ = other_tenant_ticket()
        sibling = Ticket(number="INC0077778", kind="incident", title="New", description="x",
                         requester_id=requester.id, tenant_id=tenant_id, state="New", priority="P3")
        item = ChecklistItem(text="Step", ticket=sibling)
        db.session.add_all([sibling, item])
        db.session.flush()
        assert item.tenant_id == tenant_id
        db.session.rollback()


def test_approval_chain_history_takes_the_chain_tenant(app):
    from app import ApprovalChain
    with app.app_context():
        tenant_id, ticket, _, _ = other_tenant_ticket()
        chain = ApprovalChain(name="T2 chain", target_type="ticket", target_id=ticket.id, tenant_id=tenant_id)
        db.session.add(chain)
        db.session.flush()
        history = TaskHistory(target_type="approval_chain", target_id=chain.id, event="Cancelled")
        db.session.add(history)
        db.session.flush()
        assert history.tenant_id == tenant_id
        db.session.rollback()
