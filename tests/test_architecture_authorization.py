"""Role hierarchy and acting-role demotion must agree across shared readers/writers."""
import pytest
from flask import session

from app import (CatalogItem, CatalogRequest, EnterpriseRecord, RequestedItem, Ticket, User, UserRoleGrant,
                 db, manageable_ticket_ids, user_can_add_request_item, user_can_manage_enterprise_record,
                 user_can_manage_ritm, user_can_manage_ticket, user_requires_mfa_by_policy,
                 visible_catalog_request_query, visible_enterprise_record_query, visible_ticket_query)
from tests.test_app import app  # noqa: F401


@pytest.mark.parametrize("operation", ["ticket_read", "ticket_write", "ticket_bulk", "request_read", "request_write",
                                       "request_add", "enterprise_read", "enterprise_write"])
@pytest.mark.parametrize("acting_requester", [False, True])
def test_hierarchy_and_demotion_are_consistent(app, operation, acting_requester):
    with app.test_request_context("/"):
        employee = User.query.filter_by(username="employee").one()
        if acting_requester:
            actor = User.query.filter_by(username="admin").one()
            db.session.add(UserRoleGrant(user_id=actor.id, role="requester"))
            session["_acting_role"] = "requester"
        else:
            actor = User(username="review.superadmin", name="Platform admin", email="review.superadmin@test.invalid",
                         password_hash="unused", role="superadmin")
            db.session.add(actor)
        ticket = Ticket(number="INC9900001", kind="incident", title="Other person's work", description="test",
                        requester_id=employee.id)
        request = CatalogRequest(number="REQ9900001", requested_by_id=employee.id, requested_for_id=employee.id)
        record = EnterpriseRecord(number="PRB9900001", domain="problem", record_type="problem", title="Other case",
                                  description="test", requester_id=employee.id)
        db.session.add_all([ticket, request, record])
        db.session.flush()
        item = RequestedItem(number="RITM9900001", request_id=request.id, catalog_item_id=CatalogItem.query.first().id)
        db.session.add(item)
        db.session.commit()
        answers = {
            "ticket_read": lambda: visible_ticket_query(actor).filter_by(id=ticket.id).first() is not None,
            "ticket_write": lambda: user_can_manage_ticket(actor, ticket),
            "ticket_bulk": lambda: ticket.id in manageable_ticket_ids(actor, [ticket]),
            "request_read": lambda: visible_catalog_request_query(actor).filter_by(id=request.id).first() is not None,
            "request_write": lambda: user_can_manage_ritm(actor, item),
            "request_add": lambda: user_can_add_request_item(actor, request),
            "enterprise_read": lambda: visible_enterprise_record_query(actor).filter_by(id=record.id).first() is not None,
            "enterprise_write": lambda: user_can_manage_enterprise_record(actor, record),
        }
        assert answers[operation]() is not acting_requester


def test_superadmin_cannot_bypass_mandatory_admin_mfa_policy(app):
    from app import PlatformSetting
    with app.app_context():
        actor = User(username="mfa.superadmin", name="Platform admin", email="mfa.superadmin@test.invalid",
                     password_hash="unused", role="superadmin")
        db.session.add(actor)
        db.session.add(PlatformSetting(key="REQUIRE_MFA_FOR_ADMIN", value="true"))
        db.session.commit()
        assert user_requires_mfa_by_policy(actor)


def test_request_item_add_permission_rejects_another_tenant(app):
    from app import Tenant
    with app.app_context():
        other = Tenant(slug="request-other", name="Other")
        db.session.add(other)
        db.session.flush()
        actor = User.query.filter_by(username="admin").one()
        user = User(username="other.requester", name="Other", email="other.requester@test.invalid",
                    password_hash="unused", role="requester", tenant_id=other.id)
        db.session.add(user)
        db.session.flush()
        request = CatalogRequest(number="REQ9900002", requested_by_id=user.id, requested_for_id=user.id,
                                 tenant_id=other.id)
        db.session.add(request)
        db.session.commit()
        assert not user_can_add_request_item(actor, request)
