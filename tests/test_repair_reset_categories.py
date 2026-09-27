"""tools/repair_reset_categories.py: restores incident categories the empty
category picker reset to "General" (fixed in 1.104.11), from ticket history."""
from datetime import datetime, timezone

from app import Audit, TaskHistory, Tenant, Ticket, TicketCategory, User, db
from tests.test_app import app  # noqa: F401  (pytest fixture)
from tools.repair_reset_categories import repair

IN_WINDOW = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)
AFTER_WINDOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


def reset_incident(number, old_category, old_subcategory="", new_subcategory="", when=IN_WINDOW, tenant_id=1):
    requester = User.query.filter_by(tenant_id=tenant_id).first()
    ticket = Ticket(number=number, kind="incident", title=number, description="d", category="General",
                    subcategory=new_subcategory, priority="P3", state="In Progress",
                    requester_id=requester.id, tenant_id=tenant_id)
    db.session.add(ticket)
    db.session.flush()
    db.session.add(TaskHistory(target_type="ticket", target_id=ticket.id, event="Field changed",
                               field_name="category", old_value=old_category, new_value="General",
                               created_at=when))
    if old_subcategory:
        db.session.add(TaskHistory(target_type="ticket", target_id=ticket.id, event="Field changed",
                                   field_name="subcategory", old_value=old_subcategory,
                                   new_value=new_subcategory, created_at=when))
    db.session.commit()
    return ticket.id


def test_restores_category_and_subcategory_from_the_reset_save(app):
    with app.app_context():
        ticket_id = reset_incident("INC0090001", "Network", "VPN")
        dry_run = repair(apply_changes=False)
        assert dry_run == ["RESTORE INC0090001 (tenant 1): category General -> Network, subcategory '' -> 'VPN'"]
        assert db.session.get(Ticket, ticket_id).category == "General"

        repair(apply_changes=True)
        ticket = db.session.get(Ticket, ticket_id)
        assert (ticket.category, ticket.subcategory) == ("Network", "VPN")
        restored = TaskHistory.query.filter_by(target_id=ticket_id, event="Category restored").all()
        assert {(row.field_name, row.new_value) for row in restored} == {("category", "Network"),
                                                                        ("subcategory", "VPN")}
        assert Audit.query.filter_by(action="repair", target="INC0090001").count() == 1
        assert repair(apply_changes=True) == []


def test_maps_categories_relabelled_by_the_itil_migration(app):
    with app.app_context():
        reset_incident("INC0090002", "Access")
        assert repair() == ["RESTORE INC0090002 (tenant 1): category General -> Access / Identity"]


def test_leaves_deliberate_or_out_of_window_changes_alone(app):
    with app.app_context():
        reset_incident("INC0090003", "Network", when=AFTER_WINDOW)
        changed_later = reset_incident("INC0090004", "Network")
        db.session.add(TaskHistory(target_type="ticket", target_id=changed_later, event="Field changed",
                                   field_name="category", old_value="General", new_value="Hardware",
                                   created_at=datetime(2026, 9, 26, 13, 0, tzinfo=timezone.utc)))
        db.session.add(TaskHistory(target_type="ticket", target_id=changed_later, event="Field changed",
                                   field_name="category", old_value="Hardware", new_value="General",
                                   created_at=datetime(2026, 9, 26, 12, 30, tzinfo=timezone.utc)))
        TicketCategory.query.filter_by(tenant_id=1, name="Security").one().active = False
        reset_incident("INC0090005", "Security")
        db.session.commit()
        assert repair() == [
            "SKIP    INC0090004 (tenant 1): category changed again after the reset",
            "SKIP    INC0090005 (tenant 1): 'Security' is not an active category for this tenant",
        ]


def test_only_restores_categories_that_exist_in_the_incidents_own_tenant(app):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="repair-other", name="Other"))
        db.session.add(User(username="repair.other", name="Other", email="ro@test.invalid", role="agent",
                            tenant_id=2, password_hash="x"))
        db.session.commit()
        reset_incident("INC0090006", "Network", tenant_id=2)
        assert TicketCategory.query.filter_by(tenant_id=2).count() == 0
        # Tenant 1 has an active "Network"; tenant 2's incident must not borrow it.
        assert repair() == ["SKIP    INC0090006 (tenant 2): 'Network' is not an active category for this tenant"]
        db.session.add(TicketCategory(tenant_id=2, name="Network"))
        db.session.commit()
        assert repair() == ["RESTORE INC0090006 (tenant 2): category General -> Network"]
