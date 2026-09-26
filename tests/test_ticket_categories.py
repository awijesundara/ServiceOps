"""Admin-configurable ITIL v4/ServiceNow-style ticket category taxonomy (B-388 follow-up)."""
from werkzeug.security import generate_password_hash

from app import ServiceOffering, Tenant, Ticket, TicketCategory, TicketSubcategory, User, db, normalize_ticket_category, normalize_ticket_subcategory
from tests.test_app import app, client, group_id, login  # noqa: F401  (pytest fixtures)


def test_admin_can_create_update_and_deactivate_a_category_and_subcategory(client, app):
    login(client)
    created = client.post("/service-operations/settings", data={
        "action": "create_ticket_category", "name": "Facilities",
    })
    assert created.status_code == 302
    with app.app_context():
        category = TicketCategory.query.filter_by(name="Facilities").one()
        category_id = category.id
        assert category.active is True and category.tenant_id == 1

    sub_created = client.post("/service-operations/settings", data={
        "action": "create_ticket_subcategory", "category_id": category_id, "name": "HVAC",
    })
    assert sub_created.status_code == 302
    with app.app_context():
        subcategory = TicketSubcategory.query.filter_by(category_id=category_id, name="HVAC").one()
        subcategory_id = subcategory.id
        assert subcategory.active is True and subcategory.default_service_offering_id is None

    renamed = client.post("/service-operations/settings", data={
        "action": "update_ticket_category", "category_id": category_id, "name": "Facilities & Office", "active": "on",
    })
    assert renamed.status_code == 302
    deactivated_sub = client.post("/service-operations/settings", data={
        "action": "update_ticket_subcategory", "subcategory_id": subcategory_id, "name": "HVAC",
    })  # "active" checkbox omitted -> deactivates
    assert deactivated_sub.status_code == 302
    with app.app_context():
        category = db.session.get(TicketCategory, category_id)
        subcategory = db.session.get(TicketSubcategory, subcategory_id)
        assert category.name == "Facilities & Office"
        assert subcategory.active is False
        # Deactivating removes it from the ticket form's offered list, not the row itself.
        assert TicketSubcategory.query.filter_by(id=subcategory_id).count() == 1


def test_duplicate_category_and_subcategory_names_are_rejected(client, app):
    login(client)
    with app.app_context():
        existing = TicketCategory.query.filter_by(tenant_id=1, name="Hardware").one()
        existing_id = existing.id
    duplicate = client.post("/service-operations/settings", data={
        "action": "create_ticket_category", "name": "hardware",  # case-insensitive collision
    })
    assert duplicate.status_code == 409
    client.post("/service-operations/settings", data={
        "action": "create_ticket_subcategory", "category_id": existing_id, "name": "Laptop",  # already seeded
    })
    duplicate_sub = client.post("/service-operations/settings", data={
        "action": "create_ticket_subcategory", "category_id": existing_id, "name": "laptop",
    })
    assert duplicate_sub.status_code == 409


def test_categories_and_subcategories_are_tenant_isolated(client, app):
    with app.app_context():
        other_tenant = Tenant(slug="other-category-org", name="Other Category Org")
        db.session.add(other_tenant)
        db.session.flush()
        other_admin = User(
            username="other.category.admin", name="Other Category Admin",
            email="other.category.admin@test.invalid",
            password_hash=generate_password_hash("Other123!"),
            role="admin", tenant_id=other_tenant.id,
        )
        db.session.add(other_admin)
        db.session.flush()
        other_category = TicketCategory(name="Secret Category", active=True, tenant_id=other_tenant.id)
        db.session.add(other_category)
        db.session.commit()
        other_category_id = other_category.id

    login(client)
    page = client.get("/service-operations/settings/ticket-categories")
    assert b"Secret Category" not in page.data
    # Tenant 1's admin cannot add a subcategory under another tenant's category.
    forbidden = client.post("/service-operations/settings", data={
        "action": "create_ticket_subcategory", "category_id": other_category_id, "name": "Reach across tenants",
    })
    assert forbidden.status_code == 404


def test_ticket_create_validates_category_and_lets_subcategory_fall_back_to_other(client, app):
    login(client)
    team_id = group_id(app, "Network")
    base = {"impact": "Medium", "urgency": "Medium", "contact_type": "Self-service", "notify": "Email", "group_id": team_id}

    modeled = client.post("/tickets/new/incident", data={
        **base, "title": "Printer offline", "description": "d", "category": "Hardware", "subcategory": "Printer",
    }, follow_redirects=True)
    assert modeled.status_code == 200
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Printer offline").one()
        assert ticket.category == "Hardware" and ticket.subcategory == "Printer"

    other_text = client.post("/tickets/new/incident", data={
        **base, "title": "Unusual request", "description": "d", "category": "Hardware",
        "subcategory": "__other__", "subcategory_other": "Something not yet modeled",
    }, follow_redirects=True)
    assert other_text.status_code == 200
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Unusual request").one()
        assert ticket.category == "Hardware" and ticket.subcategory == "Something not yet modeled"

    unrecognized_category = client.post("/tickets/new/incident", data={
        **base, "title": "Odd category", "description": "d", "category": "Not A Real Category",
    }, follow_redirects=True)
    assert unrecognized_category.status_code == 200
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Odd category").one()
        assert ticket.category == "General"  # falls back rather than rejecting


def test_admin_page_and_ticket_forms_render_the_new_fields(client, app):
    login(client)
    admin_page = client.get("/service-operations/settings/ticket-categories")
    assert admin_page.status_code == 200
    assert b"Ticket categories" in admin_page.data and b"Hardware" in admin_page.data and b"Printer" in admin_page.data
    new_incident = client.get("/tickets/new/incident")
    assert new_incident.status_code == 200
    assert b'name="category"' in new_incident.data and b'name="subcategory"' in new_incident.data
    new_change = client.get("/tickets/new/change")
    assert new_change.status_code == 200
    assert b'name="category"' in new_change.data
    admin_section_page = client.get("/admin/section/service-configuration")
    assert admin_section_page.status_code == 200
    assert b"Ticket categories" in admin_section_page.data


def test_normalize_helpers_are_case_insensitive_and_never_raise(app):
    with app.app_context():
        assert normalize_ticket_category(1, "hardware") == "Hardware"
        assert normalize_ticket_category(1, "not a category") == "General"
        assert normalize_ticket_category(1, "") == "General"
        assert normalize_ticket_subcategory(1, "Hardware", "printer") == "Printer"
        assert normalize_ticket_subcategory(1, "Hardware", "A totally custom description") == "A totally custom description"
        assert normalize_ticket_subcategory(1, "Hardware", "") == ""


def test_subcategory_can_suggest_a_service_offering(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        offering = ServiceOffering(name="Print Services", owner_id=admin_id, tenant_id=1)
        db.session.add(offering)
        db.session.flush()
        category_id = TicketCategory.query.filter_by(tenant_id=1, name="Hardware").one().id
        offering_id = offering.id
        db.session.commit()
    linked = client.post("/service-operations/settings", data={
        "action": "create_ticket_subcategory", "category_id": category_id, "name": "Label Printer",
        "default_service_offering_id": offering_id,
    })
    assert linked.status_code == 302
    with app.app_context():
        subcategory = TicketSubcategory.query.filter_by(category_id=category_id, name="Label Printer").one()
        assert subcategory.default_service_offering_id == offering_id
