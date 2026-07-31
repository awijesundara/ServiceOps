"""Tests for the compliance-audit remediation: GDPR Art. 17 (right to
erasure), GDPR Art. 20 (data portability), configurable password policy
enforced consistently, and cross-tenant lookup fixes in seeding/approval
routing (ISO 27001 A.5.23).
"""
from app import (
    Audit, CatalogItem, GroupMember, PlatformSetting, SupportGroup, Tenant,
    User, catalog_fulfillment_group, db, seed_itil,
)
from tests.test_app import app, client, login


def test_admin_cannot_erase_own_account(client, app):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
    response = client.post(f"/admin/users/{admin_id}/erase")
    assert response.status_code == 400


def test_active_account_must_be_deactivated_before_erasure(client, app):
    login(client)
    with app.app_context():
        target = User(
            username="still.active", name="Still Active", email="still.active@test.invalid",
            password_hash="x", role="requester", active=True, tenant_id=1,
        )
        db.session.add(target)
        db.session.commit()
        target_id = target.id
    response = client.post(f"/admin/users/{target_id}/erase")
    assert response.status_code == 400


def test_erasing_a_deactivated_user_scrubs_personal_fields_and_is_idempotent_guarded(client, app):
    login(client)
    with app.app_context():
        target = User(
            username="leaving.employee", name="Leaving Employee",
            email="leaving.employee@test.invalid", password_hash="x",
            role="requester", active=False, title="Analyst", department="Finance",
            business_phone="+81-1-2345", tenant_id=1,
        )
        db.session.add(target)
        db.session.commit()
        target_id = target.id

    erased = client.post(f"/admin/users/{target_id}/erase")
    assert erased.status_code == 302
    with app.app_context():
        row = db.session.get(User, target_id)
        assert row.erased_at is not None
        assert row.name == f"Erased user #{target_id}"
        assert "leaving.employee" not in row.email
        assert row.title == ""
        assert row.department == ""
        assert row.business_phone == ""
        # The erasure audit entry itself must not carry the erased PII forward.
        entry = Audit.query.filter_by(action="erase").order_by(Audit.id.desc()).first()
        assert entry is not None
        assert "Leaving Employee" not in (entry.target or "") + (entry.details or "")
        assert "leaving.employee@test.invalid" not in (entry.target or "") + (entry.details or "")

    already_erased = client.post(f"/admin/users/{target_id}/erase")
    assert already_erased.status_code == 400


def test_profile_export_returns_own_data_as_json(client, app):
    login(client)
    response = client.get("/profile/export")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert response.json["username"] == "admin"


def test_admin_created_password_must_meet_minimum_length(client, app):
    login(client)
    with app.app_context():
        db.session.add(PlatformSetting(key="PASSWORD_MIN_LENGTH", value="16", encrypted=False))
        db.session.commit()

    rejected = client.post("/admin/users/new", data={
        "username": "shortpass.user", "name": "Short Pass", "email": "shortpass@test.invalid",
        "password": "Short1234!", "role": "requester",
    })
    assert rejected.status_code == 200
    with app.app_context():
        assert User.query.filter_by(username="shortpass.user").first() is None

    accepted = client.post("/admin/users/new", data={
        "username": "longpass.user", "name": "Long Pass", "email": "longpass@test.invalid",
        "password": "ThisPasswordIsLongEnough1!", "role": "requester",
    })
    assert accepted.status_code == 302
    with app.app_context():
        assert User.query.filter_by(username="longpass.user").first() is not None


def test_seed_itil_and_fulfillment_lookup_are_tenant_scoped(app):
    """seed_itil() and catalog_fulfillment_group() previously looked up
    "Service Desk"/"Change Control Board" by name with no tenant filter --
    proves a second tenant gets its own groups rather than reusing (or
    colliding with) tenant 1's.
    """
    with app.app_context():
        other_tenant = Tenant(id=2, slug="other-seed", name="Other seed tenant")
        other_admin = User(
            username="other.seed.admin", name="Other Seed Admin",
            email="other.seed.admin@test.invalid", password_hash="x",
            role="admin", tenant_id=2,
        )
        db.session.add_all([other_tenant, other_admin])
        db.session.commit()

        seed_itil(other_admin)
        db.session.commit()

        tenant1_service_desk = SupportGroup.query.filter_by(name="Service Desk", tenant_id=1).one()
        tenant2_service_desk = SupportGroup.query.filter_by(name="Service Desk", tenant_id=2).one()
        assert tenant1_service_desk.id != tenant2_service_desk.id

        item = CatalogItem(
            name="Other tenant's item", category="Hardware", description="d",
            delivery_days=1, active=True, tenant_id=2,
        )
        db.session.add(item)
        db.session.commit()
        resolved = catalog_fulfillment_group(item)
        assert resolved.id == tenant2_service_desk.id
