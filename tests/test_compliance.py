"""Tests for the compliance-audit remediation: GDPR Art. 17 (right to
erasure), GDPR Art. 20 (data portability), configurable password policy
enforced consistently, and cross-tenant lookup fixes in seeding/approval
routing (ISO 27001 A.5.23).
"""
from datetime import timedelta

from app import (
    Audit, CatalogItem, ClientContact, ClientOrganization, ClientTicket,
    DataRetentionPolicy, GroupMember, PlatformSetting, RecordLegalHold,
    SupportGroup, Tenant, User, catalog_fulfillment_group, db, now,
    process_data_retention_purge, seed_itil,
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


def test_client_contact_erasure_scrubs_fields_blocks_active_hold_and_is_idempotent(app, client):
    login(client)
    with app.app_context():
        organization = ClientOrganization(tenant_id=1, name="Data Governance Test Org")
        db.session.add(organization)
        db.session.flush()
        contact = ClientContact(
            tenant_id=1, organization_id=organization.id, name="Leaving Customer",
            email="leaving.customer@test.invalid", phone="+81-1-2345", job_title="Buyer",
        )
        db.session.add(contact)
        db.session.commit()
        contact_id = contact.id

    # A legal hold blocks erasure entirely, admin route included.
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        db.session.add(RecordLegalHold(
            tenant_id=1, record_type="client_contact", record_id=contact_id,
            reason="Active litigation hold", applied_by_id=admin_id,
        ))
        db.session.commit()
    held = client.post("/client-management/contacts", data={"action": "erase", "contact_id": contact_id})
    assert held.status_code == 302
    with app.app_context():
        assert db.session.get(ClientContact, contact_id).erased_at is None

    with app.app_context():
        RecordLegalHold.query.filter_by(record_type="client_contact", record_id=contact_id).update(
            {"released_at": now()}
        )
        db.session.commit()

    erased = client.post("/client-management/contacts", data={"action": "erase", "contact_id": contact_id})
    assert erased.status_code == 302
    with app.app_context():
        row = db.session.get(ClientContact, contact_id)
        assert row.erased_at is not None
        assert row.name == f"Erased contact #{contact_id}"
        assert "leaving.customer" not in row.email
        assert row.phone == ""
        assert row.job_title == ""
        entry = Audit.query.filter_by(action="erase").order_by(Audit.id.desc()).first()
        assert "Leaving Customer" not in (entry.target or "") + (entry.details or "")
        assert "leaving.customer@test.invalid" not in (entry.target or "") + (entry.details or "")

    already_erased = client.post("/client-management/contacts", data={"action": "erase", "contact_id": contact_id})
    assert already_erased.status_code == 302
    with app.app_context():
        assert Audit.query.filter_by(action="erase").count() == 1  # not re-erased/re-audited


def test_client_contact_erase_requires_admin_and_is_tenant_isolated(app, client):
    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        manager = User.query.filter_by(username="database.manager").one()
        db.session.add(GroupMember(group_id=sysops.id, user_id=manager.id, role="member", tenant_id=1))
        organization = ClientOrganization(tenant_id=1, name="Tenant-Isolation Org")
        db.session.add(organization)
        db.session.flush()
        contact = ClientContact(
            tenant_id=1, organization_id=organization.id, name="Isolated Contact",
            email="isolated.contact@test.invalid",
        )
        db.session.add(contact)
        other_tenant = Tenant(id=2, slug="contact-other", name="Other Tenant")
        db.session.add(other_tenant)
        db.session.flush()
        other_org = ClientOrganization(tenant_id=2, name="Other Tenant Org")
        db.session.add(other_org)
        db.session.flush()
        other_contact = ClientContact(
            tenant_id=2, organization_id=other_org.id, name="Other Tenant Contact",
            email="other.tenant.contact@test.invalid",
        )
        db.session.add(other_contact)
        db.session.commit()
        contact_id, other_contact_id = contact.id, other_contact.id

    login(client, "database.manager", "Manager123!")
    not_admin = client.post("/client-management/contacts", data={"action": "erase", "contact_id": contact_id})
    assert not_admin.status_code == 403
    with app.app_context():
        assert db.session.get(ClientContact, contact_id).erased_at is None
    client.post("/logout")

    login(client)
    cross_tenant = client.post("/client-management/contacts", data={"action": "erase", "contact_id": other_contact_id})
    assert cross_tenant.status_code == 404
    with app.app_context():
        assert db.session.get(ClientContact, other_contact_id).erased_at is None


def test_client_contact_export_returns_own_data_and_is_visibility_scoped(app, client):
    login(client)
    with app.app_context():
        organization = ClientOrganization(tenant_id=1, name="Export Test Org")
        db.session.add(organization)
        db.session.flush()
        contact = ClientContact(
            tenant_id=1, organization_id=organization.id, name="Export Contact",
            email="export.contact@test.invalid",
        )
        db.session.add(contact)
        db.session.flush()
        ticket = ClientTicket(
            tenant_id=1, number="CXT-EXPORT-1", subject="A support question",
            description="d", contact_id=contact.id, organization_id=organization.id,
            support_group_id=SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one().id,
            created_by_id=User.query.filter_by(username="admin").one().id,
        )
        db.session.add(ticket)
        db.session.commit()
        contact_id = contact.id

    response = client.get(f"/client-management/contacts/{contact_id}/export")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert response.json["email"] == "export.contact@test.invalid"
    assert response.json["tickets"][0]["subject"] == "A support question"


def test_data_retention_purge_erases_inactive_contacts_past_window_and_skips_legal_hold(app, client):
    login(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        organization = ClientOrganization(tenant_id=1, name="Retention Test Org")
        db.session.add(organization)
        db.session.flush()
        stale = ClientContact(
            tenant_id=1, organization_id=organization.id, name="Stale Contact",
            email="stale.contact@test.invalid", active=False,
        )
        held = ClientContact(
            tenant_id=1, organization_id=organization.id, name="Held Contact",
            email="held.contact@test.invalid", active=False,
        )
        fresh = ClientContact(
            tenant_id=1, organization_id=organization.id, name="Fresh Contact",
            email="fresh.contact@test.invalid", active=False,
        )
        db.session.add_all([stale, held, fresh])
        db.session.flush()
        # Backdate updated_at past the retention window directly -- the
        # column's onupdate=now() would otherwise stamp "now" on any save.
        db.session.query(ClientContact).filter(
            ClientContact.id.in_([stale.id, held.id])
        ).update({"updated_at": now() - timedelta(days=100)}, synchronize_session=False)
        db.session.add(RecordLegalHold(
            tenant_id=1, record_type="client_contact", record_id=held.id,
            reason="Investigation hold", applied_by_id=admin_id,
        ))
        db.session.add(DataRetentionPolicy(
            tenant_id=1, record_type="client_contact", retention_days=30,
            updated_by_id=admin_id,
        ))
        db.session.commit()
        stale_id, held_id, fresh_id = stale.id, held.id, fresh.id

    with app.app_context():
        purged = process_data_retention_purge()
        assert purged == 1
        assert db.session.get(ClientContact, stale_id).erased_at is not None
        assert db.session.get(ClientContact, held_id).erased_at is None
        assert db.session.get(ClientContact, fresh_id).erased_at is None
        policy = DataRetentionPolicy.query.filter_by(tenant_id=1, record_type="client_contact").one()
        assert policy.last_run_count == 1
        assert policy.last_run_at is not None


def test_data_governance_admin_requires_admin_and_is_tenant_isolated(app, client):
    with app.app_context():
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one()
        manager = User.query.filter_by(username="database.manager").one()
        db.session.add(GroupMember(group_id=sysops.id, user_id=manager.id, role="member", tenant_id=1))
        db.session.commit()

    login(client, "database.manager", "Manager123!")
    assert client.get("/admin/data-governance").status_code == 403
    assert client.post("/admin/data-governance", data={
        "action": "save_retention_policy", "record_type": "client_contact", "retention_days": "365",
    }).status_code == 403
    client.post("/logout")

    login(client)
    saved = client.post("/admin/data-governance", data={
        "action": "save_retention_policy", "record_type": "client_contact",
        "retention_days": "365", "policy_active": "on",
    })
    assert saved.status_code == 302
    with app.app_context():
        policy = DataRetentionPolicy.query.filter_by(tenant_id=1, record_type="client_contact").one()
        assert policy.retention_days == 365

    rejected_type = client.post("/admin/data-governance", data={
        "action": "save_retention_policy", "record_type": "not_a_real_type", "retention_days": "365",
    })
    assert rejected_type.status_code == 400

    page = client.get("/admin/data-governance")
    assert page.status_code == 200
    assert b"Data classification" in page.data
