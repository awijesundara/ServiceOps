"""Groups on Sign-in and directory: create, edit and delete a group, map
AD/LDAP groups to it, and grant its members access levels."""
import app as app_module
from app import (Audit, ConfigurationItem, DirectoryGroupMapping, GroupMember, ManagedRoleGrant, SupportGroup,
                 Tenant, User, db, ldap_authenticate)
from test_app import app, client, login  # noqa: F401 - pytest fixtures
from test_ldap_access import ADMINS, DirectoryConn, put, use_directory


def create(client, **fields):
    data = {"name": "Admins", "group_type": "IT Fulfillment", "description": "ServiceOps administration",
            "directory_groups": "cn=gg_serviceops_admins,ou=groups,dc=example,dc=com", "access_roles": ["admin"]}
    data.update(fields)
    return client.post("/admin/groups/new", data=data)


def test_group_with_admin_role_makes_mapped_directory_users_admins(client, app, monkeypatch):
    login(client)
    assert create(client, directory_groups="gg_serviceops_admins").status_code == 302
    page = client.get("/admin/settings/sign_in_and_directory").get_data(as_text=True)
    assert "Admins" in page and "gg_serviceops_admins" in page and "Administrator" in page
    with app.app_context():
        put("LDAP_ENABLED", "true")
        use_directory(monkeypatch, DirectoryConn([ADMINS]))
        user = ldap_authenticate("jsmith", "correct-horse")
        assert user.role == "admin"
        assert ManagedRoleGrant.query.filter_by(user_id=user.id, source="group", role="admin").one()
        user_id = user.id
        db.session.commit()
    # Taking the role off the group takes it off its members.
    with app.app_context():
        group_id = SupportGroup.query.filter_by(name="Admins").one().id
    client.post(f"/admin/groups/{group_id}", data={
        "name": "Admins", "group_type": "IT Fulfillment", "active": "on",
        "directory_groups": "gg_serviceops_admins", "access_roles": ["agent"],
    })
    with app.app_context():
        assert db.session.get(User, user_id).role == "agent"


def test_group_form_validates_and_rejects_platform_admin(client, app):
    login(client)
    create(client, access_roles=["admin", "superadmin"])
    with app.app_context():
        assert SupportGroup.query.filter_by(name="Admins").one().access_roles == "admin"
    # The same AD group may map to several groups; names stay unique.
    assert create(client, name="Other").status_code == 302
    assert create(client, directory_groups="gg_other").status_code == 400
    assert create(client, name="").status_code == 400


def test_new_group_page_has_name_description_ldap_and_roles(client):
    login(client)
    page = client.get("/admin/groups/new").get_data(as_text=True)
    for text in ("Group name", "Description", "Map to AD/LDAP groups", "Roles", "Full administration"):
        assert text in page


def test_unused_group_is_deleted_and_referenced_group_is_deactivated(client, app):
    login(client)
    create(client)
    with app.app_context():
        group_id = SupportGroup.query.filter_by(name="Admins").one().id
    assert client.post(f"/admin/groups/{group_id}/delete").status_code == 302
    with app.app_context():
        assert db.session.get(SupportGroup, group_id) is None
        assert not DirectoryGroupMapping.query.filter_by(support_group_id=group_id).first()
        assert Audit.query.filter_by(action="delete", target="Group: Admins").one()
        unix_id = SupportGroup.query.filter_by(name="Unix").one().id
        db.session.add(ConfigurationItem(name="ref", ci_class="Server", support_group_id=unix_id, tenant_id=1))
        db.session.commit()
    assert client.post(f"/admin/groups/{unix_id}/delete").status_code == 302
    with app.app_context():
        unix = db.session.get(SupportGroup, unix_id)
        assert unix is not None and not unix.active
        assert not GroupMember.query.filter_by(group_id=unix_id).first()


def test_governance_and_client_support_groups_are_protected(client, app):
    login(client)
    with app.app_context():
        ccb = SupportGroup.query.filter_by(name="Change Control Board").one().id
        sysops = SupportGroup.query.filter_by(name="SysOps", tenant_id=1).one().id
    assert client.get(f"/admin/groups/{ccb}").status_code == 404
    assert client.post(f"/admin/groups/{sysops}/delete").status_code == 400


def test_team_managers_page_no_longer_creates_or_edits_groups(client):
    login(client)
    page = client.get("/service-operations/settings/team-managers").get_data(as_text=True)
    assert "create_support_group" not in page and "update_support_group" not in page
    assert "set_manager" in page and "/admin/groups" in page


def test_non_admin_cannot_manage_groups(client, app):
    with app.app_context():
        from werkzeug.security import generate_password_hash
        db.session.add(User(username="agent1", name="Agent", email="agent1@test.invalid",
                            password_hash=generate_password_hash("Agent123!pass"), role="agent", tenant_id=1))
        db.session.commit()
    login(client, "agent1", "Agent123!pass")
    assert create(client).status_code in (302, 403)
    with app.app_context():
        assert not SupportGroup.query.filter_by(name="Admins").first()


def test_group_roles_never_cross_tenants(client, app):
    login(client)
    create(client)
    with app.app_context():
        other = Tenant(name="Other org", slug="other-org")
        db.session.add(other)
        db.session.flush()
        outsider = User(username="outsider", name="O", email="o@test.invalid", password_hash="x",
                        role="requester", tenant_id=other.id)
        db.session.add(outsider)
        db.session.flush()
        group = SupportGroup.query.filter_by(name="Admins").one()
        db.session.add(GroupMember(group_id=group.id, user_id=outsider.id, role="member"))
        db.session.flush()
        app_module.sync_implied_role_grants(outsider)
        assert outsider.role != "admin"
