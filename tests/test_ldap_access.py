"""Directory access policy: AD group → access level mappings, the
mapped-group sign-in requirement, nested/searched group resolution, server
failover, scheduled access reconciliation and the administrator check tool."""
import json

import app as app_module
from app import ManagedRoleGrant, PlatformSetting, User, db, ldap_authenticate
from serviceops_core.ldap_access import resolve_groups, server_uris
from serviceops_core.ldap_sync import sync_directory
from test_app import app, client, login  # noqa: F401 - pytest fixtures
from test_ldap_sync import FakeConnection, FakeEntry, enable_ldap, provision_ldap_user

ADMINS = "CN=gg_serviceops_admins,OU=Groups,DC=example,DC=com"
STAFF = "CN=gg_staff,OU=Groups,DC=example,DC=com"
JANE_DN = "CN=Jane Smith,OU=Users,DC=example,DC=com"


def put(key, value):
    row = db.session.get(PlatformSetting, key) or PlatformSetting(key=key, encrypted=False)
    row.value = value
    db.session.add(row)
    db.session.commit()


class FakeServer:
    ssl = False


class FakeUserConn:
    def __init__(self, server, user, password, auto_bind):
        self.bound = password == "correct-horse"

    def open(self):
        pass

    def start_tls(self):
        return True

    def bind(self):
        return self.bound

    def unbind(self):
        pass


class DirectoryConn:
    """A service connection whose user search returns Jane, and whose
    nested-group (in-chain) search returns `nested`."""

    def __init__(self, member_of, nested=()):
        self.member_of = list(member_of)
        self.nested = list(nested)
        self.entries = []
        self.filters = []

    def search(self, base_dn, search_filter, search_scope=None, attributes=None, size_limit=None):
        self.filters.append(search_filter)
        if "1.2.840.113556.1.4.1941" in search_filter or "memberUid" in search_filter:
            self.entries = [FakeEntry(dn, {}) for dn in self.nested]
        elif "sAMAccountName=jsmith" in search_filter:
            self.entries = [FakeEntry(JANE_DN, {
                "memberOf": self.member_of, "displayName": ["Jane Smith"], "mail": ["jane@example.com"],
                "userAccountControl": ["512"],
            })]
        else:
            self.entries = []
        return bool(self.entries)

    def unbind(self):
        pass


def use_directory(monkeypatch, connection):
    monkeypatch.setattr(app_module, "ldap_server_and_service_connection", lambda: (FakeServer(), connection))
    monkeypatch.setattr(app_module, "Connection", FakeUserConn)


def test_mapped_admin_group_grants_admin_and_unmapped_user_gets_default(app, monkeypatch):
    with app.app_context():
        put("LDAP_ENABLED", "true")
        put("LDAP_ROLE_MAPPINGS", json.dumps({"gg_serviceops_admins": "admin", "gg_staff": "agent"}))
        use_directory(monkeypatch, DirectoryConn([ADMINS]))
        assert ldap_authenticate("jsmith", "correct-horse").role == "admin"

        use_directory(monkeypatch, DirectoryConn([]))
        put("LDAP_ROLE_MAPPINGS_DEFAULT", "requester")
        user = ldap_authenticate("jsmith", "correct-horse")
        # Losing the admin group at the next sign-in removes admin.
        assert user.role == "requester"
        assert not ManagedRoleGrant.query.filter_by(user_id=user.id, role="admin").first()


def test_require_access_group_refuses_users_outside_mapped_groups(app, monkeypatch):
    with app.app_context():
        put("LDAP_ENABLED", "true")
        put("LDAP_ROLE_MAPPINGS", json.dumps({"gg_staff": "requester"}))
        put("LDAP_REQUIRE_ACCESS_GROUP", "true")
        use_directory(monkeypatch, DirectoryConn(["CN=gg_unrelated,DC=example,DC=com"]))
        assert ldap_authenticate("jsmith", "correct-horse") is None
        assert not User.query.filter_by(username="jsmith").first()

        use_directory(monkeypatch, DirectoryConn([STAFF]))
        assert ldap_authenticate("jsmith", "correct-horse").role == "requester"
        # The password is still checked first.
        assert ldap_authenticate("jsmith", "wrong") is None


def test_nested_ad_group_grants_access_only_when_enabled(app, monkeypatch):
    with app.app_context():
        put("LDAP_ENABLED", "true")
        put("LDAP_ROLE_MAPPINGS", json.dumps({"gg_serviceops_admins": "admin"}))
        # Jane is directly in gg_dba, which is itself a member of the admin group.
        connection = DirectoryConn(["CN=gg_dba,DC=example,DC=com"], nested=[ADMINS])
        use_directory(monkeypatch, connection)
        assert ldap_authenticate("jsmith", "correct-horse").role == "requester"
        put("LDAP_NESTED_GROUPS", "true")
        assert ldap_authenticate("jsmith", "correct-horse").role == "admin"
        assert any(":1.2.840.113556.1.4.1941:=CN=Jane Smith" in f for f in connection.filters)


def test_group_search_filter_escapes_the_user_dn_and_username(app):
    with app.app_context():
        put("LDAP_GROUP_SEARCH_FILTER", "(|(member={dn})(memberUid={username}))")
        connection = DirectoryConn([], nested=["cn=admins,ou=groups,dc=example,dc=com"])
        groups = resolve_groups(connection, "uid=j*,dc=example,dc=com", "j)(uid=*", [])
        assert groups == ["cn=admins,ou=groups,dc=example,dc=com"]
        assert connection.filters == [r"(|(member=uid=j\2a,dc=example,dc=com)(memberUid=j\29\28uid=\2a))"]


def test_server_uri_lists_several_servers_for_failover():
    assert server_uris("ldaps://dc1.example.com, ldaps://dc2.example.com:3269") == [
        "ldaps://dc1.example.com", "ldaps://dc2.example.com:3269",
    ]


def test_scheduled_sync_revokes_admin_and_deactivates_users_outside_mapped_groups(app, monkeypatch):
    with app.app_context():
        put("LDAP_ROLE_MAPPINGS", json.dumps({"gg_serviceops_admins": "admin", "gg_staff": "agent"}))
        put("LDAP_REQUIRE_ACCESS_GROUP", "true")
        demoted = provision_ldap_user("demoted", "CN=Demoted,DC=example,DC=com")
        app_module.sync_role_grants(demoted, "directory", {"admin": ADMINS})
        removed = provision_ldap_user("removed", "CN=Removed,DC=example,DC=com")
        db.session.commit()
        before = demoted.auth_version
        entries = [
            FakeEntry("CN=Demoted,DC=example,DC=com", {"sAMAccountName": ["demoted"], "memberOf": [STAFF]}),
            FakeEntry("CN=Removed,DC=example,DC=com", {"sAMAccountName": ["removed"], "memberOf": []}),
        ]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        summary = sync_directory(1)
        assert summary["access_levels_changed"] >= 1
        assert db.session.get(User, demoted.id).role == "agent"
        assert db.session.get(User, demoted.id).auth_version > before
        assert db.session.get(User, demoted.id).active
        assert not db.session.get(User, removed.id).active


def test_admin_manages_access_mappings_and_policy(client, app):
    login(client)
    response = client.post("/admin/settings/sign_in_and_directory/access", data={
        "action": "add_access_mapping", "directory_group": "gg_serviceops_admins", "access_level": "admin",
    })
    assert response.status_code == 302
    # Platform administrator cannot be granted from a directory group.
    assert client.post("/admin/settings/sign_in_and_directory/access", data={
        "action": "add_access_mapping", "directory_group": "gg_root", "access_level": "superadmin",
    }).status_code == 400
    assert client.post("/admin/settings/sign_in_and_directory/access", data={
        "action": "save_access_policy", "default_access_level": "requester", "require_access_group": "on",
    }).status_code == 302
    page = client.get("/admin/settings/sign_in_and_directory").get_data(as_text=True)
    assert "gg_serviceops_admins" in page and "AD group → access level" in page
    with app.app_context():
        assert json.loads(app_module.setting_value("LDAP_ROLE_MAPPINGS")) == {"gg_serviceops_admins": "admin"}
        assert app_module.setting_bool("LDAP_REQUIRE_ACCESS_GROUP")
    # Saving the main settings form must not silently clear the policy.
    client.post("/admin/settings/sign_in_and_directory", data={"LOCAL_AUTH_ENABLED": "on"})
    with app.app_context():
        assert app_module.setting_bool("LDAP_REQUIRE_ACCESS_GROUP")
    assert client.post("/admin/settings/sign_in_and_directory/access", data={
        "action": "remove_access_mapping", "directory_group": "gg_serviceops_admins",
    }).status_code == 302
    with app.app_context():
        assert json.loads(app_module.setting_value("LDAP_ROLE_MAPPINGS")) == {}


def test_check_user_reports_access_without_signing_in(client, app, monkeypatch):
    login(client)
    with app.app_context():
        put("LDAP_ROLE_MAPPINGS", json.dumps({"gg_serviceops_admins": "admin"}))
    monkeypatch.setattr(app_module, "ldap_server_and_service_connection",
                        lambda: (FakeServer(), DirectoryConn([ADMINS])))
    client.post("/admin/settings/sign_in_and_directory/access", data={"action": "check_user", "username": "jsmith"})
    page = client.get("/admin/settings/sign_in_and_directory").get_data(as_text=True)
    assert "Jane Smith" in page and "Administrator" in page and "Allowed" in page
    with app.app_context():
        assert not User.query.filter_by(username="jsmith").first()


def test_non_admin_cannot_change_access_mappings(client, app):
    with app.app_context():
        from werkzeug.security import generate_password_hash
        db.session.add(User(username="agent1", name="Agent", email="agent1@test.invalid",
                            password_hash=generate_password_hash("Agent123!pass"), role="agent", tenant_id=1))
        db.session.commit()
    login(client, "agent1", "Agent123!pass")
    response = client.post("/admin/settings/sign_in_and_directory/access", data={
        "action": "add_access_mapping", "directory_group": "gg_x", "access_level": "admin",
    })
    assert response.status_code in (302, 403)
    with app.app_context():
        assert app_module.setting_value("LDAP_ROLE_MAPPINGS", "{}") == "{}"
