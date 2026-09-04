"""Tests for the generic LDAP directory sync (serviceops_core/ldap_sync.py).

These mock the LDAP directory entirely (no live LDAP server required) by
monkeypatching app.ldap_server_and_service_connection, matching the same
approach used elsewhere in this test suite for other network dependencies
(see test_durable_smtp_signed_webhook_and_teams_delivery for SMTP/webhook
mocking).
"""
import os
import tempfile

import pytest
from werkzeug.security import generate_password_hash

from app import (DirectoryGroupMapping, DirectoryManagedMembership, DirectoryProfile,
                  ExternalIdentity, GroupMember, ManagedRoleGrant, PlatformSetting,
                  SupportGroup, Tenant, User, create_app, db)
from serviceops_core.ldap_sync import DirectorySyncError, sync_directory


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        db.session.commit()
    yield app
    os.unlink(path)


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="admin", password="Admin123!"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


class FakeEntry:
    def __init__(self, dn, attrs):
        self.entry_dn = dn
        self._attrs = attrs

    @property
    def entry_attributes_as_dict(self):
        return self._attrs


class _FakeStandard:
    def __init__(self, connection):
        self._connection = connection

    def paged_search(self, search_base=None, search_filter=None, search_scope=None,
                      attributes=None, paged_size=None, generator=True):
        for entry in self._connection._entries:
            yield {"type": "searchResEntry", "dn": entry.entry_dn, "attributes": entry.entry_attributes_as_dict}


class _FakeExtend:
    def __init__(self, connection):
        self.standard = _FakeStandard(connection)


class FakeConnection:
    def __init__(self, entries):
        self._entries = entries
        self.entries = []
        self.extend = _FakeExtend(self)

    def search(self, base_dn, search_filter, search_scope=None, attributes=None, size_limit=None):
        self.entries = self._entries
        return True

    def unbind(self):
        pass


def enable_ldap(entries):
    existing = db.session.get(PlatformSetting, "LDAP_ENABLED")
    if existing:
        existing.value = "true"
    else:
        db.session.add(PlatformSetting(key="LDAP_ENABLED", value="true", encrypted=False))
    db.session.commit()

    def fake_bind():
        return object(), FakeConnection(entries)

    return fake_bind


def provision_ldap_user(username, dn, tenant_id=1, **extra):
    user = User(
        username=username, name=username, email=f"{username}@test.invalid",
        password_hash=generate_password_hash("Password123!"), role="agent",
        tenant_id=tenant_id, **extra,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(ExternalIdentity(provider="ldap", subject=dn, user_id=user.id))
    db.session.commit()
    return user


def test_manager_dn_resolves_to_manager_id(app, monkeypatch):
    with app.app_context():
        alice_dn = "CN=Alice,OU=Users,DC=example,DC=com"
        bob_dn = "CN=Bob,OU=Users,DC=example,DC=com"
        alice = provision_ldap_user("alice", alice_dn)
        bob = provision_ldap_user("bob", bob_dn)
        entries = [
            FakeEntry(alice_dn, {"manager": [bob_dn]}),
            FakeEntry(bob_dn, {}),
        ]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        result = sync_directory(1)
        db.session.refresh(alice)
        assert alice.manager_id == bob.id
        assert result["managers_resolved"] == 1


def test_rich_directory_profile_team_creation_and_people_manager_role(app, monkeypatch):
    """The representative AD attributes in the reported screenshots should
    become useful profile intelligence without retaining certificate blobs,
    and a real reporting line should imply manager capability deterministically."""
    with app.app_context():
        employee_dn = "CN=Directory Person,OU=Users,DC=example,DC=com"
        manager_dn = "CN=Directory Manager,OU=Users,DC=example,DC=com"
        employee = provision_ldap_user("directory.person", employee_dn)
        manager = provision_ldap_user("directory.manager", manager_dn)
        db.session.add(PlatformSetting(
            key="LDAP_AUTO_CREATE_TEAMS", value="true", encrypted=False,
        ))
        db.session.commit()
        entries = [
            FakeEntry(employee_dn, {
                "manager": [manager_dn], "displayName": ["Directory Person"],
                "userPrincipalName": ["directory.person@example.com"],
                "givenName": ["Directory"], "sn": ["Person"],
                "teamName": ["Datacenter"], "physicalDeliveryOfficeName": ["CC1"],
                "employeeID": ["490059"], "userAccountControl": [512],
                "whenCreated": ["20221013014833.0Z"],
                "lastLogonTimestamp": [133686782287858735],
                "uidNumber": [11010], "gidNumber": [10005],
                "unixHomeDirectory": ["/home/directory.person"], "loginShell": ["/bin/bash"],
                "memberOf": [
                    "CN=gg_unix_team,OU=Groups,DC=example,DC=com",
                    "CN=gg_monitoring_users,OU=Groups,DC=example,DC=com",
                ],
                "userCertificate": [b"must never be retained"],
            }),
            FakeEntry(manager_dn, {
                "sAMAccountName": ["directory.manager"],
                "displayName": ["Directory Manager"], "userAccountControl": [512],
            }),
        ]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        result = sync_directory(1)
        db.session.refresh(employee)
        db.session.refresh(manager)
        profile = DirectoryProfile.query.filter_by(user_id=employee.id).one()
        assert profile.profile["user_principal_name"] == "directory.person@example.com"
        assert profile.profile["account_enabled"] is True
        assert profile.profile["unix_home_directory"] == "/home/directory.person"
        assert "userCertificate" not in profile.profile_json
        assert profile.group_names == ["gg_monitoring_users", "gg_unix_team"]
        datacenter = SupportGroup.query.filter_by(name="Datacenter", tenant_id=1).one()
        assert GroupMember.query.filter_by(user_id=employee.id, group_id=datacenter.id).one()
        assert datacenter.manager_id == manager.id
        assert employee.manager_id == manager.id
        assert ManagedRoleGrant.query.filter_by(
            user_id=manager.id, role="manager", source="team_responsibility"
        ).one()
        assert result["teams_created"] == 1
        assert result["team_managers_inferred"] == 1
        assert result["directory_profiles_updated"] == 2
        assert result["users_unmatched"] == 0


def test_manager_who_never_logged_in_is_provisioned_and_resolved(app, monkeypatch):
    """A user's `manager` DN may belong to someone who has never logged into
    ServiceOps themselves (e.g. a senior manager who never touches the
    ticketing tool). Since that DN is present in the same directory search,
    sync_directory must provision a normal LDAP-identity account for them so
    the reporting chain is actually reflected, instead of silently leaving
    manager_id unset forever."""
    with app.app_context():
        alice_dn = "CN=Alice,OU=Users,DC=example,DC=com"
        wei_dn = "CN=Wei Guo,OU=GSuiteUsers,OU=Users,DC=example,DC=com"
        alice = provision_ldap_user("alice", alice_dn)
        entries = [
            FakeEntry(alice_dn, {"manager": [wei_dn], "mail": ["alice@example.com"]}),
            FakeEntry(wei_dn, {
                "sAMAccountName": ["wei.guo"], "mail": ["wei.guo@example.com"],
                "displayName": ["Wei Guo"],
            }),
        ]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        result = sync_directory(1)
        db.session.refresh(alice)
        wei = User.query.filter_by(username="wei.guo").one()
        assert alice.manager_id == wei.id
        assert wei.tenant_id == 1
        assert ExternalIdentity.query.filter_by(provider="ldap", subject=wei_dn).one().user_id == wei.id
        assert result["managers_provisioned"] == 1
        assert result["managers_resolved"] == 1

        # A second run must not re-provision Wei Guo again.
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        result2 = sync_directory(1)
        assert result2["managers_provisioned"] == 0
        assert User.query.filter_by(username="wei.guo").count() == 1


def test_manager_dn_outside_directory_search_is_left_unresolved(app, monkeypatch):
    """A manager DN that isn't itself a real entry in this directory search
    (out of base DN/filter scope) must never be fabricated -- manager_id
    stays unset and the rest of the sync still succeeds."""
    with app.app_context():
        alice_dn = "CN=Alice,OU=Users,DC=example,DC=com"
        alice = provision_ldap_user("alice", alice_dn)
        entries = [
            FakeEntry(alice_dn, {"manager": ["CN=Outside Scope,OU=Other,DC=example,DC=com"]}),
        ]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        result = sync_directory(1)
        db.session.refresh(alice)
        assert alice.manager_id is None
        assert result["managers_provisioned"] == 0
        assert result["managers_resolved"] == 0
        assert not result["errors"]


def test_self_manager_dn_is_skipped_and_reported(app, monkeypatch):
    """If AD points a user's manager to their own DN, sync must not set a
    self-reference and must report it clearly instead of crashing."""
    with app.app_context():
        alice_dn = "CN=Alice,OU=Users,DC=example,DC=com"
        alice = provision_ldap_user("alice", alice_dn)
        entries = [
            FakeEntry(alice_dn, {"manager": [alice_dn]}),
        ]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        result = sync_directory(1)
        db.session.refresh(alice)
        assert alice.manager_id is None
        assert result["managers_resolved"] == 0
        assert result["self_manager_skipped"] == 1
        assert result["self_manager_users"] == ["alice"]
        assert any("Self-manager record skipped for alice" in error for error in result["errors"])


def test_group_membership_sync_adds_membership_and_managed_row(app, monkeypatch):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        db.session.add(DirectoryGroupMapping(directory_group="gg_unix", support_group_id=unix.id))
        db.session.commit()
        dn = "CN=Carol,OU=Users,DC=example,DC=com"
        carol = provision_ldap_user("carol", dn)
        entries = [FakeEntry(dn, {"memberOf": ["CN=gg_unix,OU=Groups,DC=example,DC=com"]})]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        result = sync_directory(1)
        assert result["memberships_added"] == 1
        assert GroupMember.query.filter_by(user_id=carol.id, group_id=unix.id, role="member").one()
        assert DirectoryManagedMembership.query.filter_by(user_id=carol.id, group_id=unix.id).one()


def test_second_sync_run_no_duplicate_removes_stale_keeps_manual(app, monkeypatch):
    with app.app_context():
        unix = SupportGroup.query.filter_by(name="Unix").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        db.session.add(DirectoryGroupMapping(directory_group="gg_unix", support_group_id=unix.id))
        db.session.commit()
        dn = "CN=Carol,OU=Users,DC=example,DC=com"
        carol = provision_ldap_user("carol", dn)
        # A manually-added membership to a different team (no DirectoryManagedMembership row).
        db.session.add(GroupMember(group_id=windows.id, user_id=carol.id, role="member"))
        db.session.commit()

        entries = [FakeEntry(dn, {"memberOf": ["CN=gg_unix,OU=Groups,DC=example,DC=com"]})]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        result1 = sync_directory(1)
        assert result1["memberships_added"] == 1
        assert GroupMember.query.filter_by(user_id=carol.id).count() == 2  # unix (synced) + windows (manual)

        # Run again with identical directory state: no duplicate membership rows.
        entries2 = [FakeEntry(dn, {"memberOf": ["CN=gg_unix,OU=Groups,DC=example,DC=com"]})]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries2))
        result2 = sync_directory(1)
        assert result2["memberships_added"] == 0
        assert result2["memberships_removed"] == 0
        assert GroupMember.query.filter_by(user_id=carol.id, group_id=unix.id).count() == 1

        # Now the directory no longer reports gg_unix membership: sync should remove
        # the synced Unix membership but leave the manually-added Windows membership.
        entries3 = [FakeEntry(dn, {"memberOf": []})]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries3))
        result3 = sync_directory(1)
        assert result3["memberships_removed"] == 1
        assert GroupMember.query.filter_by(user_id=carol.id, group_id=unix.id).count() == 0
        assert GroupMember.query.filter_by(user_id=carol.id, group_id=windows.id).count() == 1
        assert DirectoryManagedMembership.query.filter_by(user_id=carol.id).count() == 0


def test_tenant_isolation_never_mutates_other_tenant(app, monkeypatch):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="other", name="Other Org"))
        db.session.commit()
        dn1 = "CN=Dave,OU=Users,DC=example,DC=com"
        dn2 = "CN=Erin,OU=Users,DC=example,DC=com"
        dave = provision_ldap_user("dave", dn1, tenant_id=1, title="Old Title 1")
        # Give tenant 2 its own admin/base user so User(tenant_id=2) isn't orphaned.
        User.query.filter_by(username="admin").first()
        erin = provision_ldap_user("erin", dn2, tenant_id=2, title="Old Title 2")
        entries = [
            FakeEntry(dn1, {"title": ["New Title 1"]}),
            FakeEntry(dn2, {"title": ["New Title 2"]}),
        ]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        result = sync_directory(1)
        db.session.refresh(dave)
        db.session.refresh(erin)
        assert dave.title == "New Title 1"
        assert erin.title == "Old Title 2"  # tenant 2 untouched by a tenant-1 sync
        assert result["users_unmatched"] == 1  # erin's entry present in directory but out of tenant scope


def test_sparse_entries_do_not_null_existing_values(app, monkeypatch):
    with app.app_context():
        dn = "CN=Frank,OU=Users,DC=example,DC=com"
        frank = provision_ldap_user("frank", dn, title="Existing Title", department="Existing Dept")
        entries = [FakeEntry(dn, {})]  # no title/department attributes present at all
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
        sync_directory(1)
        db.session.refresh(frank)
        assert frank.title == "Existing Title"
        assert frank.department == "Existing Dept"


def test_missing_or_invalid_tenant_id_fails_closed(app, monkeypatch):
    with app.app_context():
        db.session.add(PlatformSetting(key="LDAP_ENABLED", value="true", encrypted=False))
        db.session.commit()
        with pytest.raises(DirectorySyncError):
            sync_directory(None)
        with pytest.raises(DirectorySyncError):
            sync_directory(0)
        with pytest.raises(DirectorySyncError):
            sync_directory(999999)  # tenant does not exist


def test_admin_route_triggers_directory_sync_preview(client, app, monkeypatch):
    with app.app_context():
        dn = "CN=Grace,OU=Users,DC=example,DC=com"
        provision_ldap_user("grace", dn, title="Old Title")
        entries = [FakeEntry(dn, {"title": ["New Title"]})]
        monkeypatch.setattr("app.ldap_server_and_service_connection", enable_ldap(entries))
    login(client)
    response = client.post(
        "/itil/administration",
        data={"action": "sync_directory", "dry_run": "1"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    with app.app_context():
        grace = User.query.filter_by(username="grace").one()
        # dry_run must not persist changes
        assert grace.title == "Old Title"
