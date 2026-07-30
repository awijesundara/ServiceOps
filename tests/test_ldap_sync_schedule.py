"""Tests for the scheduled LDAP directory sync (app.process_ldap_sync_schedule),
which drives serviceops_core.ldap_sync.sync_directory from the same
in-process worker-loop polling pattern used by process_workflow_schedules /
process_sla_breaches (tools/outbox_worker.py) -- no Celery/Redis, no new
infrastructure.

These mock the LDAP directory entirely (no live LDAP server required),
following the same convention as tests/test_ldap_sync.py.
"""
import os
import tempfile
from datetime import timedelta

import pytest

from app import (LdapSyncState, PlatformSetting, Tenant, User, create_app, db, now,
                  process_ldap_sync_schedule)


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        db.session.commit()
    yield app
    os.unlink(path)


class FakeConnection:
    def __init__(self):
        self.entries = []

    def search(self, base_dn, search_filter, search_scope=None, attributes=None):
        self.entries = []
        return True

    def unbind(self):
        pass


def set_setting(key, value):
    existing = db.session.get(PlatformSetting, key)
    if existing:
        existing.value = value
    else:
        db.session.add(PlatformSetting(key=key, value=value, encrypted=False))
    db.session.commit()


def enable_scheduled_ldap(monkeypatch, interval_minutes=60):
    set_setting("LDAP_ENABLED", "true")
    set_setting("LDAP_SYNC_ENABLED", "true")
    set_setting("LDAP_SYNC_INTERVAL_MINUTES", str(interval_minutes))
    monkeypatch.setattr("app.ldap_server_and_service_connection", lambda: (object(), FakeConnection()))


def test_disabled_flags_never_run_sync(app, monkeypatch):
    with app.app_context():
        set_setting("LDAP_ENABLED", "false")
        set_setting("LDAP_SYNC_ENABLED", "true")
        processed = process_ldap_sync_schedule()
        assert processed == 0
        assert LdapSyncState.query.count() == 0

        set_setting("LDAP_ENABLED", "true")
        set_setting("LDAP_SYNC_ENABLED", "false")
        processed = process_ldap_sync_schedule()
        assert processed == 0
        assert LdapSyncState.query.count() == 0


def test_first_run_is_due_and_creates_state(app, monkeypatch):
    with app.app_context():
        enable_scheduled_ldap(monkeypatch)
        processed = process_ldap_sync_schedule()
        assert processed == 1
        state = db.session.get(LdapSyncState, 1)
        assert state is not None
        assert state.last_run_at is not None
        assert state.last_status == "ok"


def test_second_call_before_interval_elapses_is_not_due(app, monkeypatch):
    with app.app_context():
        enable_scheduled_ldap(monkeypatch, interval_minutes=60)
        assert process_ldap_sync_schedule() == 1
        # Immediately calling again: interval has not elapsed, so nothing runs.
        assert process_ldap_sync_schedule() == 0


def test_due_again_once_interval_has_elapsed(app, monkeypatch):
    with app.app_context():
        enable_scheduled_ldap(monkeypatch, interval_minutes=60)
        assert process_ldap_sync_schedule() == 1
        state = db.session.get(LdapSyncState, 1)
        # Simulate the interval having elapsed by backdating the last run.
        state.last_run_at = now() - timedelta(minutes=61)
        db.session.commit()
        assert process_ldap_sync_schedule() == 1


def test_per_tenant_enable_isolation(app, monkeypatch):
    """Only tenants that are active are iterated; a globally-disabled sync
    never runs for any tenant (settings are platform-wide in this codebase,
    matching existing LDAP_ENABLED semantics), but iteration itself must
    remain explicit per-tenant rather than a hard-coded single tenant."""
    with app.app_context():
        db.session.add(Tenant(id=2, slug="other", name="Other Org"))
        db.session.commit()
        enable_scheduled_ldap(monkeypatch)
        processed = process_ldap_sync_schedule()
        # Both active tenants (1 and 2) get their own scheduler-state row.
        assert processed == 2
        assert db.session.get(LdapSyncState, 1) is not None
        assert db.session.get(LdapSyncState, 2) is not None


def test_one_tenant_sync_exception_does_not_block_other_tenant(app, monkeypatch):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="other", name="Other Org"))
        db.session.commit()
        enable_scheduled_ldap(monkeypatch)

        import serviceops_core.ldap_sync as ldap_sync_module
        real_sync = ldap_sync_module.sync_directory

        def flaky_sync(tenant_id, dry_run=False):
            if tenant_id == 1:
                raise RuntimeError("simulated directory outage for tenant 1")
            return real_sync(tenant_id, dry_run=dry_run)

        monkeypatch.setattr(
            "serviceops_core.ldap_sync.sync_directory", flaky_sync
        )
        processed = process_ldap_sync_schedule()
        assert processed == 2
        state1 = db.session.get(LdapSyncState, 1)
        state2 = db.session.get(LdapSyncState, 2)
        assert state1.last_status == "error"
        assert state1.last_error == "RuntimeError"
        assert state2.last_status == "ok"


def test_inactive_tenant_is_never_synced(app, monkeypatch):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="other", name="Other Org", active=False))
        db.session.commit()
        enable_scheduled_ldap(monkeypatch)
        processed = process_ldap_sync_schedule()
        assert processed == 1
        assert db.session.get(LdapSyncState, 1) is not None
        assert db.session.get(LdapSyncState, 2) is None
