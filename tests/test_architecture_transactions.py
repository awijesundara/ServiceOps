"""Adversarial transaction interleavings against an explicitly disposable PostgreSQL DB."""
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy.engine import make_url
from werkzeug.exceptions import HTTPException

from app import (ApprovalChain, ApprovalVote, PlatformSetting, User, create_app, create_approval_chain,
                 create_ticket_with_unique_number, db, decide_vote)
from serviceops_core.mfa import verify_second_factor
from serviceops_core.projects import service
from serviceops_core.projects.models import Project
from serviceops_core.security import hash_backup_code


@pytest.fixture(scope="module")
def pg_review():
    url = os.getenv("ARCHITECTURE_DATABASE_URL")
    if not url:
        pytest.skip("ARCHITECTURE_DATABASE_URL is required")
    parsed = make_url(url)
    assert parsed.get_backend_name() == "postgresql" and parsed.database.endswith("_architecture_test"), \
        "Only a disposable _architecture_test database is allowed"
    application = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": url,
                              "AUTO_MIGRATE_IN_TESTS": True, "AUTO_MIGRATE": True,
                              "CSRF_ENABLED": False, "SESSION_COOKIE_SECURE": False})
    with application.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.merge(PlatformSetting(key="PROJECTS_ENABLED", value="true", tenant_id=admin.tenant_id))
        db.session.commit()
    return application


def _interleave(application, load, write):
    """Both requests read first; request 2 writes after request 1 commits."""
    loaded = threading.Barrier(2)
    committed = threading.Event()

    def request(index):
        with application.app_context():
            state = load(index)
            loaded.wait(timeout=20)
            if index:
                assert committed.wait(timeout=20)
            try:
                result = write(index, state)
                db.session.commit()
                return result
            finally:
                if not index:
                    committed.set()
                db.session.rollback()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(request, index) for index in range(2)]
        return [future.result(timeout=40) for future in futures]


def test_preloaded_project_counter_is_refreshed_under_lock(pg_review):
    with pg_review.app_context():
        admin = User.query.filter_by(username="admin").one()
        project = service.create_project(admin, "P" + uuid.uuid4().hex[:7].upper(), "Concurrent creation")
        db.session.commit()
        project_id, admin_id = project.id, admin.id

    def load(index):
        return db.session.get(User, admin_id), db.session.get(Project, project_id)

    def write(index, state):
        return service.create_item(*state, f"Concurrent item {index}").number

    assert _interleave(pg_review, load, write) == [1, 2]


def test_backup_code_cannot_be_reused_by_a_preloaded_request(pg_review):
    code = "ab12cd34ef"
    with pg_review.app_context():
        user = User(username="backup." + uuid.uuid4().hex[:8], name="Backup test", role="agent",
                    email=uuid.uuid4().hex + "@test.invalid", password_hash="unused", mfa_enabled=True, mfa_backup_codes_json=json.dumps([hash_backup_code(code)]))
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    def load(index):
        return db.session.get(User, user_id)

    def write(index, user):
        return verify_second_factor(user, code)

    assert _interleave(pg_review, load, write) == [(True, True), (False, False)]


@pytest.mark.parametrize("first_decision", ["Approved", "Rejected"])
def test_preloaded_approval_decisions_see_committed_chain_state(pg_review, first_decision):
    with pg_review.app_context():
        admin = User.query.filter_by(username="admin").one()
        other = User(username="approver." + uuid.uuid4().hex[:8], name="Other approver", role="manager",
                     email=uuid.uuid4().hex + "@test.invalid", password_hash="unused")
        db.session.add(other)
        db.session.flush()
        ticket = create_ticket_with_unique_number("change", title="Concurrent approval", description="test",
                                                  priority="P3", requester_id=admin.id)
        chain = create_approval_chain("Concurrent", "ticket", ticket.id,
                                      [{"name": "All", "approver_ids": [admin.id, other.id], "mode": "all"}])
        db.session.commit()
        chain_id = chain.id
        vote_ids = [vote.id for vote in chain.gates[0].votes]

    def load(index):
        vote = db.session.get(ApprovalVote, vote_ids[index])
        assert vote.gate.chain.state == "Running"
        assert all(v.state == "Requested" for v in vote.gate.votes)
        return vote

    def write(index, vote):
        try:
            decide_vote(vote, "Approved" if index else first_decision, "test")
            return 200
        except HTTPException as error:
            assert error.code == 409
            return error.code

    expected = [200, 200 if first_decision == "Approved" else 409]
    assert _interleave(pg_review, load, write) == expected
    with pg_review.app_context():
        assert db.session.get(ApprovalChain, chain_id).state == first_decision
        if first_decision == "Approved":
            assert all(v.state == "Approved" for v in db.session.get(ApprovalChain, chain_id).gates[0].votes)


def test_mobile_refresh_is_single_use_under_parallel_requests(pg_review, monkeypatch):
    import serviceops_core.web.api as api_routes
    from app import issue_mobile_session
    headers = {"X-ServiceOps-App-Version": "test", "X-ServiceOps-App-Build": "1",
               "X-ServiceOps-Platform": "iOS", "X-ServiceOps-Device": "review-test"}
    with pg_review.test_request_context(headers=headers):
        user = User(username="mobile." + uuid.uuid4().hex[:8], name="Refresh test", role="agent",
                    email=uuid.uuid4().hex + "@test.invalid", password_hash="unused")
        db.session.add(user)
        db.session.flush()
        _, refresh = issue_mobile_session(user, "password")
        db.session.commit()
    # Hold the first request after lookup to expose an unprotected rotation.
    # A correct row lock lets only one request reach this point: the other
    # waits for commit and then no longer finds the old refresh token.
    after_lookup = threading.Barrier(2)
    usable = api_routes.account_usable

    def delayed_usable(user):
        try:
            after_lookup.wait(timeout=2)
        except threading.BrokenBarrierError:
            pass
        return usable(user)

    monkeypatch.setattr(api_routes, "account_usable", delayed_usable)
    start = threading.Barrier(2)

    def refresh_request():
        start.wait(timeout=10)
        with pg_review.test_client() as client:
            return client.post("/api/v1/auth/mobile/refresh", json={"refresh_token": refresh}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: refresh_request(), range(2)))
    assert sorted(results) == [200, 401]


def test_password_recovery_link_is_single_use_under_parallel_posts(pg_review, monkeypatch):
    import hashlib
    import hmac
    from datetime import timedelta
    import serviceops_core.web.auth as auth_routes
    from app import PasswordResetToken, now
    token = uuid.uuid4().hex
    with pg_review.app_context():
        user = User(username="reset." + uuid.uuid4().hex[:8], name="Recovery test", role="agent",
                    email=uuid.uuid4().hex + "@test.invalid", password_hash="unused")
        db.session.add(user)
        db.session.flush()
        digest = hmac.new(pg_review.config["SECRET_KEY"].encode(), token.encode(), hashlib.sha256).hexdigest()
        db.session.add(PasswordResetToken(token_hash=digest, user_id=user.id, tenant_id=user.tenant_id,
                                         expires_at=now() + timedelta(minutes=5)))
        db.session.commit()
    after_lookup = threading.Barrier(2)
    hash_password = auth_routes.hash_password

    def delayed_hash(password):
        try:
            after_lookup.wait(timeout=2)
        except threading.BrokenBarrierError:
            pass
        return hash_password(password)

    monkeypatch.setattr(auth_routes, "hash_password", delayed_hash)
    start = threading.Barrier(2)

    def reset_request(index):
        start.wait(timeout=10)
        password = f"Review-password-{index}-long-enough!"
        with pg_review.test_client() as client:
            return client.post("/reset-password/" + token,
                               data={"password": password, "confirmation": password}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reset_request, range(2)))
    assert sorted(results) == [302, 400]


def test_parallel_worklogs_do_not_lose_remaining_estimate_updates(pg_review):
    from serviceops_core.projects import tracking
    with pg_review.app_context():
        admin = User.query.filter_by(username="admin").one()
        project = service.create_project(admin, "T" + uuid.uuid4().hex[:7].upper(), "Concurrent time tracking")
        item = service.create_item(admin, project, "Log together", estimate_minutes=600)
        db.session.commit()
        admin_id, item_id = admin.id, item.id

    def load(index):
        from serviceops_core.projects.models import WorkItem
        return db.session.get(User, admin_id), db.session.get(WorkItem, item_id)

    def write(index, state):
        tracking.log_work(*state, "1h")
        return True

    assert _interleave(pg_review, load, write) == [True, True]
    with pg_review.app_context():
        from serviceops_core.projects.models import WorkItem
        item = db.session.get(WorkItem, item_id)
        assert item.spent_minutes == 120 and item.remaining_minutes == 480


def test_realtime_notify_failure_does_not_abort_business_transaction(pg_review, caplog):
    from sqlalchemy import event
    from app import Notification
    title = "Signal failure " + uuid.uuid4().hex

    def fail_notify(conn, cursor, statement, parameters, context, executemany):
        if "SELECT pg_notify" in statement:
            return "SELECT 1 / 0", {}
        return statement, parameters

    with pg_review.app_context():
        user = User.query.filter_by(username="admin").one()
        engine = db.engine
        event.listen(engine, "before_cursor_execute", fail_notify, retval=True)
        try:
            db.session.add(Notification(user_id=user.id, title=title, body="Business write survives",
                                        tenant_id=user.tenant_id))
            db.session.commit()
            assert Notification.query.filter_by(title=title).count() == 1
            assert "Real-time signal could not be queued" in caplog.text
        finally:
            event.remove(engine, "before_cursor_execute", fail_notify)
            db.session.rollback()
