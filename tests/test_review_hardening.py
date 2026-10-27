"""Regression tests for the 2026-10-27 review: lockout, backup reports, webhook redirects and work ownership."""
from datetime import timedelta

import pytest

from app import (ImprovementItem, MonitoringSource, SupportGroup, User, create_api_token, db, deliver_webhook, now)
from tests.test_app import app, client, login  # noqa: F401
from tests.test_internal_webhooks import FLOWOPS, _connection


def test_a_locked_account_gets_the_same_answer_as_a_wrong_password(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin.locked_until = now() + timedelta(minutes=15)
        db.session.commit()
    locked = client.post("/login", data={"username": "ADMIN", "password": "x"}).get_data(as_text=True)
    unknown = client.post("/login", data={"username": "nobody", "password": "x"}).get_data(as_text=True)
    assert "temporarily locked" not in locked
    assert "Invalid username or password." in locked and "Invalid username or password." in unknown


def _source(app, tenant_name="Backup reporter"):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        token, prefix, token_hash = create_api_token()
        source = MonitoringSource(name=tenant_name, token_prefix=prefix, token_hash=token_hash,
                                  assignment_group_id=SupportGroup.query.filter_by(name="Unix").one().id,
                                  created_by_id=admin.id)
        db.session.add(source)
        db.session.commit()
        return source.source_id, token


def test_only_the_backup_reporter_sets_backup_status(client, app):
    source_id, token = _source(app, "Nagios")
    response = client.post(f"/api/v1/monitoring/{source_id}/backup-report",
                           json={"manifest": "x", "offsite": "archived"},
                           headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


@pytest.mark.parametrize("location", ["https://elsewhere.example.net/hook", "/other-path"])
def test_signed_webhooks_do_not_follow_redirects(monkeypatch, app, location):
    sent = []

    class Redirect:
        status_code = 302
        is_redirect = True
        headers = {"Location": location}

    monkeypatch.setattr("app.requests.post", lambda url, **kwargs: sent.append(url) or Redirect())
    monkeypatch.setattr("app.socket.getaddrinfo", lambda host, port, *a, **k: [(2, 1, 6, "", ("10.152.183.20", 0))])
    monkeypatch.setenv("WEBHOOK_INTERNAL_HOSTS", "flowops.operations.svc.cluster.local")
    with app.app_context():
        connection, event = _connection(app, FLOWOPS)
        with pytest.raises(RuntimeError, match="Redirect refused"):
            deliver_webhook(event, connection)
    assert sent == [FLOWOPS]


def test_an_owned_improvement_is_changed_by_its_owner_or_a_manager(client, app):
    with app.app_context():
        owner = User.query.filter(User.role == "manager", User.tenant_id == 1).first()
        item = ImprovementItem(number="CSI0099991", title="Faster triage", status="Proposed", owner_id=owner.id, created_by_id=owner.id,
                               tenant_id=1)
        from werkzeug.security import generate_password_hash
        db.session.add_all([item, User(username="csi.agent", name="CSI agent", email="csi.agent@example.com",
                                       password_hash=generate_password_hash("Agent123!"), role="agent", tenant_id=1)])
        db.session.commit()
        item_id = item.id
    login(client, "csi.agent", "Agent123!")
    response = client.post(f"/improvement/{item_id}", data={"status": "Closed"})
    assert response.status_code == 403
