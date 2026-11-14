"""Stability, speed and arrangement pass of 2026-11-14."""
import re
from pathlib import Path

import requests
from sqlalchemy import event

import app as app_module
from tests.test_app import app, client, login
from app import ConfigurationItem, Notification, PlatformSetting, Ticket, User, db

ROOT = Path(__file__).resolve().parents[1]


def test_notifications_page_does_not_query_once_per_row(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        tickets = [Ticket(number=f"INC99{index:05}", kind="incident", title=f"T{index}", description="d",
                          state="New", priority="P3", requester_id=admin.id, tenant_id=1) for index in range(30)]
        db.session.add_all(tickets)
        db.session.flush()
        db.session.add_all([Notification(user_id=admin.id, title=f"N{t.id}", body="b", tenant_id=1,
                                         target_type="ticket", target_id=t.id) for t in tickets])
        db.session.commit()
        statements = []

        def count(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(db.engine, "before_cursor_execute", count)
        try:
            response = client.get("/notifications")
        finally:
            event.remove(db.engine, "before_cursor_execute", count)
    assert response.status_code == 200
    ticket_reads = [s for s in statements if re.search(r"FROM ticket\b", s) and "WHERE ticket.id = " in s]
    assert len(ticket_reads) <= 2, len(ticket_reads)


def test_unreachable_netbox_is_not_retried_for_every_device_picture(client, app, monkeypatch):
    calls = []

    class DownSession:
        verify = True

        def get(self, url, **kwargs):
            calls.append(url)
            raise requests.ConnectionError("down")

        def close(self):
            return None

    with app.app_context():
        for key, value in (("NETBOX_ENABLED", "true"), ("NETBOX_BASE_URL", "https://netbox.example.com"),
                           ("NETBOX_API_TOKEN", "server-only-token")):
            setting = db.session.get(PlatformSetting, key)
            if setting:
                setting.value = value
            else:
                db.session.add(PlatformSetting(key=key, value=value, encrypted=False))
        ids = []
        for number in (41, 42, 43):
            ci = ConfigurationItem(name=f"down-device-{number}", ci_class="Server", tenant_id=1,
                                   external_source="netbox", external_id=f"dcim.device:{number}")
            db.session.add(ci)
            db.session.flush()
            ids.append(ci.id)
        db.session.commit()
    monkeypatch.setattr("serviceops_core.netbox_sync._netbox_session", lambda base_url, token: DownSession())
    login(client)
    assert [client.get(f"/cmdb/device-artwork/{ci_id}/front").status_code for ci_id in ids] == [502, 502, 502]
    assert len(calls) == 1
    # After the pause it is tried again.
    app.extensions["netbox_artwork_unavailable_until"].clear()
    assert client.get(f"/cmdb/device-artwork/{ids[0]}/front").status_code == 502
    assert len(calls) == 2


def test_contract_alerts_run_in_the_worker_at_most_every_quarter_hour(app, monkeypatch):
    runs = []
    monkeypatch.setattr("serviceops_core.itam.alerts.send_contract_alerts", lambda: runs.append(1) or 2)
    monkeypatch.setattr(app_module, "_contract_alerts_checked", [None])
    with app.app_context():
        assert app_module.process_contract_alerts() == 2
        assert app_module.process_contract_alerts() == 0
    assert len(runs) == 1
    worker = (ROOT / "tools/outbox_worker.py").read_text()
    assert "process_contract_alerts()" in worker and "purge_expired_rows()" in worker


def test_pages_paint_at_once_and_load_the_experience_stylesheet(client):
    page = client.get("/login").get_data(as_text=True)
    assert "/static/experience.css" in page
    css = (ROOT / "static/experience.css").read_text()
    assert "@view-transition" not in css  # reported page errors in Chromium
    assert ".page-reveal{animation:none}" in css
    # Layout and motion only, so no theme needs its own copy of these rules.
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", css)
