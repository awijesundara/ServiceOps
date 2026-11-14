"""Review of 2026-11-14: installer secrets, forged client addresses, RT import
tenancy, spreadsheet formulas in exports, and rows that were never purged."""
import io
import subprocess
from datetime import timedelta

from tests.test_app import app, client, login
from app import (
    APIClient, APIRateLimitWindow, RouteRateLimitWindow, Tenant, Ticket, User, UserSession, db, now,
)
import pytest

from installer.app import env_line, validate
from serviceops_core import housekeeping
from serviceops_core.csv_export import safe_cell, safe_row, safe_writer
from serviceops_core.rt_import import _resolve_or_create_user
from tests.test_client_identity import resolve


def test_installer_secret_survives_bash_and_runs_nothing(tmp_path):
    secret = 'Summer$HOME-2026$(echo RAN)${PATH}"quoted"\\back!'
    env_file = tmp_path / "serviceops.env"
    env_file.write_text(env_line("ADMIN_PASSWORD", secret) + "\n")
    seen = subprocess.run(
        ["bash", "-c", 'set -a; source "$1"; set +a; printf %s "$ADMIN_PASSWORD"', "bash", str(env_file)],
        capture_output=True, text=True, check=True,
    ).stdout
    assert seen == secret


def test_installer_refuses_a_backtick(monkeypatch):
    monkeypatch.setattr("installer.app.load_json", lambda *_: {"ok": True, "message": "Host passed"})
    checks = validate({
        "db_mode": "bundled", "bind_address": "127.0.0.1", "app_port": "0",
        "admin_password": "strong-`id`-production-password",
        "ldap_enabled": False, "keycloak_enabled": False,
    })
    assert not checks["security"]["ok"]
    with pytest.raises(ValueError):
        env_line("ADMIN_PASSWORD", "a`b")


def test_private_client_cannot_forge_its_address_when_private_proxies_are_not_trusted():
    forged = {"X-Forwarded-For": "203.0.113.99, 10.5.5.5"}
    strict = {"TRUST_PRIVATE_PROXIES": "false", "TRUSTED_PROXY_CIDRS": "10.42.0.0/16"}
    # The ingress pod (10.42.x) is the only proxy; 10.5.5.5 is the user.
    assert resolve("10.42.0.7", forged, **strict) == "10.5.5.5"
    # A peer outside the listed proxies gets no say at all.
    assert resolve("10.5.5.5", {"X-Forwarded-For": "203.0.113.99"}, **strict) == "10.5.5.5"
    # The bundled nginx in the same container stays trusted.
    assert resolve("127.0.0.1", {"X-Forwarded-For": "198.51.100.7"}, TRUST_PRIVATE_PROXIES="false") == "198.51.100.7"
    # Unchanged default: every private range is a proxy.
    assert resolve("10.42.0.7", {"X-Forwarded-For": "198.51.100.7, 10.1.0.3"}) == "198.51.100.7"


def test_rt_import_matches_users_in_the_importing_tenant(app):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="second", name="Second"))
        db.session.flush()
        existing = User(username="second-user", name="Second User", email="person@example.com",
                        role="requester", tenant_id=2, password_hash="x")
        db.session.add(existing)
        db.session.commit()
        # The worker has no signed-in user; the import's tenant must be used.
        found = _resolve_or_create_user("Person@Example.com", "Person", 2, {"users_created": 0})
        assert found.id == existing.id
        admin = User.query.filter_by(username="admin").one()
        assert _resolve_or_create_user(admin.email, "Admin", 1, {"users_created": 0}).id == admin.id


def test_safe_cell_neutralises_formulas_and_keeps_numbers():
    assert safe_cell("=HYPERLINK(\"http://x\")") == "'=HYPERLINK(\"http://x\")"
    assert safe_cell("  @SUM(A1)") == "'  @SUM(A1)"
    assert safe_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert safe_cell("\tlate") == "'\tlate"
    assert safe_cell("-5") == "-5" and safe_cell("+3.2") == "+3.2"
    assert safe_cell(-5) == -5 and safe_cell(None) is None
    assert safe_cell("Printer offline") == "Printer offline"
    assert safe_row({"message": "=1+1", "count": 3}) == {"message": "'=1+1", "count": 3}
    buffer = io.StringIO()
    safe_writer(buffer).writerow(["INC1", "=1+1"])
    assert buffer.getvalue().strip() == "INC1,'=1+1"


def test_ticket_export_does_not_carry_a_formula(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(Ticket(number="INC9990001", kind="incident", title="=HYPERLINK(\"http://evil\")",
                              description="d", state="New", priority="P3", requester_id=admin.id, tenant_id=1))
        db.session.commit()
    body = client.get("/tickets/incident/export.csv").get_data(as_text=True)
    assert "INC9990001" in body
    assert "'=HYPERLINK" in body and ",=HYPERLINK" not in body


def test_purge_removes_only_expired_rows(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        api_client = APIClient(name="c", token_prefix="p", token_hash="h", scopes_json="[]",
                               acting_user_id=admin.id, created_by_id=admin.id, tenant_id=1)
        db.session.add(api_client)
        db.session.flush()
        old, recent = now() - timedelta(hours=5), now() - timedelta(minutes=5)
        db.session.add_all([
            RouteRateLimitWindow(key="login:user:gone", window_start=old, request_count=1),
            RouteRateLimitWindow(key="login:user:live", window_start=recent, request_count=1),
            APIRateLimitWindow(api_client_id=api_client.id, window_start=old, request_count=1),
            APIRateLimitWindow(api_client_id=api_client.id, window_start=recent, request_count=1),
            UserSession(session_id="ancient", user_id=admin.id, tenant_id=1, expires_at=now() - timedelta(days=200)),
            UserSession(session_id="expired-last-week", user_id=admin.id, tenant_id=1,
                        expires_at=now() - timedelta(days=7)),
            UserSession(session_id="live", user_id=admin.id, tenant_id=1, expires_at=now() + timedelta(hours=8)),
        ])
        db.session.commit()
        assert housekeeping.purge_expired_rows(force=True) == 3
        assert [row.key for row in RouteRateLimitWindow.query.all()] == ["login:user:live"]
        assert APIRateLimitWindow.query.count() == 1
        assert {row.session_id for row in UserSession.query.all()} == {"expired-last-week", "live"}
        # Not due again within the hour.
        db.session.add(RouteRateLimitWindow(key="login:user:later", window_start=old, request_count=1))
        db.session.commit()
        assert housekeeping.purge_expired_rows() == 0
