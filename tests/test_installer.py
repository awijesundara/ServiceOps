from installer.app import validate


def test_demo_validation_accepts_disabled_enterprise_identity(monkeypatch):
    monkeypatch.setattr("installer.app.load_json",
                        lambda *_: {"ok": True, "message": "Host passed"})
    checks = validate({
        "profile": "demo", "db_mode": "bundled", "bind_address": "127.0.0.1",
        "app_port": "0", "ldap_enabled": False, "keycloak_enabled": False,
    })
    assert all(check["ok"] for check in checks.values())


def test_production_requires_strong_admin_password(monkeypatch):
    monkeypatch.setattr("installer.app.load_json",
                        lambda *_: {"ok": True, "message": "Host passed"})
    checks = validate({
        "profile": "production", "db_mode": "bundled", "bind_address": "127.0.0.1",
        "app_port": "0", "admin_password": "weak",
        "ldap_enabled": False, "keycloak_enabled": False,
    })
    assert not checks["security"]["ok"]
