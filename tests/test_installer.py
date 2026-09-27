from installer.app import validate, write_environment


def test_validation_defaults_to_postgres_storage_mode(monkeypatch):
    monkeypatch.setattr("installer.app.load_json",
                        lambda *_: {"ok": True, "message": "Host passed"})
    checks = validate({
        "db_mode": "bundled", "bind_address": "127.0.0.1", "app_port": "0",
        "admin_password": "strong-production-password",
        "ldap_enabled": False, "keycloak_enabled": False,
    })
    assert checks["ipfs"]["ok"]
    assert "PostgreSQL" in checks["ipfs"]["message"]


def test_validation_ipfs_bundled_mode_skips_live_check(monkeypatch):
    monkeypatch.setattr("installer.app.load_json",
                        lambda *_: {"ok": True, "message": "Host passed"})
    checks = validate({
        "db_mode": "bundled", "bind_address": "127.0.0.1", "app_port": "0",
        "admin_password": "strong-production-password",
        "ldap_enabled": False, "keycloak_enabled": False,
        "storage_mode": "ipfs", "ipfs_mode": "bundled",
    })
    assert checks["ipfs"]["ok"]


def test_validation_ipfs_external_mode_requires_api_url(monkeypatch):
    monkeypatch.setattr("installer.app.load_json",
                        lambda *_: {"ok": True, "message": "Host passed"})
    checks = validate({
        "db_mode": "bundled", "bind_address": "127.0.0.1", "app_port": "0",
        "admin_password": "strong-production-password",
        "ldap_enabled": False, "keycloak_enabled": False,
        "storage_mode": "ipfs", "ipfs_mode": "external", "ipfs_api_url": "",
    })
    assert not checks["ipfs"]["ok"]


def test_write_environment_defaults_storage_mode_to_postgres(tmp_path, monkeypatch):
    monkeypatch.setattr("installer.app.STATE", tmp_path)
    write_environment({
        "db_mode": "bundled", "admin_password": "strong-production-password",
    })
    env_text = (tmp_path / "serviceops.env").read_text()
    assert 'STORAGE_MODE="postgres"' in env_text
    assert 'IPFS_API_URL=""' in env_text


def test_write_environment_ipfs_mode_defaults_bundled_api_url(tmp_path, monkeypatch):
    monkeypatch.setattr("installer.app.STATE", tmp_path)
    write_environment({
        "db_mode": "bundled", "admin_password": "strong-production-password",
        "storage_mode": "ipfs",
    })
    env_text = (tmp_path / "serviceops.env").read_text()
    assert 'STORAGE_MODE="ipfs"' in env_text
    assert 'IPFS_API_URL="http://ipfs:5001"' in env_text


def test_validation_accepts_disabled_enterprise_identity(monkeypatch):
    monkeypatch.setattr("installer.app.load_json",
                        lambda *_: {"ok": True, "message": "Host passed"})
    checks = validate({
        "db_mode": "bundled", "bind_address": "127.0.0.1", "app_port": "0",
        "admin_password": "strong-production-password",
        "ldap_enabled": False, "keycloak_enabled": False,
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


def installer_client(tmp_path, monkeypatch, allowed_hosts=""):
    from installer.app import create_app

    monkeypatch.setattr("installer.app.STATE", tmp_path)
    monkeypatch.setenv("INSTALLER_ALLOWED_HOSTS", allowed_hosts)
    monkeypatch.setattr("installer.app.validate", lambda config: {"host": {"ok": True, "message": "ok"}})
    return create_app().test_client()


def test_installer_rejects_dns_rebinding_host(tmp_path, monkeypatch):
    client = installer_client(tmp_path, monkeypatch)
    assert client.get("/", headers={"Host": "attacker.example:8090"}).status_code == 403
    assert client.post("/api/deploy", json={}, headers={"Host": "attacker.example:8090"}).status_code == 403
    assert client.get("/health", headers={"Host": "127.0.0.1:8090"}).status_code == 200
    assert client.get("/health", headers={"Host": "[::1]:8090"}).status_code == 200


def test_installer_allows_configured_bind_host(tmp_path, monkeypatch):
    client = installer_client(tmp_path, monkeypatch, allowed_hosts="10.0.0.5")
    assert client.get("/health", headers={"Host": "10.0.0.5:8090"}).status_code == 200


def test_installer_rejects_cross_site_posts(tmp_path, monkeypatch):
    client = installer_client(tmp_path, monkeypatch)
    # A cross-site page can send text/plain without a CORS preflight.
    simple = client.post("/api/deploy", data='{"db_mode": "bundled"}', content_type="text/plain")
    assert simple.status_code == 400
    assert not (tmp_path / "serviceops.env").exists()
    foreign = client.post("/api/validate", json={}, headers={"Origin": "https://attacker.example"})
    assert foreign.status_code == 403
    same_origin = client.post("/api/validate", json={}, headers={"Origin": "http://localhost"})
    assert same_origin.status_code == 200
