import json
import os
import socket
import ssl
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import psycopg
from cryptography.fernet import Fernet
from flask import Flask, jsonify, render_template, request
from ldap3 import ALL, Connection, Server, Tls

STATE = Path(os.getenv("INSTALLER_STATE_DIR", "/config"))


def clean(value):
    return str(value or "").replace("\r", "").replace("\n", "").strip()


def load_json(name, default):
    try:
        return json.loads((STATE / name).read_text())
    except (OSError, json.JSONDecodeError):
        return default


def save_json(name, value):
    STATE.mkdir(parents=True, exist_ok=True)
    target = STATE / name
    target.write_text(json.dumps(value, indent=2))
    target.chmod(0o600)


def result(ok, message, details=""):
    return {"ok": bool(ok), "message": message, "details": details}


def test_database(config):
    if config.get("db_mode") == "bundled":
        return result(True, "Bundled PostgreSQL is selected",
                      "The database image and persistent volume will be verified during deployment.")
    url = clean(config.get("database_url")).replace("postgresql+psycopg://", "postgresql://", 1)
    if not url:
        return result(False, "Database URL is required")
    try:
        with psycopg.connect(url, connect_timeout=8) as conn:
            row = conn.execute(
                "select current_database(), current_user, version()"
            ).fetchone()
        return result(True, "PostgreSQL connection succeeded", " · ".join(row))
    except Exception as exc:
        return result(False, "PostgreSQL connection failed", str(exc))


def ldap_server(config):
    uri = clean(config.get("ldap_uri"))
    parsed = urlparse(uri)
    use_ssl = parsed.scheme == "ldaps"
    validate = ssl.CERT_REQUIRED if config.get("ldap_validate_cert", True) else ssl.CERT_NONE
    tls = Tls(validate=validate, ca_certs_file=clean(config.get("ldap_ca_cert")) or None)
    return Server(parsed.hostname, port=parsed.port or (636 if use_ssl else 389),
                  use_ssl=use_ssl, tls=tls, get_info=ALL, connect_timeout=8), use_ssl


def test_ldap(config):
    if not config.get("ldap_enabled"):
        return result(True, "AD/LDAP is disabled")
    try:
        server, use_ssl = ldap_server(config)
        connection = Connection(server, user=clean(config.get("ldap_bind_dn")) or None,
                                password=config.get("ldap_bind_password") or None,
                                auto_bind=False, receive_timeout=8)
        connection.open()
        if not use_ssl and config.get("ldap_start_tls", True) and not connection.start_tls():
            return result(False, "LDAP StartTLS failed", str(connection.result))
        if not connection.bind():
            return result(False, "LDAP bind failed", str(connection.result))
        if not connection.search(clean(config.get("ldap_base_dn")), "(objectClass=*)",
                                 attributes=["distinguishedName"], size_limit=1):
            return result(False, "LDAP base search failed", str(connection.result))
        connection.unbind()
        return result(True, "LDAP bind and directory search succeeded",
                      f"Server: {server.host}; TLS: {'LDAPS' if use_ssl else 'StartTLS'}")
    except Exception as exc:
        return result(False, "LDAP validation failed", str(exc))


def test_keycloak(config):
    if not config.get("keycloak_enabled"):
        return result(True, "Keycloak is disabled")
    discovery = clean(config.get("keycloak_discovery_url"))
    try:
        context = ssl.create_default_context()
        with urllib.request.urlopen(discovery, timeout=8, context=context) as response:
            metadata = json.load(response)
        required = ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"]
        missing = [key for key in required if not metadata.get(key)]
        if missing:
            return result(False, "Keycloak discovery is incomplete", ", ".join(missing))
        if not clean(config.get("keycloak_client_id")):
            return result(False, "Keycloak client ID is required")
        return result(True, "Keycloak OIDC discovery succeeded", metadata["issuer"])
    except Exception as exc:
        return result(False, "Keycloak discovery failed", str(exc))


def test_ipfs(config):
    if config.get("storage_mode", "postgres") != "ipfs":
        return result(True, "PostgreSQL storage mode is selected (default)")
    if config.get("ipfs_provider", "kubo") == "pinata":
        jwt = clean(config.get("pinata_jwt"))
        if not jwt:
            return result(False, "A Pinata JWT is required (get one free at pinata.cloud)")
        if not clean(config.get("pinata_gateway_url")):
            return result(
                False,
                "A dedicated Pinata gateway URL is required",
                "Pinata's shared public gateway is unreliable -- use your account's "
                "free dedicated gateway (Pinata dashboard -> Gateways), e.g. "
                "https://<your-name>.mypinata.cloud",
            )
        try:
            request_obj = urllib.request.Request(
                "https://api.pinata.cloud/data/testAuthentication",
                headers={"Authorization": f"Bearer {jwt}"},
            )
            context = ssl.create_default_context()
            with urllib.request.urlopen(request_obj, timeout=8, context=context) as response:
                payload = json.load(response)
            return result(True, "Pinata JWT authenticated", payload.get("message", ""))
        except Exception as exc:
            return result(False, "Pinata authentication failed", str(exc))
    if config.get("ipfs_mode", "bundled") == "bundled":
        return result(True, "Bundled IPFS node is selected",
                      "The IPFS node container will be verified during deployment.")
    api_url = clean(config.get("ipfs_api_url"))
    if not api_url:
        return result(False, "IPFS API URL is required for an external node")
    try:
        request_obj = urllib.request.Request(api_url.rstrip("/") + "/api/v0/id", method="POST")
        context = ssl.create_default_context()
        with urllib.request.urlopen(request_obj, timeout=8, context=context) as response:
            payload = json.load(response)
        return result(True, "IPFS node reachable", payload.get("ID", ""))
    except Exception as exc:
        return result(False, "IPFS node connection failed", str(exc))


def test_network(config):
    port = int(config.get("app_port", 8080))
    sock = socket.socket()
    try:
        sock.bind((clean(config.get("bind_address")) or "127.0.0.1", port))
        return result(True, f"Application port {port} is available")
    except OSError as exc:
        return result(False, f"Application port {port} is unavailable", str(exc))
    finally:
        sock.close()


def validate(config):
    checks = {
        "host": load_json("host-preflight.json", result(False, "Host preflight has not run")),
        "network": test_network(config),
        "database": test_database(config),
        "ipfs": test_ipfs(config),
        "ldap": test_ldap(config),
        "keycloak": test_keycloak(config),
    }
    if len(config.get("admin_password", "")) < 14:
        checks["security"] = result(False, "Administrator password must be at least 14 characters")
    elif config.get("ldap_enabled") and not (
            clean(config.get("ldap_uri")).startswith("ldaps://") or config.get("ldap_start_tls")
        ):
        checks["security"] = result(False, "LDAP must use LDAPS or StartTLS")
    elif config.get("keycloak_enabled") and not clean(
            config.get("keycloak_discovery_url")
        ).startswith("https://"):
        checks["security"] = result(False, "Keycloak discovery must use HTTPS")
    else:
        checks["security"] = result(True, "Production security policy passed")
    return checks


def env_line(key, value):
    value = clean(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'{key}="{value}"'


def write_environment(config):
    db_mode = config.get("db_mode", "bundled")
    storage_mode = config.get("storage_mode", "postgres")
    lines = [
        env_line("DEPLOYMENT_MODE", db_mode),
        env_line("DEPLOYMENT_PROFILE", "production"),
        # Optional database-less deployment mode (experimental): see the
        # storage-mode plan. STORAGE_MODE=postgres (default) is the
        # production-ready path; the IPFS_* lines are unused/ignored
        # unless storage_mode=="ipfs".
        env_line("STORAGE_MODE", storage_mode),
        env_line("IPFS_MODE", config.get("ipfs_mode", "bundled")),
        # IPFS_PROVIDER selects the IPFS client implementation within
        # STORAGE_MODE=ipfs: "kubo" (default -- bundled or external Kubo
        # node, IPFS_API_URL below) or "pinata" (a free hosted pinning
        # service -- no node container at all, PINATA_JWT below).
        env_line("IPFS_PROVIDER", config.get("ipfs_provider", "kubo")),
        env_line("IPFS_API_URL", config.get("ipfs_api_url",
                 "http://ipfs:5001" if storage_mode == "ipfs" else "")),
        env_line("PINATA_JWT", config.get("pinata_jwt", "")),
        # Pinata's shared public gateway (the default) was found via live
        # testing to be unreliable -- every free Pinata account gets its
        # own dedicated gateway subdomain (e.g. https://x.mypinata.cloud),
        # which administrators should set here instead.
        env_line("PINATA_GATEWAY_URL", config.get("pinata_gateway_url", "")),
        env_line("INSTANCE_NAME", config.get("instance_name", "ServiceOps")),
        env_line("COMPANY_NAME", config.get("company_name", "Your Company")),
        env_line("BRAND_TEAL", config.get("brand_teal", "#003e4c")),
        env_line("BRAND_AMBER", config.get("brand_amber", "#f9aa3c")),
        env_line("APP_PORT", config.get("app_port", "8080")),
        env_line("BIND_ADDRESS", config.get("bind_address", "127.0.0.1")),
        env_line("POSTGRES_DB", config.get("postgres_db", "serviceops")),
        env_line("POSTGRES_USER", config.get("postgres_user", "serviceops")),
        env_line("POSTGRES_PASSWORD", config.get("postgres_password", "")),
        env_line("DATABASE_URL", config.get("database_url", "")),
        env_line("SECRET_KEY", config.get("secret_key", "")),
        env_line("SETTINGS_ENCRYPTION_KEY",
                 config.get("settings_encryption_key") or Fernet.generate_key().decode()),
        env_line("AUDIT_INTEGRITY_KEY",
                 config.get("audit_integrity_key") or Fernet.generate_key().decode()),
        env_line("API_TOKEN_PEPPER",
                 config.get("api_token_pepper") or Fernet.generate_key().decode()),
        env_line("ADMIN_PASSWORD", config.get("admin_password", "")),
        env_line("SERVICEOPS_IMAGE", config.get("serviceops_image", "serviceops-app:1.79.3")),
        'LOCAL_AUTH_ENABLED="true"',
        env_line("LDAP_ENABLED", str(bool(config.get("ldap_enabled"))).lower()),
        env_line("LDAP_SERVER_URI", config.get("ldap_uri", "")),
        env_line("LDAP_BIND_DN", config.get("ldap_bind_dn", "")),
        env_line("LDAP_BIND_PASSWORD", config.get("ldap_bind_password", "")),
        env_line("LDAP_BASE_DN", config.get("ldap_base_dn", "")),
        env_line("LDAP_USER_FILTER", config.get("ldap_user_filter",
                                               "(&(objectClass=user)(sAMAccountName={username}))")),
        env_line("LDAP_START_TLS", str(bool(config.get("ldap_start_tls", True))).lower()),
        env_line("LDAP_VALIDATE_CERT", str(bool(config.get("ldap_validate_cert", True))).lower()),
        env_line("LDAP_CA_CERT", config.get("ldap_ca_cert", "")),
        env_line("LDAP_ROLE_MAPPINGS", config.get("ldap_role_mappings", "{}")),
        env_line("KEYCLOAK_ENABLED", str(bool(config.get("keycloak_enabled"))).lower()),
        env_line("KEYCLOAK_DISCOVERY_URL", config.get("keycloak_discovery_url", "")),
        env_line("KEYCLOAK_CLIENT_ID", config.get("keycloak_client_id", "")),
        env_line("KEYCLOAK_CLIENT_SECRET", config.get("keycloak_client_secret", "")),
        env_line("KEYCLOAK_ROLE_MAPPINGS", config.get("keycloak_role_mappings", "{}")),
    ]
    target = STATE / "serviceops.env"
    target.write_text("\n".join(lines) + "\n")
    target.chmod(0o600)


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.getenv("INSTALLER_SECRET", os.urandom(32).hex())

    @app.get("/")
    def index():
        return render_template("index.html", config=load_json("config.json", {}),
                               host=load_json("host-preflight.json", {}))

    @app.post("/api/validate")
    def api_validate():
        config = request.get_json(force=True)
        save_json("config.json", config)
        checks = validate(config)
        save_json("validation.json", checks)
        return jsonify(checks=checks, ready=all(item["ok"] for item in checks.values()))

    @app.post("/api/deploy")
    def api_deploy():
        config = request.get_json(force=True)
        checks = validate(config)
        if not all(item["ok"] for item in checks.values()):
            return jsonify(error="Every required check must pass before deployment.", checks=checks), 400
        write_environment(config)
        save_json("deploy-request.json", {"requested": True})
        return jsonify(status="requested")

    @app.post("/api/logo")
    def api_logo():
        logo = request.files.get("company_logo")
        if not logo or not logo.filename:
            return jsonify(status="none")
        header = logo.stream.read(8)
        logo.stream.seek(0)
        if header != b"\x89PNG\r\n\x1a\n":
            return jsonify(error="Company logo must be a valid PNG file."), 400
        target = STATE / "company-logo.png"
        logo.save(target)
        target.chmod(0o600)
        return jsonify(status="saved")

    @app.get("/api/deployment")
    def api_deployment():
        return jsonify(load_json("deployment-result.json", {"status": "waiting"}))

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    return app
