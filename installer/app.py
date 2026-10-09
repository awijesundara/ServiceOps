import json
import os
import logging
import tempfile
import socket
import ssl
import urllib.request
from pathlib import Path
from urllib.parse import urlparse, urlsplit

import psycopg
from cryptography.fernet import Fernet
from flask import Flask, abort, jsonify, render_template, request

from serviceops_core.localization import init_app as init_localization, tr
from ldap3 import ALL, Connection, Server, Tls

logger = logging.getLogger(__name__)


class InstallerStateError(RuntimeError):
    """Existing configuration could not be read or safely written."""


STATE = Path(os.getenv("INSTALLER_STATE_DIR", "/config"))


def clean(value):
    return str(value or "").replace("\r", "").replace("\n", "").strip()


def load_json(name, default):
    try:
        payload = json.loads((STATE / name).read_text())
        if not isinstance(payload, dict):
            raise ValueError("State must be an object")
        return payload
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as error:
        logger.error("Installer state read failed: %s", name)
        raise InstallerStateError("Existing installer state requires recovery.") from error


def save_json(name, value):
    _atomic_state_write(name, json.dumps(value, indent=2))


def _atomic_state_write(name, content):
    temporary = None
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".installer-", dir=STATE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, STATE / name)
    except (OSError, ValueError) as error:
        logger.error("Installer state write failed: %s", name)
        raise InstallerStateError("Installer state could not be saved safely.") from error
    finally:
        if temporary and os.path.exists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                logger.error("Installer temporary state cleanup failed")


def result(ok, message, details=""):
    return {"ok": bool(ok), "message": message, "details": details}


def test_database(config):
    if config.get("db_mode") == "bundled":
        return result(True, tr("Bundled PostgreSQL is selected"),
                      "The database image and persistent volume will be verified during deployment.")
    url = clean(config.get("database_url")).replace("postgresql+psycopg://", "postgresql://", 1)
    if not url:
        return result(False, tr("Database URL is required"))
    try:
        with psycopg.connect(url, connect_timeout=8) as conn:
            row = conn.execute(
                "select current_database(), current_user, version()"
            ).fetchone()
        return result(True, tr("PostgreSQL connection succeeded"), " · ".join(row))
    except Exception as exc:
        return result(False, tr("PostgreSQL connection failed"), str(exc))


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
        return result(True, tr("AD/LDAP is disabled"))
    try:
        server, use_ssl = ldap_server(config)
        connection = Connection(server, user=clean(config.get("ldap_bind_dn")) or None,
                                password=config.get("ldap_bind_password") or None,
                                auto_bind=False, receive_timeout=8)
        connection.open()
        if not use_ssl and config.get("ldap_start_tls", True) and not connection.start_tls():
            return result(False, tr("LDAP StartTLS failed"), str(connection.result))
        if not connection.bind():
            return result(False, tr("LDAP bind failed"), str(connection.result))
        if not connection.search(clean(config.get("ldap_base_dn")), "(objectClass=*)",
                                 attributes=["distinguishedName"], size_limit=1):
            return result(False, tr("LDAP base search failed"), str(connection.result))
        connection.unbind()
        return result(True, tr("LDAP bind and directory search succeeded"),
                      f"Server: {server.host}; TLS: {'LDAPS' if use_ssl else 'StartTLS'}")
    except Exception as exc:
        return result(False, tr("LDAP validation failed"), str(exc))


def test_keycloak(config):
    if not config.get("keycloak_enabled"):
        return result(True, tr("Keycloak is disabled"))
    discovery = clean(config.get("keycloak_discovery_url"))
    try:
        context = ssl.create_default_context()
        with urllib.request.urlopen(discovery, timeout=8, context=context) as response:
            metadata = json.load(response)
        required = ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"]
        missing = [key for key in required if not metadata.get(key)]
        if missing:
            return result(False, tr("Keycloak discovery is incomplete"), ", ".join(missing))
        if not clean(config.get("keycloak_client_id")):
            return result(False, tr("Keycloak client ID is required"))
        return result(True, tr("Keycloak OIDC discovery succeeded"), metadata["issuer"])
    except Exception as exc:
        return result(False, tr("Keycloak discovery failed"), str(exc))


def test_ipfs(config):
    if config.get("storage_mode", "postgres") != "ipfs":
        return result(True, tr("PostgreSQL storage mode is selected (default)"))
    if config.get("ipfs_provider", "kubo") == "pinata":
        jwt = clean(config.get("pinata_jwt"))
        if not jwt:
            return result(False, tr("A Pinata JWT is required (get one free at pinata.cloud)"))
        if not clean(config.get("pinata_gateway_url")):
            return result(
                False,
                tr("A dedicated Pinata gateway URL is required"),
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
            return result(True, tr("Pinata JWT authenticated"), payload.get("message", ""))
        except Exception as exc:
            return result(False, tr("Pinata authentication failed"), str(exc))
    if config.get("ipfs_mode", "bundled") == "bundled":
        return result(True, tr("Bundled IPFS node is selected"),
                      "The IPFS node container will be verified during deployment.")
    api_url = clean(config.get("ipfs_api_url"))
    if not api_url:
        return result(False, tr("IPFS API URL is required for an external node"))
    try:
        request_obj = urllib.request.Request(api_url.rstrip("/") + "/api/v0/id", method="POST")
        context = ssl.create_default_context()
        with urllib.request.urlopen(request_obj, timeout=8, context=context) as response:
            payload = json.load(response)
        return result(True, tr("IPFS node reachable"), payload.get("ID", ""))
    except Exception as exc:
        return result(False, tr("IPFS node connection failed"), str(exc))


def test_network(config):
    sock = None
    try:
        raw_port = config.get("app_port", 8080)
        if isinstance(raw_port, bool) or not isinstance(raw_port, (str, int)):
            raise ValueError("Application port must be an integer")
        port = int(raw_port)
        if not 0 <= port <= 65535:
            raise ValueError("Application port must be between 0 and 65535")
        sock = socket.socket()
        sock.bind((clean(config.get("bind_address")) or "127.0.0.1", port))
        return result(True, tr("Application port {port} is available", port=port))
    except (OSError, ValueError, TypeError, OverflowError):
        logger.warning("Installer network validation failed")
        return result(False, tr("Application port is invalid or unavailable"))
    finally:
        if sock is not None:
            sock.close()


def validate(config):
    checks = {
        "host": load_json("host-preflight.json", result(False, tr("Host preflight has not run"))),
        "network": test_network(config),
        "database": test_database(config),
        "ipfs": test_ipfs(config),
        "ldap": test_ldap(config),
        "keycloak": test_keycloak(config),
    }
    if len(config.get("admin_password", "")) < 14:
        checks["security"] = result(False, tr("Administrator password must be at least 14 characters"))
    elif config.get("ldap_enabled") and not (
            clean(config.get("ldap_uri")).startswith("ldaps://") or config.get("ldap_start_tls")
        ):
        checks["security"] = result(False, tr("LDAP must use LDAPS or StartTLS"))
    elif config.get("keycloak_enabled") and not clean(
            config.get("keycloak_discovery_url")
        ).startswith("https://"):
        checks["security"] = result(False, tr("Keycloak discovery must use HTTPS"))
    else:
        checks["security"] = result(True, tr("Production security policy passed"))
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
        env_line("SERVICEOPS_IMAGE", config.get("serviceops_image", "serviceops-app:1.113.12")),
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
    _atomic_state_write("serviceops.env", "\n".join(lines) + "\n")


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.getenv("INSTALLER_SECRET", os.urandom(32).hex())
    # No accounts or settings yet: follow the browser language; the installer's
    # /api/ endpoints serve only its own page, so they are localized too.
    init_localization(app, default_language=lambda: "auto", api_prefix=None)
    allowed_hosts = {"localhost", "127.0.0.1", "::1"} | {
        host.strip().lower() for host in os.getenv("INSTALLER_ALLOWED_HOSTS", "").split(",") if host.strip()
    }

    @app.before_request
    def reject_foreign_requests():
        # The installer has no login and writes deployment secrets. Beyond
        # being published on loopback only, refuse a foreign Host (DNS
        # rebinding turns a web page into a same-origin client) and a
        # foreign Origin (a cross-site page posting to 127.0.0.1).
        hostname = (urlsplit(f"//{request.host}").hostname or "").lower()
        if hostname not in allowed_hosts:
            abort(403)
        origin = request.headers.get("Origin")
        if request.method != "GET" and origin and urlsplit(origin).netloc.lower() != request.host.lower():
            abort(403)

    def json_config():
        # Deliberately not force=True: requiring application/json makes a
        # cross-site browser request need a CORS preflight, which is refused.
        config = request.get_json(silent=True)
        if not isinstance(config, dict):
            abort(400, description=tr("A JSON object is required."))
        flags = {"ldap_enabled", "ldap_start_tls", "ldap_validate_cert", "keycloak_enabled"}
        for key, value in config.items():
            if key in flags:
                if type(value) is not bool:
                    abort(400, description=tr("{key} must be a boolean.", key=key))
            elif key == "app_port":
                if isinstance(value, bool) or not isinstance(value, (str, int)):
                    abort(400, description=tr("app_port must be an integer."))
                try:
                    port = int(value)
                except ValueError:
                    abort(400, description=tr("app_port must be an integer."))
                if not 1 <= port <= 65535:
                    abort(400, description=tr("app_port must be between 1 and 65535."))
            elif not isinstance(value, str):
                abort(400, description=tr("{key} must be a string.", key=key))
        return config

    @app.errorhandler(OSError)
    @app.errorhandler(InstallerStateError)
    def state_error(_error):
        logger.error("Installer state operation failed; recovery is required")
        return jsonify(error=tr("Installer state requires recovery; existing configuration was preserved.")), 503

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify(error=error.description), 400

    @app.get("/")
    def index():
        return render_template("index.html", config=load_json("config.json", {}),
                               host=load_json("host-preflight.json", {}))

    @app.post("/api/validate")
    def api_validate():
        config = json_config()
        load_json("config.json", {})
        checks = validate(config)
        save_json("validation.json", checks)
        if all(item["ok"] for item in checks.values()):
            save_json("config.json", config)
        return jsonify(checks=checks, ready=all(item["ok"] for item in checks.values()))

    @app.post("/api/deploy")
    def api_deploy():
        config = json_config()
        load_json("config.json", {})
        checks = validate(config)
        if not all(item["ok"] for item in checks.values()):
            return jsonify(error=tr("Every required check must pass before deployment."), checks=checks), 400
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
            return jsonify(error=tr("Company logo must be a valid PNG file.")), 400
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
