"""On-demand NetBox inventory sync.

Pulls DCIM devices and virtualization VMs from a NetBox instance's REST API
and upserts them into ConfigurationItem, using the same "manual trigger,
dry-run preview, per-record error isolation" shape as
serviceops_core/ldap_sync.py.

NetBox is treated as the source of truth for hardware fields (name, serial
number, vendor, model, IP address, location) — every sync overwrites those
fields on matched CIs. Non-hardware fields (owner, cost center, description,
business criticality, ...) are left untouched here; those are populated by
serviceops_core/cmdb_import.py (CSV/spreadsheet import), which in turn never
overwrites hardware fields on a netbox-sourced CI.
"""
import os
import tempfile

import requests

DEVICES_PATH = "/api/dcim/devices/"
VMS_PATH = "/api/virtualization/virtual-machines/"

STATUS_MAP = {
    "active": "Operational",
    "offline": "Retired",
    "planned": "Pre-production",
    "staged": "Pre-production",
    "failed": "Down",
    "inventory": "Retired",
    "decommissioning": "Retired",
}

# ConfigurationItem columns NetBox owns outright; a re-sync always overwrites
# these on a matched CI (see cmdb_import.py's mirrored NETBOX_OWNED_FIELDS,
# which is why the two modules never fight over the same columns).
HARDWARE_FIELDS = ("name", "serial_number", "vendor", "model", "ip_address", "location")


class NetboxSyncError(RuntimeError):
    """Raised for conditions that must abort the whole sync (e.g. not configured)."""


def _netbox_session(base_url, token):
    """Build a requests.Session for talking to NetBox. Isolated in its own
    function so tests can monkeypatch it with a fake, matching the
    app.ldap_server_and_service_connection mocking convention.

    Certificate verification is on by default. An internal NetBox instance
    served from a corporate CA that isn't in the public trust store (the
    common case for on-prem tools) should be handled by pasting that CA's
    certificate into the NETBOX_CA_CERT setting -- that's the secure fix and
    takes priority here. NETBOX_TLS_INSECURE is a separate, explicit
    admin-opt-in escape hatch for when the CA can't be obtained; it disables
    verification entirely and is deliberately not the default."""
    import app as core_app

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Token {token}",
        "Accept": "application/json",
    })
    ca_cert = core_app.setting_value("NETBOX_CA_CERT", "").strip()
    if ca_cert:
        session.verify = _write_ca_bundle(ca_cert)
    elif core_app.setting_bool("NETBOX_TLS_INSECURE"):
        session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


def _write_ca_bundle(pem_text):
    """Writes an admin-supplied CA certificate (PEM) to a private temp file
    and returns its path, for use as requests' `verify=`. The caller
    (sync_from_netbox) removes this file once the sync finishes."""
    fd, path = tempfile.mkstemp(prefix="netbox-ca-", suffix=".pem")
    with os.fdopen(fd, "w") as handle:
        handle.write(pem_text)
    return path


def _get(session, base_url, path, params=None):
    url = base_url.rstrip("/") + path
    response = session.get(url, params=params, timeout=15)
    response.raise_for_status()
    return response.json()


def _paginate(session, base_url, path):
    params = {"limit": 100, "offset": 0}
    while True:
        payload = _get(session, base_url, path, params=params)
        for result in payload.get("results", []):
            yield result
        if not payload.get("next"):
            return
        params["offset"] += params["limit"]


def _first_attr(record, *keys):
    node = record
    for key in keys:
        if node is None:
            return None
        node = node.get(key) if isinstance(node, dict) else None
    return node


def _location_of(record):
    site = _first_attr(record, "site", "name")
    location = _first_attr(record, "location", "name")
    if site and location:
        return f"{site} / {location}"
    return site or location or None


def _ip_of(record):
    address = _first_attr(record, "primary_ip4", "address") or _first_attr(record, "primary_ip", "address")
    if not address:
        return None
    return address.split("/")[0]


def _map_device(record, ci_class):
    status_value = _first_attr(record, "status", "value")
    return {
        "name": record.get("name") or f"device-{record.get('id')}",
        "ci_class": ci_class,
        "serial_number": record.get("serial") or None,
        "vendor": _first_attr(record, "device_type", "manufacturer", "name"),
        "model": _first_attr(record, "device_type", "model"),
        "ip_address": _ip_of(record),
        "location": _location_of(record),
        "operational_status": STATUS_MAP.get(status_value, "Operational"),
        "netbox_id": str(record["id"]),
    }


def _map_vm(record):
    status_value = _first_attr(record, "status", "value")
    return {
        "name": record.get("name") or f"vm-{record.get('id')}",
        "ci_class": "Virtual Machine",
        "serial_number": None,
        "vendor": None,
        "model": _first_attr(record, "platform", "name"),
        "ip_address": _ip_of(record),
        "location": _first_attr(record, "cluster", "name"),
        "operational_status": STATUS_MAP.get(status_value, "Operational"),
        "netbox_id": str(record["id"]),
    }


def _upsert(mapped, tenant_id, summary):
    import app as core_app
    from app import db

    ci = core_app.ConfigurationItem.query.filter_by(
        tenant_id=tenant_id, external_source="netbox", external_id=mapped["netbox_id"],
    ).first()
    matched_by_serial = False
    if not ci and mapped["serial_number"]:
        ci = core_app.ConfigurationItem.query.filter_by(
            tenant_id=tenant_id, serial_number=mapped["serial_number"],
        ).first()
        matched_by_serial = ci is not None

    if ci:
        for field in HARDWARE_FIELDS:
            value = mapped.get(field)
            if value is not None:
                setattr(ci, field, value)
        ci.operational_status = mapped["operational_status"]
        ci.ci_class = mapped["ci_class"]
        ci.external_source = "netbox"
        ci.external_id = mapped["netbox_id"]
        ci.discovery_source = "API"
        summary["cis_updated"] += 1
        if matched_by_serial:
            summary["cis_matched_by_serial"] += 1
    else:
        db.session.add(core_app.ConfigurationItem(
            name=mapped["name"], ci_class=mapped["ci_class"],
            operational_status=mapped["operational_status"],
            serial_number=mapped["serial_number"], vendor=mapped["vendor"],
            model=mapped["model"], ip_address=mapped["ip_address"],
            location=mapped["location"], discovery_source="API",
            external_source="netbox", external_id=mapped["netbox_id"],
            tenant_id=tenant_id,
        ))
        summary["cis_created"] += 1


def sync_from_netbox(tenant_id, dry_run=False, session_factory=_netbox_session):
    """Pull devices and VMs from NetBox and upsert them into ConfigurationItem
    for ``tenant_id``. Fails closed on missing tenant/configuration rather
    than silently defaulting."""
    import app as core_app
    from app import db

    if not tenant_id or not isinstance(tenant_id, int):
        raise NetboxSyncError("A valid integer tenant_id is required; refusing to sync.")
    tenant = db.session.get(core_app.Tenant, tenant_id)
    if not tenant or not tenant.active:
        raise NetboxSyncError(f"Tenant {tenant_id} does not exist or is inactive; refusing to sync.")
    if not core_app.setting_bool("NETBOX_ENABLED"):
        raise NetboxSyncError("NetBox sync is not enabled; refusing to sync.")

    base_url = core_app.setting_value("NETBOX_BASE_URL", "")
    token = core_app.setting_value("NETBOX_API_TOKEN", "")
    if not base_url or not token:
        raise NetboxSyncError("NetBox base URL and API token must both be configured.")
    # allow_private_network=True: NetBox is a trusted, admin-configured
    # integration (unlike a per-automation-rule webhook URL) and is almost
    # always self-hosted on the internal network, so unlike the general
    # webhook/export SSRF guard this only blocks loopback/link-local/
    # multicast/reserved targets, not ordinary RFC1918 addresses.
    if not core_app.integration_endpoint_valid(base_url, allow_private_network=True):
        raise NetboxSyncError("NetBox base URL failed safety validation (must be an https host).")
    # DNS-rebinding re-check (see app.integration_endpoint_resolves_safely) is done
    # once here, immediately before the sync's network calls begin, rather than on
    # every paginated request -- the target host doesn't change page-to-page.
    if not core_app.integration_endpoint_resolves_safely(base_url, allow_private_network=True):
        raise NetboxSyncError("NetBox base URL failed DNS safety validation.")

    summary = {
        "tenant_id": tenant_id,
        "dry_run": bool(dry_run),
        "devices_seen": 0,
        "cis_created": 0,
        "cis_updated": 0,
        "cis_matched_by_serial": 0,
        "errors": [],
    }

    session = session_factory(base_url, token)
    try:
        for record in _paginate(session, base_url, DEVICES_PATH):
            summary["devices_seen"] += 1
            try:
                _upsert(_map_device(record, "Server"), tenant_id, summary)
            except Exception as error:  # noqa: BLE001 - isolate one bad record from the whole sync
                summary["errors"].append(f"device {record.get('name', record.get('id'))}: {type(error).__name__}")
        for record in _paginate(session, base_url, VMS_PATH):
            summary["devices_seen"] += 1
            try:
                _upsert(_map_vm(record), tenant_id, summary)
            except Exception as error:  # noqa: BLE001
                summary["errors"].append(f"vm {record.get('name', record.get('id'))}: {type(error).__name__}")
    except requests.RequestException as error:
        summary["errors"].append(f"NetBox request failed: {type(error).__name__}: {error}")
    finally:
        session.close()
        ca_bundle_path = getattr(session, "verify", None)
        if isinstance(ca_bundle_path, str) and ca_bundle_path.startswith(tempfile.gettempdir()):
            try:
                os.unlink(ca_bundle_path)
            except OSError:
                pass

    if dry_run:
        db.session.rollback()
    else:
        db.session.commit()

    return summary
