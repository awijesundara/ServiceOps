"""On-demand NetBox inventory sync.

Pulls DCIM devices and virtualization VMs from a NetBox instance's REST API
and upserts them into ConfigurationItem, using the same "manual trigger,
dry-run preview, per-record error isolation" shape as
serviceops_core/ldap_sync.py.

NetBox is treated as the source of truth for hardware fields (name, serial
number, vendor, model, IP address, location) and physical rack placement
(rack, position, height in U, front/rear face) — every sync overwrites those
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
RACKS_PATH = "/api/dcim/racks/"


def _format_interface(record):
    label = record.get("name") or "?"
    bits = []
    type_label = _first_attr(record, "type", "label")
    if type_label:
        bits.append(type_label)
    mac = record.get("mac_address") or _first_attr(record, "primary_mac_address", "mac_address")
    if mac:
        bits.append(mac)
    parent = _first_attr(record, "lag", "name")
    if parent:
        bits.append(f"in {parent}")
    if record.get("enabled") is False:
        bits.append("disabled")
    return f"{label} ({', '.join(bits)})" if bits else label


def _format_port(record):
    label = record.get("name") or "?"
    type_label = _first_attr(record, "type", "label")
    return f"{label} ({type_label})" if type_label else label


def _format_power_port(record):
    label = record.get("name") or "?"
    bits = []
    type_label = _first_attr(record, "type", "label")
    if type_label:
        bits.append(type_label)
    watts = record.get("maximum_draw")
    if watts:
        bits.append(f"{watts}W")
    return f"{label} ({', '.join(bits)})" if bits else label


def _format_inventory_item(record):
    label = record.get("name") or "?"
    role = _first_attr(record, "role", "name")
    return f"{label} ({role})" if role else label


# Per-device components pulled in bulk (one full paginated fetch per type,
# grouped by device id in memory) rather than one request per device -- a
# NetBox instance can have thousands of devices, so an N+1 fetch pattern
# here would make every sync prohibitively slow.
COMPONENT_ENDPOINTS = (
    ("/api/dcim/interfaces/", "Interfaces", _format_interface),
    ("/api/dcim/console-ports/", "Console Ports", _format_port),
    ("/api/dcim/power-ports/", "Power Ports", _format_power_port),
    ("/api/dcim/inventory-items/", "Inventory Items", _format_inventory_item),
)

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
# which is why the two modules never fight over the same columns). The four
# rack_* fields were added alongside the rack elevation view -- previously
# this data lived only as free-text "NetBox: Rack"/"NetBox: Position"
# attributes (see _map_device below).
HARDWARE_FIELDS = (
    "name", "serial_number", "vendor", "model", "ip_address", "location",
    "rack_id", "rack_position", "rack_u_height", "rack_face",
)


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


def _fetch_all_components(session, base_url):
    """Fetches interfaces/console ports/power ports/inventory items for every
    device and groups the formatted summaries by device id. Each component
    type is fetched independently -- if the API token lacks permission for
    one (e.g. inventory items), that type is skipped rather than aborting
    the whole sync."""
    grouped = {}
    for path, label, formatter in COMPONENT_ENDPOINTS:
        by_device = {}
        try:
            for record in _paginate(session, base_url, path):
                device_id = str(_first_attr(record, "device", "id") or "")
                if not device_id:
                    continue
                by_device.setdefault(device_id, []).append(formatter(record))
        except requests.RequestException:
            continue
        for device_id, items in by_device.items():
            grouped.setdefault(device_id, {})[f"NetBox: {label}"] = "; ".join(items)
    return grouped


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


def _oob_ip_of(record):
    address = _first_attr(record, "oob_ip", "address")
    return address.split("/")[0] if address else None


def _ipv6_of(record):
    address = _first_attr(record, "primary_ip6", "address")
    return address.split("/")[0] if address else None


def _extra_attributes(record, *, fields=()):
    """Everything NetBox has on this record beyond the handful of columns
    ConfigurationItem has dedicated fields for -- rack position, role,
    platform, custom fields, tags, comments, etc. Kept under a "NetBox: "
    prefix in ConfigurationItem.attributes so it never collides with fields
    a CSV import captured for the same CI, and so a re-sync can safely
    refresh only the NetBox-owned keys without touching the rest."""
    attributes = {}

    def add(label, value):
        if value not in (None, "", []):
            attributes[f"NetBox: {label}"] = value

    for label, keys in fields:
        add(label, _first_attr(record, *keys))

    add("Out-of-band IP", _oob_ip_of(record))
    add("Primary IPv6", _ipv6_of(record))
    tags = [tag.get("name") for tag in (record.get("tags") or []) if tag.get("name")]
    if tags:
        add("Tags", ", ".join(tags))
    add("Comments", (record.get("comments") or "").strip() or None)

    for key, value in (record.get("custom_fields") or {}).items():
        if isinstance(value, dict):
            value = value.get("label") or value.get("value")
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        add(key.replace("_", " ").title(), value)

    return attributes


def _map_device(record, ci_class, rack_id_map=None):
    status_value = _first_attr(record, "status", "value")
    rack_id_map = rack_id_map or {}
    netbox_rack_id = _first_attr(record, "rack", "id")
    face_value = _first_attr(record, "face", "value")
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
        # Physical rack placement -- rack_id resolved against the map of
        # already-synced racks built by sync_from_netbox this run (see
        # _upsert_rack); a device on a rack NetBox itself doesn't return
        # (shouldn't happen, but matches nothing rather than raising) or a
        # device with no rack at all both simply get rack_id=None here.
        # device_type.u_height may not be present on every NetBox version's
        # nested device_type representation -- read defensively, the CI
        # form/rack view fall back to 1U when it's missing.
        "rack_id": rack_id_map.get(str(netbox_rack_id)) if netbox_rack_id is not None else None,
        "rack_position": record.get("position"),
        "rack_u_height": _first_attr(record, "device_type", "u_height"),
        "rack_face": face_value,
        "attributes": _extra_attributes(record, fields=(
            ("Region", ("site", "region", "name")),
            ("Tenant", ("tenant", "name")),
            ("Role", ("role", "name")),
            ("Platform", ("platform", "name")),
            ("Status", ("status", "label")),
        )),
    }


def _map_rack(record):
    return {
        "name": record.get("name") or f"rack-{record.get('id')}",
        "site": _first_attr(record, "site", "name") or "",
        "u_height": record.get("u_height") or 42,
        "netbox_id": str(record["id"]),
    }


def _upsert_rack(mapped, tenant_id, summary):
    """Same three-tier match as _upsert (external id, then tenant-unique
    name) -- returns the local Rack row so the caller can build a
    {netbox_rack_id: local_rack_id} map for device linking."""
    import app as core_app
    from app import db

    rack = core_app.Rack.query.filter_by(
        tenant_id=tenant_id, external_source="netbox", external_id=mapped["netbox_id"],
    ).first()
    if not rack:
        rack = core_app.Rack.query.filter_by(tenant_id=tenant_id, name=mapped["name"]).first()
    if rack:
        rack.site = mapped["site"]
        rack.u_height = mapped["u_height"]
        rack.external_source = "netbox"
        rack.external_id = mapped["netbox_id"]
        summary["racks_updated"] += 1
    else:
        rack = core_app.Rack(
            tenant_id=tenant_id, name=mapped["name"], site=mapped["site"],
            u_height=mapped["u_height"], external_source="netbox", external_id=mapped["netbox_id"],
        )
        db.session.add(rack)
        summary["racks_created"] += 1
    db.session.flush()
    return rack


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
        "attributes": _extra_attributes(record, fields=(
            ("Tenant", ("tenant", "name")),
            ("Role", ("role", "name")),
            ("Platform", ("platform", "name")),
            ("vCPUs", ("vcpus",)),
            ("Memory (MB)", ("memory",)),
            ("Disk (GB)", ("disk",)),
            ("Status", ("status", "label")),
        )),
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
    # Hostname is unique too (see uq_ci_tenant_name), so a device with no
    # serial number (common for VMs/blades) still adopts an existing CI of
    # the same name -- e.g. one a CSV import or manual entry created --
    # instead of creating a second CI with the same hostname.
    if not ci:
        ci = core_app.ConfigurationItem.query.filter_by(
            tenant_id=tenant_id, name=mapped["name"],
        ).first()

    # NetBox's extra fields (rack, role, custom fields, ...) are namespaced
    # "NetBox: " in attributes so a re-sync can refresh just those keys
    # without clobbering anything a CSV import stored there.
    netbox_attributes = mapped.get("attributes") or {}

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
        preserved = {k: v for k, v in (ci.attributes or {}).items() if not k.startswith("NetBox: ")}
        ci.attributes = {**preserved, **netbox_attributes}
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
            tenant_id=tenant_id, attributes=netbox_attributes,
            rack_id=mapped.get("rack_id"), rack_position=mapped.get("rack_position"),
            rack_u_height=mapped.get("rack_u_height"), rack_face=mapped.get("rack_face"),
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
        "racks_created": 0,
        "racks_updated": 0,
        "errors": [],
    }

    session = session_factory(base_url, token)
    try:
        rack_id_map = {}
        for record in _paginate(session, base_url, RACKS_PATH):
            try:
                rack = _upsert_rack(_map_rack(record), tenant_id, summary)
                rack_id_map[str(record["id"])] = rack.id
            except Exception as error:  # noqa: BLE001 - isolate one bad record from the whole sync
                summary["errors"].append(f"rack {record.get('name', record.get('id'))}: {type(error).__name__}")
        devices = list(_paginate(session, base_url, DEVICES_PATH))
        components_by_device = _fetch_all_components(session, base_url) if devices else {}
        for record in devices:
            summary["devices_seen"] += 1
            try:
                # NetBox's own device role, when present, classifies the
                # device far more usefully than a blanket "Server" -- this
                # is what lets a PDU (or Switch/Router) ever come back
                # correctly classified from a real sync rather than
                # everything landing as "Server" regardless of its real
                # role. Falls back to "Server" only when NetBox has no role
                # set on the device at all.
                ci_class = _first_attr(record, "role", "name") or "Server"
                mapped = _map_device(record, ci_class, rack_id_map=rack_id_map)
                mapped["attributes"].update(components_by_device.get(mapped["netbox_id"], {}))
                _upsert(mapped, tenant_id, summary)
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
