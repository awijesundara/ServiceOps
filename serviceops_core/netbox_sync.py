"""On-demand NetBox inventory sync.

Pulls DCIM devices and virtualization VMs from a NetBox instance's REST API
and upserts them into ConfigurationItem, using the same "manual trigger,
dry-run preview, per-record error isolation" shape as
serviceops_core/ldap_sync.py.

NetBox is treated as the source of truth for inventory fields (name, serial
number, vendor, model, IP address, location) and physical rack placement
(rack, position, height in U, front/rear face) — every sync overwrites those
fields on matched CIs. Non-hardware fields (owner, cost center, description,
business criticality, ...) are left untouched here; those are populated by
serviceops_core/cmdb_import.py (CSV/spreadsheet import), which in turn never
overwrites hardware fields on a netbox-sourced CI.
"""
import os
import re
import tempfile
from contextlib import nullcontext

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
    if record.get("mtu"):
        bits.append(f"MTU {record['mtu']}")
    mode = _first_attr(record, "mode", "label")
    if mode:
        bits.append(mode)
    untagged = _first_attr(record, "untagged_vlan", "display") or _first_attr(record, "untagged_vlan", "name")
    if untagged:
        bits.append(f"untagged {untagged}")
    tagged = [item.get("display") or item.get("name") for item in (record.get("tagged_vlans") or [])]
    tagged = [item for item in tagged if item]
    if tagged:
        bits.append(f"tagged {', '.join(tagged)}")
    cable = _first_attr(record, "cable", "label") or _first_attr(record, "cable", "display")
    if cable:
        bits.append(f"cable {cable}")
    if record.get("description"):
        bits.append(str(record["description"]).strip())
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
    bits = [value for value in (
        role,
        f"manufacturer {_first_attr(record, 'manufacturer', 'name')}" if _first_attr(record, 'manufacturer', 'name') else None,
        f"part {record.get('part_id')}" if record.get("part_id") else None,
        f"serial {record.get('serial')}" if record.get("serial") else None,
        f"asset {record.get('asset_tag')}" if record.get("asset_tag") else None,
    ) if value]
    return f"{label} ({', '.join(bits)})" if bits else label


def _format_component(record):
    label = record.get("name") or record.get("label") or "?"
    bits = []
    for value in (
        _first_attr(record, "type", "label"), record.get("label"),
        record.get("description"),
    ):
        if value and value != label:
            bits.append(str(value).strip())
    if record.get("enabled") is False:
        bits.append("disabled")
    return f"{label} ({', '.join(bits)})" if bits else label


def _format_virtual_disk(record):
    label = record.get("name") or "?"
    size = record.get("size")
    description = str(record.get("description") or "").strip()
    bits = [f"{size} MB" if size is not None else None, description or None]
    return f"{label} ({', '.join(value for value in bits if value)})" if any(bits) else label


def _format_ip(record):
    address = record.get("address") or "?"
    bits = []
    for value in (
        record.get("dns_name"), _first_attr(record, "status", "label"),
        _first_attr(record, "role", "label"), _first_attr(record, "vrf", "display"),
        record.get("description"),
    ):
        if value:
            bits.append(str(value).strip())
    return f"{address} ({', '.join(bits)})" if bits else address


# Per-device components pulled in bulk (one full paginated fetch per type,
# grouped by device id in memory) rather than one request per device -- a
# NetBox instance can have thousands of devices, so an N+1 fetch pattern
# here would make every sync prohibitively slow.
COMPONENT_ENDPOINTS = (
    ("/api/dcim/interfaces/", "Interfaces", _format_interface),
    ("/api/dcim/console-ports/", "Console Ports", _format_port),
    ("/api/dcim/power-ports/", "Power Ports", _format_power_port),
    ("/api/dcim/inventory-items/", "Inventory Items", _format_inventory_item),
    ("/api/dcim/modules/", "Modules", _format_component),
    ("/api/dcim/module-bays/", "Module Bays", _format_component),
    ("/api/dcim/device-bays/", "Device Bays", _format_component),
    ("/api/dcim/front-ports/", "Front Ports", _format_component),
    ("/api/dcim/rear-ports/", "Rear Ports", _format_component),
    ("/api/dcim/console-server-ports/", "Console Server Ports", _format_component),
    ("/api/dcim/power-outlets/", "Power Outlets", _format_component),
    ("/api/dcim/cooling-intakes/", "Cooling Intakes", _format_component),
    ("/api/dcim/cooling-outflows/", "Cooling Outflows", _format_component),
)

VM_COMPONENT_ENDPOINTS = (
    ("/api/virtualization/interfaces/", "Interfaces", _format_interface),
    ("/api/virtualization/virtual-disks/", "Virtual Disks", _format_virtual_disk),
)

OPERATIONAL_STATUS_MAP = {
    "active": "Operational",
    "offline": "Down",
    "planned": "Maintenance",
    "staged": "Maintenance",
    "failed": "Down",
    "inventory": "Maintenance",
    "decommissioning": "Maintenance",
}

LIFECYCLE_STATUS_MAP = {
    "active": "In Use",
    "offline": "In Use",
    "planned": "Planned",
    "staged": "Planned",
    "failed": "In Use",
    "inventory": "Planned",
    "decommissioning": "Retired",
}

# NetBox roles are administrator-defined functional labels, not a controlled
# CI-class vocabulary. Only well-known role terms are normalized; everything
# else remains visible as an attribute and lands in the neutral Device class.
ROLE_CLASS_TERMS = (
    (("pdu", "power distribution"), "PDU"),
    (("firewall",), "Firewall"),
    (("load balancer", "load-balancer", "loadbalancer"), "Load Balancer"),
    (("wireless", "access point", "wifi", "wlan"), "Wireless Access Point"),
    (("switch",), "Switch"),
    (("router",), "Router"),
    (("storage", "san", "nas"), "Storage"),
    (("server", "hypervisor", "compute"), "Server"),
)

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
        # NetBox v2 tokens (introduced in 4.5) use Bearer authentication;
        # legacy v1 tokens use Token. Supporting both keeps older supported
        # installations working while avoiding a forced deprecated token.
        "Authorization": f"{'Bearer' if token.startswith('nbt_') else 'Token'} {token}",
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
    response = session.get(url, params=params, timeout=15, allow_redirects=False)
    if getattr(response, "is_redirect", False):
        raise NetboxSyncError(f"NetBox unexpectedly redirected {path}; refusing to leave the configured host.")
    response.raise_for_status()
    return response.json()


def _paginate(session, base_url, path):
    params = {"limit": 100, "offset": 0}
    while True:
        payload = _get(session, base_url, path, params=params)
        results = payload.get("results", [])
        for result in results:
            yield result
        if not payload.get("next"):
            return
        # NetBox may cap a requested page below `limit`; advance by the rows
        # actually returned or records between the server-provided pages are
        # skipped.
        if not results:
            raise NetboxSyncError(f"NetBox returned an empty page with a next link for {path}.")
        params["offset"] += len(results)


def _fetch_all_components(session, base_url):
    """Fetches interfaces/console ports/power ports/inventory items for every
    device and groups the formatted summaries by device id. Each component
    type is fetched independently -- if the API token lacks permission for
    one (e.g. inventory items), that type is skipped rather than aborting
    the whole sync."""
    grouped = {}
    warnings = []
    for path, label, formatter in COMPONENT_ENDPOINTS:
        by_device = {}
        try:
            for record in _paginate(session, base_url, path):
                device_id = str(_first_attr(record, "device", "id") or "")
                if not device_id:
                    continue
                by_device.setdefault(device_id, []).append(formatter(record))
        except (requests.RequestException, NetboxSyncError) as error:
            warnings.append(f"{label} were not imported: {type(error).__name__}")
            continue
        for device_id, items in by_device.items():
            grouped.setdefault(device_id, {})[f"NetBox: {label}"] = "; ".join(items)
    return grouped, warnings


def _fetch_vm_components(session, base_url):
    grouped = {}
    warnings = []
    for path, label, formatter in VM_COMPONENT_ENDPOINTS:
        by_vm = {}
        try:
            for record in _paginate(session, base_url, path):
                vm_id = str(_first_attr(record, "virtual_machine", "id") or "")
                if vm_id:
                    by_vm.setdefault(vm_id, []).append(formatter(record))
        except (requests.RequestException, NetboxSyncError) as error:
            warnings.append(f"VM {label} were not imported: {type(error).__name__}")
            continue
        for vm_id, items in by_vm.items():
            grouped.setdefault(vm_id, {})[f"NetBox: {label}"] = "; ".join(items)
    return grouped, warnings


def _fetch_assigned_ip_addresses(session, base_url):
    devices, vms, warnings = {}, {}, []
    try:
        for record in _paginate(session, base_url, "/api/ipam/ip-addresses/"):
            assigned = record.get("assigned_object") or {}
            device_id = _first_attr(assigned, "device", "id")
            vm_id = _first_attr(assigned, "virtual_machine", "id")
            target = devices if device_id is not None else vms if vm_id is not None else None
            target_id = device_id if device_id is not None else vm_id
            if target is not None:
                target.setdefault(str(target_id), []).append(_format_ip(record))
    except (requests.RequestException, NetboxSyncError) as error:
        warnings.append(f"Assigned IP addresses were not imported: {type(error).__name__}")
    return (
        {key: {"NetBox: Assigned IP Addresses": "; ".join(values)} for key, values in devices.items()},
        {key: {"NetBox: Assigned IP Addresses": "; ".join(values)} for key, values in vms.items()},
        warnings,
    )


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


def _device_class(record):
    role = (_first_attr(record, "role", "slug") or _first_attr(record, "role", "name") or "").casefold()
    normalized = " ".join(re.findall(r"[a-z0-9]+", role))
    words = set(normalized.split())
    for terms, ci_class in ROLE_CLASS_TERMS:
        if any((term in words) if " " not in term else (term in normalized) for term in terms):
            return ci_class
    return "Device"


def _status_fields(record):
    value = (_first_attr(record, "status", "value") or "").casefold()
    return {
        "operational_status": OPERATIONAL_STATUS_MAP.get(value),
        "lifecycle_state": LIFECYCLE_STATUS_MAP.get(value),
    }


def _environment_from_custom_fields(record):
    custom_fields = record.get("custom_fields") or {}
    value = custom_fields.get("environment")
    if isinstance(value, dict):
        value = value.get("value") or value.get("label")
    normalized = str(value or "").strip().casefold().replace("_", "-")
    aliases = {
        "prod": "Production", "production": "Production",
        "stage": "Staging", "staging": "Staging", "preprod": "Staging",
        "pre-production": "Staging", "preproduction": "Staging",
        "dev": "Development", "development": "Development",
        "test": "Test", "testing": "Test", "qa": "Test", "uat": "Test",
    }
    return aliases.get(normalized)


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


def _map_device(record, rack_id_map=None):
    rack_id_map = rack_id_map or {}
    netbox_rack_id = _first_attr(record, "rack", "id")
    face_value = _first_attr(record, "face", "value")
    return {
        "name": record.get("name") or f"device-{record.get('id')}",
        "ci_class": _device_class(record),
        "serial_number": record.get("serial") or None,
        "vendor": _first_attr(record, "device_type", "manufacturer", "name"),
        "model": _first_attr(record, "device_type", "model"),
        "ip_address": _ip_of(record),
        "location": _location_of(record),
        **_status_fields(record),
        "environment": _environment_from_custom_fields(record),
        "netbox_id": f"dcim.device:{record['id']}",
        "legacy_netbox_id": str(record["id"]),
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
            ("Site Group", ("site", "group", "name")),
            ("Tenant", ("tenant", "name")),
            ("Tenant Group", ("tenant", "group", "name")),
            ("Role", ("role", "name")),
            ("Platform", ("platform", "name")),
            ("Status", ("status", "label")),
            ("Asset Tag", ("asset_tag",)),
            ("Airflow", ("airflow", "label")),
            ("Cooling Method", ("cooling_method", "label")),
            ("Latitude", ("latitude",)),
            ("Longitude", ("longitude",)),
            ("Parent Device", ("parent_device", "name")),
            ("Owner", ("owner", "name")),
            ("Description", ("description",)),
            ("Cluster", ("cluster", "name")),
            ("Virtual Chassis", ("virtual_chassis", "name")),
            ("Virtual Chassis Position", ("vc_position",)),
            ("Virtual Chassis Priority", ("vc_priority",)),
            ("Config Template", ("config_template", "name")),
            ("Config Context", ("config_context",)),
            ("Local Context Data", ("local_context_data",)),
            ("Created", ("created",)),
            ("Last Updated", ("last_updated",)),
        )),
    }


def _map_rack(record):
    return {
        "name": record.get("name") or f"rack-{record.get('id')}",
        "site": _first_attr(record, "site", "name") or "",
        "u_height": record.get("u_height") or 42,
        "netbox_id": f"dcim.rack:{record['id']}",
        "legacy_netbox_id": str(record["id"]),
        "attributes": _extra_attributes(record, fields=(
            ("Location", ("location", "name")),
            ("Rack Group", ("group", "name")),
            ("Tenant", ("tenant", "name")),
            ("Status", ("status", "label")),
            ("Role", ("role", "name")),
            ("Facility ID", ("facility_id",)),
            ("Serial Number", ("serial",)),
            ("Asset Tag", ("asset_tag",)),
            ("Rack Type", ("rack_type", "display")),
            ("Width", ("width", "label")),
            ("Starting Unit", ("starting_unit",)),
            ("Descending Units", ("desc_units",)),
            ("Airflow", ("airflow", "label")),
            ("Weight", ("weight",)),
            ("Maximum Weight", ("max_weight",)),
            ("Mounting Depth", ("mounting_depth",)),
            ("Description", ("description",)),
            ("Created", ("created",)),
            ("Last Updated", ("last_updated",)),
        )),
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
        rack = core_app.Rack.query.filter_by(
            tenant_id=tenant_id, external_source="netbox", external_id=mapped["legacy_netbox_id"],
        ).first()
    if not rack:
        rack = core_app.Rack.query.filter_by(tenant_id=tenant_id, name=mapped["name"]).first()
    if rack:
        rack.site = mapped["site"]
        rack.u_height = mapped["u_height"]
        rack.external_source = "netbox"
        rack.external_id = mapped["netbox_id"]
        rack.attributes = mapped.get("attributes") or {}
        summary["racks_updated"] += 1
    else:
        rack = core_app.Rack(
            tenant_id=tenant_id, name=mapped["name"], site=mapped["site"],
            u_height=mapped["u_height"], external_source="netbox", external_id=mapped["netbox_id"],
            attributes=mapped.get("attributes") or {},
        )
        db.session.add(rack)
        summary["racks_created"] += 1
    db.session.flush()
    return rack


def _map_vm(record):
    return {
        "name": record.get("name") or f"vm-{record.get('id')}",
        "ci_class": "Virtual Machine",
        "serial_number": None,
        "vendor": None,
        "model": None,
        "ip_address": _ip_of(record),
        "location": _location_of(record),
        **_status_fields(record),
        "environment": _environment_from_custom_fields(record),
        "netbox_id": f"virtualization.virtualmachine:{record['id']}",
        "legacy_netbox_id": str(record["id"]),
        "attributes": _extra_attributes(record, fields=(
            ("Tenant", ("tenant", "name")),
            ("Owner", ("owner", "name")),
            ("Role", ("role", "name")),
            ("Platform", ("platform", "name")),
            ("Type", ("type", "name")),
            ("Virtual Machine Type", ("virtual_machine_type", "name")),
            ("Site", ("site", "name")),
            ("Cluster", ("cluster", "name")),
            ("Host Device", ("device", "name")),
            ("vCPUs", ("vcpus",)),
            ("Memory (MB)", ("memory",)),
            ("Disk (MB)", ("disk",)),
            ("Serial Number", ("serial",)),
            ("Status", ("status", "label")),
            ("Start On Boot", ("start_on_boot", "label")),
            ("Description", ("description",)),
            ("Config Template", ("config_template", "name")),
            ("Config Context", ("config_context",)),
            ("Local Context Data", ("local_context_data",)),
            ("Created", ("created",)),
            ("Last Updated", ("last_updated",)),
        )),
    }


def _upsert(mapped, tenant_id, summary):
    import app as core_app
    from app import db

    ci = core_app.ConfigurationItem.query.filter_by(
        tenant_id=tenant_id, external_source="netbox", external_id=mapped["netbox_id"],
    ).first()
    if not ci:
        legacy = core_app.ConfigurationItem.query.filter_by(
            tenant_id=tenant_id, external_source="netbox", external_id=mapped["legacy_netbox_id"],
        ).first()
        # Safely migrate legacy untyped IDs only when the record identity also
        # agrees. Device and VM primary keys occupy independent NetBox tables.
        if legacy and (legacy.name == mapped["name"] or (
            mapped["serial_number"] and legacy.serial_number == mapped["serial_number"]
        )):
            ci = legacy
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
            setattr(ci, field, mapped.get(field))
        if mapped.get("operational_status"):
            ci.operational_status = mapped["operational_status"]
        if mapped.get("lifecycle_state"):
            ci.lifecycle_state = mapped["lifecycle_state"]
        if mapped.get("environment"):
            ci.environment = mapped["environment"]
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
            operational_status=mapped.get("operational_status") or "Degraded",
            lifecycle_state=mapped.get("lifecycle_state") or "In Use",
            environment=mapped.get("environment") or "Production",
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

    base_url = core_app.setting_value("NETBOX_BASE_URL", "").strip()
    token = core_app.setting_value("NETBOX_API_TOKEN", "").strip()
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
        "virtual_machines_seen": 0,
        "cis_created": 0,
        "cis_updated": 0,
        "cis_matched_by_serial": 0,
        "racks_created": 0,
        "racks_updated": 0,
        "errors": [],
        "warnings": [],
    }

    session = session_factory(base_url, token)
    record_transaction = nullcontext if dry_run else db.session.begin_nested
    try:
        rack_id_map = {}
        for record in _paginate(session, base_url, RACKS_PATH):
            counts_before = (summary["racks_created"], summary["racks_updated"])
            try:
                with record_transaction():
                    rack = _upsert_rack(_map_rack(record), tenant_id, summary)
                rack_id_map[str(record["id"])] = rack.id
            except Exception as error:  # noqa: BLE001 - isolate one bad record from the whole sync
                summary["racks_created"], summary["racks_updated"] = counts_before
                summary["errors"].append(f"rack {record.get('name', record.get('id'))}: {type(error).__name__}")
        devices = list(_paginate(session, base_url, DEVICES_PATH))
        components_by_device, component_warnings = _fetch_all_components(session, base_url) if devices else ({}, [])
        vm_components, vm_component_warnings = _fetch_vm_components(session, base_url)
        device_ips, vm_ips, ip_warnings = _fetch_assigned_ip_addresses(session, base_url)
        summary["warnings"].extend(component_warnings)
        summary["warnings"].extend(vm_component_warnings)
        summary["warnings"].extend(ip_warnings)
        for record in devices:
            summary["devices_seen"] += 1
            counts_before = (
                summary["cis_created"], summary["cis_updated"], summary["cis_matched_by_serial"],
            )
            try:
                with record_transaction():
                    mapped = _map_device(record, rack_id_map=rack_id_map)
                    mapped["attributes"].update(components_by_device.get(str(record["id"]), {}))
                    mapped["attributes"].update(device_ips.get(str(record["id"]), {}))
                    _upsert(mapped, tenant_id, summary)
            except Exception as error:  # noqa: BLE001 - isolate one bad record from the whole sync
                summary["cis_created"], summary["cis_updated"], summary["cis_matched_by_serial"] = counts_before
                summary["errors"].append(f"device {record.get('name', record.get('id'))}: {type(error).__name__}")
        for record in _paginate(session, base_url, VMS_PATH):
            summary["virtual_machines_seen"] += 1
            counts_before = (
                summary["cis_created"], summary["cis_updated"], summary["cis_matched_by_serial"],
            )
            try:
                with record_transaction():
                    mapped = _map_vm(record)
                    mapped["attributes"].update(vm_components.get(str(record["id"]), {}))
                    mapped["attributes"].update(vm_ips.get(str(record["id"]), {}))
                    _upsert(mapped, tenant_id, summary)
            except Exception as error:  # noqa: BLE001
                summary["cis_created"], summary["cis_updated"], summary["cis_matched_by_serial"] = counts_before
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
