"""On-demand Snipe-IT asset inventory sync.

Pulls hardware assets from a Snipe-IT instance's REST API (/api/v1/hardware)
and upserts them into ConfigurationItem, with the same "test the connection,
preview, then import a reviewed preview" shape as serviceops_core/netbox_sync.py
and the same per-record error isolation.

Ownership between the inventory sources:
  * A CI that Snipe-IT created or adopted (external_source "snipeit") has its
    asset fields (SNIPEIT_OWNED_FIELDS: name, serial, manufacturer, model,
    location, purchase and warranty dates) refreshed on every sync.
  * A CI that NetBox owns (external_source "netbox") keeps NetBox as the
    source of truth for hardware and status. Snipe-IT only adds what NetBox
    does not track: purchase and warranty dates, the assigned person and its
    own "Snipe-IT: " attributes.
  * Operational and business fields (owning team, cost center, business
    criticality, description, ...) are never written here.

Snipe-IT's own extra data (asset tag, category, status label, company,
supplier, order number, cost, assignee, audit dates, custom fields, ...) is
kept in ConfigurationItem.attributes under a "Snipe-IT: " prefix, so a
re-sync refreshes exactly those keys and nothing a CSV import or NetBox
stored there.
"""
import html
import re
from contextlib import nullcontext
from datetime import date

import requests

from serviceops_core import ci_precedence, ci_sources, import_changes
from serviceops_core.netbox_sync import _close, _write_ca_bundle
from serviceops_core.localization import tr

HARDWARE_PATH = "/api/v1/hardware"
ATTRIBUTE_PREFIX = "Snipe-IT: "

# ConfigurationItem columns a Snipe-IT-owned CI takes from Snipe-IT on every
# sync (cmdb_import.SNIPEIT_OWNED_FIELDS mirrors this so a spreadsheet import
# never fights the sync over them).
SNIPEIT_OWNED_FIELDS = (
    "name", "serial_number", "vendor", "model", "location", "install_date", "warranty_expiry_date",
)

# Snipe-IT status labels are administrator-defined; their status_meta is the
# fixed vocabulary underneath them.
STATUS_META_MAP = {
    "deployed": ("Operational", "In Use"),
    "deployable": (None, "Planned"),
    "pending": ("Maintenance", "Planned"),
    "undeployable": ("Down", "Maintenance"),
    "archived": ("Retired", "Retired"),
}

# Snipe-IT categories are administrator-defined. Only well-known terms map to
# a CI class; everything else lands in the neutral Hardware Asset class and
# the category stays visible as an attribute.
CATEGORY_CLASS_TERMS = (
    (("laptop", "laptops", "notebook", "notebooks", "macbook"), "Laptop"),
    (("desktop", "desktops", "workstation", "workstations", "pc", "pcs"), "Desktop"),
    (("server", "servers"), "Server"),
    (("monitor", "monitors", "display", "displays"), "Monitor"),
    (("phone", "phones", "mobile", "smartphone", "smartphones", "tablet", "tablets", "ipad"), "Mobile Device"),
    (("printer", "printers"), "Printer"),
    (("firewall", "firewalls"), "Firewall"),
    (("switch", "switches"), "Switch"),
    (("router", "routers"), "Router"),
    (("access point", "access points", "wireless", "wifi"), "Wireless Access Point"),
    (("storage", "nas", "san"), "Storage"),
)

IP_FIELD_LABELS = {"ip", "ip address", "ipv4", "ipv4 address", "management ip", "primary ip"}

# Snipe-IT has no native rack, environment or cost-center fields, so
# organisations keep them in custom fields. A custom field whose name
# (lower-cased, punctuation ignored) is one of these fills the matching CMDB
# field instead of staying an attribute.
PLACEMENT_LABELS = {
    "rack": {"rack", "rack no", "rack number", "rack name", "rack id"},
    "rack_position": {"position", "rack position", "rack unit", "rack u", "u position", "start u", "starting u"},
    "rack_face": {"orientation", "rack face", "face", "rack side", "mounting side"},
    "rack_u_height": {"height", "u height", "rack height", "size u", "rack units", "units"},
    "environment": {"environment", "service environment", "server environment", "env"},
    "cost_center": {"cost center", "cost centre"},
}


class SnipeitSyncError(RuntimeError):
    """Raised for conditions that must abort the whole sync (e.g. not configured)."""


def _snipeit_session(base_url, token):
    """A requests.Session for the Snipe-IT API, isolated so tests can replace
    it. Certificate trust and egress follow the same rules as the NetBox
    session: SNIPEIT_CA_CERT first, SNIPEIT_TLS_INSECURE only as an explicit
    last resort, and the SNIPEIT proxy policy instead of process proxy
    variables."""
    import app as core_app

    session = requests.Session()
    proxies = core_app.resolve_component_proxies("SNIPEIT")
    if proxies:
        session.proxies.update(proxies)
    session.trust_env = False
    session.headers.update({
        # Without an explicit JSON Accept header Snipe-IT answers an
        # unauthenticated API call with its HTML login page.
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    ca_cert = core_app.setting_value("SNIPEIT_CA_CERT", "").strip()
    if ca_cert:
        session.verify = _write_ca_bundle(ca_cert)
    elif core_app.setting_bool("SNIPEIT_TLS_INSECURE"):
        session.verify = False
        from flask import current_app
        current_app.logger.warning(
            "Snipe-IT TLS certificate verification is disabled (SNIPEIT_TLS_INSECURE); "
            "configure SNIPEIT_CA_CERT instead."
        )
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


def normalize_base_url(url):
    """Administrators often paste the API root (https://snipe/api/v1) or a
    trailing slash; every request path already starts with /api/v1."""
    url = (url or "").strip().rstrip("/")
    for suffix in ("/api/v1", "/api"):
        if url.casefold().endswith(suffix):
            return url[:-len(suffix)]
    return url


def describe_request_error(error):
    """A plain-language cause for a failed Snipe-IT request, without echoing
    headers or the token."""
    response = getattr(error, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(error, requests.exceptions.SSLError):
        return ("Snipe-IT's TLS certificate is not trusted. Paste the issuing CA certificate into the Snipe-IT "
                "connection settings.")
    if isinstance(error, requests.exceptions.JSONDecodeError):
        return ("The Snipe-IT URL answered with something other than the Snipe-IT API (for example a login or "
                "proxy page). Check the base URL and any access proxy in front of Snipe-IT.")
    if status in (401, 403):
        return (f"Snipe-IT refused the API token (HTTP {status}). Check the token is valid, not expired, and "
                "that its user may view assets.")
    if status == 404:
        return ("No Snipe-IT API was found at this URL (HTTP 404). Use the Snipe-IT base address, "
                "e.g. https://snipeit.example.com.")
    if status == 429:
        return "Snipe-IT rate-limited the request (HTTP 429). Lower the batch size or raise API_THROTTLE_PER_MINUTE."
    if status:
        return f"Snipe-IT answered HTTP {status}."
    if isinstance(error, requests.exceptions.Timeout):
        return "Snipe-IT did not answer within 20 seconds."
    if isinstance(error, requests.exceptions.ConnectionError):
        return "Snipe-IT could not be reached. Check the URL, DNS, firewall and outbound proxy settings."
    return f"The Snipe-IT request failed ({type(error).__name__})."


def _get(session, base_url, path, params=None):
    response = session.get(base_url.rstrip("/") + path, params=params, timeout=20, allow_redirects=False)
    if getattr(response, "is_redirect", False):
        raise SnipeitSyncError(
            f"Snipe-IT redirected {path} instead of answering. This usually means the token was not accepted "
            "or the URL points at a login page; refusing to leave the configured host.")
    response.raise_for_status()
    payload = response.json()
    # Snipe-IT reports some failures as HTTP 200 with a status envelope.
    if isinstance(payload, dict) and payload.get("status") == "error":
        messages = payload.get("messages") or payload.get("message") or "unknown error"
        raise SnipeitSyncError(f"Snipe-IT reported an error for {path}: {_text(messages) or messages}")
    return payload


def _paginate(session, base_url, path, *, page_size=100, progress_callback=None, cancel_check=None):
    """Yield one bounded Snipe-IT page at a time, ordered by id so offsets stay
    stable while records are added during the sync."""
    page_size = max(10, min(int(page_size), 500))
    params = {"limit": page_size, "offset": 0, "sort": "id", "order": "asc"}
    while True:
        if cancel_check and cancel_check():
            raise SnipeitSyncError("Synchronization cancelled by an administrator.")
        payload = _get(session, base_url, path, params=params)
        rows = payload.get("rows") or []
        total = payload.get("total")
        for row in rows:
            yield row
        if progress_callback:
            progress_callback(path, len(rows), total)
        params["offset"] += len(rows)
        # Snipe-IT caps a page at its MAX_RESULTS; advance by what came back.
        if not rows or (isinstance(total, int) and params["offset"] >= total):
            return


def _label_key(label):
    return " ".join(re.findall(r"[a-z0-9]+", (label or "").casefold()))


def _environment(value):
    """A canonical environment from free text such as "JNX Internal - Dev",
    using the app's own aliases; None when no single environment is named."""
    import app as core_app

    text = (value or "").casefold()
    if "preprod" in text or "pre-prod" in text or "pre production" in text or "pre-production" in text:
        return "Staging"
    found = {core_app.ENVIRONMENT_ALIASES[word] for word in re.findall(r"[a-z]+", text)
             if word in core_app.ENVIRONMENT_ALIASES}
    return found.pop() if len(found) == 1 else None


def _placement(label, value):
    """(cmdb_field, parsed_value) for a recognised custom field, or None when
    the label is not recognised or the value cannot be parsed."""
    key = _label_key(label)
    field = next((name for name, labels in PLACEMENT_LABELS.items() if key in labels), None)
    if not field:
        return None
    if field == "rack_position":
        try:
            number = float(value.replace(",", "."))
        except ValueError:
            return None
        return (field, number) if 0 < number <= 100 else None
    if field == "rack_u_height":
        try:
            number = int(float(value))
        except ValueError:
            return None
        return (field, number) if 0 < number <= 60 else None
    if field == "rack_face":
        face = value.casefold()
        return (field, "front") if face.startswith("front") else (field, "rear") if face.startswith(
            ("rear", "back")) else None
    if field == "environment":
        environment = _environment(value)
        return (field, environment) if environment else None
    return (field, value[:160] if field == "rack" else value[:80])


def _rich_text(value):
    """Notes arrive as escaped inline HTML; keep their line breaks and drop
    the markup."""
    if value in (None, ""):
        return None
    text = html.unescape(str(value))

    def link(match):
        url, label = match.group(1).strip(), re.sub(r"<[^>]+>", "", match.group(2)).strip()
        return url if not label or label == url else f"{label} ({url})"

    # Keep where a link pointed: "ticket (https://…)" instead of "ticket".
    text = re.sub(r"(?is)<a\b[^>]*\bhref=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", link, text)
    text = re.sub(r"(?i)<br\s*/?>|</p>|</li>|</div>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line) or None


def _text(value):
    """Snipe-IT's API HTML-escapes free text ("R&amp;D"); store it readable."""
    if value in (None, ""):
        return None
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        value = "; ".join(f"{key}: {item}" for key, item in value.items())
    text = html.unescape(str(value)).strip()
    return text or None


def _nested(record, *keys):
    node = record
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _date(value):
    """Snipe-IT dates arrive as {"date": "YYYY-MM-DD", "formatted": ...} or a
    plain string; anything unparseable is treated as absent."""
    if isinstance(value, dict):
        value = value.get("date") or value.get("datetime")
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _datetime_text(value):
    if isinstance(value, dict):
        value = value.get("datetime") or value.get("date") or value.get("formatted")
    return _text(value)


def _singular(text):
    return (text or "").casefold().strip().removesuffix("s")


def redundant_attribute(name, value, ci):
    """True when a stored Snipe-IT attribute only repeats a CMDB field of
    `ci`. Used when displaying attributes saved before duplicates were
    dropped at import, and for values the CI already shows."""
    text = str(value or "").strip()
    if name in ("Asset ID", "Created"):
        return True
    if name == "Asset Name":
        return text.casefold() == (ci.name or "").casefold()
    if name == "Category":
        return _singular(text) == _singular(ci.ci_class)
    if name in ("Default Location", "Assigned To"):
        return text == (ci.location or "")
    if name == "Assigned To Type":
        attributes = ci.attributes or {}
        return text == "location" and attributes.get(f"{ATTRIBUTE_PREFIX}Assigned To", "") == (ci.location or "")
    parsed = _placement(name, text)
    if not parsed:
        return False
    field, parsed_value = parsed
    if field == "rack":
        return bool(ci.rack) and ci.rack.name.casefold() == str(parsed_value).casefold()
    return getattr(ci, field, None) == parsed_value


def category_class(category_name):
    normalized = " ".join(re.findall(r"[a-z0-9]+", (category_name or "").casefold()))
    words = set(normalized.split())
    for terms, ci_class in CATEGORY_CLASS_TERMS:
        if any((term in words) if " " not in term else (term in normalized) for term in terms):
            return ci_class
    return "Hardware Asset"


def _status_fields(record):
    meta = (_nested(record, "status_label", "status_meta") or "").casefold()
    operational, lifecycle = STATUS_META_MAP.get(meta, (None, None))
    return {"operational_status": operational, "lifecycle_state": lifecycle}


def _custom_fields(record):
    """{label: (value, field_format)} for every populated custom field."""
    fields = {}
    for label, spec in (record.get("custom_fields") or {}).items():
        if isinstance(spec, dict):
            value, field_format = spec.get("value"), (spec.get("field_format") or "")
        else:
            value, field_format = spec, ""
        value = _text(value)
        if value:
            fields[_text(label) or label] = (value, str(field_format).casefold())
    return fields


def _ip_from_custom_fields(custom_fields):
    for label, (value, field_format) in custom_fields.items():
        if label.casefold().strip() in IP_FIELD_LABELS or field_format in ("ip", "ipv4"):
            return value.split("/")[0]
    return None


def _assignee(record):
    assigned = record.get("assigned_to")
    if not isinstance(assigned, dict):
        return None
    name = _text(assigned.get("name")) or " ".join(
        part for part in (_text(assigned.get("first_name")), _text(assigned.get("last_name"))) if part) or None
    return {
        "type": (assigned.get("type") or "").casefold(),
        "name": name or _text(assigned.get("username")),
        "email": (_text(assigned.get("email")) or "").casefold() or None,
        "username": _text(assigned.get("username")),
    }


def map_asset(record, base_url=""):
    asset_id = record.get("id")
    if not isinstance(asset_id, int) or isinstance(asset_id, bool):
        raise ValueError(tr("Snipe-IT asset has no numeric id"))
    asset_tag = _text(record.get("asset_tag"))
    custom_fields = _custom_fields(record)
    assignee = _assignee(record)
    category = _text(_nested(record, "category", "name"))
    attributes = {}

    def add(label, value):
        if value not in (None, "", []):
            attributes[f"{ATTRIBUTE_PREFIX}{label}"] = value

    # Only data the CMDB fields do not already hold is kept as an attribute:
    # the asset ID is part of the record link, and a category, default
    # location or location assignee equal to the CI's class or location is
    # dropped (see redundant_attribute()).
    location = _text(_nested(record, "location", "name")) or _text(_nested(record, "rtd_location", "name"))
    ci_class = category_class(category)
    asset_name = _text(record.get("name"))
    add("Asset Name", asset_name)
    add("Asset Tag", asset_tag)
    if base_url:
        add("Record", f"{base_url.rstrip('/')}/hardware/{asset_id}")
    if category and _singular(category) != _singular(ci_class):
        add("Category", category)
    add("Status", _text(_nested(record, "status_label", "name")))
    add("Model Number", _text(record.get("model_number")))
    add("Company", _text(_nested(record, "company", "name")))
    add("Supplier", _text(_nested(record, "supplier", "name")))
    add("Order Number", _text(record.get("order_number")))
    add("Purchase Cost", _text(record.get("purchase_cost")))
    add("Book Value", _text(record.get("book_value")))
    add("Warranty", _text(record.get("warranty_months")))
    add("End of Life", _datetime_text(record.get("asset_eol_date") or record.get("eol")))
    default_location = _text(_nested(record, "rtd_location", "name"))
    if default_location != location:
        add("Default Location", default_location)
    if assignee and not (assignee["type"] == "location" and assignee["name"] == location):
        add("Assigned To", assignee["name"])
        add("Assigned To Type", assignee["type"] or None)
        add("Assigned To Email", assignee["email"])
    add("Last Checkout", _datetime_text(record.get("last_checkout")))
    add("Expected Checkin", _datetime_text(record.get("expected_checkin")))
    add("Last Audit", _datetime_text(record.get("last_audit_date")))
    add("Next Audit", _datetime_text(record.get("next_audit_date")))
    add("BYOD", "Yes" if record.get("byod") else None)
    add("Notes", _rich_text(record.get("notes")))
    add("Last Updated", _datetime_text(record.get("updated_at")))
    placement = {}
    for label, (value, _) in custom_fields.items():
        parsed = _placement(label, value)
        if parsed and parsed[0] not in placement:
            placement[parsed[0]] = parsed[1]
        else:
            add(label, value)

    return {
        "name": asset_name or asset_tag or f"asset-{asset_id}",
        "asset_tag": asset_tag,
        "ci_class": ci_class,
        "serial_number": _text(record.get("serial")),
        "vendor": _text(_nested(record, "manufacturer", "name")),
        "model": _text(_nested(record, "model", "name")),
        "ip_address": _ip_from_custom_fields(custom_fields),
        "location": location,
        "install_date": _date(record.get("purchase_date")),
        "warranty_expiry_date": _date(record.get("warranty_expires")),
        **_status_fields(record),
        "assignee": assignee,
        "placement": placement,
        "external_id": f"hardware:{asset_id}",
        "attributes": attributes,
    }


def _owner_id(assignee, tenant_id, user_cache):
    """The tenant user an asset is checked out to, matched by email."""
    if not assignee or assignee["type"] != "user" or not assignee["email"]:
        return None
    email = assignee["email"]
    if email not in user_cache:
        import app as core_app
        from sqlalchemy import func

        user = core_app.User.query.filter(
            core_app.User.tenant_id == tenant_id, func.lower(core_app.User.email) == email,
        ).first()
        user_cache[email] = user.id if user else None
    return user_cache[email]


def _unique_name(mapped, tenant_id, used_names):
    """CI names are unique per tenant, while Snipe-IT asset names often are not
    ("MacBook Pro"). A second asset with a taken name gets its asset tag
    appended rather than overwriting the first."""
    import app as core_app

    name = mapped["name"]
    taken = name.casefold() in used_names or core_app.ConfigurationItem.query.filter_by(
        tenant_id=tenant_id, name=name).first() is not None
    if taken:
        suffix = mapped["asset_tag"] or mapped["external_id"].split(":", 1)[1]
        name = f"{name} ({suffix})"[:160]
    return name


def _rack_id(name, location, tenant_id, summary, rack_cache):
    """The tenant rack with this name (case-insensitive), created on first
    use so the item appears in the rack elevation."""
    import app as core_app
    from app import db
    from sqlalchemy import func

    key = name.casefold()
    if key not in rack_cache:
        Rack = core_app.Rack
        rack = Rack.query.filter(Rack.tenant_id == tenant_id, func.lower(Rack.name) == key).first()
        if not rack:
            rack = Rack(tenant_id=tenant_id, name=name, site=(location or "")[:120], u_height=42,
                        external_source="snipeit", external_id=f"rack:{name}"[:120])
            db.session.add(rack)
            db.session.flush()
            summary["racks_created"] += 1
        rack_cache[key] = rack.id
    return rack_cache[key]


def _model_u_height(ci, tenant_id):
    """The U height other items of the same model already have (for example
    a NetBox-synced device of that model), so an asset Snipe-IT gives no
    height draws at its real size in the rack elevation."""
    import app as core_app
    from sqlalchemy import func

    if not ci.model:
        return None
    CI = core_app.ConfigurationItem
    conditions = [CI.tenant_id == tenant_id, func.lower(CI.model) == ci.model.casefold(),
                  CI.rack_u_height.isnot(None)]
    if ci.id:
        conditions.append(CI.id != ci.id)
    row = core_app.db.session.query(CI.rack_u_height, func.count(CI.id)).filter(
        *conditions,
    ).group_by(CI.rack_u_height).order_by(func.count(CI.id).desc()).first()
    return row[0] if row else None


def _set(ci, field, value, written, *, clear=False):
    """Write a Snipe-IT value. An empty value clears the field only when
    `clear` is set (Snipe-IT owns this item) and Snipe-IT set it before, so
    adopting an item never blanks what another source filled in."""
    if value not in (None, ""):
        setattr(ci, field, value)
        written.append(field)
    elif clear and (ci.field_sources or {}).get(field) == "snipeit":
        setattr(ci, field, None)
        written.append(field)


def _apply_placement(ci, mapped, tenant_id, summary, rack_cache, written, *, netbox_owned=False):
    """Fill rack placement, environment and cost center from recognised
    custom fields. Only values Snipe-IT actually holds are written; an
    organisation without such a custom field keeps whatever the CI has. On
    an item NetBox manages, rack placement and environment stay NetBox's."""
    placement = mapped.get("placement") or {}
    _set(ci, "cost_center", placement.get("cost_center"), written)
    if netbox_owned:
        return
    _set(ci, "environment", placement.get("environment"), written)
    if placement.get("rack"):
        ci.rack_id = _rack_id(placement["rack"], mapped["location"], tenant_id, summary, rack_cache)
        written.append("rack_id")
    for field in ("rack_position", "rack_u_height", "rack_face"):
        _set(ci, field, placement.get(field), written)
    if ci.rack_id and ci.rack_u_height is None:
        height = _model_u_height(ci, tenant_id)
        if height:
            ci.rack_u_height = height
            ci_sources.mark(ci, ["rack_u_height"], "inferred")


def _follows_snipeit_name(ci):
    """Whether the CI still carries the name Snipe-IT gave it. A hostname
    from NetBox, a spreadsheet or a person is never replaced by an asset
    name."""
    attributes = ci.attributes or {}
    previous = attributes.get(f"{ATTRIBUTE_PREFIX}Asset Name") or attributes.get(f"{ATTRIBUTE_PREFIX}Asset Tag")
    if not previous or (ci.field_sources or {}).get("name") not in (None, "snipeit"):
        return False
    name, previous = (ci.name or "").casefold(), previous.casefold()
    return name == previous or name.startswith(previous + " (")


def _upsert(mapped, tenant_id, summary, used_names, user_cache, rack_cache=None):
    rack_cache = {} if rack_cache is None else rack_cache
    import app as core_app
    from app import db

    CI = core_app.ConfigurationItem
    ci = CI.query.filter_by(tenant_id=tenant_id, external_source="snipeit",
                            external_id=mapped["external_id"]).first()
    matched_by_serial = False
    if not ci and mapped["serial_number"]:
        candidate = CI.query.filter_by(tenant_id=tenant_id, serial_number=mapped["serial_number"]).first()
        if candidate and candidate.external_source != "snipeit":
            ci, matched_by_serial = candidate, True
    if not ci:
        # Adopt a manual, CSV or NetBox CI of the same name, but never another
        # Snipe-IT asset that merely shares a generic name.
        candidate = CI.query.filter_by(tenant_id=tenant_id, name=mapped["name"]).first()
        if candidate and candidate.external_source != "snipeit":
            ci = candidate

    owner_id = _owner_id(mapped["assignee"], tenant_id, user_cache)
    if owner_id is None and mapped["assignee"] and mapped["assignee"]["type"] == "user":
        summary["assignees_unmatched"] += 1

    if ci:
        before = import_changes.snapshot(ci)
        # NetBox keeps hardware and status only while it outranks Snipe-IT.
        netbox_owned = ci.external_source == "netbox" and ci_precedence.outranks("netbox", "snipeit")
        written = []
        if netbox_owned:
            # NetBox stays the source of truth for hardware and status.
            for field in ("install_date", "warranty_expiry_date"):
                _set(ci, field, mapped[field], written)
            _set(ci, "owner_id", owner_id, written)
            summary["cis_enriched_netbox"] += 1
        else:
            if ci.external_source == "snipeit" and ci.name != mapped["name"] and _follows_snipeit_name(ci):
                ci.name = _unique_name(mapped, tenant_id, used_names)
                written.append("name")
            for field in SNIPEIT_OWNED_FIELDS:
                if field != "name":
                    _set(ci, field, mapped[field], written, clear=True)
            _set(ci, "ip_address", mapped["ip_address"], written)
            _set(ci, "operational_status", mapped["operational_status"], written)
            _set(ci, "lifecycle_state", mapped["lifecycle_state"], written)
            _set(ci, "ci_class", mapped["ci_class"], written)
            ci.external_source = "snipeit"
            ci.external_id = mapped["external_id"]
            ci.discovery_source = "API"
            # Snipe-IT owns assignment for its own assets: a returned asset
            # no longer has an owner.
            _set(ci, "owner_id", owner_id, written, clear=True)
        _apply_placement(ci, mapped, tenant_id, summary, rack_cache, written, netbox_owned=netbox_owned)
        ci_sources.mark(ci, written, "snipeit")
        preserved = {key: value for key, value in (ci.attributes or {}).items()
                     if not key.startswith(ATTRIBUTE_PREFIX)}
        ci.attributes = {**preserved, **mapped["attributes"]}
        ci_precedence.apply_field_mappings(ci, "snipeit")
        ci_precedence.arbitrate(ci, before, "snipeit", summary)
        used_names.add(ci.name.casefold())
        summary["cis_updated"] += 1
        if matched_by_serial:
            summary["cis_matched_by_serial"] += 1
        import_changes.record_update(summary, before, ci)
        return

    name = _unique_name(mapped, tenant_id, used_names)
    used_names.add(name.casefold())
    ci = CI(
        name=name, ci_class=mapped["ci_class"],
        operational_status=mapped["operational_status"] or "Operational",
        lifecycle_state=mapped["lifecycle_state"] or "In Use",
        environment="Production",
        serial_number=mapped["serial_number"], vendor=mapped["vendor"], model=mapped["model"],
        ip_address=mapped["ip_address"], location=mapped["location"],
        install_date=mapped["install_date"], warranty_expiry_date=mapped["warranty_expiry_date"],
        owner_id=owner_id, discovery_source="API",
        external_source="snipeit", external_id=mapped["external_id"],
        tenant_id=tenant_id, attributes=mapped["attributes"],
    )
    written = []
    _apply_placement(ci, mapped, tenant_id, summary, rack_cache, written)
    ci_sources.mark(ci, ["name", "ci_class", "operational_status", "lifecycle_state", "serial_number", "vendor",
                         "model", "ip_address", "location", "install_date", "warranty_expiry_date", "owner_id",
                         *written], "snipeit")
    ci_precedence.apply_field_mappings(ci, "snipeit")
    db.session.add(ci)
    summary["cis_created"] += 1
    import_changes.record_create(summary, ci)


def _configured_connection():
    """The validated Snipe-IT base URL and token, or SnipeitSyncError."""
    import app as core_app

    if not core_app.setting_bool("SNIPEIT_ENABLED"):
        raise SnipeitSyncError("Snipe-IT sync is not enabled; refusing to sync.")
    base_url = normalize_base_url(core_app.setting_value("SNIPEIT_BASE_URL", ""))
    token = core_app.setting_value("SNIPEIT_API_TOKEN", "").strip()
    if not base_url or not token:
        raise SnipeitSyncError("Snipe-IT base URL and API token must both be configured.")
    # Snipe-IT is an admin-configured integration that is usually self-hosted,
    # so private addresses are allowed; loopback, link-local and reserved
    # targets are not (same policy as NetBox).
    if not core_app.integration_endpoint_valid(base_url, allow_private_network=True):
        raise SnipeitSyncError("Snipe-IT base URL failed safety validation (must be an https host).")
    if not core_app.integration_endpoint_resolves_safely(base_url, allow_private_network=True):
        raise SnipeitSyncError("Snipe-IT base URL failed DNS safety validation.")
    return base_url, token


def _count(session, base_url, path):
    payload = _get(session, base_url, path, params={"limit": 1, "offset": 0})
    return int(payload.get("total") or 0)


PROBE_ENDPOINTS = (
    ("assets", "Hardware assets", HARDWARE_PATH, True),
    ("categories", "Categories", "/api/v1/categories", False),
    ("models", "Asset models", "/api/v1/models", False),
    ("locations", "Locations", "/api/v1/locations", False),
    ("status_labels", "Status labels", "/api/v1/statuslabels", False),
)


def probe_snipeit(tenant_id, session_factory=_snipeit_session):
    """Test the configured connection and describe what an import would see,
    without writing anything: which Snipe-IT user the token belongs to, what
    it may read and how much, how categories map to CI classes, how status
    labels map to CMDB status, and a small asset sample."""
    import app as core_app

    base_url, token = _configured_connection()
    report = {"base_url": base_url, "endpoints": [], "categories": [], "status_labels": [], "sample": [],
              "warnings": [], "egress": core_app.describe_component_egress("SNIPEIT")}
    session = session_factory(base_url, token)
    try:
        try:
            me = _get(session, base_url, "/api/v1/users/me")
        except requests.RequestException as error:
            code = getattr(getattr(error, "response", None), "status_code", None)
            if code != 404:
                raise SnipeitSyncError(describe_request_error(error)) from error
            me = {}
        report["token_user"] = _text(me.get("name")) or _text(me.get("username"))
        for key, label, path, required in PROBE_ENDPOINTS:
            row = {"key": key, "label": label, "required": required, "count": None, "readable": False}
            try:
                row["count"], row["readable"] = _count(session, base_url, path), True
            except (requests.RequestException, SnipeitSyncError) as error:
                code = getattr(getattr(error, "response", None), "status_code", None)
                row["problem"] = ("not permitted for this token" if code in (401, 403) else
                                  describe_request_error(error) if isinstance(error, requests.RequestException)
                                  else str(error))
            report["endpoints"].append(row)
        counts = {row["key"]: row["count"] for row in report["endpoints"]}
        if not report["endpoints"][0]["readable"]:
            raise SnipeitSyncError(
                "Snipe-IT answered but the token cannot list hardware assets "
                f"({report['endpoints'][0].get('problem')}). Give the token's user permission to view assets.")
        if not counts.get("assets"):
            report["warnings"].append(
                "The token sees no hardware assets. Either Snipe-IT is empty or the token's user is limited to "
                "a company with no assets; an import would change nothing.")
        try:
            for row in _get(session, base_url, "/api/v1/categories",
                            params={"limit": 200, "category_type": "asset"}).get("rows") or []:
                name = _text(row.get("name"))
                report["categories"].append({
                    "name": name, "assets": row.get("assets_count", row.get("item_count")),
                    "ci_class": category_class(name),
                })
        except (requests.RequestException, SnipeitSyncError):
            report["warnings"].append("Categories could not be read, so CI classes cannot be previewed here.")
        try:
            for row in _get(session, base_url, "/api/v1/statuslabels", params={"limit": 200}).get("rows") or []:
                # A deployable label reads "deployed" on an asset that is
                # checked out; the probe shows the label's own type.
                operational, lifecycle = STATUS_META_MAP.get((row.get("type") or "").casefold(), (None, None))
                report["status_labels"].append({
                    "name": _text(row.get("name")), "type": row.get("type"),
                    "operational_status": operational, "lifecycle_state": lifecycle,
                })
        except (requests.RequestException, SnipeitSyncError):
            report["warnings"].append("Status labels could not be read, so status mapping cannot be previewed.")
        if counts.get("assets"):
            unmatched = 0
            try:
                for record in _get(session, base_url, HARDWARE_PATH,
                                   params={"limit": 5, "offset": 0, "sort": "id", "order": "asc"}).get("rows") or []:
                    try:
                        mapped = map_asset(record)
                    except ValueError:
                        continue
                    owner_id = _owner_id(mapped["assignee"], tenant_id, {})
                    if mapped["assignee"] and mapped["assignee"]["type"] == "user" and not owner_id:
                        unmatched += 1
                    report["sample"].append({key: mapped.get(key) for key in (
                        "name", "asset_tag", "ci_class", "serial_number", "vendor", "model", "location",
                        "lifecycle_state")} | {
                        "rack": " / ".join(str(part) for part in (
                            mapped["placement"].get("rack"), mapped["placement"].get("rack_position"))
                            if part not in (None, "")) or None,
                        "environment": mapped["placement"].get("environment"),
                        "assigned_to": (mapped["assignee"] or {}).get("name"),
                        "owner_matched": bool(owner_id)})
            except (requests.RequestException, SnipeitSyncError) as error:
                detail = describe_request_error(error) if isinstance(error, requests.RequestException) else error
                report["warnings"].append(f"Sample assets could not be read: {detail}")
            if unmatched:
                report["warnings"].append(
                    f"{unmatched} sampled asset(s) are checked out to people with no ServiceOps account of the "
                    "same email. They are imported without an owner; the assignee is kept as an attribute.")
    finally:
        _close(session)
    cmdb = core_app.ConfigurationItem.query.filter_by(tenant_id=tenant_id)
    report["cmdb_total"] = cmdb.count()
    report["cmdb_from_snipeit"] = cmdb.filter_by(external_source="snipeit").count()
    report["ready"] = bool(counts.get("assets"))
    return report


def sync_from_snipeit(tenant_id, dry_run=False, session_factory=_snipeit_session,
                      *, page_size=100, progress_callback=None, cancel_check=None):
    """Pull hardware assets from Snipe-IT and upsert them into
    ConfigurationItem for ``tenant_id``. Fails closed on a missing tenant or
    configuration. A request that fails outright raises SnipeitSyncError and
    nothing is written; individual records are isolated as errors."""
    import app as core_app
    from app import db

    if not tenant_id or not isinstance(tenant_id, int):
        raise SnipeitSyncError("A valid integer tenant_id is required; refusing to sync.")
    tenant = db.session.get(core_app.Tenant, tenant_id)
    if not tenant or not tenant.active:
        raise SnipeitSyncError(f"Tenant {tenant_id} does not exist or is inactive; refusing to sync.")
    base_url, token = _configured_connection()

    summary = {
        "tenant_id": tenant_id, "dry_run": bool(dry_run), "assets_seen": 0,
        "cis_created": 0, "cis_updated": 0, "cis_matched_by_serial": 0, "cis_enriched_netbox": 0,
        "assignees_unmatched": 0, "racks_created": 0, "errors": [], "warnings": [],
        "app_version": core_app.display_version(),
    }
    import_changes.start(summary)
    session = session_factory(base_url, token)
    record_transaction = nullcontext if dry_run else db.session.begin_nested
    used_names, user_cache, seen_ids, rack_cache = set(), {}, set(), {}
    try:
        for record in _paginate(session, base_url, HARDWARE_PATH, page_size=page_size,
                                progress_callback=progress_callback, cancel_check=cancel_check):
            if record.get("id") in seen_ids:
                continue
            seen_ids.add(record.get("id"))
            summary["assets_seen"] += 1
            counts_before = (summary["cis_created"], summary["cis_updated"], summary["cis_matched_by_serial"],
                             summary["cis_enriched_netbox"], summary["assignees_unmatched"],
                             summary["racks_created"])
            racks_before = dict(rack_cache)
            changes_before = import_changes.checkpoint(summary)
            try:
                with record_transaction():
                    _upsert(map_asset(record, base_url), tenant_id, summary, used_names, user_cache, rack_cache)
            except Exception as error:  # noqa: BLE001 - isolate one bad record from the whole sync
                (summary["cis_created"], summary["cis_updated"], summary["cis_matched_by_serial"],
                 summary["cis_enriched_netbox"], summary["assignees_unmatched"],
                 summary["racks_created"]) = counts_before
                # A rack created inside the failed record was rolled back too.
                rack_cache.clear()
                rack_cache.update(racks_before)
                import_changes.restore(summary, changes_before)
                label = _text(record.get("asset_tag")) or _text(record.get("name")) or record.get("id")
                summary["errors"].append(f"asset {label}: {type(error).__name__}")
    except requests.RequestException as error:
        db.session.rollback()
        raise SnipeitSyncError(f"Nothing was imported. {describe_request_error(error)}") from error
    finally:
        _close(session)

    if not summary["assets_seen"]:
        summary["warnings"].append(
            "Snipe-IT returned no hardware assets to this token. Use Test connection to see what it can read.")
    if summary["assignees_unmatched"]:
        summary["warnings"].append(
            f"{summary['assignees_unmatched']} asset(s) are checked out to people with no ServiceOps account "
            "of the same email; they have no CI owner and keep the assignee as an attribute.")
    if cancel_check and cancel_check():
        db.session.rollback()
        raise SnipeitSyncError("Synchronization cancelled before commit.")
    if dry_run:
        db.session.rollback()
    else:
        db.session.commit()
    return summary
