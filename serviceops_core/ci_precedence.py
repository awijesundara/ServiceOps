"""Which source wins when two sources hold different values for one CI field.

Every importer (spreadsheet, Snipe-IT, NetBox) writes a CI as before; then
`arbitrate()` compares each field it changed with the source that set the
field previously (ConfigurationItem.field_sources). If that earlier source
ranks higher in CMDB_SOURCE_PRECEDENCE, its value is kept and the import's
value is reported as a conflict. A field nobody set before, or set by a
lower-ranked source, takes the new value, and a differing value it replaced
is reported too, so administrators can see every disagreement.

Administrators can also map a field of a remote system to a CMDB column
(CMDB_FIELD_MAPPINGS), for example Snipe-IT's "Cost Center" custom field to
cost_center. Mapped values go through the same precedence.
"""
import json

from serviceops_core import ci_sources

SOURCES = ("manual", "csv", "snipeit", "netbox")
DEFAULT_PRECEDENCE = ("manual", "csv", "snipeit", "netbox")
# Remote fields an administrator may map, and the CMDB columns they may fill.
MAPPABLE_SOURCES = {"netbox": "NetBox: ", "snipeit": "Snipe-IT: "}
MAPPABLE_FIELDS = {
    "description": "Description", "environment": "Environment", "location": "Location",
    "cost_center": "Cost center", "vendor": "Manufacturer", "model": "Model",
    "ip_address": "IP address", "serial_number": "Serial number",
}
CONFLICT_LIMIT = 200
VALUE_LIMIT = 80


def precedence():
    """Sources from highest to lowest priority. Unknown or missing entries
    fall back to the default order."""
    import app as core_app
    raw = core_app.setting_value("CMDB_SOURCE_PRECEDENCE", ",".join(DEFAULT_PRECEDENCE))
    order = [item.strip() for item in str(raw).split(",") if item.strip() in SOURCES]
    for source in DEFAULT_PRECEDENCE:
        if source not in order:
            order.append(source)
    return order


def rank(source, order=None):
    order = order or precedence()
    # Sources outside the list (e.g. "inferred") rank below every listed one.
    return order.index(source) if source in order else len(order)


def field_mappings():
    """{source: {cmdb_field: remote field name}} for the mappable sources."""
    import app as core_app
    try:
        raw = json.loads(core_app.setting_value("CMDB_FIELD_MAPPINGS", "{}"))
    except (TypeError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        source: {field: str(name) for field, name in (raw.get(source) or {}).items()
                 if field in MAPPABLE_FIELDS and str(name).strip()}
        for source in MAPPABLE_SOURCES if isinstance(raw.get(source), dict)
    }


def apply_field_mappings(ci, source, written=None):
    """Copy the remote fields an administrator mapped into their CMDB columns."""
    import app as core_app
    prefix = MAPPABLE_SOURCES.get(source)
    mapping = field_mappings().get(source) or {}
    if not prefix or not mapping:
        return
    attributes = ci.attributes or {}
    for field, remote in mapping.items():
        value = attributes.get(f"{prefix}{remote}")
        if value in (None, ""):
            continue
        value = str(value)[:255]
        if field == "environment":
            value = core_app.normalize_environment(value)
        setattr(ci, field, value)
        ci_sources.mark(ci, [field], source)
        if written is not None:
            written.append(field)


def _display(value):
    text = "" if value is None else str(value)
    return text if len(text) <= VALUE_LIMIT else text[:VALUE_LIMIT - 1] + "…"


def _record(summary, ci, field, kept_source, kept, other_source, other, outcome):
    summary["conflicts_total"] = summary.get("conflicts_total", 0) + 1
    conflicts = summary.setdefault("conflicts", [])
    if len(conflicts) < CONFLICT_LIMIT:
        conflicts.append({
            "name": ci.name, "field": field,
            "kept_source": ci_sources.SOURCE_LABELS.get(kept_source, kept_source or "—"), "kept": _display(kept),
            "other_source": ci_sources.SOURCE_LABELS.get(other_source, other_source), "other": _display(other),
            "outcome": outcome,
        })


def arbitrate(ci, before, source, summary):
    """Resolve each field `source` just changed on `ci` against the source
    that held it before. `before` is an import_changes.snapshot() taken
    before the import wrote anything."""
    previous_sources = before.get("_sources") or {}
    order = precedence()
    sources = dict(ci.field_sources or {})
    for field in ci_sources.FORM_FIELDS:
        if field not in before:
            continue
        old, new = before[field], getattr(ci, field, None)
        if old == new or old in (None, ""):
            continue
        old_source = previous_sources.get(field)
        if not old_source or old_source == source:
            continue
        if rank(old_source, order) < rank(source, order):
            setattr(ci, field, old)
            sources[field] = old_source
            _record(summary, ci, field, old_source, old, source, new, "kept")
        else:
            _record(summary, ci, field, source, new, old_source, old, "replaced")
    ci.field_sources = sources


def outranks(source, other):
    """True if `source` has higher priority than `other`."""
    order = precedence()
    return rank(source, order) < rank(other, order)
