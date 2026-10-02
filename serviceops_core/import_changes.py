"""Field-level change records for CMDB imports.

Every importer (NetBox, Snipe-IT, spreadsheet) reports the same thing in its
summary so a preview can show exactly what an import would do, not only how
many records it touched:

  summary["changes"]        the first CHANGE_LIMIT planned or applied
                            changes, each {"action", "name", "fields"}
  summary["changes_total"]  how many changes there were in all
  summary["cis_unchanged"]  matched items that were already up to date

Values are rendered as short display strings when recorded, so the stored
job result stays small and never holds raw objects.
"""
from datetime import date, datetime

CHANGE_LIMIT = 200
VALUE_LIMIT = 80

TRACKED_FIELDS = (
    ("name", "Name"), ("ci_class", "Class"), ("serial_number", "Serial"), ("vendor", "Manufacturer"),
    ("model", "Model"), ("ip_address", "IP address"), ("location", "Location"),
    ("operational_status", "Status"), ("lifecycle_state", "Lifecycle"), ("environment", "Environment"),
    ("install_date", "Install date"), ("warranty_expiry_date", "Warranty expiry"), ("owner_id", "Owner"),
    ("support_group_id", "Owning team"), ("cost_center", "Cost center"),
    ("business_criticality", "Criticality"), ("description", "Description"), ("rack_id", "Rack"),
    ("rack_position", "Rack position"), ("rack_u_height", "Height (U)"), ("rack_face", "Rack face"),
)


def start(summary):
    summary.setdefault("changes", [])
    summary.setdefault("changes_total", 0)
    summary.setdefault("cis_unchanged", 0)


def snapshot(ci):
    values = {field: getattr(ci, field, None) for field, _ in TRACKED_FIELDS}
    values["attributes"] = dict(getattr(ci, "attributes", None) or {})
    return values


def _display(field, value, cache):
    if value in (None, ""):
        return "—"
    if field in ("owner_id", "support_group_id", "rack_id"):
        key = (field, value)
        if key not in cache:
            import app as core_app
            from app import db

            model = {"owner_id": core_app.User, "support_group_id": core_app.SupportGroup,
                     "rack_id": core_app.Rack}[field]
            row = db.session.get(model, value)
            cache[key] = getattr(row, "name", None) or f"#{value}"
        return cache[key]
    if isinstance(value, (date, datetime)):
        return value.isoformat()[:10]
    text = " ".join(str(value).split())
    return text if len(text) <= VALUE_LIMIT else text[:VALUE_LIMIT - 1] + "…"


def _append(summary, entry):
    summary["changes_total"] += 1
    if len(summary["changes"]) < CHANGE_LIMIT:
        summary["changes"].append(entry)


def record_create(summary, ci, cache=None):
    """A new item: list the identifying fields it will be created with."""
    start(summary)
    cache = {} if cache is None else cache
    fields = [
        {"label": label, "after": _display(field, getattr(ci, field, None), cache)}
        for field, label in TRACKED_FIELDS
        if field != "name" and getattr(ci, field, None) not in (None, "")
    ]
    _append(summary, {"action": "create", "name": ci.name, "fields": fields})


def record_update(summary, before, ci, cache=None):
    """A matched item: list only the fields that actually change. An item
    with no change is counted as unchanged and not listed."""
    start(summary)
    cache = {} if cache is None else cache
    fields = []
    for field, label in TRACKED_FIELDS:
        old, new = before.get(field), getattr(ci, field, None)
        if old != new and not (old in (None, "") and new in (None, "")):
            fields.append({"label": label, "before": _display(field, old, cache),
                           "after": _display(field, new, cache)})
    old_attributes, new_attributes = before.get("attributes") or {}, dict(ci.attributes or {})
    changed_keys = {key for key in set(old_attributes) | set(new_attributes)
                    if old_attributes.get(key) != new_attributes.get(key)}
    if changed_keys:
        count = len(changed_keys)
        fields.append({"label": "Attributes", "before": "",
                       "after": f"{count} source attribute{'' if count == 1 else 's'} changed"})
    if not fields:
        summary["cis_unchanged"] += 1
        return
    _append(summary, {"action": "update", "name": before.get("name") or ci.name, "fields": fields})


def checkpoint(summary):
    start(summary)
    return len(summary["changes"]), summary["changes_total"], summary["cis_unchanged"]


def restore(summary, saved):
    """Undo what one failed record added, alongside the caller's own counters."""
    length, total, unchanged = saved
    del summary["changes"][length:]
    summary["changes_total"], summary["cis_unchanged"] = total, unchanged
