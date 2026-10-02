"""One configuration item, several sources: where each value came from.

A CI can be built from NetBox (hardware and placement), Snipe-IT (asset
management), a spreadsheet (operational data) and manual edits. This module
keeps the merge transparent:

  * ConfigurationItem.field_sources records which source last wrote each
    column, so the CI page can label every field with its origin.
  * Attributes a sync owns are namespaced ("NetBox: ", "Snipe-IT: ").
    group_attributes() presents them as read-only source groups without the
    prefix, and drops values that only repeat a CMDB field.
"""

SOURCE_LABELS = {
    "netbox": "NetBox",
    "snipeit": "Snipe-IT",
    "csv": "Spreadsheet",
    "manual": "Manual",
    "inferred": "Same model",
}

# Attribute namespaces owned by a sync. Values under these prefixes are
# rewritten by every sync, so the CI form shows them read-only.
SYNCED_PREFIXES = (("NetBox: ", "netbox"), ("Snipe-IT: ", "snipeit"))

# Columns the CI form edits and that can carry a source label.
FORM_FIELDS = (
    "name", "ci_class", "description", "environment", "operational_status", "lifecycle_state",
    "business_criticality", "ip_address", "serial_number", "vendor", "model", "location", "cost_center",
    "rack_id", "rack_position", "rack_u_height", "rack_face", "install_date", "warranty_expiry_date",
    "support_group_id", "owner_id",
)


def mark(ci, fields, source):
    """Record `source` as the origin of each field in `fields`. A listed
    field that is now empty has no origin any more."""
    sources = dict(ci.field_sources or {})
    for field in fields:
        if getattr(ci, field, None) not in (None, ""):
            sources[field] = source
        else:
            sources.pop(field, None)
    ci.field_sources = sources


def mark_changed(ci, before, source, fields=FORM_FIELDS):
    """Record `source` for every field whose value differs from `before`
    (a {field: value} snapshot). A cleared field loses its origin."""
    sources = dict(ci.field_sources or {})
    for field in fields:
        after = getattr(ci, field, None)
        if before.get(field) == after:
            continue
        if after in (None, ""):
            sources.pop(field, None)
        else:
            sources[field] = source
    ci.field_sources = sources


def label(ci, field):
    """The display name of the source of `field` on `ci`, or None."""
    return SOURCE_LABELS.get((ci.field_sources or {}).get(field)) if ci is not None else None


def is_synced_attribute(key):
    return any(key.startswith(prefix) for prefix, _ in SYNCED_PREFIXES)


def group_attributes(ci, hidden_keys=()):
    """Split a CI's attributes into read-only source groups and editable
    fields. Returns (groups, editable): groups is a list of
    {"source", "label", "link", "rows": [(name, value), ...]} and editable
    a {key: value} dict of spreadsheet and manual fields."""
    from serviceops_core.snipeit_sync import redundant_attribute

    groups, editable = {}, {}
    for key, value in (ci.attributes or {}).items():
        if key in hidden_keys:
            continue
        for prefix, source in SYNCED_PREFIXES:
            if key.startswith(prefix):
                name = key[len(prefix):]
                group = groups.setdefault(source, {
                    "source": source, "label": SOURCE_LABELS[source], "link": None, "rows": [],
                })
                if source == "snipeit" and name == "Record":
                    group["link"] = value
                    break
                if source == "snipeit" and redundant_attribute(name, value, ci):
                    break
                group["rows"].append((name, value))
                break
        else:
            editable[key] = value
    ordered = [groups[source] for _, source in SYNCED_PREFIXES if source in groups]
    return [group for group in ordered if group["rows"] or group["link"]], editable
