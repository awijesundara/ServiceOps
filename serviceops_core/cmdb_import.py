"""CSV/spreadsheet import into ConfigurationItem.

Accepts CSV text (pasted, uploaded, or fetched from a published Google Sheet
CSV export — see app.py's cmdb_import route for how csv_text is obtained)
and upserts rows into ConfigurationItem, matched by serial number or exact
name.

NetBox (serviceops_core/netbox_sync.py) is the source of truth for hardware
fields. To avoid the two importers fighting over the same columns, this
module never overwrites NETBOX_OWNED_FIELDS on a CI whose external_source is
"netbox" -- it only fills in the operational/business fields NetBox doesn't
carry. CIs with no external_source (manual) or external_source == "csv" are
fully writable by this importer.
"""
import csv
import io

from app import parse_form_date

# Columns NetBox owns; matches netbox_sync.HARDWARE_FIELDS (kept separate to
# avoid a hard import-time dependency between the two sync modules).
NETBOX_OWNED_FIELDS = ("name", "serial_number", "vendor", "model", "ip_address", "location")

# Spreadsheet header -> ConfigurationItem field. Header matching is
# case-insensitive and tolerant of the sheet having many unrecognized extra
# columns (only keys present here are ever read).
COLUMN_ALIASES = {
    "host": "name",
    "hostname": "name",
    "name": "name",
    "desc of application": "description",
    "description": "description",
    "environment": "environment",
    "owner": "owner_name",
    "serial number": "serial_number",
    "vendor": "vendor",
    "builder": "vendor",
    "model": "model",
    "location": "location",
    "cost center": "cost_center",
    "business criticality": "business_criticality",
    "lifecycle state": "lifecycle_state",
    "install date": "install_date",
    "built date": "install_date",
    "shipped date": "install_date",
    "end of support": "warranty_expiry_date",
    "warranty expiry": "warranty_expiry_date",
    "ip address": "ip_address",
}

DATE_FIELDS = ("install_date", "warranty_expiry_date")


class CmdbImportError(RuntimeError):
    """Raised for conditions that must abort the whole import (e.g. no rows)."""


def parse_ci_rows(csv_text):
    """Parses CSV text into a list of dicts keyed by recognized
    ConfigurationItem field names, using COLUMN_ALIASES to map the sheet's
    actual (arbitrary) header row. Unrecognized columns are ignored."""
    if not csv_text or not csv_text.strip():
        raise CmdbImportError("No CSV data was provided.")
    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames:
        raise CmdbImportError("CSV data has no header row.")
    header_map = {}
    for header in reader.fieldnames:
        field = COLUMN_ALIASES.get(header.strip().lower())
        if field:
            header_map[header] = field
    rows = []
    for raw_row in reader:
        row = {}
        for header, field in header_map.items():
            value = (raw_row.get(header) or "").strip()
            if value:
                row[field] = value
        rows.append(row)
    return rows


def _resolve_owner(owner_name, tenant_id, unmatched):
    import app as core_app

    if not owner_name:
        return None
    user = core_app.User.query.filter(
        core_app.User.tenant_id == tenant_id,
        core_app.func.lower(core_app.User.name) == owner_name.casefold(),
    ).first()
    if not user:
        unmatched.add(owner_name)
    return user


def _apply_row(row, ci, is_netbox_owned):
    """Sets fields on `ci` from `row`, skipping NETBOX_OWNED_FIELDS when
    `is_netbox_owned` is True. Returns the count of fields that were skipped
    for that reason."""
    skipped = 0
    for field, value in row.items():
        if field == "owner_name":
            continue
        if is_netbox_owned and field in NETBOX_OWNED_FIELDS:
            skipped += 1
            continue
        if field in DATE_FIELDS:
            try:
                setattr(ci, field, parse_form_date(value))
            except ValueError:
                pass
            continue
        setattr(ci, field, value)
    return skipped


def import_ci_rows(rows, tenant_id, dry_run=False):
    """Upserts `rows` (as returned by parse_ci_rows) into ConfigurationItem
    for `tenant_id`. Matches existing CIs by serial number, then exact name.
    A row-level error never aborts the whole import."""
    import app as core_app
    from app import db

    if not tenant_id or not isinstance(tenant_id, int):
        raise CmdbImportError("A valid integer tenant_id is required; refusing to import.")

    summary = {
        "tenant_id": tenant_id,
        "dry_run": bool(dry_run),
        "rows_seen": len(rows),
        "cis_created": 0,
        "cis_updated": 0,
        "fields_skipped_netbox_owned": 0,
        "unmatched_owners": [],
        "errors": [],
    }
    unmatched_owners = set()

    for row in rows:
        name = row.get("name")
        if not name:
            summary["errors"].append("Row skipped: no hostname/name column value.")
            continue
        try:
            ci = None
            serial = row.get("serial_number")
            if serial:
                ci = core_app.ConfigurationItem.query.filter_by(
                    tenant_id=tenant_id, serial_number=serial,
                ).first()
            if not ci:
                ci = core_app.ConfigurationItem.query.filter_by(
                    tenant_id=tenant_id, name=name,
                ).first()

            owner = _resolve_owner(row.get("owner_name"), tenant_id, unmatched_owners)

            if ci:
                is_netbox_owned = ci.external_source == "netbox"
                summary["fields_skipped_netbox_owned"] += _apply_row(row, ci, is_netbox_owned)
                if owner:
                    ci.owner_id = owner.id
                if ci.external_source is None:
                    ci.external_source = "csv"
                summary["cis_updated"] += 1
            else:
                ci = core_app.ConfigurationItem(
                    name=name, ci_class=row.get("ci_class", "Server"),
                    tenant_id=tenant_id, external_source="csv", discovery_source="Import",
                )
                _apply_row(row, ci, is_netbox_owned=False)
                if owner:
                    ci.owner_id = owner.id
                db.session.add(ci)
                summary["cis_created"] += 1
        except Exception as error:  # noqa: BLE001 - isolate one bad row from the whole import
            summary["errors"].append(f"{name or '(unknown)'}: {type(error).__name__}")

    summary["unmatched_owners"] = sorted(unmatched_owners)

    if dry_run:
        db.session.rollback()
    else:
        db.session.commit()

    return summary
