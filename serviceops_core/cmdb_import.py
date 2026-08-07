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

Ownership in these inventory spreadsheets is a team ("UNIX", "Core apps"),
not a named person -- individual owners only make sense for
personally-assigned assets like laptops/phones, which this importer doesn't
handle. So an "Owner"/"System Owner" column resolves to ConfigurationItem's
support_group (team), auto-creating the SupportGroup by name if it doesn't
exist yet, rather than trying (and failing) to match it against User names.

Decommission state is read from whatever state/status column is present
(e.g. "State", "Status") independent of which sheet/tab the CSV came from --
the source tab name is never inspected, only the cell value on each row --
so a row is recognized as decommissioned regardless of which tab it was
exported from.

Any spreadsheet column that isn't recognized by COLUMN_ALIASES (e.g. "CPUs",
"RAM (GB)", "Builder", "iDRAC", "DNS", "Checker") is not dropped -- it's kept
verbatim, under its original header text, in ConfigurationItem.attributes
(a JSON column), so nothing the sheet contains is silently lost even though
this importer only has dedicated model columns for the common fields.
"""
import csv
import io

from app import parse_form_date

# Columns NetBox owns; matches netbox_sync.HARDWARE_FIELDS (kept separate to
# avoid a hard import-time dependency between the two sync modules).
NETBOX_OWNED_FIELDS = (
    "name", "serial_number", "vendor", "model", "ip_address", "location",
    "rack_id", "rack_position", "rack_u_height", "rack_face",
)

# Spreadsheet header -> ConfigurationItem field. Header matching is
# case-insensitive and tolerant of the sheet having many unrecognized extra
# columns (only keys present here are ever read).
COLUMN_ALIASES = {
    "host": "name",
    "hostname": "name",
    "hostname(fqdn)": "name",
    "name": "name",
    "desc of application": "description",
    "description": "description",
    "environment": "environment",
    "owner": "owning_team_name",
    "system owner": "owning_team_name",
    "owning team": "owning_team_name",
    "team": "owning_team_name",
    "serial number": "serial_number",
    "vendor": "vendor",
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
    "state": "state_raw",
    "status": "state_raw",
}

DATE_FIELDS = ("install_date", "warranty_expiry_date")

# Free-text state/status values (case-insensitive, punctuation-insensitive)
# that mean "this asset has been decommissioned", seen across the various
# tabs/exports of these inventory sheets ("Decomm'd", "Decommissioned",
# "Retired", ...). Anything not in this set is left alone -- we only ever
# act on an explicit decommission signal, never guess a "live" status from
# ambiguous text, so importing an Active-tab export can't accidentally
# downgrade a CI's real status.
DECOMMISSIONED_STATE_VALUES = {
    "decommd", "decommissioned", "decomm", "retired", "disposed",
    "end of life", "eol", "removed",
}


def _normalize_state(value):
    return "".join(ch for ch in value.casefold() if ch.isalnum() or ch == " ").strip()


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
    unmapped_headers = []
    for header in reader.fieldnames:
        field = COLUMN_ALIASES.get(header.strip().lower())
        if field:
            header_map[header] = field
        elif header.strip():
            unmapped_headers.append(header)
    rows = []
    for raw_row in reader:
        row = {}
        for header, field in header_map.items():
            value = (raw_row.get(header) or "").strip()
            if value:
                row[field] = value
        extra = {}
        for header in unmapped_headers:
            value = (raw_row.get(header) or "").strip()
            if value:
                extra[header.strip()] = value
        if extra:
            row["extra_attributes"] = extra
        rows.append(row)
    return rows


def _resolve_owning_team(team_name, tenant_id, created):
    """Finds the SupportGroup matching `team_name` (case-insensitive) for
    this tenant, auto-creating it if it doesn't exist yet. Inventory
    spreadsheets name a team ("UNIX", "Core apps"), not a person, so there's
    nothing to leave "unmatched" here -- every team name resolves to a
    group, created on first sight."""
    import app as core_app
    from app import db

    if not team_name:
        return None
    group = core_app.resolve_support_group_by_name(team_name, tenant_id)
    if not group:
        group = core_app.SupportGroup(name=team_name, tenant_id=tenant_id)
        db.session.add(group)
        db.session.flush()
        created.add(team_name)
    return group


def _apply_row(row, ci, is_netbox_owned):
    """Sets fields on `ci` from `row`, skipping NETBOX_OWNED_FIELDS when
    `is_netbox_owned` is True. Returns the count of fields that were skipped
    for that reason."""
    import app as core_app

    skipped = 0
    for field, value in row.items():
        if field in ("owning_team_name", "state_raw", "extra_attributes"):
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
        if field == "environment":
            value = core_app.normalize_environment(value)
        setattr(ci, field, value)

    state_raw = row.get("state_raw")
    if state_raw and _normalize_state(state_raw) in DECOMMISSIONED_STATE_VALUES:
        ci.operational_status = "Retired"
        ci.lifecycle_state = "Retired"

    extra = row.get("extra_attributes")
    if extra:
        ci.attributes = {**(ci.attributes or {}), **extra}

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
        "teams_created": [],
        "teams_merged": 0,
        "errors": [],
    }
    teams_created = set()

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

            team = _resolve_owning_team(row.get("owning_team_name"), tenant_id, teams_created)

            if ci:
                is_netbox_owned = ci.external_source == "netbox"
                summary["fields_skipped_netbox_owned"] += _apply_row(row, ci, is_netbox_owned)
                if team:
                    ci.support_group_id = team.id
                if ci.external_source is None:
                    ci.external_source = "csv"
                summary["cis_updated"] += 1
            else:
                ci = core_app.ConfigurationItem(
                    name=name, ci_class=row.get("ci_class", "Server"),
                    tenant_id=tenant_id, external_source="csv", discovery_source="Import",
                )
                _apply_row(row, ci, is_netbox_owned=False)
                if team:
                    ci.support_group_id = team.id
                db.session.add(ci)
                summary["cis_created"] += 1
        except Exception as error:  # noqa: BLE001 - isolate one bad row from the whole import
            summary["errors"].append(f"{name or '(unknown)'}: {type(error).__name__}")

    summary["teams_created"] = sorted(teams_created)

    if dry_run:
        db.session.rollback()
    else:
        # Sweeps up any spelling/formatting-variant duplicate teams (e.g.
        # this import created "Core apps" while "CoreApps" already existed
        # under a different owner name) so dropdowns never accumulate
        # near-duplicates from repeated imports.
        summary["teams_merged"] = core_app.find_and_merge_duplicate_groups(tenant_id)
        db.session.commit()

    return summary
