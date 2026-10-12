"""Numbers and dates read from forms. A blank or malformed value is the
caller's mistake: it answers 400 with the field named, never a 500.

    group_id = form_int("group_id", required=True)
    offering = form_int("service_offering_id")            # None when blank
    scale = form_int("font_scale", default=100, minimum=80, maximum=140)
"""
from datetime import datetime

from flask import abort, request

from serviceops_core.localization import tr


def _label(name):
    labels = {
        "group_id": tr("Team"), "subject_group_id": tr("Team"), "user_id": tr("User"),
        "member_id": tr("Member"), "manager_id": tr("Manager"), "owner_id": tr("Owner"),
        "assignee_id": tr("Assignee"), "tenant_id": tr("Tenant"), "ticket_id": tr("Ticket"),
        "job_id": tr("Job"), "schedule_id": tr("Schedule"), "window_id": tr("Window"),
        "link_id": tr("Link"), "alias_id": tr("Alias"), "approval_id": tr("Approval"),
        "category_id": tr("Category"), "subcategory_id": tr("Subcategory"),
        "catalog_item_id": tr("Catalog item"), "service_offering_id": tr("Service offering"),
        "default_service_offering_id": tr("Service offering"), "parent_id": tr("Parent CI"),
        "primary_ci_id": tr("Primary CI"), "ci_id": tr("Configuration item"), "source_id": tr("Source record"),
        "font_scale": tr("Text size"), "snmp_port": tr("SNMP port"),
        "schedule_interval_minutes": tr("Schedule interval"), "message_thread_id": tr("Message thread ID"),
        "escalation_group_id": tr("Escalation team"),
        "install_date": tr("Install date"), "warranty_expiry_date": tr("Warranty expiry date"),
    }
    return labels.get(name) or name.removesuffix("_id").replace("_", " ").capitalize()


def parse_int(raw, name, *, default=None, required=False, minimum=None, maximum=None):
    text = "" if raw is None else str(raw).strip()
    if not text:
        if required:
            abort(400, description=tr("Choose or enter {field}.", field=_label(name)))
        return default
    try:
        value = int(text)
    except ValueError:
        abort(400, description=tr("{field} must be a whole number.", field=_label(name)))
    if (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        abort(400, description=tr("{field} must be between {minimum} and {maximum}.",
                                  field=_label(name), minimum=minimum, maximum=maximum))
    return value


def form_int(name, **options):
    return parse_int(request.form.get(name), name, **options)


def parse_date(raw, name):
    """A YYYY-MM-DD form value as a date, None when blank."""
    text = "" if raw is None else str(raw).strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        abort(400, description=tr("{field} must be a date (YYYY-MM-DD).", field=_label(name)))
