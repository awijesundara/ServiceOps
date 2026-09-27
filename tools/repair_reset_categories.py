#!/usr/bin/env python3
"""Restore incident categories reset to "General" by the empty category picker.

From 5f86c1c (2026-09-26) until the 1.104.11 fix, the incident form's
category picker rendered with no options, so saving an incident from the web
changed its category (and subcategory) to "General". Ticket history kept the
original values. This restores them when all of these hold:

- the history row is a "category" change to "General" inside the bug window;
- the incident's category is still "General" and nothing changed it later;
- the original category (after migration 20260927_0106's relabels) is an
  active category of the incident's own tenant.

A subcategory reset in the same save is restored too, if the incident's
subcategory is still what that save left and the original subcategory
belongs to the restored category. Each restore is recorded in the incident's
history and the audit trail. Dry-run by default; pass --apply to commit.
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import (TaskHistory, Ticket, TicketCategory, TicketSubcategory, UNCATEGORISED, audit, create_app, db,
                 log_history)

JST = timezone(timedelta(hours=9))
BUG_WINDOW = (datetime(2026, 9, 26, 9, 0, tzinfo=JST), datetime(2026, 9, 27, 19, 0, tzinfo=JST))
RENAMES = {"Access": "Access / Identity", "Software": "Software / Application"}
SAME_SAVE = timedelta(seconds=5)
EVENT = "Category restored"


def as_utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def history_rows(ticket_id, field_name):
    return TaskHistory.query.filter_by(target_type="ticket", target_id=ticket_id, field_name=field_name) \
        .order_by(TaskHistory.created_at, TaskHistory.id).all()


def active_category(tenant_id, name):
    return TicketCategory.query.filter_by(tenant_id=tenant_id, name=name, active=True).first()


def plan_ticket(ticket):
    """Returns (category, subcategory or None, reason) for one incident, or a skip reason."""
    rows = history_rows(ticket.id, "category")
    resets = [row for row in rows if row.new_value == UNCATEGORISED and row.old_value
              and row.old_value != UNCATEGORISED
              and BUG_WINDOW[0] <= as_utc(row.created_at) <= BUG_WINDOW[1]]
    if not resets:
        return None
    reset = resets[-1]
    if any(row.created_at > reset.created_at or (row.created_at == reset.created_at and row.id > reset.id)
           for row in rows):
        return ("skip", "category changed again after the reset")
    if TaskHistory.query.filter_by(target_type="ticket", target_id=ticket.id, event=EVENT).first():
        return ("skip", "already restored")
    category = RENAMES.get(reset.old_value, reset.old_value)
    category_row = active_category(ticket.tenant_id, category)
    if not category_row:
        return ("skip", f"'{category}' is not an active category for this tenant")
    subcategory = None
    subcategory_rows = history_rows(ticket.id, "subcategory")
    last = subcategory_rows[-1] if subcategory_rows else None
    # Only when the reset save was also the last subcategory change.
    if last and last.old_value and abs(as_utc(last.created_at) - as_utc(reset.created_at)) <= SAME_SAVE \
            and last.new_value == (ticket.subcategory or "") \
            and TicketSubcategory.query.filter_by(category_id=category_row.id, name=last.old_value,
                                                  active=True).first():
        subcategory = last.old_value
    return ("restore", category, subcategory)


def repair(apply_changes=False):
    report = []
    candidates = Ticket.query.filter_by(kind="incident", category=UNCATEGORISED).order_by(Ticket.id).all()
    for ticket in candidates:
        plan = plan_ticket(ticket)
        if plan is None:
            continue
        if plan[0] == "skip":
            report.append(f"SKIP    {ticket.number} (tenant {ticket.tenant_id}): {plan[1]}")
            continue
        _, category, subcategory = plan
        old_subcategory = ticket.subcategory or ""
        report.append(f"RESTORE {ticket.number} (tenant {ticket.tenant_id}): category General -> {category}"
                      + (f", subcategory '{old_subcategory}' -> '{subcategory}'" if subcategory else ""))
        ticket.category = category
        log_history("ticket", ticket.id, EVENT, "category", UNCATEGORISED, category,
                    details="Reset to General by the empty category picker (fixed in 1.104.11); restored from history.")
        if subcategory:
            ticket.subcategory = subcategory
            log_history("ticket", ticket.id, EVENT, "subcategory", old_subcategory, subcategory)
        audit("repair", ticket.number, f"category restored to {category}", tenant_id=ticket.tenant_id)
    if apply_changes:
        db.session.commit()
    else:
        db.session.rollback()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true", help="commit the restores (default: dry run)")
    args = parser.parse_args()
    app = create_app()
    with app.app_context():
        report = repair(args.apply)
        for line in report:
            print(line)
        restored = sum(line.startswith("RESTORE") for line in report)
        print(f"{restored} incident(s) to restore, {len(report) - restored} skipped; "
              f"{'committed' if args.apply else 'dry run, rolled back'}")


if __name__ == "__main__":
    main()
