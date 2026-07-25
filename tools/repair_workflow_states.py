#!/usr/bin/env python3
"""Reconcile records that bypassed approval-derived workflow states."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import ApprovalChain, EnterpriseRecord, Ticket, create_app, db


def repair(apply_changes=False):
    changes = []
    for chain in ApprovalChain.query.filter_by(target_type="ticket").all():
        ticket = db.session.get(Ticket, chain.target_id)
        if not ticket:
            continue
        required = {
            "Running": "Awaiting Approval",
            "Rejected": "Rejected",
            "Cancelled": "Cancelled",
        }.get(chain.state)
        if required and ticket.state != required:
            changes.append(f"{ticket.number}: {ticket.state} -> {required}")
            ticket.state = required
    for record in EnterpriseRecord.query.all():
        pending = any(item.state == "Requested" for item in record.approvals)
        rejected = any(item.state == "Rejected" for item in record.approvals)
        required = "Awaiting Approval" if pending else ("Rejected" if rejected else None)
        if required and record.state != required:
            changes.append(f"{record.number}: {record.state} -> {required}")
            record.state = required
    if apply_changes:
        db.session.commit()
    else:
        db.session.rollback()
    return changes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    app = create_app()
    with app.app_context():
        changes = repair(args.apply)
        for change in changes:
            print(change)
        print(f"{len(changes)} record(s); {'committed' if args.apply else 'dry-run rolled back'}")


if __name__ == "__main__":
    main()
