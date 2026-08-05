"""Removes tickets created by tools/stress_test.py, identified by their
title prefix ("Stress test ticket"). Run inside the app container after a
stress-test run so synthetic load-test data never lingers in a real
deployment (CLAUDE.md's production-only policy). Deletes every dependent
child row first (comments, attachments, checklist items, task links,
history, and the change-specific governance tables) so the ticket rows
themselves can be removed without violating a foreign key.
"""
import argparse
import sys

from app import (
    ChangeGovernance, ChangeOwnership, ChangeRevision, ChecklistItem, Comment,
    FileAttachment, MajorIncidentProfile, TaskCI, TaskHistory,
    TicketAssignmentGroup, Ticket, audit, create_app, db,
)

TITLE_PREFIX = "Stress test ticket"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        tickets = Ticket.query.filter(Ticket.title.ilike(f"{TITLE_PREFIX}%")).all()
        if not tickets:
            print("No stress-test tickets found.")
            return 0
        print(f"Found {len(tickets)} stress-test ticket(s).")
        if not args.confirm:
            print("Refusing deletion without --confirm.", file=sys.stderr)
            return 2
        ticket_ids = [ticket.id for ticket in tickets]
        for model in (
            Comment, ChecklistItem, FileAttachment, TicketAssignmentGroup,
            ChangeGovernance, ChangeOwnership, ChangeRevision, MajorIncidentProfile,
        ):
            rows = model.query.filter(model.ticket_id.in_(ticket_ids)).all()
            for row in rows:
                db.session.delete(row)
            print(f"  removed {len(rows)} {model.__name__} row(s)")
        task_ci_rows = TaskCI.query.filter(
            TaskCI.target_type == "ticket", TaskCI.target_id.in_(ticket_ids),
        ).all()
        for row in task_ci_rows:
            db.session.delete(row)
        print(f"  removed {len(task_ci_rows)} TaskCI row(s)")
        history_rows = TaskHistory.query.filter(
            TaskHistory.target_type == "ticket", TaskHistory.target_id.in_(ticket_ids),
        ).all()
        for row in history_rows:
            db.session.delete(row)
        print(f"  removed {len(history_rows)} TaskHistory row(s)")
        by_tenant = {}
        for ticket in tickets:
            by_tenant.setdefault(ticket.tenant_id, []).append(ticket)
        for tenant_id, tenant_tickets in by_tenant.items():
            numbers = [ticket.number for ticket in tenant_tickets]
            audit(
                "stress test cleanup", "bulk",
                f"removed {len(tenant_tickets)} stress-test ticket(s): "
                f"{numbers[:10]}{'...' if len(numbers) > 10 else ''}",
                tenant_id=tenant_id,
            )
        for ticket in tickets:
            db.session.delete(ticket)
        db.session.commit()
        print(f"Deleted {len(tickets)} stress-test ticket(s).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
