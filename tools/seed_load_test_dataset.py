"""Bulk-seeds a production-volume-scale ticket dataset for load-test
rehearsal only (B-071's "production-volume datasets" evidence gap).

Never called by application startup, and deliberately separate from
tools/load_demo_dataset.py (that one is a small, hand-curated set of
realistic-looking demo tickets meant to be browsed; this one is a fast
bulk insert meant purely to give query-planner/index behavior something
production-sized to work against under load). Run only against a disposable
database -- this is not incremental/idempotent and is not safe to run
against a database with real data.

Usage: python3 tools/seed_load_test_dataset.py --confirm-non-production --tickets 5000
"""
import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import (
    SupportGroup, Ticket, TicketAssignmentGroup, User, create_app, db, now, sequence_number,
)

RNG = random.Random(20260811)

KINDS = ["incident", "incident", "incident", "change", "request"]
PRIORITIES = ["P1", "P2", "P3", "P3", "P4", "P4"]
STATES_OPEN = ["New", "In Progress", "Pending"]
STATES_CLOSED = ["Resolved", "Closed"]
CATEGORIES = ["Software", "Hardware", "Network", "Infrastructure", "Access"]


def seed(ticket_count, batch_size=500):
    admin = User.query.filter_by(username="admin").one()
    requesters = User.query.filter(User.role == "requester").all() or [admin]
    agents = User.query.filter(User.role.in_(["agent", "manager"])).all() or [admin]
    groups = SupportGroup.query.filter_by(active=True).all()
    if not groups:
        raise SystemExit("No support groups found -- seed_itil() must have already run (fresh install does this automatically).")

    created = 0
    batch = []
    for i in range(ticket_count):
        kind = RNG.choice(KINDS)
        state = RNG.choice(STATES_OPEN if RNG.random() < 0.3 else STATES_CLOSED)
        requester = RNG.choice(requesters)
        assignee = RNG.choice(agents) if RNG.random() < 0.7 else None
        group = RNG.choice(groups)
        ticket = Ticket(
            number=sequence_number(Ticket, {"incident": "INC", "change": "CHG", "request": "REQ"}[kind]),
            kind=kind, title=f"Load test {kind} #{i}", description="Bulk load-test rehearsal data.",
            state=state, priority=RNG.choice(PRIORITIES),
            impact=RNG.choice(["Low", "Medium", "High"]), urgency=RNG.choice(["Low", "Medium", "High"]),
            category=RNG.choice(CATEGORIES), requester_id=requester.id,
            assignee_id=assignee.id if assignee else None,
            created_at=now(), updated_at=now(),
        )
        db.session.add(ticket)
        # sequence_number() looks up Ticket.id.desc() to pick the next
        # number -- it must be flushed (id assigned) before generating the
        # *next* ticket's number, or every ticket in an unflushed batch
        # would collide on the same number and violate the unique
        # constraint on Ticket.number.
        db.session.flush()
        batch.append((ticket, group.id))
        if len(batch) >= batch_size:
            for row, group_id in batch:
                db.session.add(TicketAssignmentGroup(ticket_id=row.id, group_id=group_id))
            db.session.commit()
            created += len(batch)
            batch = []
            print(f"...{created}/{ticket_count}")
    if batch:
        for row, group_id in batch:
            db.session.add(TicketAssignmentGroup(ticket_id=row.id, group_id=group_id))
        db.session.commit()
        created += len(batch)
    return created


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm-non-production", action="store_true", required=True)
    parser.add_argument("--tickets", type=int, default=5000)
    args = parser.parse_args()
    if not args.confirm_non_production:
        raise SystemExit("Explicit non-production confirmation is required.")
    if not 1 <= args.tickets <= 200000:
        raise SystemExit("--tickets must be between 1 and 200000.")
    app = create_app()
    with app.app_context():
        created = seed(args.tickets)
        print(f"Seeded {created} load-test tickets.")


if __name__ == "__main__":
    main()
