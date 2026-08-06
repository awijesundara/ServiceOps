"""Finds and merges duplicate ConfigurationItem rows (same hostname, same
tenant, different id) -- the class of duplicate this tool exists for is a
CI first created manually/via import (often with no ip_address recorded)
that agentless discovery later re-created as a second row at the IP it
actually found the device at, because reconcile_facts_into_cmdb used to
match only by ip_address (see network_discovery.py -- fixed to also match
by hostname, which stops *new* duplicates; this tool cleans up ones that
already exist).

Dry-run by default: prints every duplicate group and which record would
survive, with nothing written. Pass --confirm to actually merge.

For each duplicate group:
  - The survivor is whichever record has discovery_source == "Manual" (a
    human classified it, so it's the more trustworthy identity) if exactly
    one candidate qualifies; otherwise the oldest row (lowest id) is kept,
    on the theory that the first-created record is least likely to be the
    accidental duplicate.
  - Any field the survivor is missing (ip_address, vendor, model, ...) is
    backfilled from a losing record that has it -- "merged with known
    information," not just "delete the newer one and lose its data."
  - Every foreign key referencing a losing record (CIRelationship,
    ServiceOfferingCI, ChangeGovernance, TaskCI, ProblemProfile) is
    repointed to the survivor before the losing record is deleted, so
    nothing is silently orphaned. A repoint that would violate a unique
    constraint (the survivor already has the same relationship/link) is
    skipped rather than crashing -- the losing row's duplicate link is
    simply dropped along with the loser, since the survivor already has
    the same information.
"""
import argparse
import sys

from app import (
    ChangeGovernance, CIRelationship, ConfigurationItem, ProblemProfile,
    ServiceOfferingCI, TaskCI, Tenant, audit, create_app, db,
)
from sqlalchemy import func


MERGEABLE_FIELDS = (
    "ip_address", "vendor", "model", "serial_number", "location",
    "cost_center", "description", "install_date", "warranty_expiry_date",
    "support_group_id", "owner_id",
)


def find_duplicate_groups(tenant_id):
    names = db.session.query(func.lower(ConfigurationItem.name)).filter(
        ConfigurationItem.tenant_id == tenant_id,
    ).group_by(func.lower(ConfigurationItem.name)).having(func.count() > 1).all()
    groups = []
    for (lowered_name,) in names:
        rows = ConfigurationItem.query.filter(
            ConfigurationItem.tenant_id == tenant_id,
            func.lower(ConfigurationItem.name) == lowered_name,
        ).order_by(ConfigurationItem.id).all()
        groups.append(rows)
    return groups


def choose_survivor(rows):
    manual = [row for row in rows if row.discovery_source == "Manual"]
    if len(manual) == 1:
        return manual[0]
    return min(rows, key=lambda row: row.id)


def merge_group(rows, survivor):
    losers = [row for row in rows if row.id != survivor.id]
    for field in MERGEABLE_FIELDS:
        if getattr(survivor, field) in (None, ""):
            for loser in losers:
                value = getattr(loser, field)
                if value not in (None, ""):
                    setattr(survivor, field, value)
                    break
    if not survivor.attributes:
        for loser in losers:
            if loser.attributes:
                survivor.attributes = loser.attributes
                break

    loser_ids = [loser.id for loser in losers]

    for rel in CIRelationship.query.filter(
        db.or_(CIRelationship.parent_id.in_(loser_ids), CIRelationship.child_id.in_(loser_ids)),
    ).all():
        new_parent = survivor.id if rel.parent_id in loser_ids else rel.parent_id
        new_child = survivor.id if rel.child_id in loser_ids else rel.child_id
        if new_parent == new_child:
            db.session.delete(rel)
            continue
        collision = CIRelationship.query.filter_by(
            parent_id=new_parent, child_id=new_child, relationship_type=rel.relationship_type,
        ).filter(CIRelationship.id != rel.id).first()
        if collision:
            db.session.delete(rel)
        else:
            rel.parent_id, rel.child_id = new_parent, new_child

    for link in ServiceOfferingCI.query.filter(ServiceOfferingCI.ci_id.in_(loser_ids)).all():
        collision = ServiceOfferingCI.query.filter_by(
            service_offering_id=link.service_offering_id, ci_id=survivor.id,
        ).first()
        if collision:
            db.session.delete(link)
        else:
            link.ci_id = survivor.id

    for task_ci in TaskCI.query.filter(TaskCI.ci_id.in_(loser_ids)).all():
        collision = TaskCI.query.filter_by(
            target_type=task_ci.target_type, target_id=task_ci.target_id,
            ci_id=survivor.id, relationship_role=task_ci.relationship_role,
        ).first()
        if collision:
            db.session.delete(task_ci)
        else:
            task_ci.ci_id = survivor.id

    ChangeGovernance.query.filter(ChangeGovernance.ci_id.in_(loser_ids)).update(
        {"ci_id": survivor.id}, synchronize_session=False,
    )
    ProblemProfile.query.filter(ProblemProfile.primary_ci_id.in_(loser_ids)).update(
        {"primary_ci_id": survivor.id}, synchronize_session=False,
    )

    for loser in losers:
        db.session.delete(loser)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", default=None, help="Tenant slug; all active tenants if omitted.")
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        tenants = (
            [Tenant.query.filter_by(slug=args.tenant).one()] if args.tenant
            else Tenant.query.filter_by(active=True).all()
        )
        total_groups = 0
        for tenant in tenants:
            groups = find_duplicate_groups(tenant.id)
            if not groups:
                continue
            print(f"== {tenant.slug}: {len(groups)} duplicate hostname group(s) ==")
            for rows in groups:
                survivor = choose_survivor(rows)
                total_groups += 1
                print(f"  {rows[0].name}: survivor id={survivor.id} "
                      f"(class={survivor.ci_class}, source={survivor.discovery_source}); "
                      f"merging {[r.id for r in rows if r.id != survivor.id]}")
                if args.confirm:
                    merge_group(rows, survivor)
                    audit(
                        "merge", "CI duplicate",
                        f"{rows[0].name}: kept id={survivor.id}, merged {[r.id for r in rows if r.id != survivor.id]}",
                        tenant_id=tenant.id,
                    )
        if total_groups == 0:
            print("No duplicate CI hostnames found.")
            return 0
        if not args.confirm:
            print(f"\n{total_groups} group(s) would be merged. Re-run with --confirm to apply.")
            return 0
        db.session.commit()
        print(f"\nMerged {total_groups} group(s).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
