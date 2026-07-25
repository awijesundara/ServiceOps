#!/usr/bin/env python3
"""Remove bootstrap demonstration data without breaking audit references.

Dry-run is the default. Use --apply only after taking a database backup.
"""

import argparse
import uuid

from app import (
    Asset, CatalogItem, CIRelationship, ConfigurationItem, GroupMember, Knowledge,
    RequestedItem, SupportGroup, User, create_app, db,
)
from werkzeug.security import generate_password_hash


DEMO_USERS = {
    "agent", "employee",
    "coreapps.manager", "database.manager", "network.manager",
    "windows.manager", "unix.manager", "ssd.manager",
    "coreapps.agent", "database.agent", "network.agent",
    "windows.agent", "unix.agent", "ssd.agent",
}
DEMO_CIS = {"Customer Portal", "Portal API", "Customer Database"}
DEMO_CATALOG = {
    "Laptop computer", "Software access", "Password reset", "New employee onboarding",
}


def cleanup(apply_changes=False):
    report = []
    users = User.query.filter(User.username.in_(DEMO_USERS)).all()
    demo_ids = {user.id for user in users}

    memberships = GroupMember.query.filter(GroupMember.user_id.in_(demo_ids)).all()
    report.append(f"group memberships removed: {len(memberships)}")
    for membership in memberships:
        db.session.delete(membership)

    groups = SupportGroup.query.filter(SupportGroup.manager_id.in_(demo_ids)).all()
    report.append(f"group manager assignments cleared: {len(groups)}")
    for group in groups:
        group.manager_id = None

    # Audit, comments and approvals are immutable evidence. Tombstoning retains
    # their foreign keys while eliminating credentials and demo-facing identity.
    report.append(f"bootstrap identities tombstoned: {len(users)}")
    for user in users:
        user.username = f"removed-bootstrap-{user.id}"
        user.name = "Removed bootstrap identity"
        user.email = f"removed-bootstrap-{user.id}@invalid.local"
        user.password_hash = generate_password_hash(uuid.uuid4().hex + uuid.uuid4().hex)
        user.active = False

    assets = Asset.query.filter_by(asset_tag="LAP-0001", serial_number="DEMO-001").all()
    knowledge = Knowledge.query.filter_by(title="Reset your password").all()
    report.extend((f"demo assets removed: {len(assets)}",
                   f"demo knowledge articles removed: {len(knowledge)}"))
    for row in assets + knowledge:
        db.session.delete(row)

    cis = ConfigurationItem.query.filter(ConfigurationItem.name.in_(DEMO_CIS)).all()
    ci_ids = {ci.id for ci in cis}
    relationships = CIRelationship.query.filter(
        db.or_(CIRelationship.parent_id.in_(ci_ids), CIRelationship.child_id.in_(ci_ids))
    ).all() if ci_ids else []
    report.extend((f"seeded CI relationships removed: {len(relationships)}",
                   f"seeded configuration items removed: {len(cis)}"))
    for row in relationships + cis:
        db.session.delete(row)

    catalog = CatalogItem.query.filter(CatalogItem.name.in_(DEMO_CATALOG)).all()
    removable = []
    retained = []
    for item in catalog:
        if RequestedItem.query.filter_by(catalog_item_id=item.id).first():
            item.active = False
            retained.append(item)
        else:
            removable.append(item)
            db.session.delete(item)
    report.append(f"unreferenced seeded catalog items removed: {len(removable)}")
    report.append(f"referenced seeded catalog items retired: {len(retained)}")

    if apply_changes:
        db.session.commit()
    else:
        db.session.rollback()
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true",
                        help="commit cleanup; default is a rolled-back dry run")
    args = parser.parse_args()
    app = create_app()
    with app.app_context():
        for line in cleanup(args.apply):
            print(line)
        print("result:", "committed" if args.apply else "dry-run rolled back")


if __name__ == "__main__":
    main()
