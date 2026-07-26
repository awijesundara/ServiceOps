#!/usr/bin/env python3
"""Load an explicit, disposable all-team test fixture.

This is never called by application startup. Run only after intentionally
recreating a non-production database.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from werkzeug.security import generate_password_hash

from app import (
    Asset, CatalogItem, CatalogItemRouting, ConfigurationItem, DirectoryGroupMapping, GroupMember,
    Knowledge, PlatformSetting, ServiceOffering, SupportGroup, User, create_app, db,
)


TEAM_ACCOUNTS = {
    "CoreApps": ("coreapps", "coreapps"),
    "Database": ("db", "db"),
    "Network": ("network", "network"),
    "Windows": ("windows", "windows"),
    "Unix": ("unix", "unix"),
    "SSD": ("ssd", "ssd"),
}


def add_membership(group, user, role):
    membership = GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first()
    if membership:
        membership.role = role
    else:
        db.session.add(GroupMember(group_id=group.id, user_id=user.id, role=role))


def load_fixture():
    admin = User.query.filter_by(username="admin").one()
    admin.password_hash = generate_password_hash("admin")
    admin.name = "Temporary Test Administrator"

    ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
    service_desk = SupportGroup.query.filter_by(name="Service Desk").one()
    created = []
    for team_name, (username, password) in TEAM_ACCOUNTS.items():
        team = SupportGroup.query.filter_by(name=team_name).one()
        user = User(
            username=username,
            name=f"{team_name} Test User",
            email=f"{username}@test.invalid",
            password_hash=generate_password_hash(password),
            role="manager",
        )
        db.session.add(user)
        db.session.flush()
        team.manager_id = user.id
        add_membership(team, user, "manager")
        add_membership(ccb, user, "CCB approver")
        if team_name == "Windows":
            add_membership(service_desk, user, "member")
        db.session.add(DirectoryGroupMapping(
            directory_group=f"gg_{team_name.lower()}", support_group_id=team.id
        ))
        created.append(username)

    laptop = CatalogItem(
        name="Test laptop", category="Hardware",
        description="Disposable catalog item for end-to-end request testing.",
        delivery_days=1, approval_required=True,
    )
    software = CatalogItem(
        name="Test software access", category="Access",
        description="Disposable catalog item for fulfillment testing.",
        delivery_days=1, approval_required=False,
    )
    db.session.add_all([laptop, software])
    db.session.flush()
    windows = SupportGroup.query.filter_by(name="Windows").one()
    db.session.add_all([
        CatalogItemRouting(
            catalog_item_id=laptop.id, support_group_id=windows.id,
            updated_by_id=admin.id,
        ),
        CatalogItemRouting(
            catalog_item_id=software.id, support_group_id=windows.id,
            updated_by_id=admin.id,
        ),
    ])
    ci = ConfigurationItem(
        name="Test Business Service", ci_class="Business Application",
        environment="Test", owner_id=admin.id,
    )
    db.session.add(ci)
    db.session.add(Asset(
        asset_tag="TEST-0001", name="Disposable test laptop", asset_type="Laptop",
        status="In stock", serial_number="TEST-SERIAL-0001",
    ))
    db.session.add(Knowledge(
        title="ServiceOps test procedure", category="Testing",
        body="Temporary article used to verify knowledge search and article access.",
        author_id=admin.id,
    ))
    db.session.add(ServiceOffering(
        name="Temporary Test Service", owner_id=admin.id,
        support_group_id=service_desk.id, criticality="Low", status="Operational",
    ))
    db.session.merge(PlatformSetting(
        key="TEST_FIXTURE_ACTIVE", value="true", encrypted=False,
        updated_by_id=admin.id,
    ))
    db.session.commit()
    return created


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm-non-production", action="store_true", required=True)
    args = parser.parse_args()
    if not args.confirm_non_production:
        raise SystemExit("Explicit non-production confirmation is required.")
    app = create_app()
    with app.app_context():
        users = load_fixture()
        print("Temporary fixture loaded:", ", ".join(users))


if __name__ == "__main__":
    main()
