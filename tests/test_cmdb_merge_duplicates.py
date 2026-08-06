from app import (
    ChangeGovernance, CIRelationship, ConfigurationItem, ServiceOffering,
    ServiceOfferingCI, TaskCI, Ticket, User, db, next_number,
)
from tests.test_app import app, client
from tools.cmdb_merge_duplicates import (
    choose_survivor, find_duplicate_groups, merge_group,
)


def test_choose_survivor_prefers_the_manual_record(app):
    with app.app_context():
        manual = ConfigurationItem(name="dup-01", ci_class="Server", discovery_source="Manual", tenant_id=1)
        discovered = ConfigurationItem(name="dup-01", ci_class="Device", discovery_source="SNMP Discovery", tenant_id=1)
        db.session.add_all([manual, discovered])
        db.session.commit()
        assert choose_survivor([manual, discovered]).id == manual.id
        assert choose_survivor([discovered, manual]).id == manual.id


def test_choose_survivor_falls_back_to_oldest_when_no_single_manual_record(app):
    with app.app_context():
        first = ConfigurationItem(name="dup-02", ci_class="Device", discovery_source="SNMP Discovery", tenant_id=1)
        db.session.add(first)
        db.session.commit()
        second = ConfigurationItem(name="dup-02", ci_class="Device", discovery_source="SNMP Discovery", tenant_id=1)
        db.session.add(second)
        db.session.commit()
        assert choose_survivor([first, second]).id == first.id
        assert choose_survivor([second, first]).id == first.id


def test_find_duplicate_groups_is_case_insensitive_and_tenant_scoped(app):
    with app.app_context():
        db.session.add_all([
            ConfigurationItem(name="Dup-Case", ci_class="Server", tenant_id=1),
            ConfigurationItem(name="dup-case", ci_class="Device", tenant_id=1),
            ConfigurationItem(name="dup-case", ci_class="Device", tenant_id=2),
            ConfigurationItem(name="unique-only", ci_class="Server", tenant_id=1),
        ])
        db.session.commit()
        groups = find_duplicate_groups(1)
        assert len(groups) == 1
        assert len(groups[0]) == 2


def test_merge_group_backfills_missing_fields_onto_survivor(app):
    with app.app_context():
        survivor = ConfigurationItem(
            name="merge-fields", ci_class="Server", discovery_source="Manual",
            tenant_id=1, vendor=None, ip_address=None,
        )
        loser = ConfigurationItem(
            name="merge-fields", ci_class="Device", discovery_source="SNMP Discovery",
            tenant_id=1, vendor="Arista Networks", ip_address="10.0.0.5",
            attributes={"sys_descr": "Arista EOS"},
        )
        db.session.add_all([survivor, loser])
        db.session.commit()
        merge_group([survivor, loser], survivor)
        db.session.commit()
        assert survivor.vendor == "Arista Networks"
        assert survivor.ip_address == "10.0.0.5"
        assert survivor.attributes == {"sys_descr": "Arista EOS"}
        assert ConfigurationItem.query.filter_by(id=loser.id).first() is None


def test_merge_group_reassigns_relationships_without_creating_duplicates(app):
    with app.app_context():
        survivor = ConfigurationItem(name="merge-rel-survivor", ci_class="Server", discovery_source="Manual", tenant_id=1)
        loser = ConfigurationItem(name="merge-rel-survivor", ci_class="Device", discovery_source="SNMP Discovery", tenant_id=1)
        other = ConfigurationItem(name="merge-rel-other", ci_class="Server", tenant_id=1)
        db.session.add_all([survivor, loser, other])
        db.session.commit()
        # loser has a relationship the survivor does NOT already have -- must be repointed.
        db.session.add(CIRelationship(
            tenant_id=1, parent_id=loser.id, child_id=other.id, relationship_type="Connects to",
        ))
        # survivor ALSO already has the identical relationship to `other` --
        # reassigning the loser's copy would violate the unique constraint,
        # so it must be dropped instead of repointed.
        db.session.add(CIRelationship(
            tenant_id=1, parent_id=survivor.id, child_id=other.id, relationship_type="Depends on",
        ))
        db.session.add(CIRelationship(
            tenant_id=1, parent_id=loser.id, child_id=other.id, relationship_type="Depends on",
        ))
        db.session.commit()

        merge_group([survivor, loser], survivor)
        db.session.commit()

        remaining = CIRelationship.query.filter(
            db.or_(CIRelationship.parent_id == survivor.id, CIRelationship.child_id == survivor.id),
        ).all()
        pairs = {(rel.parent_id, rel.child_id, rel.relationship_type) for rel in remaining}
        assert (survivor.id, other.id, "Connects to") in pairs
        assert (survivor.id, other.id, "Depends on") in pairs
        assert len(remaining) == 2  # the duplicate "Depends on" copy was dropped, not doubled


def test_merge_group_reassigns_task_ci_and_change_governance(app):
    with app.app_context():
        survivor = ConfigurationItem(name="merge-taskci", ci_class="Server", discovery_source="Manual", tenant_id=1)
        loser = ConfigurationItem(name="merge-taskci", ci_class="Device", discovery_source="SNMP Discovery", tenant_id=1)
        db.session.add_all([survivor, loser])
        db.session.commit()
        ticket = Ticket(
            number=next_number("change"), kind="change", title="Merge test change",
            description="x", tenant_id=1, requester_id=User.query.filter_by(username="admin").one().id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(TaskCI(target_type="ticket", target_id=ticket.id, ci_id=loser.id, relationship_role="Primary CI"))
        offering = ServiceOffering(name="Merge test service", owner_id=User.query.filter_by(username="admin").one().id, tenant_id=1)
        db.session.add(offering)
        db.session.flush()
        db.session.add(ServiceOfferingCI(service_offering_id=offering.id, ci_id=loser.id, tenant_id=1))
        db.session.add(ChangeGovernance(
            ticket_id=ticket.id, change_type="Standard", risk_score=0, impact="Low",
            implementation_plan="x", test_plan="x", backout_plan="x", ci_id=loser.id,
        ))
        db.session.commit()

        merge_group([survivor, loser], survivor)
        db.session.commit()

        assert TaskCI.query.filter_by(ci_id=survivor.id).count() == 1
        assert ServiceOfferingCI.query.filter_by(ci_id=survivor.id).count() == 1
        assert ChangeGovernance.query.filter_by(ci_id=survivor.id).count() == 1
