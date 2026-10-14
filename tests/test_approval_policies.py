"""B-460: configurable approval policies -- the engine, the administration
page, its authorization and tenant boundaries, and per-catalog-item policy
selection."""
import json

import pytest
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import HTTPException

from app import (ApprovalChain, CatalogItem, RequestedItem, SupportGroup, Tenant, User, db)
from serviceops_core import approval_policies as policies
from serviceops_models import ApprovalPolicy, ApprovalPolicyStage
from tests.test_app import app, client, login


def _admin():
    return User.query.filter_by(username="admin").one()


def _policy_with(tenant_id, applies_to, *stages, name="Test policy"):
    policies.ensure_defaults(tenant_id)
    policy = ApprovalPolicy(tenant_id=tenant_id, applies_to=applies_to, name=name, description="",
                            is_default=False, active=True, updated_at=policies.now())
    db.session.add(policy)
    db.session.flush()
    for position, fields in enumerate(stages):
        db.session.add(ApprovalPolicyStage(
            tenant_id=tenant_id, policy_id=policy.id, position=position, name=fields.pop("name", f"Stage {position}"),
            user_ids_json=json.dumps(fields.pop("user_ids", [])), include_manager=False,
            mode=fields.pop("mode", "any"), condition=fields.pop("condition", "always"),
            fallback=fields.pop("fallback", "none"), skip_duplicates=fields.pop("skip_duplicates", False), **fields))
    db.session.flush()
    db.session.refresh(policy)
    return policy


def test_defaults_are_created_once_per_tenant_and_are_editable_records(app):
    with app.app_context():
        tenant_id = _admin().tenant_id
        policies.ensure_defaults(tenant_id)
        policies.ensure_defaults(tenant_id)
        db.session.commit()
        for applies_to in policies.APPLIES_TO:
            defaults = ApprovalPolicy.query.filter_by(tenant_id=tenant_id, applies_to=applies_to,
                                                      is_default=True).all()
            assert len(defaults) == 1 and defaults[0].stages
        catalog = policies.default_policy(tenant_id, "catalog")
        assert [stage.source for stage in catalog.stages] == ["line_manager", "request_team_manager"]


def test_conditions_select_stages_by_change_type_and_ccb_need(app):
    with app.app_context():
        admin = _admin()
        policy = _policy_with(admin.tenant_id, "change",
                              dict(name="Always", source="users", user_ids=[admin.id]),
                              dict(name="Emergency only", source="users", user_ids=[admin.id], condition="emergency"),
                              dict(name="CCB", source="users", user_ids=[admin.id], condition="ccb_required"))
        names = lambda context: [stage["name"] for stage in policies.build_stages(policy, context)]
        assert names({"change_type": "Normal", "needs_ccb": False}) == ["Always"]
        assert names({"change_type": "Emergency", "needs_ccb": True}) == ["Always", "Emergency only", "CCB"]
        assert names({"change_type": "Standard", "needs_ccb": True}) == ["Always"]


def test_empty_stage_uses_its_fallback_or_refuses_to_start(app):
    with app.app_context():
        admin = _admin()
        empty = SupportGroup(name="Empty approvers", tenant_id=admin.tenant_id)
        db.session.add(empty)
        db.session.flush()
        fallback = _policy_with(admin.tenant_id, "catalog",
                                dict(name="Empty group", source="group", group_id=empty.id,
                                     fallback="first_administrator"), name="With fallback")
        assert policies.build_stages(fallback, {})[0]["approver_ids"] == [admin.id]
        strict = _policy_with(admin.tenant_id, "catalog",
                              dict(name="Empty group", source="group", group_id=empty.id), name="Strict")
        with pytest.raises(policies.ApprovalRouteError):
            policies.build_stages(strict, {})
        with pytest.raises(policies.ApprovalRouteError):
            policies.build_stages(None, {})


def test_skip_duplicates_drops_a_stage_repeating_earlier_approvers(app):
    with app.app_context():
        admin = _admin()
        policy = _policy_with(admin.tenant_id, "catalog",
                              dict(name="First", source="users", user_ids=[admin.id]),
                              dict(name="Repeat", source="users", user_ids=[admin.id], skip_duplicates=True),
                              dict(name="Kept", source="users", user_ids=[admin.id]))
        assert [stage["name"] for stage in policies.build_stages(policy, {})] == ["First", "Kept"]


def test_catalog_item_follows_its_chosen_policy(client, app):
    with app.app_context():
        admin = _admin()
        approver = User.query.filter_by(username="database.manager").first() or admin
        policy = _policy_with(admin.tenant_id, "catalog",
                              dict(name="Security office", source="users", user_ids=[approver.id]),
                              name="Security office only")
        item = CatalogItem(name="Firewall exception", category="Access", description="x", approval_required=True,
                           approval_policy_id=policy.id)
        db.session.add(item)
        db.session.commit()
        item_id, approver_id = item.id, approver.id
    login(client, "employee", "Employee123!")
    client.post(f"/catalog/{item_id}/order", data={"details": "Port 443"}, follow_redirects=True)
    with app.app_context():
        ritm = RequestedItem.query.filter_by(catalog_item_id=item_id).one()
        chain = ApprovalChain.query.filter_by(target_type="ritm", target_id=ritm.id).one()
        assert [gate.name for gate in chain.gates] == ["Security office"]
        assert [vote.approver_id for vote in chain.gates[0].votes] == [approver_id]


def test_inactive_chosen_policy_falls_back_to_the_default(app):
    with app.app_context():
        admin = _admin()
        policy = _policy_with(admin.tenant_id, "catalog", dict(source="users", user_ids=[admin.id]))
        policy.active = False
        item = CatalogItem(name="Fallback item", category="Access", description="x", approval_policy_id=policy.id,
                           tenant_id=admin.tenant_id)
        db.session.add(item)
        db.session.flush()
        assert policies.policy_for_catalog_item(item).is_default


def test_approval_policies_page_is_admin_only(client, app):
    login(client, "employee", "Employee123!")
    assert client.get("/admin/approval-policies").status_code in (302, 403)
    response = client.post("/admin/approval-policies", data={"action": "create_policy", "applies_to": "catalog",
                                                             "name": "Sneaky"})
    assert response.status_code in (302, 403)
    with app.app_context():
        assert not ApprovalPolicy.query.filter_by(name="Sneaky").first()


def test_admin_builds_a_policy_through_the_page(client, app):
    login(client)
    page = client.get("/admin/approval-policies")
    assert page.status_code == 200
    assert b"Line manager, then fulfilment team" in page.data and b"Change authorization" in page.data
    assert client.post("/admin/approval-policies", data={
        "action": "create_policy", "applies_to": "catalog", "name": "Two people", "description": "d",
    }).status_code == 302
    with app.app_context():
        admin = _admin()
        policy = ApprovalPolicy.query.filter_by(tenant_id=admin.tenant_id, name="Two people").one()
        policy_id, admin_id = policy.id, admin.id
    assert client.post("/admin/approval-policies", data={
        "action": "add_stage", "policy_id": policy_id, "name": "Named approvers", "source": "users",
        "user_ids": [admin_id], "mode": "all", "condition": "always", "fallback": "none",
    }).status_code == 302
    assert client.post("/admin/approval-policies", data={
        "action": "add_stage", "policy_id": policy_id, "name": "Admins", "source": "administrators",
        "mode": "any", "condition": "always", "fallback": "none",
    }).status_code == 302
    with app.app_context():
        stages = db.session.get(ApprovalPolicy, policy_id).stages
        assert [stage.name for stage in stages] == ["Named approvers", "Admins"]
        second_id = stages[1].id
    client.post("/admin/approval-policies", data={"action": "move_up", "policy_id": policy_id, "stage_id": second_id})
    assert client.post("/admin/approval-policies", data={"action": "set_default", "policy_id": policy_id}
                       ).status_code == 302
    with app.app_context():
        policy = db.session.get(ApprovalPolicy, policy_id)
        assert [stage.name for stage in policy.stages] == ["Admins", "Named approvers"]
        assert policy.is_default
        assert ApprovalPolicy.query.filter_by(tenant_id=policy.tenant_id, applies_to="catalog",
                                              is_default=True).count() == 1
    # The default cannot be deactivated or deleted.
    assert client.post("/admin/approval-policies", data={"action": "deactivate", "policy_id": policy_id}
                       ).status_code == 409
    assert client.post("/admin/approval-policies", data={"action": "delete_policy", "policy_id": policy_id}
                       ).status_code == 409


def test_stage_validation_rejects_sources_and_conditions_for_another_record_kind(client, app):
    login(client)
    with app.app_context():
        policy_id = policies.default_policy(_admin().tenant_id, "catalog").id
        db.session.commit()
    for data in ({"source": "owning_team_manager", "condition": "always"},
                 {"source": "administrators", "condition": "emergency"},
                 {"source": "users", "condition": "always"},
                 {"source": "group", "condition": "always", "group_id": "999999"}):
        response = client.post("/admin/approval-policies", data={
            "action": "add_stage", "policy_id": policy_id, "name": "Bad", "mode": "any", "fallback": "none", **data})
        assert response.status_code == 400, data


def test_deleting_a_policy_returns_its_items_to_the_default(app):
    with app.app_context():
        admin = _admin()
        policy = _policy_with(admin.tenant_id, "catalog", dict(source="administrators"))
        item = CatalogItem(name="Policy item", category="Access", description="x", approval_policy_id=policy.id,
                           tenant_id=admin.tenant_id)
        db.session.add(item)
        db.session.flush()
        policies.delete_policy(admin, policy)
        db.session.commit()
        assert db.session.get(CatalogItem, item.id).approval_policy_id is None


def test_policies_and_groups_of_another_tenant_are_out_of_reach(client, app):
    with app.app_context():
        other = Tenant(slug="policy-isolation", name="Policy isolation tenant")
        db.session.add(other)
        db.session.flush()
        foreign_group = SupportGroup(name="Foreign approvers", tenant_id=other.id)
        db.session.add(foreign_group)
        foreign = _policy_with(other.id, "catalog", dict(source="administrators"), name="Foreign")
        db.session.commit()
        foreign_id, foreign_group_id = foreign.id, foreign_group.id
        own_id = policies.default_policy(_admin().tenant_id, "catalog").id
        db.session.commit()
    login(client)
    assert client.post("/admin/approval-policies", data={"action": "set_default", "policy_id": foreign_id}
                       ).status_code == 404
    assert client.post("/admin/approval-policies", data={
        "action": "add_stage", "policy_id": own_id, "name": "Foreign group", "source": "group",
        "group_id": foreign_group_id, "mode": "any", "condition": "always", "fallback": "none",
    }).status_code == 400
    assert b"Foreign" not in client.get("/admin/approval-policies").data
    with app.app_context():
        item = CatalogItem(name="Isolated", category="Access", description="x", approval_policy_id=foreign_id,
                           tenant_id=_admin().tenant_id)
        db.session.add(item)
        db.session.flush()
        assert policies.policy_for_catalog_item(item).id != foreign_id


def test_policy_functions_refuse_non_administrators(app):
    with app.app_context():
        employee = User.query.filter_by(username="employee").one()
        with pytest.raises(HTTPException) as refused:
            policies.save_policy(employee, "catalog", "Mine")
        assert refused.value.code == 403
        policy = policies.default_policy(employee.tenant_id, "catalog")
        with pytest.raises(HTTPException):
            policies.save_stage(employee, policy, MultiDict({"name": "x", "source": "administrators"}))
