"""Configurable approval policies (B-460).

Every approval route in ServiceOps -- catalog requests, changes and
enterprise records -- comes from an ApprovalPolicy that administrators can
see and edit. Nothing about who approves is fixed in code: the routes
ServiceOps used before are created as ordinary default policies the first
time a tenant needs them, and can be changed, replaced or removed.

A policy is an ordered list of stages. Each stage names where its
approvers come from (a source), how many must approve (a mode), when it
applies (a condition) and who approves when the source finds nobody (a
fallback). Approvers are resolved when an approval starts and stored as
individual votes, so later changes to people or policies never rewrite a
decision in progress.
"""
import json

from flask import abort

import app as core
from serviceops_core.localization import tr
from serviceops_models import (ApprovalPolicy, ApprovalPolicyStage, CatalogItem, GroupMember, SupportGroup, User,
                               db, now)

APPLIES_TO = {
    "catalog": "Catalog requests",
    "change": "Changes",
    "enterprise": "Problems and other enterprise records",
}

# key: (label, record kinds it applies to, what it needs: group / users / None)
SOURCES = {
    "line_manager": ("Requester's line manager", {"catalog"}, None),
    "request_team_manager": ("Fulfilment team's manager (and its approval groups)", {"catalog"}, None),
    "request_team_members": ("Every member of the fulfilment team", {"catalog"}, None),
    "owning_team_manager": ("Owning team's manager (and its approval groups)", {"change"}, None),
    "ci_owner_team_managers": ("Each other team owning an affected CI: its manager", {"change"}, None),
    "service_coowner_team_managers": ("Each other team sharing an affected service: its manager", {"change"}, None),
    "task_team_managers": ("Each other team assigned a change task: its manager", {"change"}, None),
    "group": ("Members of a chosen group", {"catalog", "change", "enterprise"}, "group"),
    "authority": ("Groups linked to an approval authority", {"catalog", "change", "enterprise"}, "authority"),
    "users": ("Chosen people", {"catalog", "change", "enterprise"}, "users"),
    "administrators": ("Every active administrator", {"catalog", "change", "enterprise"}, None),
}
MODES = {
    "any": "Any one approver decides",
    "all": "Every approver must approve",
    "majority": "A majority must approve",
    "group_mode": "Use the group's own approval mode",
}
CONDITIONS = {
    "always": ("Always", {"catalog", "change", "enterprise"}),
    "standard": ("Standard changes only", {"change"}),
    "normal": ("Normal changes only", {"change"}),
    "emergency": ("Emergency changes only", {"change"}),
    "non_standard": ("Normal and emergency changes", {"change"}),
    "ccb_required": ("Non-standard changes that need CCB review", {"change"}),
    "ccb_required_normal": ("Normal changes that need CCB review", {"change"}),
    "ccb_required_emergency": ("Emergency changes that need CCB review", {"change"}),
}
FALLBACKS = {
    "none": "Nobody: the approval cannot start",
    "team_members": "The team's own active members (team stages)",
    "first_administrator": "The first active administrator",
    "all_administrators": "Any active administrator",
}
AUTHORITIES = {"ccb": "Change Control Board", "executive": "Executive approval", "enterprise": "Enterprise records"}


TEAM_SOURCES = {"request_team_manager", "owning_team_manager", "ci_owner_team_managers",
                "service_coowner_team_managers", "task_team_managers", "line_manager"}


class ApprovalRouteError(ValueError):
    """The policy cannot produce an approver for a stage."""


# --- defaults -------------------------------------------------------------------------

def _stage(position, name, source, **fields):
    return dict(position=position, name=name, source=source, **fields)


def _default_definitions(tenant_id):
    ccb = SupportGroup.query.filter_by(tenant_id=tenant_id, name="Change Control Board").first()
    executive = SupportGroup.query.filter_by(tenant_id=tenant_id, name="Executive Office").first()
    return [
        ("catalog", "Line manager, then fulfilment team", True,
         "The requester's line manager approves, then the manager of the team that fulfils the item "
         "(its catalog routing). A stage is skipped when it would ask the same person again.",
         [_stage(0, "Line manager approval", "line_manager", mode="all"),
          _stage(1, "Fulfilment team authorization", "request_team_manager", mode="any",
                 fallback="team_members")]),
        ("catalog", "Line manager only", False, "Only the requester's line manager approves.",
         [_stage(0, "Line manager approval", "line_manager", mode="all")]),
        ("change", "Change authorization", True,
         "The owning team's manager, the managers of other teams owning affected CIs, sharing an affected "
         "service or assigned a change task, then for non-standard changes that need CCB review one CCB "
         "approver and the executive.",
         [_stage(0, "{team} manager assessment", "owning_team_manager", mode="any", skip_duplicates=False),
          _stage(1, "{team} manager assessment (CI owner)", "ci_owner_team_managers", mode="any", skip_duplicates=False),
          _stage(2, "{team} manager assessment (service co-owner)", "service_coowner_team_managers", mode="any", skip_duplicates=False),
          _stage(3, "{team} manager approval (change task)", "task_team_managers", mode="any", skip_duplicates=False),
          _stage(4, "CCB authorization", "group", group_id=ccb.id if ccb else None, role_filter="CCB approver",
                 authority="ccb", mode="any", skip_duplicates=False, condition="ccb_required_normal"),
          _stage(5, "Emergency CCB authorization (expedited)", "group", group_id=ccb.id if ccb else None,
                 role_filter="CCB approver", authority="ccb", mode="any", skip_duplicates=False, condition="ccb_required_emergency"),
          _stage(6, "Executive (CEO) approval", "group", group_id=executive.id if executive else None,
                 role_filter="executive approver", include_manager=True, authority="executive",
                 mode="group_mode", skip_duplicates=False, condition="ccb_required")]),
        ("enterprise", "Enterprise record approval", True,
         "Anyone in the groups linked to the enterprise approval authority; if none are linked, the first "
         "active administrator. One decision settles it.",
         [_stage(0, "Enterprise record approval", "authority", authority="enterprise", mode="any", skip_duplicates=False,
                 fallback="first_administrator")]),
    ]


def ensure_defaults(tenant_id):
    """Create the default policies of each kind the tenant does not have yet."""
    have = {row[0] for row in db.session.query(ApprovalPolicy.applies_to).filter_by(tenant_id=tenant_id).distinct()}
    created = False
    for applies_to, name, is_default, description, stages in _default_definitions(tenant_id):
        if applies_to in have:
            continue
        policy = ApprovalPolicy(tenant_id=tenant_id, name=name, applies_to=applies_to, is_default=is_default,
                                description=description)
        db.session.add(policy)
        db.session.flush()
        for stage in stages:
            db.session.add(ApprovalPolicyStage(tenant_id=tenant_id, policy_id=policy.id, **stage))
        created = True
    if created:
        db.session.flush()


def policies(tenant_id, applies_to=None):
    ensure_defaults(tenant_id)
    query = ApprovalPolicy.query.filter_by(tenant_id=tenant_id)
    if applies_to:
        query = query.filter_by(applies_to=applies_to)
    return query.order_by(ApprovalPolicy.applies_to, ApprovalPolicy.is_default.desc(), ApprovalPolicy.name).all()


def default_policy(tenant_id, applies_to):
    ensure_defaults(tenant_id)
    return ApprovalPolicy.query.filter_by(tenant_id=tenant_id, applies_to=applies_to, is_default=True,
                                          active=True).first()


def policy_for_catalog_item(item):
    if item.approval_policy_id:
        policy = db.session.get(ApprovalPolicy, item.approval_policy_id)
        if policy and policy.active and policy.tenant_id == item.tenant_id and policy.applies_to == "catalog":
            return policy
    return default_policy(item.tenant_id, "catalog")


# --- resolving approvers ----------------------------------------------------------------------

def _active_ids(users, tenant_id):
    return {user.id for user in users if user and user.active and user.tenant_id == tenant_id}


def _team_manager_ids(group):
    """A team's manager assessment: its manager and the members of groups
    linked to it under the team_manager authority."""
    from serviceops_core.approval_groups import authority_user_ids
    ids = set(authority_user_ids(group.tenant_id, "team_manager", group.id))
    if group.manager and group.manager.active:
        ids.add(group.manager_id)
    return ids


def _group_ids(stage, tenant_id):
    group = stage.group
    if not group or not group.active or group.tenant_id != tenant_id:
        return set()
    members = GroupMember.query.filter_by(group_id=group.id).all()
    ids = {member.user_id for member in members
           if member.user and member.user.active and member.user.tenant_id == tenant_id
           and (not stage.role_filter or member.role == stage.role_filter)}
    if stage.include_manager and group.manager and group.manager.active:
        ids.add(group.manager_id)
    return ids


def _resolve(stage, context, tenant_id, covered_group_ids):
    """[(stage name, approver ids, group used for the mode)] for one policy
    stage; the per-team sources may produce several stages."""
    from serviceops_core.approval_groups import authority_user_ids
    source = stage.source
    name = stage.name
    if source == "line_manager":
        person = context.get("requested_for")
        manager = person.manager if person else None
        ids = set()
        if manager and manager.active and manager.tenant_id == person.tenant_id and manager.id != person.id:
            ids = {manager.id}
        return [(name, ids, None, tr("An active, same-tenant line manager must be assigned to the requested-for "
                                     "user before an approval-required item can be submitted."))]
    if source in ("request_team_manager", "request_team_members"):
        group = core.catalog_fulfillment_group(context["item"]) if context.get("item") else None
        if not group:
            return [(name, set(), None, tr("{item} has no fulfilment team.", item=context["item"].name))]
        ids = _team_manager_ids(group) if source == "request_team_manager" else (
            {m.user_id for m in group.members if m.user and m.user.active and m.user.tenant_id == tenant_id}
            | ({group.manager_id} if group.manager and group.manager.active else set()))
        return [(name.replace("{team}", group.name), ids, group,
                 tr("The {team} team needs an active manager or approval group.", team=group.name))]
    if source == "owning_team_manager":
        ownership = context["ticket"].change_ownership
        if not ownership:
            return [(name, set(), None, tr("The owning team requires an active manager or approval group."))]
        covered_group_ids.add(ownership.group_id)
        return [(name.replace("{team}", ownership.group.name), _team_manager_ids(ownership.group), ownership.group,
                 tr("The owning team requires an active manager or approval group."))]
    if source == "ci_owner_team_managers":
        rows = []
        groups = {}
        for ci in context.get("cis", []):
            if ci.support_group:
                groups.setdefault(ci.support_group.id, (ci.support_group, ci))
        for group_id in sorted(set(groups) - covered_group_ids):
            group, ci = groups[group_id]
            ids = _team_manager_ids(group) if group.active else set()
            rows.append((name.replace("{team}", group.name), ids, group,
                         tr("The {name} team (owner of {name2}) requires an active manager or approval group.",
                            name=group.name, name2=ci.name)))
            covered_group_ids.add(group_id)
        return rows
    if source == "service_coowner_team_managers":
        rows = []
        for group in context.get("coowner_groups", []):
            if group.id in covered_group_ids or not group.active:
                continue
            rows.append((name.replace("{team}", group.name), _team_manager_ids(group), group,
                         tr("The {name} team (co-owner of a service this CI backs) requires an active manager or "
                            "approval group.", name=group.name)))
            covered_group_ids.add(group.id)
        return rows
    if source == "task_team_managers":
        # A team doing work on the change approves it, unless it already approves
        # as the owning team, a CI owner or a service co-owner.
        rows = []
        for group in context.get("task_groups", []):
            if group.id in covered_group_ids:
                continue
            ids = _team_manager_ids(group) if group.active else set()
            rows.append((name.replace("{team}", group.name), ids, group,
                         tr("The {name} team (assigned a change task) requires an active manager or approval group.",
                            name=group.name)))
            covered_group_ids.add(group.id)
        return rows
    if source == "group":
        ids = _group_ids(stage, tenant_id)
        if stage.authority and (not stage.group or stage.group.active):
            ids |= set(authority_user_ids(tenant_id, stage.authority))
        group_name = stage.group.name if stage.group else tr("the chosen group")
        return [(name, ids, stage.group, tr("{stage}: nobody can approve. Add active members to {group} or link "
                                            "groups to its approval authority.", stage=name, group=group_name))]
    if source == "authority":
        ids = set(authority_user_ids(tenant_id, stage.authority)) if stage.authority else set()
        return [(name, ids, None, tr("{stage}: no groups with active members are linked to this approval "
                                     "authority.", stage=name))]
    if source == "users":
        try:
            wanted = [int(value) for value in json.loads(stage.user_ids_json or "[]")]
        except (TypeError, ValueError):
            wanted = []
        users = User.query.filter(User.id.in_(wanted or [0]), User.tenant_id == tenant_id).all()
        return [(name, _active_ids(users, tenant_id), None,
                 tr("{stage}: none of the chosen people is an active user.", stage=name))]
    if source == "administrators":
        users = User.query.filter(User.tenant_id == tenant_id, User.role.in_(["admin", "superadmin"]),
                                  User.active.is_(True)).all()
        return [(name, {user.id for user in users}, None, tr("{stage}: there is no active administrator.",
                                                              stage=name))]
    return [(name, set(), None, tr("{stage} has an unknown approver source.", stage=name))]


def _fallback_ids(stage, tenant_id, group=None):
    if stage.fallback == "team_members":
        if group is None or not group.active or group.tenant_id != tenant_id:
            return set()
        return {member.user_id for member in GroupMember.query.filter_by(group_id=group.id)
                if member.user and member.user.active and member.user.tenant_id == tenant_id}
    if stage.fallback in ("first_administrator", "all_administrators"):
        query = User.query.filter(User.tenant_id == tenant_id, User.role.in_(["admin", "superadmin"]),
                                  User.active.is_(True)).order_by(User.id)
        rows = query.limit(1).all() if stage.fallback == "first_administrator" else query.all()
        return {user.id for user in rows}
    return set()


def _applies(stage, context):
    condition = stage.condition or "always"
    if condition == "always":
        return True
    change_type = context.get("change_type")
    needs_ccb = context.get("needs_ccb", False)
    return {
        "standard": change_type == "Standard",
        "normal": change_type == "Normal",
        "emergency": change_type == "Emergency",
        "non_standard": change_type in ("Normal", "Emergency"),
        "ccb_required": change_type != "Standard" and needs_ccb,
        "ccb_required_normal": change_type == "Normal" and needs_ccb,
        "ccb_required_emergency": change_type == "Emergency" and needs_ccb,
    }.get(condition, False)


def task_team_route_error(tenant_id, group, covered_group_ids=()):
    """Why `group` cannot be given a change task under the default change
    policy (nobody would approve for it), or None. Checked before the task is
    created, so a refused task never exists."""
    policy = default_policy(tenant_id, "change")
    if policy is None or group.id in set(covered_group_ids):
        return None
    for stage in policy.stages:
        if stage.source == "task_team_managers":
            ids = _team_manager_ids(group) if group.active else set()
            if not ids and not _fallback_ids(stage, tenant_id, group):
                return tr("The {name} team (assigned a change task) requires an active manager or approval group.",
                          name=group.name)
    return None


def build_stages(policy, context, exclude_user_ids=()):
    """The approval chain stages a policy produces for one record:
    [{"name", "mode", "approver_ids"}]. Raises ApprovalRouteError when a
    stage finds nobody and has no fallback."""
    if policy is None:
        raise ApprovalRouteError(tr("No active approval policy is configured. An administrator can set one up "
                                    "under Approval policies."))
    tenant_id = policy.tenant_id
    built, covered = [], set()
    for stage in policy.stages:
        if not _applies(stage, context):
            continue
        for name, ids, group, error in _resolve(stage, context, tenant_id, covered):
            ids = set(ids) - set(exclude_user_ids)
            if not ids:
                # The fallback may include an excluded person (an administrator
                # approving their own record when nobody else can).
                ids = _fallback_ids(stage, tenant_id, group)
            if not ids:
                raise ApprovalRouteError(error)
            if stage.skip_duplicates and any(set(previous["approver_ids"]) == ids for previous in built):
                continue
            mode = stage.mode
            if mode == "group_mode":
                mode = group.approval_mode if group is not None and group.approval_mode in ("all", "any") else "all"
            if mode not in ("all", "any", "majority"):
                mode = "any"
            if stage.source in TEAM_SOURCES and len(ids) == 1:
                mode = "all"  # a team's sole manager simply approves
            built.append({"name": name, "mode": mode, "approver_ids": sorted(ids)})
    if not built:
        raise ApprovalRouteError(tr("The approval policy {name} has no stage that applies here.", name=policy.name))
    return built


# --- administration -------------------------------------------------------------------------------

def _require_admin(user):
    if not core.role_at_least(user.effective_role, "admin"):
        abort(403, description=tr("Only administrators can change approval policies."))


def policy_or_404(tenant_id, policy_id):
    policy = ApprovalPolicy.query.filter_by(id=policy_id, tenant_id=tenant_id).first()
    if not policy:
        abort(404)
    return policy


def save_policy(actor, applies_to, name, description="", policy=None):
    _require_admin(actor)
    if applies_to not in APPLIES_TO:
        abort(400, description=tr("Choose what the policy applies to."))
    name = (name or "").strip()
    if not 0 < len(name) <= 120:
        abort(400, description=tr("A policy name has 1 to 120 characters."))
    clash = ApprovalPolicy.query.filter(ApprovalPolicy.tenant_id == actor.tenant_id,
                                        ApprovalPolicy.applies_to == applies_to,
                                        db.func.lower(ApprovalPolicy.name) == name.lower()).first()
    if clash and (policy is None or clash.id != policy.id):
        abort(409, description=tr("A policy called {name} already exists.", name=name))
    if policy is None:
        policy = ApprovalPolicy(tenant_id=actor.tenant_id, applies_to=applies_to)
        db.session.add(policy)
    policy.name, policy.description = name, (description or "").strip()[:5000]
    policy.updated_by_id, policy.updated_at = actor.id, now()
    db.session.flush()
    core.audit("approval policy saved", name, f"applies to {applies_to}", user_id=actor.id, tenant_id=actor.tenant_id)
    return policy


def set_default(actor, policy):
    _require_admin(actor)
    if not policy.active:
        abort(409, description=tr("Activate the policy before making it the default."))
    if not policy.stages:
        abort(409, description=tr("Add at least one stage before making the policy the default."))
    ApprovalPolicy.query.filter_by(tenant_id=policy.tenant_id, applies_to=policy.applies_to).update(
        {"is_default": False}, synchronize_session=False)
    policy.is_default = True
    core.audit("approval policy default", policy.name, policy.applies_to, user_id=actor.id,
               tenant_id=actor.tenant_id)


def set_active(actor, policy, active):
    _require_admin(actor)
    if not active and policy.is_default:
        abort(409, description=tr("Choose another default before deactivating this policy."))
    policy.active = bool(active)
    core.audit("approval policy activated" if active else "approval policy deactivated", policy.name, "",
               user_id=actor.id, tenant_id=actor.tenant_id)


def delete_policy(actor, policy):
    _require_admin(actor)
    if policy.is_default:
        abort(409, description=tr("Choose another default before deleting this policy."))
    CatalogItem.query.filter_by(approval_policy_id=policy.id).update({"approval_policy_id": None},
                                                                      synchronize_session=False)
    core.audit("approval policy deleted", policy.name, policy.applies_to, user_id=actor.id,
               tenant_id=actor.tenant_id)
    db.session.delete(policy)


def save_stage(actor, policy, form, stage=None):
    _require_admin(actor)
    name = (form.get("name") or "").strip()
    if not 0 < len(name) <= 160:
        abort(400, description=tr("A stage name has 1 to 160 characters."))
    source = form.get("source")
    if source not in SOURCES or policy.applies_to not in SOURCES[source][1]:
        abort(400, description=tr("Choose where this stage's approvers come from."))
    mode = form.get("mode") or "any"
    condition = form.get("condition") or "always"
    fallback = form.get("fallback") or "none"
    if mode not in MODES:
        abort(400, description=tr("Choose how approvers decide."))
    if condition not in CONDITIONS or policy.applies_to not in CONDITIONS[condition][1]:
        abort(400, description=tr("Choose when the stage applies."))
    if fallback not in FALLBACKS:
        abort(400, description=tr("Choose a fallback."))
    if policy.applies_to == "enterprise" and stage is None and policy.stages:
        abort(409, description=tr("Enterprise record approvals have a single stage; edit the existing one."))
    group_id = None
    if SOURCES[source][2] == "group":
        try:
            group_id = int(form.get("group_id"))
        except (TypeError, ValueError):
            abort(400, description=tr("Choose a group."))
        if not SupportGroup.query.filter_by(id=group_id, tenant_id=policy.tenant_id).first():
            abort(400, description=tr("Choose a group of this organisation."))
    authority = form.get("authority") or None
    if authority and authority not in AUTHORITIES:
        abort(400, description=tr("Choose an approval authority."))
    if source == "authority" and not authority:
        abort(400, description=tr("Choose an approval authority."))
    user_ids = []
    if source == "users":
        raw = form.getlist("user_ids") if hasattr(form, "getlist") else form.get("user_ids", [])
        for value in raw:
            if str(value).isdigit() and User.query.filter_by(id=int(value), tenant_id=policy.tenant_id).first():
                user_ids.append(int(value))
        if not user_ids:
            abort(400, description=tr("Choose at least one person."))
    if stage is None:
        stage = ApprovalPolicyStage(tenant_id=policy.tenant_id, policy_id=policy.id,
                                    position=max([row.position for row in policy.stages] or [-1]) + 1)
        db.session.add(stage)
    stage.name, stage.source, stage.mode, stage.condition, stage.fallback = name, source, mode, condition, fallback
    stage.group_id = group_id
    stage.role_filter = ((form.get("role_filter") or "").strip()[:60] or None) if group_id else None
    stage.include_manager = str(form.get("include_manager") or "") in ("1", "on", "true")
    stage.authority = authority if source in ("group", "authority") else None
    stage.user_ids_json = json.dumps(user_ids)
    stage.skip_duplicates = str(form.get("skip_duplicates") or "") in ("1", "on", "true")
    policy.updated_by_id, policy.updated_at = actor.id, now()
    db.session.flush()
    core.audit("approval policy stage saved", policy.name, name, user_id=actor.id, tenant_id=actor.tenant_id)
    return stage


def stage_or_404(policy, stage_id):
    stage = ApprovalPolicyStage.query.filter_by(id=stage_id, policy_id=policy.id).first()
    if not stage:
        abort(404)
    return stage


def delete_stage(actor, policy, stage):
    _require_admin(actor)
    if len(policy.stages) <= 1 and policy.is_default:
        abort(409, description=tr("The default policy needs at least one stage."))
    core.audit("approval policy stage deleted", policy.name, stage.name, user_id=actor.id, tenant_id=actor.tenant_id)
    db.session.delete(stage)
    db.session.flush()
    for position, row in enumerate(sorted((s for s in policy.stages if s.id != stage.id), key=lambda s: s.position)):
        row.position = position


def move_stage(actor, policy, stage, direction):
    _require_admin(actor)
    ordered = sorted(policy.stages, key=lambda row: row.position)
    index = ordered.index(stage)
    other = index + (-1 if direction == "up" else 1)
    if 0 <= other < len(ordered):
        ordered[index], ordered[other] = ordered[other], ordered[index]
        for position, row in enumerate(ordered):
            row.position = position
        core.audit("approval policy stage moved", policy.name, f"{stage.name} {direction}", user_id=actor.id,
                   tenant_id=actor.tenant_id)


def describe_stage(stage):
    """A plain-language sentence for the policy page."""
    who = tr(SOURCES.get(stage.source, (stage.source,))[0])
    if stage.source == "group":
        who = tr("Members of {group}", group=stage.group.name if stage.group else tr("(no group chosen)"))
        if stage.role_filter:
            who += " " + tr("with the role {role}", role=stage.role_filter)
        if stage.include_manager:
            who += " " + tr("and its manager")
    if stage.source == "authority" and stage.authority:
        who = tr("Groups linked to {authority}", authority=tr(AUTHORITIES[stage.authority]))
    elif stage.authority:
        who += " · " + tr("plus groups linked to {authority}", authority=tr(AUTHORITIES[stage.authority]))
    if stage.source == "users":
        try:
            ids = json.loads(stage.user_ids_json or "[]")
        except ValueError:
            ids = []
        names = [user.name for user in User.query.filter(User.id.in_(ids or [0])).order_by(User.name)]
        who = ", ".join(names) or tr("(nobody chosen)")
    return who


def catalog_items_using(policy):
    return CatalogItem.query.filter_by(approval_policy_id=policy.id).order_by(CatalogItem.name).all()
