"""Groups as approvers.

An administrator can link ServiceOps teams to an approval authority so that
every active member (and the manager) of those teams is an approver alongside
the named users:

  ccb           CCB authorization for non-standard changes (any one approves)
  executive     Executive (CEO) approval (the Executive Office rule applies)
  team_manager  a team's manager assessment; subject_group_id names the team,
                and the manager or any member of the linked groups approves
  enterprise    approval of problem and other enterprise records

Members are resolved when an approval starts and stored as individual votes,
so later membership changes never rewrite an in-flight decision.
"""
from serviceops_models import ApprovalAuthorityGroup, GroupMember, SupportGroup, User, db

AUTHORITIES = ("ccb", "executive", "team_manager", "enterprise")
MAX_GROUPS = 50


def authority_groups(tenant_id, authority, subject_group_id=None):
    """The active groups linked to `authority`, by name."""
    return (
        SupportGroup.query.join(ApprovalAuthorityGroup, ApprovalAuthorityGroup.group_id == SupportGroup.id)
        .filter(
            ApprovalAuthorityGroup.tenant_id == tenant_id,
            ApprovalAuthorityGroup.authority == authority,
            ApprovalAuthorityGroup.subject_group_id.is_(subject_group_id) if subject_group_id is None
            else ApprovalAuthorityGroup.subject_group_id == subject_group_id,
            SupportGroup.tenant_id == tenant_id,
            SupportGroup.active.is_(True),
        )
        .order_by(SupportGroup.name)
        .all()
    )


def group_user_ids(groups, tenant_id):
    """Active same-tenant users who belong to (or manage) any of `groups`."""
    group_ids = [group.id for group in groups]
    if not group_ids:
        return set()
    member_ids = {
        row[0] for row in db.session.query(GroupMember.user_id)
        .filter(GroupMember.group_id.in_(group_ids)).all()
    }
    member_ids |= {group.manager_id for group in groups if group.manager_id}
    if not member_ids:
        return set()
    return {
        row[0] for row in db.session.query(User.id).filter(
            User.id.in_(member_ids), User.active.is_(True), User.tenant_id == tenant_id,
        ).all()
    }


def authority_user_ids(tenant_id, authority, subject_group_id=None):
    return group_user_ids(authority_groups(tenant_id, authority, subject_group_id), tenant_id)


def set_authority_groups(tenant_id, authority, group_ids, eligible_groups, subject_group_id=None, actor_id=None):
    """Replace the groups linked to `authority`. `eligible_groups` is the
    query of teams an administrator may choose (the caller's team list), so a
    governance group or another tenant's team can never be linked. Returns
    the linked groups. Raises ValueError on an invalid selection."""
    if authority not in AUTHORITIES:
        raise ValueError("Unknown approval authority.")
    wanted = sorted(set(group_ids))
    if len(wanted) > MAX_GROUPS:
        raise ValueError(f"Select at most {MAX_GROUPS} groups.")
    groups = eligible_groups.filter(SupportGroup.id.in_(wanted)).all() if wanted else []
    if len(groups) != len(wanted):
        raise ValueError("Select active teams in this organization.")
    existing = ApprovalAuthorityGroup.query.filter(
        ApprovalAuthorityGroup.tenant_id == tenant_id,
        ApprovalAuthorityGroup.authority == authority,
        ApprovalAuthorityGroup.subject_group_id.is_(subject_group_id) if subject_group_id is None
        else ApprovalAuthorityGroup.subject_group_id == subject_group_id,
    ).all()
    for row in existing:
        if row.group_id not in wanted:
            db.session.delete(row)
    linked = {row.group_id for row in existing}
    for group in groups:
        if group.id not in linked:
            db.session.add(ApprovalAuthorityGroup(
                tenant_id=tenant_id, authority=authority, subject_group_id=subject_group_id,
                group_id=group.id, created_by_id=actor_id,
            ))
    return groups


def linked_group_ids(tenant_id, authority):
    """{subject_group_id: [group ids]} for an authority (subject None for tenant-wide)."""
    mapping = {}
    for row in ApprovalAuthorityGroup.query.filter_by(tenant_id=tenant_id, authority=authority).all():
        mapping.setdefault(row.subject_group_id, []).append(row.group_id)
    return mapping
