"""Groups: create, edit and delete ServiceOps groups, the AD/LDAP groups
mapped to each, and the access levels each grants its members. Listed on
Administration → Sign-in and directory."""
from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

import app as core
from app import (
    DirectoryGroupMapping, GroupMember, SupportGroup, audit, db, group_access_roles, require_action, roles,
    sync_implied_role_grants, tenant_query, tenant_record_or_404,
)
from serviceops_core.ldap_access import ACCESS_LEVEL_LABELS, ACCESS_LEVELS
from serviceops_core.localization import tr

GROUP_TYPES = ("IT Fulfillment", "Fulfillment", "Executive")
ACCESS_LEVEL_HELP = {
    "requester": "Raise and follow their own tickets and requests.",
    "agent": "Work tickets, tasks and requests assigned to their teams.",
    "manager": "Agent access plus team management, reports and approvals.",
    "admin": "Full administration of this organization.",
}


def managed_groups():
    """Every group an administrator manages here: all groups except the
    governance bodies, which keep their own controls. Inactive groups stay
    listed so they can be reactivated."""
    return tenant_query(SupportGroup).filter(
        SupportGroup.group_type != "CCB Approval",
        SupportGroup.name.notin_(core.GOVERNANCE_GROUP_NAMES),
    ).order_by(SupportGroup.name).all()


def directory_groups_of(group):
    return DirectoryGroupMapping.query.filter_by(
        support_group_id=group.id, tenant_id=group.tenant_id, active=True,
    ).order_by(DirectoryGroupMapping.directory_group).all()


def _reconcile_members(group):
    for member in GroupMember.query.filter_by(group_id=group.id).all():
        sync_implied_role_grants(member.user)


def _save(group, is_new):
    """Validate and apply the submitted form to `group`. Returns an error
    message, or None once the group, its mappings and its members' access
    are updated (the caller commits)."""
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    group_type = request.form.get("group_type", "IT Fulfillment")
    access_roles = [role for role in ACCESS_LEVELS if role in request.form.getlist("access_roles")]
    directory_names = []
    for line in request.form.get("directory_groups", "").replace("\r", "").split("\n"):
        line = line.strip()
        if line and line.casefold() not in {n.casefold() for n in directory_names}:
            directory_names.append(line)
    if not name or len(name) > 120:
        return tr("Group name must contain 1 to 120 characters.")
    if len(description) > 500:
        return tr("Description must be 500 characters or fewer.")
    if any(len(entry) > 500 for entry in directory_names):
        return tr("Each AD/LDAP group must be 500 characters or fewer.")
    if name in core.GOVERNANCE_GROUP_NAMES:
        return tr("Use the dedicated governance controls for this group.")
    # The client-support group keeps its type: it gates client management.
    if group_type not in GROUP_TYPES and not (group_type == "Client Support" and group.group_type == "Client Support"):
        return tr("Select a supported group type.")
    duplicate = tenant_query(SupportGroup).filter(func.lower(SupportGroup.name) == name.casefold())
    if group.id:
        duplicate = duplicate.filter(SupportGroup.id != group.id)
    if duplicate.first():
        return tr("A group with that name already exists.")
    for entry in directory_names:
        taken = DirectoryGroupMapping.query.join(SupportGroup).filter(
            SupportGroup.tenant_id == current_user.tenant_id,
            DirectoryGroupMapping.active.is_(True),
            func.lower(DirectoryGroupMapping.directory_group) == entry.casefold(),
            DirectoryGroupMapping.support_group_id != (group.id or -1),
        ).first()
        if taken:
            return tr("{entry} is already mapped to {name}.", entry=entry, name=taken.support_group.name)

    before = "" if is_new else (
        f"{group.name}; {group.group_type}; active={group.active}; roles={group.access_roles or 'none'}"
    )
    old_name = group.name
    group.name, group.description, group.group_type = name, description, group_type
    group.access_roles = ",".join(access_roles)
    group.active = True if is_new else bool(request.form.get("active"))
    if is_new:
        group.tenant_id = current_user.tenant_id
        db.session.add(group)
    db.session.flush()

    wanted = {entry.casefold(): entry for entry in directory_names}
    existing = {
        mapping.directory_group.casefold(): mapping
        for mapping in DirectoryGroupMapping.query.filter_by(support_group_id=group.id, tenant_id=group.tenant_id)
    }
    for key, mapping in existing.items():
        mapping.active = key in wanted
    for key, entry in wanted.items():
        if key in existing:
            continue
        # A disabled mapping of this AD group to another group is retained for
        # audit; the unique (tenant, AD group) row moves to this group.
        retained = DirectoryGroupMapping.query.filter(
            DirectoryGroupMapping.tenant_id == group.tenant_id,
            func.lower(DirectoryGroupMapping.directory_group) == key,
        ).first()
        if retained:
            retained.support_group_id, retained.active, retained.directory_group = group.id, True, entry
        else:
            db.session.add(DirectoryGroupMapping(
                directory_group=entry, support_group_id=group.id, tenant_id=group.tenant_id,
            ))
    db.session.flush()

    if not is_new and old_name != name:
        core.record_group_rename(group, old_name)
    _reconcile_members(group)
    roles_text = ", ".join(access_roles) or "none"
    mapped = "; ".join(directory_names) or "none"
    if is_new:
        audit("create", f"Group: {name}", f"{group_type}; roles={roles_text}; ldap={mapped}")
    else:
        audit("update", f"Group: {name}", f"{before} -> {group_type}; active={group.active}; roles={roles_text}; ldap={mapped}")
    return None


def register(app):
    def render_form(group, error=None):
        if error:
            flash(error, "error")
        return render_template(
            "group_form.html", group=group,
            directory_groups="\n".join(m.directory_group for m in directory_groups_of(group)) if group.id
            else request.form.get("directory_groups", ""),
            selected_roles=set(group_access_roles(group)) if group.id and request.method == "GET"
            else set(request.form.getlist("access_roles")),
            access_levels=ACCESS_LEVELS, access_level_labels=ACCESS_LEVEL_LABELS,
            access_level_help=ACCESS_LEVEL_HELP, group_types=GROUP_TYPES,
        ), 400 if error else 200

    @app.route("/admin/groups")
    @roles("admin")
    @require_action("configure")
    def groups():
        return redirect(url_for("system_settings_category", category="sign_in_and_directory") + "#groups")

    @app.route("/admin/groups/new", methods=["GET", "POST"])
    @roles("admin")
    @require_action("configure")
    def group_new():
        group = SupportGroup(name="", group_type="IT Fulfillment", active=True)
        if request.method == "POST":
            error = _save(group, is_new=True)
            if error:
                db.session.rollback()
                return render_form(group, error)
            db.session.commit()
            flash(tr("Group {name} created.", name=group.name), "success")
            return redirect(url_for("groups"))
        return render_form(group)

    @app.route("/admin/groups/<int:group_id>", methods=["GET", "POST"])
    @roles("admin")
    @require_action("configure")
    def group_edit(group_id):
        group = tenant_record_or_404(SupportGroup, group_id)
        if group.group_type == "CCB Approval" or group.name in core.GOVERNANCE_GROUP_NAMES:
            abort(404)
        if request.method == "POST":
            error = _save(group, is_new=False)
            if error:
                db.session.rollback()
                group = tenant_record_or_404(SupportGroup, group_id)
                return render_form(group, error)
            db.session.commit()
            flash(tr("Group {name} updated.", name=group.name), "success")
            return redirect(url_for("groups"))
        return render_form(group)

    @app.route("/admin/groups/<int:group_id>/delete", methods=["POST"])
    @roles("admin")
    @require_action("configure")
    def group_delete(group_id):
        group = tenant_record_or_404(SupportGroup, group_id)
        if group.group_type in ("CCB Approval", "Client Support") or group.name in core.GOVERNANCE_GROUP_NAMES:
            abort(400, description=tr("This group is required by the platform and cannot be deleted."))
        name = group.name
        users = [member.user for member in group.members]
        if group.manager:
            users.append(group.manager)
        # Work, CIs, catalog routes and history that point at the group keep it
        # (deactivated) so nothing loses its owner; otherwise it is removed.
        referenced = any(
            model.query.filter(getattr(model, field) == group.id).first()
            for model, field in core.SUPPORT_GROUP_FK_MODELS
            if model not in (DirectoryGroupMapping, core.DirectoryManagedMembership)
        )
        mappings = DirectoryGroupMapping.query.filter_by(support_group_id=group.id)
        if not referenced:
            savepoint = db.session.begin_nested()
            try:
                mappings.delete(synchronize_session=False)
                core.DirectoryManagedMembership.query.filter_by(group_id=group.id).delete(synchronize_session=False)
                core.SupportGroupAlias.query.filter_by(group_id=group.id).delete(synchronize_session=False)
                db.session.delete(group)
                db.session.flush()
                savepoint.commit()
            except IntegrityError:
                savepoint.rollback()
                referenced = True
        if referenced:
            group = tenant_record_or_404(SupportGroup, group_id)
            group.active = False
            mappings.update({"active": False}, synchronize_session=False)
            GroupMember.query.filter_by(group_id=group.id).delete(synchronize_session=False)
            core.DirectoryManagedMembership.query.filter_by(group_id=group.id).delete(synchronize_session=False)
            db.session.flush()
        for user in {user.id: user for user in users if user}.values():
            sync_implied_role_grants(user)
        audit("delete", f"Group: {name}", "deactivated; records still reference it" if referenced else "deleted")
        db.session.commit()
        flash(tr("Group {name} deactivated: existing records still reference it.", name=name) if referenced
              else tr("Group {name} deleted.", name=name), "success")
        return redirect(url_for("groups"))
