"""Approval policies (B-460): the administration page where each
organization defines who approves catalog requests, changes and other
enterprise records. The routing engine lives in
serviceops_core/approval_policies.py; nothing about approvers is fixed in
code beyond the editable defaults created there."""
import json

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user

from app import SupportGroup, User, db, require_action, roles, tenant_query
from serviceops_core import approval_policies as policies
from serviceops_core.localization import tr


def _back(policy=None):
    target = url_for("approval_policies_admin")
    return redirect(f"{target}#policy-{policy.id}" if policy is not None and policy.id else target)


def _stage_user_ids(stage):
    try:
        return set(json.loads(stage.user_ids_json or "[]")) if stage is not None else set()
    except ValueError:
        return set()


def register(app):
    @app.route("/admin/approval-policies", methods=["GET", "POST"])
    @roles("admin")
    @require_action("security_administer")
    def approval_policies_admin():
        tenant_id = current_user.tenant_id
        if request.method == "POST":
            action = request.form.get("action", "")
            policy = None
            if action != "create_policy":
                try:
                    policy_id = int(request.form.get("policy_id", ""))
                except ValueError:
                    abort(400, description=tr("Choose a policy."))
                policy = policies.policy_or_404(tenant_id, policy_id)
            if action == "create_policy":
                policy = policies.save_policy(current_user, request.form.get("applies_to"),
                                              request.form.get("name"), request.form.get("description"))
                message = tr("Policy created. Add its stages next.")
            elif action == "update_policy":
                policies.save_policy(current_user, policy.applies_to, request.form.get("name"),
                                     request.form.get("description"), policy=policy)
                message = tr("Policy saved.")
            elif action == "set_default":
                policies.set_default(current_user, policy)
                message = tr("{name} is now the default.", name=policy.name)
            elif action in ("activate", "deactivate"):
                policies.set_active(current_user, policy, action == "activate")
                message = tr("Policy activated.") if action == "activate" else tr("Policy deactivated.")
            elif action == "delete_policy":
                policies.delete_policy(current_user, policy)
                db.session.commit()
                flash(tr("Policy deleted. Catalog items that used it now follow the default."), "success")
                return _back()
            elif action == "add_stage":
                policies.save_stage(current_user, policy, request.form)
                message = tr("Stage added.")
            elif action in ("update_stage", "delete_stage", "move_up", "move_down"):
                try:
                    stage = policies.stage_or_404(policy, int(request.form.get("stage_id", "")))
                except ValueError:
                    abort(400, description=tr("Choose a stage."))
                if action == "update_stage":
                    policies.save_stage(current_user, policy, request.form, stage=stage)
                    message = tr("Stage saved.")
                elif action == "delete_stage":
                    policies.delete_stage(current_user, policy, stage)
                    message = tr("Stage removed.")
                else:
                    policies.move_stage(current_user, policy, stage, "up" if action == "move_up" else "down")
                    message = tr("Stage order saved.")
            else:
                abort(400, description=tr("Unknown action."))
            db.session.commit()
            flash(message, "success")
            return _back(policy)

        policies.ensure_defaults(tenant_id)
        db.session.commit()
        grouped = [(key, label, policies.policies(tenant_id, key)) for key, label in policies.APPLIES_TO.items()]
        return render_template(
            "approval_policies_admin.html",
            grouped=grouped,
            sources=policies.SOURCES, modes=policies.MODES, conditions=policies.CONDITIONS,
            fallbacks=policies.FALLBACKS, authorities=policies.AUTHORITIES,
            describe=policies.describe_stage, stage_user_ids=_stage_user_ids, items_using=policies.catalog_items_using,
            groups=tenant_query(SupportGroup).order_by(SupportGroup.name).all(),
            people=tenant_query(User).filter_by(active=True).order_by(User.name).all(),
        )
