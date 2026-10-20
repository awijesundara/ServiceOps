"""Incident handling administration: assignment rules and incident templates.
The rules themselves live in serviceops_core/incident_handling.py."""
from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user

from app import ServiceOffering, db, require_action, roles, tenant_query, tenant_ticket_categories, \
    tenant_ticket_subcategories
import app as core
from serviceops_core import incident_handling as handling
from serviceops_core.localization import tr
from serviceops_core.request_values import parse_int


def register(app):
    @app.route("/admin/workspace-teams", methods=["GET", "POST"])
    @roles("admin")
    @require_action("administer")
    def workspace_teams_admin():
        """Which team handles each enterprise workspace (HR, security, ...)."""
        from app import DOMAIN_CONFIG, EnterpriseRecord, SupportGroup, WorkspaceTeam
        tenant_id = current_user.tenant_id
        groups = tenant_query(SupportGroup).filter_by(active=True).order_by(SupportGroup.name).all()
        if request.method == "POST":
            domain = request.form.get("domain", "")
            if domain not in DOMAIN_CONFIG:
                abort(400)
            row = WorkspaceTeam.query.filter_by(tenant_id=tenant_id, domain=domain).first()
            group_id = request.form.get("group_id") or ""
            if not group_id:
                if row is not None:
                    db.session.delete(row)
                core.audit("workspace team cleared", DOMAIN_CONFIG[domain]["name"])
                message = tr("{name} has no team now.", name=DOMAIN_CONFIG[domain]["name"])
            else:
                group = core.tenant_record_or_404(SupportGroup, parse_int(group_id, "group_id"))
                if row is None:
                    row = WorkspaceTeam(tenant_id=tenant_id, domain=domain, group_id=group.id)
                    db.session.add(row)
                row.group_id = group.id
                moved = 0
                if request.form.get("assign_existing"):
                    moved = EnterpriseRecord.query.filter_by(tenant_id=tenant_id, domain=domain, support_group_id=None) \
                        .update({"support_group_id": group.id})
                core.audit("workspace team set", DOMAIN_CONFIG[domain]["name"], f"-> {group.name}; {moved} existing")
                message = tr("{team} now handles {name}.", team=group.name, name=DOMAIN_CONFIG[domain]["name"])
                if moved:
                    message += " " + tr("{count} existing records were given to the team.", count=moved)
            db.session.commit()
            flash(message, "success")
            return redirect(url_for("workspace_teams_admin"))
        rows = {row.domain: row for row in WorkspaceTeam.query.filter_by(tenant_id=tenant_id)}
        unassigned = dict(db.session.query(EnterpriseRecord.domain, db.func.count(EnterpriseRecord.id)).filter(
            EnterpriseRecord.tenant_id == tenant_id, EnterpriseRecord.support_group_id.is_(None))
            .group_by(EnterpriseRecord.domain).all())
        workspaces = [{"domain": key, "name": config["name"], "team": rows[key].group if key in rows else None,
                       "unassigned": unassigned.get(key, 0)} for key, config in DOMAIN_CONFIG.items()]
        return render_template("workspace_teams_admin.html", workspaces=workspaces, groups=groups)

    @app.route("/admin/incident-handling", methods=["GET", "POST"])
    @roles("admin")
    @require_action("administer")
    def incident_handling_admin():
        tenant_id = current_user.tenant_id
        if request.method == "POST":
            action = request.form.get("action", "")
            anchor = "rules"
            if action in ("save_rule", "delete_rule", "move_rule"):
                rule = handling.rule_or_404(tenant_id, parse_int(request.form.get("rule_id"), "rule_id")) \
                    if request.form.get("rule_id") else None
                if action == "save_rule":
                    rule = handling.save_rule(current_user, request.form, rule)
                    message = tr("Assignment rule saved.")
                elif rule is None:
                    abort(400)
                elif action == "delete_rule":
                    handling.delete_rule(current_user, rule)
                    message = tr("Assignment rule deleted.")
                else:
                    handling.move_rule(current_user, rule, "up" if request.form.get("direction") == "up" else "down")
                    message = tr("Rule order saved.")
            elif action in ("save_template", "delete_template"):
                anchor = "templates"
                template = handling.template_or_404(tenant_id, parse_int(request.form.get("template_id"), "template_id")) \
                    if request.form.get("template_id") else None
                if action == "save_template":
                    handling.save_template(current_user, request.form, template)
                    message = tr("Template saved.")
                elif template is None:
                    abort(400)
                else:
                    core.audit("incident template deleted", template.name)
                    db.session.delete(template)
                    message = tr("Template deleted.")
            else:
                abort(400)
            db.session.commit()
            flash(message, "success")
            return redirect(url_for("incident_handling_admin") + "#" + anchor)
        ci_classes = sorted({row[0] for row in tenant_query(core.ConfigurationItem).with_entities(
            core.ConfigurationItem.ci_class).distinct() if row[0]})
        return render_template(
            "incident_admin.html", rules=handling.rules(tenant_id), templates=handling.templates(tenant_id),
            teams=core.team_groups().all(), ci_classes=ci_classes,
            offerings=tenant_query(ServiceOffering).filter_by(status="Operational").order_by(ServiceOffering.name).all(),
            categories=tenant_ticket_categories(tenant_id), subcategories=tenant_ticket_subcategories(tenant_id),
            impacts=handling.IMPACTS,
        )
