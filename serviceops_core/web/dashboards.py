"""Dashboards (B-464): personal and group dashboards. The rules and the widget
catalog live in serviceops_core/dashboards.py."""
from flask import abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import SupportGroup, db
from serviceops_core import dashboards as boards
from serviceops_core.localization import tr


def _back(dashboard, edit=True):
    return redirect(url_for("dashboard_view", dashboard_id=dashboard.id, edit=1 if edit else None))


def register(app):
    @app.get("/dashboards")
    @login_required
    def dashboards_home():
        return redirect(url_for("dashboard_view", dashboard_id=boards.home_dashboard(current_user).id))

    @app.get("/dashboards/<int:dashboard_id>")
    @login_required
    def dashboard_view(dashboard_id):
        dashboard = boards.dashboard_or_404(current_user, dashboard_id)
        editable = boards.can_edit(current_user, dashboard)
        editing = editable and request.args.get("edit") == "1"
        personal, shared = boards.visible_dashboards(current_user)
        home = boards.home_dashboard(current_user)
        manageable_groups = [g for g in boards.member_groups(current_user) if boards.can_manage_group(current_user, g)]
        return render_template(
            "dashboards/view.html", dashboard=dashboard, widgets=boards.render_context(current_user, dashboard),
            personal=personal, shared=shared, editable=editable, editing=editing, home_id=home.id,
            catalog=boards.catalog(dashboard.scope), spans=boards.SPANS, member_groups=boards.member_groups(current_user),
            manageable_groups=manageable_groups,
        )

    @app.post("/dashboards")
    @login_required
    def dashboard_create():
        group = None
        group_id = request.form.get("group_id", "")
        if group_id:
            group = SupportGroup.query.filter_by(id=int(group_id) if group_id.isdigit() else 0,
                                                 tenant_id=current_user.tenant_id).first()
            if group is None:
                abort(404)
        template = boards.DEFAULT_GROUP if group is not None else boards.DEFAULT_PERSONAL
        start = request.form.get("start", "suggested")
        dashboard = boards.create_dashboard(current_user, request.form.get("name"), group=group,
                                            description=request.form.get("description", ""),
                                            widgets=template if start == "suggested" else [])
        db.session.commit()
        flash(tr("Dashboard created. Add, arrange and configure its widgets."), "success")
        return _back(dashboard)

    @app.post("/dashboards/<int:dashboard_id>/settings")
    @login_required
    def dashboard_settings(dashboard_id):
        dashboard = boards.dashboard_or_404(current_user, dashboard_id, edit=True)
        boards.update_dashboard(current_user, dashboard, request.form.get("name"), request.form.get("description"))
        db.session.commit()
        flash(tr("Dashboard saved."), "success")
        return _back(dashboard)

    @app.post("/dashboards/<int:dashboard_id>/delete")
    @login_required
    def dashboard_delete(dashboard_id):
        dashboard = boards.dashboard_or_404(current_user, dashboard_id, edit=True)
        name = dashboard.name
        boards.delete_dashboard(current_user, dashboard)
        db.session.commit()
        flash(tr("{name} deleted.", name=name), "success")
        return redirect(url_for("dashboards_home"))

    @app.post("/dashboards/<int:dashboard_id>/copy")
    @login_required
    def dashboard_copy(dashboard_id):
        source = boards.dashboard_or_404(current_user, dashboard_id)
        copy = boards.copy_dashboard(current_user, source)
        db.session.commit()
        flash(tr("Copied to your dashboards as {name}.", name=copy.name), "success")
        return _back(copy)

    @app.post("/dashboards/<int:dashboard_id>/home")
    @login_required
    def dashboard_home_set(dashboard_id):
        dashboard = boards.dashboard_or_404(current_user, dashboard_id)
        boards.set_home(current_user, dashboard)
        db.session.commit()
        flash(tr("{name} now opens first.", name=dashboard.name), "success")
        return _back(dashboard, edit=False)

    @app.post("/dashboards/<int:dashboard_id>/widgets")
    @login_required
    def dashboard_widget_add(dashboard_id):
        dashboard = boards.dashboard_or_404(current_user, dashboard_id, edit=True)
        widget = boards.add_widget(current_user, dashboard, request.form.get("widget_key", ""))
        db.session.commit()
        return redirect(url_for("dashboard_view", dashboard_id=dashboard.id, edit=1) + f"#widget-{widget.id}")

    @app.post("/dashboards/<int:dashboard_id>/widgets/<int:widget_id>")
    @login_required
    def dashboard_widget_update(dashboard_id, widget_id):
        dashboard = boards.dashboard_or_404(current_user, dashboard_id, edit=True)
        widget = boards.widget_or_404(dashboard, widget_id)
        boards.update_widget(current_user, dashboard, widget, request.form)
        db.session.commit()
        return redirect(url_for("dashboard_view", dashboard_id=dashboard.id, edit=1) + f"#widget-{widget.id}")

    @app.post("/dashboards/<int:dashboard_id>/widgets/<int:widget_id>/delete")
    @login_required
    def dashboard_widget_remove(dashboard_id, widget_id):
        dashboard = boards.dashboard_or_404(current_user, dashboard_id, edit=True)
        boards.remove_widget(current_user, dashboard, boards.widget_or_404(dashboard, widget_id))
        db.session.commit()
        return _back(dashboard)

    @app.post("/dashboards/<int:dashboard_id>/widgets/<int:widget_id>/move")
    @login_required
    def dashboard_widget_move(dashboard_id, widget_id):
        dashboard = boards.dashboard_or_404(current_user, dashboard_id, edit=True)
        widget = boards.widget_or_404(dashboard, widget_id)
        boards.move_widget(current_user, dashboard, widget, "up" if request.form.get("direction") == "up" else "down")
        db.session.commit()
        return redirect(url_for("dashboard_view", dashboard_id=dashboard.id, edit=1) + f"#widget-{widget.id}")

    @app.post("/dashboards/<int:dashboard_id>/layout")
    @login_required
    def dashboard_layout(dashboard_id):
        """Drag-and-drop order from the editor: {"order": [widget ids]}."""
        dashboard = boards.dashboard_or_404(current_user, dashboard_id, edit=True)
        body = request.get_json(silent=True)
        order = body.get("order") if isinstance(body, dict) else None
        if not isinstance(order, list) or not all(isinstance(i, int) for i in order):
            abort(400, description=tr("order must be a list of widget ids."))
        boards.reorder_widgets(current_user, dashboard, order[:boards.MAX_WIDGETS])
        db.session.commit()
        return jsonify({"order": [w.id for w in dashboard.widgets]})
