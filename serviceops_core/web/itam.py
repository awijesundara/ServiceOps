"""Generic list, form and delete pages for the IT asset management record
types declared in serviceops_core.itam.registry. Agents and above may view;
the roles a type lists in edit_roles may change it. Every query is scoped to
the current tenant."""
from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import or_

from app import (
    ConfigurationItem, User, audit, db, roles, tenant_query, tenant_record_or_404,
)
from serviceops_core.itam.registry import RESOURCES, display, parse_value, readable_cis
from serviceops_core.ci_class_policy import restrict_ci_query_to_readable_classes
from serviceops_core.localization import tr

LIST_LIMIT = 500


def resource_or_404(kind):
    resource = RESOURCES.get(kind)
    if not resource:
        abort(404)
    return resource


def can_edit(resource):
    return current_user.effective_role in resource.edit_roles


def _choices(resource, record):
    """Options for every reference, user and CI field on the form."""
    options = {}
    for spec in resource.fields:
        if spec.kind == "ref":
            target = RESOURCES[spec.ref]
            options[spec.name] = [(row.id, target.title(row)) for row in tenant_query(target.model).order_by(
                getattr(target.model, target.order_by)).limit(LIST_LIMIT)]
        elif spec.kind == "user":
            options[spec.name] = [(user.id, user.name) for user in tenant_query(User).filter(
                User.active.is_(True)).order_by(User.name).limit(LIST_LIMIT)]
        elif spec.kind == "cis":
            query = restrict_ci_query_to_readable_classes(
                tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role)
            options[spec.name] = [(ci.id, ci.name) for ci in query.order_by(
                ConfigurationItem.name).limit(2000)]
    # A bounded picker must always retain its current selection, including
    # inactive owners and readable CIs beyond the first page of choices.
    for spec in resource.fields:
        if spec.kind not in ("ref", "user", "cis"):
            continue
        selected = readable_cis(getattr(record, spec.name) or []) if spec.kind == "cis" else []
        if spec.kind in ("ref", "user"):
            row = getattr(record, spec.name.removesuffix("_id"), None)
            if row and row.tenant_id == current_user.tenant_id:
                selected = [row]
        ids = {identifier for identifier, _ in options[spec.name]}
        for row in selected:
            if row.id not in ids:
                label = RESOURCES[spec.ref].title(row) if spec.kind == "ref" else row.name
                options[spec.name].append((row.id, label))
    return options


def _apply(resource, record):
    """Validate the submitted form into `record`. Returns a list of errors."""
    values, errors = {}, []
    for spec in resource.fields:
        value, error = parse_value(spec, request.form.get(spec.name), current_user.tenant_id)
        if error:
            errors.append(error)
        values[spec.name] = value
    if not errors and resource.validate:
        error = resource.validate(record, values)
        if error:
            errors.append(error)
    if errors:
        return errors
    for name, value in values.items():
        if resource.field(name).kind == "cis" and record.id:
            existing = getattr(record, name)
            visible_ids = {ci.id for ci in readable_cis(existing)}
            value = value + [ci for ci in existing if ci.id not in visible_ids]
        setattr(record, name, value)
    return []


def _describe(resource, record):
    return "; ".join(
        f"{spec.name}={display(spec, record)}" for spec in resource.fields
        if spec.kind not in ("textarea",)
    )[:2000]


def register(app):
    @app.context_processor
    def itam_context():
        return {"itam_resources": RESOURCES}

    @app.route("/itam/<kind>")
    @roles("agent", "manager", "admin")
    def itam_list(kind):
        resource = resource_or_404(kind)
        model = resource.model
        query = tenant_query(model)
        search = request.args.get("q", "").strip()[:120]
        if search:
            like = f"%{search}%"
            query = query.filter(or_(*(getattr(model, name).ilike(like) for name in resource.search_fields)))
        order = getattr(model, resource.order_by)
        records = query.order_by(order.is_(None), order, model.id).yield_per(200)
        status_filter = request.args.get("status", "")
        rows = []
        statuses = set()
        for record in records:
            status = resource.status(record) if resource.status else None
            if status:
                statuses.add(status[0])
            if status_filter and (not status or status[0] != status_filter):
                continue
            if len(rows) >= LIST_LIMIT:
                continue
            rows.append({"record": record, "status": status,
                         "cells": [display(spec, record) for spec in resource.fields if spec.in_list]})
        statuses = sorted(statuses)
        return render_template(
            "itam_list.html", resource=resource, rows=rows, search=search, status_filter=status_filter,
            statuses=statuses, columns=[spec for spec in resource.fields if spec.in_list],
            can_edit=can_edit(resource),
        )

    def render_form(resource, record, errors=()):
        for error in errors:
            flash(error, "error")
        return render_template(
            "itam_form.html", resource=resource, record=record, options=_choices(resource, record),
            can_edit=can_edit(resource), status=resource.status(record) if resource.status and record.id else None,
            related=[(title, rows(record)) for title, rows in resource.related] if record.id else [],
        ), 400 if errors else 200

    @app.route("/itam/<kind>/new", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def itam_new(kind):
        resource = resource_or_404(kind)
        if not can_edit(resource):
            abort(403)
        record = resource.model(tenant_id=current_user.tenant_id)
        for spec in resource.fields:
            if spec.kind == "bool" and request.method == "GET":
                setattr(record, spec.name, True)
        if request.method == "POST":
            errors = _apply(resource, record)
            if errors:
                db.session.rollback()
                return render_form(resource, record, errors)
            db.session.add(record)
            db.session.flush()
            audit("create", f"{resource.label}: {resource.title(record)}", _describe(resource, record))
            db.session.commit()
            flash(tr("{label} {name} created.", label=tr(resource.label), name=resource.title(record)), "success")
            return redirect(url_for("itam_edit", kind=kind, record_id=record.id))
        return render_form(resource, record)

    @app.route("/itam/<kind>/<int:record_id>", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def itam_edit(kind, record_id):
        resource = resource_or_404(kind)
        record = tenant_record_or_404(resource.model, record_id)
        if request.method == "POST":
            if not can_edit(resource):
                abort(403)
            before = _describe(resource, record)
            errors = _apply(resource, record)
            if errors:
                db.session.rollback()
                record = tenant_record_or_404(resource.model, record_id)
                return render_form(resource, record, errors)
            audit("update", f"{resource.label}: {resource.title(record)}", f"{before} -> {_describe(resource, record)}")
            db.session.commit()
            flash(tr("{label} {name} updated.", label=tr(resource.label), name=resource.title(record)), "success")
            return redirect(url_for("itam_edit", kind=kind, record_id=record.id))
        return render_form(resource, record)

    @app.route("/itam/<kind>/<int:record_id>/delete", methods=["POST"])
    @roles("agent", "manager", "admin")
    def itam_delete(kind, record_id):
        resource = resource_or_404(kind)
        if not can_edit(resource):
            abort(403)
        record = tenant_record_or_404(resource.model, record_id)
        reason = resource.delete_blocker(record) if resource.delete_blocker else None
        if reason:
            flash(reason, "error")
            return redirect(url_for("itam_edit", kind=kind, record_id=record.id))
        name = resource.title(record)
        audit("delete", f"{resource.label}: {name}", _describe(resource, record))
        db.session.delete(record)
        db.session.commit()
        flash(tr("{label} {name} deleted.", label=tr(resource.label), name=name), "success")
        return redirect(url_for("itam_list", kind=kind))
