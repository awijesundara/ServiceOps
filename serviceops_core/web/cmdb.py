"""CMDB, assets, racks and topology routes.

Moved from app.create_app(); endpoint names are unchanged."""
import csv
import io
import ipaddress
import json
import time
from datetime import timedelta, timezone
from urllib.parse import urljoin, urlparse

import requests
from flask import abort, current_app, flash, jsonify, redirect, render_template, request, Response, url_for
from flask_login import current_user
from sqlalchemy import func
from sqlalchemy.orm import aliased

import app as core
from app import (
    apply_filter_conditions,
    audit,
    ci_always_requires_ccb,
    ci_impact_set,
    CMDB_RELATIONSHIP_DISPLAY_LIMIT,
    csv_response,
    filter_conditions_breadcrumb,
    integration_endpoint_valid,
    log_field_changes,
    normalize_environment,
    parse_form_date,
    parse_list_filter_param,
    require_action,
    resolve_endpoint_addresses_safely,
    roles,
    setting_bool,
    tenant_query,
    tenant_record_or_404,
)
from serviceops_core.ci_class_policy import (
    ci_class_action_allowed,
    ci_class_read_allowed,
    managed_ci_classes,
    restrict_ci_query_to_readable_classes,
    unreadable_ci_classes,
)
from serviceops_core.dns_lookup import resolve_hostname, resolve_ip
from serviceops_core.dns_pin import pin_resolved_addresses
from serviceops_core.feature_flags import feature_enabled
from serviceops_core import ci_sources
from serviceops_core.web.common import (
    _ci_attributes_from_form,
    _ci_duplicate_of,
    _rack_elevation_payload,
    CI_CLASS_PERMISSION_CRUD_ROLES,
    CI_CLASS_PERMISSION_ROLES,
    CI_DISCOVERY_ATTRIBUTE_KEYS,
    cmdb_filter_field_spec,
    form_text,
)
from serviceops_models import (
    Asset,
    CI_RELATIONSHIP_TYPES,
    CiClassPermission,
    CIRelationship,
    ConfigurationItem,
    db,
    DiscoveryCandidate,
    DiscoveryTarget,
    IntegrationSyncJob,
    now,
    Rack,
    SupportGroup,
    TaskHistory,
    User,
)
from serviceops_core.localization import tr, tr_value


# An import must follow a preview reviewed this recently.
NETBOX_PREVIEW_VALID_HOURS = 24


def _tenant_reference_id(model, field, label):
    """The id submitted in form `field`, accepted only if it names a `model`
    row in the current tenant. Blank means "none". Anything else -- not a
    number, or another tenant's (or a nonexistent) id -- is refused, so a
    crafted form can never link a CI to another tenant's record."""
    raw = (request.form.get(field) or "").strip()
    if not raw:
        return None
    try:
        record_id = int(raw)
    except ValueError:
        abort(400, description=tr("Select a valid {label}.", label=label))
    if not tenant_query(model).filter_by(id=record_id).first():
        abort(400, description=tr("Select a valid {label}.", label=label))
    return record_id

def _bounded_netbox_body(response, ceiling, deadline):
    try:
        if response.is_redirect:
            abort(502)
        response.raise_for_status()
        length = response.headers.get("Content-Length")
        if length is not None and (int(length) < 0 or int(length) > ceiling):
            abort(415)
        body = bytearray()
        for chunk in response.iter_content(chunk_size=16384):
            if time.monotonic() > deadline:
                raise TimeoutError("NetBox response deadline exceeded")
            if len(body) + len(chunk) > ceiling:
                abort(415)
            body.extend(chunk)
        return bytes(body)
    finally:
        response.close()


def _netbox_object(response, deadline):
    payload = json.loads(_bounded_netbox_body(response, 1024 * 1024, deadline))
    if not isinstance(payload, dict):
        raise ValueError(tr("NetBox metadata must be an object"))
    return payload


def register(app):
    @app.get("/assets")
    @roles("agent", "manager", "admin")
    def assets():
        query = tenant_query(Asset)
        q = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        if q:
            query = query.filter(db.or_(
                Asset.asset_tag.ilike(f"%{q}%"), Asset.name.ilike(f"%{q}%"),
                Asset.serial_number.ilike(f"%{q}%"),
            ))
        field_spec = {
            "asset_tag": {"label": "Asset tag", "type": "text", "column": Asset.asset_tag},
            "name": {"label": "Name", "type": "text", "column": Asset.name},
            "asset_type": {"label": "Type", "type": "text", "column": Asset.asset_type},
            "status": {"label": "Status", "type": "choice", "column": Asset.status,
                      "options": [(s, s) for s in ["In stock", "In use", "In repair", "Retired"]]},
            "serial_number": {"label": "Serial", "type": "text", "column": Asset.serial_number},
        }
        query = apply_filter_conditions(query, conditions, field_spec)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = query.order_by(Asset.asset_tag).offset(
            (page - 1) * per_page
        ).limit(per_page).all()
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec)
        client_fields = {
            key: {"label": tr_value(spec["label"]), "type": spec["type"],
                  "options": [(value, tr_value(label)) for value, label in spec.get("options", [])]}
            for key, spec in field_spec.items()
        }
        return render_template(
            "assets.html", assets=rows, q=q, raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts,
            filter_fields=client_fields, page=page, pages=pages, total=total,
        )

    @app.route("/assets/new", methods=["GET", "POST"])
    @roles("admin")
    def asset_new():
        if request.method == "POST":
            asset = Asset(asset_tag=request.form["asset_tag"], name=request.form["name"],
                          asset_type=request.form["asset_type"], status=request.form["status"],
                          serial_number=request.form.get("serial_number"))
            db.session.add(asset)
            audit("create", asset.asset_tag, asset.name)
            db.session.commit()
            return redirect(url_for("assets"))
        return render_template("asset_form.html")

    @app.get("/cmdb")
    @roles("agent", "manager", "admin")
    def cmdb():
        status = request.args.get("status", "").strip()
        q = request.args.get("q", "").strip()
        raw_filter = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw_filter)
        query = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        )
        if status:
            query = query.filter(ConfigurationItem.operational_status == status)
        if q:
            pattern = f"%{q}%"
            query = query.filter(db.or_(
                ConfigurationItem.name.ilike(pattern),
                ConfigurationItem.serial_number.ilike(pattern),
                ConfigurationItem.ip_address.ilike(pattern),
                ConfigurationItem.model.ilike(pattern),
                ConfigurationItem.vendor.ilike(pattern),
                ConfigurationItem.location.ilike(pattern),
                ConfigurationItem.description.ilike(pattern),
            ))
        field_spec = cmdb_filter_field_spec()
        query = apply_filter_conditions(query, conditions, field_spec)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 50
        total = query.count()
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        visible_cis = query.options(
            db.joinedload(ConfigurationItem.support_group),
            db.joinedload(ConfigurationItem.owner),
        ).order_by(
            ConfigurationItem.ci_class, ConfigurationItem.name
        ).offset((page - 1) * per_page).limit(per_page).all()
        readable_ci_ids = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        )
        cis_total = readable_ci_ids.count()
        operational_total = readable_ci_ids.filter(
            ConfigurationItem.operational_status == "Operational"
        ).count()
        # Filtered and capped in SQL: this panel previously loaded every
        # relationship in the tenant and ran two permission queries per row,
        # which grows without bound once NetBox/LLDP sync adds cabling.
        denied_classes = unreadable_ci_classes(current_user.tenant_id, current_user.effective_role)
        parent_ci = aliased(ConfigurationItem)
        child_ci = aliased(ConfigurationItem)
        relationship_query = tenant_query(CIRelationship).join(
            parent_ci, CIRelationship.parent_id == parent_ci.id,
        ).join(child_ci, CIRelationship.child_id == child_ci.id)
        if denied_classes:
            relationship_query = relationship_query.filter(
                ~parent_ci.ci_class.in_(denied_classes), ~child_ci.ci_class.in_(denied_classes),
            )
        relationships_total = relationship_query.count()
        relationships = relationship_query.options(
            db.contains_eager(CIRelationship.parent.of_type(parent_ci)),
            db.contains_eager(CIRelationship.child.of_type(child_ci)),
        ).order_by(parent_ci.name, child_ci.name, CIRelationship.id).limit(CMDB_RELATIONSHIP_DISPLAY_LIMIT).all()
        # CIs pulled in from NetBox/CSV carry many more fields than the default
        # table shows (attributes is a free-form JSON bag); surface whatever keys
        # actually appear on this page so users can opt into columns beyond the
        # fixed set via the "Columns" picker, instead of that data being hidden.
        extra_attribute_keys = sorted({
            key for ci in visible_cis for key in (ci.attributes or {}).keys()
        })
        default_hidden_columns = [
            "ip_address", "vendor", "model", "cost_center", "discovery_source",
            "owner", "install_date", "warranty_expiry_date",
        ] + [f"attr:{key}" for key in extra_attribute_keys]
        value_labels = {("support_group_id", key): label
                        for key, label in field_spec["support_group_id"]["options"]}
        breadcrumb_parts = filter_conditions_breadcrumb(conditions, field_spec, value_labels)
        client_fields = {
            key: {"label": tr_value(spec["label"]), "type": spec["type"],
                  "options": [(value, tr_value(label)) for value, label in spec.get("options", [])]}
            for key, spec in field_spec.items()
        }
        return render_template(
            "cmdb.html", visible_cis=visible_cis, relationships=relationships,
            relationships_total=relationships_total, status=status,
            q=q, raw_filter=raw_filter, breadcrumb_parts=breadcrumb_parts, filter_fields=client_fields,
            page=page, pages=pages, total=total, cis_total=cis_total, operational_total=operational_total,
            ci_relationship_types=CI_RELATIONSHIP_TYPES, extra_attribute_keys=extra_attribute_keys,
            default_hidden_columns=default_hidden_columns,
        )

    @app.get("/cmdb/export.csv")
    @roles("agent", "manager", "admin")
    def cmdb_export():
        status = request.args.get("status", "").strip()
        conditions = parse_list_filter_param(request.args.get("filter", ""))
        query = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        )
        if status:
            query = query.filter(ConfigurationItem.operational_status == status)
        query = apply_filter_conditions(query, conditions, cmdb_filter_field_spec())
        export_limit = 5000
        cis = query.order_by(ConfigurationItem.ci_class, ConfigurationItem.name).limit(export_limit).all()
        # Attribute keys vary per CI (they come from whatever columns a CSV
        # import happened to have), so the export's extra columns are the
        # union of every key seen across the CIs being exported, in first-
        # seen order -- that way nothing captured on import is left out of
        # the export.
        attribute_keys = []
        seen_keys = set()
        for ci in cis:
            for key in (ci.attributes or {}):
                if key not in seen_keys:
                    seen_keys.add(key)
                    attribute_keys.append(key)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow([
            "Name", "Class", "Environment", "Operational status", "Lifecycle state",
            "Business criticality", "IP address", "Serial number", "Vendor", "Model",
            "Location", "Cost center", "Owning team", "Owner", *attribute_keys,
        ])
        for ci in cis:
            attributes = ci.attributes or {}
            writer.writerow([
                ci.name, ci.ci_class, ci.environment, ci.operational_status, ci.lifecycle_state,
                ci.business_criticality, ci.ip_address or "", ci.serial_number or "", ci.vendor or "",
                ci.model or "", ci.location or "", ci.cost_center or "",
                ci.support_group.name if ci.support_group else "", ci.owner.name if ci.owner else "",
                *[attributes.get(key, "") for key in attribute_keys],
            ])
        return csv_response(buffer.getvalue(), "cmdb.csv")

    @app.route("/cmdb/new", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def ci_new():
        if request.method == "POST":
            name = request.form["name"].strip()
            serial_number = form_text("serial_number")
            ci_class = request.form["ci_class"].strip()
            if not ci_class_action_allowed(
                current_user.tenant_id, ci_class, current_user.effective_role, "create",
            ):
                abort(403, description=tr("You are not permitted to create {ci_class} configuration items.", ci_class=ci_class))
            duplicate = _ci_duplicate_of(name, serial_number)
            if duplicate:
                flash(
                    tr("{name} already exists in the CMDB (matched by {value}) — edit that record instead of creating a duplicate.", name=duplicate.name, value='serial number' if duplicate.serial_number == serial_number else 'name'), "error",
                )
                return redirect(url_for("ci_edit", ci_id=duplicate.id))
            install_date = request.form.get("install_date") or None
            warranty_expiry_date = request.form.get("warranty_expiry_date") or None
            support_group_id = _tenant_reference_id(SupportGroup, "support_group_id", "support group")
            environment = normalize_environment(request.form["environment"])
            business_criticality = request.form.get("business_criticality", "Medium")
            rack_id = _tenant_reference_id(Rack, "rack_id", "rack")
            ci = ConfigurationItem(
                name=request.form["name"].strip(), ci_class=ci_class,
                description=form_text("description"),
                environment=environment, operational_status=request.form["operational_status"],
                lifecycle_state=request.form.get("lifecycle_state", "In Use"),
                business_criticality=business_criticality,
                ip_address=form_text("ip_address"),
                serial_number=form_text("serial_number"),
                vendor=form_text("vendor"),
                model=form_text("model"),
                location=form_text("location"),
                cost_center=form_text("cost_center"),
                discovery_source=request.form.get("discovery_source", "Manual"),
                install_date=parse_form_date(install_date),
                warranty_expiry_date=parse_form_date(warranty_expiry_date),
                support_group_id=support_group_id,
                owner_id=current_user.id,
                attributes=_ci_attributes_from_form(),
                require_ccb_approval=(
                    ci_always_requires_ccb(ci_class, environment, business_criticality)
                    or request.form.get("require_ccb_approval") == "on"
                ),
                rack_id=rack_id,
                rack_position=request.form.get("rack_position", type=float),
                rack_u_height=request.form.get("rack_u_height", type=int),
                rack_face=request.form.get("rack_face", "").strip() or None,
            )
            ci_sources.mark_changed(ci, {}, "manual")
            db.session.add(ci)
            audit("create", "CI", ci.name)
            db.session.commit()
            flash(tr("{name} created.", name=ci.name), "success")
            return redirect(url_for("cmdb"))
        support_groups = core.team_groups().all()
        racks = tenant_query(Rack).filter_by(active=True).order_by(Rack.name).all()
        return render_template("ci_form.html", support_groups=support_groups, racks=racks)

    @app.route("/cmdb/<int:ci_id>/edit", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def ci_edit(ci_id):
        ci = tenant_record_or_404(ConfigurationItem, ci_id)
        if not ci_class_action_allowed(
            current_user.tenant_id, ci.ci_class, current_user.effective_role, "update",
        ):
            abort(403, description=tr("You are not permitted to edit {ci_class} configuration items.", ci_class=ci.ci_class))
        if request.method == "POST":
            name = request.form["name"].strip()
            serial_number = form_text("serial_number")
            duplicate = _ci_duplicate_of(name, serial_number, exclude_id=ci.id)
            if duplicate:
                flash(
                    tr("{name} already has this {value} — resolve the conflict before saving.", name=duplicate.name, value='serial number' if duplicate.serial_number == serial_number else 'name'), "error",
                )
                return redirect(url_for("ci_edit", ci_id=ci.id))
            tracked_fields = [
                "name", "ci_class", "environment", "operational_status", "lifecycle_state",
                "business_criticality", "ip_address", "serial_number", "vendor", "model",
                "location", "cost_center",
            ]
            new_ci_class = request.form["ci_class"].strip()
            if new_ci_class != ci.ci_class and not ci_class_action_allowed(
                current_user.tenant_id, new_ci_class, current_user.effective_role, "update",
            ):
                abort(403, description=tr("You are not permitted to move this CI into {new_ci_class}.", new_ci_class=new_ci_class))
            support_group_id = _tenant_reference_id(SupportGroup, "support_group_id", "support group")
            owner_id = _tenant_reference_id(User, "owner_id", "owner")
            rack_id = _tenant_reference_id(Rack, "rack_id", "rack")
            before = {field: getattr(ci, field) or "" for field in tracked_fields}
            before["attributes"] = json.dumps(ci.attributes or {}, sort_keys=True)
            sources_before = {field: getattr(ci, field, None) for field in ci_sources.FORM_FIELDS}
            ci.name = request.form["name"].strip()
            ci.ci_class = new_ci_class
            ci.description = form_text("description")
            ci.environment = normalize_environment(request.form["environment"])
            ci.operational_status = request.form["operational_status"]
            ci.lifecycle_state = request.form.get("lifecycle_state", "In Use")
            ci.business_criticality = request.form.get("business_criticality", "Medium")
            ci.ip_address = form_text("ip_address")
            ci.serial_number = form_text("serial_number")
            ci.vendor = form_text("vendor")
            ci.model = form_text("model")
            ci.location = form_text("location")
            ci.cost_center = form_text("cost_center")
            ci.discovery_source = request.form.get("discovery_source", ci.discovery_source)
            ci.install_date = parse_form_date(request.form.get("install_date") or None)
            ci.warranty_expiry_date = parse_form_date(request.form.get("warranty_expiry_date") or None)
            ci.support_group_id = support_group_id
            ci.owner_id = owner_id
            ci.attributes = _ci_attributes_from_form(ci.attributes)
            ci.require_ccb_approval = (
                ci_always_requires_ccb(ci.ci_class, ci.environment, ci.business_criticality)
                or request.form.get("require_ccb_approval") == "on"
            )
            ci.rack_id = rack_id
            ci.rack_position = request.form.get("rack_position", type=float)
            ci.rack_u_height = request.form.get("rack_u_height", type=int)
            ci.rack_face = request.form.get("rack_face", "").strip() or None
            # A value a person changed here is theirs until a sync that owns
            # the field writes it again.
            ci_sources.mark_changed(ci, sources_before, "manual")
            after = {field: getattr(ci, field) or "" for field in tracked_fields}
            after["attributes"] = json.dumps(ci.attributes or {}, sort_keys=True)
            log_field_changes("ci", ci.id, before, after)
            audit("update", "CI", ci.name)
            db.session.commit()
            flash(tr("{name} updated.", name=ci.name), "success")
            return redirect(url_for("cmdb"))
        owners = tenant_query(User).filter_by(active=True).order_by(User.name).all()
        support_groups = core.team_groups().all()
        # Keep the CI's current owner selectable even when it is not a listed team.
        if ci.support_group and ci.support_group not in support_groups:
            support_groups.append(ci.support_group)
        racks = tenant_query(Rack).filter_by(active=True).order_by(Rack.name).all()
        history = TaskHistory.query.filter_by(
            target_type="ci", target_id=ci.id
        ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).limit(50).all()
        impacted_ids = ci_impact_set(ci.tenant_id, {ci.id}) - {ci.id}
        impacted_cis = tenant_query(ConfigurationItem).filter(ConfigurationItem.id.in_(impacted_ids)).all() if impacted_ids else []
        lldp_neighbor_cis = {}
        for neighbor in (ci.attributes or {}).get("lldp_neighbors") or []:
            neighbor_name = (neighbor.get("neighbor_name") or "").strip()
            if not neighbor_name or neighbor_name in lldp_neighbor_cis:
                continue
            match = tenant_query(ConfigurationItem).filter(
                func.lower(ConfigurationItem.name) == neighbor_name.casefold()
            ).first()
            if match:
                lldp_neighbor_cis[neighbor_name] = match
        # "Connects to" is the physical/network-link relationship type this
        # CI's own discovered LLDP data (or a manually-drawn relationship)
        # produces -- see B-289/cmdb_topology. Surfaced here directly
        # (both directions: this CI as parent or child) so a switch shows
        # every server plugged into it and a server shows the switch it's
        # plugged into, without leaving the CI page for the topology map.
        connects_to_rels = tenant_query(CIRelationship).filter(
            CIRelationship.relationship_type == "Connects to",
            db.or_(CIRelationship.parent_id == ci.id, CIRelationship.child_id == ci.id),
        ).options(db.joinedload(CIRelationship.parent), db.joinedload(CIRelationship.child)).all()
        denied_classes = unreadable_ci_classes(current_user.tenant_id, current_user.effective_role)
        network_connections = []
        for rel in connects_to_rels:
            other = rel.child if rel.parent_id == ci.id else rel.parent
            if not other or other.ci_class in denied_classes:
                continue
            local_port, other_port = "", ""
            if rel.label and "<->" in rel.label:
                left, right = rel.label.split("<->", 1)
                local_port, other_port = (left.strip(), right.strip()) if rel.parent_id == ci.id else (right.strip(), left.strip())
            network_connections.append({
                "ci": other, "local_port": local_port, "other_port": other_port,
            })
        source_groups, editable_attributes = ci_sources.group_attributes(ci, CI_DISCOVERY_ATTRIBUTE_KEYS)
        return render_template(
            "ci_form.html", ci=ci, owners=owners, support_groups=support_groups, racks=racks, history=history,
            source_groups=source_groups, editable_attributes=editable_attributes,
            field_source=lambda field: ci_sources.label(ci, field),
            impacted_cis=impacted_cis, lldp_neighbor_cis=lldp_neighbor_cis,
            network_connections=network_connections,
        )

    @app.route("/cmdb/import", methods=["GET", "POST"])
    @roles("admin")
    def cmdb_import():
        from serviceops_core.cmdb_import import CmdbImportError, import_ci_rows, parse_ci_rows

        preview = None
        csv_text = ""
        if request.method == "POST":
            action = request.form.get("action", "preview")
            if action == "preview":
                upload = request.files.get("file")
                sheet_url = request.form.get("sheet_url", "").strip()
                pasted = request.form.get("csv_text", "")
                if upload and upload.filename:
                    csv_text = upload.read().decode("utf-8-sig", errors="replace")
                elif sheet_url:
                    if "docs.google.com/spreadsheets/d/" not in sheet_url:
                        flash(tr("Enter a valid Google Sheets URL."), "error")
                        return _cmdb_import_page()
                    sheet_id = sheet_url.split("/d/")[1].split("/")[0]
                    gid = "0"
                    if "gid=" in sheet_url:
                        gid = sheet_url.split("gid=")[1].split("&")[0].split("#")[0] or "0"
                    export_url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}"
                    if not integration_endpoint_valid(export_url):
                        flash(tr("That sheet URL could not be reached safely."), "error")
                        return _cmdb_import_page()
                    proxies = core.resolve_component_proxies("CMDB_IMPORT")
                    ok, hostname, infos = (True, None, None) if proxies else resolve_endpoint_addresses_safely(export_url)
                    if not ok:
                        flash(tr("That sheet URL could not be reached safely."), "error")
                        return _cmdb_import_page()
                    try:
                        # Pin the addresses just validated: requests' own
                        # internal DNS lookup would otherwise re-resolve
                        # `hostname` independently of the safety check above,
                        # reopening the same DNS-rebinding TOCTOU window
                        # deliver_webhook() already closes for outbound
                        # webhooks (see serviceops_core/dns_pin.py).
                        if hostname and infos:
                            with pin_resolved_addresses(hostname, infos):
                                response = requests.get(export_url, timeout=15, allow_redirects=False, proxies=proxies)
                        else:
                            response = requests.get(export_url, timeout=15, allow_redirects=False, proxies=proxies)
                        response.raise_for_status()
                        csv_text = response.text
                    except requests.RequestException as error:
                        flash(tr("Could not fetch the sheet: {error}", error=error), "error")
                        return _cmdb_import_page()
                else:
                    csv_text = pasted
                try:
                    rows = parse_ci_rows(csv_text)
                    preview = import_ci_rows(rows, core.tenant_context_id(), dry_run=True)
                except CmdbImportError as error:
                    flash(str(error), "error")
            elif action == "apply":
                csv_text = request.form.get("csv_text", "")
                if not request.form.get("confirm_reviewed"):
                    flash(tr("Confirm that you reviewed the preview before applying it."), "error")
                    try:
                        preview = import_ci_rows(parse_ci_rows(csv_text), core.tenant_context_id(), dry_run=True)
                    except CmdbImportError:
                        preview = None
                    return _cmdb_import_page(preview=preview, csv_text=csv_text)
                try:
                    rows = parse_ci_rows(csv_text)
                    result = import_ci_rows(rows, core.tenant_context_id(), dry_run=False)
                except CmdbImportError as error:
                    flash(str(error), "error")
                else:
                    audit(
                        "configure", "CMDB import",
                        f"{result['cis_created']} created, {result['cis_updated']} updated, "
                        f"{result['fields_skipped_netbox_owned']} NetBox-owned and "
                        f"{result['fields_skipped_snipeit_owned']} Snipe-IT-owned fields preserved, "
                        f"{len(result['errors'])} errors",
                    )
                    flash(
                        tr("CMDB import applied: {result} created, {result2} updated, {count} errors, {count2} warnings.", result=result['cis_created'], result2=result['cis_updated'], count=len(result['errors']), count2=len(result['warnings'])),
                        "success" if not result["errors"] and not result["warnings"] else "warning",
                    )
                    return redirect(url_for("cmdb"))
            else:
                abort(400)
        return _cmdb_import_page(preview=preview, csv_text=csv_text)

    # Inventory sources that run as previewed, cancellable background jobs:
    # integration key -> (label, advisory lock offset, result keys that show
    # the preview found something to import, feature flag).
    inventory_syncs = {
        "netbox": ("NetBox", 349, ("devices_seen", "virtual_machines_seen", "racks_created", "racks_updated"),
                   "netbox_sync"),
        "snipeit": ("Snipe-IT", 350, ("assets_seen",), "snipeit_sync"),
    }

    def _latest_sync_job(integration):
        return tenant_query(IntegrationSyncJob).filter_by(integration=integration).order_by(
            IntegrationSyncJob.created_at.desc(), IntegrationSyncJob.id.desc()).first()

    def _sync_preview_for_import(integration):
        """The preview an import may proceed from: the tenant's most recent job
        for this source, a completed dry run finished within
        NETBOX_PREVIEW_VALID_HOURS that saw records and hit no record errors.
        An import (or any later preview) consumes it, so every import follows
        its own reviewed preview."""
        job = _latest_sync_job(integration)
        if not job or not job.dry_run or job.status != "Completed" or not job.finished_at:
            return None
        finished = job.finished_at if job.finished_at.tzinfo else job.finished_at.replace(tzinfo=timezone.utc)
        if now() - finished > timedelta(hours=NETBOX_PREVIEW_VALID_HOURS):
            return None
        result = job.result or {}
        if result.get("errors") or not any(result.get(key) for key in inventory_syncs[integration][2]):
            return None
        return job

    def _last_import(integration):
        return tenant_query(IntegrationSyncJob).filter_by(
            integration=integration, dry_run=False, status="Completed",
        ).order_by(IntegrationSyncJob.finished_at.desc(), IntegrationSyncJob.id.desc()).first()

    def _preview_expires(job):
        if not job:
            return None
        finished = job.finished_at if job.finished_at.tzinfo else job.finished_at.replace(tzinfo=timezone.utc)
        return finished + timedelta(hours=NETBOX_PREVIEW_VALID_HOURS)

    def _import_metrics(integration, result, dry_run):
        """(label, value, tone) tiles for one finished sync, in reading order."""
        created = result.get("cis_created", 0)
        # changes_total counts creates and real updates; older results (before
        # change tracking) only know how many items were matched.
        changed = (result["changes_total"] - created) if "changes_total" in result else result.get("cis_updated", 0)
        if integration == "netbox":
            seen = [("Devices", result.get("devices_seen", 0), ""),
                    ("Virtual machines", result.get("virtual_machines_seen", 0), ""),
                    ("Racks", result.get("racks_created", 0) + result.get("racks_updated", 0), "")]
        else:
            seen = [("Assets", result.get("assets_seen", 0), "")]
        tiles = seen + [
            ("Would be created" if dry_run else "Created", created, "is-create"),
            ("Would be updated" if dry_run else "Updated", changed, "is-update"),
        ]
        if "cis_unchanged" in result:
            tiles.append(("Already up to date", result["cis_unchanged"], ""))
        if result.get("cis_matched_by_serial"):
            tiles.append(("Matched by serial", result["cis_matched_by_serial"], ""))
        if integration == "snipeit" and result.get("racks_created"):
            tiles.append(("Racks created" if not dry_run else "Racks to create", result["racks_created"], ""))
        if result.get("cis_enriched_netbox"):
            tiles.append(("NetBox items enriched", result["cis_enriched_netbox"], ""))
        tiles.append(("Errors", len(result.get("errors") or []), "is-bad" if result.get("errors") else ""))
        return tiles

    def _cmdb_import_page(preview=None, csv_text="", netbox_probe=None, netbox_probe_error=None,
                          snipeit_probe=None, snipeit_probe_error=None):
        netbox_ready = _sync_preview_for_import("netbox")
        snipeit_ready = _sync_preview_for_import("snipeit")
        return render_template(
            "cmdb_import.html", preview=preview, csv_text=csv_text,
            import_metrics=_import_metrics,
            netbox_enabled=setting_bool("NETBOX_ENABLED"),
            netbox_sync_job=_latest_sync_job("netbox"),
            netbox_import_ready=netbox_ready, netbox_import_expires=_preview_expires(netbox_ready),
            netbox_last_import=_last_import("netbox"),
            netbox_preview_valid_hours=NETBOX_PREVIEW_VALID_HOURS,
            netbox_probe=netbox_probe, netbox_probe_error=netbox_probe_error,
            snipeit_enabled=setting_bool("SNIPEIT_ENABLED"),
            snipeit_sync_job=_latest_sync_job("snipeit"),
            snipeit_import_ready=snipeit_ready, snipeit_import_expires=_preview_expires(snipeit_ready),
            snipeit_last_import=_last_import("snipeit"),
            snipeit_probe=snipeit_probe, snipeit_probe_error=snipeit_probe_error,
        )

    def _queue_sync(integration, anchor):
        label, lock_offset, _, flag = inventory_syncs[integration]
        if not feature_enabled(flag, default=True):
            abort(503, description=tr("{label} synchronization is temporarily disabled by an operator feature flag.", label=label))
        dry_run = bool(request.form.get("dry_run"))
        tenant_id = core.tenant_context_id()
        # Serialize enqueue decisions per tenant on PostgreSQL. Without this,
        # simultaneous browser requests could both pass the active-job check.
        if db.engine.dialect.name == "postgresql":
            db.session.execute(
                db.text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": tenant_id * 1000 + lock_offset},
            )
        active = tenant_query(IntegrationSyncJob).filter(
            IntegrationSyncJob.integration == integration,
            IntegrationSyncJob.status.in_(("Pending", "Running")),
        ).first()
        if active:
            flash(tr("A {label} synchronization is already queued or running.", label=label), "warning")
            return redirect(url_for("cmdb_import") + anchor)
        if not dry_run:
            if not _sync_preview_for_import(integration):
                flash(tr("Run a preview first. An import starts only from a successful preview of the last {netbox_preview_valid_hours} hours.", netbox_preview_valid_hours=NETBOX_PREVIEW_VALID_HOURS), "error")
                return redirect(url_for("cmdb_import") + anchor)
            if not request.form.get("confirm_reviewed"):
                flash(tr("Confirm that you reviewed the preview before importing."), "error")
                return redirect(url_for("cmdb_import") + anchor)
        job = IntegrationSyncJob(
            tenant_id=tenant_id, actor_user_id=current_user.id,
            integration=integration, dry_run=dry_run,
        )
        db.session.add(job)
        db.session.flush()
        audit("configure", f"{label} CMDB sync queued", f"Job {job.id}; preview={dry_run}")
        db.session.commit()
        flash(tr("{source} preview queued. Nothing is saved until you review it and import.", source=label)
              if dry_run else tr("{source} import queued. It runs in controlled batches.", source=label), "success")
        return redirect(url_for("cmdb_import") + anchor)

    def _sync_job_status(integration, job_id):
        job = tenant_record_or_404(IntegrationSyncJob, job_id)
        if job.integration != integration:
            abort(404)
        total = job.total or 0
        percent = min(99, int(job.processed * 100 / total)) if total else 0
        if job.status == "Completed":
            percent = 100
        return jsonify({
            "id": job.id, "status": job.status, "phase": job.phase,
            "processed": job.processed, "total": job.total, "percent": percent,
            "cancel_requested": job.cancel_requested, "result": job.result,
            "error": job.error,
        })

    def _cancel_sync_job(integration, job_id):
        job = tenant_record_or_404(IntegrationSyncJob, job_id)
        if job.integration != integration:
            abort(404)
        if job.status in ("Pending", "Running"):
            job.cancel_requested = True
            if job.status == "Pending":
                job.status = "Cancelled"
                job.phase = "Cancelled before start"
                job.finished_at = now()
            audit("configure", f"{inventory_syncs[integration][0]} CMDB sync cancellation requested",
                  f"Job {job.id}")
            db.session.commit()
        return jsonify({"status": job.status, "cancel_requested": job.cancel_requested})

    @app.post("/cmdb/import/netbox/test")
    @roles("admin")
    @require_action("configure")
    def cmdb_import_netbox_test():
        from serviceops_core.netbox_sync import NetboxSyncError, probe_netbox

        try:
            probe = probe_netbox(core.tenant_context_id())
        except NetboxSyncError as error:
            audit("configure", "NetBox connection test failed", str(error)[:300])
            db.session.commit()
            return _cmdb_import_page(netbox_probe_error=str(error))
        audit("configure", "NetBox connection test succeeded",
              f"NetBox {probe.get('netbox_version')}; "
              + ", ".join(f"{row['key']}={row['count']}" for row in probe["endpoints"] if row["readable"]))
        db.session.commit()
        return _cmdb_import_page(netbox_probe=probe)

    @app.post("/cmdb/import/netbox")
    @roles("admin")
    @require_action("configure")
    def cmdb_import_netbox():
        return _queue_sync("netbox", "#netbox-sync")

    @app.get("/cmdb/import/netbox/jobs/<int:job_id>")
    @roles("admin")
    @require_action("configure")
    def cmdb_import_netbox_job(job_id):
        return _sync_job_status("netbox", job_id)

    @app.post("/cmdb/import/netbox/jobs/<int:job_id>/cancel")
    @roles("admin")
    @require_action("configure")
    def cmdb_import_netbox_cancel(job_id):
        return _cancel_sync_job("netbox", job_id)

    @app.post("/cmdb/import/snipeit/test")
    @roles("admin")
    @require_action("configure")
    def cmdb_import_snipeit_test():
        from serviceops_core.snipeit_sync import SnipeitSyncError, probe_snipeit

        try:
            probe = probe_snipeit(core.tenant_context_id())
        except SnipeitSyncError as error:
            audit("configure", "Snipe-IT connection test failed", str(error)[:300])
            db.session.commit()
            return _cmdb_import_page(snipeit_probe_error=str(error))
        audit("configure", "Snipe-IT connection test succeeded",
              ", ".join(f"{row['key']}={row['count']}" for row in probe["endpoints"] if row["readable"]))
        db.session.commit()
        return _cmdb_import_page(snipeit_probe=probe)

    @app.post("/cmdb/import/snipeit")
    @roles("admin")
    @require_action("configure")
    def cmdb_import_snipeit():
        return _queue_sync("snipeit", "#snipeit-sync")

    @app.get("/cmdb/import/snipeit/jobs/<int:job_id>")
    @roles("admin")
    @require_action("configure")
    def cmdb_import_snipeit_job(job_id):
        return _sync_job_status("snipeit", job_id)

    @app.post("/cmdb/import/snipeit/jobs/<int:job_id>/cancel")
    @roles("admin")
    @require_action("configure")
    def cmdb_import_snipeit_cancel(job_id):
        return _cancel_sync_job("snipeit", job_id)

    @app.route("/cmdb/racks", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def rack_list():
        if request.method == "POST":
            if current_user.effective_role not in ("admin", "superadmin"):
                abort(403)
            name = request.form.get("name", "").strip()
            if not name:
                flash(tr("Rack name is required."), "error")
            elif tenant_query(Rack).filter(func.lower(Rack.name) == name.casefold()).first():
                flash(tr("A rack with that name already exists."), "error")
            else:
                rack = Rack(
                    tenant_id=current_user.tenant_id, name=name,
                    site=request.form.get("site", "").strip(),
                    u_height=request.form.get("u_height", type=int) or 42,
                    notes=request.form.get("notes", "").strip(),
                )
                db.session.add(rack)
                audit("create", "Rack", name)
                db.session.commit()
                flash(tr("{name} created.", name=name), "success")
                return redirect(url_for("rack_list"))
        racks = tenant_query(Rack).filter_by(active=True).order_by(Rack.site, Rack.name).all()
        occupied_u = {
            row.rack_id: row.total
            for row in db.session.query(
                ConfigurationItem.rack_id,
                # A CI with no height set defaults to 1U everywhere else in
                # this feature (see ci_dict() in rack_elevation()) -- must
                # coalesce per-row here too, not just at the end: SUM() of
                # an all-NULL group returns SQL NULL, not 0, which crashed
                # the template's "used / rack.u_height" division outright.
                func.sum(func.coalesce(ConfigurationItem.rack_u_height, 1)).label("total"),
            ).filter(ConfigurationItem.rack_id.isnot(None), ConfigurationItem.tenant_id == current_user.tenant_id)
            .group_by(ConfigurationItem.rack_id).all()
        }
        return render_template("rack_list.html", racks=racks, occupied_u=occupied_u)

    @app.route("/cmdb/racks/<int:rack_id>/edit", methods=["GET", "POST"])
    @roles("admin")
    def rack_edit(rack_id):
        rack = tenant_record_or_404(Rack, rack_id)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            duplicate = tenant_query(Rack).filter(
                func.lower(Rack.name) == name.casefold(), Rack.id != rack.id,
            ).first()
            if not name:
                flash(tr("Rack name is required."), "error")
            elif duplicate:
                flash(tr("A rack with that name already exists."), "error")
            else:
                rack.name = name
                rack.site = request.form.get("site", "").strip()
                rack.u_height = request.form.get("u_height", type=int) or rack.u_height
                rack.notes = request.form.get("notes", "").strip()
                audit("update", "Rack", rack.name)
                db.session.commit()
                flash(tr("{name} updated.", name=rack.name), "success")
                return redirect(url_for("rack_list"))
        return render_template("rack_form.html", rack=rack)

    @app.post("/cmdb/racks/<int:rack_id>/delete")
    @roles("admin")
    def rack_delete(rack_id):
        rack = tenant_record_or_404(Rack, rack_id)
        still_mounted = tenant_query(ConfigurationItem).filter_by(rack_id=rack.id).count()
        if still_mounted:
            flash(
                tr("Cannot delete {name}: {still_mounted} configuration item(s) are still mounted in it. Unassign them first.", name=rack.name, still_mounted=still_mounted), "error",
            )
            return redirect(url_for("rack_list"))
        audit("delete", "Rack", rack.name)
        db.session.delete(rack)
        db.session.commit()
        flash(tr("{name} deleted.", name=rack.name), "success")
        return redirect(url_for("rack_list"))

    @app.get("/cmdb/racks/<int:rack_id>")
    @roles("agent", "manager", "admin")
    def rack_elevation(rack_id):
        rack = tenant_record_or_404(Rack, rack_id)
        payload = _rack_elevation_payload(rack)
        return render_template("rack_elevation.html", rack=rack, rack_json=json.dumps(payload))

    @app.get("/cmdb/racks/<int:rack_id>/embed")
    @roles("agent", "manager", "admin")
    def rack_elevation_embed(rack_id):
        # A compact, chrome-free version of the same view (no sidebar nav,
        # no stats/PDU panels) meant to be iframed directly into a CI's own
        # detail page -- see ci_form.html -- so "where does this device sit"
        # is visible without leaving the CI you're already looking at.
        rack = tenant_record_or_404(Rack, rack_id)
        payload = _rack_elevation_payload(rack, compact=True)
        return render_template("rack_elevation_embed.html", rack=rack, rack_json=json.dumps(payload))

    @app.get("/cmdb/device-artwork/<int:ci_id>/<face>")
    @roles("agent", "manager", "admin")
    def rack_device_artwork(ci_id, face):
        """Proxy a NetBox device-type elevation image without exposing its token.

        NetBox's device serializer identifies the device type, whose detail
        serializer owns the actual front/rear image URL. Both API reads and
        the image fetch are constrained to the configured NetBox origin;
        redirects, active content, and oversized files are rejected.
        """
        if face not in ("front", "rear"):
            abort(404)
        ci = tenant_record_or_404(ConfigurationItem, ci_id)
        # ci_id is directly addressable by URL, bypassing the CMDB list's own
        # class filtering -- the same read-permission check cmdb_network_info
        # already applies for the same reason.
        if not ci_class_read_allowed(current_user.tenant_id, ci.ci_class, current_user.effective_role):
            abort(403)
        if ci.external_source != "netbox" or not (ci.external_id or "").startswith("dcim.device:"):
            abort(404)
        if not setting_bool("NETBOX_ENABLED"):
            abort(404)
        from serviceops_core.netbox_sync import _netbox_session, normalize_base_url

        base_url = normalize_base_url(core.setting_value("NETBOX_BASE_URL", ""))
        token = core.setting_value("NETBOX_API_TOKEN", "").strip()
        if not base_url or not token or not integration_endpoint_valid(base_url, allow_private_network=True):
            abort(404)

        netbox_device_id = ci.external_id.split(":", 1)[1]
        # Validated before it is placed in any request path.
        if not netbox_device_id.isdecimal():
            abort(404)
        client = _netbox_session(base_url, token)
        deadline = time.monotonic() + 30
        try:
            device_response = client.get(
                f"{base_url.rstrip('/')}/api/dcim/devices/{netbox_device_id}/",
                timeout=(5, 5), allow_redirects=False, stream=True,
            )
            device_type = _netbox_object(device_response, deadline).get("device_type")
            if device_type is None:
                abort(404)
            if not isinstance(device_type, dict):
                raise ValueError(tr("Invalid NetBox device type"))
            device_type_id = device_type.get("id")
            if type(device_type_id) is not int or device_type_id <= 0:
                raise ValueError(tr("Invalid NetBox device type identifier"))
            type_response = client.get(
                f"{base_url.rstrip('/')}/api/dcim/device-types/{device_type_id}/",
                timeout=(5, 5), allow_redirects=False, stream=True,
            )
            image_url = _netbox_object(type_response, deadline).get(f"{face}_image")
            if not image_url:
                abort(404)
            if not isinstance(image_url, str):
                raise ValueError(tr("Invalid NetBox artwork URL"))
            image_url = urljoin(f"{base_url.rstrip('/')}/", image_url)
            base = urlparse(base_url)
            image = urlparse(image_url)
            def effective_port(parsed):
                return parsed.port or (443 if parsed.scheme == "https" else 80)
            if (image.scheme, image.hostname, effective_port(image)) != (
                base.scheme, base.hostname, effective_port(base),
            ):
                abort(502)
            image_response = client.get(image_url, timeout=(5, 5), allow_redirects=False, stream=True)
            content_type = str(image_response.headers.get("Content-Type", "")).split(";", 1)[0].lower()
            body = _bounded_netbox_body(image_response, 5 * 1024 * 1024, deadline)
            allowed_types = {"image/png", "image/jpeg", "image/webp", "image/gif"}
            if content_type not in allowed_types or not body or len(body) > 5 * 1024 * 1024:
                abort(415)
            response = Response(body, mimetype=content_type)
            response.headers["Cache-Control"] = "private, max-age=3600"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response
        except (requests.RequestException, ValueError, TypeError, TimeoutError):
            current_app.logger.warning("NetBox device artwork retrieval failed: invalid or unavailable upstream response")
            abort(502)
        finally:
            client.close()

    @app.post("/cmdb/relationships")
    @roles("agent", "manager", "admin")
    def ci_relationship_add():
        parent = tenant_record_or_404(ConfigurationItem, int(request.form["parent_id"]))
        if not ci_class_action_allowed(
            current_user.tenant_id, parent.ci_class, current_user.effective_role, "update",
        ):
            abort(403, description=tr("You are not permitted to edit {ci_class} configuration items.", ci_class=parent.ci_class))
        relationship_type = request.form.get("relationship_type", "Depends on")
        if relationship_type not in CI_RELATIONSHIP_TYPES:
            abort(400, description=tr("Select a valid relationship type."))
        try:
            child_ids = [int(raw) for raw in request.form.getlist("child_id") if raw.strip()]
        except ValueError:
            abort(400)
        if not child_ids:
            abort(400, description=tr("Select at least one child configuration item."))
        linked_names = []
        for child_id in dict.fromkeys(child_ids):
            child = tenant_record_or_404(ConfigurationItem, child_id)
            if parent.id == child.id:
                abort(400, description=tr("A configuration item cannot depend on itself."))
            if not ci_class_action_allowed(
                current_user.tenant_id, child.ci_class, current_user.effective_role, "update",
            ):
                abort(403, description=tr("You are not permitted to edit {ci_class} configuration items.", ci_class=child.ci_class))
            existing = tenant_query(CIRelationship).filter_by(
                parent_id=parent.id, child_id=child.id, relationship_type=relationship_type,
            ).first()
            if existing:
                continue
            db.session.add(CIRelationship(parent_id=parent.id, child_id=child.id, relationship_type=relationship_type))
            linked_names.append(child.name)
        if linked_names:
            audit("create", "CI relationship",
                  f"{parent.name} — {relationship_type} → {', '.join(linked_names)}")
            db.session.commit()
            flash(tr("Linked {name} to {linked_names}.", name=parent.name, linked_names=', '.join(linked_names)), "success")
        return redirect(url_for("cmdb"))

    @app.post("/cmdb/relationships/<int:relationship_id>/delete")
    @roles("agent", "manager", "admin")
    def ci_relationship_delete(relationship_id):
        relationship = tenant_record_or_404(CIRelationship, relationship_id)
        for endpoint_class in (relationship.parent.ci_class, relationship.child.ci_class):
            if not ci_class_action_allowed(
                current_user.tenant_id, endpoint_class, current_user.effective_role, "update",
            ):
                abort(403, description=tr("You are not permitted to edit {endpoint_class} configuration items.", endpoint_class=endpoint_class))
        audit("delete", "CI relationship", f"{relationship.parent.name} — {relationship.child.name}")
        db.session.delete(relationship)
        db.session.commit()
        flash(tr("Relationship removed."), "success")
        return redirect(url_for("cmdb"))

    @app.get("/cmdb/discovery")
    @require_action("security_administer")
    def cmdb_discovery():
        targets = tenant_query(DiscoveryTarget).order_by(DiscoveryTarget.name).all()
        pending_counts = dict(
            db.session.query(DiscoveryCandidate.target_id, db.func.count(DiscoveryCandidate.id))
            .filter(DiscoveryCandidate.target_id.in_([t.id for t in targets]))
            .group_by(DiscoveryCandidate.target_id).all()
        ) if targets else {}
        return render_template("cmdb_discovery.html", targets=targets, pending_counts=pending_counts)

    @app.post("/cmdb/discovery")
    @require_action("security_administer")
    def cmdb_discovery_add():
        name = request.form.get("name", "").strip()
        target_type = request.form.get("target_type", "host")
        address = request.form.get("address", "").strip()
        community = request.form.get("community", "")
        if not name or not address:
            flash(tr("Name and address are required."), "error")
            return redirect(url_for("cmdb_discovery"))
        if target_type not in ("host", "subnet"):
            abort(400, description=tr("Invalid target type."))
        try:
            if target_type == "host":
                ipaddress.ip_address(address)
            else:
                ipaddress.ip_network(address, strict=False)
        except ValueError:
            flash(tr("Address must be a valid IP address (host) or CIDR range (subnet)."), "error")
            return redirect(url_for("cmdb_discovery"))
        target = DiscoveryTarget(
            name=name, target_type=target_type, address=address,
            snmp_version=request.form.get("snmp_version", "2c"),
            snmp_port=int(request.form.get("snmp_port") or 161),
            schedule_enabled=request.form.get("schedule_enabled") == "on",
            schedule_interval_minutes=max(int(request.form.get("schedule_interval_minutes") or 1440), 5),
            created_by_id=current_user.id,
        )
        target.community = community
        db.session.add(target)
        audit("create", "Discovery target", f"{name} ({target_type}: {address})")
        db.session.commit()
        flash(tr("Discovery target {name} created.", name=name), "success")
        return redirect(url_for("cmdb_discovery"))

    @app.post("/cmdb/discovery/<int:target_id>/run")
    @require_action("security_administer")
    def cmdb_discovery_run(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        from serviceops_core.network_discovery import discover_subnet, probe_host
        try:
            if target.target_type == "host":
                facts = probe_host(
                    target.address, target.community,
                    port=target.snmp_port, version=target.snmp_version,
                )
                facts_list = [facts] if facts else []
            else:
                facts_list = discover_subnet(
                    target.address, target.community,
                    port=target.snmp_port, version=target.snmp_version,
                )
            # A run only stages candidates for review -- it never creates a
            # CI by itself. Clear this target's previous pending candidates
            # first so re-running doesn't pile up stale ones alongside
            # fresh results for the same address.
            DiscoveryCandidate.query.filter_by(target_id=target.id).delete()
            snmp_hosts = bare_hosts = 0
            for facts in facts_list:
                source = facts.get("discovery_source", "SNMP Discovery")
                if source == "SNMP Discovery":
                    snmp_hosts += 1
                else:
                    bare_hosts += 1
                db.session.add(DiscoveryCandidate(
                    target_id=target.id, host=facts["host"],
                    name=facts.get("sys_name") or facts["host"],
                    ci_class=facts.get("ci_class", "Device"),
                    vendor=facts.get("vendor") or None,
                    discovery_source=source, facts=facts,
                    tenant_id=target.tenant_id,
                ))
            target.last_run_status = "ok"
            target.last_run_summary = (
                f"{len(facts_list)} host(s) responded ({snmp_hosts} via SNMP, {bare_hosts} liveness-only) "
                f"-- awaiting review before anything is added to the CMDB."
            )
            flash(
                tr("{summary} Review and add them below.", summary=target.last_run_summary) if facts_list
                else tr("No hosts responded."),
                "success" if facts_list else "warning",
            )
        except Exception as error:  # noqa: BLE001 - a bad target must surface, not crash the request
            target.last_run_status = "failed"
            target.last_run_summary = str(error)[:2000]
            flash(tr("Discovery run failed: {error}", error=error), "error")
        target.last_run_at = now()
        audit("run", "Discovery target", f"{target.name}: {target.last_run_status}")
        db.session.commit()
        return redirect(url_for("cmdb_discovery"))

    @app.get("/cmdb/discovery/<int:target_id>/review")
    @require_action("security_administer")
    def cmdb_discovery_review(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        candidates = DiscoveryCandidate.query.filter_by(target_id=target.id).order_by(
            DiscoveryCandidate.discovery_source.desc(), DiscoveryCandidate.name
        ).all()
        return render_template("cmdb_discovery_review.html", target=target, candidates=candidates)

    @app.post("/cmdb/discovery/<int:target_id>/import")
    @require_action("security_administer")
    def cmdb_discovery_import(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        from serviceops_core.network_discovery import reconcile_facts_into_cmdb

        query = DiscoveryCandidate.query.filter_by(target_id=target.id)
        if request.form.get("select_all") != "1":
            selected_ids = {int(value) for value in request.form.getlist("candidate_id")}
            if not selected_ids:
                flash(tr("No devices selected -- nothing was added."), "warning")
                return redirect(url_for("cmdb_discovery_review", target_id=target.id))
            query = query.filter(DiscoveryCandidate.id.in_(selected_ids))
        candidates = query.all()
        facts_list = [candidate.facts for candidate in candidates]
        summary = reconcile_facts_into_cmdb(target.tenant_id, target.name, facts_list)
        for candidate in candidates:
            db.session.delete(candidate)
        audit(
            "import", "Discovery target",
            f"{target.name}: {summary['created']} created, {summary['updated']} updated from review",
        )
        db.session.commit()
        flash(
            tr("Added {summary} new and updated {summary2} existing CI(s), {summary3} relationship(s) created.", summary=summary['created'], summary2=summary['updated'], summary3=summary['relationships_created']),
            "success" if not summary["errors"] else "warning",
        )
        remaining = DiscoveryCandidate.query.filter_by(target_id=target.id).count()
        return redirect(
            url_for("cmdb_discovery_review", target_id=target.id) if remaining
            else url_for("cmdb_discovery")
        )

    @app.post("/cmdb/discovery/<int:target_id>/discard")
    @require_action("security_administer")
    def cmdb_discovery_discard(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        deleted = DiscoveryCandidate.query.filter_by(target_id=target.id).delete()
        audit("discard", "Discovery target", f"{target.name}: {deleted} candidate(s) discarded")
        db.session.commit()
        flash(tr("Discarded {deleted} discovered device(s) without adding them to the CMDB.", deleted=deleted), "success")
        return redirect(url_for("cmdb_discovery"))

    @app.post("/cmdb/discovery/<int:target_id>/delete")
    @require_action("security_administer")
    def cmdb_discovery_delete(target_id):
        target = tenant_record_or_404(DiscoveryTarget, target_id)
        DiscoveryCandidate.query.filter_by(target_id=target.id).delete()
        audit("delete", "Discovery target", target.name)
        db.session.delete(target)
        db.session.commit()
        flash(tr("Discovery target removed."), "success")
        return redirect(url_for("cmdb_discovery"))

    @app.get("/cmdb/topology")
    @roles("agent", "manager", "admin")
    def cmdb_topology():
        # Virtual machines are excluded from the physical connectivity map --
        # a VM's meaningful "connection" is to its hypervisor host (oVirt,
        # not LLDP-discoverable switch-port topology), which is a separate,
        # not-yet-built concern. Showing VMs here today would only add noise
        # with no physical-port information behind it.
        cis = restrict_ci_query_to_readable_classes(
            tenant_query(ConfigurationItem), current_user.tenant_id, current_user.effective_role,
        ).filter(ConfigurationItem.ci_class != "Virtual Machine").all()
        visible_ci_ids = {ci.id for ci in cis}
        relationships = [
            rel for rel in tenant_query(CIRelationship).all()
            if rel.parent_id in visible_ci_ids and rel.child_id in visible_ci_ids
        ]
        graph = {
            "nodes": [
                {
                    "id": ci.id, "name": ci.name, "ci_class": ci.ci_class,
                    "status": ci.operational_status, "discovery_source": ci.discovery_source,
                }
                for ci in cis
            ],
            "edges": [
                {
                    "source": rel.parent_id, "target": rel.child_id, "type": rel.relationship_type,
                    "label": rel.label,
                }
                for rel in relationships
            ],
        }
        return render_template("cmdb_topology.html", graph_json=json.dumps(graph))

    @app.get("/cmdb/<int:ci_id>/network-info")
    @roles("agent", "manager", "admin")
    def cmdb_network_info(ci_id):
        # Purely informational hostname<->IP resolution for the topology
        # detail panel and the CI edit page's discovered-interfaces table --
        # never used to open an outbound connection, so this only needs the
        # same read-permission check ci_edit already applies, not the
        # SSRF-focused address allowlist used for webhook delivery.
        ci = tenant_record_or_404(ConfigurationItem, ci_id)
        if not ci_class_read_allowed(current_user.tenant_id, ci.ci_class, current_user.effective_role):
            abort(403)
        ips = []
        if ci.ip_address:
            ips.append(ci.ip_address)
        for iface in (ci.attributes or {}).get("interfaces") or []:
            addr = iface.get("ip_address") if isinstance(iface, dict) else None
            if addr and addr not in ips:
                ips.append(addr)
        hostnames = [ci.name] if ci.name else []
        addresses = [{"ip": ip, "hostname": resolve_hostname(ip)} for ip in ips]
        hostname_results = [{"hostname": name, "ips": resolve_ip(name)} for name in hostnames]
        return jsonify({"addresses": addresses, "hostnames": hostname_results})

    @app.route("/cmdb/permissions", methods=["GET", "POST"])
    @roles("admin")
    def cmdb_permissions():
        tenant_id = current_user.tenant_id
        if request.method == "POST":
            new_class = request.form.get("new_class", "").strip()
            submitted_classes = set(request.form.getlist("ci_class")) | ({new_class} if new_class else set())
            changed = []
            for ci_class in submitted_classes:
                if not ci_class:
                    continue
                for role in CI_CLASS_PERMISSION_ROLES:
                    can_read = request.form.get(f"read__{ci_class}__{role}") == "on"
                    can_create = (
                        request.form.get(f"create__{ci_class}__{role}") == "on"
                        if role in CI_CLASS_PERMISSION_CRUD_ROLES else False
                    )
                    can_update = (
                        request.form.get(f"update__{ci_class}__{role}") == "on"
                        if role in CI_CLASS_PERMISSION_CRUD_ROLES else False
                    )
                    can_delete = (
                        request.form.get(f"delete__{ci_class}__{role}") == "on"
                        if role in CI_CLASS_PERMISSION_CRUD_ROLES else False
                    )
                    row = CiClassPermission.query.filter_by(
                        tenant_id=tenant_id, ci_class=ci_class, role=role,
                    ).first()
                    if not row:
                        # Only create a row when it actually grants something,
                        # or when this class is newly opted-in via "Add" (an
                        # all-unchecked row still needs to exist so the class
                        # shows up as managed going forward).
                        if not (can_read or can_create or can_update or can_delete) and ci_class != new_class:
                            continue
                        row = CiClassPermission(tenant_id=tenant_id, ci_class=ci_class, role=role)
                        db.session.add(row)
                    if (
                        row.can_read != can_read or row.can_create != can_create
                        or row.can_update != can_update or row.can_delete != can_delete
                    ):
                        row.can_read, row.can_create = can_read, can_create
                        row.can_update, row.can_delete = can_update, can_delete
                        row.updated_by_id = current_user.id
                        changed.append(
                            f"{ci_class}/{role}=read:{can_read},create:{can_create},"
                            f"update:{can_update},delete:{can_delete}"
                        )
            if changed:
                audit("configure", "CI class permission", "; ".join(changed))
            db.session.commit()
            flash(tr("CI class permissions saved."), "success")
            return redirect(url_for("cmdb_permissions"))

        classes_in_use = {
            row[0] for row in tenant_query(ConfigurationItem)
            .with_entities(ConfigurationItem.ci_class).distinct().all()
        }
        all_classes = sorted(classes_in_use | managed_ci_classes(tenant_id))
        existing = CiClassPermission.query.filter_by(tenant_id=tenant_id).all()
        grants = {
            (row.ci_class, row.role): {
                "read": row.can_read, "create": row.can_create,
                "update": row.can_update, "delete": row.can_delete,
            }
            for row in existing
        }
        return render_template(
            "cmdb_permissions.html", ci_classes=all_classes, roles=CI_CLASS_PERMISSION_ROLES,
            crud_roles=CI_CLASS_PERMISSION_CRUD_ROLES, grants=grants,
            managed_classes=managed_ci_classes(tenant_id),
        )
