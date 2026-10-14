"""Project management REST API (B-443), /api/v1/projects and
/api/v1/work-items. API clients act as their acting user: every project
rule (tenant, private projects, project roles) applies to that user.

Scopes: projects:read for reads, projects:write for creating and changing
work items and adding comments. Creating a work item requires an
Idempotency-Key header, as creating an incident does."""
from flask import abort, g, jsonify, request

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import service
from serviceops_core.projects.models import Project, WorkItem, WorkItemComment
from serviceops_models import db

WRITE_FIELDS = {"title", "description", "type", "status_id", "priority", "assignee_ids", "labels", "parent_key",
                "start_date", "due_date", "story_points", "estimate_minutes"}


def project_document(project):
    return {
        "key": project.key, "name": project.name, "description": project.description,
        "visibility": project.visibility, "lead": project.lead.username if project.lead else None,
        "archived": project.archived_at is not None,
        "statuses": [{"id": status.id, "name": status.name, "category": status.category,
                      "wip_limit": status.wip_limit} for status in project.statuses],
    }


def item_document(item, include_comments=False):
    document = {
        "key": item.key, "project": item.project.key, "type": item.item_type, "title": item.title,
        "description": item.description,
        "status": {"id": item.status.id, "name": item.status.name, "category": item.status.category},
        "priority": item.priority, "reporter": item.reporter.username if item.reporter else None,
        "assignees": [user.username for user in item.assignees], "labels": [row.label for row in item.labels],
        "parent": item.parent.key if item.parent else None,
        "start_date": item.start_date.isoformat() if item.start_date else None,
        "due_date": item.due_date.isoformat() if item.due_date else None,
        "story_points": item.story_points, "estimate_minutes": item.estimate_minutes,
        "created_at": item.created_at.isoformat(), "updated_at": item.updated_at.isoformat(),
        "resolved_at": item.resolved_at.isoformat() if item.resolved_at else None,
    }
    if include_comments:
        document["comments"] = [
            {"id": row.id, "author": row.author.username, "body": row.body, "created_at": row.created_at.isoformat()}
            for row in WorkItemComment.query.filter_by(work_item_id=item.id).order_by(WorkItemComment.created_at)]
    return document


def _user():
    service.require_enabled()
    return g.api_user


def _body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400, description=tr("A JSON object is required."))
    unknown = set(body) - WRITE_FIELDS
    if unknown:
        abort(400, description=tr("Unknown fields: {unknown}.", unknown=", ".join(sorted(unknown))))
    return body


def _fields(body, project):
    fields = {}
    mapping = {"title": "title", "description": "description", "type": "item_type", "status_id": "status_id",
               "priority": "priority", "labels": "labels", "start_date": "start_date", "due_date": "due_date",
               "story_points": "story_points", "estimate_minutes": "estimate_minutes"}
    for name, target in mapping.items():
        if name in body:
            value = body[name]
            if isinstance(value, bool) or isinstance(value, (dict, list)) and name != "labels":
                abort(400, description=tr("{field} has the wrong type.", field=name))
            fields[target] = value
    if "assignee_ids" in body:
        if not isinstance(body["assignee_ids"], list):
            abort(400, description=tr("assignee_ids must be a list of user ids."))
        fields["assignee_ids"] = body["assignee_ids"]
    if "parent_key" in body:
        parent = service.find_visible_item(g.api_user, body["parent_key"]) if body["parent_key"] else None
        if body["parent_key"] and (not parent or parent.project_id != project.id):
            abort(400, description=tr("parent_key must be a work item in this project."))
        fields["parent_id"] = parent.id if parent else None
    return fields


def register(app):
    @app.get("/api/v1/projects")
    def api_projects():
        core.require_api_scope("projects:read")
        user = _user()
        projects = service.visible_projects(user).order_by(Project.key).limit(500).all()
        return jsonify({"data": [project_document(project) for project in projects],
                        "meta": {"request_id": g.request_id}})

    @app.get("/api/v1/projects/<key>")
    def api_project(key):
        core.require_api_scope("projects:read")
        return jsonify({"data": project_document(service.project_or_404(_user(), key))})

    @app.get("/api/v1/projects/<key>/work-items")
    def api_project_items(key):
        core.require_api_scope("projects:read")
        user = _user()
        project = service.project_or_404(user, key)
        try:
            limit = min(max(int(request.args.get("limit", "50")), 1), 200)
            cursor = int(request.args.get("cursor", "0"))
        except ValueError:
            abort(400, description=tr("limit and cursor must be integers."))
        filters = {name: request.args.get(name, "").strip() for name in
                   ("q", "type", "status", "category", "priority", "assignee", "label", "epic")
                   if request.args.get(name, "").strip()}
        rows = service.item_query(project, filters, user).filter(WorkItem.number > cursor).order_by(
            WorkItem.number).limit(limit + 1).all()
        page = rows[:limit]
        return jsonify({"data": [item_document(item) for item in page],
                        "meta": {"limit": limit, "next_cursor": page[-1].number if len(rows) > limit and page else None,
                                 "request_id": g.request_id}})

    @app.post("/api/v1/projects/<key>/work-items")
    def api_item_create(key):
        core.require_api_scope("projects:write")
        user = _user()
        project = service.project_or_404(user, key)
        idempotency_key, request_hash, replay = core.api_idempotency_context()
        if replay:
            return replay
        body = _body()
        fields = _fields(body, project)
        item = service.create_item(
            user, project, fields.pop("title", ""), item_type=fields.pop("item_type", "task"),
            description=fields.pop("description", "") or "", status_id=fields.pop("status_id", None),
            priority=fields.pop("priority", "medium"), assignee_ids=fields.pop("assignee_ids", None),
            labels=fields.pop("labels", None), parent_id=fields.pop("parent_id", None),
            start_date=fields.pop("start_date", None), due_date=fields.pop("due_date", None),
            story_points=fields.pop("story_points", None), estimate_minutes=fields.pop("estimate_minutes", None))
        document = {"data": item_document(item)}
        core.store_api_idempotency(idempotency_key, request_hash, document, 201)
        core.audit("api create", item.key, core.mobile_client_details(g.api_client), user_id=user.id,
                   tenant_id=user.tenant_id)
        db.session.commit()
        return jsonify(document), 201

    @app.get("/api/v1/work-items/<item_key>")
    def api_item(item_key):
        core.require_api_scope("projects:read")
        item = service.item_or_404(_user(), item_key)
        return jsonify({"data": item_document(item, include_comments=True)})

    @app.patch("/api/v1/work-items/<item_key>")
    def api_item_update(item_key):
        core.require_api_scope("projects:write")
        user = _user()
        item = service.item_or_404(user, item_key)
        service.update_item(user, item, _fields(_body(), item.project))
        db.session.commit()
        return jsonify({"data": item_document(item)})

    @app.post("/api/v1/work-items/<item_key>/comments")
    def api_item_comment(item_key):
        core.require_api_scope("projects:write")
        user = _user()
        item = service.item_or_404(user, item_key)
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("body"), str):
            abort(400, description=tr("A JSON object with a body string is required."))
        comment = service.add_comment(user, item, body["body"])
        db.session.commit()
        return jsonify({"data": {"id": comment.id, "author": user.username, "body": comment.body,
                                 "created_at": comment.created_at.isoformat()}}), 201
