"""Dashboards for the mobile app (B-464): the signed-in user's personal and
team dashboards as JSON, and the ticket list behind each number.

Widgets are rendered by the same code as the web page (dashboards.render_context),
so the app shows exactly what the browser shows. A number or bar that opens a
list on the web carries a `list` reference here, {"kind", "filter"}, which
/api/v1/mobile/ticket-list resolves with the web list's own query.
"""
from datetime import date, datetime
from urllib.parse import parse_qs, urlsplit

from flask import abort, g, jsonify, request

from app import Ticket, api_ticket_document, parse_list_filter_param
from serviceops_core import dashboards as boards
from serviceops_core.localization import tr, tr_value
from serviceops_core.mobile_pagination import paginate
from serviceops_core.web.common import mobile_only, ticket_list_query

LIST_KINDS = ("incident", "change", "all")


def list_reference(url):
    """{"kind", "filter"} for a ticket list link made by ticket_list_link, else None."""
    if not url:
        return None
    parts = urlsplit(url)
    segments = parts.path.strip("/").split("/")
    if len(segments) != 2 or segments[0] != "tickets" or segments[1] not in LIST_KINDS:
        return None
    raw = parse_qs(parts.query).get("filter", [""])[0]
    return {"kind": segments[1], "filter": parse_list_filter_param(raw)}


def _iso(value):
    return value.isoformat() if isinstance(value, (date, datetime)) else None


def _person(user):
    return {"id": user.id, "name": user.name, "username": user.username} if user else None


def _dashboard_summary(dashboard, home_id):
    return {"id": dashboard.id, "name": dashboard.name, "description": dashboard.description or "",
            "scope": dashboard.scope, "home": dashboard.id == home_id,
            "group": {"id": dashboard.group.id, "name": dashboard.group.name} if dashboard.group else None}


def _widget_body(viewer, key, data):
    """The widget's data as plain JSON; `view` tells the app how to draw it."""
    if key == "ticket_counts":
        return {"view": "tiles", "tiles": [{"label": tr_value(tile["label"]), "count": tile["count"], "tone": tile["tone"],
                                            "list": list_reference(tile["url"])} for tile in data["tiles"]]}
    if key == "ticket_list":
        return {"view": "tickets", "tickets": [api_ticket_document(row, viewer) for row in data["tickets"]],
                "list": list_reference(data["url"])}
    if key == "ticket_chart":
        return {"view": "bars", "total": data["total"], "list": list_reference(data["url"]),
                "bars": [{"label": bar["label"], "count": bar["count"], "list": list_reference(bar["url"])}
                         for bar in data["bars"]]}
    if key == "ticket_trend":
        return {"view": "trend", "opened_total": data["opened_total"], "resolved_total": data["resolved_total"],
                "days": [{"date": _iso(day["date"]), "opened": day["opened"], "resolved": day["resolved"]}
                         for day in data["days"]]}
    if key == "team_workload":
        return {"view": "workload", "missing_team": bool(data.get("missing_team")),
                "members": [{"person": _person(row["user"]), "tickets": row["tickets"], "tasks": row["tasks"],
                             "list": list_reference(row["url"])} for row in data["members"]]}
    if key == "tasks":
        return {"view": "tasks", "tasks": [{
            "number": row["task"].number, "title": row["task"].title, "state": row["task"].state,
            "due_at": _iso(getattr(row["task"], "due_at", None) or getattr(row["task"], "planned_end", None)),
        } for row in data["tasks"]]}
    if key == "approvals":
        return {"view": "approvals", "approvals": [{
            "vote_id": row["vote"].id, "number": row["number"], "title": row["title"],
            "gate": row["vote"].gate.name,
        } for row in data["approvals"]]}
    if key == "upcoming_changes":
        return {"view": "changes", "changes": [{
            "ticket": api_ticket_document(row["ticket"], viewer),
            "planned_start": _iso(row["governance"].planned_start), "planned_end": _iso(row["governance"].planned_end),
        } for row in data["changes"]]}
    if key == "requests":
        return {"view": "requests", "requests": [{
            "number": item.number, "title": item.item.name if item.item else item.number, "state": item.state,
            "due_at": _iso(item.due_at),
        } for item in data["items"]]}
    if key == "knowledge":
        return {"view": "articles", "articles": [{
            "id": row.id, "title": row.title, "category": row.category, "created_at": _iso(row.created_at),
        } for row in data["articles"]]}
    if key == "work_items":
        return {"view": "work_items", "disabled": bool(data.get("disabled")), "work_items": [{
            "key": item.key, "title": item.title, "project": item.project.key, "priority": item.priority,
            "status": {"name": item.status.name, "category": item.status.category},
            "due_date": _iso(item.due_date),
        } for item in data["items"]]}
    if key in ("favorites", "recently_viewed"):
        rows = data["favorites"] if key == "favorites" else data["views"]
        return {"view": "links", "links": [{"label": row.label, "url": row.url} for row in rows]}
    if key == "notifications":
        return {"view": "notifications", "notifications": [{
            "id": row.id, "title": row.title, "body": row.body, "read": row.read, "severity": row.severity,
            "target_type": row.target_type, "target_id": row.target_id, "created_at": _iso(row.created_at),
        } for row in data["notifications"]]}
    if key == "note":
        return {"view": "note", "paragraphs": data["paragraphs"]}
    if key == "links":
        return {"view": "links", "links": data["links"]}
    return {"view": "unsupported"}


def register(app):
    @app.get("/api/v1/mobile/dashboards")
    def api_mobile_dashboards():
        mobile_only()
        user = g.api_user
        home_id = boards.home_dashboard(user).id
        personal, shared = boards.visible_dashboards(user)
        return jsonify({"data": {
            "home_id": home_id,
            "dashboards": [_dashboard_summary(row, home_id) for row in personal]
            + [_dashboard_summary(row, home_id) for _, rows in shared for row in rows],
        }})

    @app.get("/api/v1/mobile/dashboards/<int:dashboard_id>")
    def api_mobile_dashboard(dashboard_id):
        mobile_only()
        user = g.api_user
        dashboard = boards.dashboard_or_404(user, dashboard_id)
        widgets = [{
            "id": item["widget"].id, "key": item["key"], "title": item["title"], "span": item["widget"].span,
            "team": {"id": item["team"].id, "name": item["team"].name} if item["team"] else None,
            **_widget_body(user, item["key"], item["data"]),
        } for item in boards.render_context(user, dashboard)]
        return jsonify({"data": _dashboard_summary(dashboard, boards.home_dashboard(user).id) | {
            "editable": boards.can_edit(user, dashboard), "widgets": widgets}})

    @app.get("/api/v1/mobile/ticket-list")
    def api_mobile_ticket_list():
        """The tickets a dashboard number counts: kind plus the web list's filter conditions."""
        mobile_only()
        kind = request.args.get("kind", "all")
        if kind not in LIST_KINDS:
            abort(400, description=tr("kind must be incident, change or all."))
        raw = request.args.get("filter", "")
        conditions = parse_list_filter_param(raw)
        if raw and not conditions and raw.strip() not in ("", "[]"):
            abort(400, description=tr("filter must be a JSON list of conditions."))
        query = ticket_list_query(kind, conditions=conditions, viewer=g.api_user)
        rows, meta = paginate(query, [
            (Ticket.updated_at, True, lambda row: row.updated_at, datetime),
            (Ticket.id, True, lambda row: row.id, int),
        ])
        meta["total"] = query.order_by(None).count()
        return jsonify({"data": [api_ticket_document(row, g.api_user) for row in rows], "meta": meta,
                        "filter": conditions})
