"""Customizable dashboards (B-464): personal dashboards and dashboards shared
by a group, built from a closed catalog of server-rendered widgets.

Security model (unchanged from My Workspace, B-121): widgets are code-defined
and rendered by the server; options are validated against each widget's
schema; free text is escaped and links must be internal paths. Every data
function queries as the person *viewing* the dashboard, so sharing a group
dashboard never shows anyone a record they could not open themselves.
"""
import json
from collections import Counter
from datetime import timedelta

from flask import abort, url_for
from sqlalchemy import func

import app as core
from serviceops_core.localization import tr
from serviceops_core.task_lifecycle import FINISHED_TICKET_STATES
from serviceops_models import (ApprovalChain, ApprovalGate, ApprovalVote, CatalogItemRouting, CatalogRequest,
                               CatalogTask, ChangeGovernance, Dashboard, DashboardHome,
                               DashboardWidget, Favorite, GroupMember, Notification, OperationalTask, RecentView,
                               RequestedItem, SupportGroup, TaskSLA, Ticket, User,
                               UserWorkspaceLayout, db, now)

TERMINAL_TICKET = FINISHED_TICKET_STATES
TERMINAL_TASK = ("Closed Complete", "Closed Incomplete", "Closed Skipped", "Cancelled")
TERMINAL_ITEM = ("Closed Complete", "Closed Incomplete", "Closed Skipped", "Rejected", "Cancelled")
MAX_DASHBOARDS = 20
MAX_WIDGETS = 24
SPANS = (1, 2, 3)

# --- option schema -----------------------------------------------------------------------------

SCOPE_CHOICES = [("mine", "Assigned to me"), ("team", "My team"), ("visible", "Everything I can see")]
KIND_CHOICES = [("incident", "Incidents"), ("change", "Changes"), ("all", "Incidents and changes")]
LIMIT_CHOICES = [("5", "5"), ("10", "10"), ("20", "20")]


def _choice(label, choices, default):
    return {"type": "choice", "label": label, "choices": choices, "default": default}


SCOPE = _choice("Show", SCOPE_CHOICES, "mine")
KIND = _choice("Records", KIND_CHOICES, "incident")
LIMIT = _choice("Rows", LIMIT_CHOICES, "5")
TEAM = {"type": "team", "label": "Team"}


def _widget(label, description, data, scopes=("personal", "group"), span=1, options=None, icon="▤",
            category="Tickets"):
    return {"label": label, "description": description, "data": data, "scopes": scopes, "default_span": span,
            "options": options or {}, "icon": icon, "category": category}


CATEGORIES = ("Tickets", "Charts", "Work", "Personal", "Content")


def age_label(moment):
    """Compact age such as 5m, 3h or 2d, for list columns."""
    if moment is None:
        return ""
    current = now()
    if moment.tzinfo is None:
        current = current.replace(tzinfo=None)
    seconds = max(0, int((current - moment).total_seconds()))
    if seconds < 3600:
        return f"{max(1, seconds // 60)}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


# --- data helpers ------------------------------------------------------------------------------

def _tickets(viewer, opts, team):
    query = core.visible_ticket_query(viewer).filter(Ticket.deleted_at.is_(None))
    kind = opts.get("kind", "incident")
    query = query.filter(Ticket.kind.in_(("incident", "change") if kind == "all" else (kind,)))
    scope = opts.get("scope", "mine")
    if scope == "mine":
        query = query.filter(Ticket.assignee_id == viewer.id)
    elif scope == "team":
        if team is None:
            return query.filter(db.false())
        # The ticket list's own team rule, so the number and the list agree.
        from serviceops_core.web.common import team_ticket_condition
        query = query.filter(team_ticket_condition(team.id))
    return query


def _sla_ticket_ids(state):
    running = db.session.query(TaskSLA.target_id).filter(TaskSLA.target_type == "ticket",
                                                         TaskSLA.stage == "In Progress")
    if state == "breached":
        return running.filter(TaskSLA.breached.is_(True))
    horizon = now() + timedelta(hours=core.setting_int("SLA_AT_RISK_HOURS", 4))
    return running.filter(TaskSLA.breached.is_(False), TaskSLA.breach_at <= horizon)


def ticket_list_link(viewer, opts, team, **extra):
    """The ticket list showing what a ticket widget shows, so the numbers can be opened."""
    kind = opts.get("kind", "incident")
    rows = []
    if opts.get("scope", "mine") == "mine":
        rows.append({"field": "assignee", "op": "eq", "value": str(viewer.id)})
    elif opts.get("scope") == "team" and team is not None:
        rows.append({"field": "group", "op": "eq", "value": str(team.id)})
    rows += [{"field": key, "op": "eq", "value": str(value)} for key, value in extra.items()]
    return url_for("tickets", kind=kind if kind in ("incident", "change", "all") else "incident",
                   filter=json.dumps(rows, separators=(",", ":")) if rows else None)


def _ticket_counts(viewer, opts, team):
    query = _tickets(viewer, opts, team).filter(Ticket.state.notin_(TERMINAL_TICKET))
    urgent = query.filter(Ticket.priority.in_(("P1", "P2"))).count()
    unassigned = query.filter(Ticket.assignee_id.is_(None)).count()
    breached = query.filter(Ticket.id.in_(_sla_ticket_ids("breached"))).count()  # tickets, not SLA rows
    return {"tiles": [
        {"label": "Open", "count": query.count(), "tone": "", "url": ticket_list_link(viewer, opts, team, open=1)},
        {"label": "Priority 1 and 2", "count": urgent, "tone": "warn" if urgent else "",
         "url": ticket_list_link(viewer, opts, team, open=1, urgent=1)},
        {"label": "Unassigned", "count": unassigned, "tone": "warn" if unassigned else "",
         "url": ticket_list_link(viewer, opts, team, open=1, unassigned=1)},
        {"label": "SLA breached", "count": breached, "tone": "alert" if breached else "",
         "url": ticket_list_link(viewer, opts, team, sla="breached")},
    ]}


def _ticket_list(viewer, opts, team):
    query = _tickets(viewer, opts, team)
    show = opts.get("show", "open")
    if show != "recent":
        query = query.filter(Ticket.state.notin_(TERMINAL_TICKET))
    if show == "unassigned":
        query = query.filter(Ticket.assignee_id.is_(None))
    elif show in ("at_risk", "breached"):
        query = query.filter(Ticket.id.in_(_sla_ticket_ids(show)))
    order = {"priority": (Ticket.priority, Ticket.updated_at.desc()), "oldest": (Ticket.created_at,),
             "updated": (Ticket.updated_at.desc(),)}[opts.get("sort", "priority")]
    extra = {"recent": {}, "open": {"open": 1}, "unassigned": {"open": 1, "unassigned": 1}, "at_risk": {"sla": "at_risk"},
             "breached": {"sla": "breached"}}[show]
    return {"tickets": query.order_by(*order).limit(int(opts.get("limit", 5))).all(),
            "url": ticket_list_link(viewer, opts, team, **extra)}


def _ticket_chart(viewer, opts, team):
    query = _tickets(viewer, opts, team).filter(Ticket.state.notin_(TERMINAL_TICKET))
    by = opts.get("group_by", "priority")
    if by == "assignee":
        rows = [(name or tr("Unassigned"), count, user_id) for user_id, name, count in
                query.outerjoin(User, User.id == Ticket.assignee_id).with_entities(
                    Ticket.assignee_id, User.name, func.count(Ticket.id)).group_by(Ticket.assignee_id, User.name)]
    else:
        column = {"priority": Ticket.priority, "state": Ticket.state, "category": Ticket.category}[by]
        rows = [(value, count, value) for value, count in
                query.with_entities(column, func.count(Ticket.id)).group_by(column)]
    rows = sorted(rows, key=lambda row: (str(row[0]) if by == "priority" else -row[1], str(row[0])))
    total = sum(row[1] for row in rows)
    if len(rows) > 12:  # the rest as one bar, so the bars always add up to the total
        rows = rows[:11] + [(tr("Other"), sum(row[1] for row in rows[11:]), "__other__")]
    peak = max([row[1] for row in rows] or [1])

    def bar_url(key):
        if key == "__other__":
            return None  # "everything except the bars shown" is not a list filter
        if key is None and by == "assignee":
            return ticket_list_link(viewer, opts, team, open=1, unassigned=1)
        if key is None or key == "":
            return ticket_list_link(viewer, opts, team, open=1)
        return ticket_list_link(viewer, opts, team, open=1, **{by: key})

    return {"bars": [{"label": label or tr("None"), "count": count, "pct": max(2, round(count * 100 / peak)),
                      "url": bar_url(key)} for label, count, key in rows],
            "total": total, "url": ticket_list_link(viewer, opts, team, open=1)}


def _ticket_trend(viewer, opts, team):
    days = int(opts.get("days", 14))
    start = (now() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    base = _tickets(viewer, opts, team)
    opened = Counter(row[0].date() for row in base.filter(Ticket.created_at >= start)
                     .with_entities(Ticket.created_at).all())
    resolved = Counter(row[0].date() for row in base.filter(Ticket.resolved_at.isnot(None),
                                                            Ticket.resolved_at >= start)
                       .with_entities(Ticket.resolved_at).all())
    dates = [(start + timedelta(days=offset)).date() for offset in range(days)]
    peak = max([opened[d] for d in dates] + [resolved[d] for d in dates] + [1])
    return {"days": [{"date": d, "opened": opened[d], "resolved": resolved[d],
                      "opened_pct": round(opened[d] * 100 / peak), "resolved_pct": round(resolved[d] * 100 / peak)}
                     for d in dates],
            "peak": peak, "first": dates[0], "middle": dates[len(dates) // 2], "last": dates[-1],
            "opened_total": sum(opened[d] for d in dates), "resolved_total": sum(resolved[d] for d in dates)}


def _team_workload(viewer, opts, team):
    if team is None:
        return {"members": [], "missing_team": True}
    member_ids = {m.user_id for m in GroupMember.query.filter_by(group_id=team.id)}
    if team.manager_id:
        member_ids.add(team.manager_id)
    people = User.query.filter(User.id.in_(member_ids or {0}), User.active.is_(True)).order_by(User.name).all()
    tickets = dict(core.visible_ticket_query(viewer).filter(
        Ticket.assignee_id.in_(member_ids or {0}), Ticket.state.notin_(TERMINAL_TICKET), Ticket.deleted_at.is_(None))
        .with_entities(Ticket.assignee_id, func.count(Ticket.id)).group_by(Ticket.assignee_id).all())
    tasks = Counter()
    for model in (OperationalTask, CatalogTask):
        for assignee_id, count in db.session.query(model.assignee_id, func.count(model.id)).filter(
                model.assignee_id.in_(member_ids or {0}), model.state.notin_(TERMINAL_TASK),
                model.assignment_group_id == team.id).group_by(model.assignee_id):
            tasks[assignee_id] += count
    peak = max([tickets.get(p.id, 0) + tasks[p.id] for p in people] + [1])
    return {"members": [{"user": p, "tickets": tickets.get(p.id, 0), "tasks": tasks[p.id],
                         "pct": round((tickets.get(p.id, 0) + tasks[p.id]) * 100 / peak),
                         "ticket_pct": round(tickets.get(p.id, 0) * 100 / peak),
                         "task_pct": round(tasks[p.id] * 100 / peak),
                         "url": ticket_list_link(viewer, {"scope": "visible", "kind": "all"}, None,
                                                 assignee=p.id, open=1)}
                        for p in people]}


def _tasks(viewer, opts, team):
    rows = []
    for model in (OperationalTask, CatalogTask):
        # Rows written before tenant_id was backfilled are still bounded by the
        # assignee/team filters below, which are tenant-specific.
        query = model.query.filter(model.state.notin_(TERMINAL_TASK), db.or_(
            model.tenant_id == viewer.tenant_id, model.tenant_id.is_(None)))
        if opts.get("scope", "mine") == "team":
            if team is None:
                continue
            query = query.filter(model.assignment_group_id == team.id)
        else:
            query = query.filter(model.assignee_id == viewer.id)
        rows += query.limit(int(opts.get("limit", 5))).all()
    rows.sort(key=lambda t: ((getattr(t, "due_at", None) or getattr(t, "planned_end", None)) is None,
                             str(getattr(t, "due_at", None) or getattr(t, "planned_end", None) or "")))
    return {"tasks": [{"task": t, "url": core.record_url(t)} for t in rows[:int(opts.get("limit", 5))]],
            "url": url_for("my_work_tasks")}


def _approvals(viewer, opts, team):
    votes = ApprovalVote.query.join(ApprovalGate).join(ApprovalChain).filter(
        ApprovalVote.approver_id == viewer.id, ApprovalVote.state == "Requested",
        ApprovalChain.tenant_id == viewer.tenant_id).limit(int(opts.get("limit", 5))).all()
    rows = []
    for vote in votes:
        record = core.record_reference(vote.gate.chain.target_type, vote.gate.chain.target_id)
        rows.append({"vote": vote, "number": core.record_number(record) if record else vote.gate.chain.name,
                     "title": getattr(record, "title", None) if record else None,
                     "url": core.record_url(record) if record else url_for("approval_chains")})
    return {"approvals": rows, "url": url_for("approval_chains")}


def _upcoming_changes(viewer, opts, team):
    days = int(opts.get("days", 7))
    query = _tickets(viewer, dict(opts, kind="change"), team).join(
        ChangeGovernance, ChangeGovernance.ticket_id == Ticket.id).filter(
        ChangeGovernance.planned_start >= now() - timedelta(hours=12),
        ChangeGovernance.planned_start <= now() + timedelta(days=days),
        Ticket.state.notin_(TERMINAL_TICKET))
    rows = query.with_entities(Ticket, ChangeGovernance).order_by(ChangeGovernance.planned_start) \
        .limit(int(opts.get("limit", 5))).all()
    return {"changes": [{"ticket": t, "governance": g} for t, g in rows]}


def _requests(viewer, opts, team):
    limit = int(opts.get("limit", 5))
    if opts.get("scope", "mine") == "team":
        if team is None:
            return {"items": []}
        routed = db.session.query(CatalogItemRouting.catalog_item_id).filter(
            CatalogItemRouting.support_group_id == team.id)
        query = RequestedItem.query.join(CatalogRequest).filter(
            CatalogRequest.id.in_(core.visible_catalog_request_query(viewer).with_entities(CatalogRequest.id)),
            RequestedItem.catalog_item_id.in_(routed), RequestedItem.state.notin_(TERMINAL_ITEM))
    else:
        query = RequestedItem.query.join(CatalogRequest).filter(
            CatalogRequest.tenant_id == viewer.tenant_id,
            (CatalogRequest.requested_for_id == viewer.id) | (CatalogRequest.requested_by_id == viewer.id))
        if opts.get("show", "open") == "open":
            query = query.filter(RequestedItem.state.notin_(TERMINAL_ITEM))
    return {"items": query.order_by(CatalogRequest.opened_at.desc()).limit(limit).all(),
            "url": url_for("requests_list")}


def _knowledge(viewer, opts, team):
    from serviceops_models import Knowledge
    query = core.visible_knowledge_query(viewer).filter(Knowledge.published.is_(True),
                                                        Knowledge.archived.is_(False))
    return {"articles": query.order_by(Knowledge.created_at.desc()).limit(int(opts.get("limit", 5))).all(),
            "url": url_for("knowledge")}


def _work_items(viewer, opts, team):
    from serviceops_core.projects import service as projects
    if not projects.enabled():
        return {"items": [], "disabled": True}
    return {"items": projects.my_open_items(viewer, limit=int(opts.get("limit", 5))),
            "url": url_for("projects.my_items")}


def _favorites(viewer, opts, team):
    return {"favorites": Favorite.query.filter_by(user_id=viewer.id).order_by(Favorite.created_at.desc())
            .limit(int(opts.get("limit", 5))).all()}


def _recently_viewed(viewer, opts, team):
    return {"views": RecentView.query.filter_by(user_id=viewer.id).order_by(RecentView.viewed_at.desc())
            .limit(int(opts.get("limit", 5))).all()}


def _notifications(viewer, opts, team):
    return {"notifications": Notification.query.filter_by(user_id=viewer.id).order_by(
        Notification.read.asc(), Notification.created_at.desc()).limit(int(opts.get("limit", 5))).all()}


def _note(viewer, opts, team):
    return {"paragraphs": [p for p in (opts.get("text") or "").split("\n\n") if p.strip()]}


def _links(viewer, opts, team):
    return {"links": parse_links(opts.get("links") or "")}


def parse_links(text):
    """'Label | /internal/path' per line; only internal paths are kept."""
    links = []
    for line in (text or "").splitlines():
        if "|" not in line:
            continue
        label, path = (part.strip() for part in line.split("|", 1))
        if label and core.is_safe_internal_path(path):
            links.append({"label": label[:80], "url": path})
    return links[:20]


WIDGETS = {
    "ticket_counts": _widget(
        "Ticket counts", "Open, priority 1 and 2, unassigned and SLA-breached tickets, each opening the list.",
        _ticket_counts, span=3, options={"scope": SCOPE, "kind": KIND, "team": TEAM}, icon="▦", category="Tickets"),
    "ticket_list": _widget(
        "Ticket list", "Open, unassigned, at-risk, breached or recently updated tickets.", _ticket_list, span=2,
        options={"scope": SCOPE, "kind": KIND, "team": TEAM,
                 "show": _choice("Which", [("open", "Open"), ("unassigned", "Unassigned"),
                                           ("at_risk", "SLA at risk"), ("breached", "SLA breached"),
                                           ("recent", "Recently updated")], "open"),
                 "sort": _choice("Sort by", [("priority", "Priority"), ("updated", "Last updated"),
                                             ("oldest", "Oldest first")], "priority"),
                 "limit": LIMIT}, icon="☰", category="Tickets"),
    "ticket_chart": _widget(
        "Ticket chart", "Open tickets as a bar chart by priority, state, category or assignee.", _ticket_chart,
        options={"scope": SCOPE, "kind": KIND, "team": TEAM,
                 "group_by": _choice("Group by", [("priority", "Priority"), ("state", "State"),
                                                  ("category", "Category"), ("assignee", "Assignee")],
                                     "priority")}, icon="▥", category="Charts"),
    "ticket_trend": _widget(
        "Opened and resolved", "Tickets opened and resolved per day.", _ticket_trend, span=2,
        options={"scope": SCOPE, "kind": KIND, "team": TEAM,
                 "days": _choice("Period", [("7", "7 days"), ("14", "14 days"), ("30", "30 days")], "14")}, icon="◢", category="Charts"),
    "team_workload": _widget(
        "Team workload", "Open tickets and tasks per team member.", _team_workload, options={"team": TEAM}, icon="⚖", category="Charts"),
    "tasks": _widget(
        "Open tasks", "Change, problem and catalog tasks for you or your team.", _tasks,
        options={"scope": _choice("Show", [("mine", "Assigned to me"), ("team", "My team")], "mine"),
                 "team": TEAM, "limit": LIMIT}, icon="✓", category="Work"),
    "approvals": _widget(
        "Approvals awaiting me", "Decisions waiting for you, linked to their records.", _approvals,
        scopes=("personal",), options={"limit": LIMIT}, icon="✔", category="Work"),
    "upcoming_changes": _widget(
        "Upcoming changes", "Changes planned to start soon.", _upcoming_changes, span=2,
        options={"scope": SCOPE, "team": TEAM,
                 "days": _choice("Window", [("1", "24 hours"), ("7", "7 days"), ("30", "30 days")], "7"),
                 "limit": LIMIT}, icon="◷", category="Work"),
    "requests": _widget(
        "Catalog requests", "Your requests, or open requested items your team fulfils.", _requests,
        options={"scope": _choice("Show", [("mine", "My requests"), ("team", "My team fulfils")], "mine"),
                 "team": TEAM, "show": _choice("Which", [("open", "Open"), ("all", "All")], "open"),
                 "limit": LIMIT}, icon="⇄", category="Work"),
    "knowledge": _widget("New knowledge", "Recently published knowledge articles.", _knowledge,
                         options={"limit": LIMIT}, icon="✎", category="Content"),
    "work_items": _widget("My work items", "Open project work items assigned to you.", _work_items,
                          scopes=("personal",), options={"limit": LIMIT}, icon="◆", category="Work"),
    "favorites": _widget("Favorites", "Pages you have starred.", _favorites, scopes=("personal",),
                         options={"limit": LIMIT}, icon="★", category="Personal"),
    "recently_viewed": _widget("Recently viewed", "Records and pages you opened recently.", _recently_viewed,
                               scopes=("personal",), options={"limit": LIMIT}, icon="↺", category="Personal"),
    "notifications": _widget("Notifications", "Your latest notifications.", _notifications,
                             scopes=("personal",), options={"limit": LIMIT}, icon="♪", category="Personal"),
    "note": _widget("Note", "Text for yourself or your team, such as an on-call rota or announcement.", _note,
                    options={"text": {"type": "textarea", "label": "Text", "max": 2000}}, icon="✍", category="Content"),
    "links": _widget("Links", "Shortcuts to pages in ServiceOps, one 'Label | /path' per line.", _links,
                     options={"links": {"type": "textarea", "label": "Links", "max": 2000,
                                        "help": "One per line: Label | /path, for example Network changes | "
                                                "/tickets/change"}}, icon="↗", category="Content"),
}

# My Workspace (B-121) widget keys and the configured widget each becomes.
LEGACY = {
    "ticket_stats": ("ticket_counts", {"scope": "visible", "kind": "all"}),
    "my_open_tickets": ("ticket_list", {"scope": "mine", "kind": "all", "show": "open"}),
    "recent_tickets": ("ticket_list", {"scope": "visible", "kind": "all", "show": "recent", "sort": "updated"}),
    "sla_at_risk": ("ticket_list", {"scope": "visible", "kind": "all", "show": "at_risk"}),
    "approvals_awaiting_me": ("approvals", {}),
    "favorites": ("favorites", {}),
    "recently_viewed": ("recently_viewed", {}),
    "notifications": ("notifications", {}),
}
DEFAULT_PERSONAL = [("ticket_counts", 3, {"scope": "mine", "kind": "all"}),
                    ("ticket_list", 2, {"scope": "mine", "kind": "all"}),
                    ("approvals", 1, {}),
                    ("tasks", 1, {"scope": "mine"}),
                    ("upcoming_changes", 2, {"scope": "mine"})]
# A manager starts from the team's view, not only what is assigned to them
# personally (a manager's own counts are usually all zero).
DEFAULT_PERSONAL_TEAM = [("ticket_counts", 3, {"scope": "team", "kind": "all"}),
                         ("ticket_list", 2, {"scope": "team", "kind": "all", "show": "unassigned"}),
                         ("approvals", 1, {}),
                         ("tasks", 1, {"scope": "team"}),
                         ("upcoming_changes", 2, {"scope": "team"})]
DEFAULT_GROUP = [("ticket_counts", 3, {"scope": "team", "kind": "all"}),
                 ("ticket_list", 2, {"scope": "team", "kind": "incident", "show": "unassigned"}),
                 ("team_workload", 1, {}),
                 ("ticket_chart", 1, {"scope": "team", "kind": "incident", "group_by": "priority"}),
                 ("ticket_trend", 2, {"scope": "team", "kind": "incident"})]


def widget_enabled(key):
    return core.setting_bool(f"DASHBOARD_WIDGET_{key.upper()}_ENABLED", True)


def catalog(scope):
    return {key: w for key, w in WIDGETS.items() if scope in w["scopes"] and widget_enabled(key)}


# --- access ------------------------------------------------------------------------------------

def member_groups(user):
    """Active groups the person belongs to or manages, by name."""
    ids = core.user_support_group_ids(user)
    if not ids:
        return []
    return SupportGroup.query.filter(SupportGroup.id.in_(ids), SupportGroup.active.is_(True),
                                     SupportGroup.tenant_id == user.tenant_id).order_by(SupportGroup.name).all()


def _is_admin(user):
    return core.role_at_least(user.effective_role, "admin")


def can_view(user, dashboard):
    if dashboard.tenant_id != user.tenant_id:
        return False
    if dashboard.scope == "personal":
        return dashboard.owner_id == user.id
    return _is_admin(user) or dashboard.group_id in core.user_support_group_ids(user)


def can_manage_group(user, group):
    if group is None or group.tenant_id != user.tenant_id:
        return False
    if _is_admin(user) or group.manager_id == user.id:
        return True
    return GroupMember.query.filter_by(group_id=group.id, user_id=user.id, role="manager").first() is not None


def can_edit(user, dashboard):
    if not can_view(user, dashboard):
        return False
    return dashboard.owner_id == user.id if dashboard.scope == "personal" else can_manage_group(user, dashboard.group)


def dashboard_or_404(user, dashboard_id, edit=False):
    dashboard = Dashboard.query.filter_by(id=dashboard_id, tenant_id=user.tenant_id).first()
    if dashboard is None or not can_view(user, dashboard):
        abort(404)
    if edit and not can_edit(user, dashboard):
        abort(403, description=tr("Only the dashboard's owner, or for a team dashboard its manager or an "
                                  "administrator, can change it."))
    return dashboard


def visible_dashboards(user):
    """(personal dashboards, [(group, dashboards)]) the person can open."""
    personal = Dashboard.query.filter_by(tenant_id=user.tenant_id, scope="personal", owner_id=user.id) \
        .order_by(Dashboard.position, Dashboard.id).all()
    groups = member_groups(user)
    shared = Dashboard.query.filter(Dashboard.tenant_id == user.tenant_id, Dashboard.scope == "group",
                                    Dashboard.group_id.in_([g.id for g in groups] or [0])) \
        .order_by(Dashboard.position, Dashboard.id).all()
    return personal, [(g, [d for d in shared if d.group_id == g.id]) for g in groups]


# --- options -----------------------------------------------------------------------------------

def options_of(widget):
    try:
        value = json.loads(widget.options_json or "{}")
    except ValueError:
        value = {}
    return value if isinstance(value, dict) else {}


def clean_options(user, dashboard, key, form):
    """Validate a widget's options from a submitted form against its schema."""
    schema = WIDGETS[key]["options"]
    cleaned = {}
    for name, spec in schema.items():
        raw = form.get(f"opt_{name}")
        if spec["type"] == "choice":
            allowed = [value for value, _ in spec["choices"]]
            cleaned[name] = raw if raw in allowed else spec["default"]
            # A shared dashboard has no single "me": its people-scoped widgets show the team.
            if name == "scope" and dashboard.scope == "group" and cleaned[name] == "mine":
                cleaned[name] = "team"
        elif spec["type"] == "textarea":
            text = (raw or "").replace("\r\n", "\n").strip()
            if len(text) > spec["max"]:
                abort(400, description=tr("{label} has at most {max} characters.", label=tr(spec["label"]),
                                          max=spec["max"]))
            cleaned[name] = text
        elif spec["type"] == "team" and dashboard.scope == "personal":
            allowed = {str(g.id) for g in member_groups(user)}
            if raw in allowed:
                cleaned[name] = int(raw)
    return cleaned


def team_for(viewer, dashboard, opts):
    """The team a widget is about: the dashboard's group, or the chosen team on a
    personal dashboard -- only while the viewer still belongs to it."""
    if dashboard.scope == "group":
        return dashboard.group
    team_id = opts.get("team")
    if team_id and team_id in core.user_support_group_ids(viewer):
        return db.session.get(SupportGroup, team_id)
    return core.primary_team(viewer) or next(iter(member_groups(viewer)), None)


def render_context(viewer, dashboard):
    """Each widget with its data, as the viewer may see it."""
    rendered = []
    for widget in dashboard.widgets:
        spec = WIDGETS.get(widget.widget_key)
        if spec is None or not widget_enabled(widget.widget_key) or dashboard.scope not in spec["scopes"]:
            continue
        opts = options_of(widget)
        team = team_for(viewer, dashboard, opts)
        rendered.append({"widget": widget, "key": widget.widget_key, "spec": spec, "opts": opts, "team": team,
                         "title": widget.title or tr(spec["label"]), "data": spec["data"](viewer, opts, team)})
    return rendered


# --- changes -----------------------------------------------------------------------------------

def _touch(actor, dashboard):
    dashboard.updated_by_id, dashboard.updated_at = actor.id, now()


def _check_name(name):
    name = (name or "").strip()
    if not 0 < len(name) <= 80:
        abort(400, description=tr("A dashboard name has 1 to 80 characters."))
    return name


def create_dashboard(actor, name, group=None, description="", widgets=None):
    if group is not None and not can_manage_group(actor, group):
        abort(403, description=tr("Only the team's manager or an administrator can add a team dashboard."))
    owner_filter = {"group_id": group.id} if group is not None else {"owner_id": actor.id}
    count = Dashboard.query.filter_by(tenant_id=actor.tenant_id, **owner_filter).count()
    if count >= MAX_DASHBOARDS:
        abort(409, description=tr("There can be at most {count} dashboards here.", count=MAX_DASHBOARDS))
    dashboard = Dashboard(tenant_id=actor.tenant_id, scope="group" if group is not None else "personal",
                          owner_id=None if group is not None else actor.id,
                          group_id=group.id if group is not None else None, name=_check_name(name),
                          description=(description or "").strip()[:255], position=count,
                          created_by_id=actor.id, updated_by_id=actor.id)
    db.session.add(dashboard)
    db.session.flush()
    for position, (key, span, opts) in enumerate(widgets or []):
        db.session.add(DashboardWidget(tenant_id=actor.tenant_id, dashboard_id=dashboard.id, widget_key=key,
                                       span=span, position=position, options_json=json.dumps(opts)))
    db.session.flush()
    core.audit("dashboard created", dashboard.name, f"scope={dashboard.scope}"
               + (f"; group={group.name}" if group is not None else ""), user_id=actor.id,
               tenant_id=actor.tenant_id)
    return dashboard


def update_dashboard(actor, dashboard, name, description):
    dashboard.name = _check_name(name)
    dashboard.description = (description or "").strip()[:255]
    _touch(actor, dashboard)
    core.audit("dashboard updated", dashboard.name, "", user_id=actor.id, tenant_id=actor.tenant_id)


def delete_dashboard(actor, dashboard):
    core.audit("dashboard deleted", dashboard.name, f"scope={dashboard.scope}", user_id=actor.id,
               tenant_id=actor.tenant_id)
    DashboardHome.query.filter_by(dashboard_id=dashboard.id).delete(synchronize_session=False)
    db.session.delete(dashboard)


def copy_dashboard(actor, source):
    copy = create_dashboard(actor, tr("{name} (copy)", name=source.name)[:80], description=source.description)
    for widget in source.widgets:
        opts = options_of(widget)
        if source.scope == "group" and "team" in WIDGETS.get(widget.widget_key, {}).get("options", {}):
            opts["team"] = source.group_id  # keeps showing the same team
        db.session.add(DashboardWidget(tenant_id=actor.tenant_id, dashboard_id=copy.id, widget_key=widget.widget_key,
                                       title=widget.title, span=widget.span, position=widget.position,
                                       options_json=json.dumps(opts)))
    db.session.flush()
    return copy


def add_widget(actor, dashboard, key):
    if key not in catalog(dashboard.scope):
        abort(400, description=tr("Choose a widget from the list."))
    if len(dashboard.widgets) >= MAX_WIDGETS:
        abort(409, description=tr("A dashboard holds at most {count} widgets.", count=MAX_WIDGETS))
    spec = WIDGETS[key]
    opts = {name: spec_["default"] for name, spec_ in spec["options"].items() if spec_["type"] == "choice"}
    if dashboard.scope == "group" and opts.get("scope") == "mine":
        opts["scope"] = "team"
    widget = DashboardWidget(tenant_id=actor.tenant_id, dashboard_id=dashboard.id, widget_key=key,
                             span=spec["default_span"], position=len(dashboard.widgets),
                             options_json=json.dumps(opts))
    db.session.add(widget)
    _touch(actor, dashboard)
    db.session.flush()
    core.audit("dashboard widget added", dashboard.name, key, user_id=actor.id, tenant_id=actor.tenant_id)
    return widget


def widget_or_404(dashboard, widget_id):
    widget = DashboardWidget.query.filter_by(id=widget_id, dashboard_id=dashboard.id).first()
    if widget is None:
        abort(404)
    return widget


def update_widget(actor, dashboard, widget, form):
    title = (form.get("title") or "").strip()
    if len(title) > 120:
        abort(400, description=tr("A widget title has at most 120 characters."))
    widget.title = title or None
    try:
        span = int(form.get("span", widget.span))
    except ValueError:
        span = widget.span
    widget.span = span if span in SPANS else widget.span
    widget.options_json = json.dumps(clean_options(actor, dashboard, widget.widget_key, form))
    _touch(actor, dashboard)
    core.audit("dashboard widget updated", dashboard.name, widget.widget_key, user_id=actor.id,
               tenant_id=actor.tenant_id)


def remove_widget(actor, dashboard, widget):
    core.audit("dashboard widget removed", dashboard.name, widget.widget_key, user_id=actor.id,
               tenant_id=actor.tenant_id)
    db.session.delete(widget)
    db.session.flush()
    for position, row in enumerate(DashboardWidget.query.filter_by(dashboard_id=dashboard.id)
                                   .order_by(DashboardWidget.position)):
        row.position = position
    _touch(actor, dashboard)


def reorder_widgets(actor, dashboard, ordered_ids):
    """Apply a new order; ids not on this dashboard are ignored, missing ones keep their order at the end."""
    widgets = {w.id: w for w in dashboard.widgets}
    order = [widgets[i] for i in ordered_ids if i in widgets]
    order += [w for w in dashboard.widgets if w not in order]
    for position, widget in enumerate(order):
        widget.position = position
    _touch(actor, dashboard)
    core.audit("dashboard rearranged", dashboard.name, "", user_id=actor.id, tenant_id=actor.tenant_id)


def move_widget(actor, dashboard, widget, direction):
    order = list(dashboard.widgets)
    index = order.index(widget)
    other = index + (-1 if direction == "up" else 1)
    if 0 <= other < len(order):
        order[index], order[other] = order[other], order[index]
        reorder_widgets(actor, dashboard, [w.id for w in order])


def set_home(actor, dashboard):
    home = db.session.get(DashboardHome, actor.id)
    if home is None:
        db.session.add(DashboardHome(user_id=actor.id, tenant_id=actor.tenant_id, dashboard_id=dashboard.id))
    else:
        home.dashboard_id = dashboard.id
    core.audit("dashboard home set", dashboard.name, "", user_id=actor.id, tenant_id=actor.tenant_id)


def home_dashboard(user):
    """The dashboard to open: the chosen home while still visible, else the first
    personal one (created from My Workspace, or the defaults, on first use)."""
    home = db.session.get(DashboardHome, user.id)
    if home is not None:
        dashboard = db.session.get(Dashboard, home.dashboard_id)
        if dashboard is not None and can_view(user, dashboard):
            return dashboard
    personal, _ = visible_dashboards(user)
    if personal:
        return personal[0]
    return ensure_personal(user)


def ensure_personal(user):
    layout = UserWorkspaceLayout.query.filter_by(user_id=user.id).one_or_none()
    widgets = []
    if layout and isinstance(layout.layout_json, list):
        for item in layout.layout_json:
            if isinstance(item, dict) and item.get("widget_key") in LEGACY:
                key, opts = LEGACY[item["widget_key"]]
                widgets.append((key, 3 if item.get("span") == 2 and key != "ticket_counts" else
                                WIDGETS[key]["default_span"], dict(opts)))
    # A manager starts from the team's work; agents start from what is assigned to them.
    default = DEFAULT_PERSONAL_TEAM if user.effective_role == "manager" and core.primary_team(user) else DEFAULT_PERSONAL
    dashboard = create_dashboard(user, tr("My dashboard"), widgets=widgets or default)
    dashboard.updated_by_id = None  # created automatically, not changed by the person
    db.session.commit()
    return dashboard
