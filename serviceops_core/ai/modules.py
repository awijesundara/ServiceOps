"""Reach across the whole product for the chat assistant: requests, problems and other records, approvals, tasks,
service-level breaches, knowledge, configuration items and assets, plus an honest map of what the asker may open.

Every function is read-only and runs under the asker's identity, using the same visibility helpers as the rest of
the application (never a wider query of its own). What is handed to the model is aggregate counts and a few recent
records, as plain facts. People, the audit log, customer data content, settings and secrets are never included; an
administrator additionally gets head-counts of accounts by role (numbers only).
"""
import re
from datetime import timedelta

from sqlalchemy import func

from serviceops_core.ai import access
from serviceops_core.ci_class_policy import ci_class_read_allowed
from serviceops_core.navigation import NAVIGATION_ENTRIES
from serviceops_models import (ApprovalVote, Asset, CatalogRequest, CatalogTask, ClientTicket, ConfigurationItem, EnterpriseRecord,
                               Knowledge, OperationalTask, RequestedItem, TaskSLA, Ticket, User, db, now)

CLOSED = ("Resolved", "Closed", "Cancelled", "Canceled", "Completed", "Implemented", "Fulfilled", "Complete")

_INTENTS = {
    "breaches": r"breach|overdue|violat|at risk|running late|missed (the )?(sla|target)",
    "requests": r"\brequests?\b|\britms?\b|\bsctask|catalog task|fulfil|\bordered\b",
    "records": r"\bproblems?\b|\bprb\b|known errors?|\bevents?\b|\balerts?\b|improvement|\brisks?\b|security incident|\bsir\b|\bhr\b|portfolio|\bprojects?\b|field service|work orders?|customer service",
    "approvals": r"approv|awaiting (my|your)|pending (my|your)|sign[- ]?off|\bccb\b",
    "tasks": r"\btasks?\b|my work|assigned to me|to[- ]?do|workload|\bctask|\bptask",
    "knowledge": r"knowledge|\bkb\b|articles?|notes?\b|how[- ]to|documentation",
    "cmdb": r"\bcmdb\b|configuration items?|\bcis\b|\bci\b|servers?|hardware|inventory|assets?|dell|vmware|network device|laptops?|infrastructure",
    "users": r"\busers\b|\baccounts\b|head ?count|how many (staff|people|employees)|who is the admin|admins?\b",
    "clients": r"customers?\b|clients?\b|customer tickets?|client organi[sz]ations?",
    "access": r"can'?t access|cannot access|no access|not allowed|sections?|what can i (see|open|use|access)|permissions?|\bmenu\b|modules?|features?|what.*(cannot|can'?t).*(access|see)|restricted",
}
_COMPILED = {name: re.compile(pattern, re.I) for name, pattern in _INTENTS.items()}


def module_intents(question):
    return {name for name, pattern in _COMPILED.items() if pattern.search(question or "")}


def _rank(role):
    from app import role_at_least
    return lambda minimum: role_at_least(role, minimum)


def _breaches(scope, base):
    ids = base.with_entities(Ticket.id)
    at = now()
    live = TaskSLA.query.filter(TaskSLA.target_type == "ticket", TaskSLA.target_id.in_(ids), TaskSLA.stopped_at.is_(None))
    breached = live.filter(TaskSLA.breached.is_(True)).count()
    soon = live.filter(TaskSLA.breached.is_(False), TaskSLA.breach_at <= at + timedelta(hours=2)).count()
    ever = TaskSLA.query.filter(TaskSLA.target_type == "ticket", TaskSLA.target_id.in_(ids), TaskSLA.breached.is_(True)).count()
    return "Service level breaches (tickets you can see)", (
        f"{breached} open tickets have breached a service level target; {soon} more will breach within two hours; "
        f"{ever} tickets have breached a target at some point.")


def _requests(scope, evidence):
    from app import visible_catalog_request_query
    visible = visible_catalog_request_query(scope.identity)
    ids = visible.with_entities(CatalogRequest.id)
    states = dict(visible.with_entities(CatalogRequest.state, func.count()).group_by(CatalogRequest.state).all())
    items = dict(RequestedItem.query.filter(RequestedItem.request_id.in_(ids)).with_entities(RequestedItem.state, func.count())
                 .group_by(RequestedItem.state).all())
    mine = visible.filter(CatalogRequest.requested_for_id == scope.user_id, ~CatalogRequest.state.in_(CLOSED)).count()
    recent = [f"{r.number} ({r.state})" for r in visible.order_by(CatalogRequest.opened_at.desc()).limit(5)]
    text = (f"Requests you can see: " + (", ".join(f"{n} {s}" for s, n in sorted(states.items())) or "none") +
            f". Requested items: " + (", ".join(f"{n} {s}" for s, n in sorted(items.items())) or "none") +
            f". {mine} open requests are for you." + (f" Most recent: {'; '.join(recent)}." if recent else ""))
    return "Service requests", text


def _records(scope):
    from app import DOMAIN_CONFIG, visible_enterprise_record_query
    visible = visible_enterprise_record_query(scope.identity)
    rows = visible.with_entities(EnterpriseRecord.domain, EnterpriseRecord.state, func.count()).group_by(
        EnterpriseRecord.domain, EnterpriseRecord.state).all()
    if not rows:
        return "Problems, events and other records", "You can currently see no problem, event or other operational records."
    per = {}
    for domain, state, total in rows:
        entry = per.setdefault(domain, {"total": 0, "open": 0})
        entry["total"] += total
        if state not in CLOSED:
            entry["open"] += total
    parts = [f"{DOMAIN_CONFIG.get(d, {}).get('name', d)}: {v['total']} ({v['open']} open)" for d, v in sorted(per.items())]
    recent = [f"{r.number} {r.title[:60]} ({r.state})" for r in visible.order_by(EnterpriseRecord.updated_at.desc()).limit(5)]
    return "Problems, events and other records", "; ".join(parts) + ". Most recently updated: " + "; ".join(recent) + "."


def _approvals(scope):
    waiting = ApprovalVote.query.filter_by(tenant_id=scope.tenant_id, approver_id=scope.user_id, state="Requested").count()
    return "Approvals", (f"{waiting} approvals are waiting for your decision." if waiting
                        else "No approvals are waiting for your decision.")


def _tasks(scope):
    mine = OperationalTask.query.filter(OperationalTask.assignee_id == scope.user_id, ~OperationalTask.state.in_(CLOSED)).count()
    fulfil = CatalogTask.query.filter(CatalogTask.assignee_id == scope.user_id, ~CatalogTask.state.in_(CLOSED)).count()
    return "Your tasks", f"{mine} change or problem tasks and {fulfil} fulfilment tasks are assigned to you and still open."


def _knowledge(scope):
    rows = dict(Knowledge.query.filter_by(tenant_id=scope.tenant_id, published=True, archived=False).with_entities(
        Knowledge.category, func.count()).group_by(Knowledge.category).all())
    total = sum(rows.values())
    return "Knowledge base", (f"{total} published articles" + (": " + ", ".join(f"{c or 'General'} {n}" for c, n in sorted(
        rows.items(), key=lambda x: -x[1])[:8]) if rows else "") + ".")


def _cmdb(scope):
    if not scope.can_read_cmdb:
        return "Configuration items and assets", "Your access level does not include the configuration database or asset inventory."
    per = {}
    for ci_class, environment, total in ConfigurationItem.query.filter_by(tenant_id=scope.tenant_id).with_entities(
            ConfigurationItem.ci_class, ConfigurationItem.environment, func.count()).group_by(
            ConfigurationItem.ci_class, ConfigurationItem.environment).all():
        if ci_class_read_allowed(scope.tenant_id, ci_class, scope.role):
            per[ci_class] = per.get(ci_class, 0) + total
    text = ("Configuration items you may read: " + (", ".join(f"{c} {n}" for c, n in sorted(per.items(), key=lambda x: -x[1])[:10])
                                                     or "none") + f" ({sum(per.values())} in total).")
    assets = dict(Asset.query.filter_by(tenant_id=scope.tenant_id).with_entities(Asset.status, func.count()).group_by(Asset.status).all())
    if assets:
        text += " Assets by status: " + ", ".join(f"{s} {n}" for s, n in sorted(assets.items())) + "."
    return "Configuration items and assets", text


def _users(scope):
    if not _rank(scope.role)("admin"):
        return "Accounts", "Head-counts of accounts are only available to administrators."
    rows = db.session.query(User.role, func.count()).filter(User.tenant_id == scope.tenant_id, User.active.is_(True)).group_by(User.role).all()
    return "Accounts (numbers only)", (f"{sum(n for _, n in rows)} active accounts: " + ", ".join(f"{n} {r}" for r, n in sorted(rows)) +
                                       ". Names and contact details are never shared by the assistant.")


def _clients(scope):
    from app import user_can_access_client_management, visible_client_organization_query, visible_client_ticket_query
    if not user_can_access_client_management(scope.identity):
        return "Customer management", "Your access level does not include customer management."
    organizations = visible_client_organization_query(scope.identity).filter_by(active=True).count()
    rows = dict(visible_client_ticket_query(scope.identity).with_entities(ClientTicket.status, func.count()).group_by(
        ClientTicket.status).all())
    return "Customer management (numbers only)", (f"Client organizations you can see: {organizations}. Customer tickets you can see: " + (", ".join(f"{n} {s}" for s, n in sorted(rows.items()))
                                                    or "none") + ". Customer names and messages are never shared by the assistant.")


def _access_map(scope):
    """What this person can and cannot open, from the same catalogue the search bar and menu use."""
    from app import user_can_access_client_management
    allowed = _rank(scope.role)
    can_clients = user_can_access_client_management(scope.identity)
    open_to, closed_to = [], []
    for entry in NAVIGATION_ENTRIES:
        ok = (not entry.minimum_role or allowed(entry.minimum_role)) and (not entry.client_management or can_clients)
        (open_to if ok else closed_to).append(entry.label)
    return "What you can and cannot open in ServiceOps", (
        f"You can open: {', '.join(open_to[:40])}. " +
        (f"Your access level does not include: {', '.join(closed_to[:30])}." if closed_to else "Nothing is restricted for your access level."))


def suggested_pages(scope, question, limit=3):
    """Pages worth opening for this question (only ones this person may open), as endpoint names the route turns into links."""
    from app import user_can_access_client_management
    allowed = _rank(scope.role)
    can_clients = user_can_access_client_management(scope.identity)
    words = (set(access.keywords(question, limit=10)) | set(access.expanded_keywords(question))) - {
        "active", "open", "current", "show", "view", "list", "run", "display", "get",
    }
    lowered = (question or "").lower()

    def intent_boost(entry):
        """Keep generic words such as 'active' from suggesting Active sessions for an active-change question."""
        if re.search(r"\bchanges?\b", lowered) and entry.params.get("kind") == "change":
            return 20
        if re.search(r"\bincidents?\b", lowered) and entry.params.get("kind") == "incident":
            return 20
        targets = (
            (r"\b(cmdb|configuration item|serial number|servers?)\b", "CMDB and service map"),
            (r"\b(knowledge|articles?|notes?)\b", "Knowledge"),
            (r"\bservice (status|health)\b", "Service offerings"),
            (r"\b(freeze|blackout)\b", "Change freeze windows"),
            (r"\b(ccb|change control board)\b", "Change Control Board"),
            (r"\bclients?\b", "Client organizations"),
        )
        return 20 if any(re.search(pattern, lowered) and entry.label == label for pattern, label in targets) else 0

    scored = []
    for entry in NAVIGATION_ENTRIES:
        if entry.minimum_role and not allowed(entry.minimum_role):
            continue
        if entry.client_management and not can_clients:
            continue
        hay = f"{entry.label} {entry.keywords}".lower()
        score = intent_boost(entry) + sum(1 for w in words if w and w in hay)
        if score:
            scored.append((-score, entry.label, entry))
    scored.sort(key=lambda t: t[:2])
    return [{"label": e.label, "endpoint": e.endpoint, "params": dict(e.params)} for _, _, e in scored[:limit]]


def add_module_context(scope, question, evidence, base):
    found = module_intents(question)
    builders = []
    if "breaches" in found:
        builders.append(lambda: _breaches(scope, base))
    if "requests" in found:
        builders.append(lambda: _requests(scope, evidence))
    if "records" in found:
        builders.append(lambda: _records(scope))
    if "approvals" in found:
        builders.append(lambda: _approvals(scope))
    if "tasks" in found:
        builders.append(lambda: _tasks(scope))
    if "knowledge" in found:
        builders.append(lambda: _knowledge(scope))
    if "cmdb" in found:
        builders.append(lambda: _cmdb(scope))
    if "users" in found:
        builders.append(lambda: _users(scope))
    if "clients" in found:
        builders.append(lambda: _clients(scope))
    if "access" in found:
        builders.append(lambda: _access_map(scope))
    for build in builders:
        title, text = build()
        evidence.add_context("info", title, text)
