"""Reach across the whole product for the chat assistant: requests, problems and other records, approvals, tasks,
service-level breaches, knowledge, configuration items and assets, plus an honest map of what the asker may open.

Every function is read-only and runs under the asker's identity, using the same visibility helpers as the rest of
the application (never a wider query of its own). What is handed to the model is aggregate counts and a few recent
records, as plain facts. Directory contacts, the audit log, attachments, settings and secrets are never included.
Customer-ticket content, service-request variables and restricted operational records are always marked private so
they cannot leave the organization; an administrator additionally gets head-counts of accounts by role (numbers only).
"""
import json
import re
from datetime import timedelta

from sqlalchemy import func

from serviceops_core.ai import access
from serviceops_core.ci_class_policy import ci_class_read_allowed
from serviceops_core.navigation import NAVIGATION_ENTRIES
from serviceops_models import (ApprovalVote, Asset, CatalogRequest, CatalogTask, ClientTicket, ClientTicketMessage,
                               ConfigurationItem, EnterpriseRecord, Knowledge, OperationalTask, RequestedItem, SupportGroup,
                               TaskNote, TaskSLA, Ticket, TicketAssignmentGroup, User, db, now)

CLOSED = ("Resolved", "Closed", "Cancelled", "Canceled", "Completed", "Implemented", "Fulfilled", "Complete")

_INTENTS = {
    "breaches": r"breach|overdue|violat|at risk|running late|missed (the )?(sla|target)",
    "requests": r"\brequests?\b|\b(?:REQ|RITM|SCTASK)\d+\b|\britms?\b|\bsctask|catalog task|fulfil|\bordered\b",
    "records": r"\b(?:PRB|CS|HRC|SIR|RSK|PRJ|WO|EVT|REL)\d+\b|\bproblems?\b|\bprb\b|known errors?|\bevents?\b|\balerts?\b|improvement|\brisks?\b|security incident|\bsir\b|\bhr\b|portfolio|\bprojects?\b|field service|work orders?|customer service",
    "approvals": r"approv|awaiting (my|your)|pending (my|your)|sign[- ]?off|\bccb\b",
    "tasks": r"\btasks?\b|my work|assigned to me|to[- ]?do|workload|\bctask|\bptask",
    "knowledge": r"knowledge|\bkb\b|articles?|notes?\b|how[- ]to|documentation",
    "cmdb": r"\bcmdb\b|configuration items?|\bcis\b|\bci\b|servers?|hardware|inventory|assets?|dell|vmware|network device|laptops?|infrastructure",
    "users": r"\busers\b|\baccounts\b|head ?count|how many (staff|people|employees)|who is the admin|admins?\b",
    "clients": r"\bCXT\d+\b|customers?\b|clients?\b|customer tickets?|client organi[sz]ations?",
    "access": r"can'?t access|cannot access|no access|not allowed|sections?|what can i (see|open|use|access)|permissions?|\bmenu\b|modules?|features?|what.*(cannot|can'?t).*(access|see)|restricted",
    "find": r"\b(show|find|list|search for|which|filter)\b.{0,40}\b(tickets?|incidents?|changes?)\b",
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


def _requests(scope, evidence, question):
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
    numbers = access.record_numbers(question)
    words = access.expanded_keywords(question)
    selected = visible
    request_numbers = [n for n in numbers if n.startswith("REQ")]
    item_numbers = [n for n in numbers if n.startswith(("RITM", "SCTASK"))]
    if request_numbers:
        selected = selected.filter(CatalogRequest.number.in_(request_numbers))
    elif item_numbers:
        request_ids = db.session.query(RequestedItem.request_id).outerjoin(
            CatalogTask, CatalogTask.requested_item_id == RequestedItem.id).filter(
                db.or_(RequestedItem.number.in_(item_numbers), CatalogTask.number.in_(item_numbers)))
        selected = selected.filter(CatalogRequest.id.in_(request_ids))
    elif words:
        request_ids = db.session.query(RequestedItem.request_id).join(RequestedItem.item).outerjoin(
            CatalogTask, CatalogTask.requested_item_id == RequestedItem.id).filter(db.or_(*[
            db.or_(RequestedItem.number.ilike(f"%{word}%"), CatalogTask.title.ilike(f"%{word}%"))
            for word in words
        ]))
        selected = selected.filter(CatalogRequest.id.in_(request_ids))
    else:
        selected = selected.filter(CatalogRequest.id == -1)
    for request in selected.order_by(CatalogRequest.opened_at.desc()).limit(4):
        evidence.flags.add("service_request_content")
        details = [f"State: {request.state}; Opened: {request.opened_at.isoformat()}"]
        for item in request.items[:6]:
            try:
                variables = json.dumps(json.loads(item.variables_json or "{}"), ensure_ascii=True)[:700]
            except (TypeError, ValueError):
                variables = "[unreadable legacy request details]"
            details.append(f"{item.number}: {item.item.name}; state {item.state}; stage {item.stage}; requested details {variables}")
            for task in item.tasks[:6]:
                details.append(f"{task.number}: {task.title}; state {task.state}; work notes {(task.work_notes or 'none')[:500]}")
        evidence.add("request", request.id, request.number, request.number, "\n".join(details))
    return "Service requests", text


def _records(scope, question, evidence):
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
    numbers, words = access.record_numbers(question), access.expanded_keywords(question)
    selected = visible
    enterprise_numbers = [n for n in numbers if not n.startswith(("INC", "CHG", "REQ", "RITM", "SCTASK", "CXT"))]
    if enterprise_numbers:
        selected = selected.filter(EnterpriseRecord.number.in_(enterprise_numbers))
    elif words:
        selected = selected.filter(db.or_(*[
            db.or_(EnterpriseRecord.number.ilike(f"%{word}%"), EnterpriseRecord.title.ilike(f"%{word}%"),
                   EnterpriseRecord.description.ilike(f"%{word}%")) for word in words]))
    else:
        selected = selected.filter(EnterpriseRecord.id == -1)
    for record in selected.order_by(EnterpriseRecord.updated_at.desc()).limit(5):
        if record.domain in {"customer", "hr", "security", "risk"}:
            evidence.flags.add("restricted_record")
        notes = TaskNote.query.filter_by(target_type="enterprise", target_id=record.id).order_by(
            TaskNote.created_at.desc()).limit(4).all()
        details = (f"Domain: {record.domain}; Type: {record.record_type}; State: {record.state}; Priority: {record.priority}; "
                   f"Risk: {record.risk}; Due: {record.due_at or 'not set'}\n{record.description[:1400]}" +
                   "".join(f"\nWork note: {note.body[:400]}" for note in reversed(notes)))
        evidence.add("enterprise", record.id, record.number, f"{record.number} {record.title}", details)
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


def _cmdb(scope, question, evidence):
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
    words = access.expanded_keywords(question)
    if words:
        matching = Asset.query.filter(Asset.tenant_id == scope.tenant_id, db.or_(*[
            column.ilike(f"%{word}%") for word in words
            for column in (Asset.asset_tag, Asset.name, Asset.asset_type, Asset.serial_number)
        ])).order_by(Asset.asset_tag).limit(5)
        for row in matching:
            evidence.add("asset", row.id, row.asset_tag, f"{row.asset_tag} {row.name}",
                         f"Type: {row.asset_type}; Status: {row.status}; Serial number: {row.serial_number or 'not set'}")
    return "Configuration items and assets", text


_TIME_WINDOWS = (
    (re.compile(r"\btoday\b", re.I), 1), (re.compile(r"\byesterday\b", re.I), 2),
    (re.compile(r"\bthis week\b", re.I), 7), (re.compile(r"\blast (\d{1,3}) days?\b", re.I), None),
    (re.compile(r"\blast week\b", re.I), 14), (re.compile(r"\bthis month\b", re.I), 31),
)
_PRIORITY = re.compile(r"\bP([1-4])\b", re.I)
_STATE_WORDS = ("New", "In Progress", "Pending", "On Hold", "Resolved", "Closed", "Cancelled")


def _find_tickets(scope, question, base):
    """A bounded, safe slice of natural-language query: recognized filters (priority, kind, state, team name,
    a relative time window) run through the same visible-ticket query as everything else; nothing free-form
    reaches the database. Returns a compact list, not raw SQL, and is silent (returns None) if it recognizes
    no filter, so an ordinary keyword question is left to the usual evidence search."""
    filtered, applied = base, []
    priority = _PRIORITY.search(question)
    if priority:
        filtered = filtered.filter(Ticket.priority == f"P{priority.group(1)}")
        applied.append(f"priority P{priority.group(1)}")
    if re.search(r"\bincidents?\b", question, re.I) and not re.search(r"\bchanges?\b", question, re.I):
        filtered = filtered.filter(Ticket.kind == "incident")
        applied.append("incidents")
    elif re.search(r"\bchanges?\b", question, re.I) and not re.search(r"\bincidents?\b", question, re.I):
        filtered = filtered.filter(Ticket.kind == "change")
        applied.append("changes")
    for state in _STATE_WORDS:
        if re.search(rf"\b{re.escape(state.lower())}\b", question, re.I):
            filtered = filtered.filter(Ticket.state == state)
            applied.append(f"state {state}")
            break
    for group in SupportGroup.query.filter_by(tenant_id=scope.tenant_id, active=True).all():
        if group.name and re.search(rf"\b{re.escape(group.name.lower())}\b", question, re.I):
            ticket_ids = db.session.query(TicketAssignmentGroup.ticket_id).filter(TicketAssignmentGroup.group_id == group.id)
            filtered = filtered.filter(Ticket.id.in_(ticket_ids))
            applied.append(f"assigned to {group.name}")
            break
    since = None
    for pattern, days in _TIME_WINDOWS:
        match = pattern.search(question)
        if match:
            since = int(match.group(1)) if days is None else days
            break
    if since:
        filtered = filtered.filter(Ticket.updated_at >= now() - timedelta(days=since))
        applied.append(f"updated in the last {since} days")
    if not applied:
        return None
    rows = filtered.order_by(Ticket.updated_at.desc()).limit(15).all()
    listing = "; ".join(f"{r.number} {r.title[:60]} ({r.state}, {r.priority})" for r in rows) or "none matched"
    return (f"Tickets matching {', '.join(applied)}", f"{len(rows)} shown (of the ones you can see): {listing}")


def _users(scope):
    if not _rank(scope.role)("admin"):
        return "Accounts", "Head-counts of accounts are only available to administrators."
    rows = db.session.query(User.role, func.count()).filter(User.tenant_id == scope.tenant_id, User.active.is_(True)).group_by(User.role).all()
    return "Accounts (numbers only)", (f"{sum(n for _, n in rows)} active accounts: " + ", ".join(f"{n} {r}" for r, n in sorted(rows)) +
                                       ". Names and contact details are never shared by the assistant.")


def _clients(scope, question, evidence):
    from app import user_can_access_client_management, visible_client_organization_query, visible_client_ticket_query
    if not user_can_access_client_management(scope.identity):
        return "Customer management", "Your access level does not include customer management."
    organizations = visible_client_organization_query(scope.identity).filter_by(active=True).count()
    rows = dict(visible_client_ticket_query(scope.identity).with_entities(ClientTicket.status, func.count()).group_by(
        ClientTicket.status).all())
    visible = visible_client_ticket_query(scope.identity)
    numbers, words = access.record_numbers(question), access.expanded_keywords(question)
    selected = visible
    cxt_numbers = [n for n in numbers if n.startswith("CXT")]
    if cxt_numbers:
        selected = selected.filter(ClientTicket.number.in_(cxt_numbers))
    elif words:
        selected = selected.filter(db.or_(*[
            db.or_(ClientTicket.number.ilike(f"%{word}%"), ClientTicket.subject.ilike(f"%{word}%"),
                   ClientTicket.description.ilike(f"%{word}%")) for word in words]))
    else:
        selected = selected.filter(ClientTicket.id == -1)
    for ticket in selected.order_by(ClientTicket.updated_at.desc()).limit(4):
        evidence.flags.add("customer_content")
        messages = ClientTicketMessage.query.filter_by(tenant_id=scope.tenant_id, client_ticket_id=ticket.id).order_by(
            ClientTicketMessage.created_at.desc()).limit(5).all()
        body = (f"Status: {ticket.status}; Priority: {ticket.priority}; Type: {ticket.ticket_type}; Channel: {ticket.channel}; "
                f"Updated: {ticket.updated_at.isoformat()}\n{ticket.description[:1200]}" +
                "".join(f"\n{message.visibility} message: {message.body[:400]}" for message in reversed(messages)))
        evidence.add("client_ticket", ticket.id, ticket.number, f"{ticket.number} {ticket.subject}", body)
    return "Customer management", (f"Client organizations you can see: {organizations}. Customer tickets you can see: " +
                                    (", ".join(f"{n} {s}" for s, n in sorted(rows.items())) or "none") +
                                    ". Ticket content is supplied only when it matches this question and passes current access checks.")


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
        builders.append(lambda: _requests(scope, evidence, question))
    if "records" in found:
        builders.append(lambda: _records(scope, question, evidence))
    if "approvals" in found:
        builders.append(lambda: _approvals(scope))
    if "tasks" in found:
        builders.append(lambda: _tasks(scope))
    if "knowledge" in found:
        builders.append(lambda: _knowledge(scope))
    if "cmdb" in found:
        builders.append(lambda: _cmdb(scope, question, evidence))
    if "users" in found:
        builders.append(lambda: _users(scope))
    if "clients" in found:
        builders.append(lambda: _clients(scope, question, evidence))
    if "access" in found:
        builders.append(lambda: _access_map(scope))
    if "find" in found:
        builders.append(lambda: _find_tickets(scope, question, base))
    for build in builders:
        result = build()
        if result:
            title, text = result
            evidence.add_context("info", title, text)
