"""Organization context for the chat assistant: public information, the asker's own profile and authority.

Everything here is read-only and computed on the server under the asker's identity, then handed to the model as
plain facts. The model still has no tools and no database access. Nothing about other people is included: the
asker's own profile may name their own manager and teams, but never anyone else's details.
"""
import re
from datetime import timezone

from serviceops_core.ai import access
from serviceops_models import (CatalogItem, ChangeFreezeWindow, GroupMember, ServiceOffering, SLADefinition, SupportGroup, Ticket, User,
                               db, now)

OPEN_STATES_EXCLUDED = ("Resolved", "Closed", "Cancelled", "Canceled", "Completed", "Implemented")

_INTENTS = {
    "profile": r"\b(my|me)\b.{0,25}\b(team|teams|group|manager|department|title|position|job)\b|\b(am i|do i|i)\b.{0,30}\b(ccb|group|team|belong|member)\b|\bwhat do you know about me\b|\btell me about me\b|\bwho am i\b|\bline manager\b|\bwho do i report\b",
    "stats": r"\bhow many\b|\bcount\b|\bnumber of\b|\bstatistics|\bstats\b|\boverview\b|\bsummary\b|\bbacklog\b|\bopen\b|\bcritical\b|\bp[1-4]\b|\bworkload\b|\bwhat can you see\b",
    "freeze": r"\bfreeze|\bblackout|\bchange window|\bschedul|\bplanned\b|\bmaintenance\b|\bdeploy|\brelease\b|\bcan i (do|make|run|raise)\b|\bgo live\b|\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b|\bnext (week|month)\b|\bchange\b",
    "catalog": r"\bcatalog|\brequest (a|an|new)\b|\border\b|\blaptop|\bsoftware\b|\bnew (starter|joiner|account|access)\b|\bwhat (can|could) i (request|order)\b|\bservices? (do you|are)\b",
    "services": r"\bservice (status|health)|\boutage|\bdown\b|\bavailab|\bstatus of\b|\bdegraded|\boffering",
    "sla": r"\bsla\b|\bresponse time|\bresolution time|\btarget\b|\bhow long\b|\bwithin how|\bservice level",
    "teams": r"\bwhich team|\bwhat team|\bwho (handles|owns|fixes)|\bsupport (group|team)|\bassign(ed)? to\b|\bteams?\b|\bgroups?\b",
    "governance": r"\bccb\b|change control board|governance groups?|who manages? .{0,20}(group|board)",
    "about": r"\bwhat can you\b|\bwhat do you\b|\bhelp me\b|\bhow (do|can) i\b|\bserviceops\b|\bthis (tool|system|app|platform)\b|\bfeatures?\b|\bcapabilit|\braise\b|\bcreate\b|\blog (a|an)\b|\breport (a|an)\b|\bopen a\b|\bnew (ticket|incident)\b|\bget started\b",
}
_COMPILED = {name: re.compile(pattern, re.I) for name, pattern in _INTENTS.items()}


def intents(question):
    return {name for name, pattern in _COMPILED.items() if pattern.search(question or "")}


def _role_allows(scope, action):
    from app import effective_role_has_action
    return bool(effective_role_has_action(scope.role, action, tenant_id=scope.tenant_id))


def _it_team_names(scope):
    from app import user_support_group_ids
    ids = user_support_group_ids(scope.identity)
    if not ids:
        return []
    return [g.name for g in SupportGroup.query.filter(
        SupportGroup.id.in_(ids), SupportGroup.tenant_id == scope.tenant_id, SupportGroup.active.is_(True),
        SupportGroup.group_type == "IT Fulfillment").order_by(SupportGroup.name)]


def capabilities(scope):
    """What this person may do in ServiceOps, from the same role policy the application enforces."""
    it_teams = _it_team_names(scope)
    can = ["look up their own tickets and published knowledge"]
    if scope.is_staff:
        can[0] = "look up incidents and changes they can access, and published knowledge"
    if _role_allows(scope, "create"):
        can.append("raise incidents")
        if scope.role in ("admin", "superadmin") or it_teams:
            can.append("raise changes" + (f" for their teams ({', '.join(it_teams[:4])})" if it_teams and scope.role not in ("admin", "superadmin") else ""))
    for action, phrase in (("comment_internal", "add internal comments"), ("assign", "assign and progress tickets"),
                           ("approve", "approve changes"), ("report", "use analytics and reports"),
                           ("administer", "administer ServiceOps settings")):
        if _role_allows(scope, action):
            can.append(phrase)
    if scope.role in ("admin", "superadmin"):
        can.append("prepare ticket state, priority, assignment and exact-comment actions for explicit human approval")
    cannot = []
    if not scope.is_staff:
        cannot.append("see other people's tickets, configuration items or team queues")
    if not _role_allows(scope, "approve"):
        cannot.append("approve changes")
    if not _role_allows(scope, "assign"):
        cannot.append("assign or progress tickets")
    if not (scope.role in ("admin", "superadmin") or it_teams):
        cannot.append("raise changes")
    return can, cannot


def may_raise_change(scope):
    return scope.role in ("admin", "superadmin") or bool(_it_team_names(scope))


def capability_sentence(scope):
    can, cannot = capabilities(scope)
    text = "This person may: " + "; ".join(can) + "."
    if cannot:
        text += " This person may not: " + "; ".join(cannot) + ". If they ask for something outside this, explain who could help (for example a manager or their service desk) instead of promising it."
    return text


def _fmt(moment):
    return moment.strftime("%d %b %Y %H:%M UTC") if moment else "unknown"


def _profile(scope, evidence):
    user = db.session.get(User, scope.user_id)  # the asker's own record only
    if not user:
        return None
    manager = db.session.get(User, user.manager_id).name if user.manager_id else None
    memberships = db.session.query(SupportGroup.name, SupportGroup.group_type, GroupMember.role).join(
        GroupMember, GroupMember.group_id == SupportGroup.id).filter(
        GroupMember.user_id == scope.user_id,
        GroupMember.tenant_id == scope.tenant_id,
        SupportGroup.tenant_id == scope.tenant_id,
        SupportGroup.active.is_(True),
    ).order_by(SupportGroup.name).all()
    evidence.flags.add("personal")  # a person's own details: keep the question on the organization's own AI
    lines = [f"Name: {user.name}", f"Access level: {scope.role}"]
    if user.title:
        lines.append(f"Job title: {user.title}")
    if user.department:
        lines.append(f"Department: {user.department}")
    lines.append("Group memberships: " + (", ".join(
        f"{name} ({group_type}; {role})" for name, group_type, role in memberships
    ) if memberships else "none recorded"))
    ccb = next((role for name, _group_type, role in memberships if name == "Change Control Board"), None)
    lines.append("Change Control Board membership: " + (f"yes ({ccb})" if ccb else "no"))
    lines.append("Line manager: " + (manager or "not recorded"))
    return "Your profile", "; ".join(lines) + "."


def _stats(scope, base):
    rows = base.with_entities(Ticket.kind, Ticket.state, db.func.count()).group_by(Ticket.kind, Ticket.state).all()
    if not rows:
        return "Tickets you can see", "You can currently see no tickets."
    per = {}
    for kind, state, total in rows:
        entry = per.setdefault(kind, {"total": 0, "open": 0})
        entry["total"] += total
        if state not in OPEN_STATES_EXCLUDED:
            entry["open"] += total
    parts = [f"{kind} tickets: {v['total']} in total, {v['open']} still open" for kind, v in sorted(per.items())]
    text = f"You can see {sum(v['total'] for v in per.values())} tickets. " + "; ".join(parts) + "."
    mine = base.filter(Ticket.requester_id == scope.user_id, ~Ticket.state.in_(OPEN_STATES_EXCLUDED)).count()
    text += f" {mine} open tickets were raised by you."
    if scope.is_staff:
        assigned = base.filter(Ticket.assignee_id == scope.user_id, ~Ticket.state.in_(OPEN_STATES_EXCLUDED)).count()
        text += f" {assigned} open tickets are assigned to you."
        urgent = dict(base.filter(~Ticket.state.in_(OPEN_STATES_EXCLUDED)).with_entities(
            Ticket.priority, db.func.count()).group_by(Ticket.priority).all())
        if urgent:
            text += " Open by priority: " + ", ".join(f"{p} {n}" for p, n in sorted(urgent.items())) + "."
    return "Tickets you can see", text


def _aware(moment):
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _freeze(scope):
    at = _aware(now())
    rows = ChangeFreezeWindow.query.filter(ChangeFreezeWindow.tenant_id == scope.tenant_id, ChangeFreezeWindow.ends_at >= at).order_by(
        ChangeFreezeWindow.starts_at).limit(8).all()
    if not rows:
        return "Change freeze windows", "No change freeze window is active or scheduled. Standard and Normal changes are not blocked by a freeze."
    lines = []
    for row in rows:
        state = "ACTIVE NOW" if _aware(row.starts_at) <= at <= _aware(row.ends_at) else "upcoming"
        lines.append(f"{row.title} ({state}): {_fmt(row.starts_at)} to {_fmt(row.ends_at)}" + (f" - {row.reason}" if row.reason else ""))
    return "Change freeze windows", ("During a freeze only Emergency changes are allowed. " + " | ".join(lines))


def _catalog(scope):
    rows = CatalogItem.query.filter_by(tenant_id=scope.tenant_id, active=True).order_by(CatalogItem.category, CatalogItem.name).limit(20).all()
    if not rows:
        return None
    return "Service catalog (things anyone can request)", " | ".join(
        f"{r.name} ({r.category}, about {r.delivery_days} days{', needs approval' if r.approval_required else ''})" for r in rows)


def _services(scope):
    rows = ServiceOffering.query.filter_by(tenant_id=scope.tenant_id).order_by(ServiceOffering.name).limit(25).all()
    if not rows:
        return None
    bad = [r for r in rows if r.status != "Operational"]
    text = f"{len(rows)} business services. " + ("Not fully operational: " + ", ".join(f"{r.name} ({r.status})" for r in bad) + "." if bad else "All are operational.")
    return "Business service status", text


def _sla(scope):
    rows = SLADefinition.query.filter_by(active=True, agreement_type="SLA").order_by(SLADefinition.priority, SLADefinition.target_type).limit(16).all()
    if not rows:
        return None
    return "Service level targets", " | ".join(f"{r.name}: {r.priority or 'all priorities'} {r.target_type} within {r.duration_minutes} minutes" for r in rows)


def _teams(scope):
    rows = SupportGroup.query.filter_by(tenant_id=scope.tenant_id, active=True, group_type="IT Fulfillment").order_by(SupportGroup.name).limit(20).all()
    if not rows:
        return None
    return "IT support teams", "Teams that fulfil incidents and changes: " + ", ".join(r.name for r in rows) + "."


def _governance(scope):
    """Governance group structure visible to managers/admins; everyone may check their own membership via _profile."""
    from app import role_at_least
    if not role_at_least(scope.role, "manager"):
        return "Governance groups", "Your access level does not include governance-group administration."
    rows = SupportGroup.query.filter(
        SupportGroup.tenant_id == scope.tenant_id,
        SupportGroup.active.is_(True),
        SupportGroup.group_type.in_(("CCB Approval", "Executive Approval")),
    ).order_by(SupportGroup.name).all()
    if not rows:
        return "Governance groups", "No active governance groups are configured."
    return "Governance groups", " | ".join(
        f"{row.name}: manager {row.manager.name if row.manager else 'not assigned'}; {len(row.members)} members"
        for row in rows
    )


_ABOUT = ("ServiceOps is the organization's IT service management tool: incidents (restore service), changes (controlled "
          "production modifications with approvals and freezes), service requests from the catalog, knowledge articles, and "
          "configuration items. To raise something, the assistant can prepare a draft ticket for the person to review and "
          "submit; it never submits or changes anything itself.")


def add_organization_context(scope, question, evidence, base):
    """Add the facts a question needs, chosen by what it asks about. `base` is the asker's visible-ticket query."""
    found = intents(question)
    builders = []
    if "profile" in found:
        builders.append(lambda: _profile(scope, evidence))
    if "stats" in found or "profile" in found:
        builders.append(lambda: _stats(scope, base))
    if "freeze" in found:
        builders.append(lambda: _freeze(scope))
    for name, builder in (("catalog", _catalog), ("services", _services), ("sla", _sla), ("teams", _teams),
                          ("governance", _governance)):
        if name in found:
            builders.append(lambda b=builder: b(scope))
    if "about" in found:
        builders.append(lambda: ("About ServiceOps and this assistant", _ABOUT))
    for build in builders:
        item = build()
        if item:
            evidence.add_context("info", item[0], item[1])
    from serviceops_core.ai import modules
    modules.add_module_context(scope, question, evidence, base)
