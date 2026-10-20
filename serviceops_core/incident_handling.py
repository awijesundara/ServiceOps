"""Incident handling rules shared by the web pages and the API.

- Hold reasons: why a Pending incident waits; a caller's reply ends "Awaiting caller".
- Assignment rules: route a new incident to a team by category, subcategory, CI class
  or service offering (first active match wins; the CI's support group is the fallback).
- Templates: ready-made incidents for frequent problems.
- Similar incidents: open incidents whose short description shares words with a new one.
- Creating a problem from an incident, and copying a parent's comment to its children.
"""
import re

from flask import abort

import app as core
from serviceops_core.localization import tr
from serviceops_core.request_values import parse_int
from serviceops_core.task_lifecycle import FINISHED_TICKET_STATES
from serviceops_models import (AssignmentRule, ConfigurationItem, EnterpriseRecord, IncidentTemplate,
                               ProblemProfile, RecordLink, ServiceOffering, SupportGroup, Ticket, TaskCI, db)

HOLD_REASONS = ("Awaiting caller", "Awaiting vendor", "Awaiting change", "Awaiting problem")
DEFAULT_HOLD_REASON = "Awaiting caller"
IMPACTS = ("Critical", "High", "Medium", "Low")
STOP_WORDS = {"the", "and", "for", "with", "from", "that", "this", "cannot", "can't", "not", "does", "doesn't",
              "when", "after", "into", "have", "has", "are", "was", "were", "issue", "problem", "error", "please"}


# --- hold reasons -------------------------------------------------------------------------------

def check_hold_reason(value):
    if value not in HOLD_REASONS:
        abort(400, description=tr("Choose why the incident is on hold: {reasons}.", reasons=", ".join(HOLD_REASONS)))
    return value


def caller_replied(ticket, author):
    """A caller's reply resumes an incident that was waiting for them."""
    if (ticket.kind == "incident" and ticket.state == "Pending" and ticket.hold_reason == "Awaiting caller"
            and author.id == ticket.requester_id and "In Progress" in core.allowed_ticket_states(ticket)):
        core.transition_ticket(ticket, "In Progress")
        core.log_history("ticket", ticket.id, "State changed", "state", "Pending", "In Progress",
                         "The caller replied, so work resumed.")
        return True
    return False


# --- assignment rules ---------------------------------------------------------------------------

def rules(tenant_id):
    return AssignmentRule.query.filter_by(tenant_id=tenant_id).order_by(AssignmentRule.position, AssignmentRule.id).all()


def _matches(rule, category, subcategory, ci, offering_id):
    return ((not rule.category or rule.category == category)
            and (not rule.subcategory or rule.subcategory == subcategory)
            and (not rule.ci_class or (ci is not None and ci.ci_class == rule.ci_class))
            and (not rule.service_offering_id or rule.service_offering_id == offering_id))


def route(tenant_id, category, subcategory="", ci=None, offering_id=None):
    """(team, reason) for a new incident, or (None, None) when nothing applies."""
    for rule in rules(tenant_id):
        if rule.active and rule.group and core.is_team_group(rule.group) and _matches(rule, category, subcategory, ci, offering_id):
            return rule.group, tr("assignment rule “{name}”", name=rule.name)
    if ci is not None and ci.support_group and core.is_team_group(ci.support_group):
        return ci.support_group, tr("the support group of {name}", name=ci.name)
    return None, None


def _category_values(tenant_id, form):
    """The submitted category and subcategory, which must be ones this tenant uses
    (a misspelt condition would silently never match)."""
    category = (form.get("category") or "").strip()
    subcategory = (form.get("subcategory") or "").strip()
    if category and category not in {row.name for row in core.tenant_ticket_categories(tenant_id)}:
        abort(400, description=tr("Choose a category from the list."))
    if subcategory:
        known = {(row.category.name, row.name) for row in core.tenant_ticket_subcategories(tenant_id)}
        if not any(name == subcategory and (not category or parent == category) for parent, name in known):
            abort(400, description=tr("Choose a subcategory that belongs to the category."))
    return category, subcategory


def save_rule(actor, form, rule=None):
    tenant_id = actor.tenant_id
    name = (form.get("name") or "").strip()
    if not 0 < len(name) <= 80:
        abort(400, description=tr("A rule name has 1 to 80 characters."))
    group = core.tenant_record_or_404(SupportGroup, parse_int(form.get("group_id"), "group_id", required=True))
    if not core.is_team_group(group):
        abort(400, description=tr("Rules can only route to an active team."))
    offering_id = form.get("service_offering_id") or None
    if offering_id:
        offering_id = core.tenant_record_or_404(ServiceOffering, parse_int(offering_id, "service_offering_id")).id
    category, subcategory = _category_values(tenant_id, form)
    values = dict(name=name, group_id=group.id, service_offering_id=offering_id, category=category, subcategory=subcategory,
                  ci_class=(form.get("ci_class") or "").strip()[:80], active=form.get("active", "1") in ("1", "on", "true"))
    if not any((values["category"], values["subcategory"], values["ci_class"], offering_id)):
        abort(400, description=tr("Give the rule at least one condition: category, subcategory, CI class or service offering."))
    created = rule is None
    if created:
        rule = AssignmentRule(tenant_id=tenant_id, position=len(rules(tenant_id)))
        db.session.add(rule)
    for key, value in values.items():
        setattr(rule, key, value)
    db.session.flush()
    core.audit("assignment rule " + ("created" if created else "updated"), rule.name, f"-> {group.name}")
    return rule


def delete_rule(actor, rule):
    core.audit("assignment rule deleted", rule.name)
    db.session.delete(rule)
    db.session.flush()
    for position, row in enumerate(rules(actor.tenant_id)):
        row.position = position


def move_rule(actor, rule, direction):
    ordered = rules(actor.tenant_id)
    index = ordered.index(rule)
    other = index - 1 if direction == "up" else index + 1
    if 0 <= other < len(ordered):
        ordered[index], ordered[other] = ordered[other], ordered[index]
        for position, row in enumerate(ordered):
            row.position = position
        core.audit("assignment rule moved", rule.name, direction)


def rule_or_404(tenant_id, rule_id):
    rule = AssignmentRule.query.filter_by(id=rule_id, tenant_id=tenant_id).first()
    if rule is None:
        abort(404)
    return rule


# --- templates ----------------------------------------------------------------------------------

def templates(tenant_id, active_only=False):
    query = IncidentTemplate.query.filter_by(tenant_id=tenant_id)
    if active_only:
        query = query.filter_by(active=True)
    return query.order_by(IncidentTemplate.name).all()


def template_or_404(tenant_id, template_id):
    row = IncidentTemplate.query.filter_by(id=template_id, tenant_id=tenant_id).first()
    if row is None:
        abort(404)
    return row


def save_template(actor, form, template=None):
    name = (form.get("name") or "").strip()
    if not 0 < len(name) <= 80:
        abort(400, description=tr("A template name has 1 to 80 characters."))
    duplicate = IncidentTemplate.query.filter(IncidentTemplate.tenant_id == actor.tenant_id,
                                              db.func.lower(IncidentTemplate.name) == name.lower())
    if template is not None:
        duplicate = duplicate.filter(IncidentTemplate.id != template.id)
    if duplicate.first():
        abort(409, description=tr("A template named {name} already exists.", name=name))
    impact, urgency = form.get("impact", "Medium"), form.get("urgency", "Medium")
    if impact not in IMPACTS or urgency not in IMPACTS:
        abort(400, description=tr("Impact and urgency must be Critical, High, Medium or Low."))
    group_id = form.get("group_id") or None
    if group_id:
        group = core.tenant_record_or_404(SupportGroup, parse_int(group_id, "group_id"))
        if not core.is_team_group(group):
            abort(400, description=tr("Templates can only assign an active team."))
        group_id = group.id
    category, subcategory = _category_values(actor.tenant_id, form)
    title = (form.get("title") or "").strip()
    if len(title) > 180:
        abort(400, description=tr("The short description has at most 180 characters."))
    created = template is None
    if created:
        template = IncidentTemplate(tenant_id=actor.tenant_id)
        db.session.add(template)
    template.name, template.title = name, title
    template.description = (form.get("description") or "").strip()[:10000]
    template.category, template.subcategory = category, subcategory
    template.impact, template.urgency, template.group_id = impact, urgency, group_id
    template.active = form.get("active", "1") in ("1", "on", "true")
    db.session.flush()
    core.audit("incident template " + ("created" if created else "updated"), template.name)
    return template


def prefill(template):
    """Form values a template fills in on the new-incident form."""
    values = {"title": template.title, "description": template.description, "category": template.category,
              "subcategory": template.subcategory, "impact": template.impact, "urgency": template.urgency}
    if template.group_id:
        values["group_id"] = str(template.group_id)
    return values


# --- similar incidents --------------------------------------------------------------------------

def _words(text):
    return {word for word in re.findall(r"[a-z0-9][a-z0-9'-]{2,}", (text or "").lower()) if word not in STOP_WORDS}


def similar(user, text, exclude_id=None, limit=5):
    """Open incidents the person may see whose short description shares words with `text`,
    most shared words first."""
    wanted = _words(text)
    if not wanted:
        return []
    pattern = db.or_(*[Ticket.title.ilike(f"%{core.escape_like(word)}%", escape="\\") for word in list(wanted)[:8]])
    candidates = core.visible_ticket_query(user).filter(
        Ticket.kind == "incident", Ticket.deleted_at.is_(None),
        Ticket.state.notin_(FINISHED_TICKET_STATES), pattern,
    ).order_by(Ticket.updated_at.desc()).limit(200).all()
    scored = []
    for ticket in candidates:
        if ticket.id == exclude_id:
            continue
        shared = len(wanted & _words(ticket.title))
        if shared >= min(2, len(wanted)):
            scored.append((shared, ticket))
    scored.sort(key=lambda row: (-row[0], -row[1].id))
    return [ticket for _, ticket in scored[:limit]]


# --- problem from an incident; parent comments to children --------------------------------------

def create_problem(user, ticket):
    """A problem record investigating this incident, linked as its underlying problem."""
    existing = RecordLink.query.filter_by(source_type="ticket", source_id=ticket.id, link_type="underlying_problem").first()
    if existing:
        abort(409, description=tr("{number} already has an underlying problem.", number=ticket.number))
    record = EnterpriseRecord(number=core.next_enterprise_number("problem"), domain="problem",
                              record_type="Root cause analysis", title=ticket.title[:180],
                              description=tr("Raised from {number}.", number=ticket.number) + "\n\n" + ticket.description,
                              priority=ticket.priority, risk="Medium", requester_id=user.id, tenant_id=ticket.tenant_id)
    db.session.add(record)
    db.session.flush()
    db.session.add(ProblemProfile(enterprise_record_id=record.id))
    for link in TaskCI.query.filter_by(target_type="ticket", target_id=ticket.id).all():
        ci = db.session.get(ConfigurationItem, link.ci_id)
        if ci is not None and ci.tenant_id == ticket.tenant_id:
            db.session.add(TaskCI(target_type="enterprise", target_id=record.id, ci_id=ci.id,
                                  relationship_role=link.relationship_role))
    db.session.add(RecordLink(source_type="ticket", source_id=ticket.id, target_type="enterprise",
                              target_id=record.id, link_type="underlying_problem"))
    core.log_history("enterprise", record.id, "Record created", details=f"{record.number}: raised from {ticket.number}")
    core.log_history("ticket", ticket.id, "Related record linked", details=f"Problem linked to {record.number}: {record.title}")
    core.audit("create", record.number, f"Problem from {ticket.number}")
    return record


def copy_to_children(ticket, author, body):
    """Post a parent's comment on each of its child incidents; returns how many."""
    from serviceops_core import incident_hierarchy
    copied = 0
    for child in incident_hierarchy.children_of(ticket):
        if child.state in ("Closed", "Cancelled"):
            continue
        core.post_ticket_comment(child, author, tr("From parent incident {number}:", number=ticket.number) + "\n" + body)
        core.log_history("ticket", child.id, "Comment added", details=f"Copied from parent {ticket.number}")
        copied += 1
    return copied
