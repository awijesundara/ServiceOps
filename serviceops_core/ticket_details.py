"""Read-only ticket detail contract shared by REST/mobile consumers.

Uses the same stored relationships as the Web UI, with explicit tenant and
CI-class checks. Missing data remains absent; no name-based asset guessing.
"""
from flask import current_app
from werkzeug.exceptions import HTTPException
from sqlalchemy.orm import selectinload

from serviceops_core.ci_class_policy import ci_class_read_allowed
from serviceops_models import (ApprovalChain, ApprovalGate, ApprovalVote, ConfigurationItem,
                               TaskCI, TaskHistory, TaskSLA, OperationalTask, MajorIncidentUpdate)


def ticket_details(ticket, user, *, include_sections=True):
    """Return authorized CI links and compact sections for one visible ticket."""
    try:
        import app as core
        tenant = ticket.tenant_id
        staff = core.effective_role_has_action(user.effective_role, "comment_internal")
        result = {"schema_version": 1, "configuration_items": [], "sections": [],
                  "can_manage": core.user_can_manage_ticket(user, ticket) and not core.ticket_locked_for_edits(ticket),
                  "allowed_states": core.allowed_ticket_states(ticket)}
        sections = result["sections"]
        if include_sections:
            sections.extend(public_ticket_sections(ticket, user))
        # Requesters receive the public ticket contract, never internal topology/history.
        if not staff:
            return result
        links = TaskCI.query.filter_by(target_type="ticket", target_id=ticket.id).options(
            selectinload(TaskCI.ci).selectinload(ConfigurationItem.rack),
        ).order_by(TaskCI.id).all()
        governance = ticket.change_governance if ticket.kind == "change" else None
        candidates = ([(governance.ci, "Primary CI")] if governance and governance.ci else [])
        candidates += [(link.ci, link.relationship_role) for link in links]
        candidates.sort(key=lambda item: {"Primary CI": 0, "Affected CI": 1}.get(item[1], 2))
        seen = set()
        for ci, relationship in candidates:
            if not ci or ci.tenant_id != tenant or (ci.id, relationship) in seen:
                continue
            if not ci_class_read_allowed(tenant, ci.ci_class, user.effective_role):
                continue
            seen.add((ci.id, relationship))
            rack = ci.rack if ci.rack and ci.rack.tenant_id == tenant else None
            result["configuration_items"].append({
                "id": ci.id, "name": ci.name, "ci_class": ci.ci_class,
                "environment": ci.environment, "status": ci.operational_status,
                "relationship_role": relationship, "ip_address": ci.ip_address,
                "location": ci.location, "serial_number": ci.serial_number,
                "vendor": ci.vendor, "model": ci.model, "description": ci.description,
                "rack": {"id": rack.id, "name": rack.name, "site": rack.site,
                         "capacity": rack.u_height, "position": ci.rack_position,
                         "u_height": ci.rack_u_height, "face": ci.rack_face} if rack else None,
            })
        if not include_sections:
            return result
        # A stable label/value representation keeps text-heavy Web sections readable
        # without losing their fields or requiring clients to interpret HTML.
        sections = result["sections"]
        specs = [
            ("governance", "Change governance", governance, ["change_type", "risk_score", "impact", "planned_start", "planned_end", "implementation_plan", "test_plan", "backout_plan", "conflict_status", "ccb_required", "risk_score_override_reason"]),
            ("change_review", "Post-implementation review", ticket.post_implementation_review, ["outcome", "summary", "follow_up_actions", "reviewed_at", "reviewed_by"]),
            ("major_incident", "Major incident and review", ticket.major_incident_profile, ["status", "business_impact", "communications", "coordinator", "declared_at", "public", "review_what_went_well", "review_what_went_poorly", "review_follow_up_actions", "reviewed_by", "reviewed_at"]),
        ]
        for key, title, row, attrs in specs:
            if row and getattr(row, "tenant_id", tenant) == tenant:
                fields = []
                for attr in attrs:
                    value = getattr(row, attr)
                    if hasattr(value, "tenant_id"):
                        value = value.name if value.tenant_id == tenant else None
                    elif hasattr(value, "isoformat"):
                        value = value.isoformat()
                    elif isinstance(value, bool):
                        value = "Yes" if value else "No"
                    elif value is not None:
                        value = str(value)
                    fields.append({"label": attr.replace("_", " ").capitalize(), "value": value})
                sections.append({"id": key, "title": title, "entries": [{"id": key, "title": title, "fields": fields}]})
        major = ticket.major_incident_profile
        if major:
            updates = MajorIncidentUpdate.query.filter_by(major_incident_profile_id=major.id, tenant_id=tenant).order_by(MajorIncidentUpdate.created_at, MajorIncidentUpdate.id).all()
            sections.append({"id": "status_updates", "title": "Incident status updates", "entries": [
                {"id": str(row.id), "title": row.status, "fields": [
                    {"label": "Message", "value": row.message},
                    {"label": "Posted", "value": row.created_at.isoformat()},
                    {"label": "Posted by", "value": row.posted_by.name if row.posted_by and row.posted_by.tenant_id == tenant else None},
                ]} for row in updates]})
        chains = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket.id, tenant_id=tenant).options(
            selectinload(ApprovalChain.gates).selectinload(ApprovalGate.votes).selectinload(ApprovalVote.approver),
        ).order_by(ApprovalChain.id).all()
        sections.append({"id": "approvals", "title": "Approval history", "entries": [
            {"id": str(vote.id), "title": f"{chain.name} · {gate.name}", "fields": [
                {"label": "Approver", "value": vote.approver.name if vote.approver and vote.approver.tenant_id == tenant else None},
                {"label": "State", "value": vote.state}, {"label": "Comments", "value": vote.comments},
                {"label": "Gate state", "value": gate.state}, {"label": "Mode", "value": gate.mode},
                {"label": "Stage", "value": str(gate.sequence)}, {"label": "Chain state", "value": chain.state},
                {"label": "Delegated from", "value": vote.delegated_from.name if vote.delegated_from and vote.delegated_from.tenant_id == tenant else None},
                {"label": "Decided", "value": vote.decided_at.isoformat() if vote.decided_at else None},
            ]} for chain in chains for gate in chain.gates if gate.tenant_id == tenant
            for vote in gate.votes if vote.tenant_id == tenant]})
        tasks = OperationalTask.query.filter_by(parent_type="ticket", parent_id=ticket.id).order_by(OperationalTask.sequence, OperationalTask.id).all()
        sections.append({"id": "work_tasks", "title": "Work tasks", "entries": [
            {"id": str(row.id), "title": f"{row.number} · {row.title}", "fields": [
                {"label": "Type", "value": row.task_type}, {"label": "State", "value": row.state},
                {"label": "Required", "value": str(row.required)},
                {"label": "Assignment group", "value": row.assignment_group.name},
                {"label": "Assigned to", "value": row.assignee.name if row.assignee and row.assignee.tenant_id == tenant else None},
                {"label": "Planned start", "value": row.planned_start.isoformat() if row.planned_start else None},
                {"label": "Planned end", "value": row.planned_end.isoformat() if row.planned_end else None},
                {"label": "Work notes", "value": row.work_notes},
            ]} for row in tasks if row.assignment_group and row.assignment_group.tenant_id == tenant]})
        history = TaskHistory.query.filter_by(target_type="ticket", target_id=ticket.id).options(
            selectinload(TaskHistory.actor),
        ).order_by(TaskHistory.created_at.desc(), TaskHistory.id.desc()).all()
        sections.append({"id": "history", "title": "Event history", "entries": [
            {"id": str(row.id), "title": row.event, "fields": [
                {"label": "At", "value": row.created_at.isoformat()},
                {"label": "Actor", "value": row.actor.name if row.actor and row.actor.tenant_id == tenant else None},
                {"label": "Field", "value": row.field_name}, {"label": "Before", "value": row.old_value},
                {"label": "After", "value": row.new_value}, {"label": "Details", "value": row.details},
            ]} for row in history]})
        return result
    except HTTPException:
        raise
    except Exception:
        current_app.logger.exception("Ticket detail projection failed")
        raise


def public_ticket_sections(ticket, user):
    """Public Web UI service commitments and visible related records."""
    try:
        import app as core
        tenant = ticket.tenant_id
        sections = []
        group = core.ticket_owning_group(ticket)
        sections.append({"id": "record", "title": "Record information", "entries": [
            {"id": "record", "title": ticket.number, "fields": [
                {"label": "Caller", "value": ticket.requester.name if ticket.requester and ticket.requester.tenant_id == tenant else None},
                {"label": "Caller email", "value": ticket.requester.email if ticket.requester and ticket.requester.tenant_id == tenant else None},
                {"label": "Contact type", "value": ticket.contact_type},
                {"label": "Impact", "value": ticket.impact}, {"label": "Urgency", "value": ticket.urgency},
                {"label": "Notify", "value": ticket.notify},
                {"label": "Service offering", "value": ticket.service_offering.name if ticket.service_offering and ticket.service_offering.tenant_id == tenant else None},
                {"label": "Team manager", "value": group.manager.name if group and group.tenant_id == tenant and group.manager and group.manager.tenant_id == tenant else None},
                {"label": "Priority override reason", "value": ticket.priority_override_reason},
                {"label": "Following", "value": str(core.is_following_ticket(user, ticket))},
                {"label": "Approval revision", "value": str(ticket.change_revision.revision) if ticket.change_revision else None},
                {"label": "Customer rating", "value": str(ticket.csat_rating) if ticket.csat_rating else None},
                {"label": "Customer feedback", "value": ticket.csat_comment},
            ]}]})
        if not core.effective_role_has_action(user.effective_role, "comment_internal"):
            fields = sections[0]["entries"][0]["fields"]
            sections[0]["entries"][0]["fields"] = [field for field in fields if field["label"] not in {
                "Team manager", "Priority override reason", "Approval revision",
            }]
        slas = TaskSLA.query.filter_by(target_type="ticket", target_id=ticket.id).order_by(TaskSLA.id).all()
        sections.append({"id": "slas", "title": "Service level agreements", "entries": [
            {"id": str(row.id), "title": row.definition.name, "fields": [
                {"label": "Stage", "value": row.stage}, {"label": "Breached", "value": str(row.breached)},
                {"label": "Started", "value": row.started_at.isoformat()},
                {"label": "Breach time", "value": row.breach_at.isoformat()},
                {"label": "Stopped", "value": row.stopped_at.isoformat() if row.stopped_at else None},
            ]} for row in slas if row.definition and row.definition.tenant_id == tenant]})
        related = []
        for item in core.related_records("ticket", ticket.id):
            other = item["record"]
            if core.record_tenant_id(other) != tenant:
                continue
            if isinstance(other, core.Ticket) and not core.user_can_view_ticket(user, other):
                continue
            if isinstance(other, core.EnterpriseRecord) and not core.user_can_view_enterprise_record(user, other):
                continue
            if isinstance(other, core.CatalogRequest) and not core.user_can_view_catalog_request(user, other):
                continue
            if isinstance(other, (core.RequestedItem, core.CatalogTask)):
                parent = other.request if isinstance(other, core.RequestedItem) else other.requested_item.request
                if not core.user_can_view_catalog_request(user, parent):
                    continue
            if isinstance(other, core.Knowledge) and (not other.published or other.archived):
                continue
            if isinstance(other, core.OperationalTask):
                parent = core.record_reference(other.parent_type, other.parent_id)
                if not parent or (isinstance(parent, core.Ticket) and not core.user_can_view_ticket(user, parent)) or (isinstance(parent, core.EnterpriseRecord) and not core.user_can_view_enterprise_record(user, parent)):
                    continue
            related.append({"id": str(item["link"].id), "title": f'{item["label"]} · {item["number"]}',
                            "fields": [{"label": "Title", "value": item["title"]}, {"label": "Direction", "value": item["direction"]}]})
        sections.append({"id": "related", "title": "Related records", "entries": related})
        return sections
    except HTTPException:
        raise
    except Exception:
        current_app.logger.exception("Public ticket sections failed")
        raise

# The versioned client contract is intentionally independent of HTML labels.
TICKET_DETAIL_SCHEMAS = {
    "TicketDetailField": {"type": "object", "required": ["label", "value"], "properties": {
        "label": {"type": "string"}, "value": {"type": ["string", "null"]},
    }},
    "TicketDetailEntry": {"type": "object", "required": ["id", "title", "fields"], "properties": {
        "id": {"type": "string"}, "title": {"type": "string"},
        "fields": {"type": "array", "items": {"$ref": "#/components/schemas/TicketDetailField"}},
    }},
    "TicketDetailSection": {"type": "object", "required": ["id", "title", "entries"], "properties": {
        "id": {"type": "string"}, "title": {"type": "string"},
        "entries": {"type": "array", "items": {"$ref": "#/components/schemas/TicketDetailEntry"}},
    }},
    "TicketRackLocation": {"type": "object", "required": ["id", "name", "site", "capacity", "position", "u_height", "face"], "properties": {
        "id": {"type": "integer"}, "name": {"type": "string"}, "site": {"type": "string"},
        "capacity": {"type": "integer"}, "position": {"type": ["number", "null"]},
        "u_height": {"type": ["integer", "null"]}, "face": {"type": ["string", "null"]},
    }},
    "TicketConfigurationItem": {"type": "object", "required": ["id", "name", "ci_class", "environment", "status", "relationship_role", "rack"], "properties": {
        "id": {"type": "integer"}, "name": {"type": "string"}, "ci_class": {"type": "string"},
        "environment": {"type": "string"}, "status": {"type": "string"}, "relationship_role": {"type": "string"},
        **{key: {"type": ["string", "null"]} for key in ("ip_address", "location", "serial_number", "vendor", "model", "description")},
        "rack": {"anyOf": [{"$ref": "#/components/schemas/TicketRackLocation"}, {"type": "null"}]},
    }},
    "TicketDetails": {"type": "object", "required": ["schema_version", "can_manage", "allowed_states", "configuration_items", "sections"], "properties": {
        "schema_version": {"type": "integer", "const": 1}, "can_manage": {"type": "boolean"},
        "allowed_states": {"type": "array", "items": {"type": "string"}},
        "configuration_items": {"type": "array", "items": {"$ref": "#/components/schemas/TicketConfigurationItem"}},
        "sections": {"type": "array", "items": {"$ref": "#/components/schemas/TicketDetailSection"}},
    }},
    "TicketDetailsEnvelope": {"type": "object", "required": ["data"], "properties": {
        "data": {"$ref": "#/components/schemas/TicketDetails"},
    }},
}
