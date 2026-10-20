"""Parent and child incidents.

An incident can have one parent incident; a parent can have many children.
The link is a RecordLink (child -> parent, link_type "parent_incident"), the
same row the related-records list shows, so every path that sets a parent goes
through set_parent() and its rules: one parent, no loops, same tenant, and only
incidents the person may see.
"""
from flask import abort

import app as core
from serviceops_core.localization import tr
from serviceops_models import RecordLink, Ticket, db

LINK = "parent_incident"


def parent_of(ticket):
    link = RecordLink.query.filter_by(source_type="ticket", source_id=ticket.id, link_type=LINK).first()
    parent = db.session.get(Ticket, link.target_id) if link else None
    return parent if parent is not None and parent.tenant_id == ticket.tenant_id else None


def children_of(ticket):
    ids = [row.source_id for row in RecordLink.query.filter_by(
        target_type="ticket", target_id=ticket.id, link_type=LINK)]
    if not ids:
        return []
    return Ticket.query.filter(Ticket.id.in_(ids), Ticket.tenant_id == ticket.tenant_id,
                               Ticket.deleted_at.is_(None)).order_by(Ticket.id).all()


def _ancestors(ticket, limit=50):
    seen, current = set(), ticket
    while current is not None and current.id not in seen and len(seen) < limit:
        seen.add(current.id)
        current = parent_of(current)
    return seen


def find_parent(user, number, tenant_id):
    """The incident `number` names, if this person may make it a parent."""
    number = (number or "").strip().upper()
    parent = core.find_record_by_number(number) if number else None
    if not isinstance(parent, Ticket) or parent.tenant_id != tenant_id or not core.user_can_view_ticket(user, parent):
        abort(404, description=tr("No incident matches {number}.", number=number))
    if parent.kind != "incident":
        abort(400, description=tr("Only an incident can be the parent of an incident."))
    return parent


def set_parent(user, child, number):
    """Make `number` the child's parent incident; an empty number removes it.
    Returns the new parent (or None). Aborts with a clear reason otherwise."""
    current = parent_of(child)
    number = (number or "").strip().upper()
    parent = None
    if number:
        parent = find_parent(user, number, child.tenant_id)
        if child.kind != "incident":
            abort(400, description=tr("Only an incident can be the parent of an incident."))
        if parent.id == child.id:
            abort(400, description=tr("An incident cannot be its own parent."))
        if child.id in _ancestors(parent):
            abort(409, description=tr("{parent} is already a child of {child}; an incident cannot be its own "
                                      "ancestor.", parent=parent.number, child=child.number))
    if (current.id if current else None) == (parent.id if parent else None):
        return parent
    RecordLink.query.filter_by(source_type="ticket", source_id=child.id, link_type=LINK).delete()
    if current is not None:
        core.log_history("ticket", current.id, "Child incident removed", details=f"{child.number} is no longer a child.")
    if parent is not None:
        db.session.add(RecordLink(source_type="ticket", source_id=child.id, target_type="ticket",
                                  target_id=parent.id, link_type=LINK))
        core.log_history("ticket", parent.id, "Child incident added", details=f"{child.number}: {child.title}")
    core.log_history("ticket", child.id, "Field changed", "parent incident",
                     current.number if current else "None", parent.number if parent else "None")
    core.audit("parent incident", child.number, f"{current.number if current else 'none'} -> "
               f"{parent.number if parent else 'none'}")
    return parent
