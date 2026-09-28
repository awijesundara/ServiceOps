"""Read-only ServiceOps tools for the embedded MCP server (serviceops_core/mcp.py).

Every query is scoped to the API client's acting user (g.api_user) and that
user's tenant explicitly, through serviceops_core.read_access (shared with the
chat assistant): bearer-token requests have no logged-in current_user, so
tenant_query()/tenant_context_id() must not be used here.
"""
from __future__ import annotations

from flask import g

from serviceops_core import read_access
from serviceops_core.mcp import Tool, ToolInputError

MAX_LIMIT = 50
KNOWLEDGE_BODY_CHARS = 4000
TICKET_COMMENT_LIMIT = 20


def _text(arguments, name, required=False, max_length=200):
    value = arguments.get(name)
    if value is None or value == "":
        if required:
            raise ToolInputError(f"'{name}' is required.")
        return ""
    if not isinstance(value, str):
        raise ToolInputError(f"'{name}' must be a string.")
    value = value.strip()
    if len(value) > max_length:
        raise ToolInputError(f"'{name}' must be at most {max_length} characters.")
    return value


def _limit(arguments, default=20):
    value = arguments.get("limit", default)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_LIMIT:
        raise ToolInputError(f"'limit' must be an integer from 1 to {MAX_LIMIT}.")
    return value


def _pattern(value):
    import app as core

    return f"%{core.escape_like(value)}%"


def search_tickets(arguments):
    import app as core

    query_text = _text(arguments, "query")
    kind = _text(arguments, "type")
    state = _text(arguments, "state", max_length=40)
    limit = _limit(arguments)
    if kind and kind not in ("incident", "change"):
        raise ToolInputError("'type' must be 'incident' or 'change'.")
    query = read_access.tickets(g.api_user)
    if kind:
        query = query.filter(core.Ticket.kind == kind)
    if state:
        query = query.filter(core.Ticket.state == state)
    if query_text:
        pattern = _pattern(query_text)
        query = query.filter(core.db.or_(
            core.Ticket.number.ilike(pattern, escape="\\"),
            core.Ticket.title.ilike(pattern, escape="\\"),
            core.Ticket.description.ilike(pattern, escape="\\"),
        ))
    rows = query.order_by(core.Ticket.updated_at.desc()).limit(limit).all()
    return {"tickets": [{
        "number": row.number, "type": row.kind, "title": row.title, "state": row.state,
        "priority": row.priority, "category": row.category, "subcategory": row.subcategory,
        "updated_at": row.updated_at.isoformat(),
    } for row in rows]}


def get_ticket(arguments):
    import app as core

    number = _text(arguments, "number", required=True, max_length=24)
    ticket = read_access.tickets(g.api_user).filter(
        core.func.upper(core.Ticket.number) == number.upper()
    ).first()
    if not ticket:
        raise ToolInputError(f"No ticket {number} is visible to this API client.")
    document = core.api_ticket_document(ticket, g.api_user)
    document["comments"] = [{
        "author": comment.author.name, "body": comment.body, "created_at": comment.created_at.isoformat(),
    } for comment in sorted(ticket.comments, key=lambda row: row.created_at)[-TICKET_COMMENT_LIMIT:]]
    return document


def search_configuration_items(arguments):
    import app as core

    user = g.api_user
    if not read_access.may_read_cmdb(user):
        raise ToolInputError("Configuration item access requires the agent role.")
    query_text = _text(arguments, "query")
    ci_class = _text(arguments, "ci_class", max_length=80)
    limit = _limit(arguments)
    query = read_access.configuration_items(user)
    if ci_class:
        query = query.filter(core.ConfigurationItem.ci_class == ci_class)
    if query_text:
        pattern = _pattern(query_text)
        query = query.filter(core.db.or_(
            core.ConfigurationItem.name.ilike(pattern, escape="\\"),
            core.ConfigurationItem.ip_address.ilike(pattern, escape="\\"),
            core.ConfigurationItem.serial_number.ilike(pattern, escape="\\"),
            core.ConfigurationItem.description.ilike(pattern, escape="\\"),
        ))
    rows = query.order_by(core.ConfigurationItem.name).limit(limit).all()
    return {"configuration_items": [{
        "id": row.id, "name": row.name, "class": row.ci_class, "environment": row.environment,
        "status": row.operational_status, "ip_address": row.ip_address,
        "owning_team": row.support_group.name if row.support_group else None,
    } for row in rows]}


def search_knowledge(arguments):
    import app as core

    query_text = _text(arguments, "query", required=True)
    limit = _limit(arguments, default=10)
    pattern = _pattern(query_text)
    rows = read_access.reviewable_knowledge(g.api_user).filter(core.db.or_(
        core.Knowledge.title.ilike(pattern, escape="\\"),
        core.Knowledge.body.ilike(pattern, escape="\\"),
    )).order_by(core.Knowledge.created_at.desc()).limit(limit).all()
    return {"articles": [{
        "number": f"KB{row.id:07d}", "title": row.title, "category": row.category,
        "status": "archived" if row.archived else ("published" if row.published else "draft"),
        "body": row.body[:KNOWLEDGE_BODY_CHARS],
        "truncated": len(row.body) > KNOWLEDGE_BODY_CHARS,
    } for row in rows]}


def list_my_approvals(arguments):
    import app as core

    user = g.api_user
    limit = _limit(arguments)
    rows = core.ApprovalVote.query.join(core.ApprovalGate).join(core.ApprovalChain).filter(
        core.ApprovalVote.approver_id == user.id,
        core.ApprovalVote.state == "Requested",
        core.ApprovalChain.tenant_id == user.tenant_id,
    ).order_by(core.ApprovalVote.id.desc()).limit(limit).all()
    approvals = []
    for vote in rows:
        chain = vote.gate.chain
        target = core.record_reference(chain.target_type, chain.target_id)
        if target and core.record_tenant_id(target) != user.tenant_id:
            target = None
        approvals.append({
            "vote_id": vote.id, "gate": vote.gate.name, "chain": chain.name,
            "record": core.record_number(target) if target else None,
            "record_title": core.record_title(target) if target else None,
        })
    return {"pending_approvals": approvals}


def _schema(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


LIMIT_PROPERTY = {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "description": "Maximum results."}

TOOLS = [
    Tool(
        name="search_tickets", title="Search incidents and changes", scope="tickets:read",
        description=(
            "Search incidents and changes the acting user can see, newest activity first. "
            "Matches number, title and description."
        ),
        input_schema=_schema({
            "query": {"type": "string", "description": "Text to match; omit to list recent tickets."},
            "type": {"type": "string", "enum": ["incident", "change"]},
            "state": {"type": "string", "description": "Exact state, e.g. 'In Progress' or 'Resolved'."},
            "limit": LIMIT_PROPERTY,
        }),
        handler=search_tickets,
    ),
    Tool(
        name="get_ticket", title="Get a ticket", scope="tickets:read",
        description=(
            "Full details of one incident or change by number (e.g. INC0000123), including "
            "logging and closure categorisation, resolution notes and recent comments."
        ),
        input_schema=_schema({"number": {"type": "string", "description": "Ticket number."}}, required=["number"]),
        handler=get_ticket,
    ),
    Tool(
        name="search_configuration_items", title="Search the CMDB", scope="cmdb:read",
        description=(
            "Search configuration items by name, IP address, serial number or description. "
            "Requires the agent role; CI classes the user may not read are excluded."
        ),
        input_schema=_schema({
            "query": {"type": "string"},
            "ci_class": {"type": "string", "description": "Exact CI class, e.g. 'Server'."},
            "limit": LIMIT_PROPERTY,
        }),
        handler=search_configuration_items,
    ),
    Tool(
        name="search_knowledge", title="Search the knowledge base", scope="knowledge:read",
        description="Search knowledge articles by title and body. Drafts are only returned to agents and above.",
        input_schema=_schema({"query": {"type": "string"}, "limit": LIMIT_PROPERTY}, required=["query"]),
        handler=search_knowledge,
    ),
    Tool(
        name="list_my_approvals", title="List my pending approvals", scope="approvals:read",
        description="Approval votes waiting on the acting user, with the record each one is for.",
        input_schema=_schema({"limit": LIMIT_PROPERTY}),
        handler=list_my_approvals,
    ),
]
