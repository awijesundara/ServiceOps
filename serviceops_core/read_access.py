"""What a person may read, for every AI-facing reader: the chat assistant, incident
investigations and the MCP server.

One place to audit. Each function takes the acting identity (a User, or the
SimpleNamespace the AI features build with the acting role) and returns a query
already limited to that person's tenant and permissions, built on the same
visibility helpers the application's own pages use. Callers narrow these
queries further; they never widen them or write their own for these record
types.
"""
from sqlalchemy import false

from serviceops_core.ci_class_policy import ci_class_read_allowed, restrict_ci_query_to_readable_classes
from serviceops_models import ConfigurationItem, Knowledge, Ticket


def _role(identity):
    return getattr(identity, "effective_role", None) or getattr(identity, "role", None)


def tickets(identity):
    """Incidents and changes this person can open in ServiceOps, excluding deleted ones."""
    from app import visible_ticket_query

    return visible_ticket_query(identity).filter(Ticket.deleted_at.is_(None))


def published_knowledge(identity):
    """Current, published articles of the person's tenant: what the assistant answers from."""
    return Knowledge.query.filter(Knowledge.tenant_id == identity.tenant_id, Knowledge.published.is_(True),
                                  Knowledge.archived.is_(False))


def reviewable_knowledge(identity):
    """Knowledge as the knowledge pages show it: drafts for agents and above, archived versions for all."""
    from app import visible_knowledge_query

    return visible_knowledge_query(identity)


def may_read_cmdb(identity):
    """Requesters have no CMDB access in the application, so AI readers give them none either."""
    from app import role_at_least

    return bool(_role(identity)) and role_at_least(_role(identity), "agent")


def configuration_items(identity):
    """CIs of the person's tenant in classes their role may read; nothing for requesters."""
    query = ConfigurationItem.query.filter(ConfigurationItem.tenant_id == identity.tenant_id)
    if not may_read_cmdb(identity):
        return query.filter(false())
    return restrict_ci_query_to_readable_classes(query, identity.tenant_id, _role(identity))


def configuration_item_readable(identity, row):
    return bool(row and row.tenant_id == identity.tenant_id and may_read_cmdb(identity)
                and ci_class_read_allowed(identity.tenant_id, row.ci_class, _role(identity)))
