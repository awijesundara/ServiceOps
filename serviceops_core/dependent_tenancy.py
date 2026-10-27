"""tenant_id for records that belong to another record.

Tasks, SLAs, history, notes, CI links, preferences and similar rows used to
inherit their tenant only through a parent. They now store it too, so
queries, exports and constraints can be tenant-scoped directly. The value is
always taken from the parent, never from whoever happens to be signed in, so
background jobs and API calls set it correctly as well. Migration
20261025_0145 (and 20261027_0146 for approval chains and contracts) backfill
existing rows with the same rules (keep the two in
step when a parent type is added).
"""
import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.orm import Session

from serviceops_models import (APIClient, ApprovalChain, Contract, APIRateLimitWindow, BusinessSchedule, CatalogRequest, CatalogTask,
                               CatalogTaskControl, ChangeOwnership, ChangeRevision, ChecklistItem, ClientTicket,
                               ConfigurationItem, EnterpriseRecord, ExternalIdentity, Favorite, Knowledge,
                               MajorIncidentProfile, ManagedRoleGrant, NotificationPreference, OperationalTask,
                               ProblemProfile, RecentView, RecordLink, RequestedItem, ScheduleHoliday, TaskCI,
                               TaskHistory, TaskNote, TaskSLA, Ticket, TicketAssignmentGroup, User,
                               UserPreference, UserRoleGrant, WorkItem, tenant_context_id)

# Model -> (foreign-key attribute, parent model).
DIRECT_PARENTS = {
    APIRateLimitWindow: ("api_client_id", APIClient),
    CatalogTaskControl: ("task_id", CatalogTask),
    ChangeOwnership: ("ticket_id", Ticket),
    ChangeRevision: ("ticket_id", Ticket),
    ChecklistItem: ("ticket_id", Ticket),
    MajorIncidentProfile: ("ticket_id", Ticket),
    TicketAssignmentGroup: ("ticket_id", Ticket),
    ExternalIdentity: ("user_id", User),
    Favorite: ("user_id", User),
    ManagedRoleGrant: ("user_id", User),
    NotificationPreference: ("user_id", User),
    RecentView: ("user_id", User),
    UserPreference: ("user_id", User),
    UserRoleGrant: ("user_id", User),
    ProblemProfile: ("enterprise_record_id", EnterpriseRecord),
    ScheduleHoliday: ("schedule_id", BusinessSchedule),
}

# Model -> (type attribute, id attribute) for rows that can point at several record types.
POLYMORPHIC_PARENTS = {
    OperationalTask: ("parent_type", "parent_id"),
    TaskCI: ("target_type", "target_id"),
    TaskHistory: ("target_type", "target_id"),
    TaskNote: ("target_type", "target_id"),
    TaskSLA: ("target_type", "target_id"),
    RecordLink: ("source_type", "source_id"),
}

# Every record type a polymorphic row may point at.
RECORD_TYPES = {
    "ticket": Ticket,
    "enterprise": EnterpriseRecord,
    "request": CatalogRequest,
    "ritm": RequestedItem,
    "catalog_task": CatalogTask,
    "sctask": CatalogTask,
    "operational_task": OperationalTask,
    "work_task": OperationalTask,
    "ci": ConfigurationItem,
    "client_ticket": ClientTicket,
    "work_item": WorkItem,
    "knowledge": Knowledge,
    "approval_chain": ApprovalChain,
    "contract": Contract,
}


def _tenant_of(session, model, identifier):
    if model is None or identifier is None:
        return None
    parent = session.get(model, identifier)
    if parent is None:
        return None
    return parent_tenant(session, parent)


def parent_tenant(session, row):
    """The tenant a row belongs to: its own column, else its parent's."""
    tenant = getattr(row, "tenant_id", None)
    if tenant is not None:
        return tenant
    model = type(row)
    if model in DIRECT_PARENTS:
        attribute, parent_model = DIRECT_PARENTS[model]
        return _tenant_of(session, parent_model, getattr(row, attribute))
    if model in POLYMORPHIC_PARENTS:
        type_attribute, id_attribute = POLYMORPHIC_PARENTS[model]
        return _tenant_of(session, RECORD_TYPES.get(getattr(row, type_attribute)), getattr(row, id_attribute))
    return None


def _parent(row):
    """(parent model, parent id) for a dependent row, or (None, None)."""
    model = type(row)
    if model in DIRECT_PARENTS:
        attribute, parent_model = DIRECT_PARENTS[model]
        return parent_model, getattr(row, attribute)
    type_attribute, id_attribute = POLYMORPHIC_PARENTS[model]
    return RECORD_TYPES.get(getattr(row, type_attribute)), getattr(row, id_attribute)


@event.listens_for(Session, "before_flush")
def _fill_dependent_tenant(session, flush_context, instances):
    # Parents already in the session resolve here; a parent added in this same
    # flush has no id yet and is resolved at insert time below.
    with session.no_autoflush:
        for row in list(session.new):
            if type(row) in DIRECT_PARENTS or type(row) in POLYMORPHIC_PARENTS:
                if row.tenant_id is None:
                    row.tenant_id = parent_tenant(session, row)


def _fill_at_insert(mapper, connection, row):
    """By insert time the unit of work has written the parent and set the foreign key."""
    if row.tenant_id is not None:
        return
    parent_model, parent_id = _parent(row)
    if parent_model is not None and parent_id is not None:
        table = parent_model.__table__
        row.tenant_id = connection.execute(
            sa.select(table.c.tenant_id).where(table.c.id == parent_id)).scalar()
    if row.tenant_id is None:
        # No resolvable parent at all: the signed-in tenant, or NULL in a background job.
        row.tenant_id = _signed_in_tenant()


for _model in (*DIRECT_PARENTS, *POLYMORPHIC_PARENTS):
    event.listen(_model, "before_insert", _fill_at_insert)


def _signed_in_tenant():
    """Fallback for a row with no resolvable parent; None outside a request (a background job)."""
    try:
        return tenant_context_id()
    except RuntimeError:
        return None
