"""Shared, tenant-scoped published service health."""
from sqlalchemy import func
from serviceops_models import ServiceOffering, ServiceOutage


def published_service_health(tenant_id):
    """Return published services and health without exposing internal CIs."""
    services = ServiceOffering.query.filter_by(
        tenant_id=tenant_id, status_page_visible=True,
    ).order_by(ServiceOffering.name, ServiceOffering.id).all()
    outages = {row[0]: row[1] for row in ServiceOutage.query.with_entities(
        ServiceOutage.service_offering_id, func.min(ServiceOutage.started_at),
    ).join(ServiceOffering, ServiceOffering.id == ServiceOutage.service_offering_id).filter(
        ServiceOffering.tenant_id == tenant_id, ServiceOffering.status_page_visible.is_(True),
        ServiceOutage.tenant_id == tenant_id, ServiceOutage.ended_at.is_(None),
    ).group_by(ServiceOutage.service_offering_id).all()}
    return services, {service.id: {'state': 'outage' if service.id in outages else
                     'operational' if service.status == 'Operational' else 'degraded', 'since': outages.get(service.id)} for service in services}


def employee_service_notices(identity, page=1):
    """Internal freezes and readable planned changes affecting published services."""
    from datetime import timedelta, timezone
    from sqlalchemy import select
    from serviceops_core import read_access
    from serviceops_models import (ChangeFreezeWindow, ChangeGovernance, ConfigurationItem,
                                   ServiceOfferingCI, TaskCI, Ticket, db, now)

    at = now()
    horizon = at + timedelta(days=14)
    tenant = identity.tenant_id
    freezes = ChangeFreezeWindow.query.filter(
        ChangeFreezeWindow.tenant_id == tenant, ChangeFreezeWindow.ends_at > at,
        ChangeFreezeWindow.starts_at <= horizon,
        ChangeFreezeWindow.ends_at > ChangeFreezeWindow.starts_at,
    )
    scope = select(ChangeGovernance.ticket_id.label('ticket_id'), ChangeGovernance.ci_id.label('ci_id')).where(
        ChangeGovernance.tenant_id == tenant, ChangeGovernance.ci_id.is_not(None),
    ).union(select(TaskCI.target_id.label('ticket_id'), TaskCI.ci_id.label('ci_id')).join(
        Ticket, Ticket.id == TaskCI.target_id,
    ).where(TaskCI.target_type == 'ticket', Ticket.tenant_id == tenant,
            TaskCI.relationship_role.in_(('Primary CI', 'Affected CI')))).subquery()
    readable_cis = read_access.configuration_items(identity).with_entities(ConfigurationItem.id)
    visible_tickets = read_access.tickets(identity).with_entities(Ticket.id)
    work = db.session.query(Ticket).join(ChangeGovernance, ChangeGovernance.ticket_id == Ticket.id).join(
        scope, scope.c.ticket_id == Ticket.id,
    ).join(ServiceOfferingCI, ServiceOfferingCI.ci_id == scope.c.ci_id).join(
        ServiceOffering, ServiceOffering.id == ServiceOfferingCI.service_offering_id,
    ).filter(Ticket.id.in_(visible_tickets), Ticket.tenant_id == tenant, Ticket.kind == 'change',
             Ticket.deleted_at.is_(None), Ticket.state.in_(('Approved', 'In Progress')),
             ChangeGovernance.tenant_id == tenant, ChangeGovernance.planned_end > at,
             ChangeGovernance.planned_start <= horizon,
             ChangeGovernance.planned_end > ChangeGovernance.planned_start,
             ServiceOfferingCI.tenant_id == tenant, ServiceOffering.tenant_id == tenant,
             ServiceOffering.status_page_visible.is_(True), scope.c.ci_id.in_(readable_cis))
    from sqlalchemy import case, func, literal
    from math import ceil

    work_windows = work.with_entities(Ticket.id.label('id'), ChangeGovernance.planned_start.label('start'),
                                     ChangeGovernance.planned_end.label('end')).distinct().subquery()
    freeze_windows = freezes.with_entities(ChangeFreezeWindow.id.label('id'),
        ChangeFreezeWindow.starts_at.label('start'), ChangeFreezeWindow.ends_at.label('end')).subquery()
    windows = select(literal('freeze').label('kind'), freeze_windows.c.id,
                     freeze_windows.c.start, freeze_windows.c.end).union_all(select(
        literal('work').label('kind'), work_windows.c.id, work_windows.c.start, work_windows.c.end)).subquery()
    total = db.session.execute(select(func.count()).select_from(windows)).scalar_one()
    pages = max(1, ceil(total / 20))
    page = max(1, min(page, pages))
    selected = db.session.execute(select(windows).order_by(
        case((windows.c.start <= at, 0), else_=1), windows.c.start, windows.c.kind, windows.c.id,
    ).offset((page - 1) * 20).limit(20)).all()
    freeze_ids = [row.id for row in selected if row.kind == 'freeze']
    work_ids = [row.id for row in selected if row.kind == 'work']
    entries = {}
    if freeze_ids:
        for window in freezes.filter(ChangeFreezeWindow.id.in_(freeze_ids)):
            entries[('freeze', window.id)] = {'title': window.title, 'number': None, 'ticket_id': None}
    if work_ids:
        for ticket, name in work.filter(Ticket.id.in_(work_ids)).with_entities(Ticket, ServiceOffering.name).distinct():
            entry = entries.setdefault(('work', ticket.id), {'services': set(), 'number': ticket.number,
                                                           'ticket_id': ticket.id})
            entry['services'].add(name)
    notices = []
    for row in selected:
        entry = entries[(row.kind, row.id)]
        starts = row.start if row.start.tzinfo else row.start.replace(tzinfo=timezone.utc)
        if row.kind == 'work':
            entry['title'] = ', '.join(sorted(entry.pop('services'), key=str.casefold))
        entry.update(kind=row.kind, start=row.start, end=row.end, active=starts <= at)
        notices.append(entry)
    return {'items': notices, 'total': total, 'horizon': horizon, 'page': page, 'pages': pages}
