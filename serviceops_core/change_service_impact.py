"""Read-only business-service impact derived from a change's explicit CI scope."""
from flask import abort, current_app
from sqlalchemy.orm import selectinload

from serviceops_core import read_access
from serviceops_core.localization import tr
from serviceops_models import ConfigurationItem, ServiceOffering, ServiceOfferingCI, TaskCI


def impacted_services(ticket, identity):
    """Each service once, with only readable in-tenant primary/affected CI evidence."""
    try:
        if ticket.kind != "change" or not ticket.tenant_id or identity.tenant_id != ticket.tenant_id:
            return []
        tenant = ticket.tenant_id
        links = TaskCI.query.filter_by(target_type="ticket", target_id=ticket.id).filter(
            TaskCI.relationship_role.in_(("Primary CI", "Affected CI")),
        ).all()
        ci_ids = {link.ci_id for link in links}
        governance = ticket.change_governance
        if governance and governance.tenant_id == tenant and governance.ci_id:
            ci_ids.add(governance.ci_id)
        if not ci_ids:
            return []
        readable = read_access.configuration_items(identity).filter(ConfigurationItem.id.in_(ci_ids))
        rows = ServiceOfferingCI.query.join(ServiceOffering).filter(
            ServiceOfferingCI.tenant_id == tenant, ServiceOffering.tenant_id == tenant,
            ServiceOfferingCI.ci_id.in_(readable.with_entities(ConfigurationItem.id)),
        ).options(selectinload(ServiceOfferingCI.service_offering), selectinload(ServiceOfferingCI.ci)).all()
        services = {}
        for row in rows:
            service = row.service_offering
            entry = services.setdefault(service.id, {
                "id": service.id, "name": service.name, "criticality": service.criticality,
                "status": service.status, "configuration_items": [],
            })
            entry["configuration_items"].append({
                "id": row.ci.id, "name": row.ci.name, "relationship_role": row.relationship_role,
            })
        for entry in services.values():
            entry["configuration_items"].sort(key=lambda ci: (ci["name"].casefold(), ci["id"]))
        return sorted(services.values(), key=lambda service: (service["name"].casefold(), service["id"]))
    except Exception as error:
        current_app.logger.error("Unable to calculate change service impact (%s)", type(error).__name__)
        abort(503, description=tr("Service impact is temporarily unavailable. Please try again."))
