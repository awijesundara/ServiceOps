"""Transactional administration of service details and initial CI mappings."""
import json
from flask import abort, current_app, request
from flask_login import current_user
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import HTTPException

from serviceops_core import read_access
from serviceops_core.localization import tr
from serviceops_core.request_values import form_int
from serviceops_models import ConfigurationItem, ServiceOffering, ServiceOfferingCI, SupportGroup, db


def save_service_offering(service_id=None):
    """Validate the whole form before saving a service and optional initial CIs."""
    import app as core
    try:
        service = core.tenant_record_or_404(ServiceOffering, service_id) if service_id else None
        name = request.form.get('name', '').strip()
        if not name or len(name) > 160:
            abort(400, description=tr('Service name must contain 1 to 160 characters.'))
        duplicates = core.tenant_query(ServiceOffering).filter(func.lower(ServiceOffering.name) == name.lower())
        if service:
            duplicates = duplicates.filter(ServiceOffering.id != service.id)
        if duplicates.first():
            abort(409, description=tr('A service with that name already exists.'))
        criticality = request.form.get('criticality', 'Medium')
        if criticality not in ('Critical', 'High', 'Medium', 'Low'):
            abort(400, description=tr('Select a valid criticality.'))
        group = core.tenant_record_or_404(SupportGroup, form_int('support_group_id', required=True))
        if not core.is_team_group(group, current_user.tenant_id) and (not service or service.support_group_id != group.id):
            abort(400, description=tr('Select an active owning team.'))
        try:
            ci_ids = set(int(value) for value in request.form.getlist('ci_id') if value.strip())
        except ValueError:
            abort(400, description=tr('Select valid configuration items.'))
        cis = read_access.configuration_items(current_user).filter(ConfigurationItem.id.in_(ci_ids)).all() if ci_ids else []
        if {ci.id for ci in cis} != ci_ids:
            abort(404)
        fields = ('name', 'owner_id', 'support_group_id', 'criticality')
        before = {field: getattr(service, field) for field in fields} if service else None
        if not service:
            service = ServiceOffering(tenant_id=current_user.tenant_id, status='Operational')
            db.session.add(service)
        service.name = name
        service.support_group_id = group.id
        service.criticality = criticality
        db.session.flush()
        existing_ci_ids = {identifier for identifier, in db.session.query(ServiceOfferingCI.ci_id).filter(
            ServiceOfferingCI.tenant_id == current_user.tenant_id,
            ServiceOfferingCI.service_offering_id == service.id,
            ServiceOfferingCI.ci_id.in_(ci_ids),
        )} if ci_ids else set()
        for ci in cis:
            if ci.id not in existing_ci_ids:
                db.session.add(ServiceOfferingCI(service_offering_id=service.id, ci_id=ci.id,
                                                relationship_role='Supporting', tenant_id=current_user.tenant_id))
        after = {field: getattr(service, field) for field in fields}
        core.audit('configure' if before else 'create', f'Service offering: {name}'[:120],
                   json.dumps({'before': before, 'after': after, 'linked_ci_ids': sorted(ci_ids)}))
        db.session.commit()
        return service
    except HTTPException:
        db.session.rollback()
        raise
    except IntegrityError:
        db.session.rollback()
        current_app.logger.warning('Service offering save conflicted with a database constraint')
        abort(409, description=tr('The service could not be saved. Refresh and check its name and owning team.'))
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.error('Database failure while saving a service offering')
        abort(503, description=tr('The service could not be saved. Please try again.'))
    except Exception as error:
        db.session.rollback()
        current_app.logger.error('Service offering save failed (%s)', type(error).__name__)
        abort(503, description=tr('The service could not be saved. Please try again.'))
