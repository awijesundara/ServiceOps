"""Install-wide release policy, network restrictions and synthetic sandbox requests."""
import ipaddress
import json
from datetime import timedelta
from zoneinfo import ZoneInfo,ZoneInfoNotFoundError

from flask import abort,current_app,request
from sqlalchemy import func

import app as core
from serviceops_models import db,now,PlatformSetting,Audit,User,Tenant
from serviceops_core.localization import tr
from serviceops_core.projects import service,roadmap,advanced_plans
from serviceops_core.projects.models import ProjectSandbox,WorkItem,Project,ProjectAutomationRun

POLICY_KEY='PREMIUM_PLATFORM_POLICY'


@roadmap.guarded
def require_admin(actor):
    if not service._tenant_admin(actor):abort(403)
    if Tenant.query.count()>1 and not core.effective_role_has_action(actor.effective_role,'platform_administer'):abort(403)


@roadmap.guarded
def policy():
    cached=core._request_setting_rows()
    row=cached.get(POLICY_KEY) if cached is not None else db.session.get(PlatformSetting,POLICY_KEY)
    result=json.loads(row.value) if row else dict(track='continuous',next_release=None,timezone='UTC',ip_networks=[])
    result.setdefault('revision',0)
    return result


@roadmap.guarded
def save_policy(actor,data,client_ip=None):
    require_admin(actor)
    if not isinstance(data,dict) or set(data)-{'track','next_release','timezone','ip_networks','revision'}:abort(400)
    track=data.get('track','continuous');zone=data.get('timezone','UTC');networks=data.get('ip_networks',[])
    if track not in ('continuous','bundled') or not isinstance(zone,str):abort(400)
    try:ZoneInfo(zone)
    except (ZoneInfoNotFoundError,ValueError):abort(400)
    release=roadmap.parse_date(data.get('next_release'),track=='bundled')
    if track=='bundled' and release<now().astimezone(ZoneInfo(zone)).date():abort(400,description=tr('Choose today or a future release date.'))
    if not isinstance(networks,list) or len(networks)>100:abort(400)
    cleaned=[]
    for network in networks:
        try:
            if not isinstance(network,str):raise ValueError()
            value=ipaddress.ip_network(network.strip(),strict=False)
            if value.prefixlen==0:abort(400,description=tr('A zero-prefix network does not restrict access. Remove the policy to allow everyone.'))
            cleaned.append(str(value))
        except ValueError:abort(400,description=tr('Use valid IPv4 or IPv6 networks.'))
    if cleaned and client_ip and not any(ipaddress.ip_address(client_ip) in ipaddress.ip_network(n) for n in cleaned):abort(409,description=tr('Include your current client address before enabling the IP allowlist.'))
    Tenant.query.order_by(Tenant.id).with_for_update().all()
    row=PlatformSetting.query.filter_by(key=POLICY_KEY).with_for_update().populate_existing().first()
    previous=json.loads(row.value) if row else {}
    if type(data.get('revision')) is not int or data['revision']!=previous.get('revision',0):abort(409,description=tr('The installation policy changed. Reload before saving.'))
    value=previous|dict(track=track,next_release=release.isoformat() if release else None,timezone=zone,ip_networks=sorted(set(cleaned)),revision=previous.get('revision',0)+1)
    if row is None:row=PlatformSetting(key=POLICY_KEY,tenant_id=actor.tenant_id);db.session.add(row)
    row.value=json.dumps(value);row.updated_by_id=actor.id;db.session.flush()
    core.audit('premium platform policy saved',POLICY_KEY,f'track={track}; networks={len(cleaned)}',user_id=actor.id,tenant_id=actor.tenant_id)
    return value


@roadmap.guarded
def enforce_network():
    if request.path in ('/health','/ready','/metrics') or request.path.startswith('/static/'):return
    if not request.endpoint:return
    rules=policy().get('ip_networks',[])
    if not rules:return
    try:address=ipaddress.ip_address(request.remote_addr or '')
    except ValueError:abort(403)
    if not any(address in ipaddress.ip_network(n) for n in rules):abort(403,description=tr('This client address is outside the installation IP allowlist.'))


@roadmap.guarded
def request_sandbox(actor,name,hours):
    require_admin(actor)
    if not current_app.config.get('PREMIUM_SANDBOX_ENABLED',False):abort(409,description=tr('The operator must enable the isolated sandbox controller before creating environments.'))
    if type(hours) is not int or not 1<=hours<=168:abort(400)
    # Serialize the installation-wide two-environment resource budget.
    Tenant.query.order_by(Tenant.id).with_for_update().all()
    if ProjectSandbox.query.filter(ProjectSandbox.state!='deleted').count()>=2:abort(409,description=tr('Delete an existing sandbox before creating a third environment.'))
    occupied={r.slot for r in ProjectSandbox.query.filter(ProjectSandbox.state!='deleted')}
    slot=next(i for i in (1,2) if i not in occupied)
    row=ProjectSandbox(slot=slot,tenant_id=actor.tenant_id,owner_id=actor.id,name=advanced_plans.text(name,100),expires_at=now()+timedelta(hours=hours))
    db.session.add(row);db.session.flush();core.audit('sandbox requested',str(row.id),'synthetic data only; ttl_hours='+str(hours),user_id=actor.id,tenant_id=actor.tenant_id)
    return row


@roadmap.guarded
def delete_sandbox(actor,identifier):
    require_admin(actor)
    row=ProjectSandbox.query.filter_by(id=identifier,tenant_id=actor.tenant_id).with_for_update().populate_existing().first()
    if row is None:abort(404)
    if row.state!='deleted':row.state='deleting';row.updated_at=now()
    core.audit('sandbox deletion requested',str(row.id),'synthetic sandbox data will be removed',user_id=actor.id,tenant_id=actor.tenant_id)
    return row


@roadmap.guarded
def insights(actor):
    require_admin(actor);cutoffs={name:now()-timedelta(days=days) for name,days in (('daily',1),('weekly',7),('monthly',30))}
    active={name:db.session.query(func.count(func.distinct(Audit.user_id))).filter(Audit.tenant_id==actor.tenant_id,Audit.created_at>=cutoff,Audit.user_id.isnot(None)).scalar() for name,cutoff in cutoffs.items()}
    return dict(active_users=active,users=User.query.filter_by(tenant_id=actor.tenant_id,active=True).count(),projects=Project.query.filter_by(tenant_id=actor.tenant_id).count(),work_items=WorkItem.query.filter_by(tenant_id=actor.tenant_id).count(),
        automation_runs=ProjectAutomationRun.query.filter(ProjectAutomationRun.tenant_id==actor.tenant_id,ProjectAutomationRun.created_at>=cutoffs['monthly']).count())
