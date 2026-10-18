"""Synthetic-only sample data for the isolated sandbox migration job."""
import os
import re
from urllib.parse import urlsplit


def main():
    target=urlsplit(os.environ.get('DATABASE_URL',''))
    if os.environ.get('SERVICEOPS_ENVIRONMENT')!='sandbox' or not re.fullmatch(r'serviceops-sandbox-[1-9][0-9]*-db',target.hostname or '') or target.path!='/serviceops_sandbox':
        raise RuntimeError('Synthetic sandbox seed refuses any non-sandbox database')
    import app as core
    from serviceops_models import db,User,PlatformSetting,now
    from serviceops_core.projects import service,advanced_plans,automation
    application=core.create_app()
    with application.app_context():
        actor=User.query.filter_by(username='admin').one()
        db.session.merge(PlatformSetting(key='PROJECTS_ENABLED',value='true',tenant_id=actor.tenant_id))
        for key,title in (('SAMPLEOPS','Synthetic cloud migration'),('SAMPLEAPP','Synthetic application delivery')):
            from serviceops_core.projects.models import Project
            if Project.query.filter_by(tenant_id=actor.tenant_id,key=key).first():continue
            project=service.create_project(actor,key,title,description='Synthetic learning data. No production records are copied.')
            epic=service.create_item(actor,project,'Deliver a recoverable platform',item_type='epic')
            previous=None
            for index,name in enumerate(('Architecture and inventory','Build isolated platform','Data migration rehearsal','Recovery testing','Observability and alerts','Release readiness')):
                item=service.create_item(actor,project,name,parent_id=epic.id,estimate_minutes=(index%3+1)*240,story_points=(index%3+1)*2)
                if previous:service.add_link(actor,previous,'blocks',item.key)
                previous=item
            automation.save(actor,dict(name='Example: synchronize epic completion',enabled=False,projects=[key],config=dict(trigger='transitioned',conditions=[dict(field='item_type',operator='eq',value='epic')],branch='descendants',branch_conditions=[dict(field='category',operator='ne',value='done')],actions=[dict(type='transition',copy_trigger=True)])))
            db.session.flush()
        from serviceops_core.projects.models import ProjectPlan
        if not ProjectPlan.query.filter_by(tenant_id=actor.tenant_id).first():
            plan=advanced_plans.create(actor,dict(name='Synthetic delivery portfolio',projects=['SAMPLEOPS','SAMPLEAPP'],settings=dict(start=now().date().isoformat(),weeks=2,iterations=6)))
            _,payload=advanced_plans.get(actor,plan.id)
            advanced_plans.save_team(actor,plan,payload,dict(name='Platform team',capacity=80,unit='hours',members=[actor.id]))
            advanced_plans.save_node(actor,plan,payload,dict(name='Learning portfolio',kind='Portfolio',item_keys=[r['key'] for r in payload['items'] if r['type']=='epic']))
        db.session.commit()
    print('Synthetic sandbox examples created; no production data accessed')


if __name__=='__main__':main()
