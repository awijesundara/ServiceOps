"""Reconcile synthetic sandboxes using a dedicated, namespace-restricted account.

This process never imports the web application or copies production records.
It only reads/writes its control rows. Secrets exist solely in the sandbox
namespace. All resource names derive from numeric database IDs.
"""
import json
import logging
import os
import re
import secrets
import ssl
import time
from datetime import datetime,timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request,urlopen

from sqlalchemy import create_engine,text
from cryptography.fernet import Fernet

LOG=logging.getLogger(__name__)
KINDS={'deployment':('/apis/apps/v1','deployments'),'job':('/apis/batch/v1','jobs'),'pvc':('/api/v1','persistentvolumeclaims'),'service':('/api/v1','services'),'secret':('/api/v1','secrets'),'policy':('/apis/networking.k8s.io/v1','networkpolicies')}
IMAGE=re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$')


class KubernetesError(RuntimeError):
    pass


class Kubernetes:
    def __init__(self,namespace):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,61}[a-z0-9]',namespace):raise ValueError('Invalid sandbox namespace')
        self.namespace=namespace
        self.origin='https://'+os.environ['KUBERNETES_SERVICE_HOST']+':'+os.environ.get('KUBERNETES_SERVICE_PORT','443')
        self.credentials=Path('/var/run/secrets/kubernetes.io/serviceaccount')
        self.context=ssl.create_default_context(cafile=str(self.credentials/'ca.crt'))
        if os.environ.get('SANDBOX_KUBERNETES_STRICT_X509','true').lower()=='false':
            self.context.verify_flags &= ~ssl.VERIFY_X509_STRICT
            LOG.warning('Legacy Kubernetes CA compatibility enabled; certificate and hostname verification remain required')

    def request(self,method,path,body=None,optional=False):
        try:
            request=Request(self.origin+path,data=json.dumps(body).encode() if body is not None else None,method=method,
                headers={'Authorization':'Bearer '+(self.credentials/'token').read_text().strip(),'Content-Type':'application/merge-patch+json' if method=='PATCH' else 'application/json'})
            with urlopen(request,context=self.context,timeout=15) as response:return json.load(response)
        except HTTPError as error:
            if optional and error.code==404:return None
            # Method and status only: request paths name managed resources, including Secrets.
            LOG.warning('Sandbox Kubernetes request rejected: method=%s code=%s',method,error.code)
            raise KubernetesError('Kubernetes request failed with HTTP '+str(error.code)) from None
        except Exception as error:
            LOG.error('Sandbox Kubernetes connection failed: type=%s reason=%s verify_code=%s',type(error).__name__,type(getattr(error,'reason',None)).__name__,getattr(getattr(error,'reason',None),'verify_code',None))
            raise KubernetesError('Kubernetes connection unavailable') from None

    def verify_permissions(self):
        control_namespace=(self.credentials/'namespace').read_text().strip()
        checks=[('get','secrets','',control_namespace,False),('create','deployments','apps',control_namespace,False),
                ('patch','persistentvolumes','',None,False),('get','persistentvolumeclaims','',self.namespace,True),
                ('create','deployments','apps',self.namespace,True),('create','jobs','batch',self.namespace,True),('create','secrets','',self.namespace,True)]
        for verb,resource,group,namespace,expected in checks:
            attributes=dict(verb=verb,resource=resource,group=group)
            if namespace:attributes['namespace']=namespace
            review=self.request('POST','/apis/authorization.k8s.io/v1/selfsubjectaccessreviews',dict(apiVersion='authorization.k8s.io/v1',kind='SelfSubjectAccessReview',spec=dict(resourceAttributes=attributes)))
            if review.get('status',{}).get('allowed') is not expected:
                LOG.error('Sandbox controller authorization boundary failed: verb=%s resource=%s',verb,resource)
                raise KubernetesError('Kubernetes must enforce the isolated controller role before sandboxes can be enabled')

    def path(self,kind,name=None):
        prefix,plural=KINDS[kind]
        if name and not re.fullmatch(r'serviceops-sandbox-[1-9][0-9]*(?:-[a-z]+)?',name):raise ValueError('Invalid managed resource name')
        return prefix+'/namespaces/'+self.namespace+'/'+plural+('/'+name if name else '')

    def get(self,kind,name):
        return self.request('GET',self.path(kind,name),optional=True)

    def ensure(self,kind,body,identifier):
        name=body['metadata']['name'];existing=self.get(kind,name)
        if existing:
            if existing['metadata'].get('labels',{}).get('serviceops.io/sandbox-id')!=str(identifier):raise KubernetesError('An unmanaged resource already uses this name')
            return existing
        return self.request('POST',self.path(kind),body)

    def delete(self,kind,name,identifier):
        existing=self.get(kind,name)
        if not existing:return False
        if existing['metadata'].get('labels',{}).get('serviceops.io/sandbox-id')!=str(identifier):raise KubernetesError('Refusing to delete an unmanaged resource')
        if not existing['metadata'].get('deletionTimestamp'):
            self.request('DELETE',self.path(kind,name),{'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':existing['metadata']['uid']}})
        return True

    def release_volume(self,slot,kind):
        name=f'serviceops-sandbox-{kind}-slot{slot}'
        volume=self.request('GET','/api/v1/persistentvolumes/'+name)
        claim=volume['spec'].get('claimRef')
        if not claim:return
        if claim.get('namespace')!=self.namespace or not re.fullmatch(r'serviceops-sandbox-[1-9][0-9]*-(?:db|uploads)',claim.get('name','')):raise KubernetesError('Sandbox volume is bound to an unmanaged claim')
        if self.get('pvc',claim['name']):raise KubernetesError('Sandbox storage slot is still in use')
        self.request('PATCH','/api/v1/persistentvolumes/'+name,{'metadata':{'resourceVersion':volume['metadata']['resourceVersion']},'spec':{'claimRef':None}})


def labels(identifier,role=None):
    return {'serviceops.io/sandbox-id':str(identifier),'app.kubernetes.io/name':'serviceops-sandbox'}|({'serviceops.io/role':role} if role else {})


def metadata(name,identifier,role=None):
    return dict(name=name,labels=labels(identifier,role))


def security(user=100,group=101):
    return dict(runAsNonRoot=True,runAsUser=user,runAsGroup=group,fsGroup=101,fsGroupChangePolicy='Always',seccompProfile=dict(type='RuntimeDefault'))


def container_security():
    return dict(allowPrivilegeEscalation=False,readOnlyRootFilesystem=True,capabilities=dict(drop=['ALL']))


def resources(memory='256Mi'):
    return dict(requests=dict(cpu='50m',memory='64Mi'),limits=dict(cpu='500m',memory=memory))


def app_spec(name,image,identifier,command,role):
    env=[dict(name='DEPLOYMENT_PROFILE',value='development'),dict(name='SERVICEOPS_ENVIRONMENT',value='sandbox'),dict(name='AUTO_MIGRATE',value='false'),
         dict(name='SESSION_COOKIE_SECURE',value='false'),dict(name='ALLOW_INSECURE_SESSION_COOKIES',value='true'),dict(name='CSRF_ENABLED',value='true'),
         dict(name='LOCAL_AUTH_ENABLED',value='true'),dict(name='LOG_DIR',value='/tmp/logs'),dict(name='UPLOAD_FOLDER',value='/uploads'),dict(name='GUNICORN_WORKERS',value='1'),
         dict(name='TRUST_PROXY_HEADERS',value='false'),dict(name='OUTBOX_WORKER_ENABLED',value='true')]
    container=dict(name=role,image=image,command=command,env=env,envFrom=[dict(secretRef=dict(name=name))],securityContext=container_security(),resources=resources('512Mi'),
        volumeMounts=[dict(name='tmp',mountPath='/tmp'),dict(name='uploads',mountPath='/uploads')])
    return dict(restartPolicy='Always',automountServiceAccountToken=False,securityContext=security(),containers=[container],volumes=[dict(name='tmp',emptyDir={}),dict(name='uploads',persistentVolumeClaim=dict(claimName=name+'-uploads'))])


def deployment(name,identifier,spec,role):
    return dict(apiVersion='apps/v1',kind='Deployment',metadata=metadata(name,identifier,role),spec=dict(replicas=1,strategy=dict(type='Recreate'),selector=dict(matchLabels=labels(identifier,role)),template=dict(metadata=dict(labels=labels(identifier,role)),spec=spec)))


def job(name,identifier,spec):
    spec['restartPolicy']='Never'
    return dict(apiVersion='batch/v1',kind='Job',metadata=metadata(name,identifier),spec=dict(backoffLimit=1,activeDeadlineSeconds=900,template=dict(metadata=dict(labels=labels(identifier)),spec=spec)))


def claim(name,identifier,slot,kind,storage_class):
    return dict(apiVersion='v1',kind='PersistentVolumeClaim',metadata=metadata(name,identifier),spec=dict(accessModes=['ReadWriteOnce'],storageClassName=storage_class,volumeName=f'serviceops-sandbox-{kind}-slot{slot}',resources=dict(requests=dict(storage='2Gi' if kind=='db' else '1Gi'))))


def network_policy(name,identifier):
    dns=dict(to=[dict(namespaceSelector=dict(matchLabels={'kubernetes.io/metadata.name':'kube-system'}),podSelector=dict(matchLabels={'k8s-app':'kube-dns'}))],ports=[dict(protocol='UDP',port=53),dict(protocol='TCP',port=53)])
    peers=dict(podSelector=dict(matchLabels={'serviceops.io/sandbox-id':str(identifier)}))
    return dict(apiVersion='networking.k8s.io/v1',kind='NetworkPolicy',metadata=metadata(name,identifier),spec=dict(podSelector=peers['podSelector'],policyTypes=['Ingress','Egress'],ingress=[dict(from_=[peers],ports=[dict(protocol='TCP',port=5432),dict(protocol='TCP',port=8080)])],egress=[dns,dict(to=[peers],ports=[dict(protocol='TCP',port=5432)])]))


def normalize_network_policy(body):
    for rule in body['spec']['ingress']:rule['from']=rule.pop('from_')
    return body


def secret(name,identifier,slot):
    password=secrets.token_urlsafe(32)
    return dict(apiVersion='v1',kind='Secret',metadata=metadata(name,identifier),type='Opaque',stringData=dict(
        DATABASE_URL=f'postgresql+psycopg://sandbox:{password}@{name}-db:5432/serviceops_sandbox',POSTGRES_PASSWORD=password,POSTGRES_USER='sandbox',POSTGRES_DB='serviceops_sandbox',
        ADMIN_PASSWORD=secrets.token_urlsafe(32),SECRET_KEY=secrets.token_urlsafe(48),SETTINGS_ENCRYPTION_KEY=Fernet.generate_key().decode(),
        PUBLIC_BASE_URL=f'http://127.0.0.1:{18080+slot}',PUBLIC_URL=f'http://127.0.0.1:{18080+slot}'))


def provision(client,row,image,postgres_image,storage_class):
    identifier=row['id'];slot=row['slot'];name='serviceops-sandbox-'+str(identifier)
    if not IMAGE.fullmatch(image or '') or not IMAGE.fullmatch(postgres_image or ''):raise ValueError('Sandbox images must use immutable digests')
    for kind in ('db','uploads'):
        if not client.get('pvc',name+'-'+kind):client.release_volume(slot,kind)
        client.ensure('pvc',claim(name+'-'+kind,identifier,slot,kind,storage_class),identifier)
    client.ensure('policy',normalize_network_policy(network_policy(name+'-network',identifier)),identifier)
    client.ensure('secret',secret(name,identifier,slot),identifier)
    reset_containers=[]
    for kind,user in (('db',70),('uploads',100)):
        command="from pathlib import Path;import shutil;[(shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()) for p in Path('/data').iterdir()]"
        reset_containers.append(dict(name='reset-'+kind,image=image,command=['python','-c',command],securityContext=container_security()|dict(runAsUser=user,runAsGroup=101),resources=resources(),volumeMounts=[dict(name=kind,mountPath='/data')]))
    reset_spec=dict(automountServiceAccountToken=False,securityContext=security(70,101),containers=reset_containers,volumes=[dict(name=kind,persistentVolumeClaim=dict(claimName=name+'-'+kind)) for kind in ('db','uploads')])
    reset=client.ensure('job',job(name+'-reset',identifier,reset_spec),identifier)
    if reset.get('status',{}).get('failed'):raise KubernetesError('Sandbox storage reset failed; inspect the retained reset job')
    if not reset.get('status',{}).get('succeeded'):return 'provisioning','Waiting for isolated storage reset'
    db_spec=dict(automountServiceAccountToken=False,securityContext=security(70,70),containers=[dict(name='postgres',image=postgres_image,securityContext=container_security(),resources=resources('512Mi'),envFrom=[dict(secretRef=dict(name=name))],env=[dict(name='PGDATA',value='/var/lib/postgresql/data/pgdata')],ports=[dict(containerPort=5432)],volumeMounts=[dict(name='db',mountPath='/var/lib/postgresql/data'),dict(name='run',mountPath='/var/run/postgresql'),dict(name='tmp',mountPath='/tmp')],readinessProbe=dict(exec=dict(command=['pg_isready','-U','sandbox','-d','serviceops_sandbox']),initialDelaySeconds=5,periodSeconds=5))],volumes=[dict(name='db',persistentVolumeClaim=dict(claimName=name+'-db')),dict(name='run',emptyDir={}),dict(name='tmp',emptyDir={})])
    database=client.ensure('deployment',deployment(name+'-db',identifier,db_spec,'database'),identifier)
    client.ensure('service',dict(apiVersion='v1',kind='Service',metadata=metadata(name+'-db',identifier),spec=dict(selector=labels(identifier,'database'),ports=[dict(port=5432,targetPort=5432)])),identifier)
    if database.get('status',{}).get('readyReplicas')!=1:return 'provisioning','Waiting for isolated PostgreSQL readiness'
    migration=app_spec(name,image,identifier,['/bin/sh','-c','python -m tools.run_migrations && python -m tools.seed_sandbox'],'migration')
    migration['initContainers']=[dict(name='database-ready',image=image,command=['python','-m','tools.wait_for_database','--timeout','300'],envFrom=[dict(secretRef=dict(name=name))],securityContext=container_security(),resources=resources(),volumeMounts=[dict(name='tmp',mountPath='/tmp')])]
    migrated=client.ensure('job',job(name+'-migrate',identifier,migration),identifier)
    if migrated.get('status',{}).get('failed'):raise KubernetesError('Sandbox migration or synthetic seed failed; inspect the retained migration job')
    if not migrated.get('status',{}).get('succeeded'):return 'provisioning','Waiting for explicit migration and synthetic seed job'
    worker=app_spec(name,image,identifier,['python','-m','tools.outbox_worker'],'worker')
    worker['containers'][0]['readinessProbe']=dict(exec=dict(command=['python','-c',"import os,time;assert time.time()-os.path.getmtime('/tmp/serviceops-worker-heartbeat')<150"]),initialDelaySeconds=5,periodSeconds=5)
    client.ensure('deployment',deployment(name+'-worker',identifier,worker,'worker'),identifier)
    web=app_spec(name,image,identifier,['/app/tools/gunicorn-entrypoint.sh'],'web')
    web['containers'][0].update(ports=[dict(containerPort=8080)],readinessProbe=dict(httpGet=dict(path='/ready',port=8080),initialDelaySeconds=10,periodSeconds=5),livenessProbe=dict(httpGet=dict(path='/health',port=8080),initialDelaySeconds=60,periodSeconds=10))
    server=client.ensure('deployment',deployment(name,identifier,web,'web'),identifier)
    client.ensure('service',dict(apiVersion='v1',kind='Service',metadata=metadata(name,identifier),spec=dict(selector=labels(identifier,'web'),ports=[dict(port=8080,targetPort=8080)])),identifier)
    return ('ready','Isolated sandbox is ready') if server.get('status',{}).get('readyReplicas')==1 else ('provisioning','Waiting for sandbox web and worker readiness')


def remove(client,row):
    identifier=row['id'];name='serviceops-sandbox-'+str(identifier);pending=False
    for kind,suffix in (('deployment',''),('deployment','-worker'),('job','-migrate'),('job','-reset'),('deployment','-db'),('service',''),('service','-db'),('pvc','-uploads'),('pvc','-db'),('secret',''),('policy','-network')):
        pending=client.delete(kind,name+suffix,identifier) or pending
    return ('deleting','Removing synthetic sandbox resources') if pending else ('deleted','Synthetic sandbox resources removed')


def reconcile(engine,client,image,postgres_image,storage_class):
    with engine.begin() as connection:
        query="SELECT * FROM project_sandbox WHERE state IN ('queued','provisioning','deleting','ready') OR (state <> 'deleted' AND expires_at <= :now) ORDER BY updated_at,id LIMIT 1 FOR UPDATE SKIP LOCKED"
        row=connection.execute(text(query),dict(now=datetime.now(timezone.utc))).mappings().first()
        if row is None:return False
        row=dict(row);stamp=datetime.now(timezone.utc);expires=row['expires_at']
        if expires.tzinfo is None:expires=expires.replace(tzinfo=timezone.utc)
        pinned=row['image'] or image
        try:
            state,detail=remove(client,row) if row['state']=='deleting' or expires<=stamp else provision(client,row,pinned,postgres_image,storage_class)
            error=''
        except Exception as problem:
            state='deleting' if row['state']=='deleting' or expires<=stamp else 'failed';detail='Sandbox operation failed; inspect the controller and retained jobs';error=type(problem).__name__
            LOG.error('Sandbox reconciliation failed: id=%s error=%s',row['id'],type(problem).__name__)
        events=json.loads(row['events_json'])
        if state!=row['state'] or not events or events[-1]['detail']!=detail:events=(events+[dict(state=state,detail=detail,at=stamp.isoformat())])[-100:]
        connection.execute(text('UPDATE project_sandbox SET state=:state,image=:image,last_error=:error,events_json=:events,updated_at=:stamp WHERE id=:id'),dict(state=state,image=pinned,error=error,events=json.dumps(events),stamp=stamp,id=row['id']))
        LOG.info('Sandbox reconciled: id=%s state=%s',row['id'],state)
        return True


def main():
    logging.basicConfig(level=logging.INFO,format='%(levelname)s %(message)s')
    engine=create_engine(os.environ['DATABASE_URL'],pool_pre_ping=True)
    client=Kubernetes(os.environ.get('SANDBOX_NAMESPACE','serviceops-sandboxes'))
    try:
        while True:
            try:
                client.verify_permissions()
                reconcile(engine,client,os.environ['SANDBOX_IMAGE'],os.environ['SANDBOX_POSTGRES_IMAGE'],os.environ.get('SANDBOX_STORAGE_CLASS','serviceops-sandbox-local'))
            except Exception as error:LOG.error('Sandbox control loop failed: %s',type(error).__name__)
            else:Path('/tmp/serviceops-sandbox-heartbeat').touch()
            time.sleep(10)
    finally:engine.dispose()


if __name__=='__main__':main()
