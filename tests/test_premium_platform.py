"""Installation policy, release enforcement and sandbox isolation contracts."""
from datetime import datetime,timezone

import pytest
from werkzeug.exceptions import HTTPException
from tests.test_app import app,client,login  # noqa: F401
from app import db,User
from serviceops_core import premium_platform as platform,release_tracks
from serviceops_core.projects.models import ProjectSandbox
from tools import sandbox_controller as sandbox

IMAGE='example.invalid/serviceops@sha256:'+'a'*64
OTHER_IMAGE='example.invalid/serviceops@sha256:'+'b'*64


def reject(code,fn,*args,**kwargs):
    with pytest.raises(HTTPException) as error:fn(*args,**kwargs)
    assert error.value.code==code
    db.session.rollback()


def test_release_policy_window_retry_and_next_month(app):
    with app.app_context():
        actor=User.query.filter_by(username='admin').one()
        platform.save_policy(actor,dict(track='bundled',next_release='2030-01-31',timezone='UTC',ip_networks=[],revision=0));db.session.commit()
        with pytest.raises(RuntimeError,match='window'):release_tracks.check(db.engine,IMAGE,clock=datetime(2030,1,30,tzinfo=timezone.utc))
        assert release_tracks.check(db.engine,IMAGE,clock=datetime(2030,1,31,tzinfo=timezone.utc))=='bundled'
        release_tracks.record(db.engine,IMAGE,clock=datetime(2030,1,31,tzinfo=timezone.utc));db.session.expire_all()
        assert platform.policy()['next_release']=='2030-02-28'
        assert release_tracks.check(db.engine,IMAGE,clock=datetime(2030,1,31,tzinfo=timezone.utc))=='approved_retry'
        with pytest.raises(RuntimeError):release_tracks.check(db.engine,OTHER_IMAGE,clock=datetime(2030,1,31,tzinfo=timezone.utc))
        assert release_tracks.check(db.engine,OTHER_IMAGE,environment='sandbox')=='preview'
        with pytest.raises(RuntimeError):release_tracks.check(db.engine,OTHER_IMAGE,override_reason='short')
        assert release_tracks.check(db.engine,OTHER_IMAGE,override_reason='Emergency operator recovery')=='operator_override'


def test_allowlist_lockout_protection_stale_policy_and_untrusted_headers(app,client):
    with app.app_context():
        actor=User.query.filter_by(username='admin').one()
        data=dict(track='continuous',next_release=None,timezone='UTC',ip_networks=['203.0.113.0/24'],revision=0)
        reject(409,platform.save_policy,actor,data,'127.0.0.1')
        data['ip_networks']=['127.0.0.1/32'];platform.save_policy(actor,data,'127.0.0.1');db.session.commit()
        reject(409,platform.save_policy,actor,data,'127.0.0.1')
    response=client.get('/login',environ_overrides={'REMOTE_ADDR':'198.51.100.10'},headers={'X-Forwarded-For':'127.0.0.1'})
    assert response.status_code==403
    assert client.get('/health',environ_overrides={'REMOTE_ADDR':'198.51.100.10'}).status_code==200
    assert client.get('/live',environ_overrides={'REMOTE_ADDR':'10.1.134.1'}).status_code==200
    assert client.get('/login').status_code==200


def test_sandbox_budget_and_explicit_deletion(app):
    with app.app_context():
        actor=User.query.filter_by(username='admin').one()
        reject(409,platform.request_sandbox,actor,'Disabled',24)
        app.config['PREMIUM_SANDBOX_ENABLED']=True
        first=platform.request_sandbox(actor,'Synthetic one',24);second=platform.request_sandbox(actor,'Synthetic two',1);db.session.commit()
        assert {first.slot,second.slot}=={1,2}
        reject(409,platform.request_sandbox,actor,'Third',24)
        platform.delete_sandbox(actor,first.id);db.session.commit()
        assert first.state=='deleting'
        reject(409,platform.request_sandbox,actor,'Still occupied',24)
        first.state='deleted';db.session.commit()
        third=platform.request_sandbox(actor,'Reused slot',24);db.session.commit()
        assert third.slot==first.slot
        assert ProjectSandbox.query.filter(ProjectSandbox.state!='deleted').count()==2


def test_administration_pages_and_tenant_scoped_status(app,client):
    login(client)
    for section in ('release-tracks','sandboxes','insights','ip-allowlist'):
        response=client.get('/admin/premium/'+section)
        assert response.status_code==200,(section,response.get_data(as_text=True)[:500])
    assert client.get('/admin/premium/sandbox-status').json=={'data':[]}
    response=client.post('/admin/premium/release-tracks',data={'revision':'0','track':'bundled','next_release':'2030-01-31','timezone':'Asia/Tokyo'})
    assert response.status_code==302
    assert client.get(response.location).status_code==200


def test_managed_resource_collision_and_volume_claim_protection():
    client=sandbox.Kubernetes.__new__(sandbox.Kubernetes);client.namespace='serviceops-sandboxes';calls=[]
    def unmanaged(method,path,body=None,optional=False):
        calls.append(method)
        return {'metadata':{'labels':{},'uid':'unmanaged'},'spec':{'claimRef':{'namespace':'operations','name':'serviceops-postgresql'}}}
    client.request=unmanaged
    with pytest.raises(sandbox.KubernetesError):client.delete('secret','serviceops-sandbox-1',1)
    assert calls==['GET'];calls.clear()
    with pytest.raises(sandbox.KubernetesError):client.release_volume(1,'db')
    assert calls==['GET']


def test_synthetic_loader_refuses_non_sandbox_database(monkeypatch):
    from tools.seed_sandbox import main
    monkeypatch.setenv('SERVICEOPS_ENVIRONMENT','sandbox');monkeypatch.setenv('DATABASE_URL','postgresql+psycopg://production.invalid/serviceops')
    with pytest.raises(RuntimeError,match='refuses'):main()


def test_controller_ca_compatibility_preserves_tls_verification(monkeypatch):
    import ssl
    from tools.sandbox_controller import Kubernetes
    def context(**kwargs):
        result=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);result.verify_flags|=ssl.VERIFY_X509_STRICT;return result
    monkeypatch.setattr('tools.sandbox_controller.ssl.create_default_context',context)
    monkeypatch.setenv('KUBERNETES_SERVICE_HOST','10.152.183.1');monkeypatch.delenv('SANDBOX_KUBERNETES_STRICT_X509',raising=False)
    strict=Kubernetes('serviceops-sandboxes').context;assert strict.verify_flags&ssl.VERIFY_X509_STRICT
    monkeypatch.setenv('SANDBOX_KUBERNETES_STRICT_X509','false');compat=Kubernetes('serviceops-sandboxes').context
    assert not compat.verify_flags&ssl.VERIFY_X509_STRICT
    assert compat.verify_mode==ssl.CERT_REQUIRED and compat.check_hostname


def test_controller_refuses_always_allow_authorization(tmp_path):
    from tools.sandbox_controller import Kubernetes,KubernetesError
    client=object.__new__(Kubernetes);client.namespace='serviceops-sandboxes';client.credentials=tmp_path
    (tmp_path/'namespace').write_text('operations')
    client.request=lambda *args:dict(status=dict(allowed=True))
    with pytest.raises(KubernetesError,match='must enforce'):client.verify_permissions()
    def scoped(method,path,body):
        attrs=body['spec']['resourceAttributes'];return dict(status=dict(allowed=attrs.get('namespace')==client.namespace))
    client.request=scoped;client.verify_permissions()
