"""Install-wide Premium administration with existing administrative authority."""
import json
import os

from flask import abort,current_app,flash,g,jsonify,redirect,render_template,request,url_for
from flask_login import current_user,login_required
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_models import db
from serviceops_core.localization import tr
from serviceops_core import premium_platform as platform
from serviceops_core.projects.advanced_routes import number
from serviceops_core.projects.models import ProjectSandbox


def register(app):
    @app.before_request
    def premium_network_gate():
        try:platform.enforce_network()
        except HTTPException:raise
        except Exception as error:
            db.session.rollback();current_app.logger.error('Installation access policy unavailable: %s',type(error).__name__)
            abort(503,description=tr('Access policy is temporarily unavailable.'))

    @app.route('/admin/premium/<section>',methods=['GET','POST'])
    @login_required
    def premium_administration(section):
        try:
            platform.require_admin(current_user)
            if section not in ('release-tracks','sandboxes','insights','ip-allowlist'):abort(404)
            if request.method=='POST':
                if section in ('release-tracks','ip-allowlist'):
                    data=platform.policy();data={k:data[k] for k in ('track','next_release','timezone','ip_networks')};data['revision']=number(request.form.get('revision'))
                    if section=='release-tracks':data.update(track=request.form.get('track'),next_release=request.form.get('next_release') or None,timezone=request.form.get('timezone','UTC'))
                    else:data['ip_networks']=[n.strip() for n in request.form.get('ip_networks','').replace(',','\n').splitlines() if n.strip()]
                    platform.save_policy(current_user,data,request.remote_addr)
                elif section=='sandboxes':
                    if request.form.get('action')=='delete':platform.delete_sandbox(current_user,number(request.form.get('id')))
                    else:platform.request_sandbox(current_user,request.form.get('name'),number(request.form.get('hours','24')))
                else:abort(405)
                db.session.commit();flash(tr('Administration settings saved.'),'success')
                return redirect(url_for('premium_administration',section=section))
            sandboxes=ProjectSandbox.query.filter_by(tenant_id=current_user.tenant_id).order_by(ProjectSandbox.id.desc()).limit(50).all() if section=='sandboxes' else []
            return render_template('premium_administration.html',section=section,policy=platform.policy(),
                insights=platform.insights(current_user) if section=='insights' else None,sandboxes=sandboxes,sandbox_events={r.id:json.loads(r.events_json) for r in sandboxes},
                sandbox_enabled=current_app.config.get('PREMIUM_SANDBOX_ENABLED',False),client_ip=request.remote_addr,
                image=os.environ.get('SERVICEOPS_IMAGE_REFERENCE',''),sandbox_namespace=os.environ.get('SANDBOX_NAMESPACE','serviceops-sandboxes'))
        except HTTPException:
            db.session.rollback();raise
        except Exception as error:
            db.session.rollback();current_app.logger.error('Premium administration failed: %s',type(error).__name__)
            abort(503,description=tr('Administration is temporarily unavailable.'))

    @app.get('/admin/premium/sandbox-status')
    @login_required
    def premium_sandbox_status():
        try:
            platform.require_admin(current_user)
            rows=ProjectSandbox.query.filter_by(tenant_id=current_user.tenant_id).order_by(ProjectSandbox.id.desc()).limit(50)
            return jsonify(data=[dict(id=r.id,state=r.state) for r in rows])
        except HTTPException:raise
        except Exception as error:
            current_app.logger.error('Sandbox status unavailable: %s',type(error).__name__);abort(503)

    @app.route('/api/v1/platform/premium-policy',methods=['GET','PUT'])
    def api_premium_policy():
        try:
            core.require_api_scope('platform:write' if request.method=='PUT' else 'platform:read');actor=g.api_user;platform.require_admin(actor)
            if request.method=='PUT':platform.save_policy(actor,request.get_json(silent=True),request.remote_addr);db.session.commit()
            return jsonify(data=platform.policy())
        except HTTPException:db.session.rollback();raise
        except Exception as error:
            db.session.rollback();current_app.logger.error('Premium policy request failed: %s',type(error).__name__);abort(503)

    @app.route('/api/v1/platform/sandboxes',methods=['GET','POST'])
    def api_premium_sandboxes():
        try:
            core.require_api_scope('platform:write' if request.method=='POST' else 'platform:read');actor=g.api_user;platform.require_admin(actor)
            if request.method=='POST':
                data=request.get_json(silent=True)
                if not isinstance(data,dict) or set(data)-{'name','hours'}:abort(400)
                idem,request_hash,replay=core.api_idempotency_context()
                if replay:return replay
                row=platform.request_sandbox(actor,data.get('name'),data.get('hours',24));result=dict(id=row.id,state=row.state)
                core.store_api_idempotency(idem,request_hash,result,201);db.session.commit();return jsonify(result),201
            rows=ProjectSandbox.query.filter_by(tenant_id=actor.tenant_id).order_by(ProjectSandbox.id.desc()).limit(50)
            return jsonify(data=[dict(id=r.id,name=r.name,state=r.state,expires_at=r.expires_at.isoformat(),image=r.image,events=json.loads(r.events_json)) for r in rows])
        except HTTPException:db.session.rollback();raise
        except Exception as error:
            db.session.rollback();current_app.logger.error('Sandbox request failed: %s',type(error).__name__);abort(503)

    @app.delete('/api/v1/platform/sandboxes/<int:identifier>')
    def api_premium_sandbox_delete(identifier):
        try:
            core.require_api_scope('platform:write');row=platform.delete_sandbox(g.api_user,identifier);db.session.commit()
            return jsonify(id=row.id,state=row.state)
        except HTTPException:db.session.rollback();raise
        except Exception as error:
            db.session.rollback();current_app.logger.error('Sandbox deletion failed: %s',type(error).__name__);abort(503)
