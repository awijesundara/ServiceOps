"""Permission checked project content, typed forms and reporting endpoints."""
import json
from flask import abort,flash,jsonify,redirect,request,url_for
from flask_login import current_user
import app as core
from serviceops_models import db
from serviceops_core.localization import tr
from serviceops_core.projects import content,service
from serviceops_core.projects.planning_routes import guarded
from serviceops_core.projects.models import ProjectPage,ProjectForm,ProjectShortcut


@content.roadmap.guarded
def rows(actor,project,model):
    return model.query.filter_by(tenant_id=actor.tenant_id,project_id=project.id).order_by(model.id).all()


@content.roadmap.guarded
def document(row):
    if isinstance(row,ProjectPage):return dict(id=row.id,title=row.title,body=row.body,revision=row.revision)
    if isinstance(row,ProjectForm):return dict(id=row.id,name=row.name,description=row.description,enabled=row.enabled,revision=row.revision,config=json.loads(row.config_json))
    return dict(id=row.id,label=row.label,url=row.url)


@content.roadmap.guarded
def integer(value,default=None):
    if value in ('',None):return default
    try:
        if isinstance(value,bool):raise ValueError()
        return int(value)
    except (TypeError,ValueError):abort(400)


def register_web(bp,page):
    @bp.route('/projects/<key>/content/<view>',methods=['GET','POST'])
    @guarded
    def project_content(key,view):
        project=service.project_or_404(current_user,key)
        if view not in ('forms','pages','reports','shortcuts'):abort(404)
        if request.method=='POST':
            identifier=integer(request.form.get('id'))
            if view=='pages':content.save_page(current_user,project,dict(title=request.form.get('title'),body=request.form.get('body',''),revision=integer(request.form.get('revision'))),identifier)
            elif view=='forms':
                try:config=json.loads(request.form.get('config',''))
                except ValueError:abort(400,description=tr('Enter a valid form configuration.'))
                content.save_form(current_user,project,dict(name=request.form.get('name'),description=request.form.get('description',''),enabled=request.form.get('enabled')=='1',config=config,revision=integer(request.form.get('revision'))),identifier)
            elif view=='shortcuts':
                if request.form.get('action')=='delete':
                    content.lock(current_user,project,True);db.session.delete(content.get(current_user,project,ProjectShortcut,identifier))
                    core.audit('project shortcut removed',str(identifier),'project='+project.key,user_id=current_user.id,tenant_id=current_user.tenant_id)
                else:content.shortcut(current_user,project,request.form.get('label'),request.form.get('url'))
            else:abort(405)
            db.session.commit();flash(tr('Changes saved.'),'success');return redirect(url_for('projects.project_content',key=key,view=view))
        data=[];report=None
        if view=='reports':report=content.reports(current_user,project,integer(request.args.get('days'),30))
        else:data=[document(row) for row in rows(current_user,project,{'pages':ProjectPage,'forms':ProjectForm,'shortcuts':ProjectShortcut}[view])]
        return page('projects/content.html',project,tab=view,entries=data,report=report)

    @bp.route('/projects/<key>/forms/<int:form_id>/submit',methods=['GET','POST'])
    @guarded
    def project_form_submit(key,form_id):
        project=service.project_or_404(current_user,key);form=content.get(current_user,project,ProjectForm,form_id)
        service.require_edit(current_user,project)
        if not form.enabled:abort(404)
        config=json.loads(form.config_json)
        if request.method=='POST':
            answers={f['key']:request.form.getlist('answer_'+f['key']) if f['type']=='multi_choice' else request.form.get('answer_'+f['key']) for f in config['fields']}
            item=content.submit_form(current_user,project,form,dict(title=request.form.get('title'),description=request.form.get('description',''),answers=answers));db.session.commit()
            flash(tr('Work item created.'),'success');return redirect(url_for('projects.item_detail',item_key=item.key))
        return page('projects/form_submit.html',project,tab='forms',form=document(form))


def register_api(app,user):
    @app.route('/api/v1/projects/<key>/content/<view>',methods=['GET','POST'])
    @guarded
    def api_project_content(key,view):
        core.require_api_scope('projects:read' if request.method=='GET' else 'projects:write');actor=user();project=service.project_or_404(actor,key)
        if view=='reports':
            if request.method!='GET':abort(405)
            return jsonify(data=content.reports(actor,project,integer(request.args.get('days'),30)))
        if view not in ('pages','forms','shortcuts'):abort(404)
        model={'pages':ProjectPage,'forms':ProjectForm,'shortcuts':ProjectShortcut}[view]
        if request.method=='GET':return jsonify(data=[document(row) for row in rows(actor,project,model)])
        content.lock(actor,project,view!='pages');body=request.get_json(silent=True)
        if not isinstance(body,dict):abort(400)
        idem,request_hash,replay=core.api_idempotency_context()
        if replay:return replay
        if view=='pages':row=content.save_page(actor,project,body)
        elif view=='forms':row=content.save_form(actor,project,body)
        else:
            if set(body)-{'label','url'}:abort(400)
            row=content.shortcut(actor,project,body.get('label'),body.get('url'))
        result=dict(data=document(row));core.store_api_idempotency(idem,request_hash,result,201);db.session.commit();return jsonify(result),201

    @app.route('/api/v1/projects/<key>/content/<view>/<int:identifier>',methods=['PUT'])
    @guarded
    def api_project_content_update(key,view,identifier):
        core.require_api_scope('projects:write');actor=user();project=service.project_or_404(actor,key)
        if view not in ('pages','forms'):abort(404)
        content.get(actor,project,ProjectPage if view=='pages' else ProjectForm,identifier)
        if view=='pages':row=content.save_page(actor,project,request.get_json(silent=True),identifier)
        else:row=content.save_form(actor,project,request.get_json(silent=True),identifier)
        db.session.commit();return jsonify(data=document(row))

    @app.post('/api/v1/projects/<key>/forms/<int:identifier>/submit')
    @guarded
    def api_project_form_submit(key,identifier):
        core.require_api_scope('projects:write');actor=user();project=service.project_or_404(actor,key);content.lock(actor,project)
        form=content.get(actor,project,ProjectForm,identifier)
        if not form.enabled:abort(404)
        idem,request_hash,replay=core.api_idempotency_context()
        if replay:return replay
        item=content.submit_form(actor,project,form,request.get_json(silent=True))
        from serviceops_core.web.projects_api import item_document
        result=dict(data=item_document(item));core.store_api_idempotency(idem,request_hash,result,201);db.session.commit();return jsonify(result),201
