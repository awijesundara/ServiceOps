"""REST access to the same project query and saved-filter rules as the web UI."""
from functools import wraps

from flask import abort, current_app, g, jsonify, request
from werkzeug.exceptions import HTTPException

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import filters, query
from serviceops_core.projects.models import ProjectFilterFavourite, ProjectSavedFilter
from serviceops_models import db


def guarded(handler):
    @wraps(handler)
    def call(*args,**kwargs):
        try:
            return handler(*args,**kwargs)
        except query.QueryError as error:
            db.session.rollback()
            abort(400,description=str(error))
        except HTTPException:
            raise
        except Exception:
            db.session.rollback()
            current_app.logger.error('Project search API request failed')
            abort(503,description=tr('Work item search is temporarily unavailable. Please try again.'))
    return call


def pagination():
    try:
        limit=int(request.args.get('limit','50')); offset=int(request.args.get('offset','0'))
        if not 1<=limit<=200 or not 0<=offset<=1000000: raise ValueError()
        return limit,offset
    except (ValueError,TypeError):
        abort(400,description=tr('limit must be 1 to 200 and offset must be 0 to 1000000.'))


def document(row,user,favourites):
    return {'id':row.id,'name':row.name,'jql':row.query_text,'owner_id':row.owner_id,'sharing':row.sharing,
            'project_key':row.project.key if row.project else None,'favourite':row.id in favourites,
            'editable':row.owner_id==user.id}


def body_object():
    try:
        body=request.get_json(silent=True)
        if not isinstance(body,dict): abort(400,description=tr('A JSON object is required.'))
        return body
    except HTTPException:
        raise
    except Exception:
        current_app.logger.error('Project filter JSON parsing failed')
        raise


def register(app,api_user,item_document):
    @app.get('/api/v1/work-item-search')
    @guarded
    def api_work_item_search():
        core.require_api_scope('projects:read')
        user=api_user(); limit,offset=pagination()
        source=request.args.get('jql','')
        if 'filter' in request.args:
            try: filter_id=int(request.args['filter'])
            except ValueError: abort(400,description=tr('Choose a valid saved filter.'))
            row=filters.get(user,filter_id)
            source=request.args.get('jql',row.query_text)
        result=query.search(user,source)
        total=result.order_by(None).count()
        rows=result.offset(offset).limit(limit).all()
        return jsonify({'data':[item_document(row) for row in rows],
                        'meta':{'total':total,'offset':offset,'limit':limit,
                                'next_offset':offset+limit if offset+limit<total else None,'request_id':g.request_id}})

    @app.get('/api/v1/project-filters')
    @guarded
    def api_project_filters():
        core.require_api_scope('projects:read')
        user=api_user(); limit,offset=pagination()
        result=filters.visible(user)
        total=result.count()
        favourites={r.filter_id for r in ProjectFilterFavourite.query.filter_by(tenant_id=user.tenant_id,user_id=user.id)}
        rows=result.order_by(ProjectSavedFilter.name,ProjectSavedFilter.id).offset(offset).limit(limit).all()
        return jsonify({'data':[document(row,user,favourites) for row in rows],
                        'meta':{'total':total,'offset':offset,'limit':limit,
                                'next_offset':offset+limit if offset+limit<total else None}})

    @app.route('/api/v1/project-filters',methods=['POST'])
    @app.route('/api/v1/project-filters/<int:filter_id>',methods=['PATCH'])
    @guarded
    def api_project_filter_save(filter_id=None):
        core.require_api_scope('projects:write')
        user=api_user()
        key=request_hash=replay=None
        if filter_id is None:
            key,request_hash,replay=core.api_idempotency_context()
            if replay: return replay
        body=body_object()
        if set(body)-{'name','jql','sharing','project_key'}:
            abort(400,description=tr('Unknown saved filter field.'))
        for name in ('name','jql','sharing'):
            if name in body and not isinstance(body[name],str):
                abort(400,description=tr('Saved filter fields must be text.'))
        if body.get('project_key') is not None and not isinstance(body['project_key'],str):
            abort(400,description=tr('Saved filter fields must be text.'))
        old=filters.get(user,filter_id) if filter_id is not None else None
        row=filters.save(user,body.get('name',old.name if old else ''),
                         body.get('jql',old.query_text if old else ''),
                         body.get('sharing',old.sharing if old else 'private'),
                         body.get('project_key',old.project.key if old and old.project else None),filter_id)
        favourites={r.filter_id for r in ProjectFilterFavourite.query.filter_by(tenant_id=user.tenant_id,user_id=user.id)}
        response={'data':document(row,user,favourites)}
        status=201 if filter_id is None else 200
        if key: core.store_api_idempotency(key,request_hash,response,status)
        db.session.commit()
        return jsonify(response),status

    @app.delete('/api/v1/project-filters/<int:filter_id>')
    @guarded
    def api_project_filter_delete(filter_id):
        core.require_api_scope('projects:write')
        filters.delete(api_user(),filter_id)
        db.session.commit()
        return '',204

    @app.put('/api/v1/project-filters/<int:filter_id>/favourite')
    @guarded
    def api_project_filter_favourite(filter_id):
        core.require_api_scope('projects:write')
        body=body_object()
        if set(body)!={'enabled'} or not isinstance(body['enabled'],bool):
            abort(400,description=tr('Favourite requires an enabled boolean.'))
        filters.favourite(api_user(),filter_id,body['enabled'])
        db.session.commit()
        return jsonify({'data':{'favourite':body['enabled']}})
