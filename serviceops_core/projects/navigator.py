"""Web issue navigator and access-scoped CSV export for the core JQL dialect."""
import csv
import io

from flask import Response, abort, current_app, flash, redirect, request, url_for
from flask_login import current_user
from werkzeug.exceptions import HTTPException

from serviceops_core.localization import tr
from serviceops_core.projects import filters, query, service
from serviceops_core.projects.models import ProjectFilterFavourite, ProjectSavedFilter
from serviceops_models import db

PAGE_SIZE=50
EXPORT_LIMIT=10000


def csv_response(items):
    try:
        output=io.StringIO(newline='')
        writer=csv.writer(output)
        writer.writerow(['Key','Project','Type','Summary','Status','Priority','Assignees','Start','Due','Story points'])
        for item in items:
            values=[item.key,item.project.name,item.item_type,item.title,item.status.name,item.priority,
                    ', '.join(user.name for user in item.assignees),item.start_date.isoformat() if item.start_date else '',
                    item.due_date.isoformat() if item.due_date else '',item.story_points if item.story_points is not None else '']
            writer.writerow(["'"+str(value) if str(value).lstrip().startswith(('=','+','-','@')) else value for value in values])
        response=Response('\ufeff'+output.getvalue(),content_type='text/csv; charset=utf-8')
        response.headers['Content-Disposition']='attachment; filename="serviceops-work-items.csv"'
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        return response
    except Exception:
        current_app.logger.error('Work item CSV generation failed')
        raise


def register(blueprint,page):
    @blueprint.get('/projects/search')
    def issue_navigator():
        try:
            selected=None
            raw_filter=request.args.get('filter')
            if raw_filter:
                try: filter_id=int(raw_filter)
                except ValueError: abort(400,description=tr('Choose a valid saved filter.'))
                selected=filters.get(current_user,filter_id)
            source=request.args.get('jql',selected.query_text if selected else '')
            try: page_number=int(request.args.get('page','1'))
            except ValueError: abort(400,description=tr('Choose a valid search page.'))
            if not 1<=page_number<=1000000: abort(400,description=tr('Choose a valid search page.'))
            error=None; rows=[]; total=0
            try:
                results=query.search(current_user,source)
                total=results.order_by(None).count()
                page_number=min(page_number,max(1,(total+PAGE_SIZE-1)//PAGE_SIZE))
                if request.args.get('export')=='csv':
                    if total>EXPORT_LIMIT:
                        abort(400,description=tr('CSV export is limited to 10,000 work items. Refine the query first.'))
                    return csv_response(results.all())
                rows=results.offset((page_number-1)*PAGE_SIZE).limit(PAGE_SIZE).all()
            except query.QueryError as exc:
                error=str(exc)
            saved=filters.visible(current_user).order_by(ProjectSavedFilter.name,ProjectSavedFilter.id).limit(500).all()
            favourites={row.filter_id for row in ProjectFilterFavourite.query.filter_by(
                tenant_id=current_user.tenant_id,user_id=current_user.id).all()}
            projects=service.visible_projects(current_user).order_by(service.Project.name).limit(500).all()
            response=page('projects/search.html',rows=rows,total=total,jql=source,error=error,selected=selected,
                saved_filters=saved,favourites=favourites,filter_projects=projects,query_fields=query.FIELDS,
                page_number=page_number,pages=max(1,(total+PAGE_SIZE-1)//PAGE_SIZE),
                can_share_tenant=service._tenant_admin(current_user))
            return (response,400) if error else response
        except HTTPException:
            raise
        except Exception:
            db.session.rollback()
            current_app.logger.error('Issue navigator failed for tenant %s',current_user.tenant_id)
            abort(503,description=tr('Work item search is temporarily unavailable. Please try again.'))

    @blueprint.post('/projects/filters/save')
    def filter_save():
        try:
            raw=request.form.get('filter_id')
            try: filter_id=int(raw) if raw else None
            except ValueError: abort(400,description=tr('Choose a valid saved filter.'))
            row=filters.save(current_user,request.form.get('name',''),request.form.get('jql',''),
                request.form.get('sharing','private'),request.form.get('project_key'),filter_id)
            db.session.commit()
            flash(tr('Filter saved.'),'success')
            return redirect(url_for('projects.issue_navigator',filter=row.id))
        except query.QueryError as error:
            db.session.rollback()
            abort(400,description=str(error))
        except HTTPException:
            raise
        except Exception:
            db.session.rollback()
            current_app.logger.error('Saved filter request failed for tenant %s',current_user.tenant_id)
            abort(503,description=tr('The filter could not be saved. Please try again.'))

    @blueprint.post('/projects/filters/<int:filter_id>/delete')
    def filter_delete(filter_id):
        try:
            filters.delete(current_user,filter_id)
            db.session.commit()
            flash(tr('Filter deleted.'),'success')
            return redirect(url_for('projects.issue_navigator'))
        except HTTPException:
            raise
        except Exception:
            db.session.rollback()
            current_app.logger.error('Saved filter delete request failed for tenant %s',current_user.tenant_id)
            abort(503,description=tr('The filter could not be deleted. Please try again.'))

    @blueprint.post('/projects/filters/<int:filter_id>/favourite')
    def filter_favourite(filter_id):
        try:
            value=request.form.get('enabled')
            if value not in ('0','1'): abort(400,description=tr('Choose a valid favourite state.'))
            filters.favourite(current_user,filter_id,value=='1')
            db.session.commit()
            return redirect(url_for('projects.issue_navigator',filter=filter_id))
        except HTTPException:
            raise
        except Exception:
            db.session.rollback()
            current_app.logger.error('Filter favourite request failed for tenant %s',current_user.tenant_id)
            abort(503,description=tr('The favourite could not be saved. Please try again.'))
