"""PostgreSQL saved-filter persistence, scoped query and reversible migration."""
import uuid

from sqlalchemy import inspect
from pathlib import Path
from alembic import command
from alembic.config import Config

from app import User, db
from serviceops_core.projects import filters, query, service
from serviceops_core.projects.models import ProjectSavedFilter
from tests.test_architecture_transactions import pg_review  # noqa: F401


def test_project_query_and_filter_roundtrip_on_postgres(pg_review):
    with pg_review.app_context():
        admin=User.query.filter_by(username='admin').one()
        key='Q'+uuid.uuid4().hex[:7].upper()
        project=service.create_project(admin,key,'Query PostgreSQL')
        service.create_item(admin,project,'Search SQL',assignee_ids=[admin.id],due_date='2026-01-01')
        saved=filters.save(admin,'Filter '+key,f'project={key} AND assignee=currentUser() AND due < now()')
        db.session.commit()
        saved_id=saved.id
        db.session.remove()
        admin=User.query.filter_by(username='admin').one()
        saved=db.session.get(ProjectSavedFilter,saved_id)
        assert query.search(admin,saved.query_text).one().title=='Search SQL'
        filters.favourite(admin,saved.id,True)
        db.session.commit()
        filters.delete(admin,saved.id)
        db.session.commit()


def test_additive_filter_migration_downgrade_upgrade_on_disposable_postgres(pg_review):
    with pg_review.app_context():
        # The fixture accepts only an explicitly named disposable _architecture_test DB.
        db.session.remove()
        assert 'project_saved_filter' in inspect(db.engine).get_table_names()
        config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
        command.downgrade(config,'20261016_0128')
        assert 'project_saved_filter' not in inspect(db.engine).get_table_names()
        command.upgrade(config,'head')
        assert 'project_saved_filter' in inspect(db.engine).get_table_names()
        assert 'project_filter_favourite' in inspect(db.engine).get_table_names()


def test_reporting_and_history_functions_on_postgres(pg_review):
    from serviceops_core.projects.models import ProjectVersion
    with pg_review.app_context():
        admin=User.query.filter_by(username='admin').one()
        key='F'+uuid.uuid4().hex[:7].upper()
        project=service.create_project(admin,key,'Reporting functions')
        item=service.create_item(admin,project,'Reporting work',priority='high',due_date='2026-01-01')
        item.fix_versions=[ProjectVersion(tenant_id=admin.tenant_id,project_id=project.id,name='1.0',released=True)]
        service.update_item(admin,item,{'priority':'low'})
        db.session.commit()
        source=f'project={key} AND key IN watchedIssues() AND fixVersion IN releasedVersions({key}) AND fixVersion = latestReleasedVersion({key}) AND priority CHANGED FROM high TO low BY currentUser() AFTER startOfYear("-1") AND due < endOfYear("1")'
        assert query.search(admin,source).one().id==item.id
