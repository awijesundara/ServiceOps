"""Premium schema preservation and stale plan requests on PostgreSQL."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from werkzeug.exceptions import HTTPException
from tests.test_architecture_transactions import pg_review,_interleave  # noqa: F401
from tests.test_project_planning_postgres import seed
from serviceops_models import db,User
from serviceops_core.projects import advanced_plans as plans,service
from serviceops_core.projects.models import Project,WorkItem


def test_premium_expand_roundtrip_preserves_existing_work(pg_review):
    with pg_review.app_context():
        count=WorkItem.query.count();db.session.remove();config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
        command.downgrade(config,'20261017_0131')
        assert 'project_plan' not in inspect(db.engine).get_table_names();assert WorkItem.query.count()==count;db.session.remove()
        command.upgrade(config,'head')
        assert {'project_plan','project_form','project_page','project_form_response','project_shortcut'}<=set(inspect(db.engine).get_table_names());assert WorkItem.query.count()==count


def test_stale_plan_update_rejected_postgresql(pg_review):
    actor_id,project_id,*_=seed(pg_review)
    with pg_review.app_context():
        actor=db.session.get(User,actor_id);p=db.session.get(Project,project_id);plan=plans.create(actor,dict(name='Concurrent',projects=[p.key]));db.session.commit();identifier=plan.id;revision=plan.revision
    def load(index):
        actor=db.session.get(User,actor_id);plans.get(actor,identifier);return actor
    def write(index,actor):
        try:
            plan,payload=plans.get(actor,identifier,True,revision);plans.save_settings(actor,plan,dict(start='2026-10-19',iterations=8));return 200
        except HTTPException as error:db.session.rollback();return error.code
    assert _interleave(pg_review,load,write)==[200,409]
