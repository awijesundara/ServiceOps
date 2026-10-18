"""PostgreSQL planning migrations and stale-request transaction interleavings."""
import uuid
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from werkzeug.exceptions import HTTPException

from app import db,User
from serviceops_core.projects import roadmap,service
from serviceops_core.projects.models import Project,ProjectPlanningDraft,WorkItem,WorkItemHistory
from tests.test_architecture_transactions import pg_review,_interleave  # noqa: F401


def seed(application):
    with application.app_context():
        actor=User.query.filter_by(username='admin').one()
        project=service.create_project(actor,'R'+uuid.uuid4().hex[:7].upper(),'Planning PostgreSQL')
        item=service.create_item(actor,project,'Schedule work',estimate_minutes=480)
        other=service.create_item(actor,project,'Related work',estimate_minutes=480)
        row=roadmap.create_draft(actor,[project.key],'Proposal',start='2026-10-19')
        db.session.commit()
        return actor.id,project.id,item.id,other.id,row.id


def test_planning_additive_migration_roundtrip(pg_review):
    with pg_review.app_context():
        before=WorkItem.query.count();db.session.remove()
        config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
        command.downgrade(config,'20261017_0130')
        assert 'project_planning_draft' not in inspect(db.engine).get_table_names()
        assert WorkItem.query.count()==before;db.session.remove()
        command.upgrade(config,'head')
        assert {'project_planning_draft','project_view_preference','project_goal','project_goal_item'}<=set(inspect(db.engine).get_table_names())
        assert WorkItem.query.count()==before


def test_preloaded_duplicate_apply_is_consumed_once(pg_review):
    actor_id,project_id,item_id,other_id,draft_id=seed(pg_review)
    def load(index):
        actor=db.session.get(User,actor_id);roadmap.draft(actor,draft_id)
        return actor
    def write(index,actor):
        try:roadmap.apply_draft(actor,draft_id,[str(item_id)]);return 200
        except HTTPException as error:return error.code
    assert _interleave(pg_review,load,write)==[200,409]
    with pg_review.app_context():
        assert db.session.get(ProjectPlanningDraft,draft_id).applied_at
        assert WorkItemHistory.query.filter_by(work_item_id=item_id,field='start_date').count()==1


def test_dependency_change_after_preload_rejects_draft(pg_review):
    actor_id,project_id,item_id,other_id,draft_id=seed(pg_review)
    def load(index):
        actor=db.session.get(User,actor_id);roadmap.draft(actor,draft_id)
        return actor,db.session.get(WorkItem,item_id),db.session.get(WorkItem,other_id)
    def write(index,state):
        actor,item,other=state
        if not index:service.add_link(actor,item,'blocks',other.key);return 200
        try:roadmap.apply_draft(actor,draft_id,[str(item_id)]);return 200
        except HTTPException as error:return error.code
    assert _interleave(pg_review,load,write)==[200,409]
    with pg_review.app_context():assert db.session.get(WorkItem,item_id).start_date is None
