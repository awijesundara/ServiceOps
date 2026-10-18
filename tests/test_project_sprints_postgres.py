"""Real PostgreSQL sprint constraint, migration and stale-request regressions."""
import json
import uuid
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from werkzeug.exceptions import HTTPException

from app import db, User
from serviceops_core.projects import service, sprints, query
from serviceops_core.projects.models import ProjectSprintItem, ProjectSprintEvent, ProjectSprint, WorkItem, Project
from tests.test_architecture_transactions import pg_review, _interleave  # noqa: F401


def seed(application):
    with application.app_context():
        actor=User.query.filter_by(username='admin').one()
        project=service.create_project(actor,'S'+uuid.uuid4().hex[:7].upper(),'PostgreSQL sprint')
        item=service.create_item(actor,project,'Concurrent work',story_points=5)
        a=sprints.save(actor,project,{'name':'First','start_at':'2026-10-17','end_at':'2026-10-31'})
        b=sprints.save(actor,project,{'name':'Second','start_at':'2026-10-17','end_at':'2026-10-31'})
        db.session.commit()
        return actor.id,project.id,item.id,a.id,b.id


def test_concurrent_reassignment_has_one_current_membership(pg_review):
    actor_id,project_id,item_id,a_id,b_id=seed(pg_review)
    def load(index):
        return db.session.get(User,actor_id),db.session.get(Project,project_id),db.session.get(WorkItem,item_id)
    def write(index,state):
        actor,project,item=state
        return sprints.assign(actor,project,item.key,b_id if index else a_id).sprint_id
    assert _interleave(pg_review,load,write)==[a_id,b_id]
    with pg_review.app_context():
        assert ProjectSprintItem.query.filter_by(work_item_id=item_id,active=True).one().sprint_id==b_id
        actor=db.session.get(User,actor_id)
        assert query.search(actor,f'sprint IN futureSprints() AND key={db.session.get(WorkItem,item_id).key}').count()==1


def test_stale_update_after_completion_preserves_closed_snapshot(pg_review):
    actor_id,project_id,item_id,a_id,b_id=seed(pg_review)
    with pg_review.app_context():
        actor=db.session.get(User,actor_id); project=db.session.get(Project,project_id)
        sprints.assign(actor,project,db.session.get(WorkItem,item_id).key,a_id)
        sprints.start(actor,project,a_id); db.session.commit()
        done_id=next(s.id for s in project.statuses if s.category=='done')
    def load(index):
        return db.session.get(User,actor_id),db.session.get(Project,project_id),db.session.get(WorkItem,item_id)
    def write(index,state):
        actor,project,item=state
        if index: service.update_item(actor,item,{'status_id':done_id,'story_points':13})
        else: sprints.complete(actor,project,a_id,b_id)
        return True
    assert _interleave(pg_review,load,write)==[True,True]
    with pg_review.app_context():
        row=db.session.get(ProjectSprint,a_id)
        assert json.loads(row.outcome_json)['done_points']==0
        assert json.loads(row.outcome_json)['points']==5
        assert db.session.get(WorkItem,item_id).story_points==13


def test_start_race_rejects_second_and_captures_one_baseline(pg_review):
    actor_id,project_id,item_id,a_id,b_id=seed(pg_review)
    with pg_review.app_context():
        sprints.assign(db.session.get(User,actor_id),db.session.get(Project,project_id),db.session.get(WorkItem,item_id).key,a_id)
        db.session.commit()
    def load(index):
        db.session.get(ProjectSprint,a_id)  # both requests preload planned state
        return db.session.get(User,actor_id),db.session.get(Project,project_id)
    def write(index,state):
        try: sprints.start(*state,a_id); return 200
        except HTTPException as error: return error.code
    assert _interleave(pg_review,load,write)==[200,409]
    with pg_review.app_context():
        assert ProjectSprintEvent.query.filter_by(sprint_id=a_id,kind='baseline').count()==1


def test_sprint_migration_roundtrip_preserves_existing_projects(pg_review):
    with pg_review.app_context():
        before=Project.query.count()
        db.session.remove()
        config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
        command.downgrade(config,'20261017_0129')
        assert 'project_sprint' not in inspect(db.engine).get_table_names()
        assert Project.query.count()==before
        db.session.remove()
        command.upgrade(config,'head')
        assert {'project_sprint','project_sprint_item','project_sprint_event'}<=set(inspect(db.engine).get_table_names())


def test_stale_member_commands_cannot_mutate_an_item_moved_to_a_private_project(pg_review):
    from serviceops_core.projects import operations, tracking
    for operation in ('update','delete','worklog'):
        actor_id,project_id,item_id,a_id,b_id=seed(pg_review)
        with pg_review.app_context():
            actor=db.session.get(User,actor_id); source=db.session.get(Project,project_id)
            member=User(username='stale.'+uuid.uuid4().hex[:10],name='Stale member',email=uuid.uuid4().hex+'@test.invalid',role='agent',password_hash='unused',tenant_id=actor.tenant_id)
            db.session.add(member); db.session.flush(); member_id=member.id
            service.set_member(actor,source,member.id,'member')
            item=db.session.get(WorkItem,item_id); item.reporter_id=member.id
            target=service.create_project(actor,'M'+uuid.uuid4().hex[:7].upper(),'Private target')
            db.session.commit(); target_id=target.id
        def load(index):
            item=db.session.get(WorkItem,item_id)
            item.project  # preload the original authorization context in both requests
            return db.session.get(User,actor_id),db.session.get(User,member_id),item,db.session.get(Project,target_id)
        def write(index,state):
            actor,member,item,target=state
            if not index: operations.move_item(actor,item,target); return 200
            try:
                if operation=='update': service.update_item(member,item,{'title':'Unauthorized edit'})
                elif operation=='delete': service.delete_item(member,item)
                else: tracking.log_work(member,item,'1h')
                return 200
            except HTTPException as error: return error.code
        assert _interleave(pg_review,load,write)==[200,409], operation
