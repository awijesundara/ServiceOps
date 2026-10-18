"""Real PostgreSQL stale-read and recursive-query checks for nested work."""
import uuid

from werkzeug.exceptions import HTTPException
from app import User, db
from serviceops_core.projects import service
from serviceops_core.projects.models import Project, WorkItem
from tests.test_architecture_transactions import pg_review, _interleave  # noqa: F401


def test_stale_reciprocal_reparent_cannot_create_a_cycle(pg_review):
    with pg_review.app_context():
        actor=User.query.filter_by(username='admin').one()
        project=service.create_project(actor,'H'+uuid.uuid4().hex[:7].upper(),'Concurrent hierarchy')
        root=service.create_item(actor,project,'Root')
        a=service.create_item(actor,project,'A',item_type='subtask',parent_id=root.id)
        b=service.create_item(actor,project,'B',item_type='subtask',parent_id=root.id)
        db.session.commit()
        actor_id, a_id, b_id=actor.id,a.id,b.id

    def load(index):
        return db.session.get(User,actor_id), db.session.get(WorkItem,a_id if index==0 else b_id)

    def write(index,state):
        actor,item=state
        try:
            service.update_item(actor,item,{'parent_id': b_id if index==0 else a_id})
            return 'changed'
        except HTTPException as error:
            assert error.code==400
            db.session.rollback()
            return 'rejected'

    assert _interleave(pg_review,load,write)==['changed','rejected']
    with pg_review.app_context():
        a=db.session.get(WorkItem,a_id)
        assert len(service.ancestor_path(a))==2
        from serviceops_core.projects import planning
        data=planning.portfolio(db.session.get(User,actor_id))
        assert data["summaries"][a.project_id]["total"]==3
