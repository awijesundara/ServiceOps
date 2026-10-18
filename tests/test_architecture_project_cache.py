"""Project-role decisions must track rollback, bulk updates and actor state."""
import pytest

from app import db
from serviceops_core.projects import service
from serviceops_core.projects.models import ProjectMember
from tests.test_app import app  # noqa: F401
from tests.test_projects_phase2 import pm, project, u  # noqa: F401


@pytest.mark.parametrize("savepoint", [False, True])
def test_rolled_back_project_role_does_not_leave_cached_edit_permission(pm, savepoint):
    row = project()
    actor, user = u("database.manager"), u("viewer.one")
    with pm.test_request_context("/"):
        assert service.project_role(user, row) == "viewer"
        nested = db.session.begin_nested() if savepoint else None
        service.set_member(actor, row, user.id, "member")
        db.session.flush()
        assert service.can_edit(user, row)
        (nested.rollback() if nested else db.session.rollback())
        assert service.project_role(user, row) == "viewer"
        assert not service.can_edit(user, row)


def test_bulk_membership_change_invalidates_cached_project_role(pm):
    row = project()
    user = u("dev.one")
    with pm.test_request_context("/"):
        assert service.can_edit(user, row)
        ProjectMember.query.filter_by(project_id=row.id, user_id=user.id).update({"role": "viewer"})
        assert not service.can_edit(user, row)


def test_deactivating_preloaded_actor_drops_cached_project_access(pm):
    row = project()
    user = u("dev.one")
    with pm.test_request_context("/"):
        assert service.can_edit(user, row)
        user.active = False
        assert not service.can_view(user, row)
