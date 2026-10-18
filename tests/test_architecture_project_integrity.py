"""Cross-project moves preserve hierarchy and resolution invariants."""
import pytest
from werkzeug.exceptions import HTTPException

from app import db
from serviceops_core.projects import operations, service
from tests.test_app import app  # noqa: F401
from tests.test_projects_phase2 import pm, project, status, u  # noqa: F401


def test_move_cannot_leave_private_epic_children_in_another_project(pm):
    source, destination = project("SRC"), project("DST", visibility="open")
    epic = service.create_item(u("dev.one"), source, "Private epic", item_type="epic")
    story = service.create_item(u("dev.one"), source, "Private story", item_type="story", parent_id=epic.id)
    db.session.commit()
    with pytest.raises(HTTPException) as error:
        operations.move_item(u("dev.one"), epic, destination)
    assert error.value.code == 409
    db.session.rollback()
    assert epic.project_id == story.project_id == source.id


def test_move_cannot_convert_parent_with_subtasks_into_epic(pm):
    source, destination = project("SRC"), project("DST")
    parent = service.create_item(u("dev.one"), source, "Parent", item_type="story")
    child = service.create_item(u("dev.one"), source, "Child", item_type="subtask", parent_id=parent.id)
    db.session.commit()
    with pytest.raises(HTTPException) as error:
        operations.move_item(u("dev.one"), parent, destination, item_type="epic")
    assert error.value.code == 409
    db.session.rollback()
    assert parent.item_type == "story" and child.parent_id == parent.id


def test_move_into_done_status_sets_resolution_and_moving_back_clears_it(pm):
    source, destination = project("SRC"), project("DST")
    item = service.create_item(u("dev.one"), source, "Move me")
    operations.move_item(u("dev.one"), item, destination, status_id=status(destination, "done").id)
    db.session.commit()
    assert item.status.category == "done" and item.resolution_id and item.resolved_at
    operations.move_item(u("dev.one"), item, source, status_id=status(source, "todo").id)
    db.session.commit()
    assert item.status.category == "todo" and item.resolution_id is None and item.resolved_at is None
