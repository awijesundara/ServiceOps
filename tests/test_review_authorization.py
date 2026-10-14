"""Regression coverage for the interrupted whole-application security review."""
import pytest

from app import Audit, Knowledge, Tenant, User, db
from tests.test_app import app, client, login


@pytest.mark.parametrize("role,is_author,allowed", [
    ("agent", False, False), ("agent", True, True),
    ("manager", False, True), ("admin", False, True),
    ("requester", False, False),
])
def test_knowledge_archive_authorization_and_button(client, app, role, is_author, allowed):
    with app.app_context():
        user = User.query.filter_by(username="employee").one()
        author = User.query.filter_by(username="admin").one()
        user.role = role
        article = Knowledge(title="Archive permissions", body="Keep this content", category="General",
                            author_id=user.id if is_author else author.id, tenant_id=user.tenant_id)
        db.session.add(article)
        db.session.commit()
        article_id = article.id
    login(client, "employee", "Employee123!")
    archive_path = f"/knowledge/{article_id}/archive"
    page = client.get(f"/knowledge/{article_id}")
    assert page.status_code == 200
    assert (f'action="{archive_path}"'.encode() in page.data) is allowed
    response = client.post(archive_path)
    assert response.status_code == (302 if allowed else 403)
    with app.app_context():
        article = db.session.get(Knowledge, article_id)
        assert article.archived is allowed
        assert article.published is (not allowed)
        assert article.body == "Keep this content"
        assert Audit.query.filter_by(action="archive", target=f"KB{article_id:06d}").count() == int(allowed)


def test_knowledge_archive_cannot_cross_tenants(client, app):
    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        foreign = Tenant(slug="archive-other", name="Other tenant")
        db.session.add(foreign)
        db.session.flush()
        article = Knowledge(title="Foreign article", body="Private", category="General",
                            author_id=user.id, tenant_id=foreign.id)
        db.session.add(article)
        db.session.commit()
        article_id = article.id
    login(client)
    assert client.get(f"/knowledge/{article_id}").status_code == 404
    assert client.post(f"/knowledge/{article_id}/archive").status_code == 404
    with app.app_context():
        assert db.session.get(Knowledge, article_id).archived is False
