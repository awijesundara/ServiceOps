"""Notes drafted by ServiceOps AI and approved by a person are tagged and keep their structure."""
import os
import tempfile

from alembic import command
from alembic.config import Config as AlembicConfig
from markupsafe import Markup, escape
from sqlalchemy import text

from app import Comment, create_app, db
from serviceops_core.ai import service
from serviceops_core.ai_note import render_ai_note
from tests.test_ai_assistant import allow_test_endpoint, configure, fake_stream, submit  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401

STRUCTURED_NOTE = (
    "Incident Summary:\n"
    "Latency rose after the 05:50 reboot [S1].\n"
    "\n"
    "Safe Diagnostic Next Steps:\n"
    "1. Check the active `tuned` profile.\n"
    "2. Verify **irqbalance** is running.\n"
    "\n"
    "Missing Information:\n"
    "- NIC ring buffer statistics.\n"
    "\n"
    "Draft Operator Response:\n"
    '"We are restoring the IRQ affinity."'
)


def plain_mentions(body):
    return escape(body)


def approve_ai_comment(app, client, monkeypatch, answer):
    ticket_id = configure(app, actions_enabled=True)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "generate_stream", fake_stream(answer))
    with app.app_context():
        assert service.process_one()
    proposal = client.post(f"/ai/runs/{run_id}/actions/comment")
    assert proposal.status_code == 302, proposal.get_data(as_text=True)[-1500:]
    action_id = proposal.headers["Location"].rstrip("/").split("/")[-1]
    assert client.post(f"/ai/actions/{action_id}", data={"decision": "approve"}).status_code == 302
    return ticket_id


def test_approved_ai_note_is_tagged_and_rendered_with_structure(app, client, monkeypatch):
    ticket_id = approve_ai_comment(app, client, monkeypatch, STRUCTURED_NOTE)
    with app.app_context():
        comment = Comment.query.filter_by(ticket_id=ticket_id).one()
        assert comment.ai_assisted is True
        assert comment.body == STRUCTURED_NOTE  # the stored text is exactly what was approved
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "In collaboration with AI" in page
    assert 'class="ai-note"' in page
    assert '<h4 class="ai-note-heading">Safe Diagnostic Next Steps</h4>' in page
    assert "<ol><li>Check the active <code>tuned</code> profile.</li>" in page
    assert "<strong>irqbalance</strong>" in page
    assert "<blockquote>We are restoring the IRQ affinity.</blockquote>" in page


def test_a_person_s_own_comment_is_not_tagged_and_keeps_line_breaks(app, client, monkeypatch):
    ticket_id = configure(app)
    login(client)
    assert client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Step one\nStep two"}).status_code in (200, 302)
    with app.app_context():
        assert Comment.query.filter_by(ticket_id=ticket_id).one().ai_assisted is False
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "In collaboration with AI" not in page
    assert '<p class="comment-text">Step one\nStep two</p>' in page


def test_renderer_escapes_everything_it_does_not_format():
    html = str(render_ai_note('Title:\n<script>alert(1)</script> `<b>x</b>` **<i>y</i>** [S2]', plain_mentions))
    assert "<script>" not in html and "<b>" not in html and "<i>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<code>&lt;b&gt;x&lt;/b&gt;</code>" in html
    assert "<strong>&lt;i&gt;y&lt;/i&gt;</strong>" in html
    assert '<span class="ai-note-cite" title="Source S2">S2</span>' in html
    assert isinstance(render_ai_note("x", plain_mentions), Markup)


def test_renderer_keeps_list_numbering_and_plain_paragraphs():
    html = str(render_ai_note("Steps:\n3. third\n4. fourth\n\nJust a sentence.\nSecond line.", plain_mentions))
    assert '<ol start="3"><li>third</li><li>fourth</li></ol>' in html
    assert "<p>Just a sentence.<br>Second line.</p>" in html


def test_migration_tags_earlier_ai_comments_from_the_audit_log():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    migrated_app = create_app({"TESTING": True, "AUTO_MIGRATE_IN_TESTS": True,
                               "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    root = os.path.dirname(os.path.dirname(__file__))
    config = AlembicConfig(os.path.join(root, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(root, "migrations"))
    try:
        with migrated_app.app_context():
            db.session.remove()
            command.downgrade(config, "20261002_0108")
            for comment_id in (901, 902):
                db.session.execute(text(
                    "INSERT INTO comment (id, ticket_id, user_id, body, created_at, tenant_id) "
                    "VALUES (:id, 1, 1, 'note', CURRENT_TIMESTAMP, 1)"), {"id": comment_id})
            db.session.execute(text(
                "INSERT INTO audit (event_id, action, target, details, request_id, security_context_json, "
                "integrity_version, integrity_key_id, previous_hash, event_hash, created_at, tenant_id) VALUES ('e-901', "
                "'ai action execute', 'INC1', 'type=add_comment; comment=901', 'r', '{}', 'v', 'k', '', 'h-901', "
                "CURRENT_TIMESTAMP, 1)"))
            db.session.commit()
            db.session.remove()
            command.upgrade(config, "head")
            rows = dict(db.session.execute(text("SELECT id, ai_assisted FROM comment WHERE id IN (901, 902)")).all())
            assert bool(rows[901]) is True and bool(rows[902]) is False
    finally:
        os.unlink(path)
