"""Notes drafted by ServiceOps AI and approved by a person are tagged and keep their structure."""
import os
import tempfile
import pytest

from alembic import command
from alembic.config import Config as AlembicConfig
from markupsafe import Markup, escape
from sqlalchemy import text

from app import Comment, create_app, db
from serviceops_core.ai import service
from serviceops_core.ai_note import render_ai_note
from serviceops_core.ai.actions import investigation_comment_draft
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


@pytest.mark.parametrize("answer,expected", [
    (STRUCTURED_NOTE, "We are restoring the IRQ affinity."),
    ("## Draft Operator Response\nA concise reply.\n\n## Evidence\nPrivate investigation", "A concise reply."),
    ("**Draft Operator Response:**\n“Restored.”", "Restored."),
    ("Incident Summary:\nAnalysis only.", ""),
    ("A short unstructured answer.", ""),
    ("Draft Operator Response:\n" + "x" * 10001, ""),
])
def test_operator_response_extraction(answer, expected):
    assert investigation_comment_draft(answer) == expected


@pytest.mark.parametrize("body", [None, "", "   ", "x" * 10001])
def test_comment_requires_valid_user_reviewed_text(app, client, monkeypatch, body):
    ticket_id = configure(app, actions_enabled=True)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "generate_stream", fake_stream(STRUCTURED_NOTE))
    with app.app_context():
        assert service.process_one()
    proposal = client.post(f"/ai/runs/{run_id}/actions/comment")
    url = proposal.headers["Location"]
    review = client.get(url).get_data(as_text=True)
    assert 'name="body"' in review and "We are restoring the IRQ affinity." in review
    assert "Latency rose after" not in review
    data = {"decision": "approve"}
    if body is not None:
        data["body"] = body
    assert client.post(url, data=data).status_code == 400
    with app.app_context():
        assert Comment.query.filter_by(ticket_id=ticket_id).count() == 0


@pytest.mark.parametrize("width", [1440, 390])
def test_browser_edits_operator_response_before_posting(app, client, monkeypatch, width):
    import threading
    from pathlib import Path
    from playwright.sync_api import sync_playwright
    from werkzeug.serving import make_server

    ticket_id = configure(app, actions_enabled=True)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "generate_stream", fake_stream(STRUCTURED_NOTE))
    with app.app_context():
        assert service.process_one()
    proposal = client.post(f"/ai/runs/{run_id}/actions/comment")
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(viewport={"width": width, "height": 1000}, reduced_motion="reduce")
            context.add_cookies([{"name": "session", "value": client.get_cookie("session").value,
                                 "domain": "127.0.0.1", "path": "/"}])
            page = context.new_page()
            page.goto(f"http://127.0.0.1:{server.server_port}" + proposal.headers["Location"])
            editor = page.get_by_label("Comment", exact=True)
            assert editor.input_value() == "We are restoring the IRQ affinity."
            editor.fill("The gateway is restored. Please retry your connection.")
            axe = Path(os.environ["AXE_CORE_PATH"])
            page.evaluate(axe.read_text())
            assert not page.evaluate("async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa']}})).violations")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            page.get_by_role("button", name="Post comment", exact=True).click()
            page.wait_for_load_state("networkidle")
            with app.app_context():
                comment = Comment.query.filter_by(ticket_id=ticket_id).one()
                assert comment.body == "The gateway is restored. Please retry your connection."
                assert comment.ai_assisted
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


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
    assert client.post(f"/ai/actions/{action_id}", data={"decision": "approve", "body": "We are restoring the IRQ affinity."}).status_code == 302
    return ticket_id


def test_approved_ai_note_contains_only_the_edited_response(app, client, monkeypatch):
    ticket_id = approve_ai_comment(app, client, monkeypatch, STRUCTURED_NOTE)
    with app.app_context():
        comment = Comment.query.filter_by(ticket_id=ticket_id).one()
        assert comment.ai_assisted is True
        assert comment.body == "We are restoring the IRQ affinity."
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert "AI-assisted" in page
    assert "In collaboration with AI" not in page
    assert "Safe Diagnostic Next Steps" not in page
    assert "Draft Operator Response" not in page
    assert "We are restoring the IRQ affinity." in page


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
    assert "S2" not in html
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
