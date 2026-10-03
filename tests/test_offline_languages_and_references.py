"""Offline preferences and human-readable, safe AI references."""
import json
import os
from pathlib import Path
import threading

import pytest
from markupsafe import escape
from werkzeug.serving import make_server

from app import AIRun, Comment, UserPreference, db
from serviceops_core.ai import service
from serviceops_core.ai.references import readable_references, safe_reference_url, source_links
from serviceops_core.ai_note import render_ai_note
from serviceops_core.localization import CATALOGS, translate
from tests.test_ai_assistant import configure, fake_stream, submit, allow_test_endpoint  # noqa: F401
from tests.test_app import app, client, login  # noqa: F401


def test_bundled_catalogs_are_complete_for_the_common_message_set():
    assert len(CATALOGS) == 83
    expected = set(CATALOGS["en"]["messages"])
    assert len(expected) == 24
    assert all(set(catalog["messages"]) == expected for catalog in CATALOGS.values())
    assert translate("Save", "ja") == "保存"
    assert translate("Not translated", "ja") == "Not translated"
    assert translate("Save", "unknown") == "Save"


@pytest.mark.parametrize("language,direction,label", [("en", "ltr", "System preferences"), ("ja", "ltr", "システム設定"), ("si", "ltr", "පද්ධති අභිරුචි"), ("ar", "rtl", "تفضيلات النظام")])
def test_saved_language_is_account_scoped_and_english_is_default(app, client, language, direction, label):
    login(client)
    initial = client.get("/preferences").get_data(as_text=True)
    assert 'lang="en" dir="ltr"' in initial
    assert client.post("/preferences", data={"language": language, "font_scale": "100"}).status_code == 302
    with app.app_context():
        assert UserPreference.query.filter_by(user_id=1).one().language == language
    page = client.get("/preferences").get_data(as_text=True)
    assert f'lang="{language}" dir="{direction}"' in page
    assert label in page
    assert ('/static/rtl.css' in page) == (direction == "rtl")
    assert client.post("/preferences", data={"language": "../invalid", "font_scale": "100"}).status_code == 400
    with app.app_context():
        assert UserPreference.query.filter_by(user_id=1).one().language == language


@pytest.mark.parametrize("url", ["javascript:alert(1)", "//evil.example/path", "/\\evil.example/path", "/%2fEVIL", "/ticket/1%0aevil", "https://evil.example/", None])
def test_reference_links_reject_remote_or_unsafe_urls(url):
    assert not safe_reference_url(url)


def test_references_use_verified_ticket_number_and_unknown_markers_disappear(app):
    with app.test_request_context():
        sources = source_links([{"id": "S1", "kind": "ticket", "record_id": 1, "number": "INC000001", "title": "Router failure"},
                                {"id": "S2", "kind": "unlinked", "record_id": 2, "title": "Local evidence"}])
        body = readable_references("INC000001 [S1] restored. Check S2 and [S9].", sources)
        assert body.count("[INC000001](/ticket/1)") == 1
        assert "Local evidence" in body
        assert not any(marker in body for marker in ("S1", "S2", "S9"))
        assert readable_references(body, sources) == body
        html = str(render_ai_note(body + ' [bad](javascript:alert) <script>x</script>', escape))
        assert '<a class="ai-note-reference" href="/ticket/1">INC000001</a>' in html
        assert "javascript:" not in html and "<script>" not in html


def test_investigation_draft_and_posted_comment_resolve_reference_links(app, client, monkeypatch):
    ticket_id = configure(app, actions_enabled=True)
    login(client)
    run_id = submit(client, ticket_id)
    monkeypatch.setattr(service, "generate_stream", fake_stream("Summary:\nIssue [S1].\nDraft Operator Response:\nInvestigated [S1]; unavailable [S99]."))
    with app.app_context():
        assert service.process_one()
        run = db.session.get(AIRun, run_id)
        number = json.loads(run.sources_json)[0]["number"]
    fallback = client.get(f"/ai/runs/{run_id}").get_data(as_text=True)
    assert "[S1]" not in fallback and "[S99]" not in fallback
    assert f'href="/ticket/{ticket_id}">{number}</a>' in fallback
    proposal = client.post(f"/ai/runs/{run_id}/actions/comment")
    review_url = proposal.headers["Location"]
    review = client.get(review_url).get_data(as_text=True)
    assert number in review and "[S1]" not in review and "[S99]" not in review
    assert client.post(review_url, data={"decision": "approve", "body": "Investigated [S1]; not linked [S99]."}).status_code == 302
    with app.app_context():
        body = Comment.query.filter_by(ticket_id=ticket_id).one().body
        assert f"[{number}](/ticket/{ticket_id})" in body
        assert "[S" not in body
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert f'href="/ticket/{ticket_id}">{number}</a>' in page


def _require_browser_tooling():
    """Skip where the browser job's tooling is absent (e.g. the Docker test image)."""
    pytest.importorskip("playwright.sync_api")
    if not os.path.isfile(os.environ.get("AXE_CORE_PATH", "")):
        pytest.skip("AXE_CORE_PATH must point to axe.min.js for browser accessibility checks")


@pytest.mark.parametrize("language,width", [("ja", 1440), ("ar", 1440), ("ar", 390), ("si", 390)])
def test_browser_language_selection_rtl_and_safe_ai_citations(app, client, language, width):
    _require_browser_tooling()
    from playwright.sync_api import sync_playwright
    login(client)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(viewport={"width": width, "height": 1000}, reduced_motion="reduce")
            context.add_cookies([{"name": "session", "value": client.get_cookie("session").value, "domain": "127.0.0.1", "path": "/"}])
            page = context.new_page()
            page.goto(f"http://127.0.0.1:{server.server_port}/preferences")
            assert page.locator('select[name="language"] option').count() == 83
            page.locator('select[name="language"]').select_option(language)
            page.get_by_role("button", name="Save preferences", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert page.locator("html").get_attribute("lang") == language
            assert page.get_by_role("heading", name=translate("System preferences", language), exact=True).count() == 1
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            page.evaluate(Path(os.environ["AXE_CORE_PATH"]).read_text())
            assert not page.evaluate("async () => (await axe.run(document, {runOnly: {type:'tag', values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
            page.evaluate(Path("static/ai-render.js").read_text())
            result = page.evaluate('''() => {
              const host = document.createElement('div');
              host.appendChild(AIRender.render('INC000001 restored [S1]. Unknown [S9]. Unlinked [S2].', {S1:{number:'INC000001',title:'Gateway',url:'/ticket/1'}, S2:{title:'Local evidence'}}));
              const link=host.querySelector('a');
              return {text:host.textContent, label:link.textContent, url:link.getAttribute('href'), count:host.querySelectorAll('a').length};
            }''')
            assert result["count"] == 2
            assert result["label"] == "INC000001" and result["url"] == "/ticket/1"
            assert "S1" not in result["text"] and "S9" not in result["text"]
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
