"""Real browser + PostgreSQL AI control workflow on an isolated database.

AI_BROWSER_DATABASE_URL must name a disposable database ending in _ai_browser_test.
Provider responses below are contract fixtures, not real model quality evidence.
"""
import os
import threading

import pytest
from werkzeug.serving import make_server

from app import AIConfiguration, Ticket, User, create_app, db
from serviceops_core.ai import service


@pytest.fixture(scope="module")
def ai_browser_server():
    url = os.getenv("AI_BROWSER_DATABASE_URL", "")
    if not url:
        pytest.skip("AI_BROWSER_DATABASE_URL is required for isolated PostgreSQL browser testing")
    if not url.startswith("postgresql") or not url.endswith("_ai_browser_test"):
        pytest.fail("Refusing non-isolated AI browser database")
    app = create_app({"TESTING": True, "AUTO_MIGRATE_IN_TESTS": True, "AUTO_MIGRATE": True,
                      "SQLALCHEMY_DATABASE_URI": url, "CSRF_ENABLED": True, "SESSION_COOKIE_SECURE": False})
    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        ticket = Ticket(number="INC-AI-BROWSER-" + __import__("uuid").uuid4().hex[:6], kind="incident", title="VPN browser investigation",
                        description="VPN unavailable for the operator", requester_id=user.id, tenant_id=user.tenant_id)
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield app, f"http://127.0.0.1:{server.server_port}", ticket_id
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


@pytest.mark.parametrize("width,height", [(1440, 1000), (768, 1024), (390, 844)])
def test_ai_admin_to_incident_workflow(ai_browser_server, monkeypatch, width, height):
    from playwright.sync_api import sync_playwright
    app, base, ticket_id = ai_browser_server
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", "http://127.0.0.1:18099/v1/chat/completions")
    monkeypatch.setattr(service, "generate", lambda *_: ("VPN is unavailable [S1]. Check the connection. <script>bad()</script>", {}))
    axe_path = os.getenv("AXE_CORE_PATH")
    assert axe_path and os.path.isfile(axe_path), "AXE_CORE_PATH required"
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": width, "height": height}, bypass_csp=True)
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(base + "/login")
        page.locator('input[name="username"]').fill("admin")
        page.locator('input[name="password"]').fill("Admin123!")
        page.locator("button.primary").click()
        page.wait_for_load_state("networkidle")
        page.goto(base + "/admin/section/platform-security")
        page.get_by_role("link", name="AI assistance", exact=False).click()
        page.get_by_label("Enable AI for this organization", exact=True).check()
        page.get_by_label("Enable incident investigations", exact=True).check()
        page.get_by_label("Provider", exact=True).select_option("self_hosted")
        page.get_by_label("Model identifier").fill("local-test")
        page.get_by_label("Self-hosted endpoint", exact=True).fill("http://127.0.0.1:18099/v1/chat/completions")
        page.get_by_role("button", name="Save AI configuration").click()
        page.wait_for_load_state("networkidle")
        assert "AI configuration saved" in page.inner_text("body")
        for path in ("/admin/ai", f"/incidents/{ticket_id}/ai"):
            page.goto(base + path, wait_until="networkidle")
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), page.evaluate("Array.from(document.querySelectorAll('*')).filter(e => e.getBoundingClientRect().right > innerWidth + 1).slice(-15).map(e => [e.tagName,e.className,e.getBoundingClientRect().width,e.textContent.slice(0,60)])")
            page.add_script_tag(path=axe_path)
            violations = page.evaluate("async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa']}})).violations")
            assert not violations, [(v['id'], v['help']) for v in violations]
        page.get_by_role("button", name="Start investigation").click()
        page.wait_for_load_state("networkidle")
        assert "queued" in page.inner_text("body")
        with app.app_context():
            assert service.process_one()
        page.get_by_role("link", name="Refresh status").click()
        page.wait_for_load_state("networkidle")
        assert "completed" in page.inner_text("body")
        assert "<script>bad()</script>" in page.inner_text(".ai-result-text")
        page.add_script_tag(path=axe_path)
        assert not page.evaluate("async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa']}})).violations")
        page.goto(base + "/admin/ai")
        page.get_by_role("button", name="Disable all AI now").click()
        page.wait_for_load_state("networkidle")
        with app.app_context():
            assert not db.session.get(AIConfiguration, 1).enabled
        response = page.goto(base + f"/incidents/{ticket_id}/ai")
        assert response.status == 403
        assert not errors
        browser.close()
