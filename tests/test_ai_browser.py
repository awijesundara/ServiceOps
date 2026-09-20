"""Real browser + PostgreSQL AI control workflow on an isolated database.

AI_BROWSER_DATABASE_URL must name a disposable database ending in _ai_browser_test.
Provider responses below are contract fixtures, not real model quality evidence.
"""
import os
import threading
import time

import pytest
from werkzeug.serving import make_server

from app import AIConfiguration, Ticket, User, create_app, db
from serviceops_core.ai import provider, service


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
    monkeypatch.setattr(service, "generate_stream", lambda config, messages, on_delta, thinking=None: (
        on_delta("content", "VPN is unavailable [S1]. Check the connection. <script>bad()</script>"),
        ("VPN is unavailable [S1]. Check the connection. <script>bad()</script>", "", {}))[1])
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
            # The site's page-entry animation shifts <main> by 9px for 0.3s; measure only once it has settled.
            page.wait_for_timeout(600)
            page.evaluate("Promise.all(document.getAnimations().map(a => a.finished.catch(() => null)))")
            overflow = page.evaluate("({scroll: document.documentElement.scrollWidth, inner: window.innerWidth, body: document.body.scrollWidth, widest: Array.from(document.querySelectorAll('*')).map(e => [e.tagName, String(e.className).slice(0,40), e.scrollWidth]).sort((a,b) => b[2]-a[2]).slice(0,6)})")
            assert overflow["scroll"] <= overflow["inner"] + 1, overflow
            page.add_script_tag(path=axe_path)
            violations = page.evaluate("async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa']}})).violations")
            assert not violations, [(v['id'], v['help']) for v in violations]
        page.get_by_role("button", name="Start investigation").click()
        page.wait_for_selector("[data-ai-status]")
        with app.app_context():
            assert service.process_one()
        page.wait_for_function("document.querySelector('[data-ai-status]').textContent.trim() === 'Complete'")
        assert "<script>bad()</script>" in page.inner_text("[data-ai-answer]")
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


ENDPOINT = "http://127.0.0.1:18099/v1/chat/completions"


def enable_ai(app, **overrides):
    with app.app_context():
        config = db.session.get(AIConfiguration, 1) or AIConfiguration(tenant_id=1)
        config.enabled = config.incident_enabled = config.chat_enabled = True
        config.provider, config.endpoint, config.model = "self_hosted", ENDPOINT, "local-test"
        config.show_reasoning = True
        config.revision = (config.revision or 0) + 1
        for key, value in overrides.items():
            setattr(config, key, value)
        db.session.merge(config)
        db.session.commit()


def sign_in(page, base):
    page.goto(base + "/login")
    page.locator('input[name="username"]').fill("admin")
    page.locator('input[name="password"]').fill("Admin123!")
    page.locator("button.primary").click()
    page.wait_for_load_state("networkidle")


def wait_for(check, timeout=20):
    """Poll from Python: Playwright's wait_for_function needs eval, which the real CSP forbids."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if check():
                return
        except Exception:
            pass
        time.sleep(0.15)
    raise AssertionError("condition not met in time")


def start_worker(app):
    def work():
        with app.app_context():
            service.process_one()
    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    return thread


def test_investigation_streams_steps_reasoning_and_text_under_the_real_csp(ai_browser_server, monkeypatch):
    """No bypass_csp here: the streaming page must work under the production policy, and an HTML
    injection attempt inside the model's answer must stay inert text."""
    from playwright.sync_api import sync_playwright
    app, base, ticket_id = ai_browser_server
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", ENDPOINT)
    enable_ai(app)
    pieces = [("reasoning", "The ticket says the VPN drops after roaming. "), ("reasoning", "Certificates are a likely cause. "),
              ("content", "## Summary\n"), ("content", "The VPN **drops** after roaming [S1]. \n"),
              ("content", "- Renew the certificate\n"), ("content", "- Check the gateway log [S1]\n"),
              ("content", "<img src=x onerror=window.__xss=1> <script>window.__xss=2</script>")]

    def slow_stream(config, messages, on_delta, thinking=None):
        for kind, text in pieces:
            time.sleep(0.8)
            if on_delta(kind, text) is False:
                raise provider.StreamCancelled()
        return ("".join(t for k, t in pieces if k == "content"), "".join(t for k, t in pieces if k == "reasoning"),
                {"completion_tokens": 42, "duration_ms": 5600, "first_token_ms": 800})

    monkeypatch.setattr(service, "generate_stream", slow_stream)
    shots = os.getenv("AI_SCREENSHOT_DIR")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_context(viewport={"width": 1440, "height": 1000}).new_page()
        problems = []
        page.on("pageerror", lambda error: problems.append(str(error)))
        page.on("console", lambda message: problems.append(message.text) if "Content Security Policy" in message.text else None)
        sign_in(page, base)
        page.goto(base + f"/incidents/{ticket_id}/ai", wait_until="networkidle")
        page.get_by_role("button", name="Start investigation").click()
        page.wait_for_selector("[data-ai-status]")
        start_worker(app)
        # Reasoning appears first, while the pill still says "Working".
        wait_for(lambda: "roaming" in (page.locator("[data-ai-reasoning-text]").text_content() or ""))
        assert page.inner_text("[data-ai-status]") == "Working"
        # The answer grows progressively rather than appearing all at once.
        lengths = []
        deadline = time.time() + 20
        while time.time() < deadline and page.inner_text("[data-ai-status]") == "Working":
            lengths.append(len(page.inner_text("[data-ai-answer]")))
            if shots and len(lengths) == 2:
                page.screenshot(path=os.path.join(shots, "ai-streaming.png"))
            time.sleep(0.3)
        assert len({n for n in lengths if n}) >= 3, lengths
        wait_for(lambda: page.inner_text("[data-ai-status]").strip() == "Complete")
        if shots:
            page.screenshot(path=os.path.join(shots, "ai-complete.png"), full_page=True)
        answer = page.locator("[data-ai-answer]")
        assert "Renew the certificate" in answer.inner_text() and answer.locator("li").count() == 2
        assert answer.locator("strong").inner_text() == "drops" and answer.locator("h4").count() == 1
        assert answer.locator("a.ai-cite").first.get_attribute("href").startswith("/ticket/")
        # The injection attempt is displayed as text and never becomes an element or runs.
        assert answer.locator("img, script").count() == 0
        assert "<img src=x" in answer.inner_text() and page.evaluate("typeof window.__xss") == "undefined"
        steps = page.locator("[data-ai-steps]").text_content()
        for label in ("Verified your access", "Collected evidence", "Sending to the model", "The model is reasoning",
                      "Writing the answer", "Checked your access again"):
            assert label in steps
        assert page.locator("[data-ai-thinking]").get_attribute("open") is None
        assert "42 tokens" in page.inner_text("[data-ai-stats]")
        assert page.locator("[data-ai-sources] a.ai-cite").count() == 1
        assert not problems, problems
        browser.close()


def test_stop_button_ends_a_running_investigation_and_keeps_nothing(ai_browser_server, monkeypatch):
    from playwright.sync_api import sync_playwright
    app, base, ticket_id = ai_browser_server
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", ENDPOINT)
    enable_ai(app)

    def slow_stream(config, messages, on_delta, thinking=None):
        for _ in range(40):
            time.sleep(0.4)
            if on_delta("content", "Still thinking about this. ") is False:
                raise provider.StreamCancelled()
        return "Finished anyway [S1]", "", {}

    monkeypatch.setattr(service, "generate_stream", slow_stream)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
        sign_in(page, base)
        page.goto(base + f"/incidents/{ticket_id}/ai", wait_until="networkidle")
        page.get_by_role("button", name="Start investigation").click()
        page.wait_for_selector("[data-ai-status]")
        worker = start_worker(app)
        wait_for(lambda: "Still thinking" in page.inner_text("[data-ai-answer]"))
        page.get_by_role("button", name="Stop").click()
        wait_for(lambda: page.inner_text("[data-ai-status]").strip() == "Stopped", timeout=15)
        worker.join(timeout=10)
        assert page.inner_text("[data-ai-answer]").strip() == ""
        assert "Stopped" in page.inner_text("[data-ai-notice]")
        assert page.locator("[data-ai-stop]").is_hidden()
        browser.close()
