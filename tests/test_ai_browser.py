"""Real browser + PostgreSQL AI control workflow on an isolated database.

AI_BROWSER_DATABASE_URL must name a disposable database ending in _ai_browser_test.
Provider responses below are contract fixtures, not real model quality evidence.
"""
import os
import threading
import time

import pytest
from werkzeug.serving import make_server

from app import AIConfiguration, Comment, Ticket, User, create_app, db
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
        # The site's page-entry animation shifts <main> by 9px while it plays; measure layout without it.
        context = browser.new_context(viewport={"width": width, "height": height}, bypass_csp=True, reduced_motion="reduce")
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(base + "/login")
        page.locator('input[name="username"]').fill("admin")
        page.locator('input[name="password"]').fill("Admin123!")
        page.locator("button.primary").click()
        page.wait_for_load_state("networkidle")
        page.goto(base + "/admin/section/platform-security")
        page.goto(base + "/admin/ai", wait_until="networkidle")
        with app.app_context():
            from app import AIConnection
            AIConnection.query.delete()
            db.session.add(AIConnection(tenant_id=1, name="Test server", provider="self_hosted", model="local-test",
                                        endpoint="http://127.0.0.1:18099/v1/chat/completions"))
            db.session.commit()
        page.goto(base + "/admin/ai", wait_until="networkidle")
        for label in ("Turn AI on for this organization", "Investigate with AI on incidents"):
            page.get_by_label(label).uncheck()  # a change is what reveals the save bar
            page.get_by_label(label).check()
        assert page.locator("[data-ai-savebar]").is_visible()
        page.get_by_role("button", name="Save AI settings").click()
        page.wait_for_load_state("networkidle")
        assert "Saved" in page.inner_text("body")
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
        page.get_by_role("button", name="Turn AI off now").click()
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
        from app import AIConnection
        AIConnection.query.delete()  # the legacy single-service settings below are used unless a test adds services
        config = db.session.get(AIConfiguration, 1) or AIConfiguration(tenant_id=1)
        config.enabled = config.incident_enabled = config.chat_enabled = True
        config.provider, config.endpoint, config.model = "self_hosted", ENDPOINT, "local-test"
        config.show_reasoning = True
        config.revision = (config.revision or 0) + 1
        for key, value in overrides.items():
            setattr(config, key, value)
        db.session.merge(config)
        db.session.commit()


def clear_chats(app):
    from app import AIConversation, AIMessage, AIRun
    with app.app_context():
        AIRun.query.filter_by(kind="chat").delete()
        AIMessage.query.delete()
        AIConversation.query.delete()
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
        # A compact status replaces itself as work advances. Private reasoning is never put in the DOM.
        wait_for(lambda: page.locator("[data-ai-thinking-label]").inner_text() == "Thinking")
        assert page.inner_text("[data-ai-status]") == "Working"
        assert page.locator("[data-ai-reasoning-text], [data-ai-steps]").count() == 0
        wait_for(lambda: page.locator("[data-ai-thinking-label]").inner_text() == "Writing answer")
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
        wait_for(lambda: page.locator("[data-ai-answer] a.ai-cite").count() >= 1)  # typing finished, citations linked
        if shots:
            page.screenshot(path=os.path.join(shots, "ai-complete.png"), full_page=True)
        answer = page.locator("[data-ai-answer]")
        assert "Renew the certificate" in answer.inner_text() and answer.locator("li").count() == 2
        assert answer.locator("strong").inner_text() == "drops" and answer.locator("h4").count() == 1
        assert answer.locator("a.ai-cite").first.get_attribute("href").startswith("/ticket/")
        # The injection attempt is displayed as text and never becomes an element or runs.
        assert answer.locator("img, script").count() == 0
        assert "<img src=x" in answer.inner_text() and page.evaluate("typeof window.__xss") == "undefined"
        assert page.locator("[data-ai-thinking]").is_hidden()
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


def test_approved_ticket_comment_action_requires_exact_browser_review(ai_browser_server, monkeypatch):
    from playwright.sync_api import sync_playwright
    app, base, ticket_id = ai_browser_server
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", ENDPOINT)
    enable_ai(app, actions_enabled=True)
    answer = "Check the VPN gateway and client logs [S1]."
    monkeypatch.setattr(service, "generate_stream", lambda config, messages, on_delta, thinking=None: (
        on_delta("content", answer), (answer, "", {"completion_tokens": 8}))[1])

    with app.app_context():
        before = Comment.query.filter_by(ticket_id=ticket_id).count()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
        sign_in(page, base)
        page.goto(base + f"/incidents/{ticket_id}/ai", wait_until="networkidle")
        page.get_by_role("button", name="Start investigation").click()
        page.wait_for_selector("[data-ai-status]")
        start_worker(app).join(timeout=10)
        wait_for(lambda: page.locator("[data-ai-status]").inner_text().strip() == "Complete")
        page.get_by_role("button", name="Prepare as ticket comment").click()
        page.wait_for_load_state("networkidle")
        assert page.get_by_role("heading", name="Exact proposed change").is_visible()
        assert page.locator(".detail-list dd").inner_text() == answer
        assert not axe_violations(page)
        page.get_by_role("button", name="Approve and apply").click()
        page.wait_for_load_state("networkidle")
        assert "Approved and applied to the ticket" in page.inner_text("body")
        with app.app_context():
            comments = Comment.query.filter_by(ticket_id=ticket_id).order_by(Comment.id).all()
            assert len(comments) == before + 1
            assert comments[-1].body == answer
        browser.close()


def test_admin_chat_ticket_update_requires_browser_review(ai_browser_server, monkeypatch):
    from playwright.sync_api import sync_playwright
    app, base, ticket_id = ai_browser_server
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", ENDPOINT)
    enable_ai(app, actions_enabled=True)
    clear_chats(app)
    with app.app_context():
        ticket = db.session.get(Ticket, ticket_id)
        ticket.number, ticket.state, ticket.priority = f"INC9{ticket.id:07d}", "New", "P3"
        number = ticket.number
        db.session.commit()
    answer = "I prepared the exact ticket update for your review [S1]."
    monkeypatch.setattr(service, "generate_stream", lambda config, messages, on_delta, thinking=None: (
        on_delta("content", answer), (answer, "", {"completion_tokens": 8}))[1])
    stop_worker = threading.Event()

    def keep_working():
        with app.app_context():
            while not stop_worker.is_set():
                if not service.process_one():
                    time.sleep(0.2)
    threading.Thread(target=keep_working, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
            sign_in(page, base)
            page.goto(base + "/ai/chat", wait_until="networkidle")
            page.get_by_label("Your question").fill(f"Set {number} priority to P1 and move state to In Progress")
            page.get_by_role("button", name="Send").click()
            wait_for(lambda: page.get_by_role("button", name="Review exact change").count() == 1)
            with app.app_context():
                unchanged = db.session.get(Ticket, ticket_id)
                assert (unchanged.state, unchanged.priority) == ("New", "P3")
            assert not axe_violations(page)
            page.get_by_role("button", name="Review exact change").click()
            wait_for(lambda: page.get_by_role("heading", name=f"Update ticket for {number}").count() == 1)
            page.wait_for_load_state("networkidle")
            assert page.get_by_role("heading", name=f"Update ticket for {number}").is_visible()
            assert "In Progress" in page.locator(".detail-list").inner_text()
            assert "P1" in page.locator(".detail-list").inner_text()
            assert not axe_violations(page)
            page.get_by_role("button", name="Approve and apply").click()
            page.wait_for_load_state("networkidle")
            assert "Approved and applied" in page.inner_text("body")
            with app.app_context():
                updated = db.session.get(Ticket, ticket_id)
                assert (updated.state, updated.priority) == ("In Progress", "P1")
            browser.close()
    finally:
        stop_worker.set()


def axe_details(page):
    page.add_script_tag(url="/__axe.js") if not page.evaluate("typeof window.axe !== 'undefined'") else None
    return page.evaluate("async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa']}})).violations.map(v => [v.id, v.nodes.map(n => n.html.slice(0,140) + ' :: ' + (n.any[0] ? n.any[0].message : ''))])")


def axe_violations(page):
    # The production CSP forbids inline script, so serve axe as a same-origin file via request interception.
    if not getattr(page, "_axe_routed", False):
        source = open(os.getenv("AXE_CORE_PATH"), encoding="utf-8").read()
        page.route("**/__axe.js", lambda route: route.fulfill(body=source, content_type="application/javascript"))
        page._axe_routed = True
    if not page.evaluate("typeof window.axe !== 'undefined'"):
        page.add_script_tag(url="/__axe.js")
    return [(v["id"], v["help"]) for v in page.evaluate(
        "async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa']}})).violations")]


@pytest.mark.parametrize("width,height", [(1440, 1000), (768, 1024), (390, 844)])
def test_chat_widget_streams_and_deletes_under_the_real_csp(ai_browser_server, monkeypatch, width, height):
    from playwright.sync_api import sync_playwright
    app, base, _ = ai_browser_server
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", ENDPOINT)
    enable_ai(app)
    clear_chats(app)
    seen = []
    pieces = [("reasoning", "The user asks about the VPN. "), ("reasoning", "Reviewing the permitted records. "),
              ("content", "The VPN drops after roaming [S1]. "),
              ("content", "Renew the **certificate**. <img src=x onerror=window.__xss=1>")]

    def slow_stream(config, messages, on_delta, thinking=None):
        seen.append(thinking)
        for kind, text in pieces:
            time.sleep(0.8)
            if on_delta(kind, text) is False:
                raise provider.StreamCancelled()
        return ("".join(t for k, t in pieces if k == "content"), "".join(t for k, t in pieces if k == "reasoning"), {"completion_tokens": 9})

    monkeypatch.setattr(service, "generate_stream", slow_stream)
    shots = os.getenv("AI_SCREENSHOT_DIR")
    stop_worker = threading.Event()

    def keep_working():
        with app.app_context():
            while not stop_worker.is_set():
                if not service.process_one():
                    time.sleep(0.2)
    threading.Thread(target=keep_working, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_context(viewport={"width": width, "height": height}).new_page()
            problems = []
            page.on("pageerror", lambda error: problems.append(str(error)))
            page.on("console", lambda m: problems.append(m.text) if "Content Security Policy" in m.text else None)
            sign_in(page, base)
            page.goto(base + "/", wait_until="networkidle")
            launcher = page.locator("[data-chat-launch]")
            assert launcher.is_visible()
            launcher.focus()
            page.keyboard.press("Enter")
            panel = page.locator("[data-chat]")
            wait_for(lambda: panel.is_visible())
            wait_for(lambda: "Admin" in page.inner_text("[data-chat-scope]"))
            assert page.evaluate("document.activeElement.id") == "ai-chat-input"
            assert not axe_violations(page)
            page.locator("#ai-chat-input").fill("Why does my VPN keep dropping?")
            page.keyboard.press("Enter")
            wait_for(lambda: page.locator(".ai-turn-user").count() == 1)
            wait_for(lambda: page.locator("[data-ai-status]").last.inner_text().strip() in ("Working", "Complete"))
            wait_for(lambda: page.locator("[data-ai-thinking-label]").last.inner_text() == "Thinking")
            assert page.locator("[data-ai-reasoning-text], [data-ai-steps]").count() == 0
            assert page.locator("[data-ai-answer]").last.is_hidden()
            assert page.locator("[data-ai-status]").last.is_hidden()
            if shots and width == 1440:
                page.screenshot(path=os.path.join(shots, "chat-streaming.png"))
            wait_for(lambda: page.locator("[data-ai-status]").last.inner_text().strip() == "Complete")
            wait_for(lambda: page.locator("[data-ai-answer]").last.locator("a.ai-cite").count() >= 1)
            if shots:
                page.locator("[data-chat-history-toggle]").click()
                page.wait_for_timeout(300)
                page.screenshot(path=os.path.join(shots, f"chat-history-{width}.png"))
                page.locator("[data-chat-history-toggle]").click()
            assert "Private · " in page.locator("[data-ai-route]").last.inner_text() or "External · " in page.locator("[data-ai-route]").last.inner_text()
            assert page.locator("[data-ai-thinking]").last.is_hidden()
            answer = page.locator("[data-ai-answer]").last
            assert answer.is_visible() and page.locator("[data-ai-status]").last.is_hidden()
            assert "Renew the certificate" in answer.inner_text() and answer.locator("strong").count() == 1
            assert answer.locator("img, script").count() == 0 and page.evaluate("typeof window.__xss") == "undefined"
            assert answer.locator("a.ai-cite").count() == 1
            assert seen == [False]  # chat replies never request a long reasoning pass
            if shots:
                page.screenshot(path=os.path.join(shots, f"chat-complete-{width}.png"))
            assert not axe_violations(page)
            assert page.evaluate("document.documentElement.scrollWidth") <= width + 1
            # Moving to another page keeps the chat open, with its messages and any half-typed text.
            page.locator("#ai-chat-input").fill("still typing")
            page.goto(base + "/tickets", wait_until="domcontentloaded")
            assert page.locator("[data-chat]").is_visible() and page.locator("[data-chat-launch]").is_hidden()
            wait_for(lambda: page.locator(".ai-turn-user").count() == 1 and page.locator("[data-ai-answer]").count() == 1)
            assert page.locator("#ai-chat-input").input_value() == "still typing"
            assert "Renew the certificate" in page.locator("[data-ai-answer]").last.inner_text()
            page.locator("#ai-chat-input").fill("")
            # History lists the conversation; deleting it needs a confirming second press.
            page.locator("[data-chat-history-toggle]").click()
            wait_for(lambda: page.locator(".ai-history-open").count() == 1)
            page.get_by_role("button", name="Delete conversation", exact=False).click()
            page.get_by_role("button", name="Confirm deleting conversation", exact=False).click()
            wait_for(lambda: page.locator(".ai-history-open").count() == 0)
            page.locator("[data-chat-new]").click()
            assert page.locator(".ai-turn").count() == 0
            page.keyboard.press("Escape")
            wait_for(lambda: launcher.is_visible())
            assert page.evaluate("document.activeElement.hasAttribute('data-chat-launch')")
            assert not problems, problems
            browser.close()
    finally:
        stop_worker.set()


def test_full_page_chat_and_stop(ai_browser_server, monkeypatch):
    from playwright.sync_api import sync_playwright
    app, base, _ = ai_browser_server
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", ENDPOINT)
    enable_ai(app)
    clear_chats(app)

    def slow_stream(config, messages, on_delta, thinking=None):
        for _ in range(40):
            time.sleep(0.4)
            if on_delta("content", "Working on it. ") is False:
                raise provider.StreamCancelled()
        return "done", "", {}

    monkeypatch.setattr(service, "generate_stream", slow_stream)
    stop_worker = threading.Event()

    def keep_working():
        with app.app_context():
            while not stop_worker.is_set():
                if not service.process_one():
                    time.sleep(0.2)
    threading.Thread(target=keep_working, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
            sign_in(page, base)
            page.goto(base + "/ai/chat", wait_until="networkidle")
            assert page.locator("[data-chat-launch]").count() == 0
            assert page.get_by_role("heading", name="How can I help you today?").is_visible()
            assert page.locator("[data-chat-suggest]").count() == 0
            assert not axe_violations(page)
            page.get_by_label("Your question").fill("I want to report a problem")
            page.get_by_role("button", name="Send").click()
            wait_for(lambda: "Working on it" in page.inner_text("[data-chat-log]"))
            page.locator("[data-chat-stop]").click()
            wait_for(lambda: page.locator("[data-chat-send]").is_enabled(), timeout=20)
            assert "Stopped" in page.inner_text("[data-chat-log]")
            browser.close()
    finally:
        stop_worker.set()


def test_admin_adds_a_service_tests_the_privacy_rules_and_removes_it_in_the_browser(ai_browser_server, monkeypatch):
    """Add a service from a preset with automatic model detection, check the sensitive-data tester, remove it."""
    from playwright.sync_api import sync_playwright
    from tests.test_ai_providers import Server
    app, base, _ = ai_browser_server
    with app.app_context():
        from app import AIConnection
        AIConnection.query.delete()
        db.session.commit()
    model_server = Server(get_body={"data": [{"id": "models/text-embedding-004"}, {"id": "Qwen/Qwen3-8B-GGUF:Q4_K_M", "meta": {"n_ctx": 4096}}, {"id": "qwen3-4b"}, {"id": "qwen3-latest"}]})
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", model_server.origin)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            for size in ({"width": 1280, "height": 1000}, {"width": 390, "height": 844}):
                page = browser.new_context(viewport=size, reduced_motion="reduce").new_page()
                problems = []
                page.on("console", lambda m: problems.append(m.text) if "Content Security Policy" in m.text else None)
                sign_in(page, base)
                page.goto(base + "/admin/ai", wait_until="networkidle")
                assert not axe_violations(page)
                page.get_by_role("button", name="Add an AI service").click()
                if os.getenv("AI_SCREENSHOT_DIR"):
                    page.screenshot(path=os.path.join(os.getenv("AI_SCREENSHOT_DIR"), f"ai-admin-picker-{size['width']}.png"))
                page.locator('[data-ai-preset^="self_hosted|http://HOST:8080"]').click()
                page.locator('[data-ai-f="endpoint"]').fill(model_server.origin)
                page.locator('[data-ai-f="api_key"]').fill("typed-key-123")
                page.get_by_role("button", name="Connect and find models").click()
                wait_for(lambda: "Connected" in page.inner_text("[data-ai-detect-status]"))
                assert page.locator('[data-ai-f="model"]').input_value() == "qwen3-latest"
                # Every model is listed and searchable, not only the ones matching what is already typed.
                page.locator('[data-ai-f="model"]').click()
                assert page.locator(".aiadm-model-item").count() == 4
                page.locator('[data-ai-f="model"]').select_text()
                page.keyboard.type("4b")
                assert page.locator(".aiadm-model-item").count() == 1
                page.keyboard.press("ArrowDown")
                page.keyboard.press("Enter")
                assert page.locator('[data-ai-f="model"]').input_value() == "qwen3-4b"
                page.locator('[data-ai-f="model"]').click()
                page.locator(".aiadm-model-item", has_text="Qwen3-8B").click()
                assert page.locator('[data-ai-f="model"]').input_value() == "Qwen/Qwen3-8B-GGUF:Q4_K_M"
                assert not axe_violations(page)
                if os.getenv("AI_SCREENSHOT_DIR"):
                    page.screenshot(path=os.path.join(os.getenv("AI_SCREENSHOT_DIR"), f"ai-admin-dialog-{size['width']}.png"))
                page.get_by_text("Provider allowance (optional)").click()
                page.locator('[data-ai-f="rpd"]').fill("10")
                page.locator('[data-ai-f="rpm"]').fill("2")
                assert page.locator("[data-ai-use-preset]").is_hidden()  # no published free tier for a server on your network
                page.get_by_role("button", name="Save service").click()
                wait_for(lambda: page.locator(".aiadm-card").count() == 1 and "llama.cpp" in page.locator(".aiadm-card").inner_text())
                assert "Private" in page.locator(".aiadm-card").inner_text()
                assert "Today: 0 of 10" in page.locator(".aiadm-card").inner_text() and "This minute: 0 of 2" in page.locator(".aiadm-card").inner_text()
                # The privacy tester uses the real rules.
                page.locator("[data-ai-try]").click()
                page.keyboard.type("Please email anna@corp.example about her VPN")
                wait_for(lambda: "Stays on your own AI" in page.inner_text("[data-ai-verdict]"))
                page.locator("[data-ai-try]").fill("")
                page.keyboard.type("VPN drops after roaming")
                wait_for(lambda: "Not sensitive" in page.inner_text("[data-ai-verdict]"))
                assert page.evaluate("document.documentElement.scrollWidth") <= size["width"] + 1
                assert not axe_violations(page)
                if os.getenv("AI_SCREENSHOT_DIR"):
                    page.screenshot(path=os.path.join(os.getenv("AI_SCREENSHOT_DIR"), f"ai-admin-{size['width']}.png"), full_page=True)
                page.locator(".aiadm-card").get_by_role("button", name="Remove").first.click()
                page.locator(".aiadm-card").get_by_role("button", name="Confirm removing").first.click()
                wait_for(lambda: page.locator(".aiadm-card").count() == 0)
                assert not problems, problems
            browser.close()
    finally:
        model_server.close()


def test_chat_shows_a_ticket_draft_follow_up_chips_and_memory_in_the_browser(ai_browser_server, monkeypatch):
    from playwright.sync_api import sync_playwright
    app, base, _ = ai_browser_server
    monkeypatch.setenv("AI_SELF_HOSTED_ENDPOINTS", ENDPOINT)
    enable_ai(app)
    clear_chats(app)
    with app.app_context():
        from app import AIMemory
        AIMemory.query.delete()
        db.session.commit()
    answers = iter([
        ('I have prepared a draft for you.\n[[TICKET]] {"kind":"incident","title":"Email not sending","description":"Outlook cannot send",'
         '"impact":"Medium","urgency":"High","category":"Software"}\n[[FOLLOWUPS]] Is anyone else affected? | Show email articles | Any freezes?'),
        "Two people are affected [S1].\n[[FOLLOWUPS]] Anything else?"])

    def stream(config, messages, on_delta, thinking=None):
        text = next(answers)
        on_delta("content", text)
        return text, "", {}

    monkeypatch.setattr(service, "generate_stream", stream)
    stop_worker = threading.Event()

    def keep_working():
        with app.app_context():
            while not stop_worker.is_set():
                if not service.process_one():
                    time.sleep(0.2)
    threading.Thread(target=keep_working, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
            problems = []
            page.on("console", lambda m: problems.append(m.text) if "Content Security Policy" in m.text else None)
            sign_in(page, base)
            page.goto(base + "/ai/chat", wait_until="networkidle")
            page.locator("#ai-chat-input").click()
            page.keyboard.type("my email will not send, please raise a ticket")
            page.keyboard.press("Enter")
            wait_for(lambda: page.locator(".ai-draft").count() == 1)
            assert "[[" not in page.inner_text("[data-chat-log]")
            link = page.get_by_role("link", name="Review and create")
            assert link.get_attribute("href").startswith("/tickets/new/incident?") and "Email not sending" in page.locator(".ai-draft").inner_text()
            assert page.locator(".ai-suggest-chip:not(.ai-page-chip)").count() == 3
            bad = axe_violations(page)
            if bad:
                print("AXE", axe_details(page))
            assert not bad
            page.locator(".ai-suggest-chip:not(.ai-page-chip)").first.click()  # a follow-up question is sent like typed text
            wait_for(lambda: "Two people are affected" in page.inner_text("[data-chat-log]"))
            # Memory: ask it to remember, then see and remove the note.
            page.locator("#ai-chat-input").click()
            page.keyboard.type("Remember that I prefer short answers")
            page.keyboard.press("Enter")
            wait_for(lambda: "I'll remember that" in page.inner_text("[data-chat-log]"))
            page.get_by_role("button", name="Memory").click()
            wait_for(lambda: "I prefer short answers" in page.inner_text("[data-chat-memory-list]"))
            assert not axe_violations(page)
            page.get_by_role("button", name="Remove note").click()
            wait_for(lambda: page.locator("[data-chat-memory-list] li").count() == 0)
            assert not problems, problems
            browser.close()
    finally:
        stop_worker.set()
