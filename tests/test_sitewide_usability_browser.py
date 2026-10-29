"""Opt-in inventory and browser audit of all reachable HTML page families.

Uses isolated fixture records. JSON/binary/OAuth endpoints and unseeded object
states are inventoried separately instead of reported as browser coverage.
"""
import json
import os
import re
import tempfile
from datetime import timedelta
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

import app as core
from tests.test_app import app, login  # noqa: F401
from tests.test_projects_browser import _axe, server  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv("RUN_SITEWIDE_BROWSER") != "1", reason="Opt-in whole-product browser audit")


class PageLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.extend(value for key, value in attrs if key == "href" and value)


def _seed(application):
    from serviceops_core.projects import advanced_plans, automation, content, roadmap
    from serviceops_core.projects.models import Project, ProjectSprint, ProjectVersion
    from serviceops_models import MailService, Supplier, Contract, AIRun, AIAction

    with application.app_context():
        admin = core.User.query.filter_by(username="admin").one()
        admin.role = "superadmin"
        employee = core.User.query.filter_by(username="employee").one()
        group = core.SupportGroup.query.filter_by(name="CoreApps").one()
        records = [core.ConfigurationItem(name="UI audit server", ci_class="Server", tenant_id=1),
                   core.Knowledge(title="UI audit article", body="Isolated browser test content.", author_id=admin.id, tenant_id=1),
                   core.Asset(asset_tag="UI-001", name="UI audit laptop", asset_type="Laptop", owner_id=employee.id, tenant_id=1),
                   core.Rack(name="UI audit rack", u_height=42, tenant_id=1)]
        for kind, prefix in (("incident", "INC"), ("change", "CHG")):
            records.append(core.Ticket(number=prefix + "990099", kind=kind, title="UI audit " + kind,
                                       description="Isolated browser test record.", state="New", priority="P3",
                                       category="Software", requester_id=employee.id, assignee_id=admin.id, tenant_id=1))
        for domain, config in core.DOMAIN_CONFIG.items():
            records.append(core.EnterpriseRecord(number=config["prefix"] + "UI099", domain=domain,
                          record_type=config["types"][0], title="UI audit " + domain,
                          description="Isolated browser test record.", requester_id=employee.id,
                          support_group_id=group.id, tenant_id=1))
        core.db.session.add_all(records)
        core.db.session.commit()
        organization = core.ClientOrganization(name="UI audit organization", tenant_id=1)
        core.db.session.add(organization)
        core.db.session.flush()
        contact = core.ClientContact(organization_id=organization.id, name="UI audit contact", email="ui@test.invalid", tenant_id=1)
        core.db.session.add(contact)
        core.db.session.flush()
        core.db.session.add(core.ClientTicket(number="UI-990099", subject="UI audit support conversation", description="Isolated test record",
                            contact_id=contact.id, organization_id=organization.id, support_group_id=group.id, created_by_id=admin.id, tenant_id=1))
        request = core.CatalogRequest(number="REQ-UI099", requested_by_id=employee.id, requested_for_id=employee.id, tenant_id=1)
        core.db.session.add(request)
        core.db.session.flush()
        item = core.RequestedItem(number="RITM-UI099", request_id=request.id, catalog_item_id=core.CatalogItem.query.first().id, tenant_id=1)
        core.db.session.add(item)
        core.db.session.flush()
        core.db.session.add(core.CatalogTask(number="SCTASK-UI099", requested_item_id=item.id, title="UI audit fulfillment task", assignment_group_id=group.id, tenant_id=1))
        change = core.Ticket.query.filter_by(kind="change").one()
        core.db.session.add(core.OperationalTask(number="CTASK-UI099", task_kind="change", parent_type="ticket", parent_id=change.id,
                             title="UI audit change task", task_type="Implementation", assignment_group_id=group.id, tenant_id=1))
        core.db.session.add(core.ImprovementItem(number="IMP-UI099", title="UI audit improvement", created_by_id=admin.id, owner_id=admin.id, tenant_id=1))
        core.db.session.add(core.DiscoveryTarget(name="UI audit discovery", address="192.0.2.1", created_by_id=admin.id, active=False, tenant_id=1))
        mail = MailService(name="UI audit mail service", provider="smtp")
        mail.config = {"SMTP_HOST": "mail.test.invalid", "SMTP_FROM": "ui@test.invalid"}
        core.db.session.add(mail)
        supplier = Supplier(name="UI audit supplier", tenant_id=1)
        core.db.session.add(supplier)
        core.db.session.flush()
        core.db.session.add(Contract(name="UI audit contract", supplier_id=supplier.id, tenant_id=1))
        for integration in ("netbox", "snipeit"):
            core.db.session.add(core.IntegrationSyncJob(tenant_id=1, actor_user_id=admin.id, integration=integration,
                                status="Completed", phase="Complete", result_json="{}"))
        config = core.db.session.get(core.AIConfiguration, 1) or core.AIConfiguration(tenant_id=1)
        config.enabled = config.incident_enabled = config.chat_enabled = True
        core.db.session.add(config)
        incident = core.Ticket.query.filter_by(kind="incident").one()
        run = AIRun(tenant_id=1, user_id=admin.id, ticket_id=incident.id, actor_role="superadmin", config_revision=1,
                    request_key="ui-audit-completed", status="completed", provider="self_hosted", model="test-only",
                    result_text="Isolated fixture output; no provider was contacted.")
        core.db.session.add(run)
        core.db.session.flush()
        core.db.session.add(AIAction(tenant_id=1, run_id=run.id, ticket_id=incident.id, proposed_by_id=admin.id,
                            actor_role="superadmin", action_type="add_comment", payload_json='{"body":"Isolated fixture comment."}',
                            target_updated_at=incident.updated_at, expires_at=core.now() + timedelta(hours=1)))
        project = Project.query.filter_by(key="WEB").one()
        core.db.session.add(ProjectSprint(tenant_id=1, project_id=project.id, name="UI audit sprint", created_by_id=admin.id))
        core.db.session.add(ProjectVersion(tenant_id=1, project_id=project.id, name="UI audit release"))
        advanced_plans.create(admin, {"name": "UI audit plan", "projects": ["WEB"], "settings": {"start": "2026-10-29"}})
        roadmap.create_draft(admin, ["WEB"], "UI audit proposal", start="2026-10-29")
        automation.save(admin, {"name": "UI audit rule", "enabled": False, "projects": ["WEB"],
                         "config": {"trigger": "transitioned", "conditions": [], "branch": "trigger", "actions": [{"type": "comment", "body": "UI audit"}]}})
        content.save_form(admin, project, {"name": "UI audit intake", "config": {"fields": []}})
        core.db.session.commit()


def _manifest(application, output):
    from serviceops_core.itam.registry import RESOURCES
    from serviceops_core.mail import PROVIDERS
    from serviceops_core.web.administration import ITIL_ADMIN_SECTIONS, SETTING_DEFINITIONS

    rules = [rule for rule in application.url_map.iter_rules() if "GET" in rule.methods]
    excluded = re.compile(r"^/(api/|static/|auth/|scim/|events/|push/|branding/|\.well-known/)|/(export(?:\.|/|$)|poll$|stream$|mentionable-users$)|\.(json|csv|png|js|webmanifest)$")
    explicit_skip = {"/health", "/live", "/ready", "/metrics", "/ipfs-home", "/login/mfa"}

    def candidate(raw):
        parsed = urlsplit(raw)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/") or excluded.search(parsed.path) or parsed.path in explicit_skip:
            return None
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if any(key not in {"view", "section", "category", "provider", "connection"} for key, _ in query):
            return None
        return parsed.path + ("?" + urlencode(query) if query else "")

    pending = deque(rule.rule for rule in rules if not rule.arguments and candidate(rule.rule))
    pending.extend("/admin/settings/" + key for key in SETTING_DEFINITIONS)
    pending.extend("/service-operations/settings/" + key for key in ITIL_ADMIN_SECTIONS)
    pending.extend("/admin/email/new/" + key for key in PROVIDERS)
    for kind in RESOURCES:
        pending.extend((f"/itam/{kind}", f"/itam/{kind}/new"))
    for domain in core.DOMAIN_CONFIG:
        pending.extend((f"/module/{domain}", f"/module/{domain}/new"))
    for kind in ("incident", "change"):
        pending.extend((f"/tickets/{kind}", f"/tickets/new/{kind}"))
    pending.append("/tickets/all")
    pending.extend(("/projects/WEB/board", "/projects/WEB/list", "/projects/WEB/overview", "/work-items/WEB-2"))
    with application.app_context():
        from serviceops_core.projects.models import ProjectPlanningDraft, ProjectAutomationRule, ProjectPlan, ProjectSprint, ProjectVersion, ProjectForm
        from serviceops_models import MailService, Supplier, Contract, AIRun, AIAction
        for model, route in ((core.Ticket, "/ticket/{}"), (core.EnterpriseRecord, "/enterprise/{}"),
                             (core.Knowledge, "/knowledge/{}"), (core.ConfigurationItem, "/cmdb/{}/edit"),
                             (core.Rack, "/cmdb/racks/{}"), (core.User, "/people/{}"),
                             (core.ClientTicket, "/client-management/tickets/{}"), (core.ClientOrganization, "/client-management/organizations/{}"),
                             (core.CatalogRequest, "/request/{}"), (core.RequestedItem, "/ritm/{}"), (core.CatalogTask, "/catalog-task/{}"),
                             (core.OperationalTask, "/operational-task/{}"), (core.ImprovementItem, "/improvement/{}"),
                             (core.DiscoveryTarget, "/cmdb/discovery/{}/review"), (MailService, "/admin/email/{}"),
                             (ProjectPlanningDraft, "/projects/planning/drafts/{}"), (ProjectAutomationRule, "/projects/automation/{}"),
                             (ProjectSprint, "/projects/WEB/sprints/{}/report"), (ProjectVersion, "/projects/WEB/releases/{}"),
                             (ProjectForm, "/projects/WEB/forms/{}/submit")):
            pending.extend(route.format(row.id) for row in model.query.all())
        for model, route in ((Supplier, "/itam/suppliers/{}"), (Contract, "/itam/contracts/{}"),
                             (AIRun, "/ai/runs/{}"), (AIAction, "/ai/actions/{}")):
            pending.extend(route.format(row.id) for row in model.query.all())
        pending.extend(f"/cmdb/import/{row.integration}/jobs/{row.id}" for row in core.IntegrationSyncJob.query.all())
        pending.extend(f"/cmdb/racks/{row.id}/embed" for row in core.Rack.query.all())
        for plan in ProjectPlan.query.all():
            pending.extend(f"/projects/plans/{plan.id}/{view}" for view in ("timeline", "structure", "program", "teams", "releases", "dependencies", "settings"))
        pending.extend(f"/incidents/{row.id}/ai" for row in core.Ticket.query.filter_by(kind="incident"))
        pending.extend(f"/status/{row.slug}" for row in core.Tenant.query.all())
    visited = {}
    with application.test_client() as client:
        login(client)
        while pending:
            route = candidate(pending.popleft())
            if not route or route in visited:
                continue
            assert len(visited) < 1000, "Unexpected unbounded page traversal"
            try:
                response = client.get(route)
            except Exception as error:
                visited[route] = {"status": 500, "error": type(error).__name__}
                continue
            visited[route] = {"status": response.status_code, "html": response.mimetype == "text/html"}
            if response.status_code == 302:
                target = candidate(response.location)
                if target:
                    pending.append(target)
            if response.status_code != 200 or response.mimetype != "text/html":
                continue
            parser = PageLinks()
            parser.feed(response.get_data(as_text=True))
            pending.extend(parser.links)
    inventory = []
    adapter = application.url_map.bind("localhost")
    covered = set()
    for route, result in visited.items():
        if result["status"] == 200 and result.get("html"):
            endpoint, _ = adapter.match(urlsplit(route).path, method="GET")
            covered.add(endpoint)
    for rule in rules:
        inventory.append({"rule": rule.rule, "endpoint": rule.endpoint,
                          "coverage": "HTML page checked" if rule.endpoint in covered else
                          "non-page or external authentication" if excluded.search(rule.rule) or rule.rule in explicit_skip else
                          "requires record state, feature configuration, or is a redirect"})
    (output / "route-inventory.json").write_text(json.dumps({"routes": inventory, "requests": visited}, indent=2))
    return [route for route, result in visited.items() if result["status"] == 200 and result.get("html")], visited


def test_all_reachable_pages(server):
    from playwright.sync_api import sync_playwright

    application, base = server
    output = Path(os.getenv("SITEWIDE_AUDIT_DIR", str(Path(tempfile.gettempdir()) / "serviceops-sitewide-ui")))
    output.mkdir(parents=True, exist_ok=True)
    _seed(application)
    routes, requests = _manifest(application, output)
    if os.getenv("SITEWIDE_INVENTORY_ONLY") == "1":
        return
    failures = [{"route": route, **result} for route, result in requests.items() if result["status"] >= 500]
    results = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        layouts = ((1440, "light"), (390, "light"), (1280, "dark"), (390, "dark"))
        only = os.getenv("SITEWIDE_LAYOUTS")  # e.g. "1440-light,390-light"
        if only:
            layouts = tuple(layout for layout in layouts if f"{layout[0]}-{layout[1]}" in only.split(","))
        for width, theme in layouts:
            with application.app_context():
                admin = core.User.query.filter_by(username="admin").one()
                pref = core.UserPreference.query.filter_by(user_id=admin.id).first() or core.UserPreference(user_id=admin.id)
                pref.theme = theme
                core.db.session.add(pref)
                core.db.session.commit()
            page = browser.new_page(viewport={"width": width, "height": 1000}, has_touch=width < 1000, reduced_motion="reduce")
            page.goto(base + "/login", wait_until="load")
            page.fill('[name="username"]', "admin")
            page.fill('[name="password"]', "Admin123!")
            page.get_by_role("button", name="Sign in", exact=True).click()
            page.wait_for_url(base + "/")
            page.wait_for_load_state("load")
            for route in routes:
                errors = []
                listener = lambda error: errors.append(str(error))
                page.on("pageerror", listener)
                response = page.goto(base + route, wait_until="load")
                page.evaluate("document.fonts.ready")
                geometry = page.evaluate("""() => ({overflow:document.documentElement.scrollWidth-innerWidth,
                  clipped:[...document.querySelectorAll('main form')].filter(e=>e.checkVisibility()&&getComputedStyle(e).overflowY==='hidden'&&e.scrollHeight>e.clientHeight+1).map(e=>e.className)})""")
                violations = _axe(page)
                result = {"route": route, "width": width, "theme": theme, "status": response.status,
                          "geometry": geometry, "axe": violations, "errors": errors}
                results.append(result)
                failed = response.status >= 400 or geometry["overflow"] > 1 or geometry["clipped"] or violations or errors
                if failed:
                    failures.append(result)
                if failed or os.getenv("SITEWIDE_SCREENSHOT_ALL") == "1":
                    slug = re.sub(r"[^a-zA-Z0-9_-]", "-", route)[:150]
                    page.screenshot(path=str(output / f"{width}-{theme}-{slug}.png"), full_page=True)
                page.remove_listener("pageerror", listener)
                (output / "browser-audit.json").write_text(json.dumps(results, indent=2))
            page.close()
        browser.close()
    (output / "failures.json").write_text(json.dumps(failures, indent=2))
    assert not failures, json.dumps(failures, indent=2)


def test_account_and_role_pages(server):
    import hashlib
    import hmac
    import secrets
    from serviceops_models import PasswordResetToken
    from playwright.sync_api import sync_playwright

    application, base = server
    output = Path(os.getenv("SITEWIDE_AUDIT_DIR", str(Path(tempfile.gettempdir()) / "serviceops-sitewide-ui")))
    output.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    with application.app_context():
        employee = core.User.query.filter_by(username="employee").one()
        core.db.session.add(PasswordResetToken(
            token_hash=hmac.new(application.config["SECRET_KEY"].encode(), token.encode(), hashlib.sha256).hexdigest(),
            user_id=employee.id, tenant_id=employee.tenant_id, expires_at=core.now() + timedelta(minutes=30)))
        core.db.session.commit()
    results = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for width in (1440, 390):
            page = browser.new_page(viewport={"width": width, "height": 1000}, reduced_motion="reduce", has_touch=width < 1000)
            for route in ("/login", "/forgot-password", "/reset-password/" + token):
                response = page.goto(base + route, wait_until="load")
                assert response.status == 200
                violations = _axe(page)
                overflow = page.evaluate("document.documentElement.scrollWidth-innerWidth")
                results.append({"role": "anonymous", "route": "/reset-password/<isolated-token>" if token in route else route,
                                "width": width, "axe": violations, "overflow": overflow})
                assert not violations and overflow <= 1, results[-1]
            page.close()
        for username, password in (("employee", "Employee123!"), ("database.manager", "Manager123!")):
            for width, theme in ((1440, "light"), (390, "dark")):
                with application.app_context():
                    user = core.User.query.filter_by(username=username).one()
                    pref = core.UserPreference.query.filter_by(user_id=user.id).first() or core.UserPreference(user_id=user.id)
                    pref.theme = theme
                    core.db.session.add(pref)
                    core.db.session.commit()
                page = browser.new_page(viewport={"width": width, "height": 1000}, reduced_motion="reduce", has_touch=width < 1000)
                page.goto(base + "/login")
                page.fill('[name="username"]', username)
                page.fill('[name="password"]', password)
                page.get_by_role("button", name="Sign in", exact=True).click()
                page.wait_for_load_state("networkidle")
                routes = ["/", "/profile", "/profile/password", "/profile/sessions", "/notifications", "/preferences",
                          "/preferences#lists", "/preferences#forms", "/preferences#notifications", "/catalog", "/requests",
                          "/approvals", "/service-status", "/knowledge", "/help", "/mobile-app"]
                if username == "database.manager":
                    routes += ["/manager/portal", "/analytics", "/work/open", "/work/tasks"]
                for route in routes:
                    response = page.goto(base + route, wait_until="load")
                    assert response is None or response.status == 200, (username, route, response.status)
                    if "#" in route:
                        page.locator('[data-pref-panel="' + route.split("#")[1] + '"]').wait_for(state="visible")
                    violations = _axe(page)
                    overflow = page.evaluate("document.documentElement.scrollWidth-innerWidth")
                    result = {"role": username, "route": route, "width": width, "theme": theme, "axe": violations, "overflow": overflow}
                    results.append(result)
                    (output / "account-role-audit.json").write_text(json.dumps(results, indent=2))
                    assert not violations and overflow <= 1, result
                page.close()
        browser.close()


def test_mfa_challenge_page(server):
    from playwright.sync_api import sync_playwright

    application, base = server
    with application.app_context():
        admin = core.User.query.filter_by(username="admin").one()
        admin.mfa_enabled = True
        admin.mfa_secret_encrypted = core.settings_cipher().encrypt(b"JBSWY3DPEHPK3PXP").decode()
        core.db.session.commit()
    results = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for width in (1440, 390):
            page = browser.new_page(viewport={"width": width, "height": 1000}, reduced_motion="reduce", has_touch=width < 1000)
            page.goto(base + "/login")
            page.fill('[name="username"]', "admin")
            page.fill('[name="password"]', "Admin123!")
            page.get_by_role("button", name="Sign in", exact=True).click()
            page.wait_for_url("**/login/mfa")
            violations = _axe(page)
            overflow = page.evaluate("document.documentElement.scrollWidth-innerWidth")
            results.append({"route": "/login/mfa", "width": width, "axe": violations, "overflow": overflow})
            assert not violations and overflow <= 1, results[-1]
            page.close()
        browser.close()
    output = Path(os.getenv("SITEWIDE_AUDIT_DIR", str(Path(tempfile.gettempdir()) / "serviceops-sitewide-ui")))
    output.mkdir(parents=True, exist_ok=True)
    (output / "mfa-audit.json").write_text(json.dumps(results, indent=2))
