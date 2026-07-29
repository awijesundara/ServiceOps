"""Capture reference screenshots of the running local dev ServiceOps instance
for the operations manual. Not part of the production image or test suite —
a one-off documentation tool, run manually against a local dev stack only.

Usage: python3 tools/capture_screenshots.py
Requires: pip install playwright && playwright install chromium
Requires: the local dev Compose stack running at http://127.0.0.1:8080
"""
import os
import sys
import time

from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("SERVICEOPS_URL", "http://127.0.0.1:8080")
USERNAME = os.environ.get("SERVICEOPS_ADMIN_USER", "admin")
PASSWORD = os.environ.get("SERVICEOPS_ADMIN_PASSWORD")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "screenshots")

if not PASSWORD:
    print("Set SERVICEOPS_ADMIN_PASSWORD in the environment before running this tool.")
    sys.exit(1)

PAGES = [
    ("dashboard", "/"),
    ("incidents_list", "/tickets/incident"),
    ("changes_list", "/tickets/change"),
    ("open_work", "/work/open"),
    ("my_tasks", "/work/tasks"),
    ("task_board", "/task-board"),
    ("catalog", "/catalog"),
    ("requests_list", "/requests"),
    ("cmdb", "/cmdb"),
    ("org_chart", "/org-chart"),
    ("manager_portal", "/manager/portal"),
    ("analytics", "/analytics"),
    ("approval_chains", "/approval-chains"),
    ("notifications", "/notifications"),
    ("knowledge", "/knowledge"),
    ("admin_settings", "/admin/settings"),
    ("users_roles", "/admin/users"),
    ("audit_log", "/admin/audit"),
    ("itil_admin", "/itil/administration"),
]


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        page.goto(f"{BASE_URL}/login")
        page.fill('input[name="username"]', USERNAME)
        page.fill('input[name="password"]', PASSWORD)
        page.click('button:has-text("Sign in"), button[type="submit"]')
        page.wait_for_load_state("networkidle")
        if "/login" in page.url:
            print("Login appears to have failed — check credentials.")
            sys.exit(1)

        # A couple of detail pages need a real record id resolved first.
        ticket_id = None
        page.goto(f"{BASE_URL}/tickets/incident")
        page.wait_for_load_state("networkidle")
        link = page.query_selector("table a.record-number, table td a")
        if link:
            href = link.get_attribute("href")
            if href:
                ticket_id = href

        ritm_id = None
        page.goto(f"{BASE_URL}/requests")
        page.wait_for_load_state("networkidle")
        req_link = page.query_selector("table a.record-number")
        req_href = req_link.get_attribute("href") if req_link else None

        for name, path in PAGES:
            try:
                page.goto(f"{BASE_URL}{path}", wait_until="networkidle", timeout=15000)
                time.sleep(0.3)
                page.screenshot(path=os.path.join(OUT_DIR, f"{name}.png"), full_page=True)
                print(f"captured {name}")
            except Exception as exc:
                print(f"FAILED {name}: {exc}")

        if ticket_id:
            try:
                page.goto(f"{BASE_URL}{ticket_id}", wait_until="networkidle", timeout=15000)
                time.sleep(0.3)
                page.screenshot(path=os.path.join(OUT_DIR, "incident_detail.png"), full_page=True)
                print("captured incident_detail")
            except Exception as exc:
                print(f"FAILED incident_detail: {exc}")

        if req_href:
            try:
                page.goto(f"{BASE_URL}{req_href}", wait_until="networkidle", timeout=15000)
                time.sleep(0.3)
                page.screenshot(path=os.path.join(OUT_DIR, "request_detail.png"), full_page=True)
                print("captured request_detail")
                ritm_link = page.query_selector('a[href*="/ritm/"]')
                if ritm_link:
                    ritm_href = ritm_link.get_attribute("href")
                    page.goto(f"{BASE_URL}{ritm_href}", wait_until="networkidle", timeout=15000)
                    time.sleep(0.3)
                    page.screenshot(path=os.path.join(OUT_DIR, "ritm_detail.png"), full_page=True)
                    print("captured ritm_detail")
            except Exception as exc:
                print(f"FAILED request/ritm detail: {exc}")

        browser.close()


if __name__ == "__main__":
    main()
