"""Concurrent ticket-creation stress test for a deployed ServiceOps instance.

Run from outside the container against a real running instance (Compose,
Kubernetes, or the local dev server) -- not a unit test. Logs in once as a
real user, then creates --count tickets (default 1000) across --concurrency
worker threads (default 50), reporting the same latency-percentile/
error-rate/throughput evidence shape as tools/stability_probe.py, plus a
concurrent-request-safe copy of the authenticated session per worker thread
(requests.Session is not safe to share across threads for concurrent calls).

The password is read from SERVICEOPS_STRESS_PASSWORD, never accepted as a
--password argument -- a CLI argument is visible to any other process on
the host via `ps`, which is exactly what tools/admin_recovery.py's
stdin-only password already avoids for the same reason.

Incidents have no HTTP delete route (only pre-approval changes do), so this
tool cannot clean up after itself over HTTP. Every created ticket's number is
printed at the end -- run the companion `tools/stress_test_cleanup.py`
*inside* the app container afterward to remove them from the database, the
same tombstone/hard-delete-with-FK-awareness pattern this repo already uses
for other admin data cleanup (see tools/production_cleanup.py). Never leave
synthetic load-test data in a real deployment -- see CLAUDE.md's
production-only policy.
"""
import argparse
import json
import os
import re
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


def login(base, username, password):
    session = requests.Session()
    login_page = session.get(f"{base}/login", timeout=10)
    match = re.search(r'name="_csrf_token" value="([^"]+)"', login_page.text)
    if login_page.status_code != 200 or not match:
        raise RuntimeError(f"Could not load login page (HTTP {login_page.status_code}, CSRF token missing).")
    response = session.post(
        f"{base}/login",
        data={"username": username, "password": password, "provider": "local", "_csrf_token": match.group(1)},
        timeout=10, allow_redirects=True,
    )
    if response.url.endswith("/login") or b"Invalid username or password" in response.content:
        raise RuntimeError("Login failed -- check the supplied credentials.")
    # Login rotates the session's CSRF token server-side (a fresh value is
    # issued on every successful authentication, by design) -- the token
    # scraped from the pre-login page above is already stale the moment
    # login succeeds, so a fresh authenticated page must be re-scraped for
    # the token every subsequent request actually needs to send.
    authenticated_page = session.get(f"{base}/tickets/new/incident", timeout=10)
    fresh_match = re.search(r'name="_csrf_token" value="([^"]+)"', authenticated_page.text)
    if not fresh_match:
        raise RuntimeError("Logged in, but could not find a post-login CSRF token.")
    # A copied cookie jar loses the cookie's domain attribute, which silently
    # stops requests from sending it on a plain http://host URL with no
    # scheme/domain match -- passing the raw Cookie header instead sidesteps
    # cookie-jar/domain matching entirely and is what every worker thread
    # below actually needs (one shared authenticated identity, many threads).
    cookie_header = "; ".join(f"{name}={value}" for name, value in session.cookies.get_dict().items())
    return cookie_header, fresh_match.group(1)


def create_one_ticket(base, cookie_header, csrf_token, group_id, index, timeout):
    started = time.monotonic()
    try:
        response = requests.post(
            f"{base}/tickets/new/incident",
            headers={"Cookie": cookie_header},
            data={
                "_csrf_token": csrf_token,
                "title": f"Stress test ticket {index}",
                "description": "Created by tools/stress_test.py -- safe to delete; the tool cleans these up itself.",
                "impact": "Low", "urgency": "Low", "group_id": group_id,
            },
            timeout=timeout, allow_redirects=True,
        )
        duration_ms = (time.monotonic() - started) * 1000
        ok = response.status_code == 200 and "/ticket/" in response.url
        ticket_id = None
        if ok:
            ticket_match = re.search(r"/ticket/(\d+)", response.url)
            ticket_id = int(ticket_match.group(1)) if ticket_match else None
        return ok, duration_ms, ticket_id, response.status_code
    except requests.RequestException:
        return False, (time.monotonic() - started) * 1000, None, 0


def find_first_team(base, cookie_header):
    form_page = requests.get(f"{base}/tickets/new/incident", headers={"Cookie": cookie_header}, timeout=10).text
    match = re.search(r'name="group_id"[^>]*required[^>]*>.*?<option value="(\d+)"', form_page, re.S)
    if not match:
        match = re.search(r'name="group_id"[^>]*>\s*<option value="">[^<]*</option>\s*<option value="(\d+)"', form_page, re.S)
    if not match:
        raise RuntimeError("Could not find an IT team option on the incident-creation form.")
    return match.group(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:80")
    parser.add_argument("--username", required=True)
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--group-id", default=None, help="IT team id; auto-detected from the form if omitted.")
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--max-p95-ms", type=float, default=3000)
    args = parser.parse_args()
    if not 1 <= args.count <= 100000 or not 1 <= args.concurrency <= 500:
        parser.error("count must be 1-100000 and concurrency 1-500")

    password = os.environ.get("SERVICEOPS_STRESS_PASSWORD", "")
    if not password:
        parser.error("Set SERVICEOPS_STRESS_PASSWORD -- the password is never accepted as a command-line argument.")

    base = args.url.rstrip("/")
    cookies, csrf_token = login(base, args.username, password)
    group_id = args.group_id or find_first_team(base, cookies)

    started = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(create_one_ticket, base, cookies, csrf_token, group_id, index, args.timeout)
            for index in range(args.count)
        ]
        for future in as_completed(futures):
            results.append(future.result())
    duration = time.monotonic() - started

    latencies = sorted(duration_ms for _, duration_ms, _, _ in results)
    ok_count = sum(1 for ok, _, _, _ in results if ok)
    error_count = len(results) - ok_count
    created_ticket_ids = [ticket_id for ok, _, ticket_id, _ in results if ok and ticket_id]
    p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))] if latencies else 0

    evidence = {
        "url": base, "requested": args.count, "concurrency": args.concurrency,
        "created": ok_count, "errors": error_count,
        "error_rate": round(error_count / len(results), 4) if results else 1.0,
        "p50_ms": round(statistics.median(latencies), 2) if latencies else 0,
        "p95_ms": round(p95, 2), "max_ms": round(max(latencies), 2) if latencies else 0,
        "throughput_rps": round(len(results) / duration, 2) if duration > 0 else 0,
        "wall_clock_seconds": round(duration, 2),
    }
    evidence["passed"] = evidence["error_rate"] <= args.max_error_rate and evidence["p95_ms"] <= args.max_p95_ms
    evidence["created_ticket_ids"] = created_ticket_ids
    evidence["cleanup_command"] = (
        "python -m tools.stress_test_cleanup --confirm  (run inside the app container)"
    )

    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
