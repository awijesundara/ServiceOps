"""Authenticated, mixed-workload load/stability gate for a deployed
ServiceOps instance -- extends tools/stability_probe.py's unauthenticated
single-URL /health check (B-071's original evidence) to real authenticated
sessions hitting a realistic mix of endpoints, which is what B-071's
"remains" note asks for.

Each simulated user logs in for real (a real session cookie, not a
bypass), then repeatedly picks a random endpoint from the configured mix
and measures its latency, so results reflect the query-planner/index
behavior of whatever dataset the target actually has -- run this against a
disposable instance seeded via tools/seed_load_test_dataset.py for
production-volume evidence, never against a real production database with
real user accounts.
"""
import argparse
import json
import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# Deliberately only endpoints every role (including "requester", the most
# common role in a real deployment) can reach -- /cmdb and other agent+
# pages correctly 403 for a requester, which would inflate the error rate
# with expected, correct authorization responses rather than real failures
# if included here without role-matched accounts. Pass --endpoints to test
# a role-restricted mix against an all-agent/all-admin --username pool.
DEFAULT_ENDPOINTS = ["/", "/workspace", "/tickets/incident", "/requests", "/knowledge"]


def login_session(base_url, username, password, timeout):
    session = requests.Session()
    login_page = session.get(f"{base_url}/login", timeout=timeout)
    start = login_page.text.find('name="_csrf_token" value="')
    if start == -1:
        raise RuntimeError("Could not find CSRF token on login page -- login markup may have changed.")
    start += len('name="_csrf_token" value="')
    token = login_page.text[start:login_page.text.find('"', start)]
    response = session.post(
        f"{base_url}/login",
        data={"username": username, "password": password, "_csrf_token": token},
        timeout=timeout,
    )
    if "/login" in response.url:
        raise RuntimeError(f"Login failed for {username} -- check credentials.")
    return session


def one_request(session, base_url, path, timeout):
    started = time.monotonic()
    try:
        response = session.get(f"{base_url}{path}", timeout=timeout)
        return path, response.status_code, (time.monotonic() - started) * 1000
    except requests.RequestException:
        return path, 0, (time.monotonic() - started) * 1000


def worker(base_url, username, password, requests_per_user, endpoints, timeout):
    session = login_session(base_url, username, password, timeout)
    return [
        one_request(session, base_url, random.choice(endpoints), timeout)
        for _ in range(requests_per_user)
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:80")
    parser.add_argument(
        "--username", default="admin",
        help="Either one username, or a pattern with {n} (e.g. loadtest.user{n}) rotated 0..concurrent-users-1 "
             "so each simulated user logs in as a distinct account -- a shared account across many concurrent "
             "logins trips this app's real per-account login rate limit, which is correct security behavior, "
             "not a bug, but makes a single shared identity unusable for concurrency above that limit.",
    )
    parser.add_argument("--password", required=True)
    parser.add_argument("--concurrent-users", type=int, default=20)
    parser.add_argument("--requests-per-user", type=int, default=25)
    parser.add_argument("--endpoints", nargs="+", default=DEFAULT_ENDPOINTS)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--max-p95-ms", type=float, default=1500)
    args = parser.parse_args()
    if not 1 <= args.concurrent_users <= 500 or not 1 <= args.requests_per_user <= 10000:
        parser.error("concurrent-users must be 1-500 and requests-per-user 1-10000")

    usernames = (
        [args.username.format(n=n) for n in range(args.concurrent_users)]
        if "{n}" in args.username else [args.username] * args.concurrent_users
    )

    started = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=args.concurrent_users) as executor:
        futures = [
            executor.submit(
                worker, args.url, username, args.password,
                args.requests_per_user, args.endpoints, args.timeout,
            )
            for username in usernames
        ]
        for future in as_completed(futures):
            results.extend(future.result())
    duration = time.monotonic() - started

    by_endpoint = {}
    for path, status, latency in results:
        by_endpoint.setdefault(path, []).append((status, latency))

    per_endpoint_evidence = {}
    for path, rows in by_endpoint.items():
        latencies = sorted(latency for _, latency in rows)
        errors = sum(status < 200 or status >= 400 for status, _ in rows)
        p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
        per_endpoint_evidence[path] = {
            "requests": len(rows), "errors": errors, "error_rate": round(errors / len(rows), 4),
            "p50_ms": round(statistics.median(latencies), 2), "p95_ms": round(p95, 2),
            "max_ms": round(max(latencies), 2),
        }

    total_errors = sum(status < 200 or status >= 400 for _, status, _ in results)
    overall_p95 = sorted(latency for _, _, latency in results)
    overall_p95 = overall_p95[min(len(overall_p95) - 1, int(len(overall_p95) * 0.95))]
    evidence = {
        "url": args.url, "concurrent_users": args.concurrent_users,
        "requests_per_user": args.requests_per_user, "total_requests": len(results),
        "total_errors": total_errors, "error_rate": round(total_errors / len(results), 4),
        "overall_p95_ms": round(overall_p95, 2),
        "throughput_rps": round(len(results) / duration, 2),
        "duration_s": round(duration, 2), "per_endpoint": per_endpoint_evidence,
        "passed": (total_errors / len(results) <= args.max_error_rate) and (overall_p95 <= args.max_p95_ms),
    }
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
