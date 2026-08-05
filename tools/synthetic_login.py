"""External end-to-end ServiceOps login probe.

Run from a monitoring host, not inside the application container. Credentials
come from SERVICEOPS_SYNTHETIC_USERNAME/PASSWORD; output is one JSON record and
the process exits non-zero on any readiness, CSRF, login, or authenticated-page
failure. The dedicated account should be an unprivileged requester.
"""
import json
import os
import re
import sys
import time

import requests


def fail(started, stage, detail):
    print(json.dumps({"ok": False, "stage": stage, "detail": detail,
                      "duration_ms": round((time.monotonic() - started) * 1000, 2)}))
    return 1


def main():
    started = time.monotonic()
    base = os.getenv("SERVICEOPS_URL", "http://localhost:80").rstrip("/")
    username = os.getenv("SERVICEOPS_SYNTHETIC_USERNAME", "")
    password = os.getenv("SERVICEOPS_SYNTHETIC_PASSWORD", "")
    if not username or not password:
        return fail(started, "configuration", "synthetic credentials are required")
    session = requests.Session()
    try:
        ready = session.get(f"{base}/ready", timeout=10)
        if ready.status_code != 200:
            return fail(started, "readiness", f"HTTP {ready.status_code}")
        login = session.get(f"{base}/login", timeout=10)
        match = re.search(r'name="_csrf_token" value="([^"]+)"', login.text)
        if login.status_code != 200 or not match:
            return fail(started, "login_page", f"HTTP {login.status_code}; CSRF token missing")
        result = session.post(
            f"{base}/login", data={"username": username, "password": password,
                                  "provider": "local", "_csrf_token": match.group(1)},
            timeout=10, allow_redirects=True,
        )
        if result.status_code != 200 or result.url.endswith("/login") or b"Invalid username or password" in result.content:
            return fail(started, "login", f"HTTP {result.status_code}")
        authenticated = session.get(f"{base}/notifications", timeout=10)
        if authenticated.status_code != 200 or authenticated.url.endswith("/login"):
            return fail(started, "authenticated_page", f"HTTP {authenticated.status_code}")
    except requests.RequestException as error:
        return fail(started, "network", type(error).__name__)
    print(json.dumps({"ok": True, "stage": "complete", "version": ready.json().get("version"),
                      "duration_ms": round((time.monotonic() - started) * 1000, 2)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
