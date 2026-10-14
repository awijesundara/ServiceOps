"""Regression tests for the fixes made for GitHub code-scanning alerts."""
import hashlib
import time

import pytest
from flask import Flask

from serviceops_core.ai.references import _collapse_repeated_links
from serviceops_core.client_identity import describe_device
from serviceops_core.identity import normalize_email
from serviceops_core.safe_redirect import redirect_internal, redirect_to_referrer
from tests.test_app import app, client  # noqa: F401
from serviceops_core.security import (
    EMAIL_PATTERN, consume_backup_code, hash_backup_code, is_argon2_hash, use_fast_password_hashing,
)


def _runs_quickly(function, *args):
    started = time.perf_counter()
    function(*args)
    return time.perf_counter() - started < 1.0


@pytest.mark.parametrize("function, payload", [
    (lambda ua: describe_device({"User-Agent": ua}), "iPad" * 60000),
    (lambda ua: describe_device({"User-Agent": ua}), "Android ; (" + " Build/" * 20000),
    (lambda ua: describe_device({"User-Agent": ua}), "Android " * 20000),
    (EMAIL_PATTERN.search, "%" * 50000),
    (normalize_email, "!@!." + "!." * 70),
    (_collapse_repeated_links, "[" * 50000),
])
def test_user_controlled_text_is_matched_in_linear_time(function, payload):
    assert _runs_quickly(function, payload)


def test_rewritten_parsers_keep_their_results():
    assert describe_device({"User-Agent": "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) Safari/604.1"}).endswith(
        "on iPadOS 17.4 · iPad")
    assert "· Pixel 8" in describe_device({
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP1A) Chrome/141.0.0.0 Mobile Safari/537.36"})
    assert EMAIL_PATTERN.search("reach jane.doe+ops@mail.example.co.uk today").group(0) == "jane.doe+ops@mail.example.co.uk"
    assert normalize_email(" Jane@Example.COM ") == "jane@example.com"
    assert normalize_email("jane@example..com") is None
    link = "[INC0001](/ticket/1)"
    assert _collapse_repeated_links(f"See {link} {link} and {link}.") == f"See {link} and {link}."


def test_backup_codes_are_argon2_single_use_and_legacy_codes_still_work():
    use_fast_password_hashing()
    stored = [hash_backup_code("ab12cd34ef"), hash_backup_code("0011223344")]
    assert all(is_argon2_hash(entry) for entry in stored)
    remaining = consume_backup_code(stored, " AB12 CD34EF ")
    assert remaining == stored[1:]
    assert consume_backup_code(remaining, "ab12cd34ef") is None
    legacy = [hashlib.sha256(b"deadbeef00").hexdigest()]
    assert consume_backup_code(legacy, "DEADBEEF00") == []
    assert consume_backup_code(legacy, "wrong") is None


@pytest.mark.parametrize("referrer, expected", [
    ("https://desk.example.org/tickets?view=mine#top", "/tickets?view=mine#top"),
    ("https://evil.example/tickets", "/fallback"),
    ("javascript:alert(1)", "/fallback"),
    (None, "/fallback"),
])
def test_referrer_redirects_stay_inside_the_application(referrer, expected):
    app = Flask(__name__)
    headers = {"Referer": referrer} if referrer else {}
    with app.test_request_context("/", base_url="https://desk.example.org", headers=headers):
        assert redirect_to_referrer("/fallback").headers["Location"] == expected


@pytest.mark.parametrize("target, expected", [
    ("/improvements/7", "/improvements/7"),
    ("//evil.example/x", "/fallback"),
    ("/\\evil.example", "/fallback"),
    ("https://evil.example", "/fallback"),
    ("", "/fallback"),
])
def test_return_paths_must_be_relative(target, expected):
    with Flask(__name__).test_request_context("/"):
        assert redirect_internal(target, "/fallback").headers["Location"] == expected


def test_installer_connection_checks_refuse_non_http_urls():
    from installer.app import test_ipfs, test_keycloak
    keycloak = test_keycloak({"keycloak_enabled": True, "keycloak_discovery_url": "file:///etc/passwd"})
    assert keycloak["ok"] is False and "http(s)" in keycloak["message"]
    ipfs = test_ipfs({"storage_mode": "ipfs", "ipfs_mode": "external", "ipfs_api_url": "ftp://node.internal"})
    assert ipfs["ok"] is False and "http(s)" in ipfs["message"]


def test_project_durations_parse_as_before_in_linear_time(app):
    from werkzeug.exceptions import BadRequest
    from serviceops_core.projects.tracking import parse_duration
    with app.test_request_context("/"):
        assert parse_duration("2h 30m") == 150
        assert parse_duration("1.5") == 90
        assert parse_duration(" 1d\t2h ") == parse_duration("1d 2h")
        for bad in ("2x", "1 2h", "h", "2h 3"):
            with pytest.raises(BadRequest):
                parse_duration(bad)
        for hostile in ("1" * 50000, "1h" + " " * 50000 + "x", "1 " * 25000):
            started = time.perf_counter()
            with pytest.raises(BadRequest):
                parse_duration(hostile)
            assert time.perf_counter() - started < 1.0


def test_rt_ids_and_html_stripping_stay_linear():
    from serviceops_core.rt_link import _HTML_TAG, parse_rt_id
    assert [parse_rt_id(v) for v in ("1234", "#1234", " # 1234 ", "12a", "")] == ["1234", "1234", "1234", None, None]
    assert _runs_quickly(parse_rt_id, " " * 50000 + "x")
    assert _HTML_TAG.sub("", "<p>Hello <b>RT</b></p>") == "Hello RT"
    assert _runs_quickly(_HTML_TAG.sub, "", "<" * 50000)


def test_project_return_paths_cannot_leave_the_application(app, client):
    from app import PlatformSetting, User, db
    from serviceops_core.projects import service
    from tests.test_app import login
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.merge(PlatformSetting(key="PROJECTS_ENABLED", value="true", tenant_id=admin.tenant_id))
        db.session.commit()
        service.create_project(User.query.filter_by(username="database.manager").one(), "SAFE", "Redirect check",
                               visibility="open")
        db.session.commit()
    login(client)
    for target, expected in (("/\\evil.example", "/projects"), ("//evil.example", "/projects"),
                             ("/projects/SAFE/board", "/projects/SAFE/board")):
        response = client.post("/projects/SAFE/star", data={"next": target})
        assert response.status_code == 302
        assert response.headers["Location"].endswith(expected), (target, response.headers["Location"])
