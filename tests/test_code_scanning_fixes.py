"""Regression tests for the fixes made for GitHub code-scanning alerts."""
import hashlib
import time

import pytest
from flask import Flask

from serviceops_core.ai.references import _collapse_repeated_links
from serviceops_core.client_identity import describe_device
from serviceops_core.identity import normalize_email
from serviceops_core.safe_redirect import redirect_internal, redirect_to_referrer
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
