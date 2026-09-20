"""Regression tests for the 2026-09-20 security review.

Two defects were found by inspecting the *running* production pod rather than
the source: ENABLE_HSTS=true was set in the environment yet no HSTS header was
ever sent, because the typed setting helpers ignored the environment; and the
log redactor let a message through unredacted if it could not be formatted.
"""
import logging

from app import PlatformSetting, db, setting_bool, setting_int
from serviceops_core.security import RedactingFilter
from tests.test_app import app, client  # noqa: F401  (pytest fixtures)


def _clear(app, key):
    with app.app_context():
        PlatformSetting.query.filter_by(key=key).delete()
        db.session.commit()


def test_setting_bool_honors_the_environment_when_no_admin_override(app, monkeypatch):
    _clear(app, "ENABLE_HSTS")
    monkeypatch.setenv("ENABLE_HSTS", "true")
    with app.app_context():
        assert setting_bool("ENABLE_HSTS") is True


def test_setting_bool_falls_back_to_the_call_site_default_when_unset(app, monkeypatch):
    _clear(app, "ENABLE_HSTS")
    monkeypatch.delenv("ENABLE_HSTS", raising=False)
    with app.app_context():
        assert setting_bool("ENABLE_HSTS") is False
        assert setting_bool("ENABLE_HSTS", True) is True


def test_administrator_database_setting_still_beats_the_environment(app, monkeypatch):
    monkeypatch.setenv("ENABLE_HSTS", "true")
    with app.app_context():
        PlatformSetting.query.filter_by(key="ENABLE_HSTS").delete()
        db.session.add(PlatformSetting(key="ENABLE_HSTS", value="false", tenant_id=1))
        db.session.commit()
        assert setting_bool("ENABLE_HSTS") is False


def test_blank_environment_value_never_overrides_a_secure_default(app, monkeypatch):
    # Compose passes unset variables through as empty strings. If that counted
    # as "false" it would silently turn certificate validation off.
    _clear(app, "LDAP_VALIDATE_CERT")
    monkeypatch.setenv("LDAP_VALIDATE_CERT", "")
    with app.app_context():
        assert setting_bool("LDAP_VALIDATE_CERT", True) is True
    monkeypatch.setenv("LDAP_VALIDATE_CERT", "   ")
    with app.app_context():
        assert setting_bool("LDAP_VALIDATE_CERT", True) is True


def test_setting_int_honors_the_environment_and_ignores_blank(app, monkeypatch):
    _clear(app, "MAX_UPLOAD_MB")
    monkeypatch.setenv("MAX_UPLOAD_MB", "7")
    with app.app_context():
        assert setting_int("MAX_UPLOAD_MB", 25) == 7
    monkeypatch.setenv("MAX_UPLOAD_MB", "")
    with app.app_context():
        assert setting_int("MAX_UPLOAD_MB", 25) == 25


def test_hsts_header_is_sent_only_when_enabled(app, client, monkeypatch):
    _clear(app, "ENABLE_HSTS")
    monkeypatch.delenv("ENABLE_HSTS", raising=False)
    assert "Strict-Transport-Security" not in client.get("/login").headers
    monkeypatch.setenv("ENABLE_HSTS", "true")
    header = client.get("/login").headers.get("Strict-Transport-Security", "")
    assert "max-age=31536000" in header and "includeSubDomains" in header


def test_redacting_filter_withholds_a_message_it_cannot_inspect():
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "value=%d", ("not-a-number",), None)
    assert RedactingFilter().filter(record) is True
    assert "withheld" in record.getMessage()
    assert "not-a-number" not in record.getMessage()


def test_redacting_filter_still_redacts_normal_messages():
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "password=%s", ("hunter2-secret",), None)
    RedactingFilter().filter(record)
    assert "hunter2-secret" not in record.getMessage()
