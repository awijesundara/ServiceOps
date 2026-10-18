"""Secrets stay redacted in structured, escaped and formatted logging paths."""
import io
import json
import logging

import pytest

from serviceops_core.security import RedactingFilter, redact


@pytest.mark.parametrize("key", ["password", "refresh_token", "api_key", "mfa_secret_encrypted",
                                  "mfa_backup_codes_json", "session_id", "cf_authorization",
                                  "SECRET_KEY", "CLOUDFLARE_API_KEY", "DATABASE_URL", "SQLALCHEMY_DATABASE_URI",
                                  "SETTINGS_ENCRYPTION_KEY", "password_hash", "refresh_token_hash"])
@pytest.mark.parametrize("serialization", [json.dumps, repr])
def test_quoted_secret_keys_are_redacted(key, serialization):
    secret = 'private-value-with-"quote-and-\'apostrophe'
    payload = serialization({key: secret, "safe": "visible"})
    rendered = redact(payload)
    assert "private-value" not in rendered and "apostrophe" not in rendered
    assert "visible" in rendered and "REDACTED" in rendered


@pytest.mark.parametrize("scheme", ["Bearer", "Basic"])
def test_quoted_authorization_headers_are_redacted(scheme):
    assert "private-credential" not in redact(json.dumps({"Authorization": scheme + " private-credential"}))


def test_formatted_dict_log_does_not_expose_secret_values():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    logger = logging.Logger("review-redaction")
    logger.addHandler(handler)
    logger.error("Provider failure: %s", {"password": "private-credential", "safe": "visible"})
    output = stream.getvalue()
    assert "private-credential" not in output and "visible" in output


@pytest.mark.parametrize("url", ["postgresql+psycopg://user:private-credential@database.invalid/app",
                                 "redis://:private-credential@redis.invalid/0",
                                 "https://private-credential@provider.invalid/api"])
def test_connection_url_credentials_are_redacted(url):
    rendered = redact("Connection failed: " + url)
    assert "private-credential" not in rendered and "REDACTED" in rendered
