"""Declarative role/action policy for browser and future REST surfaces, plus
secret-redaction and password-hashing helpers shared by app.py."""
import json
import logging
import re
from functools import lru_cache
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "authorization.json"


# --- Secret redaction (ISO 27001 A.8.11) ------------------------------------
#
# Field names whose values must never appear in logs, error tracebacks, or
# audit `details` strings in the clear. Matched case-insensitively against
# `key=value`, `"key": "value"`, and `key: value` shaped text, plus raw
# HTTP Authorization header values.
SECRET_FIELD_PATTERN = re.compile(
    r"""(?ix)
    (
        \b(?:[a-z0-9_]*password|[a-z0-9_]*secret|[a-z0-9_]*token
           |secret_encrypted|api_key|apikey|private_key
           |ldap_bind_password|connection_string|dsn
        )\b
        \s*[:=]\s*
    )
    (?:
        "([^"]*)"          # "value"
        |'([^']*)'         # 'value'
        |(\S+)              # bareword value
    )
    """
)

AUTH_HEADER_PATTERN = re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)(\S+)")

REDACTED = "***REDACTED***"


def mask_secret(value):
    """Mask a single secret value, keeping only enough to identify it in
    support conversations (never enough to reuse it)."""
    if value is None:
        return value
    text = str(value)
    if len(text) <= 4:
        return REDACTED
    return f"{text[:2]}{REDACTED}{text[-2:]}"


def redact(text):
    """Redact secret-shaped substrings (password=..., *_secret: "...",
    Authorization: Bearer ..., etc.) out of free-form log/error text.
    Safe to call on any string, including ones with no secrets in them."""
    if text is None:
        return text
    text = str(text)

    def _replace(match):
        prefix = match.group(1)
        return f"{prefix}{REDACTED}"

    text = SECRET_FIELD_PATTERN.sub(_replace, text)
    text = AUTH_HEADER_PATTERN.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    return text


class RedactingFilter(logging.Filter):
    """A `logging.Filter` that redacts secret-shaped values out of the
    formatted log record (message plus any %-args), so any logger this is
    attached to can never leak a password/token/connection-string even if a
    call site accidentally logs a raw dict or exception containing one."""

    def filter(self, record):
        try:
            if record.args:
                record.msg = record.getMessage()
                record.args = ()
            record.msg = redact(record.msg)
        except Exception:
            # Never let redaction itself break logging.
            pass
        return True


class PolicyConfigurationError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_policy():
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyConfigurationError(
            f"Cannot load authorization policy {POLICY_PATH}: {error}"
        ) from error
    actions = policy.get("actions")
    roles = policy.get("roles")
    if not isinstance(actions, list) or not actions or len(actions) != len(set(actions)):
        raise PolicyConfigurationError("Authorization actions must be a unique non-empty list.")
    if not isinstance(roles, dict) or not roles:
        raise PolicyConfigurationError("Authorization roles must be a non-empty object.")
    action_set = set(actions)
    for role, grants in roles.items():
        if not isinstance(grants, list) or not set(grants).issubset(action_set):
            raise PolicyConfigurationError(f"Role {role} contains unknown actions.")
    return policy


# --- Password hashing: Argon2id with lazy migration off PBKDF2 -------------
#
# Werkzeug's `generate_password_hash` defaults to PBKDF2-SHA256, which is
# weaker against GPU/ASIC cracking than Argon2id (OWASP's current
# recommendation). New/changed passwords are hashed with Argon2id; existing
# PBKDF2 hashes still verify and are transparently re-hashed to Argon2id on
# next successful login (see `hash_password`/`verify_and_upgrade_password`).
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from werkzeug.security import check_password_hash as _werkzeug_check_password_hash

_ARGON2_HASHER = PasswordHasher()
ARGON2_PREFIX = "$argon2"


def hash_password(password):
    """Hash a password with Argon2id. Use for all new/changed passwords."""
    return _ARGON2_HASHER.hash(password)


def is_argon2_hash(password_hash):
    return bool(password_hash) and password_hash.startswith(ARGON2_PREFIX)


def verify_password(password_hash, password):
    """Verify a password against either an Argon2id hash or a legacy
    Werkzeug (PBKDF2/scrypt) hash, without upgrading anything. Use
    `verify_and_upgrade_password` at login time to also lazy-migrate."""
    if not password_hash:
        return False
    if is_argon2_hash(password_hash):
        try:
            return _ARGON2_HASHER.verify(password_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            return False
    return _werkzeug_check_password_hash(password_hash, password)


def verify_and_upgrade_password(password_hash, password):
    """Verify a password against whichever hash scheme is stored, and
    return `(is_valid, upgraded_hash_or_None)`. Callers should persist
    `upgraded_hash_or_None` onto the user record when it is not None -- this
    is the lazy-migration path off PBKDF2 onto Argon2id, so no bulk data
    migration or forced password reset is required."""
    if not password_hash:
        return False, None
    if is_argon2_hash(password_hash):
        try:
            valid = _ARGON2_HASHER.verify(password_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            return False, None
        if valid and _ARGON2_HASHER.check_needs_rehash(password_hash):
            return True, hash_password(password)
        return True, None
    # Legacy Werkzeug hash (PBKDF2/scrypt/plain). Verify against it, and if
    # valid, upgrade to Argon2id.
    if _werkzeug_check_password_hash(password_hash, password):
        return True, hash_password(password)
    return False, None


def role_has_action(role, action):
    policy = load_policy()
    if action not in policy["actions"]:
        raise PolicyConfigurationError(f"Unknown authorization action: {action}")
    return action in policy["roles"].get(role, ())


def validate_policy():
    load_policy()
    return True
