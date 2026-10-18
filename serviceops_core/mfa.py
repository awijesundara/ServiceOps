"""Second-factor checks shared by the web sign-in (/login/mfa) and the mobile
API sign-in (ISO 27001 A.8.5).

- A TOTP code is accepted once: the accepted time step is stored on the user
  and that step or an earlier one is refused, so an observed code cannot be
  replayed while it is still within its validity window.
- A wrong code counts toward the same account lockout as a wrong password
  (LOGIN_MAX_ATTEMPTS / LOGIN_LOCKOUT_MINUTES). Rate limiting alone still let
  someone holding the password guess codes indefinitely.
"""
import json
import time
from datetime import timedelta

import pyotp

from sqlalchemy import or_

from serviceops_core.security import consume_backup_code
from serviceops_models import User, db, now, settings_cipher

TOTP_PERIOD_SECONDS = 30


def _totp_step(user, code, at=None):
    """The time step `code` is valid for (current step +/- 1) and not yet
    used, or None."""
    if not user.mfa_secret_encrypted:
        return None
    code = code.replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(settings_cipher().decrypt(user.mfa_secret_encrypted.encode()).decode())
    current = int((time.time() if at is None else at) // TOTP_PERIOD_SECONDS)
    for step in (current - 1, current, current + 1):
        if user.mfa_last_totp_step is not None and step <= user.mfa_last_totp_step:
            continue
        if totp.verify(code, for_time=step * TOTP_PERIOD_SECONDS):
            return step
    return None


def _claim_step(user, step):
    """Record `step` as used only if no request has used it or a later one:
    a conditional UPDATE, so two simultaneous sign-ins with the same code
    cannot both succeed (the second waits on the row lock, then matches no
    row)."""
    claimed = User.query.filter(
        User.id == user.id,
        or_(User.mfa_last_totp_step.is_(None), User.mfa_last_totp_step < step),
    ).update({User.mfa_last_totp_step: step}, synchronize_session=False)
    if claimed:
        db.session.expire(user, ["mfa_last_totp_step"])
    return bool(claimed)


def verify_second_factor(user, code, at=None):
    """`(verified, backup_used)` for a TOTP or backup code. A user without MFA
    passes. On success the caller commits: the TOTP step or the consumed
    backup code is recorded on `user`."""
    if not user.mfa_enabled:
        return True, False
    code = str(code or "").strip()
    if not code:
        return False, False
    step = _totp_step(user, code, at)
    if step is not None and _claim_step(user, step):
        return True, False
    for _ in range(3):
        original = user.mfa_backup_codes_json
        if not original:
            return False, False
        remaining = consume_backup_code(json.loads(original), code)
        if remaining is None:
            return False, False
        # The JSON predicate makes code consumption single-use even when
        # another request loaded the same code list before this commit.
        claimed = User.query.filter(
            User.id == user.id, User.mfa_backup_codes_json == original,
        ).update({User.mfa_backup_codes_json: json.dumps(remaining)}, synchronize_session=False)
        db.session.expire(user, ["mfa_backup_codes_json"])
        if claimed:
            return True, True
    from flask import current_app
    current_app.logger.warning("MFA backup code update contention for user %s", user.id)
    return False, False


def account_locked(user):
    from app import align_tz
    return bool(user.locked_until and align_tz(user.locked_until, now()) > now())


def record_second_factor_failure(user, channel):
    """Count a wrong second-factor code toward the account lockout and audit
    it. Returns True when this failure locked the account. The caller
    commits."""
    from app import audit, setting_int
    user.failed_login_count = (user.failed_login_count or 0) + 1
    maximum = setting_int("LOGIN_MAX_ATTEMPTS", 5)
    if user.failed_login_count >= maximum:
        user.failed_login_count = 0
        user.locked_until = now() + timedelta(minutes=setting_int("LOGIN_LOCKOUT_MINUTES", 15))
        audit("login_locked", user.username, f"provider={channel}; reason=invalid_mfa_code; attempts={maximum}",
              user_id=user.id, tenant_id=user.tenant_id)
        return True
    audit("login_failed", user.username,
          f"provider={channel}; reason=invalid_mfa_code; attempts={user.failed_login_count}",
          user_id=user.id, tenant_id=user.tenant_id)
    return False
