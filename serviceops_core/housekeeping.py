"""Periodic removal of short-lived rows that nothing else deletes.

Rate-limit windows are pruned only when the same key is seen again, so a key
used once (a mistyped or made-up username, a one-off address) stayed forever;
session inventory rows were never removed. The worker calls
purge_expired_rows() on every pass; it does its work at most once an hour.
"""
import time
from datetime import timedelta

from flask import current_app

from serviceops_models import APIRateLimitWindow, RouteRateLimitWindow, UserSession, db, now

PURGE_INTERVAL_SECONDS = 3600
# The longest rate-limit window is one hour (password recovery).
RATE_LIMIT_RETENTION = timedelta(hours=2)
SESSION_RETENTION = timedelta(days=90)

_last_run = [None]


def purge_expired_rows(force=False):
    """Returns the number of rows removed (0 when it is not due yet)."""
    if not force and _last_run[0] is not None and time.monotonic() - _last_run[0] < PURGE_INTERVAL_SECONDS:
        return 0
    _last_run[0] = time.monotonic()
    try:
        window_cutoff = now() - RATE_LIMIT_RETENTION
        removed = RouteRateLimitWindow.query.filter(
            RouteRateLimitWindow.window_start < window_cutoff).delete(synchronize_session=False)
        removed += APIRateLimitWindow.query.filter(
            APIRateLimitWindow.window_start < window_cutoff).delete(synchronize_session=False)
        # A session row is kept well past the life of its cookie, so the
        # sign-in history stays reviewable and a deleted row can never be
        # re-created by a cookie that is still valid.
        lifetime = current_app.config.get("PERMANENT_SESSION_LIFETIME") or timedelta(0)
        session_cutoff = now() - max(SESSION_RETENTION, 2 * lifetime)
        removed += UserSession.query.filter(
            UserSession.expires_at < session_cutoff).delete(synchronize_session=False)
        db.session.commit()
        return removed
    except Exception:  # noqa: BLE001 - never stop the worker loop
        db.session.rollback()
        current_app.logger.exception("Expired-row purge failed")
        return 0
