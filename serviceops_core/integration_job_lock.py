"""Exclusive reconciliation ownership, released automatically on process loss.

PostgreSQL session advisory locks span the runner's transaction commits. SQLite
and the single-process IPFS projection use a process lock. A Running row with no
owner is terminalized rather than automatically replaying an ambiguous write.
"""
from contextlib import contextmanager
import hashlib
import logging
import threading

from sqlalchemy import text

logger = logging.getLogger(__name__)
_guard = threading.Lock()
_locks = {}


@contextmanager
def integration_job_lock(engine, tenant_id, integration):
    identity = (tenant_id, integration)
    if engine.dialect.name != "postgresql":
        with _guard:
            lock = _locks.setdefault(identity, threading.Lock())
        acquired = lock.acquire(blocking=False)
        try:
            yield (lambda: None) if acquired else None
        finally:
            if acquired:
                lock.release()
        return
    key = int.from_bytes(hashlib.sha256(f"serviceops-sync:{tenant_id}:{integration}".encode()).digest()[:8],
                         byteorder="big", signed=True)
    with engine.connect() as connection:
        acquired = False
        try:
            acquired = bool(connection.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}).scalar())
            connection.commit()
            def assert_owned():
                if connection.invalidated or connection.closed:
                    raise RuntimeError("Integration ownership connection was lost.")
                try:
                    connection.execute(text("SELECT 1"))
                    connection.commit()
                except Exception:
                    logger.error("Integration ownership connection was lost")
                    raise
            yield assert_owned if acquired else None
        except Exception:
            logger.error("Integration ownership operation failed")
            raise
        finally:
            if acquired:
                try:
                    connection.rollback()
                    connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
                    connection.commit()
                except Exception:
                    logger.error("Integration ownership release failed; discarding connection")
                    connection.invalidate()
