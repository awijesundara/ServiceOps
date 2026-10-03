"""Prevent pooled database connections from crossing process boundaries."""
import logging
import os

from sqlalchemy import event, exc

logger = logging.getLogger(__name__)


def install_process_guard(engine):
    try:
        @event.listens_for(engine, "connect")
        def record_process(connection, record):
            try:
                record.info["serviceops_pid"] = os.getpid()
            except Exception:
                logger.exception("Unable to record database connection ownership")
                raise

        @event.listens_for(engine, "checkout")
        def require_current_process(connection, record, proxy):
            try:
                owner = record.info.get("serviceops_pid")
                current = os.getpid()
                if owner != current:
                    record.dbapi_connection = proxy.dbapi_connection = None
                    logger.warning("Replacing inherited database connection from process %s in process %s", owner, current)
                    raise exc.DisconnectionError("Database connection belongs to another process")
            except exc.DisconnectionError:
                raise
            except Exception:
                logger.exception("Unable to verify database connection ownership")
                raise
    except Exception:
        logger.exception("Unable to install database process isolation")
        raise
