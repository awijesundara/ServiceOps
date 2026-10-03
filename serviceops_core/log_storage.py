"""Persist diagnostics after the business transaction has ended.

Log emission never commits or rolls back application changes. Deferring writes
also protects the single SQLite connection used by the IPFS projection.
"""
import logging
import sys
import traceback

from flask import g, has_app_context, has_request_context, request
from flask_login import current_user
from sqlalchemy import event
from sqlalchemy.orm import Session

from serviceops_core.security import redact
from serviceops_models import ApplicationLog, db

_QUEUE_KEY = 'serviceops_pending_diagnostics'
_MAX_PENDING = 256


def report_diagnostic_failure(message):
    try:
        sys.stderr.write(message + '\n')
        sys.stderr.flush()
    except Exception:
        # There is no remaining diagnostic sink; logging cannot replace the
        # original application failure with a second exception.
        return


def _persist_pending(session):
    if not has_app_context():
        return
    pending = session.info.pop(_QUEUE_KEY, [])
    if not pending:
        return
    try:
        with Session(bind=db.engine) as diagnostic_session:
            diagnostic_session.add_all(ApplicationLog(**values) for values in pending)
            diagnostic_session.commit()
    except Exception:
        report_diagnostic_failure('ServiceOps diagnostic persistence failed; inspect the application log stream.')


@event.listens_for(Session, 'after_transaction_end')
def _transaction_ended(session, transaction):
    try:
        if transaction.parent is None:
            _persist_pending(session)
    except Exception:
        report_diagnostic_failure('ServiceOps diagnostic transaction cleanup failed; inspect the application log stream.')


class DatabaseLogHandler(logging.Handler):
    """Queue sanitized diagnostics without changing business transaction state."""

    def emit(self, record):
        if not has_app_context():
            return
        try:
            business_session = db.session()
            authenticated = has_request_context() and current_user.is_authenticated
            values = {
                'level': record.levelname,
                'logger_name': record.name,
                'message': redact(self.format(record) if not record.exc_info else record.getMessage()),
                'traceback': redact(''.join(traceback.format_exception(*record.exc_info))) if record.exc_info else None,
                'path': redact(request.path if has_request_context() else getattr(record, 'path', None)),
                'method': request.method if has_request_context() else getattr(record, 'method', None),
                'request_id': g.get('request_id') if has_request_context() else getattr(record, 'request_id', None),
                'user_id': current_user.id if authenticated else None,
                'tenant_id': current_user.tenant_id if authenticated else None,
            }
            pending = business_session.info.setdefault(_QUEUE_KEY, [])
            if len(pending) >= _MAX_PENDING:
                report_diagnostic_failure('ServiceOps diagnostic queue limit reached; additional records remain in the log stream.')
                return
            pending.append(values)
            if not business_session.in_transaction():
                _persist_pending(business_session)
        except Exception:
            report_diagnostic_failure('ServiceOps diagnostic collection failed; inspect the application log stream.')
