"""Durable integration outbox worker."""
import logging
import signal
import time

from app import (
    PlatformSetting, create_app, db, now, process_kpi_snapshot_schedule,
    process_ldap_sync_schedule, process_outbox, process_rt_import_jobs,
    process_sla_breaches, process_workflow_jobs, process_workflow_schedules,
)

running = True


def stop(_signum, _frame):
    global running
    running = False


def record_heartbeat():
    """Backs System Health's worker-liveness signal (see app.py's
    /admin/system-health): a heartbeat older than a couple of loop
    intervals means the worker process is stuck or dead even though the
    container itself may still show "running"."""
    row = db.session.get(PlatformSetting, "WORKER_LAST_HEARTBEAT")
    if not row:
        row = PlatformSetting(key="WORKER_LAST_HEARTBEAT", tenant_id=1, encrypted=False)
        db.session.add(row)
    row.value = now().isoformat()
    db.session.commit()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
app = create_app()
with app.app_context():
    while running:
        try:
            processed = (
                process_sla_breaches() + process_workflow_schedules()
                + process_workflow_jobs() + process_outbox()
                + process_ldap_sync_schedule() + process_kpi_snapshot_schedule()
                + process_rt_import_jobs()
            )
        except Exception:
            # A single bad tenant/record must never kill the whole worker
            # process (every process_* function above already isolates its
            # own per-item failures -- this is the last-resort backstop for
            # something they didn't anticipate). Logged so it's visible on
            # System Health via the DatabaseLogHandler like any other error.
            app.logger.exception("Unhandled error in worker loop")
            db.session.rollback()
            processed = 0
        try:
            record_heartbeat()
        except Exception:
            app.logger.exception("Could not record worker heartbeat")
            db.session.rollback()
        if not processed:
            time.sleep(5)
