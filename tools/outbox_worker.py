"""Durable integration outbox worker."""
import signal
import time

from app import (
    create_app, process_kpi_snapshot_schedule, process_ldap_sync_schedule, process_outbox,
    process_rt_import_jobs, process_sla_breaches, process_workflow_jobs, process_workflow_schedules,
)

running = True


def stop(_signum, _frame):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
app = create_app()
with app.app_context():
    while running:
        processed = (
            process_sla_breaches() + process_workflow_schedules()
            + process_workflow_jobs() + process_outbox()
            + process_ldap_sync_schedule() + process_kpi_snapshot_schedule()
            + process_rt_import_jobs()
        )
        if not processed:
            time.sleep(5)
