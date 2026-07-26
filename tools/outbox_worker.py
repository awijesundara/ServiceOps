"""Durable integration outbox worker."""
import signal
import time

from app import (
    create_app, process_outbox, process_sla_breaches, process_workflow_jobs,
    process_workflow_schedules,
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
        )
        if not processed:
            time.sleep(5)
