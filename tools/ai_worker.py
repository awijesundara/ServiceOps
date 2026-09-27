"""Dedicated AI worker: python -m tools.ai_worker. Never runs migrations."""
import signal
import threading
import time
from pathlib import Path

from app import create_app, db
from serviceops_core.ai.provider import provider_timeout
from serviceops_core.ai.service import process_one
from serviceops_core.storage import ipfs_enabled

HEARTBEAT = Path("/tmp/serviceops-ai-heartbeat")
HEARTBEAT_INTERVAL = 20
# One job may try up to three services, each bounded by the provider timeout.
ATTEMPTS_PER_JOB = 3


class Heartbeat:
    """Keeps the probe file fresh while the worker is idle or inside a job that is still within its time
    bound. A job running longer than any bounded job can means the worker is stuck: the file then goes
    stale and Kubernetes restarts the pod."""

    def __init__(self):
        self.job_started = None
        self.limit = ATTEMPTS_PER_JOB * provider_timeout() + 120

    def healthy(self):
        started = self.job_started
        return started is None or time.monotonic() - started < self.limit

    def beat(self):
        if self.healthy():
            HEARTBEAT.touch()

    def run(self, running):
        while running():
            self.beat()
            time.sleep(HEARTBEAT_INTERVAL)


def main():
    if ipfs_enabled():
        raise SystemExit("AI worker requires PostgreSQL storage.")
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    app = create_app()
    heartbeat = Heartbeat()
    threading.Thread(target=heartbeat.run, args=(lambda: running,), daemon=True).start()
    with app.app_context():
        while running:
            heartbeat.job_started = time.monotonic()
            try:
                processed = process_one()
            except Exception:
                # No exception text: provider/DB errors can contain sensitive parameters.
                app.logger.error("AI worker iteration failed; pending job lease will expire safely")
                db.session.rollback()
                processed = False
            finally:
                heartbeat.job_started = None
                heartbeat.beat()
                db.session.remove()
            if not processed:
                time.sleep(3)


if __name__ == "__main__":
    main()
