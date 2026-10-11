"""Gunicorn hooks; command-line flags in tools/gunicorn-entrypoint.sh stay authoritative."""
import os
from pathlib import Path

from serviceops_core import crash_reports

HEALTH_DIR = Path("/tmp/serviceops-gunicorn-health")


def when_ready(server):
    crash_reports.install_arbiter_handler(server)
    if os.getenv("GUNICORN_HEALTH_PORT"):
        HEALTH_DIR.mkdir(exist_ok=True)
        for path in HEALTH_DIR.glob("worker-*"):
            path.unlink(missing_ok=True)
        (HEALTH_DIR / "master").write_text(str(os.getpid()))


def worker_abort(worker):
    crash_reports.record_worker_abort(worker)


def post_worker_init(worker):
    if os.getenv("GUNICORN_HEALTH_PORT"):
        (HEALTH_DIR / f"worker-{worker.pid}").touch()
    try:
        crash_reports.import_spooled_records(worker.wsgi)
    except Exception as error:
        worker.log.error("Unable to import spooled crash reports: %s", error)


def worker_exit(server, worker):
    (HEALTH_DIR / f"worker-{worker.pid}").unlink(missing_ok=True)
    # Workers are recycled (--max-requests), so write out the request counts
    # this worker buffered since its last flush instead of dropping them.
    app = getattr(worker, "wsgi", None)
    if app is None:
        return
    try:
        from app import flush_request_metrics
        with app.app_context():
            flush_request_metrics()
    except Exception as error:  # noqa: BLE001 - never block worker shutdown
        worker.log.error("Unable to flush request metrics on exit: %s", error)
