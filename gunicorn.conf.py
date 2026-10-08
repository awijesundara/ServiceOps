"""Gunicorn hooks; command-line flags in tools/gunicorn-entrypoint.sh stay authoritative."""
from serviceops_core import crash_reports


def when_ready(server):
    crash_reports.install_arbiter_handler(server)


def worker_abort(worker):
    crash_reports.record_worker_abort(worker)


def post_worker_init(worker):
    try:
        crash_reports.import_spooled_records(worker.wsgi)
    except Exception as error:
        worker.log.error("Unable to import spooled crash reports: %s", error)


def worker_exit(server, worker):
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
