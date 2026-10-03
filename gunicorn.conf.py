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
