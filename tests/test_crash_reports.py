"""Worker crash records outlive the worker and reach the persisted log store."""
import logging
import os
import socket

from app import JsonLogFormatter, RedactingFilter, create_app
from serviceops_core import crash_reports
from serviceops_core.syslog_forwarding import SyslogForwarder
from serviceops_models import ApplicationLog, db


def test_worker_abort_spools_thread_stacks_and_next_worker_persists_them(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    crash_reports.record_worker_abort(worker=None)
    spooled = os.listdir(tmp_path / "crash-spool")
    assert len(spooled) == 1 and spooled[0].endswith("-worker-timeout.json")

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
    with app.app_context():
        db.create_all()
    assert crash_reports.import_spooled_records(app) == 1
    assert os.listdir(tmp_path / "crash-spool") == []
    with app.app_context():
        entry = ApplicationLog.query.filter_by(level="CRITICAL").one()
        assert "exceeded the request timeout" in entry.message
        assert "test_worker_abort_spools_thread_stacks" in entry.traceback


def test_arbiter_errors_are_spooled_but_info_is_not(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    error_log = logging.getLogger("gunicorn.error")
    crash_reports.install_arbiter_handler(server=None)
    crash_reports.install_arbiter_handler(server=None)
    handlers = [h for h in error_log.handlers if isinstance(h, crash_reports.ArbiterCrashHandler)]
    try:
        assert len(handlers) == 1
        error_log.info("Booting worker with pid: 7")
        error_log.error("Worker (pid:7) was sent SIGKILL! Perhaps out of memory?")
        assert [name.endswith("-arbiter.json") for name in os.listdir(tmp_path / "crash-spool")] == [True]
    finally:
        for handler in handlers:
            error_log.removeHandler(handler)


def test_spool_without_log_dir_is_a_safe_no_op(monkeypatch):
    monkeypatch.delenv("LOG_DIR", raising=False)
    crash_reports.record_worker_abort(worker=None)
    assert crash_reports.import_spooled_records(app=None) == 0


def test_syslog_forwarder_restarts_its_sender_after_fork():
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(4)
    handler = SyslogForwarder("127.0.0.1", receiver.getsockname()[1], "udp", JsonLogFormatter(), RedactingFilter())
    try:
        # Simulate a preloaded handler inherited by a forked worker: the
        # sender thread belongs to another process and is not running here.
        inherited_thread = handler.thread
        handler.owner_pid = -1
        handler.handle(logging.LogRecord("app", logging.WARNING, __file__, 1, "after fork", (), None))
        assert handler.thread is not inherited_thread and handler.thread.is_alive()
        assert handler.owner_pid == os.getpid()
        assert b"after fork" in receiver.recv(65535)
    finally:
        handler.close()
        receiver.close()


def test_failed_persistence_keeps_the_spooled_record(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    crash_reports.record_worker_abort(worker=None)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
    # No schema: the insert fails, so the record must stay for the next worker.
    assert crash_reports.import_spooled_records(app) == 0
    assert [name.endswith("-worker-timeout.json") for name in os.listdir(tmp_path / "crash-spool")] == [True]


def test_watchdog_reports_a_stuck_request_once_with_its_stack(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    watchdog = crash_reports.RequestWatchdog(threshold_seconds=0, interval_seconds=3600)
    watchdog.begin("GET", "/tickets?token=secret-value")
    try:
        assert watchdog.check() == 1
        assert watchdog.check() == 0
    finally:
        watchdog.end()
        watchdog.stopped.set()
    [name] = os.listdir(tmp_path / "crash-spool")
    content = (tmp_path / "crash-spool" / name).read_text()
    assert name.endswith("-slow-request.json")
    assert "test_watchdog_reports_a_stuck_request_once" in content and "secret-value" not in content


def test_finished_requests_are_never_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    watchdog = crash_reports.RequestWatchdog(threshold_seconds=0, interval_seconds=3600)
    watchdog.begin("GET", "/")
    watchdog.end()
    watchdog.stopped.set()
    assert watchdog.check() == 0
