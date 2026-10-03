"""Survive Gunicorn worker crashes long enough to diagnose them.

A hung worker is killed by the arbiter (WORKER TIMEOUT -> SIGABRT -> SIGKILL)
and an out-of-memory worker is killed by the kernel. Neither event reaches the
application log store, because the worker cannot finish a database write and
the arbiter process has no application context. Crash records are therefore
spooled as small JSON files in LOG_DIR -- a write that cannot block on the
database -- and the next worker that boots imports them into ApplicationLog,
where System Health shows them and where they outlive pod replacement.
"""
import json
import logging
import os
import sys
import threading
import time
import traceback

from serviceops_core.security import redact
from serviceops_models import ApplicationLog, db

_SPOOL_DIRECTORY = "crash-spool"
_MAX_SPOOLED_FILES = 50
_MAX_DETAIL_CHARACTERS = 60000

# Not the "app" logger: its database handler would store a second copy of the
# row this module commits itself. Root still carries it to stdout, LOG_DIR and syslog.
logger = logging.getLogger("serviceops.crash")


def spool_directory():
    log_directory = os.getenv("LOG_DIR", "").strip()
    if not log_directory:
        return None
    return os.path.join(log_directory, _SPOOL_DIRECTORY)


def _write_record(kind, summary, detail):
    directory = spool_directory()
    if directory is None:
        return None
    try:
        os.makedirs(directory, exist_ok=True)
        if len(os.listdir(directory)) >= _MAX_SPOOLED_FILES:
            sys.stderr.write("ServiceOps crash spool is full; crash retained in the container log only.\n")
            return None
        name = f"{time.time_ns()}-{os.getpid()}-{kind}.json"
        temporary = os.path.join(directory, f".{name}.tmp")
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"kind": kind, "summary": summary, "detail": detail[:_MAX_DETAIL_CHARACTERS],
                       "pid": os.getpid(), "recorded_at": time.time()}, handle)
        os.replace(temporary, os.path.join(directory, name))
        return name
    except OSError as error:
        sys.stderr.write(f"ServiceOps could not spool a crash record: {error}\n")
        return None


def thread_stacks():
    """Every thread's current stack: where a hung request is actually stuck."""
    names = {thread.ident: thread.name for thread in threading.enumerate()}
    sections = []
    for ident, frame in sys._current_frames().items():
        sections.append(f"Thread {names.get(ident, 'unknown')} ({ident}):\n" + "".join(traceback.format_stack(frame)))
    return "\n".join(sections)


def record_worker_abort(worker):
    """Gunicorn worker_abort hook: runs inside the worker the arbiter timed out."""
    summary = f"Gunicorn worker {os.getpid()} exceeded the request timeout and was aborted"
    detail = thread_stacks()
    sys.stderr.write(f"{summary}\n{detail}\n")
    sys.stderr.flush()
    _write_record("worker-timeout", summary, detail)


class ArbiterCrashHandler(logging.Handler):
    """Spool the arbiter's own crash messages (timeouts, SIGKILL / OOM, boot failures)."""

    def __init__(self):
        super().__init__(level=logging.ERROR)

    def emit(self, record):
        try:
            message = record.getMessage()
            _write_record("arbiter", message[:500], message)
        except Exception:
            self.handleError(record)


def install_arbiter_handler(server):
    """Gunicorn when_ready hook: runs once in the arbiter."""
    error_log = logging.getLogger("gunicorn.error")
    if not any(isinstance(handler, ArbiterCrashHandler) for handler in error_log.handlers):
        error_log.addHandler(ArbiterCrashHandler())


def import_spooled_records(app):
    """Gunicorn post_worker_init hook: persist spooled crashes from a healthy worker."""
    directory = spool_directory()
    if directory is None or not os.path.isdir(directory):
        return 0
    imported = 0
    for name in sorted(os.listdir(directory)):
        if name.startswith(".") or not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        claimed = f"{path}.claimed-{os.getpid()}"
        try:
            # Rename is atomic: with several workers booting at once, exactly
            # one of them imports each record.
            os.rename(path, claimed)
        except OSError:
            continue
        try:
            with open(claimed, encoding="utf-8") as handle:
                record = json.load(handle)
            recorded = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.get("recorded_at", 0)))
            summary = (f"Recovered crash report ({record.get('kind')}, pid {record.get('pid')}, "
                       f"recorded {recorded}): {record.get('summary')}")
            with app.app_context():
                # Committed directly so the spool file is removed only once the
                # row is durable; the log handler swallows its own failures.
                db.session.add(ApplicationLog(level="CRITICAL", logger_name=logger.name,
                                              message=redact(summary), traceback=redact(record.get("detail", ""))))
                db.session.commit()
            logger.critical("%s", summary)
            os.remove(claimed)
            imported += 1
        except Exception:
            logger.exception("Unable to import crash report %s; it is kept for the next worker", name)
            if app is not None:
                with app.app_context():
                    db.session.rollback()
            try:
                os.rename(claimed, path)
            except OSError:
                sys.stderr.write(f"ServiceOps could not release crash report {name}.\n")
    return imported


class RequestWatchdog:
    """Report requests that are stuck inside a gthread worker.

    Gunicorn's gthread worker heartbeats from its main loop, so a request
    thread blocked on a lock, socket or database never trips WORKER TIMEOUT;
    once every thread is blocked the worker silently stops answering. This
    watchdog records each long-running request once, with its thread's stack.
    """

    def __init__(self, threshold_seconds, interval_seconds=5):
        self.threshold = threshold_seconds
        self.interval = interval_seconds
        self.active = {}
        self.reported = set()
        self.lock = threading.Lock()
        self.owner_pid = None
        self.stopped = threading.Event()

    def begin(self, method, path):
        self._ensure_running()
        with self.lock:
            self.active[threading.get_ident()] = (method, path, time.monotonic())

    def end(self):
        ident = threading.get_ident()
        with self.lock:
            self.active.pop(ident, None)
            self.reported.discard(ident)

    def _ensure_running(self):
        # Started lazily so a preloaded master never owns the thread a worker needs.
        if self.owner_pid == os.getpid():
            return
        with self.lock:
            if self.owner_pid == os.getpid():
                return
            self.active, self.reported = {}, set()
            threading.Thread(target=self._run, name="serviceops-request-watchdog", daemon=True).start()
            self.owner_pid = os.getpid()

    def check(self):
        now = time.monotonic()
        with self.lock:
            stuck = [(ident, method, path, now - started) for ident, (method, path, started) in self.active.items()
                     if now - started >= self.threshold and ident not in self.reported]
            self.reported.update(ident for ident, *_ in stuck)
        frames = sys._current_frames()
        for ident, method, path, elapsed in stuck:
            frame = frames.get(ident)
            stack = "".join(traceback.format_stack(frame)) if frame is not None else "(thread has exited)"
            summary = f"Request {method} {redact(path)} has been running for {elapsed:.0f}s in worker {os.getpid()}"
            sys.stderr.write(f"{summary}\n{stack}\n")
            sys.stderr.flush()
            _write_record("slow-request", summary, f"{stack}\n\nAll threads:\n{thread_stacks()}")
        return len(stuck)

    def _run(self):
        while not self.stopped.wait(self.interval):
            try:
                self.check()
            except Exception as error:
                sys.stderr.write(f"ServiceOps request watchdog failed: {error}\n")


def install_request_watchdog(app):
    threshold = int(os.getenv("SLOW_REQUEST_REPORT_SECONDS", "30"))
    if threshold <= 0:
        return None
    watchdog = RequestWatchdog(threshold)
    app.extensions["request_watchdog"] = watchdog

    def _watch_request():
        from flask import request
        watchdog.begin(request.method, request.path)

    # First in line, so a request stuck in authentication or rate limiting is
    # still covered.
    app.before_request_funcs.setdefault(None, []).insert(0, _watch_request)

    @app.teardown_request
    def _release_request(error):
        watchdog.end()

    return watchdog
