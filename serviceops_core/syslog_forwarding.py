"""Bounded asynchronous RFC 5424 forwarding; local logs remain authoritative."""
import logging
import os
import queue
import re
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from serviceops_core.localization import tr


def validate_destination(host, port, transport):
    if not isinstance(host, str) or not host or len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.:%_-]+", host):
        raise ValueError(tr("Enter a syslog hostname or IP address without a URL or path."))
    try:
        number = int(port)
    except (TypeError, ValueError) as error:
        raise ValueError(tr("Enter a valid syslog port.")) from error
    if not 1 <= number <= 65535 or transport not in {"udp", "tcp", "tls"}:
        raise ValueError(tr("Select a valid syslog port and transport."))
    return host, number, transport


class SyslogForwarder(logging.Handler):
    """Send redacted records outside request threads, with bounded memory and I/O."""

    def __init__(self, host, port, transport, formatter, redacting_filter):
        super().__init__()
        self.destination = validate_destination(host, port, transport)
        self.setFormatter(formatter)
        self.addFilter(redacting_filter)
        self.stopped = threading.Event()
        self.last_warning = float("-inf")
        self.warning_lock = threading.Lock()
        self.start_lock = threading.Lock()
        self.owner_pid = None
        self._start_sender()

    def _start_sender(self):
        # Gunicorn --preload builds this handler in the master and forks the
        # workers; threads do not survive fork, so each process that emits must
        # own a fresh queue, socket and sender thread.
        with self.start_lock:
            if self.owner_pid == os.getpid():
                return
            self.messages = queue.Queue(maxsize=1024)
            self.connection = None
            self.thread = threading.Thread(target=self._run, name="serviceops-syslog", daemon=True)
            self.thread.start()
            self.owner_pid = os.getpid()

    def _warn(self, message):
        with self.warning_lock:
            timestamp = time.monotonic()
            if timestamp - self.last_warning < 60:
                return
            self.last_warning = timestamp
        logging.getLogger("app").warning(message, extra={"skip_syslog": True})

    def emit(self, record):
        if self.stopped.is_set() or getattr(record, "skip_syslog", False):
            return
        try:
            if self.owner_pid != os.getpid():
                self._start_sender()
            severity = 2 if record.levelno >= logging.CRITICAL else 3 if record.levelno >= logging.ERROR else 4 if record.levelno >= logging.WARNING else 6 if record.levelno >= logging.INFO else 7
            timestamp = datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds")
            message = self.format(record).replace("\n", "\\n").replace("\r", "\\r")
            frame = f"<{16 * 8 + severity}>1 {timestamp} - ServiceOps - - - {message}".encode("utf-8")
            if len(frame) > 60000:
                self._warn("Syslog record exceeds 60,000 bytes; retained in local logs.")
                return
            self.messages.put_nowait(frame)
        except queue.Full:
            self._warn("Syslog queue is full; unsent records remain in local logs.")
        except Exception:
            self._warn("Unable to prepare syslog record; retained in local logs.")

    def _disconnect(self):
        if self.connection is not None:
            try:
                self.connection.close()
            except OSError:
                self._warn("Unable to close syslog connection.")
            finally:
                self.connection = None

    def _send(self, frame):
        host, port, transport = self.destination
        if self.connection is None:
            if transport == "udp":
                family, kind, protocol, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
                self.connection = socket.socket(family, kind, protocol)
                self.connection.settimeout(2)
                self.connection.connect(address)
            else:
                connection = socket.create_connection((host, port), timeout=2)
                try:
                    self.connection = ssl.create_default_context().wrap_socket(connection, server_hostname=host) if transport == "tls" else connection
                except Exception:
                    connection.close()
                    raise
        if transport == "udp":
            sent = self.connection.send(frame)
            if sent != len(frame):
                raise OSError("Incomplete syslog datagram")
        else:
            self.connection.sendall(str(len(frame)).encode("ascii") + b" " + frame)

    def _run(self):
        retry_after = 0
        try:
            while not self.stopped.is_set():
                try:
                    frame = self.messages.get(timeout=0.2)
                except queue.Empty:
                    continue
                try:
                    if time.monotonic() < retry_after:
                        continue
                    self._send(frame)
                except Exception:
                    self._disconnect()
                    retry_after = time.monotonic() + 30
                    self._warn("Syslog delivery failed; local logs retained. Retrying subsequent records after 30 seconds.")
                finally:
                    self.messages.task_done()
        finally:
            self._disconnect()

    def close(self):
        self.stopped.set()
        super().close()


def install(app, setting_value, formatter, redacting_filter):
    root = logging.getLogger()
    for logger in (root, logging.getLogger("gunicorn.access")):
        for handler in list(logger.handlers):
            if isinstance(handler, SyslogForwarder):
                logger.removeHandler(handler)
                handler.close()
    try:
        with app.app_context():
            if str(setting_value("SYSLOG_ENABLED", "false")).lower() not in {"true", "1", "yes", "on"}:
                return
            host = setting_value("SYSLOG_HOST", "")
            port = setting_value("SYSLOG_PORT", "514")
            transport = setting_value("SYSLOG_TRANSPORT", "udp")
            level = setting_value("SYSLOG_LEVEL", "WARNING")
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(tr("Invalid syslog severity"))
        handler = SyslogForwarder(host, port, transport, formatter, redacting_filter)
        handler.setLevel(getattr(logging, level))
        root.addHandler(handler)
        if not logging.getLogger("gunicorn.access").propagate:
            logging.getLogger("gunicorn.access").addHandler(handler)
        app.extensions["syslog_forwarder"] = handler
    except Exception:
        app.logger.exception("Unable to configure syslog forwarding; local logging remains enabled.", extra={"skip_syslog": True})
