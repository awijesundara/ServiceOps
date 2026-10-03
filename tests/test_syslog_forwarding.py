"""Real receiver contracts and local retention when remote delivery fails."""
import logging
import socket
import threading

import pytest

from app import JsonLogFormatter, RedactingFilter
from serviceops_core.syslog_forwarding import SyslogForwarder, validate_destination


@pytest.mark.parametrize("host,port,transport", [("", 514, "udp"), ("https://logs.example", 514, "tcp"),
                                                   ("logs.example", 0, "udp"), ("logs.example", "bad", "tls"),
                                                   ("logs.example", 65536, "udp"), ("logs.example", 514, "other")])
def test_invalid_syslog_settings_are_rejected(host, port, transport):
    with pytest.raises(ValueError):
        validate_destination(host, port, transport)


@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_real_syslog_receiver_gets_redacted_rfc5424_records(transport):
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(4)
    if transport == "tcp":
        receiver.listen(1)
    frames, errors = [], []

    def receive():
        try:
            if transport == "udp":
                frames.append(receiver.recv(65535))
            else:
                connection, _ = receiver.accept()
                with connection:
                    connection.settimeout(4)
                    frame = b""
                    while b" " not in frame:
                        frame += connection.recv(1)
                    length, frame = frame.split(b" ", 1)
                    while len(frame) < int(length):
                        part = connection.recv(int(length) - len(frame))
                        if not part:
                            raise OSError("Truncated syslog frame")
                        frame += part
                    frames.append(frame)
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=receive)
    thread.start()
    handler = SyslogForwarder("127.0.0.1", receiver.getsockname()[1], transport, JsonLogFormatter(), RedactingFilter())
    try:
        handler.handle(logging.LogRecord("app", logging.WARNING, __file__, 1, 'password=secret-value message=test', (), None))
        thread.join(timeout=5)
        assert not errors and len(frames) == 1
        assert frames[0].startswith(b"<132>1 ")
        assert b"ServiceOps" in frames[0] and b"message=test" in frames[0]
        assert b"secret-value" not in frames[0]
    finally:
        handler.close()
        receiver.close()
        thread.join(timeout=5)


def test_failed_destination_keeps_a_local_warning_without_recursion(caplog):
    receiver = socket.socket()
    receiver.bind(("127.0.0.1", 0))
    port = receiver.getsockname()[1]
    receiver.close()
    handler = SyslogForwarder("127.0.0.1", port, "tcp", JsonLogFormatter(), RedactingFilter())
    try:
        with caplog.at_level(logging.WARNING):
            handler.handle(logging.LogRecord("app", logging.WARNING, __file__, 1, "local retained", (), None))
            handler.messages.join()
        assert "Syslog delivery failed; local logs retained" in caplog.text
        record = next(record for record in caplog.records if "Syslog delivery failed" in record.message)
        handler.handle(record)
        assert handler.messages.empty()
    finally:
        handler.close()
