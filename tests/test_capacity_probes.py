"""Health checks remain available while user-request workers are busy."""
import os
import threading
from pathlib import Path
from http.server import HTTPServer
from urllib.request import urlopen

import pytest
from sqlalchemy import create_engine, text

import app as core
from test_app import app  # noqa: F401 — shared application fixture
from tools import health_probe


def test_private_probe_checks_workers_and_schema_without_using_app_queue(tmp_path, monkeypatch):
    directory = tmp_path / 'workers'
    directory.mkdir()
    (directory / 'master').write_text(str(os.getpid()))
    worker = directory / f'worker-{os.getpid()}'
    worker.touch()
    original = health_probe.workers_ready
    monkeypatch.setattr(health_probe, 'workers_ready', lambda: original(directory))
    url = f'sqlite:///{tmp_path / "probe.db"}'
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)'))
        connection.execute(text("INSERT INTO alembic_version VALUES ('expected')"))
    engine.dispose()
    server = HTTPServer(('127.0.0.1', 0), health_probe.handler(url, {'expected'}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f'http://127.0.0.1:{server.server_port}'
        assert urlopen(base+'/live', timeout=1).status == 200
        assert urlopen(base+'/ready', timeout=1).status == 200
        assert not health_probe.ready(url, {'different'})
        worker.unlink()
        assert not health_probe.workers_ready()
        assert not health_probe.ready(url, {'expected'})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_request_log_dns_never_waits_for_slow_lookup_or_fails_during_shutdown(monkeypatch):
    started, release = threading.Event(), threading.Event()
    def slow(address):
        started.set()
        release.wait(timeout=3)
        return None
    monkeypatch.setattr(core, '_lookup_verified_hostname', slow)
    monkeypatch.setattr(core, 'setting_bool', lambda *_args: True)
    core._hostname_cache.clear()
    assert core.verified_client_hostname('192.0.2.201', wait=False) is None
    assert started.wait(timeout=1)
    assert core.verified_client_hostname('192.0.2.201', wait=False) is None
    release.set()
    class ClosedPool:
        def submit(self, *_args):
            raise RuntimeError('cannot schedule new futures after shutdown')
    monkeypatch.setattr(core, '_hostname_pool', ClosedPool())
    assert core.verified_client_hostname('192.0.2.202', wait=False) is None


def test_audit_context_does_not_wait_for_dns_while_transaction_is_open(app, monkeypatch):
    calls = []
    def lookup(address, *, wait=True):
        calls.append((address, wait))
        assert wait is False
        return None
    monkeypatch.setattr(core, 'verified_client_hostname', lookup)
    with app.test_request_context('/login', environ_base={'REMOTE_ADDR': '192.0.2.203'}):
        context = core.audit_security_context()
    assert context['client_hostname'] is None
    assert calls == [('192.0.2.203', False)]
