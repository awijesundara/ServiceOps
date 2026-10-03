"""Startup configuration and forked processes must not share pooled sockets."""
import multiprocessing
import os

from sqlalchemy import create_engine, text

from app import create_app, db
from serviceops_core.database_pool import install_process_guard
from serviceops_core import syslog_forwarding


def test_final_startup_cleanup_runs_after_syslog_database_reads(tmp_path, monkeypatch):
    original = syslog_forwarding.install
    observed = []

    def inspect_install(application, *args):
        original(application, *args)
        with application.app_context():
            observed.append(db.engine.pool.checkedin())

    monkeypatch.setattr(syslog_forwarding, "install", inspect_install)
    application = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'startup.db'}"})
    assert observed and observed[0] > 0
    with application.app_context():
        assert db.engine.pool.checkedin() == 0
        assert db.engine.pool.checkedout() == 0
    assert application.test_client().get('/health').status_code == 200


def test_foreign_process_connection_is_replaced_without_closing_parent(tmp_path, caplog):
    engine = create_engine(f"sqlite:///{tmp_path / 'ownership.db'}")
    install_process_guard(engine)
    try:
        with engine.connect() as connection:
            inherited = connection.connection.dbapi_connection
            connection.connection.info['serviceops_pid'] = -1
        with engine.connect() as connection:
            assert connection.connection.dbapi_connection is not inherited
            assert connection.connection.info['serviceops_pid'] == os.getpid()
            assert connection.execute(text('SELECT 42')).scalar_one() == 42
        assert inherited.execute('SELECT 43').fetchone()[0] == 43
        assert 'Replacing inherited database connection' in caplog.text
        inherited.close()
    finally:
        engine.dispose()


def test_actual_fork_replaces_connection_and_parent_remains_usable(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'fork.db'}")
    install_process_guard(engine)
    with engine.connect() as connection:
        assert connection.execute(text('SELECT 42')).scalar_one() == 42
    context = multiprocessing.get_context('fork')
    receiver, sender = context.Pipe(duplex=False)

    def child():
        try:
            with engine.connect() as connection:
                sender.send((os.getpid(), connection.connection.info['serviceops_pid'], connection.execute(text('SELECT 43')).scalar_one()))
        finally:
            sender.close()

    process = context.Process(target=child)
    try:
        process.start()
        sender.close()
        assert receiver.poll(10), 'Forked database checkout timed out'
        pid, owner, result = receiver.recv()
        assert pid == owner and pid != os.getpid() and result == 43
        process.join(10)
        assert process.exitcode == 0
        with engine.connect() as connection:
            assert connection.connection.info['serviceops_pid'] == os.getpid()
            assert connection.execute(text('SELECT 44')).scalar_one() == 44
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
        receiver.close()
        engine.dispose()
