"""Round-trip the service-name constraint against SQLite and optional real PostgreSQL."""
import importlib.util
import os
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations


@pytest.mark.parametrize('url', ['sqlite://', os.getenv('SERVICE_OFFERING_TEST_POSTGRES')])
def test_service_name_migration_roundtrip(url):
    if not url:
        pytest.skip('SERVICE_OFFERING_TEST_POSTGRES enables isolated PostgreSQL coverage')
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/20261023_0142_service_offering_tenant_scoped_name.py'
    spec = importlib.util.spec_from_file_location('service_name_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine(url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql('CREATE TABLE service_offering (id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, name VARCHAR(160) NOT NULL, UNIQUE (name))')
            connection.exec_driver_sql("INSERT INTO service_offering VALUES (1, 1, 'Payments')")
        with engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                migration.upgrade()
            connection.exec_driver_sql("INSERT INTO service_offering VALUES (2, 2, 'Payments')")
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as connection:
                connection.exec_driver_sql("INSERT INTO service_offering VALUES (3, 1, 'Payments')")
        # Downgrade must fail safely while tenants share names.
        with pytest.raises(RuntimeError, match="tenants share names"):
            with engine.begin() as connection:
                with Operations.context(MigrationContext.configure(connection)):
                    migration.downgrade()
        with engine.begin() as connection:
            connection.exec_driver_sql('DELETE FROM service_offering WHERE id = 2')
            with Operations.context(MigrationContext.configure(connection)):
                migration.downgrade()
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as connection:
                connection.exec_driver_sql("INSERT INTO service_offering VALUES (2, 2, 'Payments')")
        with engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
            assert connection.exec_driver_sql('SELECT name FROM service_offering').scalar() == 'Payments'
    finally:
        with engine.begin() as connection:
            connection.exec_driver_sql('DROP TABLE IF EXISTS service_offering')
            connection.exec_driver_sql('DROP TABLE IF EXISTS _alembic_tmp_service_offering')
        engine.dispose()


@pytest.mark.parametrize('url', ['sqlite://', os.getenv('SERVICE_OFFERING_TEST_POSTGRES')])
def test_team_ownership_migration_preserves_history_and_guards_downgrade(url):
    if not url:
        pytest.skip('SERVICE_OFFERING_TEST_POSTGRES enables isolated PostgreSQL coverage')
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/20261023_0143_service_team_ownership.py'
    spec = importlib.util.spec_from_file_location('team_ownership_migration', path)
    migration = importlib.util.module_from_spec(spec); spec.loader.exec_module(migration)
    engine = sa.create_engine(url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql('CREATE TABLE service_offering (id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, name VARCHAR(160) NOT NULL, owner_id INTEGER NOT NULL, support_group_id INTEGER, UNIQUE (tenant_id, name))')
            connection.exec_driver_sql("INSERT INTO service_offering VALUES (1, 1, 'Legacy', 7, NULL)")
        with engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade(); migration.upgrade()
            assert connection.exec_driver_sql('SELECT owner_id FROM service_offering WHERE id=1').scalar() == 7
            connection.exec_driver_sql("INSERT INTO service_offering VALUES (2, 1, 'Team-owned', NULL, 3)")
        with pytest.raises(RuntimeError, match='no person assigned'):
            with engine.begin() as connection:
                with Operations.context(MigrationContext.configure(connection)):
                    migration.downgrade()
        with engine.begin() as connection:
            assert next(c for c in sa.inspect(connection).get_columns('service_offering') if c['name']=='owner_id')['nullable']
            connection.exec_driver_sql('DELETE FROM service_offering WHERE id=2')
            with Operations.context(MigrationContext.configure(connection)):
                migration.downgrade()
            assert not next(c for c in sa.inspect(connection).get_columns('service_offering') if c['name']=='owner_id')['nullable']
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
            assert connection.exec_driver_sql('SELECT owner_id FROM service_offering WHERE id=1').scalar()==7
    finally:
        with engine.begin() as connection:
            connection.exec_driver_sql('DROP TABLE IF EXISTS service_offering')
            connection.exec_driver_sql('DROP TABLE IF EXISTS _alembic_tmp_service_offering')
        engine.dispose()
