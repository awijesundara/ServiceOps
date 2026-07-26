from logging.config import fileConfig

from alembic import context
from flask import current_app

from app import db

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = db.metadata


def database_url():
    return str(current_app.extensions["sqlalchemy"].engine.url).replace("%", "%%")


def run_migrations_offline():
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connection = current_app.extensions["sqlalchemy"].engine.connect()
    try:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
