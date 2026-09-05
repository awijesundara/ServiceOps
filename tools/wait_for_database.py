"""Wait for PostgreSQL and, optionally, the expected Alembic schema.

Kubernetes runs this module from an init container.  It deliberately reports
only exception class names so a driver error can never echo DATABASE_URL (and
its password) into pod logs.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text


ROOT = Path(__file__).resolve().parent.parent


def expected_heads() -> set[str]:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    return set(ScriptDirectory.from_config(config).get_heads())


def database_state(database_url: str) -> tuple[bool, set[str]]:
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            return True, set(MigrationContext.configure(connection).get_current_heads())
    finally:
        engine.dispose()


def wait_for_database(database_url: str, timeout: int, require_migrations: bool) -> None:
    deadline = time.monotonic() + timeout
    wanted = expected_heads() if require_migrations else set()
    last_state: tuple[str, ...] | None = None
    while True:
        try:
            reachable, current = database_state(database_url)
            if reachable and (not require_migrations or current == wanted):
                state = " and migrations are current" if require_migrations else ""
                print(f"Database is reachable{state}.", flush=True)
                return
            status = tuple(sorted(current)) or ("unversioned",)
            if status != last_state:
                print(
                    "Database is reachable; waiting for migrations "
                    f"(current={','.join(status)}, expected={','.join(sorted(wanted))}).",
                    flush=True,
                )
                last_state = status
        except Exception as exc:  # connection/driver details can contain credentials
            status = (type(exc).__name__,)
            if status != last_state:
                print(f"Database is not ready yet ({type(exc).__name__}).", flush=True)
                last_state = status
        if time.monotonic() >= deadline:
            requirement = "current migrations" if require_migrations else "a connection"
            raise TimeoutError(f"Timed out after {timeout}s waiting for PostgreSQL {requirement}.")
        time.sleep(2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--migrations-current", action="store_true")
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 3600:
        parser.error("--timeout must be between 1 and 3600 seconds")
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        parser.error("DATABASE_URL is required")
    wait_for_database(database_url, args.timeout, args.migrations_current)


if __name__ == "__main__":
    main()
