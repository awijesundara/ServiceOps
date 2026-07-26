"""Verify a one-revision PostgreSQL downgrade and roll-forward without data loss."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections.abc import Iterable
from urllib.parse import urlparse

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import inspect, text

from app import create_app, db


REHEARSAL_SUFFIX = "_migration_rehearsal"


def validated_rehearsal_database(url: str) -> str:
    parsed = urlparse(url.replace("postgresql+psycopg://", "postgresql://", 1))
    database = parsed.path.removeprefix("/")
    if parsed.scheme != "postgresql" or not database.endswith(REHEARSAL_SUFFIX):
        raise ValueError(
            f"Refusing migration rehearsal: database must be PostgreSQL and end "
            f"with {REHEARSAL_SUFFIX!r}."
        )
    return database


def digest_rows(rows: Iterable[tuple[object, ...]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(
            json.dumps(list(row), sort_keys=True, default=str).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def snapshot() -> dict[str, object]:
    inspector = inspect(db.engine)
    tables = sorted(
        table for table in inspector.get_table_names()
        if table != "alembic_version"
    )
    counts = {
        table: db.session.execute(
            text(f'SELECT COUNT(*) FROM "{table}"')
        ).scalar_one()
        for table in tables
    }
    users = db.session.execute(
        text('SELECT id, username, email, tenant_id FROM "user" ORDER BY id')
    ).all()
    rehearsal_articles = db.session.execute(text(
        "SELECT title, body, tenant_id FROM knowledge "
        "WHERE category = 'Migration Rehearsal' ORDER BY title"
    )).all()
    return {
        "counts": counts,
        "user_digest": digest_rows(users),
        "rehearsal_digest": digest_rows(rehearsal_articles),
    }


def seed_representative_rows(row_count: int) -> None:
    if row_count < 1:
        raise ValueError("row_count must be positive")
    author_id = db.session.execute(
        text('SELECT id FROM "user" WHERE tenant_id = 1 ORDER BY id LIMIT 1')
    ).scalar_one()
    db.session.execute(text(
        "INSERT INTO knowledge "
        "(title, category, body, published, author_id, created_at, tenant_id) "
        "SELECT "
        "'Migration rehearsal ' || lpad(value::text, 8, '0'), "
        "'Migration Rehearsal', "
        "'Synthetic isolated migration verification record ' || value::text, "
        "true, :author_id, CURRENT_TIMESTAMP, 1 "
        "FROM generate_series(1, :row_count) AS value "
        "ON CONFLICT DO NOTHING"
    ), {"author_id": author_id, "row_count": row_count})
    db.session.commit()


def migration_config() -> AlembicConfig:
    config = AlembicConfig("alembic.ini")
    config.set_main_option("script_location", "migrations")
    return config


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=100_000)
    args = parser.parse_args()
    database_url = os.environ["DATABASE_URL"]
    database = validated_rehearsal_database(database_url)
    started = time.monotonic()

    app = create_app({"AUTO_MIGRATE_IN_TESTS": False})
    with app.app_context():
        revision = db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
        if revision != "20260726_0011":
            raise RuntimeError(
                f"Rehearsal clone must start at 20260726_0011, found {revision}."
            )
        seed_representative_rows(args.rows)
        before = snapshot()
        db.session.remove()

        command.downgrade(migration_config(), "20260726_0010")
        downgraded_revision = db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
        if downgraded_revision != "20260726_0010":
            raise RuntimeError("Downgrade revision verification failed.")
        after_downgrade = snapshot()
        if after_downgrade != before:
            raise RuntimeError("Data fingerprint changed during downgrade.")
        db.session.remove()

        command.upgrade(migration_config(), "head")
        upgraded_revision = db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
        if upgraded_revision != "20260726_0011":
            raise RuntimeError("Roll-forward revision verification failed.")
        if "integrity_key_id" not in {
            column["name"] for column in inspect(db.engine).get_columns("audit")
        }:
            raise RuntimeError("Roll-forward lacks audit.integrity_key_id.")
        after_upgrade = snapshot()
        if after_upgrade != before:
            raise RuntimeError("Data fingerprint changed during roll-forward.")

    print(json.dumps({
        "database": database,
        "source_revision": revision,
        "downgraded_revision": downgraded_revision,
        "final_revision": upgraded_revision,
        "synthetic_rows": args.rows,
        "table_count": len(before["counts"]),
        "record_count": sum(before["counts"].values()),
        "data_preserved": True,
        "duration_seconds": round(time.monotonic() - started, 3),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
