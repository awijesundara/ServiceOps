"""Volatile relational projection for the IPFS storage mode.

IPFS remains the only durable record store.  The projection exists solely in
process memory so the existing, well-tested SQLAlchemy domain and query layer
can execute unchanged.  On startup every table is restored from the encrypted
IPFS checkpoint; after a successful transaction the complete projection is
checkpointed back to IPFS.

This is deliberately generic: newly added model tables automatically join the
checkpoint without another storage-backend rollout wave.
"""
import base64
from datetime import date, datetime, time
from decimal import Decimal
import logging
import threading
import time as time_module
import uuid

from sqlalchemy import event


logger = logging.getLogger("serviceops.storage.ipfs_projection")
_TAG = "__serviceops_type__"


def _encode(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, datetime):
        return {_TAG: "datetime", "value": value.isoformat()}
    if isinstance(value, date):
        return {_TAG: "date", "value": value.isoformat()}
    if isinstance(value, time):
        return {_TAG: "time", "value": value.isoformat()}
    if isinstance(value, bytes):
        return {_TAG: "bytes", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Decimal):
        return {_TAG: "decimal", "value": str(value)}
    if isinstance(value, uuid.UUID):
        return {_TAG: "uuid", "value": str(value)}
    raise TypeError(f"Unsupported checkpoint value {type(value).__name__}")


def _decode(value):
    if not isinstance(value, dict) or _TAG not in value:
        return value
    kind, raw = value[_TAG], value["value"]
    if kind == "datetime":
        return datetime.fromisoformat(raw)
    if kind == "date":
        return date.fromisoformat(raw)
    if kind == "time":
        return time.fromisoformat(raw)
    if kind == "bytes":
        return base64.b64decode(raw)
    if kind == "decimal":
        return Decimal(raw)
    if kind == "uuid":
        return uuid.UUID(raw)
    raise ValueError(f"Unknown checkpoint value type {kind!r}")


class IPFSRelationalProjection:
    """Mirrors SQLAlchemy metadata into the active IPFS checkpoint."""

    def __init__(self, db, backend):
        self.db = db
        # Capture the concrete engine while create_app() holds an app context;
        # background checkpoint threads cannot resolve Flask's db.engine proxy.
        self.engine = db.engine
        self.backend = backend
        self._lock = threading.RLock()
        self._dirty = False
        self._restoring = False
        self._checkpoint_loop_started = False

    def restore(self):
        tables = self.backend.get_relational_state()
        if not tables:
            return False
        self._restoring = True
        try:
            with self.engine.begin() as connection:
                connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
                for table in reversed(self.db.metadata.sorted_tables):
                    connection.execute(table.delete())
                for table in self.db.metadata.sorted_tables:
                    rows = tables.get(table.name, [])
                    if rows:
                        connection.execute(
                            table.insert(),
                            [{key: _decode(value) for key, value in row.items()} for row in rows],
                        )
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            logger.info("Restored %d IPFS-backed relational tables.", len(tables))
            return True
        finally:
            self._restoring = False

    def import_legacy_identity(self):
        """One-time compatibility for checkpoints created by B-335."""
        if self.backend.get_relational_state():
            return False
        legacy = self.backend.export_legacy_entities()
        tenants = legacy.get("tenant", [])
        users = legacy.get("user", [])
        if not tenants and not users:
            return False
        metadata = self.db.metadata.tables
        with self.engine.begin() as connection:
            if tenants:
                columns = {column.name for column in metadata["tenant"].columns}
                normalized = []
                for row in tenants:
                    item = {key: value for key, value in row.items() if key in columns}
                    item.setdefault("active", True)
                    item.setdefault("created_at", datetime.now().astimezone())
                    normalized.append(item)
                connection.execute(metadata["tenant"].insert(), normalized)
            if users:
                columns = {column.name for column in metadata["user"].columns}
                normalized = []
                for row in users:
                    item = {key: value for key, value in row.items() if key in columns}
                    item.setdefault("created_at", datetime.now().astimezone())
                    normalized.append(item)
                connection.execute(metadata["user"].insert(), normalized)
        logger.info("Imported the legacy B-335 tenant/user checkpoint into the full projection.")
        return True

    def mark_dirty(self):
        if not self._restoring:
            self._dirty = True

    def checkpoint_if_dirty(self, force=False):
        if not (force or self._dirty):
            return None
        with self._lock:
            tables = {}
            with self.engine.connect() as connection:
                for table in self.db.metadata.sorted_tables:
                    rows = connection.execute(table.select()).mappings()
                    tables[table.name] = [
                        {key: _encode(value) for key, value in dict(row).items()}
                        for row in rows
                    ]
            cid = self.backend.replace_relational_state(tables)
            self._dirty = False
            return cid

    @property
    def dirty(self):
        return self._dirty

    def install_commit_tracking(self):
        projection = self

        def on_commit(connection):
            projection.mark_dirty()

        event.listen(self.engine, "commit", on_commit)
        return on_commit

    def start_checkpoint_loop(self, interval_seconds=2.0):
        """Coalesce bursts of commits into one encrypted IPFS snapshot."""
        if self._checkpoint_loop_started:
            return
        self._checkpoint_loop_started = True

        def run():
            while True:
                time_module.sleep(interval_seconds)
                try:
                    self.checkpoint_if_dirty()
                except Exception:
                    logger.exception("Failed to build the pending IPFS checkpoint")

        threading.Thread(
            target=run, name="serviceops-ipfs-checkpointer", daemon=True,
        ).start()
