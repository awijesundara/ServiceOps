"""StorageBackend: the seam between ServiceOps' business logic and
wherever data actually lives.

Two implementations exist: `postgres_backend.PostgresStorageBackend` (a
thin wrapper around today's SQLAlchemy models -- no behavior change) and
`ipfs_backend.IPFSStorageBackend` (new, for the optional database-less
deployment mode). Both satisfy this same interface so callers don't need
to know which one is active.

This first slice only gives both backends real implementations of the
file-attachment methods (`attach_file`/`read_file`/`delete_file`) --
everything else raises NotImplementedError deliberately, since the
~571 existing `db.session`/`Model.query` call sites in app.py are migrated
to this interface in later waves, not all at once. The full method surface
is declared now so no wave requires a breaking interface change later.
"""
from abc import ABC, abstractmethod


class StorageBackend(ABC):
    # -- Generic record CRUD (future waves) -----------------------------
    @abstractmethod
    def get(self, entity_type, record_id):
        """Fetch one record by primary key, or None."""

    @abstractmethod
    def create(self, entity_type, **fields):
        """Create and return a new record."""

    @abstractmethod
    def update(self, entity_type, record_id, **fields):
        """Apply field changes to an existing record."""

    @abstractmethod
    def delete(self, entity_type, record_id):
        """Delete a record."""

    @abstractmethod
    def query(self, entity_type, tenant_id, filters=None, order_by=None,
              limit=None, offset=None):
        """List records of one type, tenant-scoped, with a small portable
        predicate DSL (not raw SQL) so both backends can implement it."""

    @abstractmethod
    def relate(self, entity_type, record_id, relation_name):
        """Resolve a named relationship (replaces ORM lazy-loading)."""

    @abstractmethod
    def unit_of_work(self):
        """Context manager giving atomic multi-record writes."""

    @abstractmethod
    def enforce_unique(self, entity_type, fields):
        """Declare a uniqueness constraint the backend must enforce."""

    # -- File attachments (implemented in this first slice) -------------
    @abstractmethod
    def attach_file(self, path, data_bytes, content_type):
        """Store file bytes under a caller-chosen storage key (`path`,
        e.g. FileAttachment.stored_name). Returns a backend-specific
        reference (a local path, an S3 key, or an IPFS CID) that the
        caller should persist and pass back to read_file/delete_file."""

    @abstractmethod
    def read_file(self, path, reference):
        """Return (bytes, content_type) for a previously stored file."""

    @abstractmethod
    def delete_file(self, path, reference):
        """Remove a previously stored file. Best-effort -- callers should
        not treat failure here as blocking (matches today's local-disk
        behavior, which never raises on a missing file)."""
