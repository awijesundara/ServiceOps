"""StorageBackend: the seam between ServiceOps' business logic and
wherever data actually lives.

Two implementations exist: `postgres_backend.PostgresStorageBackend` (a
thin wrapper around today's SQLAlchemy models -- no behavior change) and
`ipfs_backend.IPFSStorageBackend` (new, for the optional database-less
deployment mode). Both satisfy the attachment interface so callers don't need
to know which one is active.

IPFS mode preserves the existing domain/query layer through a volatile
relational projection restored from and checkpointed to IPFS. IPFS also exposes a separate, bounded legacy identity API for checkpoint migration;
attachments use the explicit methods below.
"""
from abc import ABC, abstractmethod


class StorageBackend(ABC):
    # -- File attachments ------------------------------------------------
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
