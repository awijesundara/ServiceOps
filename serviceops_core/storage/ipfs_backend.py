"""IPFS-backed storage: the optional, database-less deployment mode.

This first slice implements only file attachments end-to-end (the
storage-mode plan's "suggested first concrete slice") plus the
checkpoint boot/save mechanism that every future wave will reuse. Record
CRUD for ITIL entities (tickets, changes, CIs, ...) is a later wave and
raises NotImplementedError here on purpose -- see interface.py.

State model: `self._file_index` maps a caller-chosen storage key (e.g.
FileAttachment.stored_name) to its current IPFS CID. This is the entire
"database" this backend keeps, and it exists only in memory. At boot,
`load_checkpoint()` resolves the instance's IPNS name to the latest
checkpoint object, fetches and decrypts it, and populates `_file_index`
from it. Every write updates `_file_index` immediately (so reads stay
fast and don't round-trip to IPFS) and calls `save_checkpoint()`, which
re-serializes the whole index, encrypts it, adds it to IPFS, and
republishes the IPNS pointer -- so a restart only ever needs the single
latest checkpoint, not a replay of full history.

Every file's bytes are Fernet-encrypted (same key as the checkpoint)
before being added to IPFS, and decrypted on read -- see attach_file()'s
comment for why this isn't optional.
"""
import logging

from cryptography.fernet import Fernet

from .checkpoint import decrypt_checkpoint, encrypt_checkpoint
from .interface import StorageBackend
from .ipfs_client import IPFSClient

logger = logging.getLogger("serviceops.storage.ipfs")

CHECKPOINT_KEY_NAME = "serviceops-checkpoint"


class IPFSStorageBackend(StorageBackend):
    def __init__(self, api_url, checkpoint_encryption_key, client=None):
        self.client = client or IPFSClient(api_url)
        self._checkpoint_key = checkpoint_encryption_key
        self._file_index = {}
        self._checkpoint_name = None
        # Generic entity store, added for the login-only milestone (see
        # BACKLOG B-335): {entity_type: {id: {field: value, ...}}}. This is
        # the whole "database" for whichever entity types have been wired
        # up to it so far (currently: user, tenant) -- exists only in
        # memory, checkpointed to IPFS exactly like _file_index.
        self._entities = {}
        self._next_id = {}

    # -- Checkpoint boot/save --------------------------------------------
    def load_checkpoint(self):
        """Resolve the instance's IPNS pointer and load the latest
        checkpoint into memory. Safe to call on a fresh node with no
        checkpoint published yet -- starts with an empty index."""
        self._checkpoint_name = self.client.key_gen(CHECKPOINT_KEY_NAME)
        cid = self.client.name_resolve(self._checkpoint_name)
        if not cid:
            logger.info("No existing IPFS checkpoint found; starting with an empty index.")
            return
        try:
            encrypted = self.client.cat(cid)
            state = decrypt_checkpoint(encrypted, self._checkpoint_key)
        except Exception:
            logger.exception("Failed to load IPFS checkpoint %s; starting with an empty index.", cid)
            return
        self._file_index = state.get("file_index", {})
        # JSON round-trips dict keys as strings; entity ids and the
        # per-type next-id counters need to come back as ints.
        self._entities = {
            entity_type: {int(record_id): fields for record_id, fields in rows.items()}
            for entity_type, rows in state.get("entities", {}).items()
        }
        self._next_id = {
            entity_type: next_id for entity_type, next_id in state.get("next_id", {}).items()
        }
        logger.info(
            "Loaded IPFS checkpoint %s: %d file(s), %d entity type(s) indexed.",
            cid, len(self._file_index), len(self._entities),
        )

    def save_checkpoint(self):
        """Re-snapshot the full in-memory index to IPFS and republish the
        IPNS pointer. Called after every write in this first slice; a
        later wave can debounce this (time- or write-count based) once
        real usage volume makes synchronous republish-per-write too slow
        -- correctness first, then throughput.

        Found via live testing under compose.ipfs-demo.yaml (BACKLOG
        B-335): IPNS `name/publish` can intermittently take 30+ seconds
        even with allow-offline=true (observed on a failed-login lockout-
        counter update, which -- like every write in this slice -- called
        this method synchronously). A slow/failed publish must not fail
        the caller's actual operation or hang the request that long: the
        in-memory index this process holds is already updated and correct
        for THIS process regardless of whether the durable checkpoint
        publish below succeeds, so pin/publish failures are logged and
        swallowed here, not raised. A future wave's debounced/async
        checkpoint publisher removes the need for this trade-off; until
        then, a publish failure means a hard restart of this process could
        lose writes since the last successful checkpoint -- an accepted,
        disclosed risk of the login-only milestone, not a silent one."""
        if self._checkpoint_name is None:
            self._checkpoint_name = self.client.key_gen(CHECKPOINT_KEY_NAME)
        state = {
            "file_index": self._file_index,
            "entities": self._entities,
            "next_id": self._next_id,
        }
        encrypted = encrypt_checkpoint(state, self._checkpoint_key)
        cid = self.client.add_bytes(encrypted, filename="checkpoint")
        try:
            self.client.pin_add(cid)
            self.client.name_publish(cid, CHECKPOINT_KEY_NAME)
        except Exception:
            logger.exception(
                "Failed to publish IPFS checkpoint %s -- in-memory state is "
                "still current for this process, but a restart before the "
                "next successful publish would lose writes since the last "
                "one.", cid,
            )
        return cid

    # -- Generic record CRUD -----------------------------------------------
    # Implemented for the login-only milestone (user, tenant); other
    # entity types still raise NotImplementedError until their own
    # rollout wave -- see the storage-mode plan.
    _IMPLEMENTED_ENTITY_TYPES = {"user", "tenant"}

    def _require_implemented(self, entity_type):
        if entity_type not in self._IMPLEMENTED_ENTITY_TYPES:
            raise NotImplementedError(
                f"IPFSStorageBackend does not implement {entity_type!r} yet -- "
                "only file attachments, users, and tenants are implemented so far."
            )

    def get(self, entity_type, record_id):
        self._require_implemented(entity_type)
        row = self._entities.get(entity_type, {}).get(int(record_id))
        return dict(row) if row is not None else None

    def create(self, entity_type, **fields):
        self._require_implemented(entity_type)
        table = self._entities.setdefault(entity_type, {})
        record_id = self._next_id.get(entity_type, 0) + 1
        self._next_id[entity_type] = record_id
        row = {"id": record_id, **fields}
        table[record_id] = row
        self.save_checkpoint()
        return dict(row)

    def update(self, entity_type, record_id, **fields):
        self._require_implemented(entity_type)
        table = self._entities.setdefault(entity_type, {})
        row = table.get(int(record_id))
        if row is None:
            raise KeyError(f"No {entity_type} with id {record_id}")
        row.update(fields)
        self.save_checkpoint()
        return dict(row)

    def delete(self, entity_type, record_id):
        self._require_implemented(entity_type)
        table = self._entities.setdefault(entity_type, {})
        if table.pop(int(record_id), None) is not None:
            self.save_checkpoint()

    def query(self, entity_type, tenant_id, filters=None, order_by=None,
              limit=None, offset=None):
        self._require_implemented(entity_type)
        rows = list(self._entities.get(entity_type, {}).values())
        if tenant_id is not None:
            rows = [row for row in rows if row.get("tenant_id") == tenant_id]
        for field, op, value in (filters or []):
            if op == "eq":
                rows = [row for row in rows if row.get(field) == value]
            elif op == "in":
                rows = [row for row in rows if row.get(field) in value]
            else:
                raise NotImplementedError(f"IPFSStorageBackend.query() filter op {op!r} not implemented.")
        if order_by:
            field, _, direction = order_by.partition(" ")
            rows.sort(key=lambda row: row.get(field), reverse=direction.strip().lower() == "desc")
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        return [dict(row) for row in rows]

    def relate(self, entity_type, record_id, relation_name):
        raise NotImplementedError(f"IPFSStorageBackend.relate({entity_type!r}) not implemented yet.")

    def unit_of_work(self):
        raise NotImplementedError("IPFSStorageBackend.unit_of_work() not implemented yet.")

    def enforce_unique(self, entity_type, fields):
        # No caller needs this yet for user/tenant (login checks username
        # uniqueness itself via query()); file attachments don't need it
        # either (uuid4-prefixed names). A real per-entity check lands
        # with each entity's own rollout wave if/when it's needed.
        return None

    # -- File attachments: real, implemented in this slice. --------------
    def attach_file(self, path, data_bytes, content_type):
        # Encrypted before it ever leaves this process: public IPFS (or
        # any pinning service/gateway under IPFS_MODE=external) has no
        # access control of its own -- anyone who obtains a CID can fetch
        # its content directly, bypassing every ServiceOps authorization
        # check entirely. Confidentiality here comes only from encryption,
        # never from the CID being hard to guess. Found and fixed after a
        # live test showed a stored attachment's plaintext readable
        # straight off the (private, single-node) Kubo daemon, with no
        # app-level auth involved at all.
        encrypted = Fernet(self._checkpoint_key).encrypt(data_bytes)
        cid = self.client.add_bytes(encrypted, filename=path)
        self.client.pin_add(cid)
        self._file_index[path] = cid
        self.save_checkpoint()
        return cid

    def read_file(self, path, reference):
        cid = reference or self._file_index.get(path)
        if not cid:
            raise FileNotFoundError(path)
        encrypted = self.client.cat(cid)
        return Fernet(self._checkpoint_key).decrypt(encrypted), None

    def delete_file(self, path, reference):
        cid = reference or self._file_index.get(path)
        was_indexed = self._file_index.pop(path, None) is not None
        if cid:
            self.client.pin_rm(cid)
        if was_indexed:
            self.save_checkpoint()
