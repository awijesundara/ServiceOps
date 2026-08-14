"""Encrypted checkpoint serialization for IPFSStorageBackend's in-memory
state.

Per the storage-mode plan, IPFS mode keeps no local index/database of any
kind -- all state lives in memory, rebuilt at boot from the latest
checkpoint object on IPFS (resolved via one small IPNS pointer). A
checkpoint is just "the in-memory state, serialized and encrypted." This
module only does that serialize/encrypt/decrypt step; IPFSStorageBackend
owns fetching/publishing the checkpoint via IPFSClient.

Pure and storage-agnostic (no Flask, no IPFS client) so it's directly
unit-testable, matching the style of the other serviceops_core/ modules
that take data as arguments (config_schema.py, security.py, etc).
"""
import json

from cryptography.fernet import Fernet


def serialize_checkpoint(state):
    """`state` is a plain JSON-serializable dict (e.g. {"file_index": {...},
    "written_at": "..."}). Returns encrypted bytes ready to add to IPFS."""
    return json.dumps(state, separators=(",", ":")).encode()


def encrypt_checkpoint(state, key):
    return Fernet(key).encrypt(serialize_checkpoint(state))


def decrypt_checkpoint(data_bytes, key):
    plaintext = Fernet(key).decrypt(data_bytes)
    return json.loads(plaintext)


def derive_checkpoint_key(settings_encryption_key, secret_key):
    """Same fallback logic as serviceops_models.settings_cipher(), without
    the Flask current_app dependency, so IPFS mode's checkpoint encryption
    reuses the same key material an operator already manages today."""
    if settings_encryption_key:
        return settings_encryption_key.encode() if isinstance(settings_encryption_key, str) else settings_encryption_key
    import base64
    import hashlib
    digest = hashlib.sha256(secret_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)
