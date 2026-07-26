import argparse
import io
import json
import tarfile
from pathlib import Path

import pytest

from tools.recovery_verify import (
    UPGRADE_SUFFIX,
    create_manifest,
    load_and_verify_manifest,
    safe_extract,
    validate_rehearsal_database,
)


def recovery_set(tmp_path: Path) -> Path:
    dump = tmp_path / "serviceops-test.dump"
    uploads = tmp_path / "serviceops-uploads-test.tar.gz"
    manifest = tmp_path / "serviceops-test.manifest.json"
    dump.write_bytes(b"database")
    with tarfile.open(uploads, "w:gz") as archive:
        payload = b"attachment"
        member = tarfile.TarInfo("./evidence.txt")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    create_manifest(argparse.Namespace(
        database=str(dump),
        uploads=str(uploads),
        output=str(manifest),
        started_at="2026-07-26T00:00:00Z",
        completed_at="2026-07-26T00:00:01Z",
        application_image="serviceops:test",
    ))
    return manifest


def test_recovery_manifest_detects_tampering(tmp_path):
    manifest = recovery_set(tmp_path)
    data, dump, _ = load_and_verify_manifest(manifest)
    assert data["capabilities"]["point_in_time_recovery"] is False
    dump.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="size does not match|checksum"):
        load_and_verify_manifest(manifest)


def test_upload_archive_is_safely_extracted(tmp_path):
    manifest = recovery_set(tmp_path)
    destination = tmp_path / "restored"
    safe_extract(argparse.Namespace(
        manifest=str(manifest),
        destination=str(destination),
    ))
    assert (destination / "evidence.txt").read_bytes() == b"attachment"


def test_upload_archive_rejects_path_traversal(tmp_path):
    manifest = recovery_set(tmp_path)
    data = json.loads(manifest.read_text())
    archive = tmp_path / data["uploads"]["name"]
    with tarfile.open(archive, "w:gz") as tar:
        payload = b"escape"
        member = tarfile.TarInfo("../escape.txt")
        member.size = len(payload)
        tar.addfile(member, io.BytesIO(payload))
    from tools.recovery_verify import artifact
    data["uploads"] = artifact(archive)
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Unsafe upload archive path"):
        safe_extract(argparse.Namespace(
            manifest=str(manifest),
            destination=str(tmp_path / "restored"),
        ))


def test_recovery_database_name_guard():
    assert validate_rehearsal_database(
        "postgresql+psycopg://user:secret@db/serviceops_recovery_rehearsal"
    ) == "serviceops_recovery_rehearsal"
    with pytest.raises(ValueError, match="isolated rehearsal"):
        validate_rehearsal_database(
            "postgresql+psycopg://user:secret@db/serviceops"
        )
    assert validate_rehearsal_database(
        "postgresql+psycopg://user:secret@db/serviceops_upgrade_rehearsal",
        UPGRADE_SUFFIX,
    ) == "serviceops_upgrade_rehearsal"
