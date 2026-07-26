"""Create and verify ServiceOps recovery sets and isolated restored state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse


RECOVERY_SUFFIX = "_recovery_rehearsal"
UPGRADE_SUFFIX = "_upgrade_rehearsal"
MANIFEST_VERSION = 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact(path: Path) -> dict[str, object]:
    return {
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def create_manifest(args: argparse.Namespace) -> int:
    dump = Path(args.database).resolve(strict=True)
    uploads = Path(args.uploads).resolve(strict=True)
    if dump.parent != uploads.parent:
        raise ValueError("Recovery-set artifacts must share one directory.")
    manifest = {
        "schema": "serviceops-recovery-set",
        "version": MANIFEST_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "backup_started_at": args.started_at,
        "backup_completed_at": args.completed_at,
        "application_image": args.application_image,
        "database": artifact(dump),
        "uploads": artifact(uploads),
        "capabilities": {
            "logical_database_restore": True,
            "attachment_restore": True,
            "point_in_time_recovery": False,
        },
        "pitr_notice": (
            "This pg_dump recovery set is a logical backup and is not a "
            "PostgreSQL base backup plus continuous WAL archive."
        ),
    }
    output = Path(args.output)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    os.chmod(output, 0o600)
    print(output.resolve())
    return 0


def load_and_verify_manifest(path: Path) -> tuple[dict[str, object], Path, Path]:
    manifest = json.loads(path.read_text())
    if (
        manifest.get("schema") != "serviceops-recovery-set"
        or manifest.get("version") != MANIFEST_VERSION
    ):
        raise ValueError("Unsupported recovery-set manifest.")
    resolved: list[Path] = []
    for key in ("database", "uploads"):
        record = manifest.get(key)
        if not isinstance(record, dict) or set(record) != {
            "name", "sha256", "size_bytes"
        }:
            raise ValueError(f"Invalid {key} artifact metadata.")
        name = record["name"]
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError(f"Unsafe {key} artifact name.")
        candidate = path.parent / name
        if not candidate.is_file():
            raise ValueError(f"Missing {key} artifact: {name}")
        if candidate.stat().st_size != record["size_bytes"]:
            raise ValueError(f"{key} artifact size does not match manifest.")
        if sha256_file(candidate) != record["sha256"]:
            raise ValueError(f"{key} artifact checksum does not match manifest.")
        resolved.append(candidate)
    return manifest, resolved[0], resolved[1]


def verify_manifest(args: argparse.Namespace) -> int:
    manifest, _, _ = load_and_verify_manifest(Path(args.manifest).resolve(strict=True))
    print(json.dumps({
        "manifest_valid": True,
        "created_at": manifest["created_at"],
        "logical_database_restore": True,
        "attachment_restore": True,
        "point_in_time_recovery": False,
    }, sort_keys=True))
    return 0


def safe_extract(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve(strict=True)
    _, _, archive = load_and_verify_manifest(manifest_path)
    destination = Path(args.destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"Unsafe upload archive path: {member.name}")
            if not (member.isdir() or member.isfile()):
                raise ValueError(f"Unsupported upload archive entry: {member.name}")
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise ValueError(f"Unreadable upload archive entry: {member.name}")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    print(json.dumps({"entries": len(members), "destination": str(destination)}))
    return 0


def validate_rehearsal_database(
    url: str, allowed_suffix: str = RECOVERY_SUFFIX
) -> str:
    parsed = urlparse(url.replace("postgresql+psycopg://", "postgresql://", 1))
    database = parsed.path.removeprefix("/")
    if parsed.scheme != "postgresql" or not database.endswith(allowed_suffix):
        raise ValueError(
            "Refusing recovery verification outside an isolated rehearsal database."
        )
    return database


def verify_database(args: argparse.Namespace) -> int:
    from alembic.config import Config as AlembicConfig
    from alembic.script import ScriptDirectory
    from sqlalchemy import text

    from app import FileAttachment, Tenant, create_app, db, verify_audit_chain

    suffix = RECOVERY_SUFFIX if args.purpose == "recovery" else UPGRADE_SUFFIX
    database = validate_rehearsal_database(os.environ["DATABASE_URL"], suffix)
    upload_root = Path(args.uploads).resolve(strict=True)
    app = create_app({"AUTO_MIGRATE_IN_TESTS": False})
    with app.app_context():
        expected_revision = ScriptDirectory.from_config(
            AlembicConfig("alembic.ini")
        ).get_current_head()
        actual_revision = db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
        if actual_revision != expected_revision:
            raise RuntimeError(
                f"Schema revision {actual_revision} is not head {expected_revision}."
            )
        attachment_count = 0
        attachment_bytes = 0
        for attachment in FileAttachment.query.order_by(FileAttachment.id):
            stored = upload_root / attachment.stored_name
            if not stored.is_file() or stored.stat().st_size != attachment.size_bytes:
                raise RuntimeError(
                    f"Attachment {attachment.id} is missing or has the wrong size."
                )
            attachment_count += 1
            attachment_bytes += attachment.size_bytes
        tenants = Tenant.query.order_by(Tenant.id).all()
        audit_results = [verify_audit_chain(tenant.id) for tenant in tenants]
        if any(not result["valid"] for result in audit_results):
            raise RuntimeError("Restored audit integrity verification failed.")
        table_count = db.session.execute(text(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = 'public'"
        )).scalar_one()
        health = app.test_client().get("/health")
        if health.status_code != 200 or health.get_json() != {"status": "ok"}:
            raise RuntimeError("Candidate application health verification failed.")
    print(json.dumps({
        "database": database,
        "schema_revision": actual_revision,
        "table_count": table_count,
        "tenant_count": len(tenants),
        "audit_chains_valid": True,
        "attachment_count": attachment_count,
        "attachment_bytes": attachment_bytes,
        "attachments_valid": True,
        "application_health": True,
    }, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-manifest")
    create.add_argument("--database", required=True)
    create.add_argument("--uploads", required=True)
    create.add_argument("--output", required=True)
    create.add_argument("--started-at", required=True)
    create.add_argument("--completed-at", required=True)
    create.add_argument("--application-image", required=True)
    create.set_defaults(function=create_manifest)
    verify = commands.add_parser("verify-manifest")
    verify.add_argument("manifest")
    verify.set_defaults(function=verify_manifest)
    extract = commands.add_parser("extract-uploads")
    extract.add_argument("manifest")
    extract.add_argument("destination")
    extract.set_defaults(function=safe_extract)
    database = commands.add_parser("verify-database")
    database.add_argument("--uploads", required=True)
    database.add_argument(
        "--purpose", choices=("recovery", "upgrade"), default="recovery"
    )
    database.set_defaults(function=verify_database)
    return root


def main() -> int:
    args = parser().parse_args()
    return args.function(args)


if __name__ == "__main__":
    raise SystemExit(main())
