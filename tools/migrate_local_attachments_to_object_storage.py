"""Migrates existing attachments from the local uploads volume to
S3-compatible object storage for a deployment enabling OBJECT_STORAGE_*
after already running with local-volume storage for a while (B-052's
disclosed "no supported local-to-S3 migration path" gap).

Idempotent and safe by design: for each FileAttachment whose file still
exists locally, the object is uploaded and its SHA-256 is verified against
the database record's *before* the local copy is removed -- a failed or
mismatched upload leaves the local file in place and the row untouched, so
the app keeps working from local storage for that attachment until a
re-run succeeds. Attachments already missing locally (already migrated by
a prior run, or never existed) are skipped, not treated as an error, so
re-running after a partial run is always safe.

Usage: python3 -m tools.migrate_local_attachments_to_object_storage [--dry-run]
Requires OBJECT_STORAGE_* configured exactly as the running application uses them.
"""
import argparse
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import current_app

from app import FileAttachment, create_app, db, object_storage_client, object_storage_enabled


def migrate(dry_run=False):
    if not object_storage_enabled():
        raise SystemExit("OBJECT_STORAGE_BUCKET is not set -- nothing to migrate to.")
    # Same source of truth save_ticket_attachment()/attachment_download() use
    # for the local uploads path -- not the OS environment directly, which a
    # test app-context configures differently (found by this tool's own
    # regression tests failing against the wrong directory).
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    bucket = os.environ["OBJECT_STORAGE_BUCKET"]
    client = object_storage_client()
    migrated, skipped_missing, failed = 0, 0, 0
    for attachment in FileAttachment.query.order_by(FileAttachment.id).all():
        local_path = os.path.join(upload_folder, attachment.stored_name)
        if not os.path.exists(local_path):
            skipped_missing += 1
            continue
        if dry_run:
            print(f"would migrate: {attachment.stored_name} ({attachment.size_bytes} bytes)")
            migrated += 1
            continue
        try:
            client.upload_file(
                local_path, bucket, attachment.stored_name,
                ExtraArgs={"ContentType": attachment.mime_type or "application/octet-stream"},
            )
            # Verify by downloading and re-hashing rather than trusting the
            # upload call's own success -- the same "don't trust, verify"
            # discipline this project's recovery-manifest tooling already
            # uses for backups.
            response = client.get_object(Bucket=bucket, Key=attachment.stored_name)
            digest = hashlib.sha256()
            for chunk in response["Body"].iter_chunks(65536):
                digest.update(chunk)
            if attachment.sha256 and digest.hexdigest() != attachment.sha256:
                print(f"FAILED (checksum mismatch after upload, local copy kept): {attachment.stored_name}")
                failed += 1
                continue
        except Exception as error:
            print(f"FAILED ({error}, local copy kept): {attachment.stored_name}")
            failed += 1
            continue
        os.remove(local_path)
        migrated += 1
        print(f"migrated: {attachment.stored_name}")
    print(f"\nMigrated: {migrated}  Already migrated/missing locally: {skipped_missing}  Failed: {failed}")
    return 0 if failed == 0 else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="List what would migrate without uploading or deleting anything.")
    args = parser.parse_args()
    app = create_app()
    with app.app_context():
        return migrate(dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
