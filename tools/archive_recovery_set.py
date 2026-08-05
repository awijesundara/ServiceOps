"""Upload one verified recovery set to S3-compatible immutable storage."""
import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3

from tools.recovery_verify import load_and_verify_manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    args = parser.parse_args()
    manifest_path = Path(args.manifest).resolve(strict=True)
    manifest, database, uploads = load_and_verify_manifest(manifest_path)
    bucket = os.environ["BACKUP_ARCHIVE_BUCKET"]
    prefix = os.getenv("BACKUP_ARCHIVE_PREFIX", "serviceops").strip("/")
    retain_days = int(os.getenv("BACKUP_RETENTION_DAYS", "35"))
    require_lock = os.getenv("BACKUP_REQUIRE_OBJECT_LOCK", "true").lower() == "true"
    client = boto3.client(
        "s3", endpoint_url=os.getenv("BACKUP_ARCHIVE_ENDPOINT") or None,
        region_name=os.getenv("BACKUP_ARCHIVE_REGION", "us-east-1"),
        aws_access_key_id=os.getenv("BACKUP_ARCHIVE_ACCESS_KEY") or None,
        aws_secret_access_key=os.getenv("BACKUP_ARCHIVE_SECRET_KEY") or None,
    )
    if require_lock:
        configuration = client.get_object_lock_configuration(Bucket=bucket)
        if configuration.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise RuntimeError("Backup bucket does not have S3 Object Lock enabled.")
    base = f"{prefix}/{manifest['created_at'].replace(':', '').replace('+00:00', 'Z')}"
    retained_until = datetime.now(timezone.utc) + timedelta(days=retain_days)
    uploaded = []
    for path in (database, uploads, manifest_path):
        record = next((manifest[name] for name in ("database", "uploads") if manifest[name]["name"] == path.name), None)
        extra = {"Metadata": {"recovery-set": manifest_path.stem}}
        if record:
            extra["ChecksumSHA256"] = __import__("base64").b64encode(bytes.fromhex(record["sha256"])).decode()
        if require_lock:
            extra.update(ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=retained_until)
        kms_key = os.getenv("BACKUP_ARCHIVE_KMS_KEY", "")
        if kms_key:
            extra.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=kms_key)
        client.upload_file(str(path), bucket, f"{base}/{path.name}", ExtraArgs=extra)
        uploaded.append(f"s3://{bucket}/{base}/{path.name}")
    print(json.dumps({"archived": True, "immutable_until": retained_until.isoformat() if require_lock else None,
                      "objects": uploaded}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
