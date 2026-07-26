"""Generate deterministic source/dependency evidence for a ServiceOps release."""
import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tracked_files():
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, check=True, capture_output=True
    )
    return sorted(
        ROOT / value.decode()
        for value in result.stdout.split(b"\0") if value
        if (ROOT / value.decode()).is_file()
        and not value.decode().startswith("release-evidence/")
    )


def dependencies():
    components = []
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, version = line.split("==", 1)
        components.append({
            "type": "library", "name": name, "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}",
        })
    return components


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--output")
    args = parser.parse_args()
    files = {
        str(path.relative_to(ROOT)): sha256(path)
        for path in tracked_files()
    }
    payload = {
        "schema": "serviceops.release-evidence.v1",
        "version": args.version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout.strip(),
        "git_dirty": bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout.strip()),
        "image": args.image or None,
        "source_files": files,
        "source_manifest_sha256": hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "sbom": {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": dependencies(),
        },
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
