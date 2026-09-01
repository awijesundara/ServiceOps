#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/offline/build-offline.sh [path/to/vendor.tar.gz]

Verifies and loads a ServiceOps offline image bundle. It does not start the
application or create secrets. Run the normal `sudo serviceops setup` procedure
after configuring SERVICEOPS_IMAGE to the immutable reference in images.lock.
EOF
}

if [[ "${1:-}" == "--help" ]]; then usage; exit 0; fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OFFLINE_DIR="$ROOT_DIR/tools/offline"
ARCHIVE="${1:-$OFFLINE_DIR/vendor.tar.gz}"
VENDOR_DIR="$OFFLINE_DIR/vendor"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 1; }

if [[ -f "$ARCHIVE" ]]; then
  tar -tzf "$ARCHIVE" | while IFS= read -r entry; do
    [[ "$entry" != /* && "$entry" != *"../"* && "$entry" != ".." ]] || {
      echo "Unsafe archive path: $entry" >&2
      exit 1
    }
  done
  rm -rf "$VENDOR_DIR"
  tar -C "$OFFLINE_DIR" -xzf "$ARCHIVE"
fi

[[ -f "$VENDOR_DIR/SHA256SUMS" && -f "$VENDOR_DIR/images.lock" ]] || {
  echo "A complete vendor bundle was not found" >&2
  exit 1
}

(cd "$VENDOR_DIR" && sha256sum --check SHA256SUMS)
while IFS=$'\t' read -r image archive; do
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ && "$archive" == images/*.tar ]] || {
    echo "Invalid image lock entry" >&2
    exit 1
  }
  docker load --input "$VENDOR_DIR/$archive"
  docker image inspect "$image" >/dev/null
  echo "Verified loaded image: $image"
done < "$VENDOR_DIR/images.lock"

echo "Offline bundle verified and loaded. Configure .env SERVICEOPS_IMAGE from images.lock, then use the normal packaged setup and health checks."
