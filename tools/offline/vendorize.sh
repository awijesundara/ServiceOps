#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: SERVICEOPS_IMAGE=ghcr.io/owner/serviceops-server@sha256:<digest> \
       [OFFLINE_PLATFORM=linux/amd64] tools/offline/vendorize.sh

Creates tools/offline/vendor.tar.gz on an internet-connected preparation host.
SERVICEOPS_IMAGE must be the immutable, verified image from a stable release.
EOF
}

if [[ "${1:-}" == "--help" ]]; then usage; exit 0; fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OFFLINE_DIR="$ROOT_DIR/tools/offline"
OUTPUT_DIR="$OFFLINE_DIR/vendor"
ARCHIVE="$OFFLINE_DIR/vendor.tar.gz"
IMAGE_LIST="$OFFLINE_DIR/docker-images.txt"
PLATFORM="${OFFLINE_PLATFORM:-linux/amd64}"
APP_IMAGE="${SERVICEOPS_IMAGE:-}"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 1; }
[[ "$APP_IMAGE" =~ ^[^[:space:]]+@sha256:[0-9a-f]{64}$ ]] || {
  echo "SERVICEOPS_IMAGE must be an immutable image@sha256:digest reference" >&2
  exit 1
}

STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/serviceops-offline.XXXXXX")"
CHECKSUM_FILE="${STAGING_DIR}.SHA256SUMS"
trap 'rm -rf "$STAGING_DIR"; rm -f "$CHECKSUM_FILE"' EXIT
mkdir -p "$STAGING_DIR/images"
: > "$STAGING_DIR/images.lock"

save_image() {
  local image="$1" safe_name archive
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || {
    echo "Refusing mutable image reference: $image" >&2
    exit 1
  }
  safe_name="$(printf '%s' "$image" | tr '/:@' '____')"
  archive="images/${safe_name}.tar"
  docker pull --platform "$PLATFORM" "$image"
  docker image inspect "$image" >/dev/null
  docker save --output "$STAGING_DIR/$archive" "$image"
  printf '%s\t%s\n' "$image" "$archive" >> "$STAGING_DIR/images.lock"
}

save_image "$APP_IMAGE"
while IFS= read -r image || [[ -n "$image" ]]; do
  image="${image%%#*}"
  image="$(printf '%s' "$image" | xargs)"
  [[ -z "$image" ]] || save_image "$image"
done < "$IMAGE_LIST"

cp "$ROOT_DIR/VERSION" "$STAGING_DIR/VERSION"
printf '%s\n' "$PLATFORM" > "$STAGING_DIR/PLATFORM"
(
  cd "$STAGING_DIR"
  find . -type f -print0 | sort -z | xargs -0 sha256sum > "$CHECKSUM_FILE"
  mv "$CHECKSUM_FILE" SHA256SUMS
  sha256sum --check SHA256SUMS
)

rm -rf "$OUTPUT_DIR" "$ARCHIVE"
mv "$STAGING_DIR" "$OUTPUT_DIR"
trap - EXIT
tar -C "$OFFLINE_DIR" -czf "$ARCHIVE" vendor
echo "Created checksum-verified offline bundle: $ARCHIVE"
