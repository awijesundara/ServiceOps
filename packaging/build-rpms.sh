#!/usr/bin/env bash
# Reproducibly build the noarch control-plane RPM for supported Enterprise Linux majors.
set -Eeuo pipefail

VERSION="${1:?Usage: build-rpms.sh VERSION [SOURCE_ARCHIVE]}"
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE="${2:-$ROOT_DIR/dist/serviceops-$VERSION.tar.gz}"
[[ -f "$ARCHIVE" ]] || { echo "Missing source archive: $ARCHIVE" >&2; exit 1; }
command -v docker >/dev/null || { echo "Docker is required for clean RPM builds." >&2; exit 1; }

mkdir -p "$ROOT_DIR/dist/rpm"
targets=(
  "el8|rockylinux/rockylinux:8"
  "el9|rockylinux/rockylinux:9"
  "el10|rockylinux/rockylinux:10"
  "fc43|fedora:43"
  "fc44|fedora:44"
)
for target in "${targets[@]}"; do
  label="${target%%|*}"
  image="${target#*|}"
  output="$ROOT_DIR/dist/rpm/$label"
  rm -rf "$output"
  mkdir -p "$output"
  docker run --rm \
    -v "$ROOT_DIR:/workspace" -w /workspace "$image" bash -lc \
    "dnf install -y -q rpm-build systemd-rpm-macros && \
     rpmbuild -ta '/workspace/dist/serviceops-$VERSION.tar.gz' \
       --define '_topdir /tmp/rpmbuild' \
       --define '_rpmdir /workspace/dist/rpm/$label' \
       --define 'version $VERSION'"
done

find "$ROOT_DIR/dist/rpm" -type f -name '*.rpm' -print -exec sha256sum {} \;
