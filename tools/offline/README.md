# Offline deployment bundle

This tooling prepares a fail-closed transfer bundle for an air-gapped
ServiceOps server. The supported production path transfers the already tested,
signed, immutable release image plus its pinned PostgreSQL and optional Kubo
runtime images. It does not rebuild application source inside the air gap.

## Prepare on an internet-connected Linux host

Use the digest from the stable GitHub release and verify its provenance first:

```bash
gh attestation verify \
  oci://ghcr.io/awijesundara/serviceops-server@sha256:<release-digest> \
  --repo awijesundara/ServiceOps

SERVICEOPS_IMAGE=ghcr.io/awijesundara/serviceops-server@sha256:<release-digest> \
OFFLINE_PLATFORM=linux/amd64 \
  ./tools/offline/vendorize.sh
```

The script refuses mutable image tags. It saves the application, PostgreSQL,
and optional Kubo images, records their immutable references, and creates
portable SHA-256 checksums in `tools/offline/vendor.tar.gz`.

## Transfer and verify inside the air gap

Copy the archive using approved removable-media handling, malware scanning,
and chain-of-custody controls. On the target server:

```bash
./tools/offline/build-offline.sh /path/to/vendor.tar.gz
```

The loader rejects unsafe archive paths, verifies every transferred file before
loading anything, loads each image, and confirms every locked digest exists
locally. Set `SERVICEOPS_IMAGE` in `/etc/serviceops/serviceops.env` to the
application reference in `tools/offline/vendor/images.lock`, then follow the
normal RPM `serviceops setup`, systemd, `/health`, `/ready`, backup, and recovery
procedures in the main README.

## Boundaries

- The bundle contains images and checksums, never secrets or database data.
- The RPM and Docker Engine packages must come from the organization's approved
  offline OS repository and be verified using that repository's signing policy.
- Image signatures and GitHub attestations must be verified on the connected
  preparation host; checksum verification protects the subsequent transfer.
- The platform defaults to `linux/amd64`. Build a separate bundle for each target
  architecture and never mix image archives between platforms.
