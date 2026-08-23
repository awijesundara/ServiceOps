#!/usr/bin/env bash
# Standards-conscious one-command initialization for an installed host package.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo: sudo serviceops setup [options]" >&2; exit 1; }
[[ "$ROOT_DIR" == "/opt/serviceops" ]] || {
  echo "serviceops setup is only available from an installed OS package." >&2
  exit 2
}
command -v systemctl >/dev/null || { echo "systemd is required for packaged host setup." >&2; exit 1; }
command -v docker >/dev/null || { echo "Docker Engine is not installed; install the RPM through DNF so dependencies are resolved." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "The Docker Compose plugin is required." >&2; exit 1; }

systemctl enable --now docker.service
"$ROOT_DIR/tools/install/server.sh" "$@"
systemctl enable --now serviceops.service
systemctl enable --now serviceops-health.timer serviceops-backup.timer

echo
echo "ServiceOps infrastructure is configured."
echo "  Application: systemctl status serviceops"
echo "  Health checks: systemctl list-timers serviceops-health.timer"
echo "  Backups: systemctl list-timers serviceops-backup.timer"
echo "  Data: Docker volume serviceops_postgres_data"
echo "  Recovery sets: /var/lib/serviceops/backups"
