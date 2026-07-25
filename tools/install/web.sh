#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_DIR="$ROOT_DIR/.installer-state"
INSTALLER_PORT="${INSTALLER_PORT:-8090}"
INSTALLER_BIND_ADDRESS="${INSTALLER_BIND_ADDRESS:-127.0.0.1}"
INSTALLER_SECRET="${INSTALLER_SECRET:-$(openssl rand -hex 32)}"
export INSTALLER_PORT INSTALLER_BIND_ADDRESS INSTALLER_SECRET
export HOST_UID="$(id -u)" HOST_GID="$(id -g)"
INSTALLER=(docker compose -f "$ROOT_DIR/compose.installer.yaml")

cleanup() {
  "${INSTALLER[@]}" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null || { echo "Docker is required."; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker Engine is not running."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required."; exit 1; }
command -v openssl >/dev/null || { echo "OpenSSL is required."; exit 1; }
command -v curl >/dev/null || { echo "curl is required."; exit 1; }

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
rm -f "$STATE_DIR/deploy-request.json" "$STATE_DIR/deployment-result.json"

disk_kb="$(df -Pk "$ROOT_DIR" | awk 'NR==2 {print $4}')"
memory_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
if (( disk_kb < 5242880 )); then
  host_ok=false
  host_message="Host preflight failed: at least 5 GB free disk is required."
else
  host_ok=true
  host_message="Docker, Compose, filesystem permissions, and disk capacity passed."
fi
printf '{"ok":%s,"message":"%s","details":"Free disk: %s MB; Docker memory: %s MB"}\n' \
  "$host_ok" "$host_message" "$((disk_kb/1024))" "$((memory_bytes/1024/1024))" \
  > "$STATE_DIR/host-preflight.json"
chmod 600 "$STATE_DIR/host-preflight.json"

"${INSTALLER[@]}" up --build -d
echo
echo "ServiceOps Installation Center: http://${INSTALLER_BIND_ADDRESS}:${INSTALLER_PORT}"
echo "Keep this terminal open while the web installer deploys ServiceOps."

while [[ ! -f "$STATE_DIR/deploy-request.json" ]]; do sleep 2; done

cp "$STATE_DIR/serviceops.env" "$ROOT_DIR/.env"
chmod 600 "$ROOT_DIR/.env"
mode="$(sed -n 's/^DEPLOYMENT_MODE="\\([^"]*\\)"/\\1/p' "$ROOT_DIR/.env" | tail -1)"
if [[ "$mode" == "external" ]]; then
  compose_file="$ROOT_DIR/compose.external-db.yaml"
else
  compose_file="$ROOT_DIR/compose.yaml"
fi

printf '{"status":"deploying","message":"Building and starting ServiceOps"}\n' \
  > "$STATE_DIR/deployment-result.json"
if docker compose --env-file "$ROOT_DIR/.env" -f "$compose_file" up --build -d; then
  app_port="$(sed -n 's/^APP_PORT="\\([^"]*\\)"/\\1/p' "$ROOT_DIR/.env" | tail -1)"
  bind_address="$(sed -n 's/^BIND_ADDRESS="\\([^"]*\\)"/\\1/p' "$ROOT_DIR/.env" | tail -1)"
  health_host="$bind_address"
  [[ "$health_host" == "0.0.0.0" ]] && health_host="127.0.0.1"
  healthy=false
  for _ in {1..60}; do
    if curl -fsS "http://${health_host}:${app_port}/health" >/dev/null 2>&1; then healthy=true; break; fi
    sleep 2
  done
  if [[ "$healthy" == true ]]; then
    if [[ -f "$STATE_DIR/company-logo.png" ]]; then
      docker compose --env-file "$ROOT_DIR/.env" -f "$compose_file" cp \
        "$STATE_DIR/company-logo.png" app:/app/uploads/company-logo.png >/dev/null
    fi
    printf '{"status":"success","url":"http://%s:%s","message":"ServiceOps is healthy"}\n' \
      "$health_host" "$app_port" > "$STATE_DIR/deployment-result.json"
  else
    printf '{"status":"failed","message":"Containers started, but the health check did not pass. Run ./serviceops logs."}\n' \
      > "$STATE_DIR/deployment-result.json"
  fi
else
  printf '{"status":"failed","message":"Docker Compose could not start ServiceOps. Review the installer terminal output."}\n' \
    > "$STATE_DIR/deployment-result.json"
fi

echo "Deployment result is now visible in the Installation Center."
echo "Press Ctrl+C after reviewing it; ServiceOps will remain running."
while true; do sleep 30; done
