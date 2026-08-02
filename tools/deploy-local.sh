#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
[[ -f "$ENV_FILE" ]] || { echo "ServiceOps is not installed: $ENV_FILE is missing." >&2; exit 1; }

mode="$(awk -F= '/^DEPLOYMENT_MODE=/{value=$2; gsub(/^[[:space:]\"]+|[[:space:]\"]+$/, "", value); print value}' "$ENV_FILE" | tail -1)"
compose_file="$ROOT_DIR/compose.yaml"
[[ "$mode" == "external" ]] && compose_file="$ROOT_DIR/compose.external-db.yaml"
compose=(docker compose --env-file "$ENV_FILE" -f "$compose_file")

echo "Validating the local Compose configuration..."
"${compose[@]}" config --quiet
echo "Building the current ServiceOps source..."
"${compose[@]}" build app worker
echo "Recreating the local test deployment..."
if [[ "$mode" != "external" ]]; then
  # Ensure the database exists, but never recreate a running database merely
  # because application source changed.
  "${compose[@]}" up -d --no-recreate db
fi
"${compose[@]}" up -d --no-deps --force-recreate app

port="$(awk -F= '/^APP_PORT=/{value=$2; gsub(/^[[:space:]\"]+|[[:space:]\"]+$/, "", value); print value}' "$ENV_FILE" | tail -1)"
health_url="http://127.0.0.1:${port:-8080}/health"
for attempt in $(seq 1 60); do
  if response="$(curl -fsS "$health_url" 2>/dev/null)"; then
    "${compose[@]}" up -d --no-deps --force-recreate worker
    echo "$response"
    echo "Local ServiceOps update is healthy at $health_url"
    "${compose[@]}" ps app worker db 2>/dev/null || "${compose[@]}" ps app worker
    exit 0
  fi
  sleep 2
done

echo "ServiceOps did not become healthy within 120 seconds." >&2
"${compose[@]}" ps >&2
"${compose[@]}" logs --tail=120 app worker >&2
exit 1
