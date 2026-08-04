#!/usr/bin/env bash
# Instant rollback for the blue/green topology: the slot that was active
# before the last deploy is never stopped by tools/blue_green_deploy.sh, so
# rolling back is just another graceful `nginx -s reload` pointed at it --
# no image pull, no migration, no container recreation, no dropped
# connections. Safe to run any time both slots are up; refuses if the
# "previous" slot isn't actually running.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
COMPOSE_FILE="$ROOT_DIR/compose.blue-green.yaml"
[[ -f "$ENV_FILE" ]] || { echo "ServiceOps is not installed. Missing .env." >&2; exit 2; }

set -a
source "$ENV_FILE"
set +a
: "${ACTIVE_APP_SLOT:?ACTIVE_APP_SLOT (blue|green) is required in .env}"

case "$ACTIVE_APP_SLOT" in
  blue) PREVIOUS_SLOT=green ;;
  green) PREVIOUS_SLOT=blue ;;
  *) echo "✗ ACTIVE_APP_SLOT must be 'blue' or 'green', got: $ACTIVE_APP_SLOT" >&2; exit 2 ;;
esac
PREVIOUS_SERVICE="app_${PREVIOUS_SLOT}"
PREVIOUS_IMAGE_VAR="SERVICEOPS_IMAGE_$(echo "$PREVIOUS_SLOT" | tr '[:lower:]' '[:upper:]')"
PREVIOUS_IMAGE="${!PREVIOUS_IMAGE_VAR:?$PREVIOUS_IMAGE_VAR is required in .env}"

COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

cid="$("${COMPOSE[@]}" ps -q "$PREVIOUS_SERVICE")"
[[ -n "$cid" ]] || {
  echo "✗ $PREVIOUS_SERVICE is not running -- nothing to roll back to. Deploy a known-good image with ./serviceops deploy instead." >&2
  exit 1
}
status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$cid" 2>/dev/null)"
[[ "$status" == "healthy" || "$status" == "no-healthcheck" ]] || {
  echo "✗ $PREVIOUS_SERVICE is running but not healthy ($status). Rolling back to it would just trade one outage for another." >&2
  exit 1
}

echo "Rolling back: $ACTIVE_APP_SLOT -> $PREVIOUS_SLOT ($PREVIOUS_IMAGE)"
"${COMPOSE[@]}" exec -T -e ACTIVE_APP_SLOT="$PREVIOUS_SERVICE" nginx sh -c \
  'envsubst "\$ACTIVE_APP_SLOT" < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf && nginx -t && nginx -s reload'

echo "Verifying health through the public port..."
port="${APP_PORT:-8080}"
ok=false
for _ in $(seq 1 15); do
  if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
    ok=true
    break
  fi
  sleep 2
done
[[ "$ok" == true ]] || {
  echo "✗ Public health check failed after rollback reload. Manual intervention required: docker compose -f $COMPOSE_FILE ps" >&2
  exit 1
}

tmp_env="$(mktemp "$ROOT_DIR/.env.rollback.XXXXXX")"
awk -v slot="$PREVIOUS_SLOT" -v img="$PREVIOUS_IMAGE" '
  /^ACTIVE_APP_SLOT=/ { print "ACTIVE_APP_SLOT=" slot; next }
  /^SERVICEOPS_IMAGE_ACTIVE=/ { print "SERVICEOPS_IMAGE_ACTIVE=" img; next }
  { print }
' "$ENV_FILE" >"$tmp_env"
chmod 600 "$tmp_env"
mv "$tmp_env" "$ENV_FILE"

echo "Recreating the worker on the rolled-back image..."
set -a
source "$ENV_FILE"
set +a
unset SERVICEOPS_IMAGE_BLUE SERVICEOPS_IMAGE_GREEN SERVICEOPS_IMAGE_ACTIVE
"${COMPOSE[@]}" up -d --no-deps --force-recreate worker || true

echo "Rollback complete. Active slot is now: $PREVIOUS_SLOT ($PREVIOUS_IMAGE)"
