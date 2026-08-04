#!/usr/bin/env bash
# One-time conversion from the default single-instance compose.yaml topology
# to the opt-in zero-downtime compose.blue-green.yaml topology. Adds the
# additional .env vars blue-green needs (both slots start on the currently
# running image, blue active), sets DEPLOYMENT_MODE=blue-green, brings up
# nginx + the second slot, then verifies the public port still serves
# correctly through nginx before declaring success. Safe to run against a
# live bundled install: the db/uploads/logs volumes are unchanged (same
# volume names in both compose files), and the plain "app" container from
# compose.yaml is left running and reachable on its own until you
# explicitly stop it -- this only adds the new topology alongside it.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
[[ -f "$ENV_FILE" ]] || { echo "ServiceOps is not installed. Missing .env." >&2; exit 2; }

set -a
source "$ENV_FILE"
set +a
CURRENT_MODE="${DEPLOYMENT_MODE:-bundled}"
[[ "$CURRENT_MODE" == "bundled" ]] || {
  echo "✗ blue-green bootstrap currently supports converting from DEPLOYMENT_MODE=bundled only (got: $CURRENT_MODE)." >&2
  exit 2
}
CURRENT_IMAGE="${SERVICEOPS_IMAGE:?SERVICEOPS_IMAGE is required in .env}"

if grep -q '^ACTIVE_APP_SLOT=' "$ENV_FILE"; then
  echo "✗ .env already has ACTIVE_APP_SLOT set -- blue-green looks already bootstrapped. Use ./serviceops deploy directly." >&2
  exit 2
fi

echo "Converting to blue-green: both slots start on $CURRENT_IMAGE, blue active."
{
  echo "DEPLOYMENT_MODE=blue-green"
  echo "SERVICEOPS_IMAGE_BLUE=$CURRENT_IMAGE"
  echo "SERVICEOPS_IMAGE_GREEN=$CURRENT_IMAGE"
  echo "SERVICEOPS_IMAGE_ACTIVE=$CURRENT_IMAGE"
  echo "ACTIVE_APP_SLOT=blue"
} >>"$ENV_FILE"

COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$ROOT_DIR/compose.blue-green.yaml")

echo "Starting the blue-green stack (app_blue, app_green, nginx) alongside the existing containers..."
"${COMPOSE[@]}" up -d --remove-orphans db app_blue app_green nginx worker

echo "Verifying health through nginx on the public port..."
port="${APP_PORT:-8080}"
ok=false
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
    ok=true
    break
  fi
  sleep 2
done
if [[ "$ok" != true ]]; then
  echo "✗ nginx front door did not become healthy. Bootstrap left DEPLOYMENT_MODE=blue-green in .env -- fix the issue and rerun, or revert .env manually to go back to the single-instance topology." >&2
  exit 1
fi

echo "Blue-green bootstrap complete. Active slot: blue ($CURRENT_IMAGE)."
echo "Once you've confirmed everything looks right, stop the old standalone container: docker compose -f $ROOT_DIR/compose.yaml stop app"
echo "Deploy zero-downtime updates from here on with: ./serviceops deploy <image>"
