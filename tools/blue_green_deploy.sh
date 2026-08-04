#!/usr/bin/env bash
# Zero-downtime deploy for the opt-in blue/green topology (compose.blue-green.yaml).
#
# Steps: rehearse the migration + take a backup (same as tools/safe_update.sh) ->
# start the candidate image in the currently IDLE slot, alongside the still-serving
# active slot -> health-check the idle slot directly, bypassing nginx -> cut nginx
# over with a graceful `nginx -s reload` (no dropped connections, no container
# recreation) -> verify health through the actual public port -> only then update
# the worker and record the new active slot. The previously-active slot is never
# stopped, so a bad cutover is an instant `./serviceops rollback` away -- and
# because nginx is never touched until the new slot has already proven healthy on
# its own, a failure before cutover leaves production completely untouched.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
COMPOSE_FILE="$ROOT_DIR/compose.blue-green.yaml"
[[ -f "$ENV_FILE" ]] || { echo "ServiceOps is not installed. Missing .env." >&2; exit 2; }

TARGET_IMAGE="${1:?Usage: blue_green_deploy.sh <image>}"

set -a
source "$ENV_FILE"
set +a
: "${ACTIVE_APP_SLOT:?ACTIVE_APP_SLOT (blue|green) is required in .env -- run tools/blue_green_bootstrap.sh once first}"
: "${SERVICEOPS_IMAGE_BLUE:?SERVICEOPS_IMAGE_BLUE is required in .env}"
: "${SERVICEOPS_IMAGE_GREEN:?SERVICEOPS_IMAGE_GREEN is required in .env}"

case "$ACTIVE_APP_SLOT" in
  blue) IDLE_SLOT=green ;;
  green) IDLE_SLOT=blue ;;
  *) echo "✗ ACTIVE_APP_SLOT must be 'blue' or 'green', got: $ACTIVE_APP_SLOT" >&2; exit 2 ;;
esac
IDLE_SERVICE="app_${IDLE_SLOT}"
ACTIVE_SERVICE="app_${ACTIVE_APP_SLOT}"
IDLE_IMAGE_VAR="SERVICEOPS_IMAGE_$(echo "$IDLE_SLOT" | tr '[:lower:]' '[:upper:]')"

COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

echo "Active slot:  $ACTIVE_APP_SLOT ($ACTIVE_SERVICE)"
echo "Idle slot:    $IDLE_SLOT ($IDLE_SERVICE) <- deploying $TARGET_IMAGE here"

echo "Pulling candidate image for inspection..."
if ! docker pull "$TARGET_IMAGE"; then
  docker image inspect "$TARGET_IMAGE" >/dev/null 2>&1 || {
    echo "✗ $TARGET_IMAGE is not pullable and not present locally." >&2
    exit 1
  }
  echo "Registry pull failed; using the locally-present image (build-from-source deployment)." >&2
fi

migration_head() {
  "${COMPOSE[@]}" exec -T "$ACTIVE_SERVICE" python -c "
from app import create_app, db
from sqlalchemy import text
app = create_app()
with app.app_context():
    print(db.session.execute(text('SELECT version_num FROM alembic_version')).scalar())
" 2>/dev/null | tr -d '[:space:]'
}
current_head="$(migration_head || true)"
echo "Current migration head: ${current_head:-unknown}"

# The idle slot's image var must be updated in .env BEFORE rehearsal runs:
# rehearse-upgrade.sh's `docker compose run <service>` reads the image from
# that service's own definition (SERVICEOPS_IMAGE_BLUE/_GREEN), not a
# generic SERVICEOPS_IMAGE var, so the rehearsal would otherwise silently
# test the OLD image still sitting in .env instead of the actual candidate.
tmp_env="$(mktemp "$ROOT_DIR/.env.deploy.XXXXXX")"
awk -v var="$IDLE_IMAGE_VAR" -v img="$TARGET_IMAGE" '
  $0 ~ "^" var "=" { print var "=" img; next }
  { print }
' "$ENV_FILE" >"$tmp_env"
chmod 600 "$tmp_env"
mv "$tmp_env" "$ENV_FILE"
unset SERVICEOPS_IMAGE_BLUE SERVICEOPS_IMAGE_GREEN

echo "Rehearsing the migration against an isolated copy of the production database..."
SERVICEOPS_IMAGE="$TARGET_IMAGE" \
  REHEARSE_COMPOSE_FILE="$COMPOSE_FILE" REHEARSE_APP_SERVICE="$IDLE_SERVICE" \
  "$ROOT_DIR/tools/rehearse-upgrade.sh"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
echo "Taking a pre-deploy backup..."
"$ROOT_DIR/serviceops" backup "pre-deploy-$stamp"
rollback_dump="$ROOT_DIR/backups/serviceops-pre-deploy-$stamp.dump"

wait_for_health() {
  local service="$1" deadline=$((SECONDS + 150)) cid status
  cid="$("${COMPOSE[@]}" ps -q "$service")"
  [[ -n "$cid" ]] || return 1
  while (( SECONDS < deadline )); do
    status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$cid" 2>/dev/null)"
    case "$status" in
      healthy|no-healthcheck) return 0 ;;
      unhealthy) return 1 ;;
    esac
    sleep 5
  done
  return 1
}

echo "Starting $IDLE_SERVICE on $TARGET_IMAGE alongside the still-serving $ACTIVE_SERVICE..."
# No --build: TARGET_IMAGE was already pulled (or confirmed present
# locally) above -- this must start that exact image, the same way
# safe_update.sh does, not silently rebuild from source against whatever
# happens to be in the build context on this host.
"${COMPOSE[@]}" up -d --no-deps --force-recreate "$IDLE_SERVICE"

echo "Health-checking $IDLE_SERVICE directly (bypassing nginx)..."
if ! wait_for_health "$IDLE_SERVICE"; then
  echo "✗ $IDLE_SERVICE did not become healthy. Production traffic was never touched -- $ACTIVE_SERVICE is still serving on $ACTIVE_APP_SLOT." >&2
  echo "  Inspect: docker compose -f $COMPOSE_FILE logs $IDLE_SERVICE" >&2
  exit 1
fi

idle_head="$("${COMPOSE[@]}" exec -T "$IDLE_SERVICE" python -c "
from app import create_app, db
from sqlalchemy import text
app = create_app()
with app.app_context():
    print(db.session.execute(text('SELECT version_num FROM alembic_version')).scalar())
" 2>/dev/null | tr -d '[:space:]')"
echo "New migration head (on $IDLE_SERVICE): ${idle_head:-unknown}"
if [[ -z "$idle_head" ]]; then
  echo "✗ Could not confirm the idle slot's migration head. Production traffic was never touched." >&2
  exit 1
fi

echo "Cutting nginx over to $IDLE_SERVICE (graceful reload, zero dropped connections)..."
if ! "${COMPOSE[@]}" exec -T -e ACTIVE_APP_SLOT="$IDLE_SERVICE" nginx sh -c \
  'envsubst "\$ACTIVE_APP_SLOT" < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf && nginx -t && nginx -s reload'
then
  echo "✗ nginx reload failed. Traffic should still be on $ACTIVE_SERVICE (reload only applies atomically after -t passes) -- verify with: curl http://127.0.0.1:${APP_PORT:-8080}/health" >&2
  exit 1
fi

echo "Verifying health through the public port..."
public_health_ok=false
for _ in $(seq 1 15); do
  if curl -fsS "http://127.0.0.1:${APP_PORT:-8080}/health" >/dev/null 2>&1; then
    public_health_ok=true
    break
  fi
  sleep 2
done

if [[ "$public_health_ok" != true ]]; then
  echo "✗ Public health check failed after cutover. Rolling nginx back to $ACTIVE_SERVICE immediately..." >&2
  "${COMPOSE[@]}" exec -T -e ACTIVE_APP_SLOT="$ACTIVE_SERVICE" nginx sh -c \
    'envsubst "\$ACTIVE_APP_SLOT" < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf && nginx -t && nginx -s reload' || \
    echo "✗✗ Rollback reload ALSO failed. Manual intervention required immediately: docker compose -f $COMPOSE_FILE restart nginx" >&2
  echo "Restore the pre-deploy database backup if the failure could have touched data:" >&2
  echo "  ./serviceops restore $rollback_dump" >&2
  exit 1
fi

tmp_env="$(mktemp "$ROOT_DIR/.env.deploy.XXXXXX")"
awk -v slot="$IDLE_SLOT" -v img="$TARGET_IMAGE" '
  /^ACTIVE_APP_SLOT=/ { print "ACTIVE_APP_SLOT=" slot; next }
  /^SERVICEOPS_IMAGE_ACTIVE=/ { print "SERVICEOPS_IMAGE_ACTIVE=" img; next }
  { print }
' "$ENV_FILE" >"$tmp_env"
chmod 600 "$tmp_env"
mv "$tmp_env" "$ENV_FILE"

echo "Recreating the worker on the new active image..."
set -a
source "$ENV_FILE"
set +a
unset SERVICEOPS_IMAGE_BLUE SERVICEOPS_IMAGE_GREEN SERVICEOPS_IMAGE_ACTIVE
"${COMPOSE[@]}" up -d --no-deps --force-recreate worker || true

echo "Deploy complete. Active slot is now: $IDLE_SLOT ($TARGET_IMAGE)"
echo "Previous slot ($ACTIVE_APP_SLOT) is still running for an instant rollback: ./serviceops rollback"
echo "Pre-deploy backup retained at: $rollback_dump"
