#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
[[ -f "$ENV_FILE" ]] || { echo "ServiceOps is not installed. Missing .env." >&2; exit 2; }

set -a
source "$ENV_FILE"
set +a
[[ "${DEPLOYMENT_MODE:-bundled}" == "bundled" ]] || {
  echo "Use an isolated provider database for an external PostgreSQL upgrade rehearsal." >&2
  exit 2
}

SOURCE_DATABASE="${POSTGRES_DB:-serviceops}"
REHEARSAL_DATABASE="${SOURCE_DATABASE}_upgrade_rehearsal"
[[ "$REHEARSAL_DATABASE" != "$SOURCE_DATABASE" && "$REHEARSAL_DATABASE" == *_upgrade_rehearsal ]] || {
  echo "Unsafe upgrade rehearsal database name." >&2
  exit 2
}
CANDIDATE_IMAGE="${SERVICEOPS_IMAGE:?SERVICEOPS_IMAGE is required}"
# Overridable so tools/blue_green_deploy.sh can rehearse against
# compose.blue-green.yaml's app_blue/app_green services instead of plain
# compose.yaml's single "app" -- unset (the default), behavior is
# identical to before this was made overridable.
REHEARSE_COMPOSE_FILE="${REHEARSE_COMPOSE_FILE:-$ROOT_DIR/compose.yaml}"
REHEARSE_APP_SERVICE="${REHEARSE_APP_SERVICE:-app}"
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$REHEARSE_COMPOSE_FILE")
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$ROOT_DIR/backups/serviceops-upgrade-$stamp.json"
started_epoch="$(date +%s)"

cleanup() {
  "${COMPOSE[@]}" exec -T db dropdb \
    --username "${POSTGRES_USER:-serviceops}" --if-exists \
    "$REHEARSAL_DATABASE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Creating rollback recovery set..."
"$ROOT_DIR/serviceops" backup "pre-upgrade-$stamp" >/dev/null
rollback_manifest="$ROOT_DIR/backups/serviceops-pre-upgrade-$stamp.manifest.json"
python3 "$ROOT_DIR/tools/recovery_verify.py" verify-manifest "$rollback_manifest" >/dev/null

echo "Creating isolated upgrade rehearsal database..."
cleanup
"${COMPOSE[@]}" exec -T db createdb \
  --username "${POSTGRES_USER:-serviceops}" "$REHEARSAL_DATABASE"
"${COMPOSE[@]}" exec -T db pg_dump \
  --username "${POSTGRES_USER:-serviceops}" --format=custom "$SOURCE_DATABASE" |
  "${COMPOSE[@]}" exec -T db pg_restore \
    --username "${POSTGRES_USER:-serviceops}" --dbname "$REHEARSAL_DATABASE" \
    --no-owner --exit-on-error

REHEARSAL_URL="postgresql+psycopg://${POSTGRES_USER:-serviceops}:${POSTGRES_PASSWORD}@db:5432/${REHEARSAL_DATABASE}"
"${COMPOSE[@]}" run --rm --no-deps \
  -e AUTO_MIGRATE=true -e DATABASE_URL="$REHEARSAL_URL" "$REHEARSE_APP_SERVICE" true
verification="$("${COMPOSE[@]}" run --rm --no-deps \
  -e AUTO_MIGRATE=false \
  -e DATABASE_URL="$REHEARSAL_URL" \
  -v serviceops_uploads:/recovery/uploads:ro \
  "$REHEARSE_APP_SERVICE" python -m tools.recovery_verify verify-database \
  --purpose upgrade --uploads /recovery/uploads)"
"$ROOT_DIR/serviceops" health >/dev/null
completed_epoch="$(date +%s)"

python3 -c 'import json,sys; result=json.loads(sys.argv[1]); result.update({"schema":"serviceops.upgrade-rehearsal.v1","candidate_image":sys.argv[2],"rollback_manifest":sys.argv[3],"source_unchanged":True,"source_health":True,"rehearsal_passed":True,"duration_seconds":int(sys.argv[4])}); open(sys.argv[5],"w").write(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result,sort_keys=True))' \
  "$verification" "$CANDIDATE_IMAGE" "$(basename "$rollback_manifest")" \
  "$((completed_epoch - started_epoch))" "$evidence"
chmod 600 "$evidence"
echo "Upgrade rehearsal passed; evidence: $evidence"
