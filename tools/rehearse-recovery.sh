#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
MANIFEST="${1:-}"
[[ -f "$ENV_FILE" ]] || { echo "ServiceOps is not installed. Missing .env." >&2; exit 2; }

set -a
source "$ENV_FILE"
set +a
[[ "${DEPLOYMENT_MODE:-bundled}" == "bundled" ]] || {
  echo "Use an isolated provider recovery environment for external PostgreSQL." >&2
  exit 2
}

if [[ -z "$MANIFEST" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  "$ROOT_DIR/serviceops" backup "$stamp"
  MANIFEST="$ROOT_DIR/backups/serviceops-$stamp.manifest.json"
fi
[[ -f "$MANIFEST" ]] || { echo "Provide a valid recovery-set manifest." >&2; exit 2; }
MANIFEST="$(cd -- "$(dirname -- "$MANIFEST")" && pwd)/$(basename "$MANIFEST")"

SOURCE_DATABASE="${POSTGRES_DB:-serviceops}"
REHEARSAL_DATABASE="${SOURCE_DATABASE}_recovery_rehearsal"
[[ "$REHEARSAL_DATABASE" != "$SOURCE_DATABASE" && "$REHEARSAL_DATABASE" == *_recovery_rehearsal ]] || {
  echo "Unsafe rehearsal database name." >&2
  exit 2
}
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$ROOT_DIR/compose.yaml")
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/serviceops-recovery.XXXXXX")"
started_epoch="$(date +%s)"

cleanup() {
  "${COMPOSE[@]}" exec -T db dropdb --username "${POSTGRES_USER:-serviceops}" \
    --if-exists "$REHEARSAL_DATABASE" >/dev/null 2>&1 || true
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

python3 "$ROOT_DIR/tools/recovery_verify.py" verify-manifest "$MANIFEST"
python3 "$ROOT_DIR/tools/recovery_verify.py" extract-uploads "$MANIFEST" "$TEMP_DIR/uploads"
dump_name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["database"]["name"])' "$MANIFEST")"
dump="$(dirname "$MANIFEST")/$dump_name"

cleanup
mkdir -p "$TEMP_DIR/uploads"
python3 "$ROOT_DIR/tools/recovery_verify.py" extract-uploads "$MANIFEST" "$TEMP_DIR/uploads"
"${COMPOSE[@]}" exec -T db createdb \
  --username "${POSTGRES_USER:-serviceops}" "$REHEARSAL_DATABASE"
"${COMPOSE[@]}" exec -T db pg_restore \
  --username "${POSTGRES_USER:-serviceops}" --dbname "$REHEARSAL_DATABASE" \
  --no-owner --exit-on-error <"$dump"

REHEARSAL_URL="postgresql+psycopg://${POSTGRES_USER:-serviceops}:${POSTGRES_PASSWORD}@db:5432/${REHEARSAL_DATABASE}"
verification="$("${COMPOSE[@]}" run --rm --no-deps \
  -e AUTO_MIGRATE=false \
  -e DATABASE_URL="$REHEARSAL_URL" \
  -v "$TEMP_DIR/uploads:/recovery/uploads:ro" \
  app python -m tools.recovery_verify verify-database --uploads /recovery/uploads)"
completed_epoch="$(date +%s)"
duration="$((completed_epoch - started_epoch))"
created_at="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["created_at"])' "$MANIFEST")"
recovery_age="$(python3 -c 'from datetime import datetime,timezone; import sys; print(max(0,int((datetime.now(timezone.utc)-datetime.fromisoformat(sys.argv[1])).total_seconds())))' "$created_at")"

python3 -c 'import json,sys; result=json.loads(sys.argv[1]); result.update({"recovery_rehearsal_passed":True,"observed_rto_seconds":int(sys.argv[2]),"recovery_point_age_seconds":int(sys.argv[3]),"pitr_proven":False}); print(json.dumps(result,sort_keys=True))' \
  "$verification" "$duration" "$recovery_age"
echo "Recovery rehearsal passed; isolated database and extracted uploads removed."
