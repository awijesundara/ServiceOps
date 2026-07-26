#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
[[ -f "$ENV_FILE" ]] || { echo "ServiceOps is not installed. Missing .env." >&2; exit 2; }

set -a
source "$ENV_FILE"
set +a
[[ "${DEPLOYMENT_MODE:-bundled}" == "bundled" ]] || {
  echo "Use the managed PostgreSQL provider PITR rehearsal for external mode." >&2
  exit 2
}

POSTGRES_IMAGE="postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="serviceops-pitr-$$"
network="${run_id}-network"
source_container="${run_id}-source"
recovery_container="${run_id}-recovery"
database="${POSTGRES_DB:-serviceops}_recovery_rehearsal"
target="serviceops_target_${stamp}"
temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/serviceops-pitr.XXXXXX")"
archive_dir="$temp_dir/archive"
base_dir="$temp_dir/base"
recovery_dir="$temp_dir/recovery"
dump="$temp_dir/source.dump"
evidence="$ROOT_DIR/backups/serviceops-pitr-$stamp.json"
started_epoch="$(date +%s)"
mkdir -p "$archive_dir" "$base_dir" "$recovery_dir"
chmod 777 "$archive_dir" "$base_dir" "$recovery_dir"

cleanup() {
  docker rm -f "$source_container" "$recovery_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf -- "$temp_dir"
}
trap cleanup EXIT

wait_for_database() {
  local container="$1"
  local attempts=60
  until docker exec "$container" pg_isready \
    --username "${POSTGRES_USER:-serviceops}" --dbname "$database" >/dev/null 2>&1; do
    attempts=$((attempts - 1))
    if [[ "$attempts" -le 0 ]]; then
      docker logs "$container" >&2 || true
      echo "PostgreSQL PITR rehearsal did not become ready." >&2
      return 1
    fi
    sleep 1
  done
}

echo "Exporting the live database for an isolated physical-recovery rehearsal..."
docker compose --env-file "$ENV_FILE" -f "$ROOT_DIR/compose.yaml" exec -T db \
  pg_dump --username "${POSTGRES_USER:-serviceops}" \
  --format=custom "${POSTGRES_DB:-serviceops}" >"$dump"

docker network create "$network" >/dev/null
docker run -d --name "$source_container" --network "$network" \
  -e "POSTGRES_DB=$database" \
  -e "POSTGRES_USER=${POSTGRES_USER:-serviceops}" \
  -e "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
  -v "$archive_dir:/archive" -v "$base_dir:/base" \
  "$POSTGRES_IMAGE" \
  postgres -c wal_level=replica -c archive_mode=on \
  -c "archive_command=test ! -f /archive/%f && cp %p /archive/%f" >/dev/null
wait_for_database "$source_container"

docker exec -i "$source_container" pg_restore \
  --username "${POSTGRES_USER:-serviceops}" --dbname "$database" \
  --no-owner --exit-on-error <"$dump"
docker exec "$source_container" psql \
  --username "${POSTGRES_USER:-serviceops}" --dbname "$database" \
  --set=ON_ERROR_STOP=1 --command \
  "CREATE TABLE serviceops_pitr_marker (phase text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now()); INSERT INTO serviceops_pitr_marker(phase) VALUES ('before-target');" >/dev/null

echo "Taking a physical base backup..."
docker exec "$source_container" pg_basebackup \
  --username "${POSTGRES_USER:-serviceops}" --pgdata=/base \
  --format=plain --wal-method=stream --checkpoint=fast --progress
docker exec "$source_container" psql \
  --username "${POSTGRES_USER:-serviceops}" --dbname "$database" \
  --set=ON_ERROR_STOP=1 --command "SELECT pg_create_restore_point('$target');" >/dev/null
target_wal="$(docker exec "$source_container" psql \
  --username "${POSTGRES_USER:-serviceops}" --dbname "$database" \
  --set=ON_ERROR_STOP=1 --tuples-only --no-align --command \
  "INSERT INTO serviceops_pitr_marker(phase) VALUES ('after-target'); SELECT pg_walfile_name(pg_switch_wal());" | tail -1)"
[[ "$target_wal" =~ ^[0-9A-F]{24}$ ]] || { echo "Could not identify target WAL segment." >&2; exit 1; }

attempts=60
until [[ -f "$archive_dir/$target_wal" ]]; do
  attempts=$((attempts - 1))
  [[ "$attempts" -gt 0 ]] || { echo "WAL archive did not become complete." >&2; exit 1; }
  sleep 1
done
docker stop "$source_container" >/dev/null

docker run --rm --user root \
  -v "$base_dir:/base:ro" -v "$recovery_dir:/recovery" \
  "$POSTGRES_IMAGE" sh -c \
  "cp -a /base/. /recovery/ && chown -R postgres:postgres /recovery"
docker run --rm --user root -e "RECOVERY_TARGET=$target" \
  -v "$recovery_dir:/recovery" "$POSTGRES_IMAGE" sh -c \
  "printf \"\\nrestore_command = 'cp /archive/%%f %%p'\\nrecovery_target_name = '%s'\\nrecovery_target_action = 'promote'\\n\" \"\$RECOVERY_TARGET\" >> /recovery/postgresql.auto.conf && touch /recovery/recovery.signal && chown -R postgres:postgres /recovery"

echo "Restoring to named recovery point $target..."
docker run -d --name "$recovery_container" --network "$network" \
  --user postgres -v "$recovery_dir:/var/lib/postgresql/data" \
  -v "$archive_dir:/archive:ro" "$POSTGRES_IMAGE" postgres >/dev/null
wait_for_database "$recovery_container"

before_count="$(docker exec "$recovery_container" psql \
  --username "${POSTGRES_USER:-serviceops}" --dbname "$database" \
  --tuples-only --no-align --command \
  "SELECT count(*) FROM serviceops_pitr_marker WHERE phase='before-target'")"
after_count="$(docker exec "$recovery_container" psql \
  --username "${POSTGRES_USER:-serviceops}" --dbname "$database" \
  --tuples-only --no-align --command \
  "SELECT count(*) FROM serviceops_pitr_marker WHERE phase='after-target'")"
[[ "$before_count" == "1" && "$after_count" == "0" ]] || {
  echo "PITR target boundary verification failed." >&2
  exit 1
}

rehearsal_url="postgresql+psycopg://${POSTGRES_USER:-serviceops}:${POSTGRES_PASSWORD}@${recovery_container}:5432/$database"
verification="$(docker run --rm --network "$network" --env-file "$ENV_FILE" \
  -e AUTO_MIGRATE=false -e DATABASE_URL="$rehearsal_url" \
  -e "SECRET_KEY=$SECRET_KEY" \
  -e "SETTINGS_ENCRYPTION_KEY=$SETTINGS_ENCRYPTION_KEY" \
  -e "AUDIT_INTEGRITY_KEY=${AUDIT_INTEGRITY_KEY:-}" \
  -e "AUDIT_INTEGRITY_KEY_FILE=${AUDIT_INTEGRITY_KEY_FILE:-}" \
  -e "API_TOKEN_PEPPER=${API_TOKEN_PEPPER:-}" \
  -v serviceops_uploads:/recovery/uploads:ro \
  "${SERVICEOPS_IMAGE:?SERVICEOPS_IMAGE is required}" \
  python -m tools.recovery_verify verify-database \
  --purpose recovery --uploads /recovery/uploads)"
completed_epoch="$(date +%s)"

python3 -c 'import json,sys; result=json.loads(sys.argv[1]); result.update({"schema":"serviceops.pitr-rehearsal.v1","pitr_proven":True,"base_backup":"pg_basebackup plain with streamed WAL","continuous_wal_archive":True,"recovery_target_name":sys.argv[2],"before_target_present":True,"after_target_excluded":True,"source_production_unchanged":True,"duration_seconds":int(sys.argv[3])}); open(sys.argv[4],"w").write(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result,sort_keys=True))' \
  "$verification" "$target" "$((completed_epoch - started_epoch))" "$evidence"
chmod 600 "$evidence"
echo "PITR rehearsal passed; evidence: $evidence"
