#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
ROWS="${1:-100000}"
[[ "$ROWS" =~ ^[1-9][0-9]*$ ]] || {
  echo "Row count must be a positive integer." >&2
  exit 2
}
[[ -f "$ENV_FILE" ]] || {
  echo "ServiceOps is not installed. Missing .env." >&2
  exit 2
}

set -a
source "$ENV_FILE"
set +a
[[ "${DEPLOYMENT_MODE:-bundled}" == "bundled" ]] || {
  echo "This command is for bundled PostgreSQL. Rehearse external PostgreSQL in an isolated provider database." >&2
  exit 2
}

SOURCE_DATABASE="${POSTGRES_DB:-serviceops}"
REHEARSAL_DATABASE="${SOURCE_DATABASE}_migration_rehearsal"
[[ "$REHEARSAL_DATABASE" != "$SOURCE_DATABASE" && "$REHEARSAL_DATABASE" == *_migration_rehearsal ]] || {
  echo "Unsafe rehearsal database name." >&2
  exit 2
}

COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$ROOT_DIR/compose.yaml")
cleanup() {
  "${COMPOSE[@]}" exec -T db dropdb \
    --username "${POSTGRES_USER:-serviceops}" --if-exists "$REHEARSAL_DATABASE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Creating isolated PostgreSQL migration rehearsal database..."
cleanup
"${COMPOSE[@]}" exec -T db createdb \
  --username "${POSTGRES_USER:-serviceops}" "$REHEARSAL_DATABASE"
"${COMPOSE[@]}" exec -T db pg_dump \
  --username "${POSTGRES_USER:-serviceops}" --format=custom "$SOURCE_DATABASE" |
  "${COMPOSE[@]}" exec -T db pg_restore \
    --username "${POSTGRES_USER:-serviceops}" --dbname "$REHEARSAL_DATABASE" --no-owner

REHEARSAL_URL="postgresql+psycopg://${POSTGRES_USER:-serviceops}:${POSTGRES_PASSWORD}@db:5432/${REHEARSAL_DATABASE}"
"${COMPOSE[@]}" run --rm --no-deps \
  -e AUTO_MIGRATE=true \
  -e DATABASE_URL="$REHEARSAL_URL" \
  app true
"${COMPOSE[@]}" run --rm --no-deps \
  -e AUTO_MIGRATE=false \
  -e DATABASE_URL="$REHEARSAL_URL" \
  app python -m tools.postgres_migration_rehearsal --rows "$ROWS"
echo "Migration rehearsal passed; isolated database removed."
