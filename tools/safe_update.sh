#!/usr/bin/env bash
# Safe, verified update for a Docker Compose ServiceOps deployment (bundled or external database).
#
# Steps: resolve the candidate image -> verify its provenance -> rehearse the
# migration against an isolated copy of the real data (bundled mode only) ->
# take a real backup -> apply the update -> verify health and migration head
# -> automatically roll back the image (and offer to restore the backup) if
# any verification step fails.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
[[ -f "$ENV_FILE" ]] || { echo "ServiceOps is not installed. Missing .env." >&2; exit 2; }

# .env is `source`d directly as bash below, not parsed as plain key=value
# pairs. A value containing shell-special characters (&, #, (, ), {, },
# spaces, ...) left unquoted breaks that `source` with a cryptic "syntax
# error near unexpected token" pointing at a line number with no
# explanation. Catch it here with an actionable message instead.
validate_env_file() {
  local file="$1" line_num=0 key value bad=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_num=$((line_num + 1))
    [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    [[ -z "$value" ]] && continue
    [[ "$value" == \"*\" || "$value" == \'*\' ]] && continue
    if [[ "$value" =~ [\&\#\(\)\;\|\<\>\$\'\`[:space:]] ]]; then
      echo "✗ $file line $line_num: ${key}'s value contains a shell-special character (this file is sourced by bash) and must be double-quoted." >&2
      echo "  Change it to: ${key}=\"${value}\"" >&2
      bad=1
    fi
  done <"$file"
  [[ "$bad" -eq 0 ]] || { echo "Fix the line(s) above, then retry." >&2; exit 2; }
}
validate_env_file "$ENV_FILE"

set -a
source "$ENV_FILE"
set +a
MODE="${DEPLOYMENT_MODE:-bundled}"
if [[ "$MODE" == "external" ]]; then
  COMPOSE_FILE="$ROOT_DIR/compose.external-db.yaml"
else
  COMPOSE_FILE="$ROOT_DIR/compose.yaml"
fi
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

CURRENT_IMAGE="${SERVICEOPS_IMAGE:?SERVICEOPS_IMAGE is required}"
TARGET_IMAGE="${1:-$CURRENT_IMAGE}"

echo "Current image: $CURRENT_IMAGE"
echo "Target image:  $TARGET_IMAGE"

# `--force-recreate --remove-orphans` below only cleans up containers that
# belong to THIS compose project. A container bound to the same host port
# under a *different* COMPOSE_PROJECT_NAME (e.g. a stray `serviceops_fresh`
# stack from manual experimentation) is invisible to that flag by design --
# Compose deliberately never touches another project's containers. Without
# this check, that scenario surfaces only as a generic "address already in
# use" failure deep inside `up -d`, which the `|| true` below would then let
# through silently, misleadingly failing the health check instead.
check_port_conflict() {
  local port="${APP_PORT:-8080}" bind="${BIND_ADDRESS:-127.0.0.1}"
  local project="${COMPOSE_PROJECT_NAME:-serviceops}"
  local conflict
  conflict="$(docker ps --format '{{.ID}}\t{{.Names}}\t{{.Label "com.docker.compose.project"}}\t{{.Ports}}' \
    | awk -F'\t' -v port=":$port->" -v proj="$project" '
        $4 ~ port && $3 != proj { print $2 " (project: " ($3 == "" ? "unknown" : $3) ")" }
      ')"
  if [[ -n "$conflict" ]]; then
    echo "✗ Port ${bind}:${port} is already bound by a container outside this compose project:" >&2
    echo "  $conflict" >&2
    echo "  Stop it first (e.g. \`docker stop <container>\` or \`docker compose -p <project> down\`) before retrying the update." >&2
    exit 1
  fi
}
check_port_conflict

echo "Pulling candidate image for inspection..."
if ! docker pull "$TARGET_IMAGE"; then
  docker image inspect "$TARGET_IMAGE" >/dev/null 2>&1 || {
    echo "✗ $TARGET_IMAGE is not pullable and not present locally." >&2
    exit 1
  }
  echo "Registry pull failed; using the locally-present image (build-from-source deployment)." >&2
fi

if [[ -n "${SERVICEOPS_GITHUB_ORGANIZATION:-}" ]] && command -v gh >/dev/null 2>&1; then
  digest="$(docker inspect --format='{{index .RepoDigests 0}}' "$TARGET_IMAGE" 2>/dev/null | sed -E 's/^.*@//')"
  if [[ -n "$digest" ]]; then
    repo="${TARGET_IMAGE%%:*}"
    repo="${repo%%@*}"
    if gh attestation verify "oci://${repo}@${digest}" --repo "${SERVICEOPS_GITHUB_ORGANIZATION}/serviceops" >/dev/null; then
      echo "✓ Candidate image provenance verified"
    else
      echo "✗ Candidate image failed GitHub provenance verification. Refusing to update." >&2
      exit 1
    fi
  fi
else
  echo "Skipping provenance verification: set SERVICEOPS_GITHUB_ORGANIZATION and install gh to enable it." >&2
fi

# Queries through the app container's own DATABASE_URL rather than execing
# into a `db` service directly: compose.external-db.yaml has no `db`
# service (the database is external), so this must work identically in
# both bundled and external mode.
migration_head() {
  "${COMPOSE[@]}" exec -T app python -c "
from app import create_app, db
from sqlalchemy import text
app = create_app()
with app.app_context():
    print(db.session.execute(text('SELECT version_num FROM alembic_version')).scalar())
" 2>/dev/null | tr -d '[:space:]'
}

current_head="$(migration_head || true)"
echo "Current migration head: ${current_head:-unknown}"

if [[ "$MODE" == "bundled" ]]; then
  echo "Rehearsing the migration against an isolated copy of the production database..."
  SERVICEOPS_IMAGE="$TARGET_IMAGE" "$ROOT_DIR/tools/rehearse-upgrade.sh"
else
  echo "External database mode: skipping isolated rehearsal. Verify migrations in a staging database first." >&2
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
rollback_dump=""
if [[ "$MODE" == "bundled" ]]; then
  echo "Taking a pre-update backup..."
  "$ROOT_DIR/serviceops" backup "pre-update-$stamp"
  rollback_dump="$ROOT_DIR/backups/serviceops-pre-update-$stamp.dump"
else
  # `./serviceops backup` refuses to run in external mode (it isn't this
  # tool's database to snapshot), so calling it unconditionally would abort
  # the whole update under `set -e` before the image is ever touched.
  echo "External database mode: ensure a provider-side snapshot/backup exists before proceeding." >&2
fi

tmp_env="$(mktemp "$ROOT_DIR/.env.update.XXXXXX")"
awk -v img="$TARGET_IMAGE" '
  /^SERVICEOPS_IMAGE=/ { print "SERVICEOPS_IMAGE=" img; next }
  { print }
' "$ENV_FILE" >"$tmp_env"
chmod 600 "$tmp_env"
cp "$ENV_FILE" "$ENV_FILE.pre-update-bak"

# `docker compose up --wait` has been observed to return success while the
# container is still in the "starting" health state rather than blocking
# for the full healthcheck cycle, so container health is polled explicitly
# below instead of trusting that exit code alone.
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

rolled_back=false
roll_back() {
  echo "Update failed verification. Rolling back image to $CURRENT_IMAGE..." >&2
  mv "$ENV_FILE.pre-update-bak" "$ENV_FILE"
  "${COMPOSE[@]}" up -d --force-recreate --remove-orphans app worker || true
  if wait_for_health app; then
    echo "Rollback image is healthy." >&2
  else
    echo "✗ Rollback image did NOT become healthy. Manual intervention required immediately." >&2
  fi
  if [[ -n "$rollback_dump" ]]; then
    echo "Restore the pre-update database backup if the failure could have touched data:" >&2
    echo "  ./serviceops restore $rollback_dump" >&2
  else
    echo "External database mode: restore the provider-side snapshot taken before this update if the failure could have touched data." >&2
  fi
  rolled_back=true
}

mv "$tmp_env" "$ENV_FILE"
# `set -a; source .env` above exported SERVICEOPS_IMAGE with the OLD value
# into this shell's environment. Docker Compose prefers a real environment
# variable over the same key in --env-file, so every compose call below
# would otherwise keep silently using the old image even though .env now
# points at the target -- unset it so compose re-reads the updated file.
unset SERVICEOPS_IMAGE

echo "Pulling and applying the update..."
"${COMPOSE[@]}" pull app worker || docker image inspect "$TARGET_IMAGE" >/dev/null 2>&1
# --force-recreate is required: when `pull` above fails to reach the
# registry (offline/build-from-source), plain `up -d` silently leaves the
# OLD container running instead of swapping to the locally-tagged target
# image, and still exits 0 -- a false-positive "update applied" with nothing
# actually changed. The `|| true` keeps a failed/unhealthy recreation (e.g.
# a dependent service refusing to start because app is unhealthy) from
# aborting the script via `set -e` before wait_for_health/roll_back below
# get a chance to run.
"${COMPOSE[@]}" up -d --force-recreate --remove-orphans app worker || true

echo "Verifying application health..."
if ! wait_for_health app || ! "$ROOT_DIR/serviceops" health >/dev/null 2>&1; then
  roll_back
  exit 1
fi

new_head="$(migration_head || true)"
echo "New migration head: ${new_head:-unknown}"
if [[ -z "$new_head" ]]; then
  roll_back
  exit 1
fi

rm -f "$ENV_FILE.pre-update-bak"
echo "Update to $TARGET_IMAGE completed and verified."
if [[ -n "$rollback_dump" ]]; then
  echo "Pre-update backup retained at: $rollback_dump"
fi
