#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
STATE_FILE="$ROOT_DIR/.serviceops-install"
MODE=""
APP_PORT="8080"
BIND_ADDRESS="127.0.0.1"
DATABASE_URL=""
ASSUME_YES=0

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'
info() { printf "${CYAN}ℹ${RESET} %s\n" "$*"; }
ok() { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}!${RESET} %s\n" "$*"; }
die() { printf "${RED}✗ %s${RESET}\n" "$*" >&2; exit 1; }
on_error() { printf "${RED}Installation stopped at line %s.${RESET}\n" "$1" >&2; printf "Run: ./serviceops doctor\n" >&2; }
trap 'on_error "$LINENO"' ERR

banner() {
  clear 2>/dev/null || true
  printf "${BOLD}${CYAN}\n"
  printf "  ┌──────────────────────────────────────────┐\n"
  printf "  │          SERVICEOPS INSTALLER            │\n"
  printf "  │  Enterprise service management platform │\n"
  printf "  └──────────────────────────────────────────┘\n${RESET}\n"
}

usage() {
  cat <<'EOF'
Usage: ./serviceops install server [options]
  --mode bundled|external
  --port PORT
  --bind 127.0.0.1|0.0.0.0|IP
  --database-url URL       Required for external mode
  --yes                    Non-interactive confirmation
  --help
EOF
}

while (($#)); do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --port) APP_PORT="${2:-}"; shift 2 ;;
    --bind) BIND_ADDRESS="${2:-}"; shift 2 ;;
    --database-url) DATABASE_URL="${2:-}"; shift 2 ;;
    --yes) ASSUME_YES=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

command -v docker >/dev/null || die "Docker is not installed. Install Docker Engine 24+ and the Compose plugin."
command -v curl >/dev/null || die "curl is required for health verification."
command -v openssl >/dev/null || die "OpenSSL is required for secure key generation."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required."
docker info >/dev/null 2>&1 || die "Docker daemon is not running or your user cannot access it."
((APP_PORT >= 1 && APP_PORT <= 65535)) || die "Port must be between 1 and 65535."
[[ "$BIND_ADDRESS" != *$'\n'* && "$BIND_ADDRESS" != *" "* ]] || die "Invalid bind address."
AVAILABLE_KB="$(df -Pk "$ROOT_DIR" | awk 'NR==2 {print $4}')"
((AVAILABLE_KB >= 2097152)) || die "At least 2 GB free disk space is required."

if [[ -z "$MODE" ]]; then
  banner
  printf "Choose a database architecture:\n\n"
  printf "  ${BOLD}1) Bundled PostgreSQL${RESET}  Recommended for simple single-server installs\n"
  printf "  ${BOLD}2) External PostgreSQL${RESET} Database runs on another managed server\n"
  printf "  3) Exit\n\n"
  read -r -p "Selection [1]: " selection
  case "${selection:-1}" in
    1) MODE="bundled" ;;
    2) MODE="external" ;;
    3) exit 0 ;;
    *) die "Invalid selection." ;;
  esac
fi
[[ "$MODE" == "bundled" || "$MODE" == "external" ]] || die "Mode must be bundled or external."

if [[ -t 0 && "$ASSUME_YES" -eq 0 ]]; then
  read -r -p "Application port [$APP_PORT]: " entered_port
  APP_PORT="${entered_port:-$APP_PORT}"
  printf "\nBind address:\n  1) 127.0.0.1 — behind an HTTPS proxy (recommended)\n  2) 0.0.0.0 — directly reachable on the network\n"
  read -r -p "Selection [1]: " bind_choice
  [[ "${bind_choice:-1}" == "2" ]] && BIND_ADDRESS="0.0.0.0"
fi

if [[ "$MODE" == "external" && -z "$DATABASE_URL" ]]; then
  read -r -s -p "External PostgreSQL URL: " DATABASE_URL
  printf "\n"
fi
if [[ "$MODE" == "external" ]]; then
  [[ "$DATABASE_URL" == postgresql://* || "$DATABASE_URL" == postgresql+psycopg://* ]] || die "Use a postgresql:// or postgresql+psycopg:// URL."
  [[ "$DATABASE_URL" != *"'"* && "$DATABASE_URL" != *$'\n'* ]] || die "Database URL contains unsupported characters."
  [[ "$DATABASE_URL" == *"sslmode="* ]] || warn "External DATABASE_URL has no sslmode setting. Use sslmode=require or verify-full in production."
  DATABASE_URL="${DATABASE_URL/postgresql:\/\//postgresql+psycopg:\/\/}"
fi

random_hex() {
  if command -v openssl >/dev/null; then openssl rand -hex "$1"; else
    od -An -N "$1" -tx1 /dev/urandom | tr -d ' \n'
  fi
}
SECRET_KEY="$(random_hex 48)"
POSTGRES_PASSWORD="$(random_hex 24)"
ADMIN_PASSWORD="$(random_hex 12)"
SETTINGS_ENCRYPTION_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n')"

if [[ -f "$ENV_FILE" ]]; then
  backup="$ENV_FILE.backup.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$ENV_FILE" "$backup"
  warn "Existing .env backed up to $(basename "$backup")."
fi

umask 077
{
  printf "DEPLOYMENT_MODE=%s\n" "$MODE"
  printf "APP_PORT=%s\n" "$APP_PORT"
  printf "BIND_ADDRESS=%s\n" "$BIND_ADDRESS"
  printf "SECRET_KEY=%s\n" "$SECRET_KEY"
  printf "ADMIN_PASSWORD=%s\n" "$ADMIN_PASSWORD"
  printf "SETTINGS_ENCRYPTION_KEY=%s\n" "$SETTINGS_ENCRYPTION_KEY"
  printf "SERVICEOPS_IMAGE=serviceops-app:1.3.0\n"
  if [[ "$MODE" == "bundled" ]]; then
    printf "POSTGRES_DB=serviceops\nPOSTGRES_USER=serviceops\nPOSTGRES_PASSWORD=%s\n" "$POSTGRES_PASSWORD"
  else
    printf "DATABASE_URL='%s'\n" "$DATABASE_URL"
  fi
} >"$ENV_FILE"
chmod 600 "$ENV_FILE"
printf "MODE=%s\nCOMPOSE_FILE=%s\nINSTALLED_AT=%s\n" "$MODE" \
  "$([[ "$MODE" == "bundled" ]] && printf compose.yaml || printf compose.external-db.yaml)" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$STATE_FILE"
chmod 600 "$STATE_FILE"

if [[ "$MODE" == "bundled" ]]; then
  COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$ROOT_DIR/compose.yaml")
else
  COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$ROOT_DIR/compose.external-db.yaml")
fi

banner
info "Running preflight configuration validation…"
"${COMPOSE[@]}" config --quiet
ok "Configuration is valid."
info "Building and starting ServiceOps…"
"${COMPOSE[@]}" up --build -d

info "Waiting for application readiness…"
deadline=$((SECONDS + 180))
until [[ "$("${COMPOSE[@]}" ps --format json 2>/dev/null | grep -c '"Health":"healthy"' || true)" -ge 1 ]]; do
  ((SECONDS < deadline)) || {
    "${COMPOSE[@]}" logs --tail=100 app
    die "ServiceOps did not become healthy within 180 seconds."
  }
  sleep 3
done
http_deadline=$((SECONDS + 60))
until curl -fsS "http://127.0.0.1:${APP_PORT}/health" >/dev/null 2>&1; do
  ((SECONDS < http_deadline)) || die "Container is healthy but the host health endpoint is unreachable."
  sleep 2
done
ok "ServiceOps is healthy."

printf "\n${GREEN}${BOLD}Installation complete${RESET}\n\n"
printf "  URL:            http://%s:%s\n" "$([[ "$BIND_ADDRESS" == "0.0.0.0" ]] && printf SERVER_IP || printf "$BIND_ADDRESS")" "$APP_PORT"
printf "  Admin username: admin\n"
printf "  Admin password: ${BOLD}%s${RESET}\n" "$ADMIN_PASSWORD"
printf "  Database mode:  %s\n\n" "$MODE"
printf "${YELLOW}Store these credentials now. They are intentionally shown only by this installer.${RESET}\n"
printf "Next: configure HTTPS, sign in, and change bootstrap passwords.\n"
printf "Operations: ./serviceops status | logs | backup | doctor\n"
