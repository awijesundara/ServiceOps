#!/bin/sh
set -eu

export SERVICEOPS_SERVING=1
if [ "${STORAGE_MODE:-postgres}" = "ipfs" ]; then
  GUNICORN_WORKERS=1
  export GUNICORN_WORKERS
  PRELOAD_FLAG=""
else
  PRELOAD_FLAG="--preload"
fi

exec gunicorn \
  ${PRELOAD_FLAG} \
  --bind "0.0.0.0:8080" \
  --workers "${GUNICORN_WORKERS:-2}" \
  --threads "${GUNICORN_THREADS:-4}" \
  --timeout "${GUNICORN_TIMEOUT:-60}" \
  --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-30}" \
  --keep-alive "${GUNICORN_KEEPALIVE:-5}" \
  --max-requests "${GUNICORN_MAX_REQUESTS:-1000}" \
  --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER:-100}" \
  --no-control-socket \
  --access-logfile - \
  --error-logfile - \
  --log-level "${GUNICORN_LOG_LEVEL:-info}" \
  "app:create_app()"
