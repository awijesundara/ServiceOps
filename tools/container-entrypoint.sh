#!/bin/sh
set -eu

if [ "${AUTO_MIGRATE:-true}" = "true" ]; then
  python -c "from app import create_app; create_app(); print('ServiceOps database migration gate complete')"
fi

export AUTO_MIGRATE=false
exec "$@"
