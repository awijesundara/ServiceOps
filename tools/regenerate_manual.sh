#!/usr/bin/env bash
# Recaptures screenshots from a running local dev stack and rebuilds the PDF
# operations manual in one step. Not part of the production image — see the
# Dockerfile's dev-tool removal step and .dockerignore.
#
# Requires:
#   - the local dev Compose stack running at http://127.0.0.1:8080 (or set
#     SERVICEOPS_URL to point elsewhere)
#   - SERVICEOPS_ADMIN_PASSWORD set to that stack's bootstrap admin password
#   - pip install -r requirements-docs.txt && playwright install chromium
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tools/capture_screenshots.py
python3 tools/generate_operations_manual.py
