#!/bin/sh
# Lightweight CMDB auto-registration agent for Linux hosts.
#
# Collects a handful of facts from the local host with standard POSIX tools
# (no facter, no puppet module, no ruby/python dependency) and upserts a
# Configuration Item in ServiceOps over its REST API. Safe to run on every
# invocation: the CI is matched and updated by hostname, never duplicated.
#
# Configure via environment variables (e.g. in the calling cron job or
# Puppet exec resource):
#   SERVICEOPS_URL    Base URL of the ServiceOps instance, e.g. https://serviceops.example.com
#   SERVICEOPS_TOKEN  A REST API client token with the cmdb:write scope
#   CI_CLASS          Optional, defaults to "Server"
#   CI_ENVIRONMENT    Optional, defaults to "Production"
#
# Usage:
#   SERVICEOPS_URL=https://serviceops.example.com \
#   SERVICEOPS_TOKEN=sop_xxxxx \
#   ./cmdb_sync_agent.sh

set -eu

: "${SERVICEOPS_URL:?Set SERVICEOPS_URL to the ServiceOps base URL}"
: "${SERVICEOPS_TOKEN:?Set SERVICEOPS_TOKEN to a REST API client token with cmdb:write scope}"
CI_CLASS="${CI_CLASS:-Server}"
CI_ENVIRONMENT="${CI_ENVIRONMENT:-Production}"

hostname_fqdn=$(hostname -f 2>/dev/null || hostname)

ip_address=$(
  ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' | head -n1
)
if [ -z "$ip_address" ]; then
  ip_address=$(hostname -I 2>/dev/null | awk '{print $1}')
fi

operational_status="Operational"
if command -v systemctl >/dev/null 2>&1; then
  if ! systemctl is-system-running >/dev/null 2>&1; then
    operational_status="Degraded"
  fi
fi

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

name_json=$(json_escape "$hostname_fqdn")
ip_json=$(json_escape "$ip_address")
class_json=$(json_escape "$CI_CLASS")
env_json=$(json_escape "$CI_ENVIRONMENT")
status_json=$(json_escape "$operational_status")

payload=$(cat <<EOF
{"name":"$name_json","ci_class":"$class_json","environment":"$env_json","operational_status":"$status_json","ip_address":"$ip_json"}
EOF
)

http_code=$(curl -sS -o /tmp/cmdb_sync_agent.response -w '%{http_code}' \
  -X PUT "${SERVICEOPS_URL%/}/api/v1/cmdb/configuration-items" \
  -H "Authorization: Bearer ${SERVICEOPS_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "$payload")

if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
  echo "CMDB sync ok for ${hostname_fqdn} (HTTP ${http_code})"
else
  echo "CMDB sync failed for ${hostname_fqdn} (HTTP ${http_code}):" >&2
  cat /tmp/cmdb_sync_agent.response >&2
  exit 1
fi
