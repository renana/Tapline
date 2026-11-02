#!/usr/bin/env bash
# VictoriaLogs + Vector (Tapline audit logs only).
#
#   ./deploy/k8s/deploy-logging.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
NS="${NAMESPACE:-observability}"
export NAMESPACE="$NS"
export VICTORIALOGS_URL="${VICTORIALOGS_URL:-http://victoria-logs.${NS}.svc:9428}"

"$ROOT/victorialogs/deploy.sh"
"$ROOT/vector/deploy.sh"
