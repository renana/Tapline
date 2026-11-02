#!/usr/bin/env bash
# Deploy single-node VictoriaLogs.
#
#   ./deploy/k8s/victorialogs/deploy.sh
#
# Optional:
#   NAMESPACE=observability
#   RETENTION=14d
#   STORAGE=20Gi
#   KUBECTL=kubectl
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
KUBECTL="${KUBECTL:-kubectl}"
NS="${NAMESPACE:-observability}"
RETENTION="${RETENTION:-14d}"
STORAGE="${STORAGE:-20Gi}"

if ! "$KUBECTL" get ns "$NS" >/dev/null 2>&1; then
  "$KUBECTL" create namespace "$NS"
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed \
  -e "s|__RETENTION__|${RETENTION}|g" \
  -e "s|__STORAGE__|${STORAGE}|g" \
  "$ROOT/victorialogs.yaml" >"$tmp"

"$KUBECTL" apply -n "$NS" -f "$tmp"
"$KUBECTL" -n "$NS" rollout status deployment/victoria-logs --timeout=180s

echo
echo "VictoriaLogs: http://victoria-logs.${NS}.svc:9428"
echo "UI:           http://victoria-logs.${NS}.svc:9428/select/vmui/"
echo
echo "Dashboard env:"
echo "  VICTORIALOGS_URL=http://victoria-logs.${NS}.svc:9428"
echo "  VICTORIALOGS_QUERY=app:tapline"
