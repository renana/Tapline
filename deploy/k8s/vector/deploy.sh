#!/usr/bin/env bash
# Deploy Vector as a DaemonSet. Collects Tapline audit JSON only → VictoriaLogs.
#
#   VICTORIALOGS_URL=http://victoria-logs.observability.svc:9428 \
#     ./deploy/k8s/vector/deploy.sh
#
# Optional:
#   NAMESPACE=observability
#   KUBECTL=kubectl
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
KUBECTL="${KUBECTL:-kubectl}"
NS="${NAMESPACE:-observability}"
VL_URL="${VICTORIALOGS_URL:-http://victoria-logs.${NS}.svc:9428}"
VL_URL="${VL_URL%/}"

if ! "$KUBECTL" get ns "$NS" >/dev/null 2>&1; then
  "$KUBECTL" create namespace "$NS"
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

sed \
  -e "s|namespace: observability|namespace: ${NS}|g" \
  -e "s|__VICTORIALOGS_URL__|${VL_URL}|g" \
  "$ROOT/vector.yaml" >"$tmp"

"$KUBECTL" apply -n "$NS" -f "$tmp"
"$KUBECTL" -n "$NS" rollout status daemonset/vector --timeout=180s

cat <<EOF

Vector is shipping Tapline audit logs to ${VL_URL}/insert/elasticsearch/

Dashboard:
  VICTORIALOGS_URL=${VL_URL}
  VICTORIALOGS_QUERY=app:tapline
EOF
