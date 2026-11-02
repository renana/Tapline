#!/usr/bin/env bash
# Add Tapline to the stock istio-ingressgateway Deployment.
set -euo pipefail
NS="${ISTIO_NAMESPACE:-istio-system}"
PATCH="$(cd "$(dirname "$0")" && pwd)/gateway-tapline.yaml"
kubectl patch deploy istio-ingressgateway -n "$NS" --type strategic --patch-file "$PATCH"
kubectl -n "$NS" rollout status deploy/istio-ingressgateway --timeout=180s
echo "ingressgateway should now have containers: istio-proxy, tapline"
kubectl -n "$NS" get pod -l app=istio-ingressgateway -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.containers[*].name}{"\n"}{end}'
