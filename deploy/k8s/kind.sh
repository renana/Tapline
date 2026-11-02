#!/usr/bin/env bash
# Bring Tapline logging up on a local kind cluster.
#
#   ./deploy/k8s/kind.sh
#
# Optional: KIND_CLUSTER, NAMESPACE, RETENTION, STORAGE
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLUSTER="${KIND_CLUSTER:-kind}"
NS="${NAMESPACE:-observability}"
export NAMESPACE="$NS"

need() { command -v "$1" >/dev/null || { echo "need $1 on PATH"; exit 1; }; }
need docker
need kind
need kubectl

if ! kind get clusters | grep -qx "$CLUSTER"; then
  echo "kind cluster '$CLUSTER' not found. Create it:"
  echo "  kind create cluster --name $CLUSTER"
  exit 1
fi

echo "==> build tapline:0.1 and tapline-nft:0.1"
docker build -t tapline:0.1 -f "$ROOT/proxy/Dockerfile" "$ROOT/proxy"
docker build -t tapline-nft:0.1 -f "$ROOT/deploy/k8s/nft/Dockerfile" "$ROOT/deploy/k8s/nft"

echo "==> load images into kind ($CLUSTER)"
kind load docker-image tapline:0.1 --name "$CLUSTER"
kind load docker-image tapline-nft:0.1 --name "$CLUSTER"

echo "==> VictoriaLogs"
"$ROOT/deploy/k8s/victorialogs/deploy.sh"

echo "==> Vector (Tapline audit only)"
export VICTORIALOGS_URL="http://victoria-logs.${NS}.svc:9428"
"$ROOT/deploy/k8s/vector/deploy.sh"

echo "==> demo Tapline (stdout JSON)"
kubectl apply -n "$NS" -f "$ROOT/deploy/k8s/kind-demo.yaml"
kubectl -n "$NS" rollout status deployment/tapline-demo --timeout=180s

cat <<EOF

Ready.

Port-forward VL:
  kubectl -n $NS port-forward svc/victoria-logs 9428:9428

Then:
  curl -sS 'http://127.0.0.1:9428/select/logsql/query' \\
    -d 'query=app:tapline | sort by (_time) desc | limit 10'

UI: http://127.0.0.1:9428/select/vmui/

Istio sandwich is a separate step:
  istioctl install -f deploy/k8s/istio/operator.yaml
EOF
