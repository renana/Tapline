#!/bin/sh
# Runs once as an initContainer. Redirects inbound TCP to Tapline.
# Skip Tapline/Envoy/admin ports so the hop cannot loop.
set -eu

DATAPLANE_PORT="${TAPLINE_PORT:-15000}"
SKIP_PORTS="${SKIP_PORTS:-15000,15001,15002}"
APP_UID="${TAPLINE_UID:-1337}"

nft -f - <<EOF
flush ruleset
table ip tapline {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport { ${SKIP_PORTS} } return
    meta l4proto tcp redirect to :${DATAPLANE_PORT}
  }
  chain output {
    type nat hook output priority dstnat; policy accept;
    skuid ${APP_UID} return
    tcp dport { ${SKIP_PORTS} } return
  }
}
EOF

echo "nft REDIRECT -> :${DATAPLANE_PORT} (skip ${SKIP_PORTS}, uid ${APP_UID})"
