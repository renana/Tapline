# Tapline on Kubernetes

The image is **only the Rust sidecar**. The dashboard stays out of the pod.

```
client → Service (app port)
      → nft REDIRECT → Tapline :15000
      → PROXY proto  → Envoy 127.0.0.1:15001
      → app 127.0.0.1:8080
```

## 1. Build and push

From the repo root:

```bash
docker build -t "$REGISTRY/tapline:0.1" -f proxy/Dockerfile proxy
docker push "$REGISTRY/tapline:0.1"
```

Edit `deploy/k8s/tapline-sidecar.yaml` and set `image:` to that tag.

No nft in this image. REDIRECT is an **initContainer** (`alpine` + `nft`) so Tapline can stay non-root and read-only.

## 2. Apply

```bash
# if alpine:3.20 does not ship nft:
# change the init image to `registry.k8s.io/networking/nftables:latest`
# or `instrumentisto/nftables` — anything with `nft` on PATH.

kubectl apply -f deploy/k8s/tapline-sidecar.yaml
```

Replace `your-app:latest` with the real app image. Envoy is `127.0.0.1:15001` with PROXY protocol on, matching `TAPLINE_PROXY_PROTOCOL=1`.

## 3. Without nft (simpler)

Skip the initContainer. Point the Service `targetPort` at **15000** instead of the app port. Tapline still splices to Envoy. You lose original-destination recovery (`SO_ORIGINAL_DST` is empty unless REDIRECT/TPROXY ran).

## 4. Caps and probes

| Container | Why |
|---|---|
| `nft-redirect` init | `NET_ADMIN` (+ `NET_RAW`) to install REDIRECT in the pod netns |
| `tapline` | uid 1337, all caps dropped — `SO_ORIGINAL_DST` is a getsockopt on an already-NATed fd |
| liveness | `tcpSocket :15000` (admin is bound to 127.0.0.1 so kubelet cannot HTTP-probe it) |

The nft script skips ports `15000,15001,15002` and uid `1337` so Tapline→Envoy never redirects again.

## 5. Env

| Variable | Prod value |
|---|---|
| `TAPLINE_LISTEN` | `0.0.0.0:15000` |
| `TAPLINE_ENVOY` | `127.0.0.1:15001` |
| `TAPLINE_ADMIN` | `127.0.0.1:15002` |
| `TAPLINE_RUN_ORIGIN` | `0` (no demo origin) |
| `TAPLINE_PROXY_PROTOCOL` | `1` |

## 6. MCP

Admin serves **MCP Streamable HTTP** at `POST /mcp` (JSON-RPC 2.0, protocol `2025-03-26`). Same bind as `TAPLINE_ADMIN` (loopback in the pod).

Tools: `tapline_stats`, `tapline_list_hops`, `tapline_get_hop`, `tapline_protocols`.  
Resources: `tapline://stats`, `tapline://hops`, `tapline://hops/{id}`.

Cookie / Authorization / Set-Cookie values are `[redacted]` on `tapline_get_hop`.

Proxied JSON-RPC MCP (`/mcp`, `Mcp-Session-Id`, `initialize` / `tools/*`) is classified as protocol `mcp`.

## 7. DLP

`TAPLINE_DLP=detect` (default) scans the splice in RAM:

- credentials: JWT, PEM, AWS `AKIA`, `Bearer`
- PII: PAN (Luhn), SSN, email
- markings: `TAPLINE_DLP_MARKINGS` (default `TOP SECRET,SECRET//,CLASSIFIED,CUI,//FOUO,NOFORN,RESTRICTED`)
- MCP: `mcp_session`, `mcp_tool` / `mcp_resource` names only; arguments hashed not stored

Stdout JSON gets `dlp_hits`, `dlp_hash`, `dlp_blocked` — **not** the matched secret. Cookie/Authorization are `[redacted]` in the sink (`TAPLINE_DLP_REDACT=0` keeps those headers).

`TAPLINE_DLP=block` refuses the hop with HTTP 403 when a high-severity hit is in the first peek (JWT/PEM/PAN/SSN/marking). `TAPLINE_DLP=off` disables scanners.
