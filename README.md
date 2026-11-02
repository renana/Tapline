# Tapline

Designed and built in collaboration with Grok.

Tapline is a transparent TCP and UDP sidecar. It sits in the pod network namespace after nftables `REDIRECT`, splices each accepted flow to its original destination, and emits one JSON record per hop.

It is an observation point, not a dataplane. Routing, retries, load balancing, and mesh mTLS remain the responsibility of the proxy in front of or behind it (Envoy, or another proxy that has already terminated encryption).

## Architecture

```
inbound:   mesh → Envoy → Tapline :15003 → application
outbound:  application → Tapline :15005 → Envoy → mesh
```

An init container installs a `nat` `output` chain at priority `-150`. The chain redirects TCP and UDP originated by the application, and inbound traffic that Envoy forwards toward the application, onto Tapline. `SO_ORIGINAL_DST` recovers the pre-NAT destination.

| Identity | UID | Role |
|---|---|---|
| Envoy | 1337 | Skipped by the nft rules, so its own sockets are not redirected |
| Tapline | 1338 | Unprivileged. Capabilities dropped. `SO_ORIGINAL_DST` is a `getsockopt` on an already rewritten socket |

Without nft, inbound connections that have no original destination are forwarded to `TAPLINE_APP`.

## Scope

- One TCP connection is one record. Later HTTP/2 streams and later MCP calls on the same socket are not separate hops.
- Protocol classification uses the first 16 KB. UDP is summarized as a flow after 30 seconds of idle time.
- TLS ClientHello SNI is parsed. Tapline does not terminate TLS. Ciphertext that has not already been decrypted stays ciphertext.
- DLP reports detector, count, and a hash of the scanned bytes. It does not retain the matched secret.

## Building

Requires a recent stable Rust toolchain.

```bash
cd proxy
cargo build --release
```

The container image contains only the release binary:

```bash
docker build -t tapline:0.1 -f proxy/Dockerfile proxy
```

The image listens on `:15003` and `:15005`, sets `TAPLINE_RUN_ORIGIN=0`, and runs as uid 1338. Kubernetes manifests, Istio injection, and the logging pipeline are documented in [`deploy/README.md`](deploy/README.md).

The container image is the Rust binary. `proxy/*.go` is an earlier comparison port and is not what the image builds.

## Running locally

```bash
TAPLINE_RUN_ORIGIN=1 \
TAPLINE_INBOUND=0.0.0.0:15000 \
TAPLINE_APP=127.0.0.1:15001 \
TAPLINE_OUTBOUND=0 \
TAPLINE_SINK=stdout \
  ./proxy/target/release/tapline
```

`TAPLINE_RUN_ORIGIN=1` starts a demo origin on `:15001`. Leave it off in a real pod.

The admin server binds to loopback (`TAPLINE_ADMIN`, default `127.0.0.1:15002`):

| Method | Path | |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/v1/snapshot` | Recent hops and counters |
| `GET` | `/v1/logs/{id}` | One hop |
| `POST` | `/mcp` | MCP Streamable HTTP |

## Records

Each accepted connection, and each flushed UDP flow, is one JSON object. The sink defaults to stdout so a node agent can collect it. VictoriaLogs fields `_time`, `_msg`, and `app=tapline` are set on every line.

| Field | Content |
|---|---|
| `id` | Hop identifier |
| `direction` | `inbound` or `outbound` |
| `protocol` | See below |
| `method`, `path`, `query`, `status`, `url` | HTTP, when present |
| `client_ip`, `client_port`, `local_port`, `original_dst`, `upstream` | Addressing |
| `bytes_in`, `bytes_out`, `duration_ms` | Sizes and duration |
| `close_reason`, `tcp_rtt_us`, `tcp_retrans` | TCP |
| `tls_sni`, `quic_version` | Handshake metadata |
| `dns_qname`, `dns_qtype`, `dns_rcode` | DNS, when the payload parses |
| `x_forwarded_for`, `x_request_id`, `user_agent` | Selected request headers |
| `request_headers`, `response_headers` | Header maps. Secret headers are redacted when DLP redaction is on |
| `instance`, `namespace` | Workload identity from the environment |
| `dlp_hits`, `dlp_hash`, `dlp_blocked` | DLP judgments |
| `mcp_session`, `mcp_tool`, `mcp_resource` | MCP classification, when recognized |

TCP protocols, from the first buffer: `tcp`, `tls`, `http1`, `websocket`, `h2`, `grpc`, `mcp`.

UDP protocols, from the first datagrams of a flow: `udp`, `dns`, `quic`, `stun`, `wireguard`, `dtls`, `ntp`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TAPLINE_INBOUND`, `TAPLINE_LISTEN` | `0.0.0.0:15000` | Inbound listener. Mesh manifests use `:15003`. |
| `TAPLINE_APP`, `TAPLINE_ENVOY` | `127.0.0.1:15001` | Upstream used when original destination is unavailable. |
| `TAPLINE_OUTBOUND` | `0.0.0.0:15005` | Outbound listener. `0` disables it. |
| `TAPLINE_ADMIN` | `127.0.0.1:15002` | Admin and MCP listener. |
| `TAPLINE_RUN_ORIGIN` | `1` in the binary, `0` in the image | Demo origin. |
| `TAPLINE_PROXY_PROTOCOL` | `0` | Emit PROXY protocol v1 toward the upstream. |
| `TAPLINE_UDP` | `1` | UDP relay. |
| `TAPLINE_UDP_IDLE_MS` | `30000` | Idle time before a UDP flow is recorded. |
| `TAPLINE_SINK` | `stdout` | `stdout`, `file:/path`, `none`, or a comma-separated list. |
| `TAPLINE_INSTANCE` | hostname | Copied onto each record. |
| `TAPLINE_NAMESPACE` | `default` | Copied onto each record. |
| `TAPLINE_DLP` | `detect` | `off`, `detect`, or `block`. |
| `TAPLINE_DLP_MARKINGS` | see DLP | Comma-separated classification strings. |
| `TAPLINE_DLP_REDACT` | `1` when DLP is enabled | Replace cookie and authorization header values with `[redacted]`. |

## Data-loss prevention

With `TAPLINE_DLP=detect`, scanners run on the bytes already buffered for the splice. The record stores the detector name, count, severity, direction, and a SHA-256 of the scanned bytes. The matched text is not written.

| Severity | Detectors |
|---|---|
| High | JWT, PEM private key, AWS access key id (`AKIA`), `Bearer` token, payment card number (Luhn), US SSN (`ddd-dd-dddd`), configured markings |
| Medium | Email address |

Default markings: `TOP SECRET`, `SECRET//`, `CLASSIFIED`, `CUI`, `//FOUO`, `NOFORN`, `RESTRICTED`.

`TAPLINE_DLP=block` returns HTTP 403 and does not forward the first peek when that peek contains a high-severity hit. `TAPLINE_DLP=off` disables scanning and header redaction.

## MCP

The admin listener implements [MCP Streamable HTTP](https://modelcontextprotocol.io) as JSON-RPC 2.0, protocol revision `2025-03-26`.

Tools: `tapline_stats`, `tapline_list_hops`, `tapline_get_hop`, `tapline_protocols`.

Resources: `tapline://stats`, `tapline://hops`, `tapline://hops/{id}`.

`tapline_get_hop` redacts cookie, authorization, and equivalent headers regardless of the DLP setting.

Traffic proxied through the splice is labeled `protocol=mcp` when the request path contains `/mcp`, an MCP session header is present, or the JSON-RPC method is `initialize`, `tools/*`, `resources/*`, `prompts/*`, `ping`, or `notifications/*`. The record stores the session id and the tool or resource name. Arguments are not stored.

## Collection

Sidecars write to stdout. The Vector DaemonSet in [`deploy/k8s/vector/`](deploy/k8s/vector/vector.yaml) retains lines whose container name is `tapline` and whose JSON field `app` is `tapline`, then inserts them into VictoriaLogs. Deployment steps are in [`deploy/logging.md`](deploy/logging.md).

The dashboard under `src/` queries VictoriaLogs when `VICTORIALOGS_URL` is set, and otherwise reads the local admin snapshot. It is not included in the sidecar image.

## Repository

| Path | Contents |
|---|---|
| [`proxy/src/`](proxy/src) | Rust dataplane |
| [`proxy/*.go`](proxy) | Go comparison port |
| [`deploy/`](deploy) | nftables, Istio injection, Vector, VictoriaLogs |
| [`src/components/tapline/`](src/components/tapline) | Dashboard |

## License

Copyright 2026 Renana Yacobi.

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).
