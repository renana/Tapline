# Logging

Tapline does **not** join Envoy/Linkerd/nginx access logs. It emits its own JSON hops. A collector puts those in VictoriaLogs. The UI reads VictoriaLogs so many replicas share one view.

Correlation is Tapline’s own `id` + 4-tuple / orig-dst / time — not `x-request-id`.

## Sinks (`TAPLINE_SINK`)

| Value | Where |
|---|---|
| `stdout` (default) | One JSON object per line. Kubernetes. |
| `file:/var/log/tapline.jsonl` | VM / systemd. |
| `stdout,file:/path` | Both. |
| `none` | Ring buffer only (UI on that pod). |

Next sink (not implemented): `jsonline:http://victoria-logs:9428/insert/jsonline` — plug it in `proxy/src/sink.rs`.

Identity (Downward API):

```yaml
- name: TAPLINE_INSTANCE
  valueFrom: { fieldRef: { fieldPath: metadata.name } }
- name: TAPLINE_NAMESPACE
  valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
```

## Ship to VictoriaLogs

**kind:**

```bash
./deploy/k8s/kind.sh
```

Builds `tapline:0.1`, `kind load`s it, installs VictoriaLogs + Vector, and a demo Tapline that emits audit JSON.

```bash
# VictoriaLogs + Vector (Tapline audit JSON only)
./deploy/k8s/deploy-logging.sh

# or separately:
./deploy/k8s/victorialogs/deploy.sh
VICTORIALOGS_URL=http://victoria-logs.observability.svc:9428 \
  ./deploy/k8s/vector/deploy.sh
```

Vector keeps lines from container `tapline` whose JSON has `"app":"tapline"` (the hop audit). Sidecar stderr is dropped.

**VM:** `TAPLINE_SINK=file:/var/log/tapline.jsonl` and run vlagent on the file, or journald → VL.

Each line looks like:

```json
{"_time":1787320835761,"_msg":"inbound GET /health 200","app":"tapline","id":"…","direction":"inbound","protocol":"http1","method":"GET","path":"/health","status":200,"instance":"pod-a","namespace":"prod"}
```

## UI

Set on the dashboard API:

```
VICTORIALOGS_URL=http://victoria-logs:9428
VICTORIALOGS_QUERY=app:tapline
```

The server queries `/select/logsql/query`. If unset, it falls back to the local sidecar ring (single process, preview).
