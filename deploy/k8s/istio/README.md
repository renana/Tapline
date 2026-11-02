# Tapline + Istio

Inject Tapline **on every pod Istio injects** (workloads):

```bash
istioctl install -f deploy/k8s/istio/operator.yaml
```

`defaultTemplates: [sidecar, tapline]` — no per-workload annotation.

The **ingress gateway is not a sidecar**. Istio ships it as a static Deployment (`inject` off). Operator overlays with `initContainers[-1]` break server-side apply. Patch instead:

```bash
istioctl install -y -f deploy/k8s/istio/operator.yaml
./deploy/k8s/istio/patch-gateway.sh
```

That adds Tapline + nft to `istio-ingressgateway`. After TLS, Envoy’s upstream dials (productpage, …) are redirected to Tapline `:15005`.

Injected/user-managed gateways:

```yaml
annotations:
  sidecar.istio.io/inject: "true"
  inject.istio.io/templates: "gateway,tapline-gateway"
```

Traffic:

```
workload inbound:  mesh → Envoy → nft uid 1337 local → Tapline :15003 → app
workload outbound: app  → nft                         → Tapline :15005 → Envoy → mesh
gateway:           client → Gateway Envoy (TLS) → nft uid 1337 non-local → Tapline :15005 → mesh
```