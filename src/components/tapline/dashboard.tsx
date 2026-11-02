import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ArrowUpRight,
  Clock3,
  Gauge,
  Layers,
  Pause,
  Play,
  Radio,
  RotateCcw,
  Search,
  Send,
  Settings2,
  Shield,
  Trash2,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input, NativeSelect } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  clearTrafficLogs,
  getTrafficDetail,
  getTrafficSnapshot,
  injectHttpProbe,
  injectTcpProbe,
  updateProxyConfig,
} from "@/lib/proxy/actions";
import type {
  ProxyConfig,
  TrafficDetail,
  TrafficSnapshot,
  TrafficStats,
  TrafficSummary,
} from "@/lib/proxy/types";
import { cn } from "@/lib/utils";
import {
  formatBytes,
  formatDateTime,
  formatDuration,
  formatRps,
  formatTime,
  hopLabel,
  methodTone,
  statusTone,
} from "./format";

const SAMPLE_PROBES: Array<{
  method: string;
  path: string;
  body?: unknown;
}> = [
  { method: "GET", path: "/health" },
  { method: "GET", path: "/users" },
  { method: "POST", path: "/users", body: { name: "Katherine Johnson", role: "analyst" } },
  { method: "GET", path: "/users/2" },
  { method: "GET", path: "/status/401" },
  { method: "GET", path: "/missing" },
  { method: "GET", path: "/slow" },
  { method: "GET", path: "/error" },
];

function TapMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <rect width="32" height="32" rx="8" className="fill-muted" />
      <path
        d="M9 6v20M9 16h9M18 11v10"
        fill="none"
        className="stroke-foreground"
        strokeWidth="2.4"
        strokeLinecap="square"
      />
    </svg>
  );
}

function Sparkline({ data }: { data: number[] }) {
  const width = 128;
  const height = 28;
  const max = Math.max(1, ...data);
  const points = data.map((value, index) => {
    const x = data.length <= 1 ? 0 : (index / (data.length - 1)) * width;
    const y = height - 2 - (value / max) * (height - 4);
    return `${x},${y}`;
  });
  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="text-foreground/55"
      aria-hidden="true"
    >
      <polyline
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        points={points.join(" ")}
      />
    </svg>
  );
}

function StatCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="min-w-36 rounded-lg bg-card px-4 py-3 shadow-[var(--shadow-border)]">
      <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {label}
      </p>
      <p className="mt-1 font-mono text-xl leading-tight font-medium tabular-nums tracking-tight">
        {value}
      </p>
      {hint ? <p className="mt-1 text-xs text-subtle">{hint}</p> : null}
    </div>
  );
}

async function sendThroughGateway(method: string, path: string, body?: string) {
  return injectHttpProbe({ data: { method, path, body } });
}

function InspectorBody({
  detail,
  isLoading,
}: {
  detail: TrafficDetail | null | undefined;
  isLoading: boolean;
}) {
  const [tab, setTab] = useState<"overview" | "headers" | "body" | "dlp">("overview");

  useEffect(() => {
    setTab("overview");
  }, [detail?.id]);

  if (isLoading) {
    return (
      <div className="space-y-3 p-5">
        <div className="h-4 w-40 rounded-sm bg-muted" />
        <div className="h-24 rounded-md bg-muted" />
        <div className="h-40 rounded-md bg-muted" />
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="flex h-full min-h-64 flex-col items-center justify-center gap-2 px-6 text-center">
        <Shield className="size-6 text-subtle" />
        <p className="text-sm font-medium">Select a request</p>
        <p className="max-w-xs text-sm text-muted-foreground">
          Headers, timing, and bodies for every hop through the proxy show up here.
        </p>
      </div>
    );
  }

  const tabs = [
    { id: "overview" as const, label: "Overview" },
    { id: "headers" as const, label: "Headers" },
    { id: "body" as const, label: "Body" },
    { id: "dlp" as const, label: "DLP" },
  ];

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-start justify-between gap-3 px-5 pt-5">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={methodTone(detail.method)}>{detail.method}</Badge>
            <Badge tone={statusTone(detail.status, detail.error)}>
              {hopLabel(detail.status, detail.protocol, detail.error)}
            </Badge>
            <Badge tone="neutral">{detail.protocol}</Badge>
            {detail.dlpBlocked ? <Badge tone="err">DLP BLOCK</Badge> : null}
            {detail.dlpDetectors && detail.dlpDetectors.length > 0 && !detail.dlpBlocked ? (
              <Badge tone="err">DLP {detail.dlpDetectors.length}</Badge>
            ) : null}
            <span className="font-mono text-xs text-muted-foreground tabular-nums">
              {formatDuration(detail.durationMs)}
            </span>
          </div>
          <p className="mt-2 truncate font-mono text-sm">
            {detail.path}
            {detail.query ? `?${detail.query}` : ""}
          </p>
        </div>
      </div>

      <div className="mt-4 flex gap-1 px-5">
        {tabs.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => setTab(item.id)}
            className={cn(
              "h-9 rounded-md px-3 text-sm font-medium transition-[color,background-color] duration-150",
              tab === item.id
                ? "bg-muted text-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {item.label}
          </button>
        ))}
      </div>

      <ScrollArea className="min-h-0 flex-1">
        <div className="space-y-4 p-5">
          {tab === "overview" ? (
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2.5 text-sm">
              <Row label="Time" value={formatDateTime(detail.ts)} />
              <Row label="Request ID" value={detail.id} mono />
              <Row label="Direction" value={detail.direction || "inbound"} />
              <Row label="Instance" value={detail.instance || "—"} />
              <Row label="Protocol" value={detail.protocol} />
              <Row label="Upstream" value={detail.upstream} />
              <Row
                label="Original dst"
                value={detail.originalDst || (detail.direction === "outbound" ? "missing" : "—")}
              />
              <Row label="Client" value={clientLabel(detail)} />
              <Row
                label="X-Forwarded-For"
                value={detail.xForwardedFor || "—"}
              />
              <Row label="X-Request-Id" value={detail.xRequestId || "—"} mono />
              {detail.mcpTool ? <Row label="MCP tool" value={detail.mcpTool} mono /> : null}
              {detail.mcpSession ? (
                <Row label="MCP session" value={detail.mcpSession} mono />
              ) : null}
              <Row label="Close" value={detail.closeReason || "—"} />
              <Row
                label="TCP RTT"
                value={detail.tcpRttUs ? `${Math.round(detail.tcpRttUs / 100) / 10} ms` : "—"}
              />
              <Row
                label="Retransmits"
                value={detail.tcpRetrans != null ? String(detail.tcpRetrans) : "—"}
              />
              <Row label="TLS SNI" value={detail.tlsSni || "—"} />
              <Row
                label="Datagrams"
                value={
                  detail.datagramsIn || detail.datagramsOut
                    ? `${detail.datagramsIn ?? 0} → ${detail.datagramsOut ?? 0}`
                    : "—"
                }
              />
              <Row label="DNS" value={dnsLabel(detail)} />
              <Row label="QUIC" value={detail.quicVersion || "—"} />
              <Row
                label="User-Agent"
                value={detail.userAgent || "—"}
              />
              <Row
                label="In / out"
                value={`${formatBytes(detail.requestBytes)} → ${formatBytes(detail.responseBytes)}`}
              />
              <Row label="Type" value={detail.contentType || "—"} />
              {detail.error ? <Row label="Error" value={detail.error} /> : null}
              {detail.source === "seed" ? (
                <Row label="Source" value="Historical sample" />
              ) : (
                <Row label="Source" value="Live proxy hop" />
              )}
            </dl>
          ) : null}

          {tab === "headers" ? (
            <div className="space-y-5">
              <HeaderBlock title="Request" pairs={detail.requestHeaders} />
              <HeaderBlock title="Response" pairs={detail.responseHeaders} />
            </div>
          ) : null}

          {tab === "body" ? (
            <div className="space-y-5">
              <BodyBlock
                title="Request"
                body={detail.requestBody}
                empty="No request body"
              />
              <BodyBlock
                title="Response"
                body={detail.responseBody}
                empty="No response body"
              />
              {detail.truncated ? (
                <p className="text-xs text-muted-foreground">
                  Bodies are truncated at 4 KB for the inspector.
                </p>
              ) : null}
            </div>
          ) : null}

          {tab === "dlp" ? (
            <div className="space-y-4">
              <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2.5 text-sm">
                <Row label="Blocked" value={detail.dlpBlocked ? "yes" : "no"} />
                <Row label="SHA-256" value={detail.dlpHash || "—"} mono />
                {detail.mcpResource ? (
                  <Row label="MCP resource" value={detail.mcpResource} mono />
                ) : null}
              </dl>
              {(detail.dlpHits ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No credential, PII, or marking hits on this hop. Matches are
                  counted only — values are not stored.
                </p>
              ) : (
                <ul className="space-y-2">
                  {(detail.dlpHits ?? []).map((hit) => (
                    <li
                      key={`${hit.detector}-${hit.dir}`}
                      className="flex items-center justify-between rounded-md bg-muted px-3 py-2 text-sm"
                    >
                      <span className="font-mono">
                        {hit.detector}
                        <span className="text-muted-foreground"> {hit.dir}</span>
                      </span>
                      <span>
                        <Badge tone={hit.severity === "high" ? "err" : "info"}>
                          {hit.severity}
                        </Badge>{" "}
                        ×{hit.count}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : null}
        </div>
      </ScrollArea>
    </div>
  );
}

function clientLabel(detail: TrafficDetail): string {
  if (!detail.clientIp) return "—";
  if (detail.clientPort) return `${detail.clientIp}:${detail.clientPort}`;
  return detail.clientIp;
}

function dnsLabel(detail: TrafficDetail): string {
  if (!detail.dnsQname && detail.protocol !== "dns") return "—";
  const name = detail.dnsQname || detail.path || "?";
  const typ = detail.dnsQtype || "";
  const rc = detail.dnsRcode != null && detail.dnsRcode >= 0 ? ` rcode=${detail.dnsRcode}` : "";
  return `${name}${typ ? " " + typ : ""}${rc}`;
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={cn("min-w-0 break-all", mono && "font-mono text-xs")}>{value}</dd>
    </>
  );
}

function HeaderBlock({
  title,
  pairs,
}: {
  title: string;
  pairs: { name: string; value: string }[];
}) {
  return (
    <section>
      <h3 className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {title}
      </h3>
      {pairs.length === 0 ? (
        <p className="text-sm text-muted-foreground">None captured</p>
      ) : (
        <ul className="divide-y divide-border rounded-md bg-muted/70">
          {pairs.map((pair, index) => (
            <li
              key={`${title}-${pair.name}-${index}`}
              className="grid gap-1 px-3 py-2 sm:grid-cols-2"
            >
              <span className="font-mono text-xs text-muted-foreground">{pair.name}</span>
              <span className="min-w-0 break-all font-mono text-xs">{pair.value}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function BodyBlock({
  title,
  body,
  empty,
}: {
  title: string;
  body: string | null;
  empty: string;
}) {
  let pretty = body;
  if (body) {
    try {
      pretty = JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      pretty = body;
    }
  }
  return (
    <section>
      <h3 className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {title}
      </h3>
      {pretty ? (
        <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">
          {pretty}
        </pre>
      ) : (
        <p className="text-sm text-muted-foreground">{empty}</p>
      )}
    </section>
  );
}

export function Dashboard({
  initial,
  initialDetail,
}: {
  initial: TrafficSnapshot;
  initialDetail: TrafficDetail | null;
}) {
  const queryClient = useQueryClient();
  const mountedAt = useRef(Date.now());
  const [live, setLive] = useState(true);
  const [query, setQuery] = useState("");
  const [method, setMethod] = useState("ALL");
  const [status, setStatus] = useState("ALL");
  const [instance, setInstance] = useState("ALL");
  const [groupByInstance, setGroupByInstance] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(
    initial.logs[0]?.id ?? null,
  );
  const [mobileInspectOpen, setMobileInspectOpen] = useState(false);
  const [probeOpen, setProbeOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [isLg, setIsLg] = useState(false);
  const [probeMethod, setProbeMethod] = useState("GET");
  const [probePath, setProbePath] = useState("/health");
  const [probeBody, setProbeBody] = useState('{\n  "name": "New user"\n}');
  const [sending, setSending] = useState(false);
  const [settings, setSettings] = useState<ProxyConfig>(initial.config);

  const snapshotQuery = useQuery({
    queryKey: ["traffic"],
    queryFn: () => getTrafficSnapshot(),
    initialData: initial,
    refetchInterval: live ? 1000 : false,
  });

  const snapshot = snapshotQuery.data ?? initial;
  const stats: TrafficStats = snapshot.stats;

  const detailQuery = useQuery({
    queryKey: ["traffic-detail", selectedId],
    queryFn: () => getTrafficDetail({ data: { id: selectedId! } }),
    enabled: Boolean(selectedId),
    initialData:
      selectedId && initialDetail && selectedId === initialDetail.id
        ? initialDetail
        : undefined,
  });

  useEffect(() => {
    const media = window.matchMedia("(min-width: 1024px)");
    const apply = () => setIsLg(media.matches);
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, []);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      for (const probe of SAMPLE_PROBES.slice(0, 3)) {
        if (cancelled) return;
        await sendThroughGateway(probe.method, probe.path, probe.body ? JSON.stringify(probe.body) : undefined);
        await new Promise((resolve) => setTimeout(resolve, 160));
      }
      void queryClient.invalidateQueries({ queryKey: ["traffic"] });
    };
    const timer = window.setTimeout(run, 450);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [queryClient]);

  const instances = useMemo(() => {
    const names = new Set<string>();
    for (const entry of snapshot.logs) {
      if (entry.instance) names.add(entry.instance);
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  }, [snapshot.logs]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return snapshot.logs.filter((entry) => {
      if (instance !== "ALL" && (entry.instance || "unknown") !== instance) return false;
      if (method !== "ALL" && entry.method !== method) return false;
      if (status === "2xx" && (entry.status < 200 || entry.status >= 300)) return false;
      if (status === "3xx" && (entry.status < 300 || entry.status >= 400)) return false;
      if (status === "4xx" && (entry.status < 400 || entry.status >= 500)) return false;
      if (status === "5xx" && (entry.status < 500 || entry.status >= 600)) return false;
      if (status === "failed" && entry.status > 0) return false;
      if (!needle) return true;
      return (
        entry.path.toLowerCase().includes(needle) ||
        entry.method.toLowerCase().includes(needle) ||
        entry.clientIp.toLowerCase().includes(needle) ||
        entry.id.toLowerCase().includes(needle) ||
        (entry.instance ?? "").toLowerCase().includes(needle) ||
        (entry.namespace ?? "").toLowerCase().includes(needle) ||
        (entry.tlsSni ?? "").toLowerCase().includes(needle) ||
        (entry.closeReason ?? "").toLowerCase().includes(needle) ||
        String(entry.status).includes(needle)
      );
    });
  }, [snapshot.logs, method, query, status, instance]);

  const grouped = useMemo(() => {
    const map = new Map<string, TrafficSummary[]>();
    for (const entry of filtered) {
      const key = entry.instance || "unknown";
      const list = map.get(key);
      if (list) list.push(entry);
      else map.set(key, [entry]);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [filtered]);

  const clearMutation = useMutation({
    mutationFn: () => clearTrafficLogs(),
    onSuccess: (next) => {
      queryClient.setQueryData(["traffic"], next);
      setSelectedId(null);
      toast("Log cleared");
    },
  });

  const configMutation = useMutation({
    mutationFn: (next: ProxyConfig) => updateProxyConfig({ data: next }),
    onSuccess: async (next) => {
      setSettings(next);
      await queryClient.invalidateQueries({ queryKey: ["traffic"] });
      setSettingsOpen(false);
      toast(
        next.mode === "builtin"
          ? "Next hop set to the Envoy stand-in"
          : `Next hop set to ${next.envoy || next.customUpstream}`,
      );
    },
    onError: (error) => {
      toast(error instanceof Error ? error.message : "Could not save upstream");
    },
  });

  const successRate =
    stats.total === 0 ? 100 : Math.round((stats.ok / stats.total) * 1000) / 10;

  async function fireBurst() {
    setSending(true);
    try {
      for (const probe of SAMPLE_PROBES) {
        await sendThroughGateway(
          probe.method,
          probe.path,
          probe.body ? JSON.stringify(probe.body) : undefined,
        );
        await new Promise((resolve) => setTimeout(resolve, 90));
      }
      await injectTcpProbe();
      await queryClient.invalidateQueries({ queryKey: ["traffic"] });
      toast("Sample traffic sent through the proxy");
    } finally {
      setSending(false);
    }
  }

  async function sendProbe() {
    setSending(true);
    try {
      const response = await sendThroughGateway(
        probeMethod,
        probePath,
        probeBody,
      );
      await queryClient.invalidateQueries({ queryKey: ["traffic"] });
      toast(`${probeMethod} ${probePath} → ${response.status}`);
      setProbeOpen(false);
    } catch {
      toast("The probe did not complete");
    } finally {
      setSending(false);
    }
  }

  const inspector = (
    <InspectorBody detail={detailQuery.data} isLoading={detailQuery.isLoading && Boolean(selectedId)} />
  );

  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <header className="border-b border-border px-4 py-4 sm:px-6">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <TapMark className="size-9 shrink-0" />
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h1 className="text-lg leading-tight font-medium tracking-tight">Tapline</h1>
                <span className="hidden text-xs tracking-wide text-muted-foreground uppercase sm:inline">
                  Envoy sidecar
                </span>
              </div>
              <p className="text-sm text-muted-foreground">
                In: Envoy → Tapline → app. Out: app → Tapline → Envoy. Plaintext both ways.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden items-center gap-3 md:flex">
              <Sparkline data={stats.series} />
              <div>
                <p className="font-mono text-sm font-medium tabular-nums">
                  {formatRps(stats.rps)} rps
                </p>
                <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <span
                    className={cn(
                      "size-1.5 rounded-full",
                      snapshot.sidecar ? "bg-ok" : "bg-err",
                      live && snapshot.sidecar && "animate-live",
                    )}
                  />
                  {snapshot.backend === "victorialogs"
                    ? live
                      ? "VictoriaLogs"
                      : "Paused"
                    : snapshot.sidecar
                      ? live
                        ? "Sidecar live"
                        : "Paused"
                      : "Sidecar down"}
                </p>
              </div>
            </div>
            <Button
              variant="secondary"
              onClick={() => setProbeOpen(true)}
            >
              <Send />
              Send request
            </Button>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Proxy settings"
              onClick={() => {
                setSettings(snapshot.config);
                setSettingsOpen(true);
              }}
            >
              <Settings2 />
            </Button>
          </div>
        </div>
      </header>

      <section className="border-b border-border px-4 py-4 sm:px-6">
        <div className="flex gap-3 overflow-x-auto pb-1">
          <StatCard
            label="Requests"
            value={stats.total.toLocaleString()}
            hint={`${stats.ok} succeeded`}
          />
          <StatCard
            label="Success"
            value={`${successRate}%`}
            hint={`${stats.clientError + stats.serverError + stats.failed} errors`}
          />
          <StatCard
            label="p50"
            value={formatDuration(stats.p50)}
            hint={`p95 ${formatDuration(stats.p95)}`}
          />
          <StatCard
            label="Transferred"
            value={formatBytes(stats.bytesIn + stats.bytesOut)}
            hint={`${formatBytes(stats.bytesIn)} in`}
          />
        </div>
      </section>

      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <section className="flex min-h-0 min-w-0 flex-1 flex-col">
          <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-3 sm:px-6">
            <div className="relative w-full min-w-0 flex-1 sm:min-w-48">
              <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-subtle" />
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Filter path, instance, client…"
                className="h-11 pl-10"
                aria-label="Filter traffic"
              />
            </div>
            <NativeSelect
              value={instance}
              onChange={(event) => setInstance(event.target.value)}
              aria-label="Instance"
              className="h-11 max-w-48 w-auto shrink-0"
            >
              <option value="ALL">All instances</option>
              {instances.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </NativeSelect>
            <NativeSelect
              value={method}
              onChange={(event) => setMethod(event.target.value)}
              aria-label="Method"
              className="h-11 w-auto shrink-0"
            >
              <option value="ALL">All methods</option>
              {["GET", "POST", "PUT", "PATCH", "DELETE"].map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </NativeSelect>
            <NativeSelect
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              aria-label="Status"
              className="h-11 w-auto shrink-0"
            >
              <option value="ALL">All status</option>
              <option value="2xx">2xx</option>
              <option value="3xx">3xx</option>
              <option value="4xx">4xx</option>
              <option value="5xx">5xx</option>
              <option value="failed">Failed</option>
            </NativeSelect>
            <Button
              variant={groupByInstance ? "secondary" : "outline"}
              onClick={() => setGroupByInstance((value) => !value)}
              aria-pressed={groupByInstance}
              aria-label="Group by instance"
            >
              <Layers />
              <span className="hidden sm:inline">Group</span>
            </Button>
            <Button
              variant="outline"
              onClick={() => setLive((value) => !value)}
              aria-pressed={live}
              aria-label={live ? "Pause live updates" : "Resume live updates"}
            >
              {live ? <Pause /> : <Play />}
              <span className="hidden sm:inline">{live ? "Pause" : "Resume"}</span>
            </Button>
            <Button
              variant="outline"
              onClick={() => void fireBurst()}
              disabled={sending}
              aria-label="Send sample traffic"
            >
              <Activity />
              <span className="hidden sm:inline">Sample burst</span>
            </Button>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Clear log"
              onClick={() => clearMutation.mutate()}
            >
              <Trash2 />
            </Button>
          </div>

          <ScrollArea className="min-h-0 flex-1">
            {filtered.length === 0 ? (
              <div className="flex min-h-80 flex-col items-center justify-center gap-3 px-6 text-center">
                <Radio className="size-6 text-subtle" />
                <p className="text-sm font-medium">No matching traffic</p>
                <p className="max-w-sm text-sm text-muted-foreground">
                  Inject HTTP or TCP through the sidecar, or run a sample burst.
                </p>
                <Button size="sm" onClick={() => void fireBurst()} disabled={sending}>
                  Fire sample traffic
                </Button>
              </div>
            ) : (
              <ul className="divide-y divide-border">
                {groupByInstance
                  ? grouped.map(([name, rows]) => (
                      <li key={name}>
                        <div className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-border bg-background/95 px-4 py-2 backdrop-blur-sm sm:px-6">
                          <p className="min-w-0 truncate font-mono text-xs font-medium">
                            {name}
                          </p>
                          <span className="shrink-0 font-mono text-xs text-muted-foreground tabular-nums">
                            {rows.length}
                          </span>
                        </div>
                        <ul className="divide-y divide-border">
                          {rows.map((entry) => (
                            <TrafficRow
                              key={entry.id}
                              entry={entry}
                              selected={selectedId === entry.id}
                              isNew={entry.source === "proxy" && entry.ts >= mountedAt.current}
                              showInstance={false}
                              onSelect={() => {
                                setSelectedId(entry.id);
                                setMobileInspectOpen(true);
                              }}
                            />
                          ))}
                        </ul>
                      </li>
                    ))
                  : filtered.map((entry) => (
                      <TrafficRow
                        key={entry.id}
                        entry={entry}
                        selected={selectedId === entry.id}
                        isNew={entry.source === "proxy" && entry.ts >= mountedAt.current}
                        showInstance
                        onSelect={() => {
                          setSelectedId(entry.id);
                          setMobileInspectOpen(true);
                        }}
                      />
                    ))}
              </ul>
            )}
          </ScrollArea>
        </section>

        <aside className="hidden min-h-0 w-full max-w-md shrink-0 border-l border-border lg:flex lg:flex-col">
          {inspector}
        </aside>
      </div>

      <Sheet
        open={Boolean(selectedId) && !isLg && mobileInspectOpen}
        onOpenChange={(open) => {
          setMobileInspectOpen(open);
        }}
      >
        <SheetContent side="bottom" className="h-[85dvh]">
          <SheetHeader>
            <SheetTitle>Request</SheetTitle>
            <SheetDescription>Inspect this hop through Tapline.</SheetDescription>
          </SheetHeader>
          <div className="min-h-0 flex-1 overflow-hidden">{inspector}</div>
        </SheetContent>
      </Sheet>

      <Sheet open={probeOpen} onOpenChange={setProbeOpen}>
        <SheetContent side={isLg ? "right" : "bottom"} className={isLg ? "" : "h-[85dvh]"}>
          <SheetHeader>
            <SheetTitle>Send through the sidecar</SheetTitle>
            <SheetDescription>
              Probes hit the Rust dataplane and are spliced to the Envoy next hop.
            </SheetDescription>
          </SheetHeader>
          <div className="flex flex-col gap-4 px-5 pb-6">
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1.5">
                <Label htmlFor="probe-method">Method</Label>
                <NativeSelect
                  id="probe-method"
                  value={probeMethod}
                  onChange={(event) => setProbeMethod(event.target.value)}
                  className="w-full"
                >
                  {["GET", "POST", "PUT", "PATCH", "DELETE"].map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </NativeSelect>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="probe-path">Path</Label>
                <Input
                  id="probe-path"
                  value={probePath}
                  onChange={(event) => setProbePath(event.target.value)}
                  placeholder="/health"
                  className="font-mono"
                />
              </div>
            </div>
            {probeMethod !== "GET" && probeMethod !== "HEAD" ? (
              <div className="space-y-1.5">
                <Label htmlFor="probe-body">JSON body</Label>
                <textarea
                  id="probe-body"
                  value={probeBody}
                  onChange={(event) => setProbeBody(event.target.value)}
                  className="min-h-32 w-full rounded-md bg-muted px-3 py-3 font-mono text-sm text-foreground outline-none shadow-[0_0_0_1px_rgb(255_255_255/0.08)] focus-visible:shadow-[0_0_0_1px_rgb(228_228_231/0.35)]"
                />
              </div>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => void sendProbe()} disabled={sending}>
                <ArrowUpRight />
                Send
              </Button>
              <Button variant="secondary" onClick={() => void fireBurst()} disabled={sending}>
                <Activity />
                Sample burst
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              HTTP paths on the stand-in: /health, /users, /error, /status/401. Sample burst also
              sends a raw TCP probe.
            </p>
          </div>
        </SheetContent>
      </Sheet>

      <Dialog open={settingsOpen} onOpenChange={setSettingsOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Next hop</DialogTitle>
            <DialogDescription>
              nft REDIRECT lands on Tapline. Tapline splices TCP to Envoy (or this stand-in).
              PROXY protocol is sent only to a real Envoy listener.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setSettings((current) => ({ ...current, mode: "builtin" }))}
                className={cn(
                  "rounded-lg px-3 py-3 text-left text-sm transition-[background-color,box-shadow] duration-150",
                  settings.mode === "builtin"
                    ? "bg-muted shadow-[0_0_0_1px_rgb(228_228_231/0.28)]"
                    : "bg-background shadow-[var(--shadow-border)] hover:bg-muted/60",
                )}
              >
                <Gauge className="mb-2 size-4 text-muted-foreground" />
                <span className="block font-medium">Envoy stand-in</span>
                <span className="mt-1 block text-xs text-muted-foreground">
                  Built-in HTTP + TCP echo. For the preview.
                </span>
              </button>
              <button
                type="button"
                onClick={() => setSettings((current) => ({ ...current, mode: "custom" }))}
                className={cn(
                  "rounded-lg px-3 py-3 text-left text-sm transition-[background-color,box-shadow] duration-150",
                  settings.mode === "custom"
                    ? "bg-muted shadow-[0_0_0_1px_rgb(228_228_231/0.28)]"
                    : "bg-background shadow-[var(--shadow-border)] hover:bg-muted/60",
                )}
              >
                <Clock3 className="mb-2 size-4 text-muted-foreground" />
                <span className="block font-medium">Envoy address</span>
                <span className="mt-1 block text-xs text-muted-foreground">
                  Sidecar next hop, host:port.
                </span>
              </button>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="upstream">Envoy host:port</Label>
              <Input
                id="upstream"
                value={settings.customUpstream}
                disabled={settings.mode !== "custom"}
                onChange={(event) =>
                  setSettings((current) => ({
                    ...current,
                    customUpstream: event.target.value,
                  }))
                }
                placeholder="127.0.0.1:15001"
                className="font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="timeout">Timeout (ms)</Label>
              <Input
                id="timeout"
                type="number"
                min={500}
                max={30000}
                value={settings.timeoutMs}
                onChange={(event) =>
                  setSettings((current) => ({
                    ...current,
                    timeoutMs: Number(event.target.value) || 8000,
                  }))
                }
                className="font-mono"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="ghost" onClick={() => setSettingsOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => configMutation.mutate(settings)}
                disabled={configMutation.isPending}
              >
                <RotateCcw />
                Save
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function TrafficRow({
  entry,
  selected,
  isNew,
  showInstance,
  onSelect,
}: {
  entry: TrafficSummary;
  selected: boolean;
  isNew: boolean;
  showInstance: boolean;
  onSelect: () => void;
}) {
  return (
    <li>
      <button
        type="button"
        onClick={onSelect}
        className={cn(
          "flex w-full items-center gap-3 px-4 py-3 text-left sm:px-6",
          "transition-[background-color] duration-150 hover:bg-muted/60",
          selected && "bg-muted",
          isNew && "animate-row-in",
        )}
      >
        <time className="hidden w-20 shrink-0 font-mono text-xs text-muted-foreground tabular-nums sm:block">
          {formatTime(entry.ts)}
        </time>
        <Badge tone={entry.direction === "outbound" ? "info" : "ok"}>
          {entry.direction === "outbound" ? "OUT" : "IN"}
        </Badge>
        <Badge tone={methodTone(entry.method)} className="w-14 justify-center">
          {entry.method}
        </Badge>
        <span className="min-w-0 flex-1 truncate font-mono text-sm">
          {entry.path}
          {entry.query ? (
            <span className="text-muted-foreground">?{entry.query}</span>
          ) : null}
        </span>
        {showInstance && entry.instance ? (
          <span
            title={entry.instance}
            className="hidden max-w-36 truncate font-mono text-xs text-muted-foreground md:block"
          >
            {entry.instance}
          </span>
        ) : null}
        <Badge tone="neutral" className="hidden sm:inline-flex">
          {entry.protocol}
        </Badge>
        {entry.dlpBlocked || (entry.dlpDetectors && entry.dlpDetectors.length > 0) ? (
          <Badge tone="err">{entry.dlpBlocked ? "DLP" : "PII"}</Badge>
        ) : null}
        <Badge tone={statusTone(entry.status, entry.error)}>
          {hopLabel(entry.status, entry.protocol, entry.error)}
        </Badge>
        <span className="hidden w-16 text-right font-mono text-xs text-muted-foreground tabular-nums sm:block">
          {formatDuration(entry.durationMs)}
        </span>
        <span className="hidden w-16 text-right font-mono text-xs text-muted-foreground tabular-nums lg:block">
          {formatBytes(entry.responseBytes)}
        </span>
      </button>
    </li>
  );
}
