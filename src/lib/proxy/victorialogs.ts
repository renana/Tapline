import type { TrafficDetail, TrafficSnapshot, TrafficStats, TrafficSummary } from "./types";

const VL = process.env.VICTORIALOGS_URL?.replace(/\/$/, "");
const STREAM = process.env.VICTORIALOGS_QUERY?.trim() || "app:tapline";

export function victoriaConfigured(): boolean {
  return Boolean(VL);
}

type VlRow = Record<string, unknown>;

function str(row: VlRow, ...keys: string[]): string {
  for (const key of keys) {
    const value = row[key];
    if (value != null && value !== "") return String(value);
  }
  return "";
}

function num(row: VlRow, ...keys: string[]): number {
  const raw = str(row, ...keys);
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

function toSummary(row: VlRow): TrafficSummary {
  const tsRaw = str(row, "_time", "ts");
  let ts = Date.parse(tsRaw);
  if (!Number.isFinite(ts)) ts = num(row, "_time", "ts");
  return {
    id: str(row, "id") || `vl-${ts}`,
    ts,
    method: str(row, "method") || "TCP",
    path: str(row, "path") || "*",
    query: str(row, "query"),
    status: num(row, "status"),
    durationMs: num(row, "duration_ms", "durationMs"),
    clientIp: str(row, "client_ip", "clientIp"),
    requestBytes: num(row, "bytes_in", "requestBytes"),
    responseBytes: num(row, "bytes_out", "responseBytes"),
    contentType: str(row, "content_type", "contentType"),
    upstream: str(row, "upstream"),
    error: str(row, "error") || null,
    source: "proxy",
    protocol: str(row, "protocol") || "tcp",
    originalDst: str(row, "original_dst", "originalDst"),
    direction: str(row, "direction") || "inbound",
    instance: str(row, "instance"),
    namespace: str(row, "namespace"),
    clientPort: num(row, "client_port", "clientPort"),
    localPort: num(row, "local_port", "localPort"),
    closeReason: str(row, "close_reason", "closeReason"),
    tlsSni: str(row, "tls_sni", "tlsSni"),
    tcpRttUs: num(row, "tcp_rtt_us", "tcpRttUs"),
    tcpRetrans: num(row, "tcp_retrans", "tcpRetrans"),
    datagramsIn: num(row, "datagrams_in", "datagramsIn"),
    datagramsOut: num(row, "datagrams_out", "datagramsOut"),
    dnsQname: str(row, "dns_qname", "dnsQname"),
    dnsQtype: str(row, "dns_qtype", "dnsQtype"),
    dnsRcode: num(row, "dns_rcode", "dnsRcode"),
    quicVersion: str(row, "quic_version", "quicVersion"),
    dlpBlocked: str(row, "dlp_blocked", "dlpBlocked") === "true" || num(row, "dlp_blocked") === 1,
    dlpDetectors: detectorsFrom(row),
    mcpTool: str(row, "mcp_tool", "mcpTool"),
    mcpSession: str(row, "mcp_session", "mcpSession"),
  };
}

function detectorsFrom(row: VlRow): string[] {
  const raw = row.dlp_detectors ?? row.dlpDetectors;
  if (Array.isArray(raw)) return raw.map(String);
  const s = str(row, "dlp_detectors");
  return s ? s.split(",").map((x) => x.trim()).filter(Boolean) : [];
}

function statsFrom(logs: TrafficSummary[]): TrafficStats {
  const series = Array.from({ length: 60 }, () => 0);
  const now = Date.now();
  const durations: number[] = [];
  let ok = 0;
  let redirect = 0;
  let clientError = 0;
  let serverError = 0;
  let failed = 0;
  let bytesIn = 0;
  let bytesOut = 0;
  for (const entry of logs) {
    bytesIn += entry.requestBytes;
    bytesOut += entry.responseBytes;
    durations.push(entry.durationMs);
    if (entry.error && entry.status <= 0) failed += 1;
    else if (entry.status >= 500) serverError += 1;
    else if (entry.status >= 400) clientError += 1;
    else if (entry.status >= 300) redirect += 1;
    else ok += 1;
    if (now >= entry.ts && now - entry.ts < 60_000) {
      const idx = Math.min(59, Math.floor((59_999 - (now - entry.ts)) / 1000));
      series[idx] += 1;
    }
  }
  const sorted = [...durations].sort((a, b) => a - b);
  const p = (q: number) =>
    sorted.length === 0 ? 0 : sorted[Math.min(sorted.length - 1, Math.floor((q * sorted.length) / 100))];
  const last5 = series.slice(-5).reduce((a, b) => a + b, 0);
  return {
    total: logs.length,
    ok,
    redirect,
    clientError,
    serverError,
    failed,
    bytesIn,
    bytesOut,
    p50: p(50),
    p95: p(95),
    rps: last5 / 5,
    series,
  };
}

async function logsql(query: string): Promise<VlRow[]> {
  if (!VL) return [];
  const response = await fetch(`${VL}/select/logsql/query`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ query }),
    signal: AbortSignal.timeout(4000),
  });
  if (!response.ok) throw new Error(`VictoriaLogs ${response.status}`);
  const text = await response.text();
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as VlRow);
}

export async function snapshotFromVictoria(): Promise<TrafficSnapshot> {
  const rows = await logsql(`${STREAM} | sort by (_time) desc | limit 400`);
  const logs = rows.map(toSummary);
  return {
    sidecar: true,
    backend: "victorialogs",
    logs,
    stats: statsFrom(logs),
    config: {
      mode: "custom",
      customUpstream: "",
      timeoutMs: 8000,
      proxyProtocol: false,
      listen: "",
      envoy: "",
    },
  };
}

function headersFromObj(raw: unknown): { name: string; value: string }[] {
  if (!raw || typeof raw !== "object") return [];
  return Object.entries(raw as Record<string, unknown>).map(([name, value]) => ({
    name,
    value: String(value ?? ""),
  }));
}

export async function detailFromVictoria(id: string): Promise<TrafficDetail | null> {
  const safe = id.replace(/["\\]/g, "");
  const rows = await logsql(`${STREAM} id:${JSON.stringify(safe)} | sort by (_time) desc | limit 1`);
  const row = rows[0];
  const summary = row ? toSummary(row) : null;
  if (!summary || !row) return null;
  return {
    ...summary,
    url: str(row, "url"),
    userAgent: str(row, "user_agent", "userAgent"),
    xForwardedFor: str(row, "x_forwarded_for", "xForwardedFor"),
    xRequestId: str(row, "x_request_id", "xRequestId"),
    requestHeaders: headersFromObj(row.request_headers ?? row.requestHeaders),
    responseHeaders: headersFromObj(row.response_headers ?? row.responseHeaders),
    requestBody: null,
    responseBody: null,
    truncated: false,
    dlpHits: Array.isArray(row.dlp_hits)
      ? (row.dlp_hits as Array<Record<string, unknown>>).map((h) => ({
          detector: String(h.detector ?? ""),
          count: Number(h.count ?? 1),
          severity: String(h.severity ?? "medium"),
          dir: String(h.dir ?? "in"),
        }))
      : [],
    dlpHash: str(row, "dlp_hash", "dlpHash"),
    mcpResource: str(row, "mcp_resource", "mcpResource"),
  };
}
