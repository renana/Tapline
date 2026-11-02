export type HeaderPair = {
  name: string;
  value: string;
};

export type TrafficSummary = {
  id: string;
  ts: number;
  method: string;
  path: string;
  query: string;
  status: number;
  durationMs: number;
  clientIp: string;
  requestBytes: number;
  responseBytes: number;
  contentType: string;
  upstream: string;
  error: string | null;
  source: "proxy" | "seed";
  protocol: string;
  originalDst: string;
  direction: "inbound" | "outbound" | string;
  instance?: string;
  namespace?: string;
  clientPort?: number;
  localPort?: number;
  closeReason?: string;
  tlsSni?: string;
  tcpRttUs?: number;
  tcpRetrans?: number;
  datagramsIn?: number;
  datagramsOut?: number;
  dnsQname?: string;
  dnsQtype?: string;
  dnsRcode?: number;
  quicVersion?: string;
  dlpBlocked?: boolean;
  dlpDetectors?: string[];
  mcpTool?: string;
  mcpSession?: string;
};

export type TrafficDetail = TrafficSummary & {
  url: string;
  userAgent: string;
  xForwardedFor?: string;
  xRequestId?: string;
  requestHeaders: HeaderPair[];
  responseHeaders: HeaderPair[];
  requestBody: string | null;
  responseBody: string | null;
  truncated: boolean;
  dlpHits?: Array<{ detector: string; count: number; severity: string; dir: string }>;
  dlpHash?: string;
  mcpResource?: string;
};

export type TrafficStats = {
  total: number;
  ok: number;
  redirect: number;
  clientError: number;
  serverError: number;
  failed: number;
  bytesIn: number;
  bytesOut: number;
  p50: number;
  p95: number;
  rps: number;
  series: number[];
};

export type ProxyConfig = {
  mode: "builtin" | "custom";
  customUpstream: string;
  timeoutMs: number;
  proxyProtocol: boolean;
  listen: string;
  envoy: string;
  inbound?: string;
  outbound?: string;
  app?: string;
};

export type TrafficSnapshot = {
  sidecar: boolean;
  backend: "sidecar" | "victorialogs";
  logs: TrafficSummary[];
  stats: TrafficStats;
  config: ProxyConfig;
};
