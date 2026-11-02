export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

export function formatTime(ts: number): string {
  const date = new Date(ts);
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function formatDateTime(ts: number): string {
  const date = new Date(ts);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${formatTime(ts)}`;
}

export function formatRps(rps: number): string {
  if (rps < 10) return rps.toFixed(1);
  return Math.round(rps).toString();
}

export function statusTone(
  status: number,
  error?: string | null,
): "ok" | "warn" | "err" | "neutral" {
  if (error && status <= 0) return "err";
  if (status === 0) return "ok";
  if (status >= 200 && status < 300) return "ok";
  if (status >= 300 && status < 400) return "warn";
  if (status <= 0 || status >= 400) return "err";
  return "neutral";
}

export function hopLabel(
  status: number,
  protocol: string,
  error?: string | null,
): string {
  if (error && status <= 0) return "FAIL";
  if (status === 0) return (protocol || "tcp").toUpperCase();
  return String(status);
}

export function methodTone(method: string): "neutral" | "info" | "err" | "ok" {
  switch (method.toUpperCase()) {
    case "POST":
    case "PUT":
    case "PATCH":
      return "info";
    case "DELETE":
      return "err";
    case "GET":
    case "HEAD":
      return "ok";
    case "TCP":
    case "TLS":
    case "UDP":
    case "DNS":
    case "QUIC":
    case "MCP":
      return "neutral";
    case "H2":
      return "info";
    default:
      return "neutral";
  }
}
