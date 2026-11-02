import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import type { ProxyConfig, TrafficDetail, TrafficSnapshot, TrafficStats } from "./types";
import {
  detailFromVictoria,
  snapshotFromVictoria,
  victoriaConfigured,
} from "./victorialogs";

const ADMIN = "http://127.0.0.1:15002";
const DATA = "http://127.0.0.1:15000";

const emptyStats = (): TrafficStats => ({
  total: 0,
  ok: 0,
  redirect: 0,
  clientError: 0,
  serverError: 0,
  failed: 0,
  bytesIn: 0,
  bytesOut: 0,
  p50: 0,
  p95: 0,
  rps: 0,
  series: Array.from({ length: 60 }, () => 0),
});

const emptyConfig = (): ProxyConfig => ({
  mode: "builtin",
  customUpstream: "127.0.0.1:15001",
  timeoutMs: 8000,
  proxyProtocol: false,
  listen: "0.0.0.0:15000",
  envoy: "127.0.0.1:15001",
});

const emptySnapshot = (): TrafficSnapshot => ({
  sidecar: false,
  backend: "sidecar",
  logs: [],
  stats: emptyStats(),
  config: emptyConfig(),
});

async function adminFetch(path: string, init?: RequestInit): Promise<Response | null> {
  try {
    return await fetch(`${ADMIN}${path}`, {
      ...init,
      signal: AbortSignal.timeout(2500),
    });
  } catch {
    return null;
  }
}

export const getTrafficSnapshot = createServerFn({ method: "GET" }).handler(async () => {
  if (victoriaConfigured()) {
    try {
      return await snapshotFromVictoria();
    } catch {
      return emptySnapshot();
    }
  }
  const response = await adminFetch("/v1/snapshot");
  if (!response?.ok) return emptySnapshot();
  const data = (await response.json()) as TrafficSnapshot;
  return { ...data, sidecar: true, backend: "sidecar" as const };
});

export const getTrafficDetail = createServerFn({ method: "GET" })
  .validator(z.object({ id: z.string().min(1) }))
  .handler(async ({ data }) => {
    if (victoriaConfigured()) {
      try {
        return await detailFromVictoria(data.id);
      } catch {
        return null;
      }
    }
    const response = await adminFetch(`/v1/logs/${data.id}`);
    if (!response?.ok) return null;
    return (await response.json()) as TrafficDetail | null;
  });

export const clearTrafficLogs = createServerFn({ method: "POST" }).handler(async () => {
  if (victoriaConfigured()) {
    return snapshotFromVictoria();
  }
  const response = await adminFetch("/v1/clear", { method: "POST" });
  if (!response?.ok) return emptySnapshot();
  const data = (await response.json()) as TrafficSnapshot;
  return { ...data, sidecar: true, backend: "sidecar" as const };
});

const configSchema = z.object({
  mode: z.enum(["builtin", "custom"]),
  customUpstream: z.string().max(200),
  timeoutMs: z.number().min(500).max(30000),
  proxyProtocol: z.boolean(),
});

export const updateProxyConfig = createServerFn({ method: "POST" })
  .validator(configSchema)
  .handler(async ({ data }) => {
    const envoy =
      data.mode === "builtin" ? "127.0.0.1:15001" : data.customUpstream.trim();
    if (data.mode === "custom") {
      if (!/^[A-Za-z0-9._:-]+$/.test(envoy) || !envoy.includes(":")) {
        throw new Error("Next hop must be host:port");
      }
    }
    const response = await adminFetch("/v1/config", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        mode: data.mode,
        envoy,
        timeoutMs: data.timeoutMs,
        proxyProtocol: data.mode === "custom" ? data.proxyProtocol : false,
      }),
    });
    if (!response?.ok) {
      throw new Error("Sidecar did not accept the config");
    }
    return (await response.json()) as ProxyConfig;
  });

export const injectHttpProbe = createServerFn({ method: "POST" })
  .validator(
    z.object({
      method: z.string().min(1),
      path: z.string().min(1),
      body: z.string().optional(),
    }),
  )
  .handler(async ({ data }) => {
    const path = data.path.startsWith("/") ? data.path : `/${data.path}`;
    const init: RequestInit = { method: data.method, signal: AbortSignal.timeout(8000) };
    if (data.body && data.method !== "GET" && data.method !== "HEAD") {
      init.headers = { "content-type": "application/json" };
      init.body = data.body;
    }
    const response = await fetch(`${DATA}${path}`, init);
    return { status: response.status };
  });

export const injectTcpProbe = createServerFn({ method: "POST" }).handler(async () => {
  const net = await import("node:net");
  await new Promise<void>((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port: 15000 }, () => {
      socket.write("tapline-tcp-probe\n");
      socket.end();
    });
    socket.setTimeout(3000);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("tcp_timeout"));
    });
    socket.on("error", reject);
    socket.on("close", () => resolve());
  });
  return { ok: true };
});
