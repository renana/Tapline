use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::sink::Sink;

const MAX_LOGS: usize = 400;
const SERIES: usize = 60;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub ts: u64,
    pub method: String,
    pub path: String,
    pub query: String,
    pub status: i32,
    pub duration_ms: u64,
    pub client_ip: String,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub content_type: String,
    pub upstream: String,
    pub error: Option<String>,
    pub source: &'static str,
    pub protocol: String,
    pub original_dst: String,
    pub direction: String,
    pub instance: String,
    pub namespace: String,
    pub client_port: u16,
    pub local_port: u16,
    pub close_reason: String,
    pub tls_sni: String,
    pub tcp_rtt_us: u32,
    pub tcp_retrans: u32,
    pub datagrams_in: u64,
    pub datagrams_out: u64,
    pub dns_qname: String,
    pub dns_qtype: String,
    pub dns_rcode: i32,
    pub quic_version: String,
    pub url: String,
    pub user_agent: String,
    pub x_forwarded_for: String,
    pub x_request_id: String,
    pub request_headers: Vec<HeaderPair>,
    pub response_headers: Vec<HeaderPair>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub truncated: bool,
    pub dlp_hits: Vec<crate::dlp::Hit>,
    pub dlp_hash: String,
    pub dlp_blocked: bool,
    pub mcp_session: String,
    pub mcp_tool: String,
    pub mcp_resource: String,
}

impl Entry {
    pub fn summary(&self) -> Summary {
        Summary {
            id: self.id.clone(),
            ts: self.ts,
            method: self.method.clone(),
            path: self.path.clone(),
            query: self.query.clone(),
            status: self.status,
            duration_ms: self.duration_ms,
            client_ip: self.client_ip.clone(),
            request_bytes: self.request_bytes,
            response_bytes: self.response_bytes,
            content_type: self.content_type.clone(),
            upstream: self.upstream.clone(),
            error: self.error.clone(),
            source: self.source,
            protocol: self.protocol.clone(),
            original_dst: self.original_dst.clone(),
            direction: self.direction.clone(),
            instance: self.instance.clone(),
            namespace: self.namespace.clone(),
            client_port: self.client_port,
            local_port: self.local_port,
            close_reason: self.close_reason.clone(),
            tls_sni: self.tls_sni.clone(),
            tcp_rtt_us: self.tcp_rtt_us,
            tcp_retrans: self.tcp_retrans,
            datagrams_in: self.datagrams_in,
            datagrams_out: self.datagrams_out,
            dns_qname: self.dns_qname.clone(),
            dns_qtype: self.dns_qtype.clone(),
            dns_rcode: self.dns_rcode,
            quic_version: self.quic_version.clone(),
            dlp_blocked: self.dlp_blocked,
            dlp_detectors: self
                .dlp_hits
                .iter()
                .map(|h| h.detector.clone())
                .collect(),
            mcp_tool: self.mcp_tool.clone(),
            mcp_session: self.mcp_session.clone(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub id: String,
    pub ts: u64,
    pub method: String,
    pub path: String,
    pub query: String,
    pub status: i32,
    pub duration_ms: u64,
    pub client_ip: String,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub content_type: String,
    pub upstream: String,
    pub error: Option<String>,
    pub source: &'static str,
    pub protocol: String,
    pub original_dst: String,
    pub direction: String,
    pub instance: String,
    pub namespace: String,
    pub client_port: u16,
    pub local_port: u16,
    pub close_reason: String,
    pub tls_sni: String,
    pub tcp_rtt_us: u32,
    pub tcp_retrans: u32,
    pub datagrams_in: u64,
    pub datagrams_out: u64,
    pub dns_qname: String,
    pub dns_qtype: String,
    pub dns_rcode: i32,
    pub quic_version: String,
    pub dlp_blocked: bool,
    pub dlp_detectors: Vec<String>,
    pub mcp_tool: String,
    pub mcp_session: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub total: u64,
    pub ok: u64,
    pub redirect: u64,
    pub client_error: u64,
    pub server_error: u64,
    pub failed: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub p50: u64,
    pub p95: u64,
    pub rps: f64,
    pub series: Vec<u64>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConfig {
    pub mode: String,
    pub custom_upstream: String,
    pub timeout_ms: u64,
    pub proxy_protocol: bool,
    pub listen: String,
    pub envoy: String,
    pub inbound: String,
    pub outbound: String,
    pub app: String,
}

pub struct Store {
    sink: Arc<dyn Sink>,
    logs: Mutex<VecDeque<Entry>>,
    total: AtomicU64,
    ok: AtomicU64,
    redirect: AtomicU64,
    client_error: AtomicU64,
    server_error: AtomicU64,
    failed: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl Store {
    pub fn new(sink: Arc<dyn Sink>) -> Self {
        Self {
            sink,
            logs: Mutex::new(VecDeque::new()),
            total: AtomicU64::new(0),
            ok: AtomicU64::new(0),
            redirect: AtomicU64::new(0),
            client_error: AtomicU64::new(0),
            server_error: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        }
    }

    pub fn record(&self, entry: Entry) {
        self.sink.emit(&entry);
        self.total.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(entry.request_bytes, Ordering::Relaxed);
        self.bytes_out
            .fetch_add(entry.response_bytes, Ordering::Relaxed);
        if entry.error.is_some() && entry.status <= 0 {
            self.failed.fetch_add(1, Ordering::Relaxed);
        } else if entry.status >= 500 {
            self.server_error.fetch_add(1, Ordering::Relaxed);
        } else if entry.status >= 400 {
            self.client_error.fetch_add(1, Ordering::Relaxed);
        } else if entry.status >= 300 {
            self.redirect.fetch_add(1, Ordering::Relaxed);
        } else {
            self.ok.fetch_add(1, Ordering::Relaxed);
        }
        let mut logs = self.logs.lock().expect("log mutex");
        logs.push_front(entry);
        while logs.len() > MAX_LOGS {
            logs.pop_back();
        }
    }

    pub fn summaries(&self) -> Vec<Summary> {
        self.logs
            .lock()
            .expect("log mutex")
            .iter()
            .map(Entry::summary)
            .collect()
    }

    pub fn by_id(&self, id: &str) -> Option<Entry> {
        self.logs
            .lock()
            .expect("log mutex")
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    pub fn query(
        &self,
        protocol: Option<&str>,
        direction: Option<&str>,
        instance: Option<&str>,
        q: Option<&str>,
        limit: usize,
    ) -> Vec<Summary> {
        let needle = q.map(|s| s.to_ascii_lowercase());
        self.logs
            .lock()
            .expect("log mutex")
            .iter()
            .filter(|e| {
                if let Some(p) = protocol {
                    if !e.protocol.eq_ignore_ascii_case(p) {
                        return false;
                    }
                }
                if let Some(d) = direction {
                    if !e.direction.eq_ignore_ascii_case(d) {
                        return false;
                    }
                }
                if let Some(i) = instance {
                    if !e.instance.contains(i) {
                        return false;
                    }
                }
                if let Some(ref n) = needle {
                    let hay = format!(
                        "{} {} {} {} {} {} {}",
                        e.method, e.path, e.protocol, e.client_ip, e.tls_sni, e.original_dst, e.dns_qname
                    );
                    if !hay.to_ascii_lowercase().contains(n) {
                        return false;
                    }
                }
                true
            })
            .take(limit.clamp(1, 400))
            .map(Entry::summary)
            .collect()
    }

    pub fn clear(&self) {
        self.logs.lock().expect("log mutex").clear();
        for a in [
            &self.total,
            &self.ok,
            &self.redirect,
            &self.client_error,
            &self.server_error,
            &self.failed,
            &self.bytes_in,
            &self.bytes_out,
        ] {
            a.store(0, Ordering::Relaxed);
        }
    }

    pub fn stats(&self) -> Stats {
        let logs = self.logs.lock().expect("log mutex");
        let now = now_ms();
        let window = SERIES as u64 * 1000;
        let mut series = vec![0u64; SERIES];
        let mut durations: Vec<u64> = Vec::new();
        for e in logs.iter() {
            if durations.len() < 120 {
                durations.push(e.duration_ms);
            }
            if now >= e.ts && now - e.ts < window {
                let age = now - e.ts;
                let idx = ((window - 1 - age) / 1000) as usize;
                let idx = idx.min(SERIES - 1);
                series[idx] += 1;
            }
        }
        let mut sorted = durations;
        sorted.sort_unstable();
        let last5: u64 = series.iter().rev().take(5).sum();
        Stats {
            total: self.total.load(Ordering::Relaxed),
            ok: self.ok.load(Ordering::Relaxed),
            redirect: self.redirect.load(Ordering::Relaxed),
            client_error: self.client_error.load(Ordering::Relaxed),
            server_error: self.server_error.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            p50: percentile(&sorted, 50),
            p95: percentile(&sorted, 95),
            rps: last5 as f64 / 5.0,
            series,
        }
    }
}

fn percentile(sorted: &[u64], p: u8) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p as usize) * sorted.len() / 100).min(sorted.len() - 1);
    sorted[idx]
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn new_id() -> String {
    format!("{:016x}", now_ms().wrapping_mul(0x9E37) ^ (now_ms() << 7))
}
