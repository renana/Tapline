use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::json;

use crate::log::Entry;

pub trait Sink: Send + Sync {
    fn emit(&self, entry: &Entry);
}

pub struct NullSink;

impl Sink for NullSink {
    fn emit(&self, _entry: &Entry) {}
}

pub struct StdoutSink {
    identity: Identity,
}

pub struct FileSink {
    identity: Identity,
    file: Mutex<std::fs::File>,
}

#[derive(Clone)]
pub struct Identity {
    pub instance: String,
    pub namespace: String,
}

pub struct Fanout(pub Vec<Box<dyn Sink>>);

impl Sink for Fanout {
    fn emit(&self, entry: &Entry) {
        for s in &self.0 {
            s.emit(entry);
        }
    }
}

impl StdoutSink {
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }
}

impl Sink for StdoutSink {
    fn emit(&self, entry: &Entry) {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "{}", line(entry, &self.identity));
    }
}

impl FileSink {
    pub fn open(path: PathBuf, identity: Identity) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            identity,
            file: Mutex::new(file),
        })
    }
}

impl Sink for FileSink {
    fn emit(&self, entry: &Entry) {
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(line(entry, &self.identity).as_bytes());
            let _ = f.write_all(b"\n");
        }
    }
}

pub fn from_env(spec: &str, identity: Identity) -> Box<dyn Sink> {
    let parts: Vec<&str> = spec.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if parts.is_empty() || (parts.len() == 1 && parts[0] == "stdout") {
        return Box::new(StdoutSink::new(identity));
    }
    if parts.len() == 1 && parts[0] == "none" {
        return Box::new(NullSink);
    }
    let mut sinks: Vec<Box<dyn Sink>> = Vec::new();
    for part in parts {
        if part == "stdout" {
            sinks.push(Box::new(StdoutSink::new(identity.clone())));
        } else if part == "none" {
            continue;
        } else if let Some(path) = part.strip_prefix("file:") {
            match FileSink::open(PathBuf::from(path), identity.clone()) {
                Ok(s) => sinks.push(Box::new(s)),
                Err(err) => eprintln!("tapline sink {part}: {err}"),
            }
        } else {
            eprintln!("tapline unknown sink `{part}` (try stdout, file:/path, none)");
        }
    }
    if sinks.is_empty() {
        Box::new(StdoutSink::new(identity))
    } else if sinks.len() == 1 {
        sinks.remove(0)
    } else {
        Box::new(Fanout(sinks))
    }
}

fn headers_obj(pairs: &[crate::log::HeaderPair]) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    for p in pairs {
        match m.get_mut(&p.name) {
            Some(serde_json::Value::String(existing)) => {
                existing.push_str("; ");
                existing.push_str(&p.value);
            }
            _ => {
                m.insert(p.name.clone(), serde_json::Value::String(p.value.clone()));
            }
        }
    }
    m
}

fn line(entry: &Entry, idn: &Identity) -> String {
    let mut m = serde_json::Map::new();
    let put = |m: &mut serde_json::Map<String, serde_json::Value>, k: &str, v: serde_json::Value| {
        m.insert(k.to_string(), v);
    };
    put(&mut m, "_time", json!(entry.ts));
    put(
        &mut m,
        "_msg",
        json!(format!(
            "{} {} {} {}",
            entry.direction, entry.method, entry.path, entry.status
        )),
    );
    put(&mut m, "app", json!("tapline"));
    put(&mut m, "id", json!(entry.id));
    put(&mut m, "direction", json!(entry.direction));
    put(&mut m, "protocol", json!(entry.protocol));
    put(&mut m, "method", json!(entry.method));
    put(&mut m, "path", json!(entry.path));
    put(&mut m, "query", json!(entry.query));
    put(&mut m, "status", json!(entry.status));
    put(&mut m, "duration_ms", json!(entry.duration_ms));
    put(&mut m, "client_ip", json!(entry.client_ip));
    put(&mut m, "client_port", json!(entry.client_port));
    put(&mut m, "local_port", json!(entry.local_port));
    put(&mut m, "original_dst", json!(entry.original_dst));
    put(&mut m, "upstream", json!(entry.upstream));
    put(&mut m, "bytes_in", json!(entry.request_bytes));
    put(&mut m, "bytes_out", json!(entry.response_bytes));
    put(&mut m, "content_type", json!(entry.content_type));
    put(&mut m, "error", json!(entry.error));
    put(&mut m, "close_reason", json!(entry.close_reason));
    put(&mut m, "tls_sni", json!(entry.tls_sni));
    put(&mut m, "tcp_rtt_us", json!(entry.tcp_rtt_us));
    put(&mut m, "tcp_retrans", json!(entry.tcp_retrans));
    put(&mut m, "datagrams_in", json!(entry.datagrams_in));
    put(&mut m, "datagrams_out", json!(entry.datagrams_out));
    put(&mut m, "dns_qname", json!(entry.dns_qname));
    put(&mut m, "dns_qtype", json!(entry.dns_qtype));
    put(&mut m, "dns_rcode", json!(entry.dns_rcode));
    put(&mut m, "quic_version", json!(entry.quic_version));
    put(&mut m, "user_agent", json!(entry.user_agent));
    put(&mut m, "url", json!(entry.url));
    put(&mut m, "x_forwarded_for", json!(entry.x_forwarded_for));
    put(&mut m, "x_request_id", json!(entry.x_request_id));
    put(&mut m, "instance", json!(idn.instance));
    put(&mut m, "namespace", json!(idn.namespace));
    put(&mut m, "dlp_blocked", json!(entry.dlp_blocked));
    put(&mut m, "dlp_hash", json!(entry.dlp_hash));
    put(&mut m, "dlp_hits", json!(entry.dlp_hits));
    put(
        &mut m,
        "dlp_detectors",
        json!(entry
            .dlp_hits
            .iter()
            .map(|h| &h.detector)
            .collect::<Vec<_>>()),
    );
    put(&mut m, "mcp_session", json!(entry.mcp_session));
    put(&mut m, "mcp_tool", json!(entry.mcp_tool));
    put(&mut m, "mcp_resource", json!(entry.mcp_resource));
    let redact = crate::dlp::Mode::from_env() != crate::dlp::Mode::Off
        && std::env::var("TAPLINE_DLP_REDACT").unwrap_or_else(|_| "1".into()) != "0";
    let mut req_h = entry.request_headers.clone();
    let mut res_h = entry.response_headers.clone();
    if redact {
        crate::dlp::redact_headers(&mut req_h);
        crate::dlp::redact_headers(&mut res_h);
    }
    if !req_h.is_empty() {
        put(&mut m, "request_headers", serde_json::Value::Object(headers_obj(&req_h)));
    }
    if !res_h.is_empty() {
        put(&mut m, "response_headers", serde_json::Value::Object(headers_obj(&res_h)));
    }
    serde_json::Value::Object(m).to_string()
}