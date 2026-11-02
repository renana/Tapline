use std::sync::Arc;
use std::sync::RwLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::log::{ProxyConfig, Store};

pub async fn run(addr: &str, store: Arc<Store>, cfg: Arc<RwLock<ProxyConfig>>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let store = store.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32_768];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let line = req.lines().next().unwrap_or("");
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or("GET");
            let path = parts.next().unwrap_or("/");

            let (status, body, ctype, extra) = route(method, path, &req, &store, &cfg);
            let mut extra_h = String::new();
            for (k, v) in extra {
                extra_h.push_str(&format!("{k}: {v}\r\n"));
            }
            let reason = if status == 204 {
                "No Content"
            } else if status == 202 {
                "Accepted"
            } else if status == 404 {
                "Not Found"
            } else if status == 405 {
                "Method Not Allowed"
            } else {
                "OK"
            };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\ncache-control: no-store\r\n{extra_h}\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        });
    }
}

fn route(
    method: &str,
    path: &str,
    raw: &str,
    store: &Store,
    cfg: &RwLock<ProxyConfig>,
) -> (u16, Vec<u8>, &'static str, Vec<(&'static str, String)>) {
    let path = path.split('?').next().unwrap_or(path);
    if path == "/mcp" {
        let (status, body, ctype, sid) = crate::mcp::handle(method, raw, store);
        let extra = match sid {
            Some(s) => vec![
                ("mcp-session-id", s),
                ("mcp-protocol-version", "2025-03-26".into()),
            ],
            None => vec![],
        };
        return (status, body, ctype, extra);
    }
    let wrap = |status: u16, body: Vec<u8>, ctype: &'static str| (status, body, ctype, Vec::new());
    if method == "GET" && (path == "/healthz" || path == "/v1/health") {
        return wrap(200, b"{\"ok\":true,\"sidecar\":true}".to_vec(), "application/json");
    }
    if method == "GET" && path == "/v1/snapshot" {
        let config = cfg.read().expect("cfg").clone();
        let body = serde_json::json!({
            "sidecar": true,
            "logs": store.summaries(),
            "stats": store.stats(),
            "config": config,
        });
        return wrap(
            200,
            serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
            "application/json",
        );
    }
    if method == "GET" && path.starts_with("/v1/logs/") {
        let id = path.trim_start_matches("/v1/logs/");
        return match store.by_id(id) {
            Some(e) => wrap(
                200,
                serde_json::to_vec(&e).unwrap_or_else(|_| b"null".to_vec()),
                "application/json",
            ),
            None => wrap(404, b"null".to_vec(), "application/json"),
        };
    }
    if method == "POST" && path == "/v1/clear" {
        store.clear();
        let config = cfg.read().expect("cfg").clone();
        let body = serde_json::json!({
            "sidecar": true,
            "logs": store.summaries(),
            "stats": store.stats(),
            "config": config,
        });
        return wrap(
            200,
            serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
            "application/json",
        );
    }
    if method == "POST" && path == "/v1/config" {
        if let Some(json) = raw.split("\r\n\r\n").nth(1) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(json.trim_end_matches('\0')) {
                let mut c = cfg.write().expect("cfg");
                if let Some(envoy) = v.get("envoy").and_then(|x| x.as_str()) {
                    if !envoy.is_empty() {
                        c.envoy = envoy.to_string();
                        c.custom_upstream = envoy.to_string();
                    }
                }
                if let Some(mode) = v.get("mode").and_then(|x| x.as_str()) {
                    c.mode = mode.to_string();
                }
                if let Some(pp) = v.get("proxyProtocol").and_then(|x| x.as_bool()) {
                    c.proxy_protocol = pp;
                }
                if let Some(ms) = v.get("timeoutMs").and_then(|x| x.as_u64()) {
                    c.timeout_ms = ms.clamp(500, 30_000);
                }
                let copy = c.clone();
                drop(c);
                return wrap(
                    200,
                    serde_json::to_vec(&copy).unwrap_or_else(|_| b"{}".to_vec()),
                    "application/json",
                );
            }
        }
        return wrap(400, b"{\"error\":\"invalid_json\"}".to_vec(), "application/json");
    }
    wrap(404, b"{\"error\":\"not_found\"}".to_vec(), "application/json")
}
