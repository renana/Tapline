mod admin;
mod detect;
mod dlp;
mod dns;
mod inspect;
mod log;
mod mcp;
mod orig_dst;
mod origin;
mod quic;
mod sink;
mod tcp_info;
mod udp;
mod udp_recv;

use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use detect::{classify, classify_response};
use inspect::Dir;
use log::{now_ms, Entry, ProxyConfig, Store};
use orig_dst::original_dst;
use sink::Identity;
use tcp_info::tcp_kernel_info;

#[derive(Clone, Copy)]
pub(crate) enum Hop {
    Inbound,
    Outbound,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let inbound = env("TAPLINE_INBOUND", &env("TAPLINE_LISTEN", "0.0.0.0:15000"));
    let app = env("TAPLINE_APP", &env("TAPLINE_ENVOY", "127.0.0.1:15001"));
    let outbound = env("TAPLINE_OUTBOUND", "0.0.0.0:15005");
    let admin_addr = env("TAPLINE_ADMIN", "127.0.0.1:15002");
    let origin_addr = env("TAPLINE_ORIGIN", "127.0.0.1:15001");
    let proxy_protocol = env("TAPLINE_PROXY_PROTOCOL", "0") != "0";
    let run_origin = env("TAPLINE_RUN_ORIGIN", "1") != "0";
    let instance = env("TAPLINE_INSTANCE", &hostname());
    let namespace = env("TAPLINE_NAMESPACE", "default");
    let sink_spec = env("TAPLINE_SINK", "stdout");

    let identity = Identity {
        instance: instance.clone(),
        namespace: namespace.clone(),
    };
    let sink = sink::from_env(&sink_spec, identity);
    let store = Arc::new(Store::new(Arc::from(sink)));
    let cfg = Arc::new(RwLock::new(ProxyConfig {
        mode: "builtin".into(),
        custom_upstream: app.clone(),
        timeout_ms: 8_000,
        proxy_protocol,
        listen: inbound.clone(),
        envoy: app.clone(),
        inbound: inbound.clone(),
        outbound: outbound.clone(),
        app: app.clone(),
    }));

    if run_origin {
        let origin_addr = origin_addr.clone();
        tokio::spawn(async move {
            if let Err(err) = origin::run(&origin_addr).await {
                eprintln!("origin failed: {err}");
            }
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    {
        let store = store.clone();
        let cfg = cfg.clone();
        let admin_addr = admin_addr.clone();
        tokio::spawn(async move {
            if let Err(err) = admin::run(&admin_addr, store, cfg).await {
                eprintln!("admin failed: {err}");
            }
        });
    }

    spawn_listener(inbound.clone(), Hop::Inbound, store.clone(), cfg.clone()).await?;
    if outbound != "0" && !outbound.is_empty() {
        spawn_listener(outbound.clone(), Hop::Outbound, store.clone(), cfg.clone()).await?;
    }
    if env("TAPLINE_UDP", "1") != "0" {
        let idle_ms: u64 = env("TAPLINE_UDP_IDLE_MS", "30000").parse().unwrap_or(30_000);
        let idle = Duration::from_millis(idle_ms.max(1000));
        udp::spawn(inbound.clone(), Hop::Inbound, store.clone(), cfg.clone(), idle).await;
        if outbound != "0" && !outbound.is_empty() {
            udp::spawn(outbound.clone(), Hop::Outbound, store.clone(), cfg.clone(), idle).await;
        }
    }

    eprintln!("tapline inbound  {inbound}  → app (Envoy already decrypted)");
    eprintln!("tapline outbound {outbound} → orig-dst (Istio intercepts to :15001)");
    eprintln!("tapline admin    {admin_addr}  (MCP POST /mcp)");
    eprintln!(
        "tapline dlp      {}  (redact secrets in sink)",
        match dlp::Mode::from_env() {
            dlp::Mode::Off => "off",
            dlp::Mode::Detect => "detect",
            dlp::Mode::Block => "block",
        }
    );

    std::future::pending::<()>().await;
    Ok(())
}

async fn spawn_listener(
    addr: String,
    hop: Hop,
    store: Arc<Store>,
    cfg: Arc<RwLock<ProxyConfig>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(err) => {
                    eprintln!("accept {err}");
                    continue;
                }
            };
            let store = store.clone();
            let cfg = cfg.clone();
            tokio::spawn(async move {
                if let Err(err) = handle(hop, stream, peer, store, cfg).await {
                    eprintln!("conn {peer}: {err}");
                }
            });
        }
    });
    Ok(())
}

pub(crate) fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

pub(crate) fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "tapline".into())
}

async fn handle(
    hop: Hop,
    client: TcpStream,
    peer: std::net::SocketAddr,
    store: Arc<Store>,
    cfg: Arc<RwLock<ProxyConfig>>,
) -> std::io::Result<()> {
    let _ = client.set_nodelay(true);
    let orig = original_dst(&client);
    let local_port = client.local_addr().map(|a| a.port()).unwrap_or(0);
    let snapshot = cfg.read().expect("cfg").clone();
    let timeout = Duration::from_millis(snapshot.timeout_ms);
    let started = Instant::now();
    let direction = match hop {
        Hop::Inbound => "inbound",
        Hop::Outbound => "outbound",
    };

    let upstream_addr = match hop {
        Hop::Inbound => orig
            .map(|addr| addr.port())
            .filter(|p| *p != 15003 && *p != 0)
            .map(|p| format!("127.0.0.1:{p}"))
            .unwrap_or_else(|| snapshot.app.clone()),
        Hop::Outbound => match orig {
            Some(addr) => addr.to_string(),
            None => {
                let mut entry = skeleton(peer, orig, local_port, direction, String::new());
                entry.error = Some("missing_so_original_dst".into());
                entry.status = -1;
                entry.close_reason = "error".into();
                store.record(entry);
                return Ok(());
            }
        },
    };

    let mut entry = skeleton(peer, orig, local_port, direction, upstream_addr.clone());

    let upstream = match tokio::time::timeout(timeout, TcpStream::connect(&upstream_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            entry.error = Some(err.to_string());
            entry.status = -1;
            entry.duration_ms = started.elapsed().as_millis() as u64;
            entry.close_reason = "error".into();
            store.record(entry);
            return Err(err);
        }
        Err(_) => {
            entry.error = Some("upstream_timeout".into());
            entry.status = -1;
            entry.duration_ms = started.elapsed().as_millis() as u64;
            entry.close_reason = "idle".into();
            store.record(entry);
            return Ok(());
        }
    };
    let _ = upstream.set_nodelay(true);
    splice(client, upstream, store, entry, started).await
}

fn skeleton(
    peer: std::net::SocketAddr,
    orig: Option<std::net::SocketAddr>,
    local_port: u16,
    direction: &'static str,
    upstream: String,
) -> Entry {
    Entry {
        id: log::new_id(),
        ts: now_ms(),
        method: "TCP".into(),
        path: "*".into(),
        query: String::new(),
        status: 0,
        duration_ms: 0,
        client_ip: peer.ip().to_string(),
        request_bytes: 0,
        response_bytes: 0,
        content_type: String::new(),
        upstream,
        error: None,
        source: "proxy",
        protocol: "tcp".into(),
        original_dst: orig.map(|s| s.to_string()).unwrap_or_default(),
        direction: direction.into(),
        instance: env("TAPLINE_INSTANCE", &hostname()),
        namespace: env("TAPLINE_NAMESPACE", "default"),
        client_port: peer.port(),
        local_port,
        close_reason: String::new(),
        tls_sni: String::new(),
        tcp_rtt_us: 0,
        tcp_retrans: 0,
        datagrams_in: 0,
        datagrams_out: 0,
        dns_qname: String::new(),
        dns_qtype: String::new(),
        dns_rcode: -1,
        quic_version: String::new(),
        url: String::new(),
        user_agent: String::new(),
        x_forwarded_for: String::new(),
        x_request_id: String::new(),
        request_headers: Vec::new(),
        response_headers: Vec::new(),
        request_body: None,
        response_body: None,
        truncated: false,
        dlp_hits: Vec::new(),
        dlp_hash: String::new(),
        dlp_blocked: false,
        mcp_session: String::new(),
        mcp_tool: String::new(),
        mcp_resource: String::new(),
    }
}

fn fill_tcp_info(entry: &mut Entry, stream: &TcpStream) {
    if let Some((rtt, retrans)) = tcp_kernel_info(stream) {
        entry.tcp_rtt_us = rtt;
        entry.tcp_retrans = retrans;
    }
}

fn close_reason(err: Option<&Error>) -> &'static str {
    match err {
        None => "fin",
        Some(e) if e.kind() == ErrorKind::UnexpectedEof => "fin",
        Some(e) if e.kind() == ErrorKind::TimedOut => "idle",
        Some(e) if e.kind() == ErrorKind::ConnectionReset => "rst",
        Some(_) => "error",
    }
}

fn worse_close<'a>(cur: Option<&'a Error>, next: &'a Error) -> &'a Error {
    if cur.is_none() {
        return next;
    }
    if next.kind() == ErrorKind::ConnectionReset {
        next
    } else {
        cur.unwrap()
    }
}

async fn splice(
    mut client: TcpStream,
    mut upstream: TcpStream,
    store: Arc<Store>,
    mut entry: Entry,
    started: Instant,
) -> std::io::Result<()> {
    let mut scan = dlp::Scanner::new(dlp::Engine::from_env());
    let mut peek = vec![0u8; 16_384];
    let peeked = match tokio::time::timeout(Duration::from_millis(150), client.read(&mut peek)).await
    {
        Ok(Ok(n)) => n,
        Ok(Err(err)) => {
            entry.error = Some(err.to_string());
            entry.status = -1;
            entry.duration_ms = started.elapsed().as_millis() as u64;
            entry.close_reason = close_reason(Some(&err)).into();
            fill_tcp_info(&mut entry, &client);
            store.record(entry);
            return Err(err);
        }
        Err(_) => 0,
    };

    if peeked > 0 {
        scan.feed(Dir::Upstream, &peek[..peeked]);
        let probe = classify(&peek[..peeked]);
        entry.protocol = probe.protocol.to_string();
        entry.method = probe.method;
        entry.path = probe.path;
        entry.query = probe.query;
        entry.content_type = probe.content_type;
        entry.tls_sni = probe.sni;
        entry.user_agent = probe.user_agent;
        let mcp = dlp::mcp_from_peek(&probe.headers, &peek[..peeked]);
        entry.mcp_session = mcp.session;
        entry.mcp_tool = mcp.tool;
        entry.mcp_resource = mcp.resource;
        entry.request_headers = probe
            .headers
            .into_iter()
            .map(|(name, value)| log::HeaderPair { name, value })
            .collect();
        apply_http_meta(&mut entry);
        if !probe.host.is_empty() {
            if entry.protocol == "tls" {
                entry.url = probe.host;
            } else {
                entry.url = format!("{}{}", probe.host, entry.path);
            }
        }
        if scan.blocked {
            let _ = client.write_all(&dlp::http_403(scan.hits())).await;
            finish_dlp(&mut entry, scan);
            entry.dlp_blocked = true;
            entry.status = 403;
            entry.error = Some("dlp_blocked".into());
            entry.request_bytes = peeked as u64;
            entry.duration_ms = started.elapsed().as_millis() as u64;
            entry.close_reason = "dlp".into();
            fill_tcp_info(&mut entry, &client);
            store.record(entry);
            return Ok(());
        }
        if let Err(err) = upstream.write_all(&peek[..peeked]).await {
            finish_dlp(&mut entry, scan);
            entry.error = Some(err.to_string());
            entry.status = -1;
            entry.request_bytes = peeked as u64;
            entry.duration_ms = started.elapsed().as_millis() as u64;
            entry.close_reason = close_reason(Some(&err)).into();
            fill_tcp_info(&mut entry, &client);
            store.record(entry);
            return Err(err);
        }
        entry.request_bytes = peeked as u64;
    }

    let scan = Arc::new(std::sync::Mutex::new(scan));
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();

    let scan_up = scan.clone();
    let c2u = tokio::spawn(async move {
        let mut buf = vec![0u8; 16_384];
        let mut total = 0u64;
        let mut err: Option<Error> = None;
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            };
            {
                let mut s = scan_up.lock().expect("dlp");
                s.feed(Dir::Upstream, &buf[..n]);
                if s.blocked {
                    err = Some(Error::new(ErrorKind::PermissionDenied, "dlp_blocked"));
                    break;
                }
            }
            if let Err(e) = uw.write_all(&buf[..n]).await {
                err = Some(e);
                break;
            }
            total += n as u64;
        }
        let _ = uw.shutdown().await;
        (total, err)
    });

    let scan_dn = scan.clone();
    let u2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 16_384];
        let mut total = 0u64;
        let mut first = true;
        let mut status: Option<u16> = None;
        let mut err: Option<Error> = None;
        let mut resp_headers: Vec<log::HeaderPair> = Vec::new();
        loop {
            let n = match ur.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            };
            {
                let mut s = scan_dn.lock().expect("dlp");
                s.feed(Dir::Downstream, &buf[..n]);
            }
            if first {
                if let Some((code, hdrs)) = classify_response(&buf[..n]) {
                    status = u16::try_from(code).ok();
                    resp_headers = hdrs
                        .into_iter()
                        .map(|(name, value)| log::HeaderPair { name, value })
                        .collect();
                }
                first = false;
            }
            if let Err(e) = cw.write_all(&buf[..n]).await {
                err = Some(e);
                break;
            }
            total += n as u64;
        }
        let info = tcp_kernel_info(ur.as_ref());
        let _ = cw.shutdown().await;
        (total, status, err, info, resp_headers)
    });

    let up = c2u.await.unwrap_or((0, None));
    let down = u2c.await.unwrap_or((0, None, None, None, Vec::new()));
    let (up_bytes, up_err) = up;
    let (down_bytes, status, down_err, info, resp_headers) = down;
    entry.request_bytes += up_bytes;
    entry.response_bytes = down_bytes;
    if let Some(code) = status {
        entry.status = code as i32;
    } else if matches!(
        entry.protocol.as_str(),
        "tcp" | "websocket" | "h2" | "grpc" | "tls" | "mcp"
    ) {
        entry.status = 0;
    }
    if let Ok(s) = Arc::try_unwrap(scan) {
        if let Ok(scanner) = s.into_inner() {
            let blocked = scanner.blocked;
            let (hits, hash, fin_block) = scanner.finish();
            entry.dlp_hits = hits;
            entry.dlp_hash = hash;
            entry.dlp_blocked = blocked || fin_block;
        }
    }
    if entry.dlp_blocked {
        if entry.status < 400 {
            entry.status = 403;
        }
        if entry.error.is_none() {
            entry.error = Some("dlp_blocked".into());
        }
    }
    entry.close_reason = match (up_err.as_ref(), down_err.as_ref()) {
        (None, None) => {
            if entry.dlp_blocked {
                "dlp"
            } else {
                close_reason(None)
            }
        }
        (Some(a), None) => close_reason(Some(a)),
        (None, Some(b)) => close_reason(Some(b)),
        (Some(a), Some(b)) => close_reason(Some(worse_close(Some(a), b))),
    }
    .into();
    if let Some((rtt, retrans)) = info {
        entry.tcp_rtt_us = rtt;
        entry.tcp_retrans = retrans;
    }
    entry.response_headers = resp_headers;
    entry.duration_ms = started.elapsed().as_millis() as u64;
    store.record(entry);
    Ok(())
}

fn finish_dlp(entry: &mut Entry, scan: dlp::Scanner) {
    let (hits, hash, blocked) = scan.finish();
    entry.dlp_hits = hits;
    entry.dlp_hash = hash;
    entry.dlp_blocked = blocked;
}

fn header_get(headers: &[log::HeaderPair], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
        .map(|p| p.value.clone())
}

fn apply_http_meta(entry: &mut Entry) {
    if let Some(v) = header_get(&entry.request_headers, "user-agent") {
        entry.user_agent = v;
    }
    entry.x_forwarded_for = header_get(&entry.request_headers, "x-forwarded-for")
        .unwrap_or_else(|| format!("{}:{}", entry.client_ip, entry.client_port));
    entry.x_request_id = header_get(&entry.request_headers, "x-request-id").unwrap_or_default();
}
