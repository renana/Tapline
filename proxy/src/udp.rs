use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::dns::{looks_like_dns, parse_dns};
use crate::log::{now_ms, Entry, ProxyConfig, Store};
use crate::quic::{looks_like_quic, parse_quic};
use crate::udp_recv::{bind_udp, recv_from_orig};
use crate::{env, hostname, Hop};

#[derive(Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src: SocketAddr,
    orig: SocketAddr,
    inbound: bool,
}

struct Flow {
    started: Instant,
    last: Instant,
    bytes_in: u64,
    bytes_out: u64,
    dgrams_in: u64,
    dgrams_out: u64,
    protocol: String,
    method: String,
    path: String,
    sni: String,
    dns_qname: String,
    dns_qtype: String,
    dns_rcode: i32,
    quic_version: String,
    classified: bool,
    dlp_hits: Vec<crate::dlp::Hit>,
    dlp_hash: String,
    client: SocketAddr,
    orig: SocketAddr,
    upstream_addr: SocketAddr,
    direction: &'static str,
    local_port: u16,
}

pub async fn spawn(
    addr: String,
    hop: Hop,
    store: Arc<Store>,
    cfg: Arc<std::sync::RwLock<ProxyConfig>>,
    idle: Duration,
) {
    tokio::spawn(async move {
        if let Err(err) = run(addr, hop, store, cfg, idle).await {
            eprintln!("udp {err}");
        }
    });
}

async fn run(
    addr: String,
    hop: Hop,
    store: Arc<Store>,
    cfg: Arc<std::sync::RwLock<ProxyConfig>>,
    idle: Duration,
) -> std::io::Result<()> {
    let listen = Arc::new(bind_udp(&addr)?);
    let local_port = listen.local_addr()?.port();
    let inbound = matches!(hop, Hop::Inbound);
    let direction: &'static str = if inbound { "inbound" } else { "outbound" };
    eprintln!("tapline udp {direction} {addr}");

    let flows: Arc<Mutex<HashMap<FlowKey, Arc<Mutex<Flow>>>>> = Arc::new(Mutex::new(HashMap::new()));
    let ups: Arc<Mutex<HashMap<FlowKey, Arc<UdpSocket>>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        listen.readable().await?;
        let (buf, src, orig_opt) = match recv_from_orig(&listen) {
            Ok(v) => v,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => {
                eprintln!("udp recv {err}");
                continue;
            }
        };
        let orig = match orig_opt {
            Some(o) if o.port() != local_port && o.port() != 0 => o,
            _ if inbound => {
                let app = cfg.read().expect("cfg").app.clone();
                app.parse().unwrap_or_else(|_| orig_opt.unwrap_or(src))
            }
            Some(o) => o,
            None => continue,
        };
        let upstream_addr = if inbound {
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, orig.port()))
        } else {
            orig
        };
        let key = FlowKey {
            src,
            orig,
            inbound,
        };
        let existing = {
            let map = flows.lock().expect("flows");
            let umap = ups.lock().expect("ups");
            match (map.get(&key), umap.get(&key)) {
                (Some(f), Some(u)) => Some((f.clone(), u.clone())),
                _ => None,
            }
        };
        let (flow, up) = if let Some(pair) = existing {
            pair
        } else {
            let up = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => Arc::new(s),
                Err(err) => {
                    eprintln!("udp bind ephemeral {err}");
                    continue;
                }
            };
            let flow = Arc::new(Mutex::new(Flow {
                started: Instant::now(),
                last: Instant::now(),
                bytes_in: 0,
                bytes_out: 0,
                dgrams_in: 0,
                dgrams_out: 0,
                protocol: "udp".into(),
                method: "UDP".into(),
                path: "*".into(),
                sni: String::new(),
                dns_qname: String::new(),
                dns_qtype: String::new(),
                dns_rcode: -1,
                quic_version: String::new(),
                classified: false,
                dlp_hits: Vec::new(),
                dlp_hash: String::new(),
                client: src,
                orig,
                upstream_addr,
                direction,
                local_port,
            }));
            {
                let mut map = flows.lock().expect("flows");
                let mut umap = ups.lock().expect("ups");
                map.insert(key.clone(), flow.clone());
                umap.insert(key.clone(), up.clone());
            }
            let listen2 = listen.clone();
            let store2 = store.clone();
            let flows2 = flows.clone();
            let ups2 = ups.clone();
            let key2 = key.clone();
            let up2 = up.clone();
            let flow2 = flow.clone();
            tokio::spawn(async move {
                relay_up(up2, listen2, flow2, idle, store2, flows2, ups2, key2).await;
            });
            (flow, up)
        };
        {
            let mut f = flow.lock().expect("flow");
            f.last = Instant::now();
            f.bytes_in += buf.len() as u64;
            f.dgrams_in += 1;
            if !f.classified {
                classify_first(&mut f, &buf, orig.port());
                f.classified = true;
            } else if f.protocol == "dns" {
                if let Some(d) = parse_dns(&buf) {
                    if d.response {
                        f.dns_rcode = i32::from(d.rcode);
                    }
                }
            }
        }
        if let Err(err) = up.send_to(&buf, upstream_addr).await {
            eprintln!("udp send upstream {err}");
        }
    }
}

fn classify_first(f: &mut Flow, buf: &[u8], orig_port: u16) {
    if orig_port == 53 || looks_like_dns(buf) {
        f.protocol = "dns".into();
        f.method = "DNS".into();
        if let Some(d) = parse_dns(buf) {
            f.path = d.qname.clone();
            f.dns_qname = d.qname;
            f.dns_qtype = d.qtype_name;
            if d.response {
                f.dns_rcode = i32::from(d.rcode);
            }
        }
        dlp_flow(f, buf);
        return;
    }
    if looks_like_quic(buf) {
        f.protocol = "quic".into();
        f.method = "QUIC".into();
        if let Some(q) = parse_quic(buf) {
            f.quic_version = format!("{:x}", q.version);
            if !q.sni.is_empty() {
                f.sni = q.sni.clone();
                f.path = q.sni;
            }
        }
        dlp_flow(f, buf);
        return;
    }
    if buf.len() >= 8 && buf[0] & 0xc0 == 0 && buf[4..8] == [0x21, 0x12, 0xa4, 0x42] {
        f.protocol = "stun".into();
        f.method = "STUN".into();
        dlp_flow(f, buf);
        return;
    }
    if buf.len() >= 4 {
        let t = buf[0];
        if (1..=4).contains(&t) && buf[1] == 0 && buf[2] == 0 && buf[3] == 0 {
            f.protocol = "wireguard".into();
            f.method = "WG".into();
            dlp_flow(f, buf);
            return;
        }
    }
    if buf.len() >= 2 && buf[0] == 0x16 && buf[1] == 0xfe {
        f.protocol = "dtls".into();
        f.method = "DTLS".into();
        dlp_flow(f, buf);
        return;
    }
    if orig_port == 123 && !buf.is_empty() {
        f.protocol = "ntp".into();
        f.method = "NTP".into();
    }
    dlp_flow(f, buf);
}

fn dlp_flow(f: &mut Flow, buf: &[u8]) {
    let eng = crate::dlp::Engine::from_env();
    if eng.mode == crate::dlp::Mode::Off {
        return;
    }
    let mut hits = eng.scan(crate::inspect::Dir::Upstream, buf);
    if !f.dns_qname.is_empty() {
        hits.extend(eng.scan(crate::inspect::Dir::Upstream, f.dns_qname.as_bytes()));
    }
    f.dlp_hits = hits;
}

async fn relay_up(
    up: Arc<UdpSocket>,
    listen: Arc<UdpSocket>,
    flow: Arc<Mutex<Flow>>,
    idle: Duration,
    store: Arc<Store>,
    flows: Arc<Mutex<HashMap<FlowKey, Arc<Mutex<Flow>>>>>,
    ups: Arc<Mutex<HashMap<FlowKey, Arc<UdpSocket>>>>,
    key: FlowKey,
) {
    let mut buf = vec![0u8; 2048];
    loop {
        match tokio::time::timeout(Duration::from_secs(1), up.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                let client = {
                    let mut f = flow.lock().expect("flow");
                    f.last = Instant::now();
                    f.bytes_out += n as u64;
                    f.dgrams_out += 1;
                    if f.protocol == "dns" {
                        if let Some(d) = parse_dns(&buf[..n]) {
                            if d.response {
                                f.dns_rcode = i32::from(d.rcode);
                            }
                        }
                    }
                    f.client
                };
                let _ = listen.send_to(&buf[..n], client).await;
            }
            Ok(Err(_)) => {
                flush(&store, &flow);
                break;
            }
            Err(_) => {
                let expired = flow.lock().expect("flow").last.elapsed() >= idle;
                if expired {
                    flush(&store, &flow);
                    break;
                }
            }
        }
    }
    flows.lock().expect("flows").remove(&key);
    ups.lock().expect("ups").remove(&key);
}

fn flush(store: &Store, flow: &Mutex<Flow>) {
    let f = flow.lock().expect("flow");
    let status = if f.protocol == "dns" && f.dns_rcode >= 0 {
        f.dns_rcode
    } else {
        0
    };
    store.record(Entry {
        id: crate::log::new_id(),
        ts: now_ms(),
        method: f.method.clone(),
        path: f.path.clone(),
        query: if f.dns_qtype.is_empty() {
            String::new()
        } else {
            f.dns_qtype.clone()
        },
        status,
        duration_ms: f.started.elapsed().as_millis() as u64,
        client_ip: f.client.ip().to_string(),
        request_bytes: f.bytes_in,
        response_bytes: f.bytes_out,
        content_type: String::new(),
        upstream: f.upstream_addr.to_string(),
        error: None,
        source: "proxy",
        protocol: f.protocol.clone(),
        original_dst: f.orig.to_string(),
        direction: f.direction.into(),
        instance: env("TAPLINE_INSTANCE", &hostname()),
        namespace: env("TAPLINE_NAMESPACE", "default"),
        client_port: f.client.port(),
        local_port: f.local_port,
        close_reason: "idle".into(),
        tls_sni: f.sni.clone(),
        tcp_rtt_us: 0,
        tcp_retrans: 0,
        datagrams_in: f.dgrams_in,
        datagrams_out: f.dgrams_out,
        dns_qname: f.dns_qname.clone(),
        dns_qtype: f.dns_qtype.clone(),
        dns_rcode: f.dns_rcode,
        quic_version: f.quic_version.clone(),
        url: f.sni.clone(),
        user_agent: String::new(),
        x_forwarded_for: String::new(),
        x_request_id: String::new(),
        request_headers: Vec::new(),
        response_headers: Vec::new(),
        request_body: None,
        response_body: None,
        truncated: false,
        dlp_hits: f.dlp_hits.clone(),
        dlp_hash: f.dlp_hash.clone(),
        dlp_blocked: false,
        mcp_session: String::new(),
        mcp_tool: String::new(),
        mcp_resource: String::new(),
    });
}
