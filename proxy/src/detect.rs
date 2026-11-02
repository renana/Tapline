use httparse::Status;

pub const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone, Debug, Default)]
pub struct Probe {
    pub protocol: &'static str,
    pub method: String,
    pub path: String,
    pub query: String,
    pub host: String,
    pub content_type: String,
    pub upgrade: String,
    pub grpc: bool,
    pub sni: String,
    pub headers: Vec<(String, String)>,
    pub user_agent: String,
}

impl Probe {
    fn tcp() -> Self {
        Self {
            protocol: "tcp",
            method: "TCP".into(),
            path: "*".into(),
            ..Self::default()
        }
    }
}

pub fn classify(buf: &[u8]) -> Probe {
    if buf.is_empty() {
        return Probe::tcp();
    }
    if buf.starts_with(H2_PREFACE) {
        return classify_h2(&buf[H2_PREFACE.len()..]);
    }
    if looks_like_http1(buf) {
        return classify_http1(buf);
    }
    if is_tls_client_hello(buf) {
        return classify_tls(buf);
    }
    Probe::tcp()
}

fn looks_like_http1(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|m| buf.starts_with(m))
}

fn classify_http1(buf: &[u8]) -> Probe {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    let mut probe = Probe::tcp();
    match req.parse(buf) {
        Ok(Status::Complete(_)) | Ok(Status::Partial) => {
            probe.protocol = "http1";
            probe.method = req.method.unwrap_or("HTTP").to_string();
            if let Some(path) = req.path {
                if let Some((p, q)) = path.split_once('?') {
                    probe.path = p.to_string();
                    probe.query = q.to_string();
                } else {
                    probe.path = path.to_string();
                }
            }
            for h in req.headers.iter() {
                let name = h.name.to_ascii_lowercase();
                let value = String::from_utf8_lossy(h.value).into_owned();
                ingest(&mut probe, name, value);
            }
            if probe.upgrade.to_ascii_lowercase().contains("websocket") {
                probe.protocol = "websocket";
            }
            mark_mcp(&mut probe, buf);
        }
        Err(_) => return Probe::tcp(),
    }
    probe
}

fn is_tls_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 6 && buf[0] == 0x16 && buf[1] == 0x03 && buf[5] == 0x01
}

fn classify_tls(buf: &[u8]) -> Probe {
    let mut probe = Probe {
        protocol: "tls",
        method: "TLS".into(),
        path: "*".into(),
        ..Probe::default()
    };
    if let Some(sni) = parse_sni(buf) {
        probe.path = sni.clone();
        probe.host = sni.clone();
        probe.sni = sni;
    }
    probe
}

/// SNI from a TLS record (0x16…) or a raw handshake (0x01 ClientHello).
pub fn tls_sni_from_handshake(buf: &[u8]) -> Option<String> {
    if buf.first() == Some(&0x16) {
        return parse_sni(buf);
    }
    if buf.len() < 4 || buf[0] != 0x01 {
        return None;
    }
    let hs_len = (usize::from(buf[1]) << 16) | (usize::from(buf[2]) << 8) | usize::from(buf[3]);
    let body = buf.get(4..4 + hs_len.min(buf.len() - 4))?;
    sni_from_client_hello_body(body)
}

fn sni_from_client_hello_body(mut p: &[u8]) -> Option<String> {
    if p.len() < 34 {
        return None;
    }
    p = &p[34..];
    if p.is_empty() {
        return None;
    }
    let sid = usize::from(p[0]);
    p = p.get(1..)?;
    p = p.get(sid..)?;
    if p.len() < 2 {
        return None;
    }
    let cs = usize::from(u16::from_be_bytes([p[0], p[1]]));
    p = p.get(2..)?;
    p = p.get(cs..)?;
    if p.is_empty() {
        return None;
    }
    let cm = usize::from(p[0]);
    p = p.get(1..)?;
    p = p.get(cm..)?;
    if p.len() < 2 {
        return None;
    }
    let ext_len = usize::from(u16::from_be_bytes([p[0], p[1]]));
    p = p.get(2..)?;
    p = &p[..ext_len.min(p.len())];
    while p.len() >= 4 {
        let typ = u16::from_be_bytes([p[0], p[1]]);
        let n = usize::from(u16::from_be_bytes([p[2], p[3]]));
        p = &p[4..];
        if n > p.len() {
            return None;
        }
        let data = &p[..n];
        p = &p[n..];
        if typ != 0 {
            continue;
        }
        if data.len() < 5 || data[2] != 0 {
            continue;
        }
        let nl = usize::from(u16::from_be_bytes([data[3], data[4]]));
        if 5 + nl > data.len() {
            return None;
        }
        return Some(String::from_utf8_lossy(&data[5..5 + nl]).into_owned());
    }
    None
}

fn parse_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    let off = 5;
    let end = (off + rec).min(buf.len());
    let h = &buf[off..end];
    if h.len() < 4 || h[0] != 0x01 {
        return None;
    }
    let hs_len = (usize::from(h[1]) << 16) | (usize::from(h[2]) << 8) | usize::from(h[3]);
    let mut p = &h[4..];
    if hs_len < p.len() {
        p = &p[..hs_len];
    }
    sni_from_client_hello_body(p)
}

fn classify_h2(after_preface: &[u8]) -> Probe {
    let mut probe = Probe {
        protocol: "h2",
        method: "H2".into(),
        path: "*".into(),
        ..Probe::default()
    };
    let mut decoder = hpack::Decoder::new();
    let mut offset = 0;
    while offset + 9 <= after_preface.len() {
        let len = u32::from_be_bytes([
            0,
            after_preface[offset],
            after_preface[offset + 1],
            after_preface[offset + 2],
        ]) as usize;
        let ty = after_preface[offset + 3];
        let end = offset + 9 + len;
        if end > after_preface.len() {
            break;
        }
        if ty == 0x1 {
            let payload = &after_preface[offset + 9..end];
            let flags = after_preface[offset + 4];
            let mut frag = payload;
            if flags & 0x8 != 0 {
                if frag.is_empty() {
                    break;
                }
                let pad = frag[0] as usize;
                frag = &frag[1..];
                if pad > frag.len() {
                    break;
                }
                frag = &frag[..frag.len() - pad];
            }
            if flags & 0x20 != 0 {
                if frag.len() < 5 {
                    break;
                }
                frag = &frag[5..];
            }
            if let Ok(headers) = decoder.decode(frag) {
                for (name, value) in headers {
                    let n = String::from_utf8_lossy(&name).into_owned();
                    let v = String::from_utf8_lossy(&value).into_owned();
                    ingest(&mut probe, n, v);
                }
            }
            break;
        }
        offset = end;
    }
    if probe.grpc {
        probe.protocol = "grpc";
    }
    mark_mcp(&mut probe, after_preface);
    probe
}

fn ingest(probe: &mut Probe, name: String, value: String) {
    let lname = name.to_ascii_lowercase();
    match lname.as_str() {
        ":method" => probe.method = value.clone(),
        ":path" => {
            if let Some((p, q)) = value.split_once('?') {
                probe.path = p.to_string();
                probe.query = q.to_string();
            } else {
                probe.path = value.clone();
            }
        }
        "host" | ":authority" => probe.host = value.clone(),
        "content-type" => {
            probe.grpc = value.to_ascii_lowercase().contains("grpc");
            probe.content_type = value.clone();
        }
        "upgrade" => probe.upgrade = value.clone(),
        "user-agent" => probe.user_agent = value.clone(),
        _ => {}
    }
    probe.headers.push((name, value));
}

fn mark_mcp(probe: &mut Probe, buf: &[u8]) {
    if probe.protocol == "websocket" {
        return;
    }
    let path_mcp = probe.path.contains("/mcp");
    let hdr_mcp = probe.headers.iter().any(|(n, _)| {
        n.eq_ignore_ascii_case("mcp-session-id") || n.eq_ignore_ascii_case("mcp-protocol-version")
    });
    let rpc = mcp_rpc_method(buf);
    if path_mcp || hdr_mcp || rpc.is_some() {
        probe.protocol = "mcp";
        if let Some(m) = rpc {
            probe.method = m;
        } else if probe.method == "TCP" || probe.method == "HTTP" || probe.method == "H2" {
            probe.method = "MCP".into();
        }
    }
}

fn mcp_rpc_method(buf: &[u8]) -> Option<String> {
    let body = if looks_like_http1(buf) {
        buf.windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| &buf[i + 4..])
            .unwrap_or(buf)
    } else {
        buf
    };
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let method = v.get("method")?.as_str()?;
    const MCP: &[&str] = &[
        "initialize",
        "ping",
        "notifications/initialized",
        "notifications/cancelled",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "prompts/list",
        "prompts/get",
        "logging/setLevel",
        "completion/complete",
    ];
    if MCP.contains(&method) || method.starts_with("notifications/") {
        Some(method.to_string())
    } else {
        None
    }
}

/// First-buffer response: HTTP/1 status-line or HTTP/2 HEADERS.
pub fn classify_response(buf: &[u8]) -> Option<(i32, Vec<(String, String)>)> {
    if buf.starts_with(b"HTTP/1.") {
        return classify_http1_response(buf);
    }
    classify_h2_response(buf)
}

fn classify_http1_response(buf: &[u8]) -> Option<(i32, Vec<(String, String)>)> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut res = httparse::Response::new(&mut headers);
    match res.parse(buf) {
        Ok(Status::Complete(_)) | Ok(Status::Partial) => {
            let code = res.code? as i32;
            let hdrs = res
                .headers
                .iter()
                .filter(|h| !h.name.is_empty())
                .map(|h| {
                    (
                        h.name.to_ascii_lowercase(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect();
            Some((code, hdrs))
        }
        Err(_) => None,
    }
}

fn classify_h2_response(buf: &[u8]) -> Option<(i32, Vec<(String, String)>)> {
    let mut decoder = hpack::Decoder::new();
    let mut offset = 0;
    while offset + 9 <= buf.len() {
        let len = u32::from_be_bytes([0, buf[offset], buf[offset + 1], buf[offset + 2]]) as usize;
        let ty = buf[offset + 3];
        let flags = buf[offset + 4];
        let end = offset + 9 + len;
        if end > buf.len() {
            break;
        }
        if ty == 0x1 {
            let mut frag = &buf[offset + 9..end];
            if flags & 0x8 != 0 {
                if frag.is_empty() {
                    break;
                }
                let pad = frag[0] as usize;
                frag = frag.get(1..frag.len().saturating_sub(pad))?;
            }
            if flags & 0x20 != 0 {
                frag = frag.get(5..)?;
            }
            let decoded = decoder.decode(frag).ok()?;
            let mut code = 0i32;
            let mut hdrs = Vec::new();
            for (name, value) in decoded {
                let n = String::from_utf8_lossy(&name).into_owned();
                let v = String::from_utf8_lossy(&value).into_owned();
                if n == ":status" {
                    code = v.parse().unwrap_or(0);
                }
                hdrs.push((n, v));
            }
            return Some((code, hdrs));
        }
        offset = end;
    }
    None
}

#[allow(dead_code)]
pub fn http_status(buf: &[u8]) -> Option<u16> {
    classify_response(buf).and_then(|(c, _)| u16::try_from(c).ok())
}
