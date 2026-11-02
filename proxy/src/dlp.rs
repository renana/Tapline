use std::collections::HashMap;

use ring::digest::{Context, SHA256};
use serde::Serialize;

use crate::inspect::Dir;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    Detect,
    Block,
}

impl Mode {
    pub fn from_env() -> Self {
        match std::env::var("TAPLINE_DLP")
            .unwrap_or_else(|_| "detect".into())
            .to_ascii_lowercase()
            .as_str()
        {
            "0" | "off" | "false" | "none" => Mode::Off,
            "block" | "prevent" | "deny" => Mode::Block,
            _ => Mode::Detect,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub detector: String,
    pub count: u32,
    pub severity: String,
    pub dir: String,
}

#[derive(Clone)]
pub struct Engine {
    pub mode: Mode,
    markings: Vec<String>,
}

impl Engine {
    pub fn from_env() -> Self {
        let raw = std::env::var("TAPLINE_DLP_MARKINGS").unwrap_or_else(|_| {
            "TOP SECRET,SECRET//,CLASSIFIED,CUI,//FOUO,NOFORN,RESTRICTED".into()
        });
        let markings = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            mode: Mode::from_env(),
            markings,
        }
    }

    pub fn scan(&self, dir: Dir, buf: &[u8]) -> Vec<Hit> {
        if self.mode == Mode::Off || buf.is_empty() {
            return Vec::new();
        }
        let d = match dir {
            Dir::Upstream => "in",
            Dir::Downstream => "out",
        };
        let mut counts: HashMap<(&'static str, &'static str), u32> = HashMap::new();
        bump(&mut counts, "jwt", "high", count_jwt(buf));
        bump(&mut counts, "pem", "high", count_pem(buf));
        bump(&mut counts, "aws_key", "high", count_aws(buf));
        bump(&mut counts, "bearer", "high", count_sub(buf, b"Bearer ") + count_sub(buf, b"bearer "));
        bump(&mut counts, "ssn", "high", count_ssn(buf));
        bump(&mut counts, "pan", "high", count_pan(buf));
        bump(&mut counts, "email", "medium", count_email(buf));
        let m = count_markings(buf, &self.markings);
        if m > 0 {
            counts.insert(("marking", "high"), m);
        }
        counts
            .into_iter()
            .filter(|(_, n)| *n > 0)
            .map(|((detector, severity), count)| Hit {
                detector: detector.into(),
                count,
                severity: severity.into(),
                dir: d.into(),
            })
            .collect()
    }
}

fn bump(map: &mut HashMap<(&'static str, &'static str), u32>, det: &'static str, sev: &'static str, n: u32) {
    if n > 0 {
        *map.entry((det, sev)).or_insert(0) += n;
    }
}

pub struct Scanner {
    engine: Engine,
    overlap: Vec<u8>,
    hits: Vec<Hit>,
    sha: Context,
    pub blocked: bool,
}

impl Scanner {
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            overlap: Vec::new(),
            hits: Vec::new(),
            sha: Context::new(&SHA256),
            blocked: false,
        }
    }

    pub fn feed(&mut self, dir: Dir, bytes: &[u8]) {
        if self.engine.mode == Mode::Off || bytes.is_empty() {
            return;
        }
        self.sha.update(bytes);
        let mut window = Vec::with_capacity(self.overlap.len() + bytes.len());
        window.extend_from_slice(&self.overlap);
        window.extend_from_slice(bytes);
        self.merge(self.engine.scan(dir, &window));
        const TAIL: usize = 96;
        let start = bytes.len().saturating_sub(TAIL);
        self.overlap = bytes[start..].to_vec();
        if self.engine.mode == Mode::Block && self.has_high() {
            self.blocked = true;
        }
    }

    fn merge(&mut self, extra: Vec<Hit>) {
        for h in extra {
            if let Some(e) = self
                .hits
                .iter_mut()
                .find(|x| x.detector == h.detector && x.dir == h.dir)
            {
                e.count += h.count;
            } else {
                self.hits.push(h);
            }
        }
    }

    pub fn has_high(&self) -> bool {
        self.hits.iter().any(|h| h.severity == "high")
    }

    pub fn hits(&self) -> &[Hit] {
        &self.hits
    }

    pub fn finish(self) -> (Vec<Hit>, String, bool) {
        let hash = hex(self.sha.finish().as_ref());
        (self.hits, hash, self.blocked)
    }
}

pub fn redact_headers(headers: &mut [crate::log::HeaderPair]) {
    for h in headers {
        if secret_header(&h.name) {
            h.value = "[redacted]".into();
        }
    }
}

pub fn secret_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "cookie"
            | "set-cookie"
            | "authorization"
            | "proxy-authorization"
            | "x-api-key"
            | "x-auth-token"
            | "authentication"
            | "x-amz-security-token"
    )
}

#[derive(Default)]
pub struct McpMeta {
    pub session: String,
    pub tool: String,
    pub resource: String,
}

pub fn mcp_from_peek(headers: &[(String, String)], buf: &[u8]) -> McpMeta {
    let mut meta = McpMeta::default();
    for (n, v) in headers {
        if n.eq_ignore_ascii_case("mcp-session-id") {
            meta.session = v.clone();
        }
    }
    let body = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &buf[i + 4..])
        .unwrap_or(buf);
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = v.get("params");
        match method {
            "tools/call" => {
                meta.tool = params
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .into();
            }
            "resources/read" => {
                meta.resource = params
                    .and_then(|p| p.get("uri"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .into();
            }
            "prompts/get" => {
                meta.tool = params
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|n| format!("prompt:{n}"))
                    .unwrap_or_default();
            }
            _ => {}
        }
    }
    meta
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

fn count_sub(buf: &[u8], pat: &[u8]) -> u32 {
    buf.windows(pat.len()).filter(|w| *w == pat).count() as u32
}

fn count_pem(buf: &[u8]) -> u32 {
    count_sub(buf, b"BEGIN PRIVATE KEY")
        + count_sub(buf, b"BEGIN RSA PRIVATE KEY")
        + count_sub(buf, b"BEGIN EC PRIVATE KEY")
        + count_sub(buf, b"BEGIN OPENSSH PRIVATE KEY")
}

fn count_aws(buf: &[u8]) -> u32 {
    let mut n = 0u32;
    for w in buf.windows(20) {
        if w.starts_with(b"AKIA") && w[4..].iter().all(|c| c.is_ascii_alphanumeric()) {
            n += 1;
        }
    }
    n
}

fn count_jwt(buf: &[u8]) -> u32 {
    let mut n = 0u32;
    let mut i = 0;
    while i + 8 < buf.len() {
        if buf[i..].starts_with(b"eyJ") {
            if let Some((a, b, c)) = jwt_parts(&buf[i..]) {
                if a >= 8 && b >= 8 && c >= 8 {
                    n += 1;
                    i += a + b + c + 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    n
}

fn jwt_parts(buf: &[u8]) -> Option<(usize, usize, usize)> {
    let d1 = buf.iter().position(|c| *c == b'.')?;
    let rest = buf.get(d1 + 1..)?;
    let d2 = rest.iter().position(|c| *c == b'.')?;
    let sig = rest.get(d2 + 1..)?;
    let s = sig
        .iter()
        .take_while(|c| c.is_ascii_alphanumeric() || **c == b'-' || **c == b'_')
        .count();
    Some((d1, d2, s))
}

fn count_ssn(buf: &[u8]) -> u32 {
    let mut n = 0u32;
    for w in buf.windows(11) {
        if w[3] == b'-'
            && w[6] == b'-'
            && w[0].is_ascii_digit()
            && w[1].is_ascii_digit()
            && w[2].is_ascii_digit()
            && w[4].is_ascii_digit()
            && w[5].is_ascii_digit()
            && w[7].is_ascii_digit()
            && w[8].is_ascii_digit()
            && w[9].is_ascii_digit()
            && w[10].is_ascii_digit()
        {
            n += 1;
        }
    }
    n
}

fn count_email(buf: &[u8]) -> u32 {
    let mut n = 0u32;
    for (i, c) in buf.iter().enumerate() {
        if *c != b'@' || i == 0 {
            continue;
        }
        let local_ok = buf[i - 1].is_ascii_alphanumeric();
        let rest = &buf[i + 1..];
        if rest.len() < 3 {
            continue;
        }
        if let Some(dot) = rest.iter().position(|x| *x == b'.') {
            if dot >= 1 && rest.get(dot + 1).is_some_and(|x| x.is_ascii_alphabetic()) {
                if local_ok {
                    n += 1;
                }
            }
        }
    }
    n
}

fn count_pan(buf: &[u8]) -> u32 {
    let mut n = 0u32;
    let mut i = 0;
    while i < buf.len() {
        if !buf[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < buf.len() && (buf[i].is_ascii_digit() || buf[i] == b' ' || buf[i] == b'-') {
            i += 1;
        }
        let digits: Vec<u8> = buf[start..i]
            .iter()
            .filter(|c| c.is_ascii_digit())
            .copied()
            .collect();
        let len = digits.len();
        if (13..=19).contains(&len) && luhn(&digits) && digits.iter().any(|&d| d != digits[0]) {
            n += 1;
        }
    }
    n
}

fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for d in digits.iter().rev() {
        let mut v = (d - b'0') as u32;
        if alt {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        alt = !alt;
    }
    sum % 10 == 0
}

fn count_markings(buf: &[u8], markings: &[String]) -> u32 {
    let lower = ascii_lower(buf);
    let mut n = 0u32;
    for m in markings {
        let pat = m.to_ascii_lowercase();
        if pat.len() < 3 {
            continue;
        }
        n += count_sub(&lower, pat.as_bytes());
    }
    n
}

fn ascii_lower(buf: &[u8]) -> Vec<u8> {
    buf.iter()
        .map(|c| if c.is_ascii_uppercase() { c + 32 } else { *c })
        .collect()
}

pub fn http_403(detectors: &[Hit]) -> Vec<u8> {
    let names: Vec<&str> = detectors.iter().map(|h| h.detector.as_str()).collect();
    let json = serde_json::json!({
        "error": "tapline_dlp",
        "blocked": true,
        "detectors": names,
    });
    let body = json.to_string();
    format!(
        "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\ncache-control: no-store\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
