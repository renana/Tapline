#[derive(Clone, Debug, Default)]
pub struct DnsInfo {
    pub qname: String,
    #[allow(dead_code)]
    pub qtype: u16,
    pub qtype_name: String,
    pub rcode: u8,
    pub response: bool,
}

pub fn parse_dns(buf: &[u8]) -> Option<DnsInfo> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    if qd == 0 {
        return None;
    }
    let (qname, off) = read_name(buf, 12)?;
    if off + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
    Some(DnsInfo {
        qname,
        qtype,
        qtype_name: qtype_name(qtype).into(),
        rcode: (flags & 0xf) as u8,
        response: flags & 0x8000 != 0,
    })
}

pub fn looks_like_dns(buf: &[u8]) -> bool {
    parse_dns(buf).is_some()
}

fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        _ => "TYPE",
    }
}

fn read_name(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end = off;
    let mut hops = 0;
    loop {
        if hops > 10 || off >= buf.len() {
            return None;
        }
        let len = buf[off] as usize;
        if len == 0 {
            if !jumped {
                end = off + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if off + 1 >= buf.len() {
                return None;
            }
            let ptr = (((len & 0x3f) as usize) << 8) | buf[off + 1] as usize;
            if !jumped {
                end = off + 2;
            }
            off = ptr;
            jumped = true;
            hops += 1;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        off += 1;
        if off + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[off..off + len]).into_owned());
        off += len;
        if !jumped {
            end = off;
        }
    }
    if labels.is_empty() {
        return Some((".".into(), end));
    }
    Some((labels.join("."), end))
}
