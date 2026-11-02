//! QUIC v1 Initial → TLS ClientHello SNI (RFC 9000/9001).

use ring::aead::{self, LessSafeKey, UnboundKey, AES_128_GCM};
use ring::aead::quic::{HeaderProtectionKey, AES_128};
use ring::hkdf::{self, HKDF_SHA256};

const V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

#[derive(Clone, Debug, Default)]
pub struct QuicInfo {
    pub version: u32,
    pub sni: String,
}

pub fn parse_quic(buf: &[u8]) -> Option<QuicInfo> {
    if buf.len() < 7 || buf[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version == 0 {
        return None;
    }
    let mut info = QuicInfo {
        version,
        sni: String::new(),
    };
    if version == 1 {
        if let Some(sni) = decrypt_initial_sni(buf) {
            info.sni = sni;
        }
    }
    Some(info)
}

pub fn looks_like_quic(buf: &[u8]) -> bool {
    buf.len() >= 7 && buf[0] & 0x80 != 0 && u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) != 0
}

struct Dummy(usize);
impl hkdf::KeyType for Dummy {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand_label(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> Option<()> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    prk.expand(&[&info], Dummy(out.len())).ok()?.fill(out).ok()
}

fn decrypt_initial_sni(pkt: &[u8]) -> Option<String> {
    let (dcid, pn_off) = parse_long_header(pkt)?;
    let salt = hkdf::Salt::new(HKDF_SHA256, &V1_SALT);
    let initial = salt.extract(&dcid);
    let mut client_in = [0u8; 32];
    expand_label(&initial, b"client in", &mut client_in)?;
    let client = hkdf::Prk::new_less_safe(HKDF_SHA256, &client_in);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    expand_label(&client, b"quic key", &mut key)?;
    expand_label(&client, b"quic iv", &mut iv)?;
    expand_label(&client, b"quic hp", &mut hp)?;

    let mut header = pkt.to_vec();
    let sample_off = pn_off + 4;
    if sample_off + 16 > header.len() {
        return None;
    }
    let sample = &header[sample_off..sample_off + 16];
    let hpk = HeaderProtectionKey::new(&AES_128, &hp).ok()?;
    let mask = hpk.new_mask(sample).ok()?;
    header[0] ^= mask[0] & 0x0f;
    let pn_len = ((header[0] & 0x03) + 1) as usize;
    for i in 0..pn_len {
        header[pn_off + i] ^= mask[i + 1];
    }
    let mut pn = 0u64;
    for i in 0..pn_len {
        pn = (pn << 8) | u64::from(header[pn_off + i]);
    }
    let payload_off = pn_off + pn_len;
    if payload_off >= header.len() {
        return None;
    }
    let mut payload = header[payload_off..].to_vec();
    let mut nonce = iv;
    for i in 0..8 {
        nonce[4 + i] ^= ((pn >> (56 - 8 * i)) & 0xff) as u8;
    }
    let aead = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key).ok()?);
    let pt = aead
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&header[..payload_off]),
            &mut payload,
        )
        .ok()?;
    crypto_sni(pt)
}

fn parse_long_header(pkt: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut i = 5;
    let dcid_len = *pkt.get(i)? as usize;
    i += 1;
    let dcid = pkt.get(i..i + dcid_len)?.to_vec();
    i += dcid_len;
    let scid_len = *pkt.get(i)? as usize;
    i += 1 + scid_len;
    let (tok_len, n) = varint(pkt, i)?;
    i += n + tok_len as usize;
    let (_, n) = varint(pkt, i)?;
    i += n;
    Some((dcid, i))
}

fn varint(buf: &[u8], i: usize) -> Option<(u64, usize)> {
    let b = *buf.get(i)?;
    let n = 1usize << (b >> 6);
    if i + n > buf.len() {
        return None;
    }
    let mut v = u64::from(b & 0x3f);
    for k in 1..n {
        v = (v << 8) | u64::from(buf[i + k]);
    }
    Some((v, n))
}

fn crypto_sni(plain: &[u8]) -> Option<String> {
    let mut i = 0;
    let mut crypto = Vec::new();
    while i < plain.len() {
        let ty = plain[i];
        if ty == 0x00 {
            i += 1;
            continue;
        }
        i += 1;
        match ty {
            0x01 => {} // PING
            0x06 => {
                let (off, n) = varint(plain, i)?;
                i += n;
                let _ = off;
                let (len, n) = varint(plain, i)?;
                i += n;
                if i + len as usize > plain.len() {
                    break;
                }
                crypto.extend_from_slice(&plain[i..i + len as usize]);
                i += len as usize;
            }
            0x02 | 0x03 => {
                // ACK: largest, delay, range count, then ranges — stop if it looks messy
                let (_, n) = varint(plain, i)?;
                i += n;
                let (_, n) = varint(plain, i)?;
                i += n;
                let (rc, n) = varint(plain, i)?;
                i += n;
                let (_, n) = varint(plain, i)?;
                i += n;
                for _ in 0..rc {
                    let (_, n) = varint(plain, i)?;
                    i += n;
                    let (_, n) = varint(plain, i)?;
                    i += n;
                }
                if ty == 0x03 {
                    let (_, n) = varint(plain, i)?;
                    i += n;
                    let (_, n) = varint(plain, i)?;
                    i += n;
                    let (_, n) = varint(plain, i)?;
                    i += n;
                }
            }
            _ => break,
        }
    }
    crate::detect::tls_sni_from_handshake(&crypto)
}
