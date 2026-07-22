//! Minimal but real DNS wire-format codec for the dnstt tunnel.
//!
//! Unlike Mirage's DoH transport (which ships opaque bytes under a
//! `application/dns-message` content-type), the dnstt tunnel emits and parses
//! ACTUAL DNS messages: upstream data is base32-encoded into the query name's
//! labels (a subdomain of the tunnel domain), downstream data rides in the
//! answer's TXT character-strings. This is what lets it traverse a recursive
//! resolver - the query is a real DNS question the resolver forwards to the
//! authoritative name server (the bridge).
//!
//! Scope: exactly what the tunnel needs - one question, TXT answers, EDNS-less
//! for now. Decoding tolerates compression pointers (real resolvers use them);
//! encoding never compresses.

/// DNS record type TXT (RFC 1035 §3.2.1).
pub const TYPE_TXT: u16 = 16;
/// DNS record type OPT (EDNS0 pseudo-RR, RFC 6891 §6.1).
pub const TYPE_OPT: u16 = 41;
/// EDNS0 advertised UDP payload size. 1232 is the DNS-flag-day-2020 default that
/// modern stub resolvers (systemd-resolved, unbound, getdns) use.
const EDNS_UDP_BUFSIZE: u16 = 1232;
/// EDNS0 COOKIE option code (RFC 7873 §4).
const EDNS_OPT_COOKIE: u16 = 10;
/// DNS class IN.
pub const CLASS_IN: u16 = 1;
/// QR bit (1 = response) in the flags word.
const FLAG_QR: u16 = 0x8000;
/// AA bit (authoritative answer). The bridge IS the tunnel zone's authoritative
/// name server, so its responses must set this (RFC 1035 §4.1.1).
const FLAG_AA: u16 = 0x0400;
/// RD bit (recursion desired). Set by the querier; copied verbatim into the
/// response per RFC 1035 §4.1.1.
const FLAG_RD: u16 = 0x0100;
/// RA bit (recursion available). Only recursive resolvers set this; an
/// authoritative-only server clears it. (Old encode_response wrongly set it.)
const FLAG_RA: u16 = 0x0080;
/// TTL (seconds) on tunnel TXT answers. A zero TTL - the previous value - is
/// atypical for an authoritative TXT and, combined with AA=0/RA=1 and a missing
/// OPT, fingerprinted the tunnel to a passive-DNS monitor (finding #11). 60s is
/// the low end of what real short-lived TXT records (ACME, SPF services) publish,
/// so it blends in. Kept short deliberately: the tunnel repeats a query name only
/// for identical idle polls (no cache-busting nonce - a wire-format change would
/// be needed to add one), so a caching resolver could serve a stale answer for at
/// most this long before re-querying the bridge.
const RESPONSE_TTL: u32 = 60;
/// Max bytes in a single DNS label.
const MAX_LABEL: usize = 63;
/// Max bytes in a full domain name (including length octets + root).
const MAX_NAME: usize = 255;
/// Max bytes in one TXT character-string.
const MAX_TXT_CHUNK: usize = 255;

// base32 (RFC 4648, lowercase, no padding) - DNS-label-safe

const B32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode `data` as lowercase RFC-4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for &b in data {
        buf = (buf << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(B32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(B32_ALPHABET[idx] as char);
    }
    out
}

/// Decode a lowercase (case-insensitive) RFC-4648 base32 string (no padding).
/// Returns `None` on an invalid character.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let val = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5) | u64::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

// Name encode / decode

/// Encode a dotted domain name into DNS label wire format. Returns `None` if a
/// label exceeds 63 bytes or the whole name exceeds 255.
pub fn encode_name(name: &str, out: &mut Vec<u8>) -> Option<()> {
    let start = out.len();
    for label in name.split('.') {
        if label.is_empty() {
            continue; // tolerate trailing dot / empty labels
        }
        if label.len() > MAX_LABEL {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root
    if out.len() - start > MAX_NAME {
        return None;
    }
    Some(())
}

/// Decode a DNS name starting at `pos` in `msg`, following compression
/// pointers. Returns `(name, next_pos)` where `next_pos` is the offset just
/// after the name in the CURRENT record (pointers do not advance it past the
/// pointer). Returns `None` on malformed input / pointer loops.
pub fn decode_name(msg: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut p = pos;
    let mut next_after: Option<usize> = None;
    let mut hops = 0;
    // Bound the TOTAL decoded output (anti-decompression-bomb, DNSTT-DECOMP-1).
    // Without this, a small message with a 128-hop pointer chain could decode to
    // a huge name - an unauthenticated CPU/allocation amplification. Aborting
    // once the accumulated name exceeds MAX_NAME(255) makes the work O(255)
    // regardless of how the pointers are arranged.
    let mut total_len = 0usize;
    loop {
        let len = *msg.get(p)? as usize;
        if len == 0 {
            p += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // compression pointer: 14-bit offset
            let b2 = *msg.get(p + 1)? as usize;
            let ptr = ((len & 0x3F) << 8) | b2;
            if next_after.is_none() {
                next_after = Some(p + 2);
            }
            hops += 1;
            if hops > 128 || ptr >= msg.len() {
                return None; // loop / out of range
            }
            p = ptr;
            continue;
        }
        if len > MAX_LABEL {
            return None;
        }
        total_len += len + 1;
        if total_len > MAX_NAME {
            return None; // decompression bomb: decoded name exceeds the cap
        }
        let label = msg.get(p + 1..p + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        p += 1 + len;
    }
    let end = next_after.unwrap_or(p);
    Some((labels.join("."), end))
}

// Message header

/// A parsed DNS message header (12 bytes).
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// Transaction ID.
    pub id: u16,
    /// Flags word.
    pub flags: u16,
    /// Question count.
    pub qd: u16,
    /// Answer count.
    pub an: u16,
    /// Authority count.
    pub ns: u16,
    /// Additional count.
    pub ar: u16,
}

impl Header {
    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.qd.to_be_bytes());
        out.extend_from_slice(&self.an.to_be_bytes());
        out.extend_from_slice(&self.ns.to_be_bytes());
        out.extend_from_slice(&self.ar.to_be_bytes());
    }
    fn read(msg: &[u8]) -> Option<Self> {
        if msg.len() < 12 {
            return None;
        }
        let g = |i: usize| u16::from_be_bytes([msg[i], msg[i + 1]]);
        Some(Self {
            id: g(0),
            flags: g(2),
            qd: g(4),
            an: g(6),
            ns: g(8),
            ar: g(10),
        })
    }
}

// Query (client -> server)

/// Build a DNS query for `qname` (a TXT question). Standard recursion-desired
/// query so a recursive resolver forwards it.
pub fn encode_query(id: u16, qname: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(96);
    Header {
        id,
        flags: 0x0100, // RD (recursion desired)
        qd: 1,
        an: 0,
        ns: 0,
        ar: 1, // one additional RR: the EDNS0 OPT below
    }
    .write(&mut out);
    encode_name(qname, &mut out)?;
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    // EDNS0 OPT pseudo-RR. Its ABSENCE is a ~100% dnstt/iodine passive tell -
    // every modern stub resolver sends EDNS0 (red-team HIGH #5). We mirror one:
    // 1232-byte UDP bufsize + a fresh 8-byte client COOKIE (RFC 7873), which
    // real resolvers randomize per server, so it also blends with normal query
    // entropy rather than repeating a constant.
    write_edns0_opt_query(&mut out);
    Some(out)
}

/// Append a client-side EDNS0 OPT pseudo-RR (root name, TYPE=OPT, CLASS=UDP
/// bufsize, TTL=0, RDATA = one COOKIE option with an 8-byte client cookie).
fn write_edns0_opt_query(out: &mut Vec<u8>) {
    out.push(0x00); // NAME = root
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&EDNS_UDP_BUFSIZE.to_be_bytes()); // CLASS field = bufsize
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL: ext-rcode/version/flags = 0
    let mut cookie = [0u8; 8];
    let _ = getrandom::fill(&mut cookie); // best-effort; zeros on CSPRNG failure
    let rdlen: u16 = 4 + 8; // COOKIE option header (4) + 8-byte client cookie
    out.extend_from_slice(&rdlen.to_be_bytes());
    out.extend_from_slice(&EDNS_OPT_COOKIE.to_be_bytes()); // OPTION-CODE
    out.extend_from_slice(&8u16.to_be_bytes()); // OPTION-LENGTH = 8 (client cookie)
    out.extend_from_slice(&cookie);
}

/// A parsed query, carrying everything the authoritative response must mirror.
#[derive(Debug, Clone)]
pub struct Query {
    /// Transaction id (echoed into the response).
    pub id: u16,
    /// Lowercased question name (the tunnel subdomain).
    pub name: String,
    /// The query's RD bit, echoed into the response (RFC 1035 §4.1.1).
    pub recursion_desired: bool,
    /// Whether the query carried an EDNS0 OPT, so the response mirrors one
    /// (RFC 6891 §6.1.1). Its absence-in-response despite an EDNS query is a tell.
    pub had_opt: bool,
}

/// Parse a query message (server side). Returns the id, question name, and the
/// RD/EDNS state the response needs to echo. `None` if it isn't a well-formed
/// query.
pub fn parse_query(msg: &[u8]) -> Option<Query> {
    let h = Header::read(msg)?;
    if h.flags & FLAG_QR != 0 || h.qd < 1 {
        return None; // not a query
    }
    let (name, mut p) = decode_name(msg, 12)?;
    p += 4; // QTYPE + QCLASS of the first question
            // Tolerate (but skip) any further questions - dnstt sends exactly one.
    for _ in 1..h.qd {
        let (_n, next) = decode_name(msg, p)?;
        p = next + 4;
    }
    // Detect an EDNS0 OPT among the remaining RRs so the response can mirror it.
    let had_opt = scan_for_opt(msg, p, h.an.saturating_add(h.ns).saturating_add(h.ar));
    Some(Query {
        id: h.id,
        name: name.to_ascii_lowercase(),
        recursion_desired: h.flags & FLAG_RD != 0,
        had_opt,
    })
}

/// Scan `count` resource records starting at `pos` for an EDNS0 OPT (TYPE 41).
/// Stops (returning false) on any truncation - bounded, allocation-free work on
/// the pre-auth query path.
fn scan_for_opt(msg: &[u8], mut pos: usize, count: u16) -> bool {
    for _ in 0..count {
        let Some((_n, next)) = decode_name(msg, pos) else {
            return false;
        };
        pos = next;
        let (Some(&t0), Some(&t1)) = (msg.get(pos), msg.get(pos + 1)) else {
            return false;
        };
        if u16::from_be_bytes([t0, t1]) == TYPE_OPT {
            return true;
        }
        // NAME(read) + TYPE(2) + CLASS(2) + TTL(4) then RDLEN(2) at pos+8.
        let (Some(&l0), Some(&l1)) = (msg.get(pos + 8), msg.get(pos + 9)) else {
            return false;
        };
        pos = pos + 10 + u16::from_be_bytes([l0, l1]) as usize;
    }
    false
}

// Response (server -> client): TXT answer carrying downstream bytes

/// Build a DNS response echoing `qname` as a TXT answer whose character-strings
/// carry `payload` (split into 255-byte TXT chunks). `recursion_desired` echoes
/// the query's RD bit; when `echo_opt` is set (the query carried an EDNS0 OPT) a
/// mirrored OPT pseudo-RR is appended to the additional section.
///
/// The response is shaped like real authoritative software (BIND/NSD/Knot): AA
/// set, RA clear, RD echoed, a non-zero TTL, and a mirrored OPT - the previous
/// AA=0/RA=1/TTL=0/no-OPT combination was a passive-DNS tell (finding #11).
pub fn encode_response(
    id: u16,
    qname: &str,
    payload: &[u8],
    recursion_desired: bool,
    echo_opt: bool,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(64 + payload.len() + payload.len() / 255 + 8);
    // Authoritative answer for the tunnel zone: QR + AA, RA clear, RD echoed.
    let mut flags = FLAG_QR | FLAG_AA;
    if recursion_desired {
        flags |= FLAG_RD;
    }
    // An authoritative-only server never advertises recursion; guard against a
    // future edit reintroducing the old RA=1 tell (finding #11).
    debug_assert_eq!(flags & FLAG_RA, 0, "authoritative response must clear RA");
    Header {
        id,
        flags,
        qd: 1,
        an: 1,
        ns: 0,
        ar: u16::from(echo_opt), // one additional RR (the mirrored OPT) when echoed
    }
    .write(&mut out);
    // Question section (echoed). The question name starts at offset 12.
    encode_name(qname, &mut out)?;
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    // Answer: NAME is a compression pointer to the question name at offset 12
    // (0xC0 0x0C). Echoing the full name here would double the ~200-byte query
    // name and blow the 512-byte UDP budget, starving the downstream payload.
    out.push(0xC0);
    out.push(0x0C);
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&RESPONSE_TTL.to_be_bytes()); // small non-zero TTL (see const)
    let mut rdata = Vec::with_capacity(payload.len() + payload.len() / 255 + 1);
    if payload.is_empty() {
        rdata.push(0); // one empty character-string
    } else {
        for chunk in payload.chunks(MAX_TXT_CHUNK) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }
    }
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    // Mirror the query's EDNS0 OPT in the additional section (RFC 6891 §6.1.1).
    // The client's parse_response walks only the answer section, so an OPT here
    // is transparent to it (see the response_* round-trip tests).
    if echo_opt {
        write_edns0_opt_response(&mut out);
    }
    Some(out)
}

/// Append a bare EDNS0 OPT pseudo-RR to a response's additional section: root
/// name, TYPE=OPT, CLASS = advertised UDP bufsize (1232), TTL 0
/// (ext-rcode/version/flags all zero), empty RDATA. This mirrors that the query
/// was EDNS-capable without echoing any specific option (e.g. the client COOKIE).
fn write_edns0_opt_response(out: &mut Vec<u8>) {
    out.push(0x00); // NAME = root
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&EDNS_UDP_BUFSIZE.to_be_bytes()); // CLASS field = UDP bufsize
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL: ext-rcode/version/flags = 0
    out.extend_from_slice(&0u16.to_be_bytes()); // RDLEN = 0 (no options echoed)
}

/// Parse a response's first TXT answer, concatenating its character-strings
/// into the downstream payload. Returns `(id, payload)`.
pub fn parse_response(msg: &[u8]) -> Option<(u16, Vec<u8>)> {
    let h = Header::read(msg)?;
    if h.flags & FLAG_QR == 0 {
        return None; // not a response
    }
    let mut p = 12;
    // Skip questions.
    for _ in 0..h.qd {
        let (_n, next) = decode_name(msg, p)?;
        p = next + 4; // QTYPE + QCLASS
    }
    // Walk answers; return the first TXT rdata.
    for _ in 0..h.an {
        let (_n, next) = decode_name(msg, p)?;
        p = next;
        let rtype = u16::from_be_bytes([*msg.get(p)?, *msg.get(p + 1)?]);
        let rdlen = u16::from_be_bytes([*msg.get(p + 8)?, *msg.get(p + 9)?]) as usize;
        p += 10;
        let rdata = msg.get(p..p + rdlen)?;
        p += rdlen;
        if rtype == TYPE_TXT {
            let mut payload = Vec::with_capacity(rdlen);
            let mut i = 0;
            while i < rdata.len() {
                let clen = rdata[i] as usize;
                i += 1;
                let end = (i + clen).min(rdata.len());
                payload.extend_from_slice(&rdata[i..end]);
                i = end;
            }
            return Some((h.id, payload));
        }
    }
    Some((h.id, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrips() {
        for input in [
            &b""[..],
            &b"f"[..],
            &b"fo"[..],
            &b"foo"[..],
            &b"foob"[..],
            &b"fooba"[..],
            &b"foobar"[..],
            &(0..200u8).collect::<Vec<u8>>()[..],
        ] {
            let enc = base32_encode(input);
            assert!(
                enc.bytes()
                    .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)),
                "DNS-unsafe char in {enc}"
            );
            assert_eq!(base32_decode(&enc).unwrap(), input, "roundtrip {enc}");
        }
    }

    #[test]
    fn name_roundtrips() {
        let mut buf = Vec::new();
        encode_name("abc.example.com", &mut buf).unwrap();
        let (name, next) = decode_name(&buf, 0).unwrap();
        assert_eq!(name, "abc.example.com");
        assert_eq!(next, buf.len());
    }

    #[test]
    fn query_roundtrip_client_to_server() {
        let q = encode_query(0x1234, "aebagba.t.example.com").unwrap();
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.name, "aebagba.t.example.com");
        assert!(parsed.recursion_desired, "client query sets RD");
        assert!(parsed.had_opt, "client query carries an EDNS0 OPT");
    }

    #[test]
    fn query_carries_edns0_opt_with_cookie() {
        // red-team HIGH #5: every query MUST carry an EDNS0 OPT (its absence is a
        // dnstt/iodine tell). Header arcount=1 and an OPT (type 41) with a
        // COOKIE option follows the question; parse_query still reads the name.
        let q = encode_query(0x0001, "aa.t.example.com").unwrap();
        let h = Header::read(&q).unwrap();
        assert_eq!(h.ar, 1, "arcount must be 1 (the OPT RR)");
        // Locate the OPT: after the 12-byte header + question (name + type + class).
        let (_name, after_name) = decode_name(&q, 12).unwrap();
        let opt = after_name + 4; // skip QTYPE + QCLASS
        assert_eq!(q[opt], 0x00, "OPT NAME is root");
        assert_eq!(u16::from_be_bytes([q[opt + 1], q[opt + 2]]), TYPE_OPT);
        assert_eq!(
            u16::from_be_bytes([q[opt + 3], q[opt + 4]]),
            EDNS_UDP_BUFSIZE
        );
        // RDATA: COOKIE option (code 10), length 8.
        let rdlen = u16::from_be_bytes([q[opt + 9], q[opt + 10]]);
        assert_eq!(rdlen, 12);
        assert_eq!(
            u16::from_be_bytes([q[opt + 11], q[opt + 12]]),
            EDNS_OPT_COOKIE
        );
        // Two independent queries draw distinct cookies (per-query entropy).
        let q2 = encode_query(0x0002, "aa.t.example.com").unwrap();
        assert_ne!(q, q2, "cookie (and id) vary per query");
    }

    #[test]
    fn response_roundtrip_server_to_client() {
        let payload: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
        let r = encode_response(0x5678, "x.t.example.com", &payload, true, true).unwrap();
        let (id, got) = parse_response(&r).unwrap();
        assert_eq!(id, 0x5678);
        assert_eq!(got, payload, "TXT chunking must reassemble exactly");
    }

    #[test]
    fn authoritative_response_flags_and_opt() {
        // finding #11: an authoritative answer sets AA, clears RA, echoes the
        // query's RD, uses a non-zero TTL, and mirrors the query's EDNS0 OPT.
        let payload: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let r = encode_response(0x4242, "x.t.example.com", &payload, true, true).unwrap();
        let h = Header::read(&r).unwrap();
        assert_ne!(h.flags & FLAG_QR, 0, "QR set");
        assert_ne!(h.flags & FLAG_AA, 0, "AA (authoritative) set");
        assert_eq!(h.flags & FLAG_RA, 0, "RA (recursion available) clear");
        assert_ne!(h.flags & FLAG_RD, 0, "RD echoed from the query");
        assert_eq!(h.ar, 1, "one additional RR: the mirrored OPT");

        // The client's parser still recovers the TXT payload despite the OPT.
        let (id, got) = parse_response(&r).unwrap();
        assert_eq!(id, 0x4242);
        assert_eq!(got, payload, "client parse must ignore the additional OPT");

        // TTL is non-zero. Locate it: header(12) + question(name + QTYPE + QCLASS)
        // + answer(name-ptr 2 + TYPE 2 + CLASS 2) then TTL(4).
        let (_qn, after_q) = decode_name(&r, 12).unwrap();
        let ttl_pos = after_q + 4 + 2 + 2 + 2;
        let ttl = u32::from_be_bytes([r[ttl_pos], r[ttl_pos + 1], r[ttl_pos + 2], r[ttl_pos + 3]]);
        assert!(ttl > 0, "authoritative TTL must be non-zero, got {ttl}");

        // The mirrored OPT is a well-formed TYPE_OPT RR in the additional section.
        assert!(
            scan_for_opt(
                &r,
                after_q + 4,
                h.an.saturating_add(h.ns).saturating_add(h.ar)
            ),
            "response must carry an OPT RR"
        );

        // A query WITHOUT an OPT (RD clear) yields a response with neither.
        let r2 = encode_response(1, "x.t.example.com", b"hi", false, false).unwrap();
        let h2 = Header::read(&r2).unwrap();
        assert_eq!(h2.ar, 0, "no OPT mirrored when the query had none");
        assert_eq!(
            h2.flags & FLAG_RD,
            0,
            "RD cleared when the query didn't set it"
        );
        assert_ne!(h2.flags & FLAG_AA, 0, "still authoritative");
        let (_id2, got2) = parse_response(&r2).unwrap();
        assert_eq!(got2, b"hi", "OPT-less response still round-trips");
    }

    #[test]
    fn decode_name_follows_compression_pointer() {
        // Message: [12-byte header placeholder] then "com" root at offset 12,
        // then a name "x" + pointer to offset 12.
        let mut msg = vec![0u8; 12];
        // offset 12: 3 'c' 'o' 'm' 0
        msg.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        let ptr_start = msg.len();
        // "x" then pointer to 12
        msg.extend_from_slice(&[1, b'x', 0xC0, 12]);
        let (name, next) = decode_name(&msg, ptr_start).unwrap();
        assert_eq!(name, "x.com");
        assert_eq!(next, ptr_start + 4); // stops right after the pointer
    }

    #[test]
    fn parse_query_rejects_response() {
        let r = encode_response(1, "a.b", b"hi", true, true).unwrap();
        assert!(parse_query(&r).is_none());
    }
}
