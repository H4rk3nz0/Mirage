//! Benign HTTP/3 probe response for QUIC carriers that advertise ALPN `h3`.
//!
//! A QUIC carrier (Hysteria2, MASQUE) negotiates ALPN `h3` so it blends with
//! real HTTP/3 origins. If it then DROPS an unauthenticated stream (a scanner's
//! `GET /`, or a wrong pre-auth knock), a probing censor can tell it apart from
//! a real h3 server, which answers. This emits a plausible nginx `404` so the
//! prober sees a real origin's response instead of a silent hang (the active-
//! probe defense the Reality/meek carriers already have).
//!
//! The encoding is a fixed spec (RFC 9114 frames + RFC 9204 QPACK, no dynamic
//! table). MASQUE's `h3.rs` carries a byte-identical private copy; this shared
//! version is what Hysteria2 uses and MASQUE could later consolidate onto.

/// The nginx default 404 body, byte-for-byte, so a probe that reads it sees a
/// real origin.
const BENIGN_404_BODY: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";

const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;

/// Append `v` as an HTTP/3 QUIC varint (RFC 9000 §16).
fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0x40 {
        out.push(v as u8);
    } else if v < 0x4000 {
        out.push(0x40 | (v >> 8) as u8);
        out.push(v as u8);
    } else if v < 0x4000_0000 {
        out.push(0x80 | (v >> 24) as u8);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    } else {
        out.push(0xc0 | (v >> 56) as u8);
        out.push((v >> 48) as u8);
        out.push((v >> 40) as u8);
        out.push((v >> 32) as u8);
        out.push((v >> 24) as u8);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    }
}

/// HTTP/3 control stream type (RFC 9114 §6.2.1) and SETTINGS frame type (§7.2.4).
const H3_STREAM_TYPE_CONTROL: u64 = 0x00;
const H3_FRAME_SETTINGS: u64 = 0x04;

/// The bytes a server writes on its HTTP/3 CONTROL stream (L2): the control
/// stream type (0x00) then a SETTINGS frame with browser/CDN-plausible values.
/// A real h3 origin opens this immediately after the connection; an "h3
/// impostor" that sends nothing is distinguishable by an active prober. The
/// control stream MUST stay open for the connection lifetime.
#[must_use]
pub fn h3_server_control_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, H3_STREAM_TYPE_CONTROL);
    // SETTINGS payload: (id, value) varint pairs.
    let mut s = Vec::new();
    put_varint(&mut s, 0x01); // SETTINGS_QPACK_MAX_TABLE_CAPACITY
    put_varint(&mut s, 4096);
    put_varint(&mut s, 0x06); // SETTINGS_MAX_FIELD_SECTION_SIZE
    put_varint(&mut s, 0x1_0000);
    put_varint(&mut s, 0x07); // SETTINGS_QPACK_BLOCKED_STREAMS
    put_varint(&mut s, 100);
    put_varint(&mut out, H3_FRAME_SETTINGS);
    put_varint(&mut out, s.len() as u64);
    out.extend_from_slice(&s);
    out
}

/// Open the server's HTTP/3 control stream and write SETTINGS (L2). Returns the
/// [`quinn::SendStream`], which the caller MUST hold open for the connection
/// lifetime - finishing or dropping (resetting) a control stream is a fatal h3
/// error (`H3_CLOSED_CRITICAL_STREAM`), so we neither finish nor drop it here.
pub async fn open_h3_server_control(conn: &quinn::Connection) -> Result<quinn::SendStream, String> {
    let mut uni = conn
        .open_uni()
        .await
        .map_err(|e| format!("h3 control open_uni: {e}"))?;
    uni.write_all(&h3_server_control_bytes())
        .await
        .map_err(|e| format!("h3 control SETTINGS write: {e}"))?;
    Ok(uni)
}

/// Encode `value` as a QPACK/HPACK prefix integer with a `prefix_bits`-bit
/// prefix, OR-ing the first byte's pattern bits with `flags` (RFC 7541 §5.1).
fn qpack_int(out: &mut Vec<u8>, flags: u8, prefix_bits: u8, value: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(flags | value as u8);
    } else {
        out.push(flags | max as u8);
        let mut v = value - max;
        while v >= 128 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
}

/// Append a QPACK "Literal Field Line with Literal Name" (RFC 9204 §4.5.6), no
/// Huffman: name uses a 3-bit-prefix length, value a 7-bit-prefix length.
fn qpack_lit(out: &mut Vec<u8>, name: &str, value: &str) {
    qpack_int(out, 0x20, 3, name.len() as u64);
    out.extend_from_slice(name.as_bytes());
    qpack_int(out, 0x00, 7, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

/// Format `secs` (Unix epoch) as an RFC 7231 IMF-fixdate for the `Date` header
/// (Howard Hinnant's civil-from-days; no date-crate dependency). A response with
/// no `Date` is a passive tell - real HTTP servers always send one.
fn http_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let dow = (((days % 7) + 4) % 7) as usize;
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    const DOW: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DOW[dow],
        d,
        MON[(month - 1) as usize],
        year,
        hh,
        mm,
        ss
    )
}

/// Encode a minimal valid QPACK field section for an h3 response: `:status`
/// from the static table (RFC 9204 App. A: 404->27), then nginx's field order
/// (`server`, `date`, `content-type`, `content-length`), no `connection`
/// (forbidden in HTTP/3, RFC 9114 §4.2).
fn qpack_404_headers(date: &str, content_len: usize) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.push(0x00); // Required Insert Count = 0
    b.push(0x00); // sign + Delta Base = 0
    b.push(0xC0 | 27); // :status: 404 (static-table index 27)
    qpack_lit(&mut b, "server", "nginx");
    qpack_lit(&mut b, "date", date);
    qpack_lit(&mut b, "content-type", "text/html");
    qpack_lit(&mut b, "content-length", &content_len.to_string());
    b
}

/// The full HTTP/3 `404 Not Found` response bytes (HEADERS + DATA frames) for a
/// given wall-clock `now_unix`. Exposed for testing; production uses
/// [`send_benign_h3_404`].
#[must_use]
pub fn benign_h3_404_bytes(now_unix: u64) -> Vec<u8> {
    let body = BENIGN_404_BODY.as_bytes();
    let headers = qpack_404_headers(&http_date(now_unix), body.len());
    let mut out = Vec::with_capacity(headers.len() + body.len() + 18);
    put_varint(&mut out, FRAME_HEADERS);
    put_varint(&mut out, headers.len() as u64);
    out.extend_from_slice(&headers);
    put_varint(&mut out, FRAME_DATA);
    put_varint(&mut out, body.len() as u64);
    out.extend_from_slice(body);
    out
}

/// Write a plausible HTTP/3 `404 Not Found` on `send` and finish the stream, so
/// a benign probe (or a wrong-knock scanner) sees a real origin's answer instead
/// of a silent drop that fingerprints the bridge. Best-effort: the caller still
/// treats the connection as rejected afterwards.
///
/// # Errors
/// Returns the underlying [`quinn::WriteError`] if the write fails.
pub async fn send_benign_h3_404(send: &mut quinn::SendStream) -> Result<(), quinn::WriteError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let out = benign_h3_404_bytes(now);
    send.write_all(&out).await?;
    let _ = send.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Read one QUIC varint (RFC 9000 §16) at `off`; returns (value, next_off).
    fn get_varint(b: &[u8], off: usize) -> (u64, usize) {
        let first = b[off];
        let len = 1usize << (first >> 6); // 1/2/4/8 bytes by the two prefix bits
        let mut v = u64::from(first & 0x3f);
        for &byte in &b[off + 1..off + len] {
            v = (v << 8) | u64::from(byte);
        }
        (v, off + len)
    }

    // The response must be well-formed h3: a HEADERS frame then a DATA frame,
    // with a QPACK field section whose prefix is RIC=0/Base=0 followed by the
    // static-table :status 404 (0xC0|27), and the nginx body verbatim.
    #[test]
    fn benign_404_is_wellformed_h3() {
        let b = benign_h3_404_bytes(1_700_000_000);
        // Frame 0: HEADERS (type 0x01) + varint length (may be 1 OR 2 bytes).
        let (ftype, o) = get_varint(&b, 0);
        assert_eq!(ftype, FRAME_HEADERS);
        let (hlen, hstart) = get_varint(&b, o);
        // QPACK field-section prefix + :status 404.
        assert_eq!(&b[hstart..hstart + 3], &[0x00, 0x00, 0xC0 | 27]);
        // Frame 1: DATA (type 0x00) directly after the header section.
        let (dtype, _) = get_varint(&b, hstart + hlen as usize);
        assert_eq!(dtype, FRAME_DATA);
        // Body is the nginx 404, verbatim, at the tail.
        assert!(b.ends_with(BENIGN_404_BODY.as_bytes()));
    }

    /// L2: the server control-stream bytes must be a well-formed h3 control
    /// stream - control stream type 0x00, then a SETTINGS frame (0x04) whose
    /// length exactly frames a set of (id, value) varint pairs including the
    /// QPACK + field-section-size settings a real origin advertises.
    #[test]
    fn h3_server_control_is_wellformed() {
        let b = h3_server_control_bytes();
        // Control stream type 0x00.
        let (stype, o) = get_varint(&b, 0);
        assert_eq!(stype, H3_STREAM_TYPE_CONTROL);
        // SETTINGS frame type 0x04 + length.
        let (ftype, o) = get_varint(&b, o);
        assert_eq!(ftype, H3_FRAME_SETTINGS);
        let (flen, body_start) = get_varint(&b, o);
        assert_eq!(
            b.len(),
            body_start + flen as usize,
            "SETTINGS length frames the whole remainder"
        );
        // Parse (id, value) pairs; they must consume exactly the frame body.
        let mut i = body_start;
        let mut ids = Vec::new();
        while i < b.len() {
            let (id, n1) = get_varint(&b, i);
            let (_val, n2) = get_varint(&b, n1);
            ids.push(id);
            i = n2;
        }
        assert_eq!(i, b.len(), "settings pairs consume the frame exactly");
        assert!(
            ids.contains(&0x01) && ids.contains(&0x06) && ids.contains(&0x07),
            "advertises QPACK table + field-section-size + blocked-streams like a real origin"
        );
    }

    #[test]
    fn http_date_matches_rfc7231() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }
}
