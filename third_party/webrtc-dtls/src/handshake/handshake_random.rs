use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;

pub const RANDOM_BYTES_LENGTH: usize = 28;
pub const HANDSHAKE_RANDOM_LENGTH: usize = RANDOM_BYTES_LENGTH + 4;

// https://tools.ietf.org/html/rfc4346#section-7.4.1.2
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeRandom {
    pub gmt_unix_time: SystemTime,
    pub random_bytes: [u8; RANDOM_BYTES_LENGTH],
}

impl Default for HandshakeRandom {
    fn default() -> Self {
        HandshakeRandom {
            gmt_unix_time: SystemTime::UNIX_EPOCH,
            random_bytes: [0u8; RANDOM_BYTES_LENGTH],
        }
    }
}

impl HandshakeRandom {
    pub fn size(&self) -> usize {
        4 + RANDOM_BYTES_LENGTH
    }

    pub fn marshal<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let secs = match self.gmt_unix_time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as u32,
            Err(_) => 0,
        };
        writer.write_u32::<BigEndian>(secs)?;
        writer.write_all(&self.random_bytes)?;

        writer.flush()
    }

    pub fn unmarshal<R: Read>(reader: &mut R) -> io::Result<Self> {
        let secs = reader.read_u32::<BigEndian>()?;
        let gmt_unix_time = if let Some(unix_time) =
            SystemTime::UNIX_EPOCH.checked_add(Duration::new(secs as u64, 0))
        {
            unix_time
        } else {
            SystemTime::UNIX_EPOCH
        };

        let mut random_bytes = [0u8; RANDOM_BYTES_LENGTH];
        reader.read_exact(&mut random_bytes)?;

        Ok(HandshakeRandom {
            gmt_unix_time,
            random_bytes,
        })
    }

    // populate fills the HandshakeRandom with random values
    // may be called multiple times
    //
    // MIRAGE FINGERPRINT PATCH: modern TLS/DTLS clients (BoringSSL
    // `ssl_fill_hello_random`, which Chrome/libwebrtc use) fill the ENTIRE
    // 32-byte Random with CSPRNG output and do NOT embed a `gmt_unix_time`. A
    // real wall-clock timestamp in the first 4 bytes is both a fingerprint (it
    // differs from every browser) and a mild clock leak. So randomize the
    // gmt_unix_time slot too — marshal() derives those 4 bytes from it, so
    // seeding it with a random u32 makes the whole 32-byte block random.
    pub fn populate(&mut self) {
        let mut rng = rand::thread_rng();
        let rand_secs: u32 = rng.gen();
        self.gmt_unix_time = SystemTime::UNIX_EPOCH + Duration::from_secs(rand_secs as u64);
        rng.fill(&mut self.random_bytes);
    }
}

#[cfg(test)]
mod mirage_random_test {
    use super::*;

    // The Random must not embed a real wall-clock timestamp (Chrome/BoringSSL
    // send 32 fully-random bytes). Assert the first 4 marshaled bytes are not
    // the current unix time, and that two populates differ (i.e. randomized).
    #[test]
    fn populate_randomizes_gmt_unix_time() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let mut a = HandshakeRandom::default();
        a.populate();
        let mut ra = vec![];
        a.marshal(&mut ra).unwrap();
        let secs_a = u32::from_be_bytes([ra[0], ra[1], ra[2], ra[3]]);
        // Not the current time (within a generous 1-day window). A random u32
        // landing in that window has probability ~86400/2^32 ≈ 2e-5.
        assert!(
            secs_a < now.saturating_sub(86_400) || secs_a > now.wrapping_add(86_400),
            "first 4 bytes look like a real timestamp ({secs_a} vs now {now})"
        );

        let mut b = HandshakeRandom::default();
        b.populate();
        let mut rb = vec![];
        b.marshal(&mut rb).unwrap();
        assert_ne!(&ra[..4], &rb[..4], "gmt_unix_time is not randomized");
        assert_ne!(a.random_bytes, b.random_bytes);
    }
}
