//! Idle-aware bidirectional copy.
//!
//! [`tokio::io::copy_bidirectional`] returns only when BOTH directions reach
//! EOF, so an idle-but-open keep-alive tunnel (neither side sending, neither
//! side closing) pins its task, sockets, session, and - on the bridge - a
//! per-IP concurrency slot *forever*. A browser deliberately holds many such
//! idle keep-alive connections open for reuse, so "reap what's gone idle" is
//! exactly the draining the proxy needs.
//!
//! [`copy_bidirectional_idle`] is a drop-in that additionally tears the tunnel
//! down after `idle_timeout` elapses with zero bytes moving in *either*
//! direction. Choose the timeout above normal keep-alive reuse (minutes, not
//! seconds) so legitimate idle-then-reused connections still work; it only
//! reaps the genuinely dead.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Copy bytes in both directions between `a` and `b` until both sides reach
/// EOF, one side errors, OR `idle_timeout` elapses with no bytes transferred in
/// either direction. Takes ownership and closes both streams on return.
///
/// Returns `(a->b bytes, b->a bytes)`. On an idle reap the counts are whatever
/// had transferred; the streams are dropped (closed) as the function returns.
pub async fn copy_bidirectional_idle<A, B>(
    a: A,
    b: B,
    idle_timeout: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let up = Arc::new(AtomicU64::new(0)); // a->b
    let down = Arc::new(AtomicU64::new(0)); // b->a
                                            // Monotonic activity counter bumped on every successful read in either
                                            // direction; the watchdog reaps when it stops advancing.
    let activity = Arc::new(AtomicU64::new(0));

    let a2b = copy_dir(&mut ar, &mut bw, &up, &activity);
    let b2a = copy_dir(&mut br, &mut aw, &down, &activity);
    let watchdog = idle_watchdog(&activity, idle_timeout);

    let result = tokio::select! {
        r = async { tokio::try_join!(a2b, b2a) } => {
            r.map(|((), ())| ())
        }
        () = watchdog => Ok(()), // idle: fall through, drop the halves (closes both)
    };

    let counts = (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed));
    result.map(|()| counts)
}

/// Copy one direction until EOF, half-closing the destination write side on EOF
/// so TCP half-close propagates. Bumps `counter` (bytes) and `activity` (the
/// idle watchdog's liveness signal) on each chunk.
async fn copy_dir<R, W>(
    src: &mut R,
    dst: &mut W,
    counter: &AtomicU64,
    activity: &AtomicU64,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            // Source half-closed: propagate the FIN to the destination.
            let _ = dst.shutdown().await;
            return Ok(());
        }
        dst.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
        activity.fetch_add(1, Ordering::Relaxed);
    }
}

/// Resolve once `activity` has not advanced across a full `idle` window.
async fn idle_watchdog(activity: &AtomicU64, idle: Duration) {
    // A zero/absurdly-small window would busy-loop; clamp to something sane.
    let idle = idle.max(Duration::from_millis(1));
    loop {
        let mark = activity.load(Ordering::Relaxed);
        tokio::time::sleep(idle).await;
        if activity.load(Ordering::Relaxed) == mark {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn copies_both_directions_to_eof() {
        let (a, mut a_peer) = tokio::io::duplex(4096);
        let (b, mut b_peer) = tokio::io::duplex(4096);

        // a_peer sends a request; b_peer echoes a response; both then close.
        let ta = tokio::spawn(async move {
            a_peer.write_all(b"request").await.unwrap();
            a_peer.shutdown().await.unwrap();
            let mut got = Vec::new();
            a_peer.read_to_end(&mut got).await.unwrap();
            got
        });
        let tb = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut buf = [0u8; 64];
            // read the request, reply, close
            let n = b_peer.read(&mut buf).await.unwrap();
            got.extend_from_slice(&buf[..n]);
            b_peer.write_all(b"response").await.unwrap();
            b_peer.shutdown().await.unwrap();
            got
        });

        let (up, down) = copy_bidirectional_idle(a, b, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(up, 7); // "request"
        assert_eq!(down, 8); // "response"
        assert_eq!(ta.await.unwrap(), b"response");
        assert_eq!(tb.await.unwrap(), b"request");
    }

    #[tokio::test]
    async fn reaps_an_idle_tunnel() {
        // Neither peer ever sends or closes -> the copy must reap on idle, not
        // hang forever.
        let (a, _a_peer) = tokio::io::duplex(4096);
        let (b, _b_peer) = tokio::io::duplex(4096);
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            copy_bidirectional_idle(a, b, Duration::from_millis(50)),
        )
        .await
        .expect("must not hang past the idle window");
        let (up, down) = res.unwrap();
        assert_eq!((up, down), (0, 0));
    }

    #[tokio::test]
    async fn activity_defers_the_reaper() {
        // A trickle of data keeps the tunnel alive past several idle windows.
        let (a, mut a_peer) = tokio::io::duplex(4096);
        let (b, mut b_peer) = tokio::io::duplex(4096);
        let feeder = tokio::spawn(async move {
            for _ in 0..5 {
                a_peer.write_all(b"x").await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            a_peer.shutdown().await.unwrap();
            // drain b's side to EOF
            let mut sink = Vec::new();
            let _ = b_peer.read_to_end(&mut sink).await;
        });
        let (up, _down) = copy_bidirectional_idle(a, b, Duration::from_millis(50))
            .await
            .unwrap();
        // All 5 bytes made it despite the 50ms idle window (each write was < 50ms apart).
        assert_eq!(up, 5);
        feeder.await.unwrap();
    }
}
