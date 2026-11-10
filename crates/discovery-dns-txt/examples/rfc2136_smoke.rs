//! Publish one announcement into a live authoritative server, then read it back.
//!
//! Not a unit test: it needs a real RFC 2136 server. Stand one up (BIND with an
//! `allow-update { key ... }` zone) and point this at it. Everything the unit
//! tests cannot reach - TSIG signing over the wire, the server's update policy,
//! the length-prefixed TCP framing - is exercised here.
//!
//! ```sh
//! cargo run -p mirage-discovery-dns-txt --example rfc2136_smoke -- \
//!   127.0.0.1:5354 example.org example.org mirage-key. <base64-secret>
//! ```
use mirage_discovery::channel::DiscoveryChannel;
use mirage_discovery_dns_txt::rfc2136::{Rfc2136Publisher, TsigAlgorithm};

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 5 {
        eprintln!("usage: rfc2136_smoke <server:port> <zone> <apex> <keyname> <b64secret>");
        std::process::exit(2);
    }
    let key = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&a[4])
            .expect("secret must be base64")
    };
    let p = Rfc2136Publisher::new(
        a[0].parse().expect("server addr"),
        &a[1],
        &a[2],
        &a[3],
        key,
        TsigAlgorithm::HmacSha256,
        60,
    )
    .expect("publisher");

    let info_hash = [0xABu8; 20];
    let announcement: Vec<u8> = (0..600u16).map(|i| (i % 251) as u8).collect();

    match p.publish(&info_hash, &announcement).await {
        Ok(()) => println!("PUBLISH OK"),
        Err(e) => {
            println!("PUBLISH FAILED: {e}");
            std::process::exit(1);
        }
    }
    println!(
        "NAME {}",
        mirage_discovery_dns_txt::channel::info_hash_to_label(&info_hash)
    );

    // Close the loop with the REAL fetcher against the REAL server: message
    // construction passing a unit test proves nothing about whether a client
    // can find and reassemble what we just wrote.
    use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;
    let addr: std::net::SocketAddr = a[0].parse().expect("server addr");
    let ns = NameServerConfigGroup::from_ips_clear(&[addr.ip()], addr.port(), true);
    let cfg = ResolverConfig::from_parts(None, vec![], ns);
    let resolver = TokioAsyncResolver::tokio(cfg, ResolverOpts::default());
    let ch = mirage_discovery_dns_txt::DnsTxtChannel::new(
        mirage_discovery_dns_txt::HickoryDnsTxtResolver::new(resolver, "smoke"),
        &a[2],
        "smoke",
    );
    match ch.fetch(&info_hash).await {
        Ok(v) if v.len() == 1 && v[0] == announcement => {
            println!("FETCH OK: reassembled {} bytes, byte-identical", v[0].len());
        }
        Ok(v) => {
            println!(
                "FETCH MISMATCH: {} record(s), lens {:?}",
                v.len(),
                v.iter().map(Vec::len).collect::<Vec<_>>()
            );
            std::process::exit(1);
        }
        Err(e) => {
            println!("FETCH FAILED: {e}");
            std::process::exit(1);
        }
    }
}
