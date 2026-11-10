//! Thin CLI entry point for the Mirage client.
//!
//! All logic lives in the `mirage_client` library so the same code can be
//! embedded on mobile (Android/iOS) behind an FFI. This binary just starts the
//! Tokio runtime and hands off to [`mirage_client::cli_main`].

#[tokio::main]
async fn main() {
    mirage_client::cli_main().await
}
