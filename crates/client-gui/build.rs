//! Compile the Slint UI markup (`ui/app.slint`) into generated Rust.
//!
//! `EmbedForSoftwareRenderer` embeds the fonts/glyphs the software renderer needs
//! at compile time, so the binary renders text without depending on any system
//! font library at build or run time (no fontconfig/freetype linkage).

fn main() {
    let cfg = slint_build::CompilerConfiguration::new()
        .embed_resources(slint_build::EmbedResourcesKind::EmbedForSoftwareRenderer);
    slint_build::compile_with_config("ui/app.slint", cfg).expect("failed to compile ui/app.slint");
}
