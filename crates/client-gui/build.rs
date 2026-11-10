//! Compile the Slint UI markup (`ui/app.slint`) into generated Rust.
//!
//! `EmbedForSoftwareRenderer` embeds the fonts/glyphs the software renderer needs
//! at compile time, so the binary renders text without depending on any system
//! font library at build or run time (no fontconfig/freetype linkage).

fn main() {
    // fluent-dark so the std-widgets we use (LineEdit, ScrollView, TextEdit) render
    // dark and blend with our hand-built dark theme instead of the default light
    // fluent style (light-grey inputs on a dark ground looked clunky).
    let cfg = slint_build::CompilerConfiguration::new()
        .embed_resources(slint_build::EmbedResourcesKind::EmbedForSoftwareRenderer)
        .with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/app.slint", cfg).expect("failed to compile ui/app.slint");
}
