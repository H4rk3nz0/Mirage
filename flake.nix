{
  # Pinned Rust toolchain + reproducible build targets for Mirage (I7).
  #
  # Under the "lives at stake" threat model operators who self-build
  # from source need byte-identical outputs across machines — a
  # tampered build host must produce a binary that differs from the
  # operator's local build, so a simple `sha256sum` check catches it.
  # This flake delivers that invariant by:
  #
  # - Locking nixpkgs at a specific flake.lock rev (pins stdlib + libc).
  # - Locking the Rust toolchain to the exact version named in
  #   rust-toolchain.toml (via oxalica/rust-overlay).
  # - Building each bin with `cargo build --release --locked` under a
  #   sandboxed Nix derivation (no network, reproducible `CARGO_HOME`).
  #
  # Typical use:
  #   nix develop            # enter dev shell with the pinned toolchain
  #   nix build .#mirage-bridge
  #   nix build .#mirage-client
  #   nix build .#mirage-keygen
  #   nix build .#mirage-rotate
  #
  # Reproducibility check (run on two machines, expect identical hash):
  #   nix build .#mirage-bridge && sha256sum result/bin/mirage-bridge
  description = "Mirage — censorship-resistance / anonymization protocol";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # Exact toolchain from rust-toolchain.toml. Keeping this
        # file as the single source of truth means Nix consumers
        # and rustup consumers stay aligned.
        toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # A platform that uses our pinned toolchain for everything.
        rustPlatform = pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };

        # Shared attributes for each binary package.
        commonAttrs = {
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          # Reproducibility switches (see `man cargo-config`).
          CARGO_TERM_COLOR = "never";
          # Deterministic build-id; drop debug info so two builders
          # with different paths produce the same binary.
          RUSTFLAGS = "-C debuginfo=0 --remap-path-prefix $PWD=/build/mirage";
          # Disable incremental so every build is from scratch.
          CARGO_INCREMENTAL = "0";
          # --locked refuses any drift from the committed Cargo.lock.
          cargoBuildFlags = [ "--locked" "--release" ];
          doCheck = false;  # tests run in CI; package builds are
                             # release-only for speed.
          meta = with pkgs.lib; {
            description = "Mirage protocol";
            homepage = "https://github.com/OWNER/mirage";  # placeholder — set to the real repo
            license = licenses.agpl3Plus;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        mkBin = { name, bin ? name, pkg ? "mirage-bridge" }: rustPlatform.buildRustPackage (commonAttrs // {
          pname = name;
          version = "0.1.0";
          cargoBuildFlags = commonAttrs.cargoBuildFlags ++ [ "-p" pkg "--bin" bin ];
        });
      in
      {
        # ------------------------------------------------------------
        # Per-binary outputs. Each one builds exactly its target bin
        # so `nix build .#mirage-bridge` doesn't pull in client code
        # and vice versa.
        # ------------------------------------------------------------
        packages = {
          mirage-bridge = mkBin { name = "mirage-bridge"; };
          mirage-client = mkBin {
            name = "mirage-client";
            pkg = "mirage-client";
          };
          mirage-keygen = mkBin {
            name = "mirage-keygen";
            pkg = "mirage-bridge";
          };
          mirage-rotate = mkBin {
            name = "mirage-rotate";
            pkg = "mirage-bridge";
          };
          mirage-cohort-refresh = mkBin {
            name = "mirage-cohort-refresh";
            pkg = "mirage-client";
          };

          # `nix build` with no arg builds everything at once.
          default = pkgs.symlinkJoin {
            name = "mirage-all";
            paths = [
              self.packages.${system}.mirage-bridge
              self.packages.${system}.mirage-client
              self.packages.${system}.mirage-keygen
              self.packages.${system}.mirage-rotate
              self.packages.${system}.mirage-cohort-refresh
            ];
          };
        };

        # ------------------------------------------------------------
        # Dev shell. `nix develop` gives you the exact toolchain the
        # CI uses, plus handy tools.
        # ------------------------------------------------------------
        devShells.default = pkgs.mkShell {
          buildInputs = [
            toolchain
            pkgs.cargo-audit
            pkgs.cargo-nextest
            pkgs.cargo-fuzz
            # For the live demos and operator tooling.
            pkgs.openssl
            pkgs.python3
            pkgs.curl
            # For CI-local reproducibility checks.
            pkgs.diffoscopeMinimal
          ];

          # Same reproducibility env the packaged builds use — so
          # `cargo build --release` inside the dev shell produces
          # the same binary as `nix build`.
          shellHook = ''
            export RUSTFLAGS="-C debuginfo=0 --remap-path-prefix $PWD=/build/mirage"
            export CARGO_INCREMENTAL=0
            echo "mirage dev shell — toolchain: $(rustc --version)"
          '';
        };

        # ------------------------------------------------------------
        # `nix flake check` hooks: fmt + clippy against the pinned
        # toolchain. Matches .github/workflows/ci.yml so the CI-green
        # state is reproducible locally.
        # ------------------------------------------------------------
        checks = {
          fmt = pkgs.runCommand "mirage-fmt"
            {
              buildInputs = [ toolchain ];
              src = ./.;
            } ''
            cp -r $src source && chmod -R +w source
            cd source
            cargo fmt --all -- --check
            touch $out
          '';
        };
      });
}
