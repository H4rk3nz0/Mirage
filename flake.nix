{
  # Rust 1.87 build targets for Mirage.
  #
  # The repository does not currently include flake.lock. Nix therefore
  # resolves moving input revisions when this flake is first built. These
  # outputs are useful for isolated builds, but byte-for-byte reproducibility
  # across machines is not yet an established property. To establish it,
  # commit flake.lock and compare independent builds of the same source.
  # This flake currently:
  #
  # - Selects the Rust 1.87 channel named in rust-toolchain.toml.
  # - Uses the committed Cargo.lock for dependency resolution.
  # - Builds each bin in a Nix derivation.
  #
  # Typical use:
  #   nix develop            # enter dev shell with the Rust 1.87 channel
  #   nix build .#mirage-bridge
  #   nix build .#mirage-client
  #   nix build .#mirage-keygen
  #   nix build .#mirage-rotate
  #
  # Build comparison (not a reproducibility guarantee without a flake lock):
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

        # Toolchain channel from rust-toolchain.toml. Keeping this
        # file as the single source of truth means Nix consumers
        # and rustup consumers stay aligned.
        toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # Use the selected toolchain for Cargo and rustc.
        rustPlatform = pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };

        # Shared attributes for each binary package.
        commonAttrs = {
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          CARGO_TERM_COLOR = "never";
          # Drop debug info, which can embed build paths. This alone does not
          # make the output byte-for-byte reproducible.
          RUSTFLAGS = "-C debuginfo=0";
          CARGO_INCREMENTAL = "0";
          cargoBuildFlags = [ "--locked" "--release" ];
          doCheck = false;  # Tests run in CI.
          meta = with pkgs.lib; {
            description = "Mirage protocol";
            license = licenses.agpl3Plus;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        mkBin = { name, bin ? name, pkg ? "mirage-bridge" }: rustPlatform.buildRustPackage (commonAttrs // {
          pname = name;
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
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
        # Development shell with the Rust 1.87 channel and build tools.
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
            # For comparing independent build outputs.
            pkgs.diffoscopeMinimal
          ];

          # Match the package's basic compiler flags in the dev shell.
          shellHook = ''
            export RUSTFLAGS="-C debuginfo=0"
            export CARGO_INCREMENTAL=0
            echo "mirage dev shell — toolchain: $(rustc --version)"
          '';
        };

        # ------------------------------------------------------------
        # `nix flake check` currently runs rustfmt only. CI also runs clippy
        # and the full test suite.
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
