{
  description = "cc.me trampoline and encrypted webhook queue";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "clippy"
            "rustfmt"
          ];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        commonArgs = {
          pname = "cc-me";
          version = "0.1.0";
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        cc-me = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });
        # OpenCL proof-of-work solver (NVIDIA/AMD); Linux-only — macOS builds
        # pow/ with the system toolchain instead (see pow/README.md).
        pow-cl = pkgs.stdenv.mkDerivation {
          pname = "pow-cl";
          version = "0.1.0";
          src = ./pow;
          nativeBuildInputs = [ pkgs.ninja ];
          buildInputs = [ pkgs.opencl-headers pkgs.ocl-icd ];
          postPatch = "patchShebangs configure";
          configurePhase = "./configure";
          installPhase = "install -Dm755 pow-cl $out/bin/pow-cl";
        };
      in
      {
        packages = {
          default = cc-me;
          cc-me = cc-me;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          pow-cl = pow-cl;
        };

        apps = {
          default = flake-utils.lib.mkApp { drv = cc-me; };
          cc-me = flake-utils.lib.mkApp { drv = cc-me; };
        };

        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.cargo-llvm-cov
            pkgs.cargo-watch
            pkgs.postgresql
            pkgs.process-compose
            pkgs.nodejs
            pkgs.bun
            pkgs.deno
            pkgs.go
            pkgs.uv
            (pkgs.python3.withPackages (ps: [ ps.pynacl ]))
            pkgs.ruby
            pkgs.libsodium
            pkgs.ninja
          ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            # For pow/pow.c, the OpenCL GPU solver (NVIDIA/AMD; macOS uses the
            # system OpenCL framework instead).
            pkgs.opencl-headers
            pkgs.ocl-icd
          ];
        };
      });
}
