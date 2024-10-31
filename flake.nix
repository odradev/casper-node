{
  description = "Rust development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    utils,
    ...
  }:
    utils.lib.eachDefaultSystem
    (
      system: let
        pkgs = import nixpkgs {inherit system;};
        toolchain = pkgs.rustPlatform;
      in rec
      {
        # Used by `nix develop`
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            pkg-config
            (with toolchain; [
              rustup
              rustLibSrc
              rust-analyzer
            ])
          ];

          buildInputs = with pkgs; [
            # (with toolchain; [
            #   rustup
            #   rustLibSrc
            #   rust-analyzer
            # ])
            # clippy
            # rustfmt
            # rustup
            # rust-analyzer
            # pkg-config
            python3
            gnumake
            wasm-strip
            openssl
            gcc
          ];

          # Specify the rust-src path (many editors rely on this)
          RUST_SRC_PATH = "${toolchain.rustLibSrc}";
        };
      }
    );
}
