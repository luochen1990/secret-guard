{
  description = "secret-guard: a lightweight LLM gateway that prevents secret leakage";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      # 支持 x86_64-linux 与 aarch64-linux (本地 devShell 主要场景).
      # 需要扩展时显式添加 system, 避免 flake-utils 的 eachDefaultSystem 抽象.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rustc
              cargo
              rustfmt
              clippy
              just
              cargo-watch
              cargo-nextest
              cargo-machete
              cargo-audit
              rust-analyzer
              pkg-config
              openssl
            ];
            RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
          };
        });
    };
}
