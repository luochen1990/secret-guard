{
  description = "secret-guard: a lightweight LLM gateway that prevents secret leakage";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    # 支持 x86_64-linux 与 aarch64-linux (本地 devShell 主要场景).
    # 需要扩展时显式添加 system, 避免 flake-utils 的 eachDefaultSystem 抽象.
    systems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

    nixpkgsFor = system:
      import nixpkgs {
        inherit system;
        overlays = [self.overlays.default];
      };
  in {
    # ─── overlays ────────────────────────────────────────────────────────────
    #
    # 让其他 flake (例如 ~/ws/nixos) 通过 `inputs.secret-guard.overlays.default`
    # 注入 pkgs.secret-guard, 也可以通过 nixosModules 自动注入.
    overlays.default = _final: prev: {
      secret-guard = prev.callPackage ./nix/package.nix { };
    };

    # ─── packages ────────────────────────────────────────────────────────────
    packages = forAllSystems (system: let
      pkgs = nixpkgsFor system;
    in {
      default = pkgs.secret-guard;
      secret-guard = pkgs.secret-guard;
    });

    # ─── devShells ───────────────────────────────────────────────────────────
    devShells = forAllSystems (system: let
      pkgs = nixpkgsFor system;
    in {
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

    # ─── nixosModules ────────────────────────────────────────────────────────
    #
    # 默认 module 自带 overlay (让 `pkgs.secret-guard` 可用), 用户无需手动加 overlay.
    # 若不想要 overlay 副作用, 可直接 import ./nix/module.nix.
    nixosModules.default = {
      imports = [self.nixosModules.secret-guard];
    };

    nixosModules.secret-guard = {...}: {
      imports = [./nix/module.nix];
      nixpkgs.overlays = [self.overlays.default];
    };

    # ─── checks (optional, 未来扩展) ────────────────────────────────────────
    #
    # 跑 `nix flake check` 时, 用 module 的测试 runner 验证服务能启动.
    # 当前 MVP 先不写, 等服务跑通后再补.
  };
}
