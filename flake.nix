{
  description = "secret-guard: a lightweight LLM gateway that prevents secret leakage";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-fhs.url = "github:luochen1990/flake-fhs";
    flake-fhs.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-fhs, ... }:
    let
      # overlay SSOT 在 nix/overlay.nix (module 内注入与 packages 共用同一份).
      overlay = import ./nix/overlay.nix;

      fhs = flake-fhs.lib.mkFlake { inherit inputs; } {
        # embed 布局: nix 文件全部收在 nix/ 下, 与项目根的 Rust 源码隔离.
        # 目录树即 flake: nix/pkgs -> packages, nix/modules -> nixosModules,
        # nix/shells -> devShells, nix/checks -> checks (辅助库 nix/module.nix,
        # nix/render.nix, nix/tests/ 在扫描名单目录之外, 不被收集).
        layout.roots = [ "/nix" ];
        # 支持 x86_64-linux 与 aarch64-linux (本地 devShell 主要场景).
        # 需要扩展时显式添加 system, 避免隐式全平台抽象.
        systems = [
          "x86_64-linux"
          "aarch64-linux"
        ];
        # 显式覆盖框架默认 ({ allowUnfree = true; }): unfree 应被拒绝 —
        # 与本仓 cargo-deny 的 Rust license 门禁同一姿态.
        nixpkgs.config = { };
        # evalContext 的 pkgs 注入 overlay (packages.<sys>.secret-guard 由此暴露).
        nixpkgs.overlays = [ overlay ];
      };
    in
    fhs
    // {
      # flake-fhs 不生成 overlays output, 手动补 (消费方: 手动加 overlay 的部署).
      overlays.default = overlay;

      # packages.default 别名: flake-fhs 不生成, 消费方 (secret-guard-flake
      # 发布归档等) 习惯 nix build .#default.
      packages = builtins.mapAttrs (_: ps: ps // { default = ps.secret-guard; }) fhs.packages;
      # nixosModules 由框架生成 (含 default, = imports 所有 modules), 无需手动补;
      # 组装层语义见 nix/modules/secret-guard.nix 头注.
    };
}
