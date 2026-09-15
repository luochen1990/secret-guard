# 职责: secret-guard 的 nixpkgs overlay SSOT — 暴露 pkgs.secret-guard.
# 消费方: flake.nix 的 overlays.default 与 nixpkgs.overlays (flake-fhs evalContext),
# 以及 nix/modules/secret-guard.nix 的 module 内注入 (module 的 package option
# default = pkgs.secret-guard 依赖它).
_final: prev: {
  secret-guard = prev.callPackage ./pkgs/secret-guard.nix { };
}
