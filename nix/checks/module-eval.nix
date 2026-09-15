# 职责: checks.module-eval — nix/tests/module-eval.nix (NixOS module 接线冒烟)
# 的 flake-fhs 接入薄包装 (callPackage 注入 lib/pkgs).
# system 取自 pkgs 实例而非声明参数: flake-fhs 的 callPackage 对声明 system
# 参数的文件发 warning (建议 stdenv.hostPlatform.system), 从源头规避.
# secretGuardModule 直接 import 组装层 (module 本体 + overlay 注入); 框架对
# nixosModules.secret-guard 的包装是透明变换 (options/config 原样保留), 裸
# import 与 output 行为等价.
{
  lib,
  pkgs,
}:
let
  system = pkgs.stdenv.hostPlatform.system;
in
(import ../tests/module-eval.nix {
  inherit lib pkgs system;
  secretGuardModule = import ../modules/secret-guard.nix;
}).testRunner
