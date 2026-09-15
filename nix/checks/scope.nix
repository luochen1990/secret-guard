# 职责: checks 的 callPackage 参数补注 — lib 显式注入 evalContext 的 mergedLib
# (flake-fhs 工具 // nixpkgs flake lib). 必要性: scope 默认解析 lib = pkgs.lib
# (import nixpkgs 产物的 lib, 不含 nixosSystem), 而 module-eval 需要
# lib.nixosSystem — flake output 的 lib 才有. nixpkgs.lib 位于 mergedLib 合并
# 链最右, 不被 flake-fhs 函数遮蔽.
{
  lib,
  ...
}:
{
  args = { inherit lib; };
}
