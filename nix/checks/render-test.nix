# 职责: checks.render-test — nix/tests/render.nix (render 纯函数契约测试) 的
# flake-fhs 接入薄包装 (callPackage 注入 lib/pkgs; 布局约束见根 AGENTS.md
# "nix flake 布局" 段).
{
  lib,
  pkgs,
}:
(import ../tests/render.nix { inherit lib pkgs; }).testRunner
