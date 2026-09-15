# 职责: nixosModules.secret-guard — 结构化选项 module (nix/module.nix) 的 flake-fhs
# 单文件组装层: imports 实现本体 + 注入 overlay (package option default =
# pkgs.secret-guard 的供给方). 单文件 module 无 enable 注入.
{
  ...
}:
{
  imports = [ ../module.nix ];
  # 括号必须: 列表字面量里 `import x` 会被解析为两个元素 (builtin + path).
  nixpkgs.overlays = [ (import ../overlay.nix) ];
}
