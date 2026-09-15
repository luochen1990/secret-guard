# 职责: 默认 devShell (flake-fhs 经 nix/shells/ 目录发现, evalContext 注入 pkgs).
# 工具链清单的取舍理由见根 AGENTS.md "覆盖率工具" 与 "rust-diff-analyzer" 段.
{
  pkgs,
  ...
}:
let
  # cargo-llvm-cov 需要 llvm-cov / llvm-profdata, nix rust toolchain 不含 llvm-tools-preview.
  # 用 llvmPackages 提供: profraw 格式跨 LLVM 主版本兼容, 不要求与 rustc 内嵌 LLVM 精确对齐.
  llvmBins = "${pkgs.llvmPackages.llvm}/bin";

  # rust-diff-analyzer (PR diff 区分 prod/test 代码, 用于 review 时判断真实膨胀).
  # 未进 nixpkgs, 用 lazy cargo install wrapper 包一层: 首次调用编译到 ~/.cache, 后续命中.
  # 用 pin 版本避免上游新版本引入未预期行为.
  # 注意: 不用 --locked — 该 crate 是低 star 个人项目, lockfile 维护未必及时,
  # 上游某个依赖被 yank 时 --locked 会硬失败. --version pin 工具版本已足够.
  rust-diff-analyzer = pkgs.writeShellScriptBin "rust-diff-analyzer" ''
    set -eu
    VERSION="2.0.1"
    CACHE_DIR="''${XDG_CACHE_HOME:-$HOME/.cache}/secret-guard-tools"
    BIN="$CACHE_DIR/rust-diff-analyzer-$VERSION"
    if [ ! -x "$BIN" ]; then
      mkdir -p "$CACHE_DIR"
      # cargo install 中间产物 ~50MB, 用临时目录隔离避免污染 cache 命名空间.
      tmp=$(mktemp -d)
      cargo install rust-diff-analyzer --version "$VERSION" --root "$tmp"
      install -m 755 "$tmp/bin/rust-diff-analyzer" "$BIN"
      rm -rf "$tmp"
    fi
    exec "$BIN" "$@"
  '';
in
pkgs.mkShell {
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
    cargo-deny
    cargo-llvm-cov
    typos
    rust-analyzer
    pkg-config
    openssl
    # WebUI 回归测试 (tests/webui/): playwright-test 自带 @playwright/test + 浏览器.
    # shellHook 把它的 node_modules symlink 到 tests/webui/node_modules,
    # 让 TS 源码的 `import "@playwright/test"` 能解析 (ESM resolver 不读 NODE_PATH).
    nodejs
    playwright-test
    # WebUI 孤儿进程清理 (just check-webui 的 lsof+kill 依赖).
    # CI runner VM 也通过 host-sw-bin fallback 提供 lsof (见 forgejo-runner-vm.mod.nix),
    # 本地 devShell 显式声明避免对宿主 fallback 的隐式依赖.
    lsof
    # PR diff 拆解: review 时区分 prod 代码 vs test 代码膨胀 (just diff-loc).
    rust-diff-analyzer
  ];
  # shellHook: 进入 devShell 时自动 symlink playwright-test 的 node_modules 到 tests/webui.
  # 用相对路径 (shellHook 在用户 shell 中执行, cwd 通常 = 项目根), 不用绝对 store 路径
  # 引用 self (git+file 工作树模式下指向只读 nix store 副本, mkdir 会失败).
  shellHook = ''
    mkdir -p tests/webui/node_modules/@playwright
    ln -sfn ${pkgs.playwright-test}/lib/node_modules/@playwright/test tests/webui/node_modules/@playwright/test
    ln -sfn ${pkgs.playwright-test}/lib/node_modules/playwright tests/webui/node_modules/playwright
    ln -sfn ${pkgs.playwright-test}/lib/node_modules/playwright-core tests/webui/node_modules/playwright-core
  '';
  # cargo-llvm-cov 需要的 LLVM 工具路径 (经 env 注入, 交互式与非交互式 nix develop 都生效).
  LLVM_COV = "${llvmBins}/llvm-cov";
  LLVM_PROFDATA = "${llvmBins}/llvm-profdata";
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
