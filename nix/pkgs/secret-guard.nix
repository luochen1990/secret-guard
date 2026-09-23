# secret-guard package: 用 rustPlatform.buildRustPackage 构建.
#
# 选择 buildRustPackage 而非 crane, 是为了零额外 flake input (nixos-unstable 即可).
# 代价: 升级依赖后需手动 sync cargoHash (cargo vendor hash 变化), 但 secret-guard
# 依赖树稳定, 这个频率很低.
#
# 无需 openssl / pkg-config: reqwest 用 rustls-tls (Cargo.toml 显式 default-features=false),
# 整个依赖树没有 native TLS / 系统库需求.
{
  lib,
  rustPlatform,
  nix-gitignore,
}:
rustPlatform.buildRustPackage {
  pname = "secret-guard";
  # version SSOT = Cargo.toml [package].version (importTOML 单点读取, 保持发布
  # 归档名 secret-guard-<version>-<triple> 与 git tag 对齐, 杜绝双处手抄漂移)。
  version = (lib.importTOML ../../Cargo.toml).package.version;

  # src 过滤策略: nix-gitignore 的 .gitignore 基线 + 显式黑名单叠加.
  #   - .gitignore 基线: 自动排除 git-untracked 项 (敏感数据 / 构建产物等), 单一事实来源.
  #   - 显式黑名单: 排除 git-tracked 但不属于构建输入的顶层文件 (docs/ flake.nix 等).
  #   - 净效果: 默认放行 + 显式排除 (与 .gitignore 心智模型一致).
  #     新增顶层源码目录 (如未来 examples/) 自动进 src, 无需回头改本文件
  #     (PR #69 漏 benches/ 的同类回归正是此策略要根治的).
  #
  # ⚠️ 前导 `/` 必须保留: gitignore 语义里 `name` 匹配任意层级同名文件,
  # `/name` 才锚定到根目录. 已实测: 去 `/` 会误排 src/codec/AGENTS.md +
  # src/web/AGENTS.md, 破坏 buildRustPackage 的 manifest 解析.
  src = nix-gitignore.gitignoreSource [
    "/.cargo"
    "/.envrc"
    "/.forgejo"
    "/.github"
    "/.gitignore"
    "/AGENTS.md"
    "/docs"
    "/flake.lock"
    "/flake.nix"
    "/justfile"
    "/nix"
    "/proptest-regressions"
    "/rust-toolchain.toml"
  ] ../../.;

  cargoLock = {
    lockFile = ../../Cargo.lock;
    # 若未来引入 git dep, 在此处追加 outputHashes; 当前所有 crate 都来自 crates.io.
    outputHashes = { };
  };

  # secret-guard 是 binary-only, 不产出 .so / .a, 无需 configure/检查 stages.
  doCheck = false; # cargo-nextest 在 devShell 中跑 (just check), nix 构建跳过以提速.

  meta = with lib; {
    description = "A lightweight LLM gateway that prevents accidental secret leakage";
    homepage = "https://git.lambda.lc/lc-studio/secret-guard";
    license = licenses.mit;
    mainProgram = "secret-guard";
    platforms = platforms.linux;
  };
}
