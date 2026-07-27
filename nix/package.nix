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
}:
rustPlatform.buildRustPackage {
  pname = "secret-guard";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type: let
      baseName = baseNameOf path;
      relPath = lib.removePrefix (toString ../. + "/") path;
      # 只保留 Cargo + src + tests + benches + README, 排除 target/ .git/ nix/ 等无关目录.
      # tests/ 当前不在 nix build 范围内 (doCheck=false), 但保留以便未来开启 doCheck 时直接 work.
      # benches/ 必须保留: Cargo.toml 的 [[bench]] 声明要求 bench 文件在 src 中存在,
      # 否则 buildRustPackage 解析 manifest 时报 "can't find bench".
      isCargoFile = baseName == "Cargo.toml" || baseName == "Cargo.lock";
      isRustSrc = lib.hasPrefix "src/" relPath;
      isTestsSrc = lib.hasPrefix "tests/" relPath;
      isBenchesSrc = lib.hasPrefix "benches/" relPath;
      isAsset = baseName == "README.md";
      isAllowedDir = type == "directory" && (baseName == "src" || baseName == "tests" || baseName == "benches");
    in
      isCargoFile || isRustSrc || isTestsSrc || isBenchesSrc || isAsset || isAllowedDir;
  };

  cargoLock = {
    lockFile = ../Cargo.lock;
    # 若未来引入 git dep, 在此处追加 outputHashes; 当前所有 crate 都来自 crates.io.
    outputHashes = {};
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
