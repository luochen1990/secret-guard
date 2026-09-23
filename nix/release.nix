# secret-guard 发布归档打包: 从本仓源码产出**最终用户可下载**的 release 聚合
# (linux×2 musl 全静态 tar.gz + SHA256SUMS linkFarm), 供 flake.nix 在
# packages."x86_64-linux".release 槽位挂载; 触达面: 本地 `nix build .#release` +
# GitHub Actions release workflow (`.github/workflows/release.yml`, tag push)。
#
# 职责边界: 只管"归档怎么打" (交叉编译包装 / 静态断言 / 命名契约 / 校验和聚合),
# 不管"何时发布" (tag 流程见根 AGENTS.md "发布流程" 段) 与"包怎么构建"
# (构建逻辑 SSOT = nix/pkgs/secret-guard.nix, 经 nix/overlay.nix 注入后消费)。
# 历史来源: 自独立仓库 secret-guard-flake 简化搬入 (丢弃 windows/darwin 归档),
# 语义保持等价 (sgPackage / mkTarball / mkRelease 三段式)。
#
# 构建主机钉 x86_64-linux (单 producer): aarch64 归档在本机交叉编译产出,
# 纯 aarch64 主机直接 `nix build .#release` 需 binfmt/远程 builder。
# 归档命名契约: secret-guard-<version>-<triple>.tar.gz, 内含同名顶层目录
# (可执行 + README.md + LICENSE), version SSOT = Cargo.toml (package 经
# importTOML 读取, 与 tag 对齐的保证在此链路上)。
{
  self,
  nixpkgs,
  overlay,
}:
let
  lib = nixpkgs.lib;

  producer = "x86_64-linux";
  # 直接 import (不经 flake-fhs evalContext): config 走 nixpkgs 默认
  # (allowUnfree = false), 与本仓 cargo-deny 的 license 门禁同一姿态。
  hostPkgs = import nixpkgs { localSystem = producer; };
  crossPkgsFor =
    crossSystem:
    import nixpkgs {
      localSystem = producer;
      inherit crossSystem;
    };

  # 项目包的打包侧重写 (overrideAttrs, 不触碰构建逻辑), 仅两处:
  #   1. meta.platforms 放宽 (上游 = linux only), 让 musl cross target 通过
  #      `nix flake check` 的 meta 校验。
  #   2. musl target 注入 +crt-static: nixpkgs musl cc wrapper 默认产出动态链接
  #      musl ELF (interpreter 指向 /nix/store 内 loader, 离开 nix 不可用),
  #      必须显式要求 rustc 静态链接 crt — 与下方 fail-closed 断言配套。
  sgPackage =
    pkgs:
    (pkgs.extend overlay).secret-guard.overrideAttrs (
      old:
      {
        meta = (old.meta or { }) // {
          platforms = lib.platforms.all;
        };
      }
      //
        lib.optionalAttrs
          (pkgs.stdenv.hostPlatform.isLinux or false && pkgs.stdenv.hostPlatform.isMusl or false)
          {
            RUSTFLAGS = "-C target-feature=+crt-static";
          }
    );

  # 本仓 Cargo.toml `[[bin]]` name (pkgs.secret-guard 的 meta.mainProgram 同源,
  # 不重复定义策略)
  binName = "secret-guard";

  # tar.gz 归档: $out = 归档文件本身, 内含顶层目录 secret-guard-<version>-<triple>/。
  # 构建时 fail-closed 断言 ELF 静态链接 (musl 产物的分发前提):
  # static-pie / statically linked 都是自包含静态 ELF; 其余形态 (含带 interpreter
  # 的动态链接) 一律拒绝。README/LICENSE 取自 flake 源 (self = tag 检出)。
  mkTarball =
    {
      targetPkgs,
      triple,
    }:
    let
      exe = sgPackage targetPkgs;
      version = exe.version;
      top = "secret-guard-${version}-${triple}";
    in
    hostPkgs.runCommand "secret-guard-${version}-${triple}.tar.gz"
      {
        nativeBuildInputs = with hostPkgs; [
          gnutar
          gzip
          file
        ];
      }
      ''
        set -eu
        exe_bin="${exe}/bin/${binName}"
        mkdir -p "${top}"
        install -m755 "$exe_bin" "${top}/${binName}"
        cp "${self}/README.md" "${top}/"
        [ -f "${self}/LICENSE" ] && cp "${self}/LICENSE" "${top}/" || true

        kind=$(file -b "$exe_bin")
        echo "artifact: $kind" >&2
        case "$kind" in
          *"static-pie linked"*|*"statically linked"*) ;;
          *interpreter*|*"dynamically linked"*)
            echo "ERROR: ${triple} 产物不是静态链接: $kind" >&2; exit 1 ;;
          *)
            echo "ERROR: ${triple} 产物形态未识别, 拒绝放行: $kind" >&2; exit 1 ;;
        esac

        tar --sort=name --owner=0 --group=0 --numeric-owner \
            --mtime=@0 -czf "$out" "${top}"

        # 布局自证 (构建即验证, 免独立 check 接线): 顶层目录 + 可执行 + README 就位
        tar -tzf "$out" | grep -q "^${top}/${binName}$" \
          || { echo "ERROR: ${triple} 归档缺可执行" >&2; exit 1; }
        tar -tzf "$out" | grep -q "^${top}/README.md$" \
          || { echo "ERROR: ${triple} 归档缺 README" >&2; exit 1; }
      '';

  # release 聚合: linkFarm 目录 = 各归档 + SHA256SUMS (归档名 → sha256, 供下载方
  # 校验; `cd result && sha256sum -c SHA256SUMS`)。
  # archives :: [ { name :: String (归档文件名, 结构性声明, 不从 store path 推导 —
  #                              baseNameOf 带 store hash 前缀且携带 derivation
  #                              context, linkFarm 不接受)
  #               , pkg  :: Derivation (归档文件) } ]
  mkRelease =
    archives:
    let
      sums = hostPkgs.runCommand "SHA256SUMS" { } (
        "set -eu\n: > $out\n"
        + lib.concatMapStringsSep "\n" (a: ''
          printf '%s  %s\n' "$(sha256sum '${a.pkg}' | cut -d' ' -f1)" '${a.name}' >> $out
        '') archives
      );
    in
    hostPkgs.linkFarm "secret-guard-release-${version}" (
      (map (a: {
        name = a.name;
        path = a.pkg;
      }) archives)
      ++ [
        {
          name = "SHA256SUMS";
          path = sums;
        }
      ]
    );

  musl-x86_64 = mkTarball {
    triple = "x86_64-linux-musl";
    targetPkgs = crossPkgsFor lib.systems.examples.musl64;
  };
  musl-aarch64 = mkTarball {
    triple = "aarch64-linux-musl";
    targetPkgs = crossPkgsFor lib.systems.examples.aarch64-multiplatform-musl;
  };
  version = (sgPackage hostPkgs).version;
in
mkRelease [
  {
    name = "secret-guard-${version}-x86_64-linux-musl.tar.gz";
    pkg = musl-x86_64;
  }
  {
    name = "secret-guard-${version}-aarch64-linux-musl.tar.gz";
    pkg = musl-aarch64;
  }
]
