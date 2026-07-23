# secret-guard — justfile
# 一键命令集合, 覆盖开发 / 检查 / 测试 / 运行.

default:
    @just --list

# 进入 nix devShell (交互式).
shell:
    nix develop --impure

# 编译.
build:
    cargo build

# 编译并运行.
run *ARGS:
    cargo run -- {{ARGS}}

# 开发模式: 自动重编译 (cargo-watch).
dev:
    cargo watch -x 'run -- run'

# 一次跑完: fmt + clippy + machete + test.
# --coverage: 测试阶段改用插桩编译 (cargo llvm-cov nextest), 产出覆盖率数据到
# target/llvm-cov-target/, 后续 just coverage-gate / coverage-html 直接消费, 无需重跑测试.
# 默认不带 (本地开发追求快速反馈, 无需插桩开销).
#
# 磁盘峰值控制 (CI): clippy/doctest/nextest 共用 target/debug (~3GB), 与 coverage 插桩产物
# target/llvm-cov-target (~1.6GB) 是两份独立编译, 互不复用. CI runner (forgejo-runner-vm)
# 根文件系统是 tmpfs (实测 ~3.9GB, 即 VM mem 的一半), 两份并存会触发 "No space left on device".
# 故: (1) doctest 提前到分支前, 复用 clippy 的 target/debug; (2) coverage 分支 clean 释放
# target/debug 后再跑 llvm-cov, 实测峰值降到 ~1.4GB, 零时间损失 (coverage 本就要全量重编译).
# 本地要 coverage 产物但不想 clean 可用 just coverage / just coverage-html (不走 check 流程).
check *ARGS:
    cargo fmt -- --check
    cargo clippy --all-targets -- -D warnings
    cargo machete
    cargo test --doc
    @if echo "{{ARGS}}" | grep -q -- "--coverage"; then \
        cargo clean; \
        cargo llvm-cov nextest --no-fail-fast --no-report; \
    else \
        cargo nextest run --no-fail-fast; \
    fi

# WebUI 回归测试 (Playwright 端到端).
# 需要 devShell (nix develop) 提供 playwright-test 包; shellHook 自动 symlink node_modules.
check-webui:
    cd tests/webui && playwright test

# check + check-webui (完整验证, devShell 内).
check-all: check
    cd tests/webui && playwright test

# 仅 fmt.
fmt:
    cargo fmt

# 仅 clippy.
clippy:
    cargo clippy --all-targets -- -D warnings

# 仅 test.
test:
    cargo nextest run --no-fail-fast

# ─── coverage ─────────────────────────────────────────────────────────────
# 基于 LLVM source-based coverage (cargo-llvm-cov). 工具链与 LLVM_COV/LLVM_PROFDATA
# 环境变量由 nix devShell 注入 (见 flake.nix), 因此以下命令需在 `nix develop` 内执行.
# CI 里 ci.yml 用 job 级 env 写死绝对路径注入 (runner VM 不进 devShell).
# 产物默认写到 target/llvm-cov-target/ + coverage/ (已 .gitignore).
#
# 门禁基线 (SSOT): 覆盖率百分比下限 + 未覆盖行数上限. 提升 coverage 后手动 bump.
# 当前实测约 ~89% / ~850 uncovered, 阈值留缓冲.
COVERAGE_MIN_LINES := "85"
COVERAGE_MAX_UNCOVERED := "1000"

# 覆盖率摘要 (终端表格).
coverage:
    cargo llvm-cov nextest --no-fail-fast --no-report
    cargo llvm-cov report --summary-only

# 覆盖率门禁 (CI 用): 双阈值, 任一不满足则非零退出.
# 前置: check --coverage 已产出 profdata 到 target/llvm-cov-target/. 本 recipe 只做 report.
#   --fail-under-lines:     总行覆盖率下限 (防整体下降)
#   --fail-uncovered-lines: 未覆盖行数上限 (防未覆盖绝对值增长)
coverage-gate:
    cargo llvm-cov report --summary-only \
      --fail-under-lines {{COVERAGE_MIN_LINES}} \
      --fail-uncovered-lines {{COVERAGE_MAX_UNCOVERED}}

# HTML 报告 (浏览器打开 coverage/html/index.html).
coverage-html:
    cargo llvm-cov nextest --no-fail-fast --no-report
    cargo llvm-cov report --output-dir coverage --html
    @echo "HTML report: coverage/html/index.html"

# LCOV 报告 (CI / IDE 集成).
coverage-lcov:
    mkdir -p coverage
    cargo llvm-cov nextest --no-fail-fast --lcov --output-path coverage/lcov.info
    @echo "LCOV report: coverage/lcov.info"

# 启动 mock 上游 (用于本地集成测试; 占位).
mock-upstream:
    @echo "TODO: 第二步会引入 mockito-based 上游"

# 检查依赖漏洞.
audit:
    cargo audit
