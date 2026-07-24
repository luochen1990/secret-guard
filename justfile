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
# ${CARGO_TARGET_DIR}/llvm-cov-target/, 后续 just coverage-gate / coverage-html 直接消费, 无需重跑测试.
# 默认不带 (本地开发追求快速反馈, 无需插桩开销).
#
# CARGO_TARGET_DIR 若设置, 产物落其下 debug/ (clippy/nextest) 与 llvm-cov-target/ (coverage) 子目录.
# 清理策略: cargo llvm-cov clean --workspace 精准清 workspace member 的插桩 artifacts
# (含历史 build hash 的孤儿 binary), 保留依赖插桩缓存. 比 --profraw-only 更彻底 (后者只清 profraw,
# 留下孤儿 binary 会被 report 当成 0% 覆盖统计, 虚降总覆盖率); 比无 flag 的 clean 更精准 (后者
# 连依赖插桩缓存也删, 实测编译时间慢 ~2.4x). report.rs 的 pkg_hash_re 只收集 workspace member
# 的 object, 所以保留依赖插桩缓存不会污染报告 — 这是该方案能 "既保速度又准报告" 的根因.
#
# doctest 暂时禁用: 当前唯一的 doctest (auth::middleware) 被标为 ```ignore, 测试价值为零.
# 需要时取消下行注释即可恢复 (增量开销 <1s, 复用 clippy 的 debug/ 产物).
#
# consistency-check feature 守卫 (CI 用): 默认关闭的视图正确性断言. 非覆盖率分支末尾
# 调用 just check-features 增量编译该 feature 跑 clippy + nextest, 确保守卫断言持续可用
# 且不漂移. CI workflow 单独成步运行 check-features (在 coverage 的 cargo clean 前),
# 复用同一 target/debug, 不影响上面的磁盘峰值控制.
check *ARGS:
    cargo fmt -- --check
    cargo clippy --all-targets -- -D warnings
    cargo machete
    # cargo test --doc
    @if echo "{{ARGS}}" | grep -q -- "--coverage"; then \
        cargo llvm-cov clean --workspace; \
        cargo llvm-cov nextest --no-fail-fast --no-report; \
    else \
        cargo nextest run --no-fail-fast; \
        just check-features; \
    fi

# consistency-check feature 守卫 (CI 用): clippy + nextest 带 feature flag.
# 该 feature 默认关闭, 包含视图正确性断言 (proxy.rs::assert_redactions_match_map).
# 详见 AGENTS.md "视图正确性确保机制". CI workflow 单独成步运行本目标.
check-features:
    cargo clippy --all-targets --features consistency-check -- -D warnings
    cargo nextest run --no-fail-fast --features consistency-check

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
# 当前实测约 ~86% / ~1350 uncovered (auth 模块的 OIDC/handler/middleware 路径
# 需 mock IdP 集成测试, 留作后续). 阈值留缓冲.
COVERAGE_MIN_LINES := "84"
COVERAGE_MAX_UNCOVERED := "1500"

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
