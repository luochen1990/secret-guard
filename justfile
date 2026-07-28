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
#
# doc 检查: cargo doc --no-deps -D warnings 验证 rustdoc 能编译 (含跨文件 doc 链接).
# 项目大量使用 //! 头部文档 + contracts.md 链接, doc 链接写错 (路径错/跨 crate 错) 在 CI 不会
# 被 clippy 发现, 只有手跑 cargo doc 才暴露.
# 不带 --document-private-items: 项目内部 doc 链接指向 private item 是合理的 (维护者文档),
# --document-private-items 会把这些当警告. 只查 public doc 的链接完整性即可守住门禁初衷.
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
        RUSTDOCFLAGS="-D warnings" cargo doc --no-deps; \
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

# redact 性能基线 (criterion bench).
# 详尽设计 (3 场景 + 2 目标 + 为什么手动构造 map) 见 benches/redact.rs 头部.
# 默认 100 samples 较慢, 调试可用 `cargo bench --bench redact -- --quick`.
bench:
    cargo bench --bench redact

# bench 编译验证 (--no-run 零样本): 防止 bench 代码逻辑错误 / runtime panic
# 长期不被发现 (criterion 从不运行时这类 bug 无声潜伏).
# 用 dev profile (而非 bench 默认的 release): release profile 的 lto=thin + codegen-units=1
# 会导致全量编译 5-8min; dev profile 复用 debug/ 缓存只需 ~30s, 且 --no-run 只验证可编译性,
# 不跑 criterion 统计, 无需 release 优化. CI 暂不跑此命令 (见 ci.yml 末尾注释), 供本地手动验证.
# 未来若引入 baseline 保存/比较, 可在此扩展跑采样.
check-benches:
    cargo bench --no-run --profile dev

# ─── 文件长度门禁 (按 prod 行数) ───────────────────────────────────────────
# 防止单文件 prod 代码失控膨胀. 用 rust-diff-analyzer 对每个 .rs 做完整 AST 分类
# (把整个文件当"全新增" diff 喂给工具), 只统计 prod_lines, 排除 #[cfg(test)] 块.
# 这样 test 代码增长不触发门禁 — 测试膨胀本就不该用文件大小卡, 而该用 PR diff
# 拆解 (just diff-loc) 在 review 时判断.
#
# 为什么不复用 awk 行号猜 #[cfg(test)] 起始位置: 不是 AST 语义分类, 识别不了
# inline #[test] 函数; 且维护第二份分类规则违反 SSOT (与 diff-loc 共用同一工具).
#
# 双阈值 (对齐 coverage-gate 风格):
#   FILE_WARN_PROD_LINES: 软提醒阈值. 超过则 echo warning, 不阻断 (开发时感知).
#   FILE_MAX_PROD_LINES:  硬门禁阈值. 超过则 exit 1 (CI 阻断).
# 当前 prod 最大是 proxy.rs=1584, MAX 1600 留极小余量强制警觉; WARN 500 让任何
# 模块膨胀到该规模时尽早引起注意 (拆分 ROI 评估的早期信号).
FILE_WARN_PROD_LINES := "500"
FILE_MAX_PROD_LINES := "1600"

check-file-size:
    #!/usr/bin/env bash
    set -euo pipefail
    # git diff --no-index /dev/null <file>: 生成"全新增" diff 让 rust-diff-analyzer
    #   对单文件做完整 AST 分类.
    # rust-diff-analyzer: 同步按 syn AST 区分 prod/test 单元 (复用 diff-loc 的工具).
    #   --format json + jq 取 .summary.prod_lines_added; --no-fail 让工具不因自身阈值
    #   退出非零 (本 recipe 用自己的 FILE_*_PROD_LINES 阈值).
    # 性能: 全仓 ~28 个 .rs, 总耗时 ~0.4s.
    warnings=""
    errors=""
    while IFS= read -r -d '' f; do
      # || true 在管道末尾, 作用于整条管道的最终退出码 (|| 优先级低于 |).
      # git diff --no-index 有差异时 exit 1, 必须吸收否则 set -e + pipefail 会终止脚本.
      # 3 个 2>/dev/null: 分别吞 git diff (二进制文件告警) / rda (parse 噪音) / jq
      #   (parse error); 失败已由下方 =~ ^[0-9]+$ 兜底捕获并 fail-closed, stderr 噪音无用.
      prod=$(git diff --no-index /dev/null "$f" 2>/dev/null \
        | rust-diff-analyzer --format json --no-fail 2>/dev/null \
        | jq -r '.summary.prod_lines_added // 0' 2>/dev/null || true)
      # fail-closed: 工具失败 (输出空或非数字) 时必须报错, 不能静默放行.
      # 否则门禁形同虚设 — [ "" -gt N ] 退出码 2 被 if 视为 false, 文件被误判合规.
      if ! [[ "$prod" =~ ^[0-9]+$ ]]; then
        echo "::error file=$f::rust-diff-analyzer failed (output not a number: '$prod')"
        errors="${errors}TOOL-FAIL $f"$'\n'
        continue
      fi
      if [ "$prod" -gt {{FILE_MAX_PROD_LINES}} ]; then
        errors="$errors$prod $f"$'\n'
      elif [ "$prod" -gt {{FILE_WARN_PROD_LINES}} ]; then
        warnings="$warnings$prod $f"$'\n'
      fi
    done < <(find src -name '*.rs' -print0)
    # 按行数降序输出 (最该拆的排第一). sort -rn: 数字逆序.
    # grep -v '^$': 过滤 printf 末尾换行产生的空行, 避免 sed 缩进成纯空格行.
    if [ -n "$warnings" ]; then
      echo "::warning::Files exceeding {{FILE_WARN_PROD_LINES}} prod lines (consider splitting; test code excluded):"
      printf '%s\n' "$warnings" | grep -v '^$' | sort -rn | sed 's|^|  |'
    fi
    if [ -n "$errors" ]; then
      echo "::error::Files blocked by gate (exceeding {{FILE_MAX_PROD_LINES}} prod lines or tool failure; test code excluded):"
      printf '%s\n' "$errors" | grep -v '^$' | sort -rn | sed 's|^|  |'
      exit 1
    fi
    echo "All source files within {{FILE_MAX_PROD_LINES}} prod-line limit (test code excluded)."

# ─── PR diff 拆解 ──────────────────────────────────────────────────────────
# 区分 diff 中的 prod 代码 vs test 代码, 用于 review 时判断真实膨胀.
# 场景: 测试代码增加不是真膨胀, prod 代码大量增加才需警惕.
# 工具: rust-diff-analyzer (syn AST 解析, 自动识别 #[cfg(test)] / #[test] / tests/ 目录).
# 默认对比当前分支与 master (origin/master 优先, 回退本地 master).
# 默认 --format human + --no-fail (报告完就退); 透传额外 ARGS, 例:
#   just diff-loc                    # human 报告
#   just diff-loc --format json      # JSON (脚本消费)
#   just diff-loc --format=json      # 等价 (等号形式也识别)
#   just diff-loc --max-units 50     # 加阈值 (但 --no-fail 不阻塞)
#
# 注意: rust-diff-analyzer 的 --format 不允许重复传 (clap 拒绝), 故下方用
# 字符串匹配检测 ARGS 是否已含 --format, 没有才补默认值.
#
# 需要 devShell (nix develop) 提供 rust-diff-analyzer.
diff-loc *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if git rev-parse --verify --quiet origin/master >/dev/null; then
        BASE="origin/master"
    else
        BASE="master"
    fi
    echo "# diff: $BASE...HEAD"
    # --no-fail 始终补; --format 仅在用户未传时补默认 human.
    # 同时识别 --format X 和 --format=X (clap 拒绝 --format 重复出现).
    FORMAT=()
    if [[ " {{ARGS}} " != *" --format "* && " {{ARGS}} " != *" --format="* ]]; then
        FORMAT=(--format human)
    fi
    git diff "$BASE...HEAD" | rust-diff-analyzer "${FORMAT[@]}" --no-fail {{ARGS}}
