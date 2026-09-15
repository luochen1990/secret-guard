# secret-guard — justfile
# 一键命令集合, 覆盖开发 / 检查 / 测试 / 运行.
#
# 约定: 验证类 cargo 命令 (check/clippy/test/check-features/coverage*/bench/bench-ci)
# 统一带 --locked — Cargo.toml 改动而 Cargo.lock 未提交时直接失败, 防 CI 静默重
# resolve 导致 "CI 测试的依赖集 ≠ 提交的 lockfile ≠ nix 发布产物" 三元漂移 (issue #142).
# 本地手改 Cargo.toml 后碰到一次 "lock file needs to be updated" 报错属预期提醒,
# 跑一次 `cargo build` 更新 lockfile 后提交即可; 开发内环 recipe (build/run/dev*) 不带.

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
    cargo run -- {{ ARGS }}

# 开发模式: 自动重编译 (cargo-watch).
dev:
    cargo watch -x 'run -- run'

# 开发模式 (仅重启进程, 现有 dev 行为的显式别名): 改代码后自动重新运行 secret-guard.
# 与 dev 等价; 单独命名是为了与 dev-test 形成对称的 "run / test" 开发命令对.
dev-run:
    cargo watch -x 'run -- run'

# 开发模式 test watcher (TDD 红绿循环): 改代码后自动跑 nextest.
# 不用 `cargo watch -x 'run' -x 'nextest run'` 组合 (watch 支持多 -x 串行), 因为 run
# 会阻塞 (server 常驻), 后续 nextest 永远轮不到; 拆成独立 recipe 让用户按需选其一.
dev-test:
    cargo watch -x 'nextest run'

# 一次跑完: fmt + clippy + machete + doc + test + typos + deny.
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
# 放在 fmt/clippy/machete 之后的公共段 (两分支都跑, issue #141): CI 走 --coverage 分支
# 也能闭环; doc 构建复用 debug/ 元数据缓存, 增量开销秒级, 不拖慢 coverage 路径.
# 不带 --document-private-items: 项目内部 doc 链接指向 private item 是合理的 (维护者文档),
# --document-private-items 会把这些当警告. 只查 public doc 的链接完整性即可守住门禁初衷.
#
# 尾部 typos + deny-offline (issue #149-8): 保证 "本地 check 全绿 ⇒ CI 阻塞项必绿"
# (CI 的 typos / deny 阻塞 step 与本地跑同一命令). deny-offline 是纯离线检查 (不拉
# advisory DB), 秒级; 全量 deny (含 advisories, 需联网) 仍由 just deny 单独提供.
#
# --locked: 见文件头 "约定" 段 (SSOT).
check *ARGS:
    just check-fmt
    cargo clippy --locked --all-targets -- -D warnings
    cargo machete
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
    just check-webui-syntax
    just check-contracts
    # cargo test --doc
    @if echo "{{ ARGS }}" | grep -q -- "--coverage"; then \
        cargo llvm-cov clean --workspace; \
        cargo llvm-cov nextest --locked --no-fail-fast --no-report; \
    else \
        cargo nextest run --locked --no-fail-fast; \
        just check-features; \
    fi
    just typos
    just deny-offline
    just nix-check

# consistency-check feature 守卫 (CI 用): clippy + nextest 带 feature flag.
# 该 feature 默认关闭, 包含视图正确性断言 (proxy/recorder.rs::assert_redactions_match_map).
# 详见 AGENTS.md "视图正确性确保机制". CI workflow 单独成步运行本目标.
check-features:
    cargo clippy --locked --all-targets --features consistency-check -- -D warnings
    cargo nextest run --locked --no-fail-fast --features consistency-check

# 内嵌 JS 语法检查 (秒级, 阻塞式).
# 从 src/web/index.html 提取 <script>...</script> 块, 用 node --check 验证语法.
# 这类低级语法错误 (未闭合括号/函数嵌套错位) 无法被 cargo 工具链发现; check-webui
# (Playwright) 虽能间接捕获 (页面白屏) 但重 (3 分钟) 且 CI 中非阻塞 (continue-on-error).
# 本 step 作为 check 的一部分, 让语法错误在秒级被阻断. devShell 已提供 node (无新依赖).
# 历史教训: f1a89c0 的 loadUntilRound 漏闭合 } 导致 SyntaxError: Unexpected end of input.
check-webui-syntax:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    script="$tmp/script.js"
    # 提取所有 <script>...</script> 块拼接. 兼容带属性的开标签 (如 <script type="...">).
    awk '/<script[[:space:]>]/{f=1;next} /<\/script>/{f=0} f' src/web/index.html > "$script"
    # fail-closed: 提取为空 = index.html 结构变了 (script 块改名/消失), 此时必须报错而非静默放行,
    # 否则本检查会被无声绕过 (保护装置自身失效). 历史教训见 recipe 头部注释.
    lines=$(wc -l < "$script")
    if [ "$lines" -eq 0 ]; then
        echo "check-webui-syntax: 未从 src/web/index.html 提取到 <script> 内容;" >&2
        echo "  检查 script 标签是否仍存在 / 是否被拆分到外部 .js 文件 (需调整本 recipe)." >&2
        exit 1
    fi
    node --check "$script"
    echo "webui-syntax: OK ($lines lines)"

# WebUI 回归测试 (Playwright 端到端). 需 devShell (nix develop).
#
# 三道防线 (缺一不可) 详见 tests/webui/playwright.config.ts 头部注释;
# 本 recipe 实现防线 #2: 在 playwright test 之前清掉端口 18790/19999 上的孤儿.
#
# 为什么用 lsof + kill 而非 pkill -f 'secret-guard run --port ...':
# pkill -f 会匹配 justfile 自己 / 父 shell / nix develop 进程 (它们的命令行也含该字串),
# 自杀卡死. lsof 按 listening socket 反查 PID, 不误伤. (CI runner microvm 不主动 kill
# job 子进程, 上次 run 异常退出留下的孤儿会持续 listening, 触发 EADDRINUSE.)
check-webui: _kill-orphans
    cd tests/webui && playwright test

# 清理占用 18790/19999 端口的孤儿进程 (Playwright webServer 残留).
# 私有 recipe (`_` 前缀约定: 不出现在 `just --list`), 供 check-webui / check-all 复用.
#
# 失败语义: recipe body 自身 fail-safe (lsof 缺失 → exit 0; kill 失败 → || true),
# 故清不到孤儿不阻塞, 让 playwright 自己 fail 时报 EADDRINUSE, 比这里硬失败更可诊断.
#
# 非并发安全: 两个并发 `just check-webui` 会互相 kill 对方 webServer. 实际开发中 WebUI
# 测试很少并发跑, 不加 flock 锁 (over-engineering), 仅在此声明边界.
#
# shebang recipe: 多行脚本由 bash 直接执行, $ 按 bash 语义解释.
# (注意: just 普通 recipe 的 $$ 不是转义 — 它会字面进入 sh 被解释为 PID, 是常见陷阱.
# 用 shebang 形式彻底避开这个坑.)
_kill-orphans:
    #!/usr/bin/env bash
    if ! command -v lsof >/dev/null 2>&1; then
        echo "check-webui: lsof not in PATH, skip orphan cleanup" >&2
        exit 0
    fi
    for port in 18790 19999; do
        for pid in $(lsof -iTCP:$port -sTCP:LISTEN -t 2>/dev/null); do
            # 排除 PID=1 (init/systemd, 误杀会重启容器/VM, 致命).
            if [ "$pid" = "1" ]; then
                continue
            fi
            echo "killing PID $pid on port $port"
            kill "$pid" 2>/dev/null || true
        done
    done
    # 等 SIGTERM 后端口释放 (孤儿无活跃连接故 0.2s 足够, 非 graceful shutdown 完整等待).
    sleep 0.2

# check + check-webui (完整验证, devShell 内).
# 行为差异提醒: 本地 check-all 让 Playwright 阻塞 (失败即 exit 1), 但 CI 的 WebUI step
# 用 continue-on-error (非阻塞, 见 .forgejo/workflows/ci.yml WebUI regression step 注释).
# 即 "本地全绿 → push" 不代表 CI 必绿 — CI flake 不会阻断合并, 维护者需人工关注 CI log.
# 这是有意设计 (WebUI 在 CI 环境 flake 率高), 详见 ci.yml 注释与 AGENTS.md "CI" 段.
check-all: check _kill-orphans
    cd tests/webui && playwright test

# org ci 契约 recipe (阻塞级门禁入口, 见 lc-studio/forgejo-actions README)。
# 本仓是 legacy 形态 (双 job 编排保留在 workflow, 见 ci.yml 头 form: legacy 标记),
# 本 recipe 收敛 CI 阻塞 job 的质量链 (check-features → check --coverage →
# coverage-gate → check-file-size), 供本地一键复现与 org 契约走查; bench/WebUI/
# PR 评论矩阵等编排类或 continue-on-error step 不在此列 (workflow 编排不可收编)。
ci:
    just check-features
    just check --coverage
    just coverage-gate
    just check-file-size

# 仅 fmt: treefmt 全仓格式化 (nix/rust/toml/py; 配置 SSOT = 根 treefmt.toml).
# 仅想格式化 rust 时手动 `cargo fmt` 亦可 (edition 一致, 输出等价).
fmt:
    treefmt

# 格式门禁: treefmt (格式范围同上方 fmt recipe 的括注). CI runner VM 未预装
# treefmt 时降级为 cargo fmt --check (仅 rust) + WARN — VM 预装
# treefmt/nixfmt/taplo/ruff 后删除降级分支 (lc-studio/nixos#1048);
# 降级窗口内 .nix/.toml/.py 的格式漂移不被 CI 拦, 记得本地跑 just fmt.
check-fmt:
    @if command -v treefmt >/dev/null 2>&1; then treefmt --fail-on-change; else \
        echo "WARN: treefmt 未安装, 降级为 cargo fmt --check (仅 rust 格式门禁; 全量门禁见 lc-studio/nixos#1048)"; \
        cargo fmt -- --check; \
    fi

# 仅 clippy.
clippy:
    cargo clippy --locked --all-targets -- -D warnings

# 仅 test.
test:
    cargo nextest run --locked --no-fail-fast

# 仅运行 ignored 测试 (TDD 红灯循环用, 详见 AGENTS.md "TDD 与可选测试").
# 子串按测试名过滤 (非 ignore reason): just test-ignored gemini
# --no-tests=warn: 无匹配不报错 (查询型语义).
test-ignored *ARGS:
    cargo nextest run --run-ignored=only --no-tests=warn {{ ARGS }}

# ─── coverage ─────────────────────────────────────────────────────────────
# 基于 LLVM source-based coverage (cargo-llvm-cov). 工具链与 LLVM_COV/LLVM_PROFDATA
# 环境变量由 nix devShell 注入 (见 nix/shells/default.nix), 因此以下命令需在 `nix develop` 内执行.
# CI 里 ci.yml 用 job 级 env 写死绝对路径注入 (runner VM 不进 devShell).
# 产物默认写到 target/llvm-cov-target/ + coverage/ (已 .gitignore).
#
# 门禁基线 (SSOT): 双阈值互补.
#   - COVERAGE_MIN_LINES (主防线, 百分比): 天然随代码增长自适应, 是防回归的核心.
#   - COVERAGE_MAX_UNCOVERED (辅助, 绝对行数): 防一次性大量未覆盖代码涌入 (如新模块
#     不写测试). 绝对值会随代码增长失效, 故阈值为当前实测 + ~7% 缓冲, 需每季度走查
#     (走查触发: `just coverage` 后人工核对 summary 的 uncovered 行数).
# 当前实测约 ~86% / ~1350 uncovered (auth 模块的 OIDC/handler/middleware 路径
# 需 mock IdP 集成测试, 留作后续).
COVERAGE_MIN_LINES := "84"
COVERAGE_MAX_UNCOVERED := "1450"

# 覆盖率摘要 (终端表格).
coverage:
    cargo llvm-cov nextest --locked --no-fail-fast --no-report
    cargo llvm-cov report --summary-only

# 覆盖率门禁 (CI 用): 双阈值, 任一不满足则非零退出.
# 前置: check --coverage 已产出 profdata 到 target/llvm-cov-target/. 本 recipe 只做 report.
# 阈值语义见上方 COVERAGE_MIN_LINES / COVERAGE_MAX_UNCOVERED 注释.
coverage-gate:
    cargo llvm-cov report --summary-only \
      --fail-under-lines {{ COVERAGE_MIN_LINES }} \
      --fail-uncovered-lines {{ COVERAGE_MAX_UNCOVERED }}

# HTML 报告 (浏览器打开 coverage/html/index.html).
coverage-html:
    cargo llvm-cov nextest --locked --no-fail-fast --no-report
    cargo llvm-cov report --output-dir coverage --html
    @echo "HTML report: coverage/html/index.html"

# LCOV 报告 (CI / IDE 集成).
coverage-lcov:
    mkdir -p coverage
    cargo llvm-cov nextest --locked --no-fail-fast --lcov --output-path coverage/lcov.info
    @echo "LCOV report: coverage/lcov.info"

# 启动 mock 上游 (用于本地集成测试; 占位).
mock-upstream:
    @echo "TODO: 第二步会引入 mockito-based 上游"

# 检查依赖漏洞.
# CARGO_AUDIT_DB (可选): advisory DB 的 git repo 路径. cargo-audit 只认 --db flag
# (无同名 env), 这里显式透传, 让 CI 的持久卷缓存 (见 ci.yml audit step) 经 env 生效
# (issue #149-3). 未设时不传 --db, 落回工具自身默认 (自动尊重 CARGO_HOME).
audit:
    cargo audit ${CARGO_AUDIT_DB:+--db "$CARGO_AUDIT_DB"}

# license 合规 + 依赖 bans + advisory 二次审查 (cargo-deny).
# 与 audit 的分工: audit 专注 RUSTSec CVE; deny 额外覆盖 license 不兼容 / 重复 crate
# 多版本 / 禁止依赖. 项目声明 MIT 且发布到 nixpkgs overlay, license 合规是硬约束
# (引入 GPL/AGPL 等 copyleft 会污染下游). 配置见 deny.toml.
#
# 重复 crate (multiple-versions) 在 deny.toml 配为 warn 不阻断 — Rust 生态 duplicate
# 多为传递依赖暂态, 强制 deny 会频繁阻塞. 跑本命令看完整列表, 维护者主动评估能否 dedupe.
deny:
    cargo deny check --hide-inclusion-graph

# 纯离线版 deny (licenses + bans + sources, 不含 advisories) — CI 阻塞门禁与本地
# check 链共用 (issue #149-3/-8). 理由: advisories 检查需联网拉 advisory DB, 网络抖动
# 会让 "阻塞门禁" 随机失败; 而 advisories 的职责已由 continue-on-error 的 cargo audit
# 覆盖 (两者本就互为冗余兜底). 离线部分只查本地 lockfile + deny.toml, 结果确定性强,
# 适合做门禁. 全量检查 (含 advisories) 用上方 just deny.
# 注: --offline 是 cargo-deny 的全局 flag (须在 check 子命令之前), 只指定要跑的
# 检查组即不触发 advisory DB 拉取.
deny-offline:
    cargo deny --offline check --hide-inclusion-graph licenses bans sources

# 拼写检查 (typos-cli). 项目大量英文术语与中文注释混排, 拼写错误难人工抓.
# 发现 typo 即 exit 1. CI 阻塞 step 与本地 check 链尾跑同一命令 (issue #149-8).
# 白名单 (合法标识符 / test fixture 误报) 见 _typos.toml, 每项需注释说明为何是误报.
typos:
    typos

# redact 性能基线 (criterion bench).
# 详尽设计 (3 场景 + 2 目标 + 为什么手动构造 map) 见 benches/redact.rs 头部.
# 默认 100 samples 较慢; CI 用 --quick (10 samples) 兼顾覆盖与速度, 本地完整跑用 `just bench`.
# 透传 criterion 参数: just bench --quick / just bench -- --quick.
#
# CI 调用: 被 ci.yml "Performance benchmark" step 调用 (非阻塞, 走 bench-ci 做基线对比).
# release 缓存复用 CARGO_TARGET_DIR/release/ (与 debug/ 物理隔离).
bench *ARGS:
    cargo bench --locked --bench redact -- {{ ARGS }}

# CI 性能回归检测 (criterion baseline 机制).
#
# 机制 (基于实测, 纠正 "criterion 退化会 exit 非零" 的常见误解):
#   criterion 即使检测到显著退化也永远 exit 0 (仅基线缺失时 panic exit 101).
#   因此本 recipe 自行解析输出, 按中位数变化率判定回归, 超阈值则 exit 1.
#
# 两阶段设计 (与 ci.yml 的 master/PR 双事件配合):
#   - mode=save  (master push):  `--save-baseline ci` — 先对比再覆盖基线, 让基线
#     持续滚动更新 (master 永远是最新基准).
#   - mode=compare (PR):          `--baseline ci`      — 只对比不覆盖. 基线缺失
#     (冷启动) 时 criterion panic, 本 recipe 先检测基线目录是否存在, 缺失则
#     fallback 到 save 模式建立首基线 (PR 第一次跑无历史可对比, 属正常).
#
# 退化判定逻辑 (解析 criterion stdout):
#   每个场景输出 `change: time:   [lo% med% hi%]` 行. 取 med (中位数):
#     - med > +REGRESSION_THRESHOLD (默认 20%): 标记回归, 收集进报告, 最终 exit 1.
#     - 否则: 视为正常波动 (--quick 10 samples 下 p>0.05 是常态, 统计显著性弱,
#       只能做量级级粗筛, 防 2x+ 退化).
#
# 输出契约 (供 CI 消费):
#   - stdout:  criterion 原始输出 + 末尾的回归判定摘要 (如有).
#   - exit 0:  无回归 (或基线冷启动).
#   - exit 1:  至少一个场景中位数退化超阈值.
#   - exit 2:  bench 本身失败 (编译/运行错误, 非退化).
#
# 阈值 SSOT: REGRESSION_THRESHOLD (百分比, 不带 %). 20% 的依据: --quick 噪声大
# (实测同机器同负载波动可达 ±15%), 20% 留缓冲只卡量级级退化; 升级到 100 samples
# 后可收紧到 10%.
REGRESSION_THRESHOLD := "20"

bench-ci mode *extra:
    #!/usr/bin/env bash
    set -uo pipefail
    THRESHOLD={{ REGRESSION_THRESHOLD }}
    BASELINE_NAME="ci"
    # criterion 基线落 CARGO_TARGET_DIR/criterion/<group>/<bench>/<baseline_name>/.
    # 基线存在性判定: 任一场景目录存在即视为基线已建立 (6 场景要么都有要么都无).
    # 假设破裂条件: 新增 bench 场景后, 老 场景基线仍在但新场景无基线, compare 模式会让
    # criterion 对新场景 panic (exit 101) → 误报 bench 失败. 此时需先让 master 跑一次
    # save 建立完整基线, 再开 PR.
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"
    BENCH_DIR="$CARGO_TARGET_DIR/criterion"
    baseline_exists() {
        [ -d "$BENCH_DIR/redact_ir/small/$BASELINE_NAME" ]
    }

    # 选择 criterion flag.
    ACTION="{{ mode }}"
    if [ "$ACTION" = "save" ]; then
        BENCH_FLAG="--save-baseline $BASELINE_NAME"
    elif [ "$ACTION" = "compare" ]; then
        if baseline_exists; then
            BENCH_FLAG="--baseline $BASELINE_NAME"
        else
            # 冷启动: PR 第一次跑无基线可对比, fallback 建立. 不算回归.
            echo "bench-ci: 基线 '$BASELINE_NAME' 不存在 (冷启动), 本次仅建立基线不判定回归." >&2
            BENCH_FLAG="--save-baseline $BASELINE_NAME"
            ACTION="save"
        fi
    else
        echo "bench-ci: 未知 mode '$ACTION' (应为 save 或 compare)" >&2
        exit 2
    fi

    # 跑 bench, 捕获输出. set +e: cargo bench 退化时仍 exit 0, 但编译/运行错误
    # 会 exit 非 101, 需捕获区分 (退化 vs 真失败).
    OUTPUT=$(cargo bench --locked --bench redact -- --quick $BENCH_FLAG {{ extra }} 2>&1)
    BENCH_EXIT=$?
    echo "$OUTPUT"
    if [ "$BENCH_EXIT" -ne 0 ]; then
        echo "bench-ci: cargo bench 失败 (exit $BENCH_EXIT), 非退化判定范畴." >&2
        exit 2
    fi

    # save 模式 (含冷启动 fallback) 不判定回归, 只更新基线.
    if [ "$ACTION" = "save" ]; then
        echo "bench-ci: 基线 '$BASELINE_NAME' 已更新."
        exit 0
    fi

    # compare 模式: 解析每个场景的 change 中位数, 判定回归.
    # criterion 输出格式 (实测): 每个场景有绝对 time 行 [lo med hi] (无 %), change 区段
    # 紧跟一个 time: [lo% med% hi%] 行 (含 %; 与绝对 time 行的区别是带 %). "含 % 的 time
    # 行 = change 行" 是单行特征, 无需跨行状态机. 用 POSIX ERE ([[:space:]] 而非 \s) +
    # match()+RSTART/RLENGTH (避免 gawk 专有的 match(s,re,arr) 三参数形式), 跨 runner 可移植.
    regressions=$(echo "$OUTPUT" | awk -v thr="$THRESHOLD" '
        # bench id 行: 形如 redact_ir/small / streaming_restorer/large (可跨行)
        /^[a-z]/ { bench = $1 }
        # change time 行: 含 % 即相对基线 (绝对 time 行与 thrpt 行均无 %)
        /time:[[:space:]]*\[.*%/ && bench != "" {
            if (match($0, /\[[^]]*\]/)) {
                split(substr($0, RSTART+1, RLENGTH-2), v, /[%[:space:]]+/)
                med = v[2] + 0
                if (med > thr) printf "%s: +%d%%\n", bench, med
            }
        }
    ')

    if [ -n "$regressions" ]; then
        echo "" >&2
        echo "bench-ci: ⚠️ 检测到性能退化 (中位数 > ${THRESHOLD}%):" >&2
        echo "$regressions" | sed 's/^/  /' >&2
        exit 1
    fi
    echo "bench-ci: ✓ 无场景退化超 ${THRESHOLD}% 阈值."
    exit 0

# bench 编译验证 (--no-run 零样本, dev profile): 快速验证 bench 可编译.
# CI 不再调用 (CI 跑完整 bench); 仅供本地秒级验证 (复用 debug 缓存).
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
# 当前 prod 最大是 codec/openai.rs=1127 (proxy.rs 拆分为 proxy/ 目录后各子模块已远低于
# 阈值), MAX 1600 留余量; WARN 500 让任何模块膨胀到该规模时尽早引起注意 (拆分 ROI
# 评估的早期信号). 更新数字前跑 `just check-file-size` 取实测值.
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
      if [ "$prod" -gt {{ FILE_MAX_PROD_LINES }} ]; then
        errors="$errors$prod $f"$'\n'
      elif [ "$prod" -gt {{ FILE_WARN_PROD_LINES }} ]; then
        warnings="$warnings$prod $f"$'\n'
      fi
    done < <(find src -name '*.rs' -print0)
    # 按行数降序输出 (最该拆的排第一). sort -rn: 数字逆序.
    # grep -v '^$': 过滤 printf 末尾换行产生的空行, 避免 sed 缩进成纯空格行.
    if [ -n "$warnings" ]; then
      echo "::warning::Files exceeding {{ FILE_WARN_PROD_LINES }} prod lines (consider splitting; test code excluded):"
      printf '%s\n' "$warnings" | grep -v '^$' | sort -rn | sed 's|^|  |'
    fi
    if [ -n "$errors" ]; then
      echo "::error::Files blocked by gate (exceeding {{ FILE_MAX_PROD_LINES }} prod lines or tool failure; test code excluded):"
      printf '%s\n' "$errors" | grep -v '^$' | sort -rn | sed 's|^|  |'
      exit 1
    fi
    echo "All source files within {{ FILE_MAX_PROD_LINES }} prod-line limit (test code excluded)."

# ─── 文档新鲜度检查 (非阻塞, #147) ─────────────────────────────────────────
# 校验文档 ↔ 代码/CI 的机械可查引用没漂移 (issue #147 的防复发机制):
#   1. 文档中 `path/to.rs::symbol` 引用: 文件存在 && symbol 在该文件中出现.
#      路径约定: 不带 src/ 前缀的相对 crate 根 (AGENTS.md 风格, 如 proxy/recorder.rs::xxx);
#      带 src/ 或 tests/ 前缀的相对仓库根也接受 (contracts.md 风格).
#   2. docs/ci.md "CI 流程" step 清单条数 == .forgejo/workflows/ci.yml 实际 `- name:` 数.
#      (ci.md 另有若干背景性 step 提及, 不在编号清单内, 故只对齐编号清单.)
# 非阻塞定位: 独立 recipe, 不进 `just check` 链 (文档漂移不拦编译, 且 symbol 字面匹配
# 对 重命名/宏生成 有已知误报面 — 人工 triage 后再决定是否升级). 与 #144 (traceability
# lint, property→测试) 互补: 本检查管 文档→符号/step.
check-docs:
    #!/usr/bin/env bash
    set -euo pipefail
    # rg 隐式依赖显式化: 缺 rg 时采集静默变空列表 → 假绿, 必须前置失败.
    command -v rg >/dev/null 2>&1 || { echo "::error::check-docs: rg not found"; exit 1; }
    errors=0
    # 统一错误出口: 前缀 + 计数. (step=0 诊断不走此函数 — 那是锚点失效, 直接 exit.)
    fail() { echo "::error::check-docs: $*"; errors=$((errors+1)); }
    # --- 1. .rs::symbol 引用存在性 ---
    while IFS= read -r ref; do
      f="${ref%%::*}"
      sym="${ref##*::}"
      # 解析仓库相对路径: 无前缀 → 相对 crate 根 (src/), src/ 或 tests/ 前缀 → 相对仓库根.
      case "$f" in
        src/*|tests/*) path="$f" ;;
        *)             path="src/$f" ;;
      esac
      if [ ! -f "$path" ]; then
        fail "文档引用的文件不存在: $ref (path=$path)"
        continue
      fi
      if ! rg -q --no-messages "\b$sym\b" "$path"; then
        fail "文档引用的 symbol 不在目标文件中: $ref"
      fi
    done < <(rg --no-messages -o --no-filename -g '*.md' \
      '[A-Za-z0-9_/.-]+\.rs::[A-Za-z0-9_]+' AGENTS.md docs src 2>/dev/null | sort -u)
    # --- 2. ci.md step 清单 == ci.yml 实际 step 数 ---
    # grep -c 零匹配时 exit 1 + 输出 0 (pipefail 会让脚本在此非零退出, 属 fail-closed,
    # 但零匹配更可能是 awk 锚点失效 — 加诊断再退出).
    md_steps=$(awk '/^## CI 流程/,/^> \*\*流程顺序原则/' docs/ci.md | grep -cE '^[0-9]+\. \*\*' || true)
    yml_steps=$(grep -cE '^\s*- name:' .forgejo/workflows/ci.yml || true)
    if [ "$md_steps" = "0" ] || [ "$yml_steps" = "0" ]; then
      echo "::error::check-docs: step 计数为 0 (awk/grep 锚点可能失效), md=$md_steps yml=$yml_steps"
      exit 1
    fi
    if [ "$md_steps" != "$yml_steps" ]; then
      fail "docs/ci.md step 清单 ($md_steps) != ci.yml 实际 step 数 ($yml_steps)"
    fi
    if [ "$errors" -gt 0 ]; then
      echo "check-docs: $errors 处文档引用漂移 (见上方 ::error, 非阻塞, 请人工确认)."
      exit 1
    fi
    echo "check-docs: ✓ 文档 .rs::symbol 引用与 ci.md step 计数均与代码一致."

# ─── 契约 property traceability lint (#144, 阻塞) ──────────────────────────
# 防 "愿望清单腐化" 复发: contracts.md 的每条 property 必须有落地状态标注, 且
# 标注锚点必须真实存在于 src/+tests/ (防幻影标注). 三种标注 (语义 SSOT 见
# contracts.md §0.6):
#   ✅  同名落地 — property 名本身在 src/+tests/ (*.rs/*.ts) 有测试载体级字面命中
#       (word-match + 排除纯注释行: 命中行须含 fn/test 定义形态, 防 "写行注释伪造 ✅").
#   🔁  改名落地 — 行内 `🔁→\`锚点\`` 起**全部**反引号锚点 (排除 `路径` 形态) 在扫描
#       范围内 grep -F 命中. 锚点通常是实际测试名; 对 Playwright (中文测试标题) /
#       注释审查项 / CI step 类守卫, 锚点可以是任意可 grep 的固定串.
#   ⏳  待补 — 真零测试. 免 grep, 但计数报告 (补齐排期见 contracts.md §0.6).
# 规则 (全部 fail-closed, 含输入侧):
#   R0: contracts.md 缺失 / property 行数为 0 (锚点 grep 失效或行格式漂移) → 报错.
#       property 行格式契约: 顶格 `- \`prop_...\`` (§0.6), 缩进/表格形式不被扫描.
#   R1: property 行缺三种标注之一 → 报错.
#   R2: ✅ 行但 property 名零命中 → 报错 (假 ✅).
#   R3: 🔁 行但任一锚点零命中 → 报错 (指向不存在的测试 = 双重幻影).
# 已知豁免面 (机械 lint 无法覆盖, 由 review + 计数公开兜底):
#   - 泛串锚点 (如 `fn`) 字面可命中 — 锚点应写具体测试名, review 时核对.
#   - ⏳ 免检 — 但计数在输出公开 + §0.6 优先级表追踪, 滥用会立刻可见 (⏳ 数暴增).
# 扫描范围: src/ tests/ (*.rs/*.ts) + justfile + .forgejo/workflows/ci.yml
# (后两处覆盖 CI step / recipe 类锚点, 如 VIEW-1 的 consistency-check step).
# 工具: 纯 bash+grep+sed (runner VM corePackages, 无 rg 依赖 — 区别于 check-docs
# 的 rg; 本检查进 `just check` 阻塞链, 必须在 CI runner 可运行).
# 自测方式: 删任一行的标注 → 本 recipe 红; 恢复 → 绿.
check-contracts:
    #!/usr/bin/env bash
    set -euo pipefail
    md=docs/design/contracts.md
    errors=0; n_ok=0; n_renamed=0; n_pending=0
    fail() { echo "::error::check-contracts: $*"; errors=$((errors+1)); }
    # R0 (输入侧 fail-closed): 文件缺失 / 零 property 行 = 锚点失效或格式漂移,
    # 循环零次执行会让 lint 静默假绿, 必须显式拦截 (同 check-docs 的 step=0 防护).
    if [ ! -f "$md" ]; then
      echo "::error::check-contracts: $md 不存在 (被移动/改名? lint 会静默假绿, 需同步 recipe 路径)."
      exit 1
    fi
    # 同 R0: 在循环前拦截 (n_lines 供末尾汇总复用).
    n_lines=$(grep -cE '^- `prop_' "$md" || true)
    if [ "$n_lines" -eq 0 ]; then
      echo "::error::check-contracts: property 行数为 0 (^- \`prop_\` 锚点失效或行格式漂移?)."
      exit 1
    fi
    # grep -w 用 _ 作为 word 字符, prop_xxx 名天然是完整 word (不会被更长名误命中).
    # 测试载体过滤: 命中行须含 "fn <name>" (Rust) 或 "test(\"...<name>...\", async"
    # (Playwright 标题; name 紧跟 test( 亦可) 定义形态, 排除纯注释 (/// doc / // 行)
    # 的同名提及 — 只在注释里写一遍 property 名不构成 ✅ 落地.
    hit_word() {
      grep -rw --include='*.rs' --include='*.ts' -e "$1" src tests 2>/dev/null \
        | grep -qE "(fn +$1|test\([^\"]*$1|$1[^\"]*\", *async)"
    }
    # 锚点固定串匹配: 不限文件类型 (justfile / ci.yml 无后缀匹配需求), grep -F 字节级.
    hit_anchor() { grep -rqF -- "$1" src tests justfile .forgejo/workflows/ci.yml 2>/dev/null; }
    # 🔁 行的全部锚点: 🔁→ 起的每个反引号对, 排除 `路径` 形态 (含 / 或 . 前后缀的
    # 文件引用, 如 `src/redact.rs`); 多锚点全部校验 (L1: 第二锚点漂移也须拦截).
    anchors_of() {
      printf '%s' "$1" | sed -n 's/.*🔁→//p' \
        | grep -oE '`[^`]+`' | tr -d '`' | grep -vE '/|\.rs$|\.ts$|\.md$|\.yml$' || true
    }
    while IFS= read -r line; do
      prop=$(printf '%s' "$line" | sed -n 's/^- `\(prop_[a-z0-9_]*\)`.*/\1/p')
      if [ -z "$prop" ]; then continue; fi
      case "$line" in
        *'⏳'*)
          n_pending=$((n_pending+1))
          ;;
        *'🔁'*)
          anchors=$(anchors_of "$line")
          bad_anchor=""
          # while read 整串消费: 防 word-splitting 的 glob 意外展开 (锚点含 * ? 时
          # for-in 会展开成 cwd 文件列表) + 多词锚点保持整串校验语义.
          while IFS= read -r anchor; do
            hit_anchor "$anchor" || { bad_anchor="$anchor"; break; }
          done <<< "$anchors"
          if [ -z "$anchors" ]; then
            fail "$prop: 🔁 标注缺锚点 (格式: 🔁→\`实际测试名\`)"
          elif [ -n "$bad_anchor" ]; then
            fail "$prop: 🔁 锚点 '$bad_anchor' 在 src/+tests/+justfile+ci.yml 零命中 (幻影锚点?)"
          else
            n_renamed=$((n_renamed+1))
          fi
          ;;
        *'✅'*)
          if hit_word "$prop"; then
            n_ok=$((n_ok+1))
          else
            fail "$prop: 标 ✅ 但同名测试零命中 — 改名落地应用 🔁→\`实际名\`, 真零测试用 ⏳"
          fi
          ;;
        *)
          fail "$prop: 缺落地状态标注 (✅ 同名 / 🔁→\`实际名\` / ⏳ 待补; 见 contracts.md §0.6)"
          ;;
      esac
    done < <(grep -E '^- `prop_' "$md")
    if [ "$errors" -gt 0 ]; then
      echo "check-contracts: $errors 处标注缺失/失效 (见上方 ::error)."
      exit 1
    fi
    echo "check-contracts: ✓ $n_lines 条全量标注有效 — ✅ 同名 $n_ok / 🔁 改名 $n_renamed / ⏳ 待补 $n_pending (优先级见 contracts.md §0.6)."

# nix 侧验证: render 契约测试 + 模块 eval 冒烟 (flake checks 的轻量子集 —
# runCommand/python3/writeText, 不含 secret-guard 的 Rust 编译闭包, 秒级).
# 挂在 just check 链尾; src serde schema 变更时此处先红.
# --extra-experimental-features: 环境 (如 CI runner 的 Lix) 未启用
# nix-command/flakes 时自包含可跑; 本地已启用时重复传无害.
# nix-daemon 探测跳过: CI runner VM 架构禁止 nix 求值 (无 writableStoreOverlay /
# 无 daemon, 见 forgejo-runner-vm.mod.nix「CI 工具链规范」), 探测到无 daemon socket
# (NIX_DAEMON_SOCKET_PATH 默认路径, systemd socket-activation 按需拉起) 时打印
# notice 跳过而非失败 — serde 漂移的 CI 门禁因此不可行, 由本地纪律承担.
nix-check:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -S /nix/var/nix/daemon-socket/socket ]; then
      echo "nix-check: skip — 无 nix-daemon (CI runner 架构禁止 nix 求值), 本地 just check 全量覆盖本项"
      exit 0
    fi
    system="$(uname -m)-linux"
    nix --extra-experimental-features "nix-command flakes" build ".#checks.${system}.render-test" ".#checks.${system}.module-eval" -L

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
    if [[ " {{ ARGS }} " != *" --format "* && " {{ ARGS }} " != *" --format="* ]]; then
        FORMAT=(--format human)
    fi
    git diff "$BASE...HEAD" | rust-diff-analyzer "${FORMAT[@]}" --no-fail {{ ARGS }}
