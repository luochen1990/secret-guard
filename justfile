# secret-guard — justfile
# 一键命令集合, 覆盖开发 / 检查 / 测试 / 运行.
#
# 约定: 验证类 cargo 命令 (check/clippy/test/coverage*/bench/bench-ci)
# 统一带 --locked — Cargo.toml 改动而 Cargo.lock 未提交时直接失败, 防 CI 静默重
# resolve 导致 "CI 测试的依赖集 ≠ 提交的 lockfile ≠ nix 发布产物" 三元漂移 (issue #142).
# 本地手改 Cargo.toml 后碰到一次 "lock file needs to be updated" 报错属预期提醒,
# 跑一次 `cargo build` 更新 lockfile 后提交即可; 开发内环 recipe (build/run/dev*) 不带.
#
# 全量档 feature 参数 SSOT (#276 + tier-collapse): 验证/测试/覆盖率入口 (check /
# clippy / test / coverage*) 统一走全量档 (oidc + consistency-check 合并 — feature
# 正交可加, 一轮 codegen 同时覆盖 OIDC 登录链与视图正确性断言, 消除档位翻转的
# 重复编译); 默认档 (无 oidc) 的编译+测试矩阵由 GitHub 镜像 CI 承担
# (.github/workflows/ci.yml, 与 forgejo 分工) — 档位切换只改这一处.
FULL_TIER := "--features oidc,consistency-check"

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
# **全量档 (--features oidc,consistency-check, #276 + tier-collapse)**: 主链一轮
# codegen 同时覆盖 OIDC 登录链 + 视图正确性断言 — 本地全绿 = 全量绿.
# 默认档 (无 oidc) 的编译 + 测试矩阵由 GitHub 镜像 CI 承担 (.github/workflows/ci.yml;
# dev/watch 类内环 recipe 不带 feature, 追求最快反馈).
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
# doctest 已恢复进链 (#357): nextest 不执行 doctest, 由独立 `cargo test --doc` 补
# (增量开销 <1s, 复用 clippy 的 debug/ 产物)。当前唯一 doctest (auth::middleware)
# 被标为 ```ignore 不执行 — 链路保持通, 新增 doctest 即时生效, 不再静默变 "永不运行".
#
# consistency-check feature 守卫: 默认关闭的视图正确性断言, 经 FULL_TIER 并入
# 本 recipe 的 clippy/test 全量档 (tier-collapse, 曾为独立 recipe + CI step —
# 动机见 docs/ci.md "双宿主验证分工"; 契约锚点 contracts.md
# prop_consistency_check_feature_runs_in_ci), 复用同一 target/debug, 不影响磁盘峰值控制.
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
#
# bare-shell 自愈 + fail-fast (2026-10-20 事故, 同 2026-10-19 treefmt wrapper
# 劫持一类; 短时两复发, 提示语不足以止血, 升级为自动修复):
# - check 链的 check-webui-freshness 依赖 devShell 的 playwright-test, 裸 shell
#   运行时 PATH 会被系统 Python 变体 (如 /etc/profiles/.../bin/playwright) 抢占;
#   已在 devShell 内也可能被 prepend 的坏 PATH 遮蔽。
# - 自愈: 守卫探测将失败 + nix 可用 → 自动重入 `nix develop --impure` 再跑同一
#   recipe (内层守卫通过即直接走链)。
# - 防循环哨兵 = SG_CHECK_REENTRY_DEPTH 深度计数 (仅允许重入一层)。
#   深度语义: 裸 shell (未设/0) → 重入并置 1; 已 ≥1 → 不再重入, 落
#   _check-body 头守卫 fail-fast (devShell 真缺 playwright-test 的准确报错)。
#   不用 IN_NIX_SHELL 判 "已在 devShell" — 它随子 shell 下泄, agent/CI shell
#   常带 IN_NIX_SHELL=impure 而 PATH 已被重建为裸 (2026-10-20 实证), 误判会
#   跳过自愈。
# - **必须 shebang recipe**: just 对无 shebang 的 recipe **逐行**起独立 shell
#   执行 — `exec nix develop` 只替换 @if 那一行的 shell, 下一行 `just
#   _check-body` 仍会在裸 shell 里跑 (2026-10-20 事故根因: 自愈内层全绿后,
#   外层继续执行下一行撞死在守卫上, 整体 exit 1)。shebang 让全 recipe 共享
#   一个 bash 进程, exec 才能真正接管并终结后续行。
# - CI runner (vm-nix, 自带 playwright-test, nix 求值被禁): 守卫探测通过 →
#   不重入, 行为与既有完全一致; 坏环境且无 nix → 内层头守卫 fail-fast。
check *ARGS:
    #!/usr/bin/env bash
    if ! just --quiet _require-playwright-test >/dev/null 2>&1 && command -v nix >/dev/null 2>&1 && [ "${SG_CHECK_REENTRY_DEPTH:-0}" -lt 1 ]; then
        echo "check: playwright 环境受损 (PATH 抢占或 devShell 缺失) — 自动重入 nix develop --impure"
        exec nix develop --impure -c bash -c 'SG_CHECK_REENTRY_DEPTH=$((1+${SG_CHECK_REENTRY_DEPTH:-0})) just check {{ ARGS }}'
    fi
    just _check-body {{ ARGS }}

# check 的内层链 (真正的验证步骤; 公共入口的自愈判定后到达)。
# 前置 _require-playwright-test (fail-fast): 守卫失败时立即报环境错误,
# 不烧 fmt/clippy/doc 数分钟才在链尾暴露。
_check-body *ARGS: _require-playwright-test
    just check-fmt
    cargo clippy --locked --all-targets {{ FULL_TIER }} -- -D warnings
    cargo machete
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps {{ FULL_TIER }}
    just check-webui-syntax
    just check-webui-freshness
    just check-contracts
    # doctest: nextest 不跑 doctest 的独立补步 (见上方头注, #357 恢复)
    cargo test --doc --locked {{ FULL_TIER }}
    @if echo "{{ ARGS }}" | grep -q -- "--coverage"; then \
        cargo llvm-cov clean --workspace; \
        cargo llvm-cov nextest --locked {{ FULL_TIER }} --no-fail-fast --no-report; \
    else \
        cargo nextest run --locked {{ FULL_TIER }} --no-fail-fast; \
    fi
    just typos
    just deny-offline
    just nix-check

# 内嵌 JS 语法检查 (秒级, 阻塞式).
# 从 src/web/index.html 提取 <script>...</script> 块, 用 node --check 验证语法.
# 这类低级语法错误 (未闭合括号/函数嵌套错位) 无法被 cargo 工具链发现; check-webui
# (Playwright) 虽能间接捕获 (页面白屏) 但重 (3 分钟) 且本地 check 主链不含 — CI 侧
# 由 ci-merge.yml 的 path-filtered WebUI step 阻塞 (#355, 仅 WebUI 面变更的 PR 跑),
# P2 nightly 非阻塞全量兜底.
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

# playwright 前置守卫 (私有, check-webui 正主使用的 SSOT):
# PATH 上的 `playwright` 必须支持 `test` 子命令。存在性之外还校验**能力** —
# 用户级 profile 常驻同名 Python 变体 (无 `test` 子命令), 未进 devShell 裸跑
# `just check` 时会抢先解析 (2026-10-18 主工作区实证), 让 freshness 门卫以误导性
# 的 "陈旧 binary 未被拦截" 失败。探针用顶层 help 的命令清单 grep `test` 行:
# 不能用 `playwright test --help` 的退出码 — Python 变体对未知子命令打 stderr
# 后**退出码仍是 0** (实测), 只有命令清单能可靠区分。准确报错 + 修复动作,
# 同 rc=127 前置守卫的先例 (纯 CLI 解析, 不启动浏览器/测试)。
# 注意: check-webui-freshness 不经本守卫 — 它是阻塞 check 链成员, 对裸 shell
# 有 WARN+跳过的降级孪生判定 (见该 recipe 头注, 2026-10-20); 本守卫保持硬失败
# (check-webui 正主的存在意义就是跑 Playwright, 裸 shell 失败给出准确指引是对的)。
_require-playwright-test:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v playwright >/dev/null 2>&1; then
        echo "check-webui: playwright CLI 不在 PATH (需 devShell 或 vm-nix runner)" >&2
        exit 1
    fi
    if ! playwright --help 2>&1 | grep -qE '^  test '; then
        echo "check-webui: PATH 上的 playwright 无 test 子命令 (疑似 Python 变体抢占解析): $(command -v playwright)" >&2
        echo "  需 devShell 的 playwright-test — 用 nix develop --impure -c bash -c 'just check' 运行" >&2
        exit 1
    fi

# WebUI freshness 门卫的行为钉子 (#314, 秒级, 阻塞式).
#
# 守护对象: tests/webui/playwright.config.ts 的 freshness 门卫与 resolveSgBin 候选选择
# (判定语义 + 事故背景 + CI 三档分析见其头部注释, 此处不重复).
#
# 两个场景, 与真实 target/ 完全隔离 (假 CARGO_TARGET_DIR + 假 binary, 不触发重编):
#   1. 拦截: 全部候选陈旧 (mtime 2000-01-01) → config 加载应 throw 且消息含 "freshness 门卫".
#   2. 选最新: debug 新 + release 旧 → resolveSgBin 应命中 debug 且门卫通过 (回归守卫:
#      P0/P2 共享持久卷下 P0 的 debug 旧产物不得压过更新候选 — #314 review 发现的潜伏缺陷).
# `--list` 只加载 config 不跑测试/webServer, 秒级返回.
#
# 前置能力检测与 `_require-playwright-test` 同源 (命令清单 grep — Python 变体退出码
# 不可信), 但**不经 recipe 依赖**: 本 recipe 是阻塞 check 链成员, 裸 shell (用户 profile
# 的 Python 变体 playwright 抢占 PATH — 2026-10-20 主工作区实证) 下 WARN+跳过而非硬失败,
# 让裸 shell `just check` 可完整跑通 — 与 7760d3d (fmt 钉 config 防裸 shell 假失败) 和
# check-fmt 的 runner 降级同型。CI (CI=true, vm-nix 契约 playwright-test 恒在) 与 devShell
# 内**阻塞语义不变**: 缺失即真故障, 硬失败。check-webui 正主仍走 _require-playwright-test
# 硬守卫 (跑 Playwright 是其存在意义)。
check-webui-freshness:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v playwright >/dev/null 2>&1 \
       || ! playwright --help 2>&1 | grep -qE '^  test '; then
        if [ "${CI:-}" != "true" ]; then
            echo "check-webui-freshness: WARN — 本环境无 playwright-test ($(command -v playwright 2>/dev/null || echo 'PATH 无 playwright')), 跳过 freshness 钉子" >&2
            echo "  (CI/devShell 内完整执行; 完整链: nix develop --impure -c bash -c 'just check')" >&2
            exit 0
        fi
        echo "check-webui-freshness: FAILED — CI 环境缺 playwright-test (vm-nix 契约被破坏?)" >&2
        exit 1
    fi
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    # 假 binary 内容无关紧要 — 两个场景都在 config 加载期结束, binary 从未真正执行.
    make_fake_bin() { # $1=dir $2=mtime
        mkdir -p "$1"
        printf '#!/bin/sh\n' > "$1/secret-guard"
        chmod +x "$1/secret-guard"
        touch -d "$2" "$1/secret-guard"
    }
    # ── 场景 1: 全部候选陈旧 → 拦截 ──
    make_fake_bin "$tmp/release" '2000-01-01'
    set +e
    out=$(cd tests/webui && CARGO_TARGET_DIR="$tmp" playwright test --list 2>&1)
    rc=$?
    set -e
    # fail-closed: 未拦截 (rc=0) 或拦截了但不是 freshness 原因 (关键词缺失) 都算门卫失效.
    if [ "$rc" -eq 0 ] || ! printf '%s' "$out" | grep -q 'freshness 门卫'; then
        echo "check-webui-freshness: FAILED — 陈旧 binary 未被拦截 (rc=$rc)" >&2
        printf '%s\n' "$out" | tail -20 >&2
        exit 1
    fi
    # ── 场景 2: debug 新 + release 旧 → 命中 debug, 门卫通过 ──
    make_fake_bin "$tmp/debug" 'now'
    set +e
    out=$(cd tests/webui && CARGO_TARGET_DIR="$tmp" playwright test --list 2>&1)
    rc=$?
    set -e
    if [ "$rc" -ne 0 ] || ! printf '%s' "$out" | grep -qF "$tmp/debug/secret-guard"; then
        echo "check-webui-freshness: FAILED — 未命中最新候选 debug (rc=$rc)" >&2
        printf '%s\n' "$out" | tail -20 >&2
        exit 1
    fi
    echo "webui-freshness: OK (陈旧 binary 被拦截 + 最新候选被选中)"

# WebUI 回归测试 (Playwright 端到端). 需 devShell (nix develop).
#
# 三道防线 (缺一不可) 详见 tests/webui/playwright.config.ts 头部注释;
# 本 recipe 实现防线 #2: 在 playwright test 之前清掉端口 18790/19999 上的孤儿.
# 另有 freshness 门卫 (被测 binary 新鲜度, 事故 #314): config 加载期拦截,
# 本 recipe 无需配合 — 门卫在 playwright test 进程内自然生效.
#
# 为什么用 lsof + kill 而非 pkill -f 'secret-guard run --port ...':
# pkill -f 会匹配 justfile 自己 / 父 shell / nix develop 进程 (它们的命令行也含该字串),
# 自杀卡死. lsof 按 listening socket 反查 PID, 不误伤. (CI runner microvm 不主动 kill
# job 子进程, 上次 run 异常退出留下的孤儿会持续 listening, 触发 EADDRINUSE.)
check-webui: _kill-orphans _require-playwright-test
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
# CI 侧 WebUI 定位 (#355 后): P0 ci-merge 有 path-filtered 阻塞 step (src/web /
# src/dag / src/dto.rs / tests/webui 变更的 PR 才跑, 一次重试缓冲 flake), P2 nightly
# 非阻塞全量兜底 (continue-on-error, flake 次晚自愈).
# 本地 check 主链不含 Playwright — 改动上述路径时用本 recipe 保持 "本地全绿 ⇒ CI
# 必绿"; 其他路径的 PR 不触发 P0 WebUI step, `just check` 即与 CI 门禁面等价.
check-all: check _kill-orphans
    cd tests/webui && playwright test

# org ci 契约 recipe (阻塞级门禁入口, 见 lc-studio/forgejo-actions README「CI 分级」)。
# v3.0 三档: 本仓 thin 形态 (SSOT 骨架 + 本地 skip-if-passed action), 质量链拆三档 —
#   P0 ci-merge    (ci-merge.yml)   合入时刻: check 主链 (全量档) + nix 语法门禁 + file-size
#                      + WebUI Playwright path-filtered 阻塞 step (#355, workflow 层独立
#                      step — 本 recipe 不含, 与 file-size 的 stage 拆分同理)
#   P1 ci-deploy   (ci-deploy.yml)  部署时刻: audit + bench 基线 (nix build 留 workflow 层)
#   P2 ci-periodic (ci-periodic.yml) 周期兜底: check --coverage + coverage-gate
# stage 语义 (CI 编排与本地复现逐段等价、无重复执行):
#   all (默认, 本地) = 主链 (just check, 全量档含 consistency 断言) + file-size
#                      —— "本地全绿 ⇒ CI 阻塞项必绿" 的锚点在本档
#   main (CI gate)   = 仅 check 主链 (file-size 由 workflow 独立 step 执行,
#                      Diagnose 表按 step 定位失败)
ci-merge *stage:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ stage }}" in
      main) just check ;;
      ""|all) just check; just check-file-size ;;
      *) echo "ci-merge: 未知 stage '{{ stage }}' (main | all)" >&2; exit 2 ;;
    esac

# org ci 契约 P1 (部署门禁档, ci-deploy.yml 调用): audit (CVE) + bench compare-save
# (判回归 + 滚动更新基线, 退化 exit 1 → run 红)。v3.0 政策变化: audit 由旧单 workflow
# 的 continue-on-error 非阻塞转 P1 阻塞 ("红 = 不能部署" 是本档职责; 旧非阻塞理由
# "不阻塞 PR 合并" 在 P1 不再适用)。
# nix build cargoHash 验证留 workflow 层且为 canary 探针 (continue-on-error — runner
# 无 nix-daemon 恒失败, 转绿即 runner 具备 nix 能力, 届时转阻塞); 本地近似复现:
# just audit / just bench-ci compare-save /
# nix --extra-experimental-features "nix-command flakes" build .#secret-guard -L
ci-deploy:
    just audit
    just bench-ci compare-save

# org ci 契约 P2 (周期兜底档, ci-periodic.yml 调用, 非超集): coverage 防倒退
# (插桩测试 + 双阈值门禁)。WebUI Playwright 留 workflow 独立 step (本档 continue-on-error,
# flake 不打断兜底 run — 与 P0 的 path-filtered 阻塞 step (#355) 分工: P0 守 PR 合入时刻,
# 本档全量兜底含 push 后的 master); 本地全量复现: just ci-periodic && just check-webui。
ci-periodic:
    just check --coverage
    just coverage-gate

# 仅 fmt: treefmt 全仓格式化 (nix/rust/toml/py; 配置 SSOT = 根 treefmt.toml).
# 仅想格式化 rust 时手动 `cargo fmt` 亦可 (edition 一致, 输出等价).
# --config-file 必须显式钉死: 本机系统 profile 的 treefmt 是 wrapper, 会强制注入
# 个人全局配置 (--config-file 覆盖项目配置, 含 prettier/alejandra, 把 md/nix 重写掉);
# 显式传参在后即胜出 (clap last-wins), 裸 shell 由此回到项目配置 (2026-10-19 事故).
fmt:
    treefmt --config-file treefmt.toml

# 格式门禁: treefmt (格式范围同上方 fmt recipe 的括注). CI runner VM 未预装
# treefmt 时降级为 cargo fmt --check (仅 rust) + WARN — VM 预装
# treefmt/nixfmt/taplo/ruff 后删除降级分支 (lc-studio/nixos#1048);
# 降级窗口内 .nix/.toml/.py 的格式漂移不被 CI 拦, 记得本地跑 just fmt.
check-fmt:
    @if command -v treefmt >/dev/null 2>&1; then treefmt --config-file treefmt.toml --fail-on-change; else \
        echo "WARN: treefmt 未安装, 降级为 cargo fmt --check (仅 rust 格式门禁; 全量门禁见 lc-studio/nixos#1048)"; \
        cargo fmt -- --check; \
    fi

# 仅 clippy (全量档, 与 check 主链同档; 默认档验证归 GitHub 镜像 CI).
clippy:
    cargo clippy --locked --all-targets {{ FULL_TIER }} -- -D warnings

# 仅 test (全量档, 与 check 主链同档; 默认档验证归 GitHub 镜像 CI).
test:
    cargo nextest run --locked {{ FULL_TIER }} --no-fail-fast

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

# 覆盖率摘要 (终端表格). 全量档 (--features oidc, 与 check --coverage 同档).
coverage:
    cargo llvm-cov nextest --locked {{ FULL_TIER }} --no-fail-fast --no-report
    cargo llvm-cov report --summary-only

# 覆盖率门禁 (CI 用): 双阈值, 任一不满足则非零退出.
# 前置: check --coverage 已产出 profdata 到 target/llvm-cov-target/. 本 recipe 只做 report.
# 阈值语义见上方 COVERAGE_MIN_LINES / COVERAGE_MAX_UNCOVERED 注释.
coverage-gate:
    cargo llvm-cov report --summary-only \
      --fail-under-lines {{ COVERAGE_MIN_LINES }} \
      --fail-uncovered-lines {{ COVERAGE_MAX_UNCOVERED }}

# HTML 报告 (浏览器打开 coverage/html/index.html). 全量档 (同 coverage).
coverage-html:
    cargo llvm-cov nextest --locked {{ FULL_TIER }} --no-fail-fast --no-report
    cargo llvm-cov report --output-dir coverage --html
    @echo "HTML report: coverage/html/index.html"

# LCOV 报告 (CI / IDE 集成). 全量档 (同 coverage).
coverage-lcov:
    mkdir -p coverage
    cargo llvm-cov nextest --locked {{ FULL_TIER }} --no-fail-fast --lcov --output-path coverage/lcov.info
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
# 三模式设计:
#   - mode=save          (本地):  `--save-baseline ci` — 纯更新基线, 不判定.
#   - mode=compare       (本地):  `--baseline ci`      — 只对比不覆盖. 基线缺失
#     (冷启动) 时 criterion panic, 本 recipe 先检测基线目录是否存在, 缺失则
#     fallback 到 save 模式建立首基线 (第一次跑无历史可对比, 属正常).
#   - mode=compare-save  (CI, ci-deploy.yml 调用): `--save-baseline ci` — criterion
#     对该 flag 的输出仍含 vs 旧基线的 change 行, 故判回归与滚动更新一步完成;
#     退化 exit 1 → ci-deploy run 红 (P1 "红 = 不能部署" 信号). 冷启动 fallback 同 compare.
#
# 退化判定逻辑 (解析 criterion stdout):
#   每个场景输出 `change: time:   [lo% med% hi%] (p = x.xx …)` 行. 双门槛:
#     - med > +REGRESSION_THRESHOLD (默认 20%) **且** p ≤ 0.05: 标记回归, 收集进
#       报告, 最终 exit 1.
#     - 否则: 视为正常波动. p 门槛吸收系统性环境噪声: --quick 10 samples 下单场景
#       波动 p>0.05 是常态; 更重要的是同物理宿主上并发的姊妹 runner VM CI job 会
#       造成全场景一致膨胀 10~25% (2026-09-17 事故: 手动重跑的 ci-merge 与 ci-deploy
#       的 bench 窗口重叠, 宿主 CPU 争抢让 6 场景全部 +7~24%, criterion 自判全部
#       "No change in performance detected" (p>0.05), 但纯 med 判定误报红灯).
#       真 20%+ 退化在 10 samples 下 p 几乎必 < 0.05, 该门槛不损灵敏度.
#
# 输出契约 (供 CI 消费):
#   - stdout:  criterion 原始输出 + 末尾的回归判定摘要 (如有).
#   - exit 0:  无回归 (或基线冷启动).
#   - exit 1:  至少一个场景中位数退化超阈值且统计显著 (p ≤ 0.05).
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
    if [ "$ACTION" = "save" ] || [ "$ACTION" = "compare-save" ]; then
        if [ "$ACTION" = "compare-save" ] && ! baseline_exists; then
            # 冷启动: 无旧基线可判回归, fallback 纯建立. 不算回归.
            echo "bench-ci: 基线 '$BASELINE_NAME' 不存在 (冷启动), 本次仅建立基线不判定回归." >&2
            ACTION="save"
        fi
        BENCH_FLAG="--save-baseline $BASELINE_NAME"
    elif [ "$ACTION" = "compare" ]; then
        if baseline_exists; then
            BENCH_FLAG="--baseline $BASELINE_NAME"
        else
            # 冷启动: 第一次跑无基线可对比, fallback 建立. 不算回归.
            echo "bench-ci: 基线 '$BASELINE_NAME' 不存在 (冷启动), 本次仅建立基线不判定回归." >&2
            BENCH_FLAG="--save-baseline $BASELINE_NAME"
            ACTION="save"
        fi
    else
        echo "bench-ci: 未知 mode '$ACTION' (应为 save / compare / compare-save)" >&2
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

    # compare-save (ci-deploy): 上方 --save-baseline 已滚动更新基线, 此处只补一行
    # 说明 (退化判定走下方公共路径, 退化时 exit 1 → run 红).
    [ "$ACTION" = "compare-save" ] && echo "bench-ci: 基线 '$BASELINE_NAME' 已滚动更新 (compare-save)."

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
                # 显著性门槛: change 行尾 "(p = 0.10 > 0.05)". p > 0.05 时 criterion
                # 自判 "No change in performance detected" — 同宿主并发 CI job 的
                # 系统性负载膨胀 (全场景 +10~25%) 不判退化 (2026-09-17 误报复盘,
                # 详见 recipe 头注). p 解析失败按 p=0 (显著) 处理 — 保持旧行为,
                # criterion 输出格式漂移不会让门禁静默放水.
                p = 0
                if (match($0, /\(p = [0-9.]+/)) p = substr($0, RSTART+5, RLENGTH-5) + 0
                if (med > thr && p <= 0.05) printf "%s: +%d%% (p=%.2f)\n", bench, med, p
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
#   2. docs/ci.md "CI 流程" step 清单条数 == .forgejo/workflows/ci-merge.yml 实际 `- name:` 数.
#      (ci.md 另有若干背景性 step 提及, 不在编号清单内, 故只对齐编号清单.)
# 扫描面: docs/research/ 不在扫描范围 — 外部仓库调研笔记 (cc-switch 等), 其
#   `.rs::symbol` 引用指向外部代码库的文件, 对本仓恒 false positive (#357 挂宿主
#   时划定; 调研笔记是 point-in-time 存档, 无漂移维护义务).
# 非阻塞定位: 独立 recipe, 不进 `just check` 链 (文档漂移不拦编译, 且 symbol 字面匹配
# 对 重命名/宏生成 有已知误报面 — 人工 triage 后再决定是否升级). 与 #144 (traceability
# lint, property→测试) 互补: 本检查管 文档→符号/step.
# 宿主: forgejo P2 ci-periodic 的 advisory step (continue-on-error, #357) — 此前
# 无任何自动宿主 (inert guard), 现由 nightly 兜底可见.
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
    done < <(rg --no-messages -o --no-filename -g '*.md' -g '!docs/research/**' \
      '[A-Za-z0-9_/.-]+\.rs::[A-Za-z0-9_]+' AGENTS.md docs src 2>/dev/null | sort -u)
    # --- 2. ci.md step 清单 == ci.yml 实际 step 数 ---
    # grep -c 零匹配时 exit 1 + 输出 0 (pipefail 会让脚本在此非零退出, 属 fail-closed,
    # 但零匹配更可能是 awk 锚点失效 — 加诊断再退出).
    md_steps=$(awk '/^## CI 流程/,/^> \*\*流程顺序原则/' docs/ci.md | grep -cE '^[0-9]+\. \*\*' || true)
    yml_steps=$(grep -cE '^\s*- name:' .forgejo/workflows/ci-merge.yml || true)
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
#   R0-b (#354): property 名基线 (docs/design/contracts.prop-baseline, 一行一名,
#       # 开头注释行允许) 单向比对 — 基线有而扫描面无 → 报错: 曾登记的行退出扫描面
#       (缩进/表格化/改名/删除) 须显式同步基线 (`just update-contracts-baseline`
#       重生成后随 PR 提交). 新增方向不比对: 新增行已有 R1-R3 标注校验把关,
#       强制登记徒增 PR 摩擦; 同名跨段引用合法 (现存 prop_internal_url_404_no_forward
#       ×2), 基线存 sort -u 名单而非行计数.
#   R1: property 行缺三种标注之一 → 报错.
#   R2: ✅ 行但 property 名零命中 → 报错 (假 ✅).
#   R2-b (#354): ✅ 行但 property 名在 ignored 名单 → 报错 — #[ignore] 的测试不
#       运行, 不构成 "同名落地" (转正/换运行载体, 或改 ⏳).
#   R3: 🔁 行但任一锚点零命中 → 报错 (指向不存在的测试 = 双重幻影). 锚点在 *.rs
#       内的命中须为非注释行 (#354: 防 "写行注释伪造 🔁") — 豁免 `Foo::bar` 符号
#       路径与 `#[...]` 属性字面两类锚点: 其合法命中面含 rustdoc intra-doc 链接,
#       行级注释过滤会误伤 (现存锚点 `SecretEntry::validate_and_resolve` 仅 doc 命中).
#   R3-b (#354): 🔁 锚点在 ignored 名单 → 报错 (指向 #[ignore] 载体 = 非运行载体);
#       例外: 标注行含 `#[ignore` prose 声明时豁免 — 明示 "该载体未落地" 的说明形态.
#   R4 (#354): 标注行 prose 含 `#[ignore` 声明, 但行内反引号串无一在 ignored 名单
#       → 报错 — 声明过时 (所点载体实际已转常驻; 升格进锚点列表并清理 prose).
#       载体日后转正常驻时本规则变红, 提示同步 — 声明与事实双向锁死.
# 已知豁免面 (机械 lint 无法覆盖, 由 review + 计数公开兜底):
#   - 泛串锚点 (如 `fn`) 字面可命中 — 锚点应写具体测试名, review 时核对.
#   - ⏳ 免检 — 但计数在输出公开 + §0.6 优先级表追踪, 滥用会立刻可见 (⏳ 数暴增).
#   - ignored 名单的识别窗口: `#[ignore` **非注释**属性行下方 3 行内的 fn 名 (常见
#     排布 #[test]/#[ignore]/fn 与 #[tokio::test]/#[ignore]/async fn 均在窗口内;
#     属性与 fn 间隔 >3 行的极端排布不识别 — 误收风险为零, 漏识别由 review 兜底).
#     .ts 载体 (Playwright) 无 Rust ignore 语义, 天然不进名单.
# 扫描范围: src/ tests/ (*.rs/*.ts) + justfile + .forgejo/workflows/ci-merge.yml
# (后两处覆盖 CI step / recipe 类锚点, 如 VIEW-1 的 consistency-check step).
# 工具: 纯 bash+grep+sed (runner VM corePackages, 无 rg 依赖 — 区别于 check-docs
# 的 rg; 本检查进 `just check` 阻塞链, 必须在 CI runner 可运行).
# 自测方式: 删任一行的标注 → 本 recipe 红; 恢复 → 绿. #354 各规则的红灯证明
# 矩阵 (master 现状 R4 红 / R0-b/R2-b/R3-b/注释过滤构造红) 见对应 PR 描述.
check-contracts:
    #!/usr/bin/env bash
    set -euo pipefail
    md=docs/design/contracts.md
    baseline=docs/design/contracts.prop-baseline
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
    # R0-b (#354): 基线单向比对 (基线 ⊆ 扫描面) — 单条行缩进/表格化会静默退出
    # 扫描面而 R0 只拦 "全归零", 基线补上这个缺口. 基线文件缺失 = 门禁被物理移除,
    # 同样 fail-closed. 比对用 sort -u 名单 (同名跨段引用合法, 行计数会误报).
    if [ ! -f "$baseline" ]; then
      echo "::error::check-contracts: $baseline 不存在 (基线机制被移除? 退出面防护失效, 需恢复)."
      exit 1
    fi
    while IFS= read -r p; do
      fail "R0-b: 基线有而扫描面无: $p — 行被缩进/表格化/改名/删除? 确认合法后 just update-contracts-baseline 重生成并随提交更新"
    # LC_ALL=C 必须显式钉在 comm 上: 两侧输入是 C-collation 排序, comm 默认用
    # 运行环境 locale 比对 — 非 C locale (如 CI runner 的 en_US.UTF-8) 下会判
    # "not in sorted order" 并产出假差异 (2026-10-20 #375 CI 假红实例).
    done < <(LC_ALL=C comm -13 \
      <(grep -E '^- `prop_' "$md" | sed -n 's/^- `\(prop_[a-z0-9_]*\)`.*/\1/p' | LC_ALL=C sort -u) \
      <(grep -vE '^#|^$' "$baseline" | LC_ALL=C sort))
    # ignored 载体名清单 (#354, R2-b/R3-b/R4 共用): 全仓 `#[ignore` 非注释属性行
    # 下方 3 行内的 fn 名. 全仓属性行仅个位数, 一次预扫描后一切 membership 判定
    # 退化为字符串比较 — 不逐 property 再扫全仓. 注释行提及 `#[ignore` 的 (如
    # integration.rs 的说明注释) 被非注释过滤排除, 不会误收其下方函数.
    ignored_names=""
    while IFS= read -r il; do
      f=${il%%:*}; l=${il##*:}
      fn_name=$(sed -n "$((l+1)),$((l+3))p" "$f" | grep -oE 'fn +[a-zA-Z0-9_]+' | head -1 | sed 's/fn *//')
      [ -n "$fn_name" ] && ignored_names="$ignored_names$fn_name"$'\n'
    done < <(grep -rn --include='*.rs' -F '#[ignore' src tests 2>/dev/null \
      | grep -vE ':[0-9]+:[[:space:]]*//' | cut -d: -f1,2)
    # membership 判定 (纯字符串, 零进程): 每名以 \n 结尾, "*$s\n*" 模式保证整名匹配
    # (foo 不会命中 foobar 行).
    in_ignored() { case "$ignored_names" in *"$1"$'\n'*) return 0 ;; *) return 1 ;; esac; }
    # grep -w 用 _ 作为 word 字符, prop_xxx 名天然是完整 word (不会被更长名误命中).
    # 测试载体过滤: 命中行须含 "fn <name>" (Rust) 或 "test(\"...<name>...\", async"
    # (Playwright 标题; name 紧跟 test( 亦可) 定义形态, 排除纯注释 (/// doc / // 行)
    # 的同名提及 — 只在注释里写一遍 property 名不构成 ✅ 落地.
    hit_word() {
      grep -rw --include='*.rs' --include='*.ts' -e "$1" src tests 2>/dev/null \
        | grep -qE "(fn +$1|test\([^\"]*$1|$1[^\"]*\", *async)"
    }
    # 锚点固定串匹配: 不限文件类型 (justfile / ci.yml 无后缀匹配需求), grep -F 字节级.
    # #354 加固: *.rs 内命中须为非注释行 (防 "写行注释伪造 🔁"); 豁免 `Foo::bar`
    # 符号路径与 `#[...]` 属性字面锚点 — 其合法命中面含 rustdoc intra-doc 链接
    # (doc 注释形态), 行级注释过滤会误伤 (见 recipe 头注 R3). .rs 外保持 #144 语义.
    hit_anchor() {
      case "$1" in
        *'::'*|'#['*)
          grep -rqF -- "$1" src tests justfile .forgejo/workflows/ci-merge.yml 2>/dev/null
          return
          ;;
      esac
      # .rs 非注释命中判定用命令替换而非管道尾 grep -q (pipefail 下 -q 提前退出
      # 会让上游 grep 收 SIGPIPE → exit 141 → 假阴性 flake).
      if [ -n "$(grep -rnF --include='*.rs' -e "$1" src tests 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*//')" ]; then
        return 0
      fi
      grep -rqF --exclude='*.rs' -e "$1" src tests 2>/dev/null && return 0
      grep -qF -- "$1" justfile .forgejo/workflows/ci-merge.yml 2>/dev/null
    }
    # 🔁 行的全部锚点: 🔁→ 起的每个反引号对, 排除 `路径` 形态 (含 / 或 . 前后缀的
    # 文件引用, 如 `src/redact.rs`); 多锚点全部校验 (L1: 第二锚点漂移也须拦截).
    # 反引号串提取管道与 R4 载体清点共享 (bt_strings).
    bt_strings() { grep -oE '`[^`]+`' | tr -d '`' | grep -vE '/|\.rs$|\.ts$|\.md$|\.yml$' || true; }
    anchors_of() {
      printf '%s' "$1" | sed -n 's/.*🔁→//p' | bt_strings
    }
    while IFS= read -r line; do
      prop=$(printf '%s' "$line" | sed -n 's/^- `\(prop_[a-z0-9_]*\)`.*/\1/p')
      if [ -z "$prop" ]; then continue; fi
      # ── R4 + ignored 载体清点 (#354) ──
      # 行内 `#[ignore` prose 声明须有事实支撑: 行内反引号串 (提取面与 anchors_of
      # 同口径, 排除路径形态) 至少一个真实被 ignore — 否则声明过时 (master 现存
      # 实例: FWD-2 行点名 openai 侧被 ignore, 实际 #284 起已转常驻). 载体日后转正
      # 时本判定变红, 提示升格锚点 + 清理 prose — 声明与事实双向锁死.
      has_ignore_decl=0
      # 注意不能用 case glob 匹配 '#\[' — 引号内反斜杠是字面字符不构成转义;
      # [[ ]] 的 pattern 里引号内 '[' 是字面 → 零进程字面包含判定.
      if [[ "$line" == *"#[ignore"* ]]; then has_ignore_decl=1; fi
      # 🔁 行额外需要载体清点 (R3-b 判定); ✅/⏳ 行只需声明核对本身.
      if [ "$has_ignore_decl" = 1 ] || [[ "$line" == *'🔁'* ]]; then
        n_ignored_carrier=0
        while IFS= read -r s; do
          case "$s" in *'::'*|'#['*) continue ;; esac
          if in_ignored "$s"; then n_ignored_carrier=$((n_ignored_carrier+1)); fi
        done <<< "$(printf '%s' "$line" | bt_strings)"
        if [ "$has_ignore_decl" = 1 ] && [ "$n_ignored_carrier" -eq 0 ]; then
          fail "$prop: R4: prose 提及 #[ignore] 但行内反引号串无一真实被忽略 — 声明过时 (载体已转常驻则升格进锚点列表并清理 prose)"
        fi
      fi
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
            # R3-b (#354): 锚点指向 ignored 载体 = 非运行载体 (幻影锚点变体);
            # 行带 #[ignore] prose 声明时豁免 — "该载体未落地"的明示说明形态
            # (R4 已锁死声明 ↔ 事实一致, 豁免不会被滥用为假落地).
            if in_ignored "$anchor"; then
              if [ "$has_ignore_decl" = 1 ]; then continue; fi
              bad_anchor="$anchor (指向 #[ignore] 载体, 非运行载体)"
              break
            fi
            hit_anchor "$anchor" || { bad_anchor="$anchor"; break; }
          done <<< "$anchors"
          if [ -z "$anchors" ]; then
            fail "$prop: 🔁 标注缺锚点 (格式: 🔁→\`实际测试名\`)"
          elif [ -n "$bad_anchor" ]; then
            fail "$prop: 🔁 锚点 '$bad_anchor' 在 src/+tests/+justfile+ci.yml 零命中或被 #[ignore] (幻影锚点?)"
          else
            n_renamed=$((n_renamed+1))
          fi
          ;;
        *'✅'*)
          if ! hit_word "$prop"; then
            fail "$prop: 标 ✅ 但同名测试零命中 — 改名落地应用 🔁→\`实际名\`, 真零测试用 ⏳"
          elif in_ignored "$prop"; then
            # R2-b (#354): #[ignore] 的测试不运行, 字面存在不等于落地.
            fail "$prop: R2-b: 标 ✅ 但载体被 #[ignore] — 转正/换运行载体, 或改 ⏳"
          else
            n_ok=$((n_ok+1))
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
    echo "check-contracts: ✓ $n_lines 条全量标注有效 (基线 $(grep -cvE '^#|^$' "$baseline") 名无退出) — ✅ 同名 $n_ok / 🔁 改名 $n_renamed / ⏳ 待补 $n_pending (优先级见 contracts.md §0.6)."

# 重生成 contracts property 名基线 (check-contracts R0-b 消费, #354).
# 何时运行: 故意变更 property 行集合 (删除/改名/缩进化退出扫描面) 后, 重生成并
# 随同一提交更新 — review 时基线 diff 即 "property 集合变化" 的显式声明.
# 新增 property 行无需动基线 (R0-b 单向比对, 见 check-contracts 头注).
# 头注释在本 recipe 内维护 (重生成永远保留, 文件自身可解释).
update-contracts-baseline:
    #!/usr/bin/env bash
    set -euo pipefail
    {
      echo '# contracts.md property 名基线 — check-contracts R0-b 单向比对消费 (#354)'
      echo '# 生成: just update-contracts-baseline (从 docs/design/contracts.md 顶格 property 行提取, sort -u)'
      echo '# 语义: 基线有而扫描面无 → lint 红 (行被缩进/表格化/改名/删除须显式同步); 新增行无需登记'
      echo '# 允许本形态的 # 注释行; 一行一个 property 名'
      grep -E '^- `prop_' docs/design/contracts.md | sed -n 's/^- `\(prop_[a-z0-9_]*\)`.*/\1/p' | LC_ALL=C sort -u
    } > docs/design/contracts.prop-baseline
    echo "baseline: $(grep -cvE '^#|^$' docs/design/contracts.prop-baseline) 名 → docs/design/contracts.prop-baseline"

# nix 侧验证: ① 全量 .nix parse 冒烟 (镜像 CI Nix syntax gate) + ② render 契约测试
# 与模块 eval 冒烟 (flake checks 的轻量子集 — runCommand/python3/writeText, 不含
# secret-guard 的 Rust 编译闭包, 秒级)。挂在 just check 链尾; src serde schema
# 变更时 ② 先红。
#
# ① parse 冒烟 — 本地↔CI 等价性修复 (#357 反例窗口): CI 的 Nix syntax gate
# (ci-merge.yml) 对 .nix 做 nix-instantiate --parse (PR 事件查变更集, push master
# 全量); 而 nix/release.nix 仅被 packages.release 惰性 import, ② 的两闭包均不含 →
# release.nix 语法错误曾是 "本地绿 / CI 红"。本地恒走全量扫描 (任何变更集的超集;
# org 仓 .nix 数量级小, 成本毫秒级), NIX_STATE_DIR 重定向与 CI 同型 — parse 纯解析
# 零求值零 store 写无需 daemon (CI runner ro store 也能跑), 但 nix 启动仍初始化
# state dir 写 temproots, 重定向到私有 tmp 避免依赖 /nix/var/nix 可写; env 前缀
# 按命令作用域限定, 不影响 ② 走真实 daemon socket。无 nix-instantiate 的环境
# 打印 notice 跳过 (与 ② 的 daemon 探测跳过同型, fail-safe)。
#
# ② --extra-experimental-features: 环境 (如 CI runner 的 Lix) 未启用
# nix-command/flakes 时自包含可跑; 本地已启用时重复传无害.
# nix-daemon 探测跳过: CI runner VM 架构禁止 nix 求值 (无 writableStoreOverlay /
# 无 daemon, 见 forgejo-runner-vm.mod.nix「CI 工具链规范」), 探测到无 daemon socket
# (NIX_DAEMON_SOCKET_PATH 默认路径, systemd socket-activation 按需拉起) 时打印
# notice 跳过而非失败 — serde 漂移的 CI 门禁因此不可行, 由本地纪律承担.
nix-check:
    #!/usr/bin/env bash
    set -euo pipefail
    # ① 全量 .nix parse 冒烟 (镜像 CI Nix syntax gate, 语义/输出同构)
    if ! command -v nix-instantiate >/dev/null 2>&1; then
        echo "nix-check: skip parse 冒烟 — PATH 无 nix-instantiate (环境无 nix?)"
    else
        state="$(mktemp -d)"
        status=0; n=0
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            n=$((n+1))
            # stderr (错误定位: 文件+行列) 原样透传供诊断, stdout (parse AST dump) 丢弃 — 同 CI gate
            if ! NIX_STATE_DIR="$state" nix-instantiate --parse "$f" >/dev/null; then
                echo "✗ $f: nix 语法错误"
                status=1
            fi
        done < <(git ls-files -- '*.nix')
        rm -rf "$state"
        # fail-closed: 0 个文件 = git ls-files 失效或锚点漂移 (本仓恒有 13+ 个 .nix),
        # 空清单静默假绿会让本门禁形同虚设 — 同 check-docs 的 step=0 防护。
        if [ "$n" -eq 0 ]; then
            echo "nix-check: parse 冒烟扫到 0 个 .nix (git ls-files 失效?) — 拒绝假绿" >&2
            exit 1
        fi
        if [ "$status" -ne 0 ]; then exit 1; fi
        echo "✓ nix parse 冒烟通过 ($n 个 .nix)"
    fi
    # ② flake checks 两闭包 (需 daemon)
    if [ ! -S /nix/var/nix/daemon-socket/socket ]; then
        echo "nix-check: skip checks 闭包 — 无 nix-daemon (CI runner 架构禁止 nix 求值), 本地 just check 全量覆盖本项"
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
