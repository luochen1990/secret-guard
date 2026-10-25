#!/usr/bin/env bash
# scripts/bench-ci.sh — CI 性能回归检测 (criterion baseline 机制) 的逻辑 SSOT.
#
# 职责边界: criterion 基线的三模式编排 (save / compare / compare-save) + 判红快照回滚
# + 判红 issue upsert + `selftest` 自测子命令。本文件从 justfile `bench-ci` recipe
# 原样搬家而来 (#400, 逻辑零改动 — recipe 改为一行委托), 搬家动机 = 让回滚守卫可自测。
#
# 消费方: justfile `bench-ci` (一行委托) / `bench-ci-selftest` recipe; CI 侧
# ci-deploy.yml (经 `just ci-deploy` → `just bench-ci compare-save`, 以及 Quality gate
# 前置的 `just bench-ci-selftest` step)。
#
# ── 机制 (基于实测, 纠正 "criterion 退化会 exit 非零" 的常见误解) ──
#   criterion 即使检测到显著退化也永远 exit 0 (仅基线缺失时 panic exit 101).
#   因此本脚本自行解析输出, 按中位数变化率判定回归, 超阈值则 exit 1.
#
# 三模式设计:
#   - mode=save          (本地):  `--save-baseline ci` — 纯更新基线, 不判定.
#   - mode=compare       (本地):  `--baseline ci`      — 只对比不覆盖. 基线缺失
#     (冷启动) 时 criterion panic, 本脚本先检测基线目录是否存在, 缺失则
#     fallback 到 save 模式建立首基线 (第一次跑无历史可对比, 属正常).
#   - mode=compare-save  (CI, ci-deploy.yml 调用): `--save-baseline ci` — criterion
#     对该 flag 的输出仍含 vs 旧基线的 change 行, 故判回归与测量落盘一步完成;
#     退化 exit 1 → ci-deploy run 红 (P1 "红 = 不能部署" 信号). 冷启动 fallback 同 compare.
#
# 基线策略 — 判红不滚动 (#359 问题一, 2026-10):
#   criterion `--save-baseline` 的执行序是 "先对比旧基线、后无条件覆写基线"
#   (0.8.2 源码: analysis::common 以 <bench>/<baseline>/ 旧内容为对比基准, 收尾
#   copy_new_dir_to_base 把 new/ 覆写回去), 而判红发生在更晚的输出解析 — 不干预
#   则红 run 的退化已成为新基准, 下一次 run 对含退化的基线判绿 (**退化永久成为
#   新常态**). 修复: compare-save 跑前快照基线目录 (cp 到 CARGO_TARGET_DIR 下,
#   不进 criterion/ 树以免干扰其目录遍历), 判红 / bench 失败时回滚快照 (旧基准
#   保留), 仅绿 run 保留滚动. 由此红信号可持续: 修复前的每个 master push /
#   nightly 都对同一旧基准重复判红. 快照 + 回滚 = 两次目录 cp (KB 级), 零额外
#   bench 运行 (对比 "跑两次" 方案省一倍测量时间).
#   辅助: 判红时经 Forgejo API upsert 退化 issue 钉住 (marker
#   `<!-- bench-regression-issue -->`), 触发门 = BENCH_CI_ISSUE=1 + GITHUB_TOKEN
#   (ci-deploy.yml Quality gate step 显式注入, 本地不设即静默跳过), best-effort
#   (API 失败只 WARN, 不吞 exit 1 门禁信号; 修复后人工关 issue, 绿 run 不自动关).
#
# 退化判定逻辑 (解析 criterion stdout):
#   每个场景输出 `change: time:   [lo% med% hi%] (p = x.xx …)` 行. 双门槛:
#     - med > +THRESHOLD (默认 20%) **且** p ≤ 0.05: 标记回归, 收集进
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
# 阈值 SSOT: BENCH_CI_THRESHOLD (百分比, 不带 %, 默认 20). 20% 的依据: --quick 噪声大
#   (实测同机器同负载波动可达 ±15%), 20% 留缓冲只卡量级级退化; 升级到 100 samples
#   后可收紧到 10%.
#
# ── 用法 ──
#   scripts/bench-ci.sh <save|compare|compare-save> [extra...]  正常模式 (跑真 bench,
#       extra 透传 criterion 参数, 如 --quick; 原 justfile recipe 参数面不变)
#   scripts/bench-ci.sh selftest                                自测 (#400, 假 runner
#       替身跑 红/绿/bench失败/冷启动 四场景, 秒级, 不编译不跑真 bench)
#   BENCH_CI_LIB=1 source scripts/bench-ci.sh                   lib 模式: 仅定义函数
#       不执行入口 — 复用函数体并 override 钩子 (如 selftest 覆盖 open_regression_issue
#       断言 "被调用", 不需要真 HTTP mock)
#
# ── 注入点 (selftest 依赖) ──
#   BENCH_CI_RUNNER: 实际执行 bench 的命令覆盖 (默认 "cargo bench --locked --bench
#       redact", 与原 justfile recipe 逐字节同一条调用); selftest 注入假 runner 替身
#       模拟 criterion 的 stdout 输出 / 基线覆写 / 退出码.

THRESHOLD="${BENCH_CI_THRESHOLD:-20}"
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

# ── 基线快照/回滚 (compare-save 专用; 语义见文件头 "基线策略" 段) ──
BASELINE_SNAPSHOT=""
trap '[ -n "$BASELINE_SNAPSHOT" ] && rm -rf "$BASELINE_SNAPSHOT" || true' EXIT
snapshot_baseline() {
    # 快照到 CARGO_TARGET_DIR 下独立目录 (与 criterion/ 同层; 不进 criterion/ 树).
    BASELINE_SNAPSHOT=$(mktemp -d "${CARGO_TARGET_DIR%/}/criterion-baseline-snapshot.XXXXXX")
    local n=0 d rel
    while IFS= read -r d; do
        rel="${d#"$BENCH_DIR"/}"
        mkdir -p "$BASELINE_SNAPSHOT/$(dirname "$rel")"
        cp -a "$d" "$BASELINE_SNAPSHOT/$rel"
        n=$((n+1))
    done < <(find "$BENCH_DIR" -mindepth 3 -type d -name "$BASELINE_NAME" 2>/dev/null)
    # fail-closed: baseline_exists 判真但 find 零命中 = 目录布局假设破裂,
    # 不带快照裸跑会失去判红回滚保证, 必须显式失败.
    if [ "$n" -eq 0 ]; then
        echo "bench-ci: 基线快照失败 (baseline_exists 判真但 find 零命中 '$BASELINE_NAME' 目录) — 目录布局漂移? fail-closed 退出." >&2
        exit 2
    fi
    echo "bench-ci: 已快照 $n 个基线目录 (判红/bench 失败时回滚, 退化不落盘)."
}
rollback_baseline() {
    # 回滚: rm 整目录再拷回 (而非增量覆盖), 防 criterion 落盘文件集变化留残渣.
    # (rm 只删叶子, 父目录必在, 无需 mkdir -p.)
    local d rel
    while IFS= read -r d; do
        rel="${d#"$BASELINE_SNAPSHOT"/}"
        rm -rf "${BENCH_DIR:?}/$rel"
        cp -a "$d" "$BENCH_DIR/$rel"
    done < <(find "$BASELINE_SNAPSHOT" -mindepth 3 -type d -name "$BASELINE_NAME" 2>/dev/null)
    echo "bench-ci: 基线已回滚 — 本次测量不落盘, 旧基准保留 (下一 run 仍对同一旧基准判红)." >&2
}
# ── 判红自动开 issue (辅助, 触发门与 best-effort 语义见文件头) ──
open_regression_issue() {
    local regressions="$1"
    if [ "${BENCH_CI_ISSUE:-}" != "1" ] || [ -z "${GITHUB_TOKEN:-}" ]; then return 0; fi
    if [ -z "${API_BASE:-}" ] || [ -z "${GITHUB_REPOSITORY:-}" ]; then
        echo "bench-ci: WARN 跳过退化 issue upsert (缺 API_BASE/GITHUB_REPOSITORY env)." >&2
        return 0
    fi
    local MARKER='<!-- bench-regression-issue -->' API existing_id PAYLOAD
    API="$API_BASE/repos/$GITHUB_REPOSITORY/issues"
    # upsert (同 ci-merge.yml PR 评论机制): 找带 marker 的 open issue 则 PATCH, 否则 POST.
    existing_id=$(curl -fsSL -H "Authorization: token $GITHUB_TOKEN" "$API?state=open&type=issues" \
        | jq -r --arg m "$MARKER" '.[] | select(.body != null and (.body | contains($m))) | .number' | head -1) || {
        echo "bench-ci: WARN 查询退化 issue 失败 (best-effort, 忽略)." >&2
        return 0
    }
    PAYLOAD=$(jq -n \
        --arg t "bench: 性能退化未处理 (ci-deploy 判红)" \
        --arg b "$MARKER"$'\n\n'"## 退化场景 (med > ${THRESHOLD}% 且 p ≤ 0.05)"$'\n\n'"$(printf '%s\n' "$regressions" | sed 's/^/- /')"$'\n\n'"- run: ${RUN_URL:-未知}"$'\n'"- commit: ${GITHUB_SHA:-未知}"$'\n\n'"基线已回滚 (退化测量未落盘) — 修复前每个 master push / nightly 都会对同一旧基准重复判红. 修复后请手动关闭本 issue." \
        '{title: $t, body: $b}')
    if [ -n "$existing_id" ]; then
        curl -fsSL -X PATCH -H "Authorization: token $GITHUB_TOKEN" -H "Content-Type: application/json" \
            -d "$PAYLOAD" "$API/$existing_id" >/dev/null \
            && echo "bench-ci: 已更新退化 issue #$existing_id (钉住)." \
            || echo "bench-ci: WARN 更新退化 issue 失败 (best-effort, 忽略)." >&2
    else
        curl -fsSL -X POST -H "Authorization: token $GITHUB_TOKEN" -H "Content-Type: application/json" \
            -d "$PAYLOAD" "$API" >/dev/null \
            && echo "bench-ci: 已开退化 issue 钉住 (marker 认领, 重跑不刷屏)." \
            || echo "bench-ci: WARN 开退化 issue 失败 (best-effort, 忽略)." >&2
    fi
}

main() {
    # 归一执行环境: -u + pipefail, **无 -e** (bench 失败靠显式 BENCH_EXIT 判定, errexit
    # 会把 OUTPUT 捕获提前杀死; lib 模式下调用方可能带 -e, 显式归一回 recipe 语义).
    set +e
    set -uo pipefail
    local ACTION="$1"
    shift
    local EXTRA="$*"
    local BENCH_FLAG OUTPUT BENCH_EXIT regressions

    # 模式归一 + criterion flag 选择 (单一出口):
    #   ① 非法 mode → exit 2.
    #   ② compare / compare-save 基线缺失 (冷启动) → 统一 fallback 纯建立
    #      (第一次跑无历史可对比/判定, 不算回归), ACTION 归一为 save.
    #   ③ 按归一后 ACTION 一处选 flag.
    #   ④ compare-save 跑前快照 (criterion 收尾即覆写基线; 冷启动分支无基线可快照).
    case "$ACTION" in
        save|compare|compare-save) ;;
        *)
            echo "bench-ci: 未知 mode '$ACTION' (应为 save / compare / compare-save)" >&2
            exit 2
            ;;
    esac
    if [ "$ACTION" != "save" ] && ! baseline_exists; then
        echo "bench-ci: 基线 '$BASELINE_NAME' 不存在 (冷启动), 本次仅建立基线不判定回归." >&2
        ACTION="save"
    fi
    case "$ACTION" in
        save)         BENCH_FLAG="--save-baseline $BASELINE_NAME" ;;
        compare)      BENCH_FLAG="--baseline $BASELINE_NAME" ;;
        compare-save) BENCH_FLAG="--save-baseline $BASELINE_NAME" ;;
    esac
    [ "$ACTION" = "compare-save" ] && snapshot_baseline

    # 跑 bench, 捕获输出. set +e: cargo bench 退化时仍 exit 0, 但编译/运行错误
    # 会 exit 非 101, 需捕获区分 (退化 vs 真失败).
    # 注入点: BENCH_CI_RUNNER 覆盖实际执行命令 (selftest 假 runner 替身; 默认值与
    # 原 justfile recipe 逐字节同一条 cargo bench 调用).
    local BENCH_CMD="${BENCH_CI_RUNNER:-cargo bench --locked --bench redact}"
    OUTPUT=$($BENCH_CMD -- --quick $BENCH_FLAG $EXTRA 2>&1)
    BENCH_EXIT=$?
    echo "$OUTPUT"
    if [ "$BENCH_EXIT" -ne 0 ]; then
        echo "bench-ci: cargo bench 失败 (exit $BENCH_EXIT), 非退化判定范畴." >&2
        # 回滚: bench 中途失败时 criterion 可能已滚动部分场景的基线 (逐 bench 落盘), 回滚保完整旧基准.
        if [ "$ACTION" = "compare-save" ]; then rollback_baseline; fi
        exit 2
    fi

    # save 模式 (含冷启动 fallback) 不判定回归, 只更新基线.
    if [ "$ACTION" = "save" ]; then
        echo "bench-ci: 基线 '$BASELINE_NAME' 已更新."
        exit 0
    fi

    # compare-save (ci-deploy): 走到这说明 bench 成功 — 基线已被 criterion 覆写为本次测量,
    # 是否保留 (绿) 或回滚 (红) 由下方判定决定.
    [ "$ACTION" = "compare-save" ] && echo "bench-ci: bench 完成, 基线待判 — 退化则回滚快照."

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
                # 详见文件头). p 解析失败按 p=0 (显著) 处理 — 保持旧行为,
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
        # 判红不滚动 (#359): 回滚快照, 退化测量不落盘 — 否则退化成为新常态 (见文件头).
        if [ "$ACTION" = "compare-save" ]; then rollback_baseline; fi
        open_regression_issue "$regressions"
        exit 1
    fi
    # 绿 run: 快照由 trap 清理, criterion 已落盘的本次测量保留为新基线.
    echo "bench-ci: ✓ 无场景退化超 ${THRESHOLD}% 阈值."
    exit 0
}

# ── selftest: 回滚守卫自测 (#400) ──────────────────────────────────────────────
# 背景: 判红回滚逻辑无常驻自测 — 回滚损坏时性能退化会**静默滚动基线** (红信号永久
# 丢失). 四场景 (红 / 绿 / bench 失败 / 冷启动) 用假 runner 替身 (BENCH_CI_RUNNER 注入)
# 不跑真 bench, 秒级; 每场景独立 mktemp -d 作为 CARGO_TARGET_DIR, 经 BENCH_CI_LIB=1
# source 本文件 + bash 函数覆盖 (open_regression_issue spy) 断言判红联动, 不需要真
# HTTP mock。selftest exit 0 = 全过 / 1 = 有失败。

# 场景工作区: $1 = 1|0 (是否预置旧基线); echo 工作区路径 (= 该场景的 CARGO_TARGET_DIR).
# 临时目录优先落 /tmp/opencode (本仓约定), 不可写 (如 CI runner) 回退 /tmp.
st_workspace() {
    local tmpbase="${TMPDIR:-/tmp/opencode}"
    mkdir -p "$tmpbase" 2>/dev/null || tmpbase=/tmp
    local ws
    ws=$(mktemp -d "$tmpbase/bench-ci-selftest.XXXXXX")
    if [ "$1" = 1 ]; then
        mkdir -p "$ws/criterion/redact_ir/small/ci" "$ws/criterion/redact_ir/large/ci"
        printf 'OLD-ESTIMATES-small-v1' > "$ws/criterion/redact_ir/small/ci/estimates.json"
        printf 'OLD-ESTIMATES-large-v1' > "$ws/criterion/redact_ir/large/ci/estimates.json"
    fi
    # 假 runner: 模拟 criterion 的三个可观察行为 (行为由 FAKE_* env 驱动, 场景函数零定制):
    #   ① stdout 打印测量/对比输出 (FAKE_OUT, 含 change 行格式)
    #   ② save-baseline 收尾覆写基线目录 (FAKE_NEW_BASELINE → estimates.json)
    #   ③ 退出码 (FAKE_EXIT; bench 失败场景也先落盘再退出 — criterion 逐 bench 落盘,
    #      中途失败可能已滚动部分基线, 这正是回滚要覆盖的窗口)
    cat > "$ws/fake-runner" <<'RUNNER'
#!/usr/bin/env bash
printf '%s\n' "$FAKE_OUT"
for spec in redact_ir/small redact_ir/large; do
    d="$CARGO_TARGET_DIR/criterion/$spec/ci"
    mkdir -p "$d"
    printf '%s' "$FAKE_NEW_BASELINE" > "$d/estimates.json"
done
exit "${FAKE_EXIT:-0}"
RUNNER
    chmod +x "$ws/fake-runner"
    echo "$ws"
}

# 场景运行器: 隔离子 shell 内 (BENCH_CI_LIB=1) source 本文件 → override spy → main;
# stdout/stderr 落 $ws/out.log; 返回 main 退出码. FAKE_* 须先由场景函数 export.
st_run() { # $1=ws $2=mode
    local ws="$1" mode="$2"
    (
        export CARGO_TARGET_DIR="$ws" BENCH_CI_RUNNER="$ws/fake-runner" BENCH_CI_LIB=1
        # shellcheck disable=SC1090
        source "$ST_SCRIPT"
        # 钩子覆盖 (lib 模式的存在意义): 判红信号联动断言 — open_regression_issue
        # "被调用" 即写 spy 文件, 不需要真 HTTP mock.
        open_regression_issue() { printf 'CALLED' > "$ws/spy"; }
        main "$mode"
    ) >"$ws/out.log" 2>&1
}

# 场景收尾: fails=0 → PASS + 清理现场; 否则 FAIL + 保留现场供诊断.
st_report() { # $1=场景名 $2=fails $3=ws
    if [ "$2" -eq 0 ]; then
        rm -rf "$3"
        echo "PASS $1"
        return 0
    fi
    echo "FAIL $1 ($2 项断言未过; 现场保留: $3)"
    return 1
}

# a. 红路径: 注入已知退化 (med +30.5% > 20%, p=0.01 ≤ 0.05) →
#    ① 基线文件字节不变 (回滚, 未静默滚动) ② exit 1 ③ open_regression_issue 被调用.
st_red() {
    local ws rc fails=0
    ws=$(st_workspace 1)
    cp -r "$ws/criterion" "$ws/pre" # 运行前基线快照 (字节比对基准)
    rm -f "$ws/spy"
    export FAKE_OUT=$'redact_ir/small time:   [1.00 ms 1.00 ms 1.00 ms]\n          change: time:   [+1% +30.5% +60%] (p = 0.01 < 0.05)'
    export FAKE_NEW_BASELINE='NEW-ESTIMATES-v2' FAKE_EXIT=0
    st_run "$ws" compare-save; rc=$?
    [ "$rc" -eq 1 ] || { echo "  ✗ 判红信号应为 exit 1, 实际 $rc"; fails=$((fails+1)); }
    diff -r "$ws/pre" "$ws/criterion" >/dev/null 2>&1 \
        || { echo "  ✗ 基线文件字节与快照前不一致 (判红未回滚 = 退化静默滚动基线)"; fails=$((fails+1)); }
    [ "$(cat "$ws/spy" 2>/dev/null)" = "CALLED" ] \
        || { echo "  ✗ open_regression_issue 未被调用 (issue 钉住联动失效)"; fails=$((fails+1)); }
    grep -q '已回滚' "$ws/out.log" || { echo "  ✗ 输出缺回滚通告"; fails=$((fails+1)); }
    st_report red "$fails" "$ws"
}

# b. 绿路径: 无回归 (med +1.1% < 20%, p=0.35) → exit 0 + 基线正常滚动
#    (runner 落盘的新测量字节存活 — save 语义未被回滚误伤) + issue 钩子
#    **不被调用** (与红场景的 spy 断言对称).
st_green() {
    local ws rc fails=0
    ws=$(st_workspace 1)
    export FAKE_OUT=$'redact_ir/small time:   [1.00 ms 1.00 ms 1.00 ms]\n          change: time:   [-2% +1.1% +3%] (p = 0.35 > 0.05)'
    export FAKE_NEW_BASELINE='NEW-ESTIMATES-v2' FAKE_EXIT=0
    st_run "$ws" compare-save; rc=$?
    [ "$rc" -eq 0 ] || { echo "  ✗ 绿 run 应为 exit 0, 实际 $rc"; fails=$((fails+1)); }
    [ "$(cat "$ws/criterion/redact_ir/small/ci/estimates.json" 2>/dev/null)" = 'NEW-ESTIMATES-v2' ] \
        || { echo "  ✗ 基线未滚动 (绿 run 新测量应存活)"; fails=$((fails+1)); }
    grep -q '无场景退化' "$ws/out.log" || { echo "  ✗ 缺绿判定输出"; fails=$((fails+1)); }
    [ ! -f "$ws/spy" ] \
        || { echo "  ✗ 绿 run 不应触发 open_regression_issue (issue 钉住仅判红联动)"; fails=$((fails+1)); }
    st_report green "$fails" "$ws"
}

# c. bench 失败路径: runner exit 101 (且已模拟 criterion 中途落盘) → exit 2 + 回滚.
st_bench_fail() {
    local ws rc fails=0
    ws=$(st_workspace 1)
    cp -r "$ws/criterion" "$ws/pre"
    export FAKE_OUT='redact_ir/small time:   [1.00 ms 1.00 ms 1.00 ms]'
    export FAKE_NEW_BASELINE='NEW-ESTIMATES-v2' FAKE_EXIT=101
    st_run "$ws" compare-save; rc=$?
    [ "$rc" -eq 2 ] || { echo "  ✗ bench 失败应为 exit 2, 实际 $rc"; fails=$((fails+1)); }
    diff -r "$ws/pre" "$ws/criterion" >/dev/null 2>&1 \
        || { echo "  ✗ 基线文件字节与快照前不一致 (bench 失败未回滚)"; fails=$((fails+1)); }
    st_report bench_fail "$fails" "$ws"
}

# d. 冷启动: 无基线目录 → compare-save fallback 纯建立, exit 0 + 基线建立 (不判定回归).
st_cold_start() {
    local ws rc fails=0
    ws=$(st_workspace 0)
    export FAKE_OUT='redact_ir/small time:   [1.00 ms 1.00 ms 1.00 ms]'
    export FAKE_NEW_BASELINE='FIRST-BASELINE' FAKE_EXIT=0
    st_run "$ws" compare-save; rc=$?
    [ "$rc" -eq 0 ] || { echo "  ✗ 冷启动应为 exit 0, 实际 $rc"; fails=$((fails+1)); }
    [ "$(cat "$ws/criterion/redact_ir/small/ci/estimates.json" 2>/dev/null)" = 'FIRST-BASELINE' ] \
        || { echo "  ✗ 首基线未建立"; fails=$((fails+1)); }
    grep -q '冷启动' "$ws/out.log" || { echo "  ✗ 缺冷启动通告"; fails=$((fails+1)); }
    st_report cold_start "$fails" "$ws"
}

bench_ci_selftest() {
    set -uo pipefail
    local ST_SCRIPT fails=0 s
    ST_SCRIPT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")
    for s in red green bench_fail cold_start; do
        "st_$s" || fails=$((fails+1))
    done
    if [ "$fails" -eq 0 ]; then
        echo "bench-ci selftest: ✓ 4/4 场景通过 (红回滚 / 绿滚动 / 失败回滚 / 冷启动)."
        return 0
    fi
    echo "bench-ci selftest: ✗ $fails 个场景失败 (见上方 FAIL 行与保留现场)." >&2
    return 1
}

# ── 入口分发 ──
if [ -n "${BENCH_CI_LIB:-}" ]; then
    # lib 模式: 仅定义函数不执行入口 (见文件头 "用法" 段).
    return 0 2>/dev/null || exit 0
fi
case "${1:-}" in
    selftest)                 bench_ci_selftest ;;
    save|compare|compare-save) main "$@" ;;
    *)
        echo "用法: $0 <save|compare|compare-save> [extra...] | selftest" >&2
        exit 2
        ;;
esac
