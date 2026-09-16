# CI 实现细节 (Forgejo Actions)

> **职责**: `.forgejo/workflows/{ci-merge,ci-deploy,ci-periodic}.yml` 三档 workflow 的
> 实现细节 SSOT (checkout 策略 / 缓存复用 / 并发假设 / 评论写回), 面向 CI 维护者.
> **受众**: 修改 CI 配置 / 需要调整 workflow 的人.
> **接口性质的高层概述** (配置位置 / 触发条件 / CI 做了什么) 在根 `AGENTS.md`
> "## 开发流程 → ### CI (Forgejo Actions)" 段, 改 CI 配置前先读那段了解整体定位.
> 与 workflow 文件不一致时以 workflow 文件为准 (P0 = ci-merge.yml).

## 触发与去重

v3.0 三档: `ci-merge.yml` (P0, PR + master push + 手动) / `ci-deploy.yml` (P1, master
push + nightly + 手动) / `ci-periodic.yml` (P2, nightly per-SHA 去重 + 手动, 无 push)。
P0 的 `pull_request` 显式 `types` 含 `edited` (WIP 门禁衔接 — forgejo 默认事件集不含
title 编辑); 三档共用 repo secrets (DEPLOY_KEY / SSH_KNOWN_HOSTS) 与持久卷。

三重跳过 (节省 runner):

- **事件去重**: 同一 commit 在 feature branch 上会同时触发 push + pull_request, 跑两次
  浪费. PR 事件总是跑 (合并前检查, 主要场景; draft/WIP PR 除外, 见 WIP 门禁); push 仅
  master 跑 (合并后的 commit, feature branch 的 push 由 PR 覆盖).
- **内容去重 (skip-if-passed)**: ff-merge 后 commit SHA 不变, master 的 push 会重复
  触发已跑过的 CI. 共享本地 action `skip-if-passed` 查 Forgejo API (服务端过滤
  `head_sha`+`status=success`+`workflow_id` 自指), 命中则后续门禁 step 跳过.
  失败退化为不跳过 (不阻断 CI). 查询时机按档位不同: P0/P1 仅 push 事件, P2 仅
  schedule 事件 (per-SHA 去重); `workflow_dispatch` 直通不查 (手动重跑需无条件执行).
- **WIP 门禁 (draft PR 跳过, issue #204 / nixos#791)**: draft PR (title 带 `WIP:`/
  `[WIP]` 前缀) 不触发 CI — WIP PR 离可合并尚远 (forgejo 本就按 WIP 前缀阻塞合并),
  其上每次 push 的 check 纯属浪费 (runner 单槽位且全 org 共享). 去 WIP 前缀 (title
  编辑) 触发 `edited` 事件自动补跑. 判定用 payload `pull_request.draft` (=
  forgejo `IsWorkInProgress()`, 与阻塞合并同一 SSOT, 前缀集随实例配置自动对齐).
  关键语义 (forgejo v15.0.7 源码核实): ① v3.0 单 job 化后, WIP 门禁在 `check` job 的
  `if` 上 — job 被跳过 → run 结论 `skipped` (非 success) → 不污染 skip-if-passed
  (去 WIP 后补跑不会被误判 "已通过"; 旧双 job 形态的 "pre 污染" 窗口随 pre 删除消失).
  ② job 级 skip 的 commit status 映射绿色 ("Has been skipped"), 已知残余窗口 (去 WIP →
  覆盖 run 写 pending 之间, 亚秒) 由 merge automation 组织级根治兜底 (CI 判定改查
  action runs, skipped run 不被采信, nixos#794). ③ WIP 化的 edited 事件经同
  concurrency group 取消在跑 CI ("标记 draft 即停止烧 CI").

**PR 并发去旧 (concurrency)**: 同 PR 快速多次 push 时, 旧 run 结果已无意义却在
single-job runner 上串行占位, 延迟最新 push 的反馈. workflow 级
`concurrency: { group: ci-pr-<PR number|sha>, cancel-in-progress: true }` 按 PR 分组
取消旧 run. 与 runner 层 single-job 互斥 (见下文"并发互斥假设") 正交 — 前者约束
"同一 PR 的 run 之间", 后者约束 "不同 run 之间".

## CI 流程 (v3.0 三档; P0 = ci-merge.yml check job)

按 ci-merge.yml step 顺序 (本节是导航辅助; check-docs 机器校验本编号清单与文件
`- name:` 数一致):

1. **Guard single-job assumption (acquire)** — 在 cache 卷根写 run_id 锁文件, 供末尾
   的释放校验检测 "另一 job 并发写了同一 CARGO_TARGET_DIR" (single-job 假设破裂时把
   静默产物污染转为带指向性的硬失败, 详见下文"并发互斥假设")。
2. **Checkout via SSH** — 见下文"checkout 用 git + SSH". PR 事件 fetch base+head 支持三点
   diff; 其他事件浅克隆 `--depth 1` 省时。
3. **Cleanup deploy key** (`if: always()`) — org 共享 runner 最小权限收尾, checkout
   写入的只读 key 用后即清。
4. **skip-if-passed** (内容去重) — 共享本地 action (`.forgejo/actions/skip-if-passed`,
   与 SSOT 逐字节同步), 仅 push 事件查询; 替代旧双 job 形态的内联 `pre` 探针。
5. **Generate diff breakdown report** (仅 PR 事件, `continue-on-error` 真正非阻塞):
   `rust-diff-analyzer` 对 `origin/<base>...HEAD` 跑 diff 拆解, `--format comment`
   输出 markdown. 放在门禁之前让 review 尽早看到膨胀分析。
6. **Upsert PR comment** (仅 PR 事件, `continue-on-error`): 把上一步报告以评论形式贴出,
   upsert 机制见下文"评论写回机制"。
7. **Record toolchain version** (`if: always()`): 把 `rustc --version` 写入 step output,
   由 Diagnose 评论携带留痕 (CI 工具链由 VM nixpkgs 决定, 三源漂移事后可追溯)。
8. **consistency-check feature guard** (`just check-features`): clippy + nextest 带
   `consistency-check` feature 跑一次 (视图正确性断言, 详见根 AGENTS.md "视图正确性确保
   机制"; 也是 contracts.md `prop_consistency_check_feature_runs_in_ci` 的锚点)。
9. **Quality gate (just ci-merge main)** — P0 阻塞主链: `just check` 普通档 (fmt +
   clippy + machete + doc 门禁 + 测试 + typos + deny-offline + check-webui-syntax +
   check-contracts + nix-check, **不带 --coverage** — 插桩与 coverage-gate 已归 P2)。
   cargo 命令均带 `--locked`。测试集只跑这一次。stage 机制见 justfile `ci-merge`
   recipe (CI 拆 step / 本地 all 档聚合, 逐段等价无重复)。
10. **File size gate** (`just check-file-size`): `rust-diff-analyzer` 对每个 .rs 做 AST
    分类, 只统计 prod 行数 (排除 test), 双阈值 (WARN 500 软提醒 / MAX 1600 硬阻断,
    fail-closed)。
11. **Diagnose failure** (仅 PR + job 失败时, `continue-on-error`): 阻塞 step outcomes
    汇总表 + 工具链版本贴到 PR 评论 (无日志权限 contributor 的 fallback)。
12. **Guard single-job assumption (verify)** (`if: always()`): 校验 acquire step 写入的
    锁文件未被覆盖; 被覆盖则显式失败并指向 "并发互斥假设" 段的应对预案。

> **流程顺序原则**: 真正非阻塞的附加检查 (diff 报告 / Diagnose) 用 `continue-on-error`
> 兜底, 即使抽风也不影响 `check` job 状态; 阻塞门禁 (consistency-check / check 主链
> 含 doc/--locked/typos/deny-offline/check-contracts / file-size / lock 校验) 失败则
> job 失败。

### P1 ci-deploy.yml (master push + nightly `0 19 * * *` + 手动; `just ci-deploy`)

部署门禁档 — 红 = 不能部署 (**不执行部署动作**)。非超集偏差 (只跑 P1 增量, 不重跑 P0
全链): 无部署流水线消费本检查 + P0 全链 6-9min 单槽位重跑不值; 升级路径 = ci-deploy
recipe 头部加一行 `just ci-merge`。step: Guard acquire / Checkout (恒浅克隆) / Cleanup
key / skip-if-passed (`workflow_file: ci-deploy.yml` 自指, 仅 push 查询 — nightly/
dispatch 无条件) / **Quality gate (`just ci-deploy`)** = cargo audit (CVE, 阻塞) +
bench compare-save (判回归 + 滚动更新基线, 退化 → run 红) / **nix build (cargoHash
validation)** (canary 探针, continue-on-error — runner 无 nix-daemon 恒失败, 转绿即
runner 具备 nix 能力, 届时再转阻塞; 见 workflow step 注释) / Guard verify。

政策变化 (相对旧单 workflow): audit 由 PR 上的 continue-on-error 非阻塞转为 P1 阻塞
— 旧非阻塞理由 ("不阻塞 PR 合并") 在 P1 (不门禁 PR 合入) 不再适用, "audit 发现 CVE
= 该挡下部署" 正是本档职责。nix build 维持 continue-on-error, 语义改为 canary 探针
(runner 无 nix-daemon 恒失败 — 旧形态下同样恒失败只是被遮掩, v3.0 转阻塞首跑暴露;
转绿之日再恢复阻塞语义)。

### P2 ci-periodic.yml (nightly `0 20 * * *` per-SHA 去重 + 手动; `just ci-periodic`)

周期兜底档 — 红 = 欠债待还, **不阻塞任何事**。**刻意无 push 触发** (check-drift 负向
断言): 慢内容 (插桩编译 + 全量测试 + Playwright) 离开 push 关键路径, 白天槽位留给门禁
run。skip 仅 schedule 事件查询 + `workflow_file: ci-periodic.yml` 自指 → 按 SHA 去重
(同代码同结果, 同 SHA 跑一次即足; 失败无 success 记录 → 次晚自愈重试; dispatch 永不
跳过且可选任意分支 = 高风险 PR 合入前全量回归逃生舱)。step: Guard acquire / Checkout /
Cleanup key / skip-if-passed / **Quality gate (`just ci-periodic`)** = `just check
--coverage` (插桩测试, 测试集只跑这一次) + `just coverage-gate` (双阈值防倒退, 阻塞) /
**WebUI regression (Playwright)** (`just check-webui`, continue-on-error — flake 由次晚
重试自愈; binary 复用插桩产物, playwright.config.ts 候选链第三命中) / Upload Playwright
artifacts on failure (截图/trace/报告, retention 14 天) / Guard verify。

### 旧 ci.yml step → v3.0 去向表

| 旧 step | 去向 |
|---|---|
| Guard acquire/verify, Checkout, Cleanup key | P0 (三档各自保留, 逐字节同构) |
| pre job (内联探针) | 删除 — 换共享本地 action (三档各自接线, workflow_file 自指) |
| diff breakdown + Upsert 评论, toolchain 留痕, Diagnose | P0 保留 |
| consistency-check feature guard | P0 保留 (独立 step, contracts.md 锚点) |
| Check + coverage data (`--coverage` 插桩) | 拆分: 普通主链留 P0 (step 9); 插桩归 P2 |
| Coverage gate | **P2** (rubric: 覆盖率防倒退 = 质量债, 不卡合入) |
| Performance benchmark + bench PR 评论 | **P1** (compare-save 单模式; PR 评论随 PR 事件消失) |
| WebUI regression + 评论 + artifact | **P2** (评论随 PR 事件消失 → 日志摘要 + artifact) |
| cargo audit + PR 评论 | **P1** (转阻塞; 评论随 PR 事件消失) |
| nix build (cargoHash) | **P1** (canary 探针 — runner 无 nix-daemon 恒失败, 保留待 runner 具备 nix 能力后转阻塞) |

## 非阻塞检查的升级路径

- **diff 报告 / Diagnose**: 真正非阻塞 (`continue-on-error: true`), 工具/网络/API 失败
  也不影响合并, 无升级计划 (附加功能性质)。
- **WebUI regression (Playwright, P2)**: 保持 `continue-on-error` — P2 无 PR 合入语义,
  无 "转阻塞" 升级目标; flake 由次晚 schedule 重试自愈, 失败 tail 摘要 + artifact 可见。
- **Performance benchmark (P1, compare-save)**: 已是 P1 阻塞信号 (退化 exit 1 → run 红);
  `--quick` 10 samples 噪声大 (±15% 实测), 阈值 20% 只做量级级粗筛 — 升级到完整 samples
  后可收紧到 10%。
- **cargo audit (P1)**: v3.0 起已阻塞化 (P1 语义), 无观察期。
- **nix build (P1, canary)**: runner 无 nix-daemon 恒失败, continue-on-error 探针保留;
  启用条件 = runner 侧 nix 能力就位 (nixos 仓 forgejo-runner-vm 模块演进), 转绿后
  移除 continue-on-error 即恢复 P1 阻塞语义。
- **cargo-deny / typos**: 已是 P0 阻塞门禁 (check 链尾, 无观察期)。新误报出现时更新
  对应配置 (`deny.toml` / `_typos.toml`) 即可, 属正常维护。

> license 合规 (cargo-deny, P0 阻塞) 与 CVE (cargo audit, P1) 性质不同 — license 违规
> 污染下游是真问题; CVE 属环境敏感信号, 归 nightly 无条件兜底档。
## 评论写回机制 (PR comment upsert)

CI 用纯 `curl` + Forgejo API (`POST/PATCH /repos/{owner}/{repo}/issues/{n}/comments`)
把报告贴到 PR, 不引入 JS action 写评论 (评论写回零依赖 shell 更轻量; 上传 artifact 用的
`forgejo/upload-artifact@v4` 是例外, VM 有 nodejs 运行它).

**upsert 语义**: 用 HTML 注释 marker 标记评论, 找到则 PATCH 更新 (PR 多次 push 不刷屏),
找不到则 POST 新建. 当前四个 marker:

- `<!-- rust-diff-analyzer -->` — diff 拆解报告.
- `<!-- bench-regression -->` — 性能回归检测结果.
- `<!-- webui-regression -->` — WebUI 回归测试结果.
- `<!-- cargo-audit -->` — CVE 扫描结果.

(Diagnose failure step 用 `<!-- ci-diagnose -->` marker 但仅 POST 不 upsert — 每次失败
独立留痕, 不覆盖历史.)

写回步骤都配 `continue-on-error: true`: API/网络失败不影响合并 (附加功能不影响核心职责,
遵循鲁棒性原则). 额外守卫 `steps.report.outcome == 'success'`: 报告没生成就不发空评论.

## 跨 job target 复用 (CARGO_TARGET_DIR 缓存)

`check` job 设 `CARGO_TARGET_DIR=/var/lib/forgejo-runner/cache/cargo-target`, 指向 runner VM
的持久 tmpfs 卷 (宿主侧 tmpfs + virtiofs 共享, 容量与预算构成 SSOT 见 nixos 仓库
`forgejo-runner-vm.mod.nix`). 跨 job 复用 cargo 编译产物: 依赖 crate 只编一次, 后续 job
增量编译 (秒级).

- **卷卫生 (防 ENOSPC)**: 卷的防满回收由 runner VM 侧的 cache-reclaim 定时服务统一负责
  (多 repo 共享同一卷, 回收逻辑收敛在基础设施层; 2026-08-24 ENOSPC 事故后从本 workflow
  的 Reclaim step 迁出, 机制与阈值见 nixos 仓库 `forgejo-runner-vm-cache-reclaim.sh`).

- **子目录隔离**: clippy/nextest 用 `debug/` 子目录, coverage 用 `llvm-cov-target/` 子目录,
  bench 用 `release/` 子目录, criterion 基线用 `criterion/` 子目录, 物理隔离无需全量
  `cargo clean`. (注: `just check --coverage` 内部跑 `cargo llvm-cov clean --workspace`
  精准清插桩 artifacts, 不影响 debug/ 缓存; criterion 基线跨 job 持久, master 建立后 PR 直接对比.)
- **卷生命周期**: 主机启动期间 (tmpfs, 主机重启才丢; 重启后 criterion 基线冷启动, bench-ci
  自动 fallback 重建).
- **Playwright 复用**: webServer 复用 debug binary (机制见 "WebUI regression" step).

## 并发互斥假设 (runner single-job mode)

跨 job target 复用机制**假设 runner vm-nix 同一时刻只跑一个 job** (runner 注册时
concurrency=1 或 single-job mode, 配置在 nixos 仓库 `forgejo-runner-vm.mod.nix`, 本仓库不可见).

**运行时防御**: job 开头在 cache 卷根 (`/var/lib/forgejo-runner/cache/.ci-target-dir-lock`)
写 run_id 锁文件, 结束时校验未被覆盖 — 被覆盖即说明另一 job 并发写了同一
`CARGO_TARGET_DIR`, 校验 step 显式失败并指向本节. 把 "静默产物污染 / 偶现怪异失败"
转化为带指向性的硬失败. 锁文件不放 CARGO_TARGET_DIR 内 (卷级全清清理 `rm -rf $CARGO_TARGET_DIR/*`
会连带删掉它导致误报).

若该假设被打破 (runner 允许并发 job), 两个 job 同时写同一 `CARGO_TARGET_DIR` 会触发 cargo
`Blocking waiting for file lock` (慢) 或产物交错污染.

**应对预案** (见 ci-merge.yml `check` job `env` 段注释, 三档一体适用):

1. 加 `concurrency: { group: ci-vm-nix, cancel-in-progress: false }` 串行化所有 CI run; 或
2. 改 `CARGO_TARGET_DIR` 按 `run_id` 隔离 (但会丢跨 job 缓存复用, 编译变慢).

> 注: workflow 级 `concurrency` (PR 并发去旧, 见 "触发与去重") 不解决本节问题 — 它只
> 取消同 PR 的旧 run, 不同 PR 的 run 之间仍依赖 runner single-job 假设.

## job 超时预算 (v3.0 按档拆分)

旧单 workflow 75min 预算按三档重算 (issue #149-1 的冷启动实测口径; timeout 算 job
failure, continue-on-error 救不了 — P0 超时会阻塞合并):

- `ci-merge` 40min: 冷链 = debug 编译 ~20min + check-features + diff/filesize ≈ 24min,
  正常热路径 ~6-9min (旧全链实测 15-19min40s 减移出档份额).
- `ci-deploy` 60min: release LTO bench 编译 10-20min + bench 运行 + audit + nix build
  (step 自身硬上限 30min), 正常热路径 ~8-12min.
- `ci-periodic` 45min: 插桩编译 20-25min + 测试 + report + Playwright ~3-5min,
  正常热路径 ~8-12min.

## commit status context (workflow name / job_id 禁改)

`ci-merge / check (pull_request)` 或 `ci-merge / check (push)` 是 branch protection 的
required status check. context 由 workflow `name: ci-merge` + job_id `check` 拼成.

**禁止改 workflow `name` 或 job_id `check`** — 会改变 context 破坏门禁规则. branch
protection 规则由 nixos 仓 forgejo-sync 声明式管理 (v3.0 迁移期为 dual-glob 桥接
`ci* / check*`, 新旧名同过门禁; 全 org 迁完后收紧, 见 forgejo-actions AGENTS.md) —
改名/调整走 nixos 仓 PR, 勿在本仓或 UI 命令式修改.

> 注: 旧 `pre` job (`ci / pre (*)` check) 已随 v3.0 单 job 化删除 (探针并入 check job 的
> skip step).

## checkout 用 git + SSH (不用 actions/checkout)

forgejo 实例启用了 `DISABLE_HTTP_GIT=true` (禁止 git over HTTPS), 且内置 SSH server 要求
用户名 `forgejo` (不是 `git`) + 非标准端口 5522. `actions/checkout@v4` 硬编码 `git@` 用户
且 SCP-style URL 无法嵌端口, 对此环境完全不兼容.

直接用 git 命令把用户名和端口写在 `ssh://` URL 里 (`ssh://forgejo@git.lambda.lc:5522/...`),
一步到位无黑盒:

- **host key**: TOFU — 优先 repo secret `SSH_KNOWN_HOSTS` (keyscan 原样输出, 消除动态
  keyscan 的 MITM 窗口); secret 缺失退回动态 `ssh-keyscan -p 5522` + stderr 警告 (org
  标准链, directory-algebra #89 同源).
- **凭据**: 依赖一个 repo-level secret `DEPLOY_KEY` (ed25519 私钥, 公钥在 repo Deploy keys 注册),
  写入 `~/.ssh/id_ed25519` (mode 0600).
- **clone 策略**: `git init` + `git remote add` + `git fetch`. PR 事件 fetch base+head
  (`--no-tags`, 支持三点 diff); 其他事件浅克隆 `--depth 1` 省时.
