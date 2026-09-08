# CI 实现细节 (Forgejo Actions)

> **职责**: `.forgejo/workflows/ci.yml` 的实现细节 SSOT (checkout 策略 / 缓存复用 /
> 并发假设 / 评论写回), 面向 CI 维护者.
> **受众**: 修改 CI 配置 / 需要调整 workflow 的人.
> **接口性质的高层概述** (配置位置 / 触发条件 / CI 做了什么) 在根 `AGENTS.md`
> "## 开发流程 → ### CI (Forgejo Actions)" 段, 改 CI 配置前先读那段了解整体定位.
> 与 ci.yml 不一致时以 ci.yml 为准.

## 触发与去重

CI 配置 `.forgejo/workflows/ci.yml`, 触发: `push` + `pull_request` (显式 `types`
含 `edited`, 为 WIP 门禁衔接 — forgejo 默认事件集不含 title 编辑) + `workflow_dispatch`.

三重跳过 (节省 runner):

- **事件去重**: 同一 commit 在 feature branch 上会同时触发 push + pull_request, 跑两次
  浪费. PR 事件总是跑 (合并前检查, 主要场景; draft/WIP PR 除外, 见 WIP 门禁); push 仅
  master 跑 (合并后的 commit, feature branch 的 push 由 PR 覆盖).
- **内容去重 (skip-if-passed)**: ff-merge 后 commit SHA 不变, master 的 push 会重复
  触发已跑过的 CI. `pre` job 查 Forgejo API (`head_sha` + `status=success`, 限 ci.yml
  workflow), 命中则 `check` job 跳过 (连 checkout 都不执行). 失败退化为不跳过 (不阻断 CI).
  `workflow_dispatch` 直通不查 skip (手动重跑需无条件执行).
- **WIP 门禁 (draft PR 跳过, issue #204 / nixos#791)**: draft PR (title 带 `WIP:`/
  `[WIP]` 前缀) 不触发 CI — WIP PR 离可合并尚远 (forgejo 本就按 WIP 前缀阻塞合并),
  其上每次 push 的 check 纯属浪费 (runner 单槽位且全 org 共享). 去 WIP 前缀 (title
  编辑) 触发 `edited` 事件自动补跑. 判定用 payload `pull_request.draft` (=
  forgejo `IsWorkInProgress()`, 与阻塞合并同一 SSOT, 前缀集随实例配置自动对齐).
  关键语义 (forgejo v15.0.7 源码核实): ① `pre` + `check` **双 job 都必须门禁** — 只门禁
  `check` 时 `pre` 跑成功 → run 结论 success → 污染 skip-if-passed 内容去重 (去 WIP 后
  补跑被误判 "已通过"); 全 job skipped → run 结论 `skipped` (非 success) → 不污染.
  ② job 级 skip 的 commit status 映射绿色 ("Has been skipped"), 已知残余窗口 (去 WIP →
  覆盖 run 写 pending 之间, 亚秒) 由 merge automation 组织级根治兜底 (CI 判定改查
  action runs, skipped run 不被采信, nixos#794). ③ WIP 化的 edited 事件经同
  concurrency group 取消在跑 CI ("标记 draft 即停止烧 CI").

**PR 并发去旧 (concurrency)**: 同 PR 快速多次 push 时, 旧 run 结果已无意义却在
single-job runner 上串行占位, 延迟最新 push 的反馈. workflow 级
`concurrency: { group: ci-pr-<PR number|sha>, cancel-in-progress: true }` 按 PR 分组
取消旧 run. 与 runner 层 single-job 互斥 (见下文"并发互斥假设") 正交 — 前者约束
"同一 PR 的 run 之间", 后者约束 "不同 run 之间".

## CI 流程 (check job, 测试集只跑一次)

按 ci.yml step 顺序 (本节是导航辅助):

1. **Guard single-job assumption (acquire)** — 在 cache 卷根写 run_id 锁文件, 供末尾
   的释放校验检测 "另一 job 并发写了同一 CARGO_TARGET_DIR" (single-job 假设破裂时把
   静默产物污染转为带指向性的硬失败, 详见下文"并发互斥假设").
2. **Checkout via SSH** — 见下文"checkout 用 git + SSH". PR 事件 fetch base+head 支持三点
   diff; 其他事件浅克隆 `--depth 1` 省时.
3. **Generate diff breakdown report** (仅 PR 事件, `continue-on-error` 真正非阻塞):
   `rust-diff-analyzer` (runner VM systemPackages 提供) 对 `origin/<base>...HEAD` 跑 diff
   拆解, `--format comment` 输出 markdown. 放在 check 之前让 review 尽早看到膨胀分析.
4. **Upsert PR comment** (仅 PR 事件, `continue-on-error`): 把上一步报告以评论形式贴出,
   upsert 机制见下文"评论写回机制".
5. **Record toolchain version** (`if: always()`): 把 `rustc --version` 写入 step output,
   由 Diagnose 评论携带留痕 — CI 工具链由 VM nixpkgs 决定, 三源 (CI/devShell/
   rust-toolchain.toml) 漂移导致 clippy 新 lint 无预警阻塞时, 事后可追溯 "哪天升的".
   放在首个阻塞 step 之前: 核心动机场景正是 "后续 step 因新 lint 失败", 那时本 step
   必须已跑过. MSRV 下界 SSOT 在 Cargo.toml `rust-version`.
6. **consistency-check feature guard** (`just check-features`): clippy + nextest 带
   `consistency-check` feature 跑一次 (视图正确性断言, 详见根 AGENTS.md "视图正确性确保机制").
   单独成步复用 checkout, 在 coverage 的 cargo clean 前, 不影响磁盘峰值控制.
7. **Check + coverage data** (`just check --coverage`): fmt + clippy + machete + **doc 门禁**
   + 测试 + **typos + deny-offline** + **check-contracts** (contracts.md property 落地
   标注 lint, #144: ✅ 须同名命中 / 🔁 锚点须可 grep / 每条 property 必有标注), 用
   `cargo llvm-cov nextest` 插桩, 产出 profdata 供
   下一步消费. **测试集只跑这一次**. cargo 命令均带 `--locked` (Cargo.toml/Cargo.lock
   不一致时 CI 硬失败, 防止 CI 静默重 resolve 导致测试对象漂移). doc 门禁
   (`RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps`) 位于 justfile check 的
   公共段 — 原先仅在非 coverage 分支执行而 CI 恒走 coverage 分支, 是从未生效的死门禁
   (issue #141). typos + deny-offline (`cargo deny --offline check licenses bans sources`)
   在链尾执行, 不设独立 step — 独立 step 只可能 "check 内失败后被 skip" 或 "check 内
   通过后重跑必过", 永远不产生独立失败信号; 本地 `just check` 链尾跑同一命令, 保证本地
   全绿 ⇒ CI 必绿 (issue #149-3/-8).
8. **Coverage gate** (`just coverage-gate`): 双阈值 (line% 下限 + 未覆盖行数上限, 阈值
   SSOT 在 justfile), 只做 report 读上一步 profdata, 不重跑测试.
9. **Performance benchmark** (`just bench-ci`, `continue-on-error` 非阻塞): criterion
    baseline 回归检测. master push → `bench-ci save` (滚动更新基线 `ci`); PR →
    `bench-ci compare` (只对比不覆盖, 冷启动自动 fallback 建 首基线). 退化判定 (解析
    criterion 输出的 change 中位数, 默认 20% 阈值) + 退出码契约 (0 正常 / 1 退化 / 2 失败)
    的 SSOT 在 justfile `bench-ci` recipe. criterion 基线落 `CARGO_TARGET_DIR/criterion/`
    跨 job 复用.
10. **Upsert benchmark report to PR** (仅 PR 事件, `continue-on-error`): bench 结果 upsert
    到 PR 评论, 复用 marker 机制让退化信号不只埋在 job log.
11. **File size gate** (`just check-file-size`): `rust-diff-analyzer` 对每个 .rs 做 AST 分类,
    只统计 prod 行数 (排除 test), 双阈值 (WARN 500 软提醒 / MAX 1600 硬阻断, fail-closed).
12. **WebUI regression (Playwright)** (`just check-webui`, `continue-on-error` 初期非阻塞):
    webServer 自动启动 mock upstream + secret-guard, 复用上一步编译的 debug binary
    (CARGO_TARGET_DIR 指向持久卷, playwright.config.ts 读此环境变量). 退出码与输出摘要
    写入 step output, 供下一步 upsert.
13. **Upsert WebUI result to PR** (仅 PR 事件, `continue-on-error`): WebUI 结果 upsert 到
    PR 评论 (marker `<!-- webui-regression -->`). 修复可见性不对称: WebUI 是非阻塞 step,
    失败若只埋在 job log + artifact, "连续 N=20 次绿 → 转阻塞" 的升级判据永远无人察觉.
14. **Upload Playwright artifacts on failure** (仅 Playwright 失败时, `continue-on-error`):
    上传截图/trace/html 报告. 用 Forgejo 官方 fork `forgejo/upload-artifact@v4`
    (GitHub 官方版会检测非 GitHub 环境报错), retention 14 天.
15. **cargo audit** (`just audit`, `continue-on-error` 非阻塞): CVE 扫描 (含 advisory
    DB 拉取 — 网络依赖是它保持非阻塞的原因之一; advisories 职责归此, 与 deny 互为冗余
    兜底), 输出 tee 到 audit.txt 供下一步 upsert 到 PR 评论. advisory DB 经
    `CARGO_AUDIT_DB` 持久缓存到卷 (justfile audit recipe 透传 `--db`, 首次 clone 后
    跨 job 增量 fetch). 忽略项配置 `.cargo/audit.toml`, 详见根 AGENTS.md
    "cargo-audit (CVE 监控)" 段.
16. **Upsert cargo audit report to PR** (仅 PR 事件, `continue-on-error`): audit 结果 upsert
    到 PR 评论, 复用 diff-loc 的 marker 机制让非阻塞的 CVE 不只埋在 job log.
17. **nix build (cargoHash validation)** (`nix build .#secret-guard -L`,
    `continue-on-error` 非阻塞起步): 验证 nix/package.nix 的 cargoHash 与 Cargo.lock
    一致 (漂移时错误只在部署侧 ~/ws/nixos 重建时暴露, 排障跨仓库). 转阻塞判据: 连续
    N=20 次 master push 跑绿 (同 WebUI step 判据). 注意依赖升级 PR 会合法触发本 step
    失败 (提醒同步 cargoHash), 属预期信号.
18. **Diagnose failure** (仅 PR + job 失败时, `continue-on-error`): 阻塞 step outcomes
    汇总表 + 工具链版本贴到 PR 评论.
19. **Guard single-job assumption (verify)** (`if: always()`): 校验 Guard acquire step
    写入的锁文件未被覆盖; 被覆盖 (= 另一 job 并发写了同一 target dir) 则显式失败并指向
    "并发互斥假设" 段的应对预案.

> **流程顺序原则**: 真正非阻塞的附加检查 (diff 报告 / bench / WebUI / audit / nix build) 用
> `continue-on-error` 兜底, 即使抽风也不影响 `check` job 状态; 阻塞门禁 (consistency-check /
> check 含 doc/--locked/typos/deny-offline / coverage-gate / file-size / lock 校验) 失败则
> job 失败.

## 非阻塞检查的升级路径

- **cargo audit**: 保持 `continue-on-error` 非阻塞 (非阻塞理由见上 "cargo audit" step). 结果已 upsert
  到 PR 评论供 review 时看到, 无需进 job log 翻找.
- **Performance benchmark**: `continue-on-error` 非阻塞 (`--quick` 10 samples 噪声大, p>0.05
  常态, 退化判定只做量级级粗筛防 2x+ 退化, 避免误伤 PR). 退化信号已 upsert 到 PR 评论供
  人工判断. **退出条件**: 连续 N=20 次 master push 无误报后, 可移除 PR 的 `continue-on-error`.
- **WebUI regression (Playwright)**: 初期 `continue-on-error` (CI 环境无 GPU / chromium 渲染
  可能有 flake). **退出条件**: 连续 N=20 次 master 分支 (push 事件) 本 step 跑绿后, 移除
  `continue-on-error` 升级为阻塞. 判定: 翻 Actions 历史筛 master + WebUI step 取最近 20 次
  全绿即达标; 升级前先在 PR 评论记录达标证据 (20 次 run 链接).
- **diff 报告**: 真正非阻塞 (`continue-on-error: true`), 工具/网络/API 失败也不影响合并,
  无升级计划 (附加功能性质).
- **nix build (cargoHash validation)**: `continue-on-error` 非阻塞起步 — 首次/依赖大版本
  升级时全量 vendor 编译较慢, 且 cargoHash 过期是已知高频事件 (升级依赖的 PR 必然触发,
  失败属预期提醒: 同步 nix/package.nix). **退出条件**: 连续 N=20 次 master push 本 step
  跑绿后移除 `continue-on-error` (判定方式同 WebUI: 翻 Actions 历史筛 master + 本 step
  取最近 20 次全绿).
- **cargo-deny / typos**: 已是阻塞门禁 (无观察期, 见下 blockquote). 新误报出现时更新对应
  配置 (`deny.toml` / `_typos.toml`) 即可, 属正常维护.

> license 合规 (cargo-deny) 与 CVE (cargo audit) 性质不同 — license 违规是真问题 (污染下游),
> 已升级阻塞; CVE 受网络 DB 抖动影响保持非阻塞更稳.

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

**应对预案** (见 ci.yml `check` job `env` 段注释):

1. 加 `concurrency: { group: ci-vm-nix, cancel-in-progress: false }` 串行化所有 CI run; 或
2. 改 `CARGO_TARGET_DIR` 按 `run_id` 隔离 (但会丢跨 job 缓存复用, 编译变慢).

> 注: workflow 级 `concurrency` (PR 并发去旧, 见 "触发与去重") 不解决本节问题 — 它只
> 取消同 PR 的旧 run, 不同 PR 的 run 之间仍依赖 runner single-job 假设.

## job 超时预算

`check` job `timeout-minutes: 75` (issue #149-1). 正常热路径 ~10min; 持久卷全清后的
冷启动需串行完成 debug 插桩编译 (~20min) → 测试 → release LTO bench (10-20min) →
playwright → audit → nix build (自身 timeout 30min), 双冷 (卷 + nix store 同时
重建, 仅 VM 首建/重建时出现) 总计可达 ~70min, 75min 留余量. 20min 的旧值在冷启动场景
必超时且 timeout 算 job failure 会阻塞合并 (continue-on-error 救不了 job 级 timeout,
预算必须计入非阻塞 step 的最坏耗时).

## commit status context (workflow name / job_id 禁改)

`ci / check (pull_request)` 或 `ci / check (push)` 是 branch protection 的 required status
check. context 由 workflow `name: ci` + job_id `check` 拼成.

**禁止改 workflow `name` 或 job_id `check`** — 会改变 context 破坏门禁规则. branch protection
status check 规则 `ci / check (*)` 用通配符覆盖 push 与 pull_request 两种事件后缀.

> 注: `pre` job 产生 `ci / pre (*)` check, 但因 step `continue-on-error` 兜底, 该 check 对 PR
> 事件恒为 success, 不影响 branch protection (无需加入 required list).

## checkout 用 git + SSH (不用 actions/checkout)

forgejo 实例启用了 `DISABLE_HTTP_GIT=true` (禁止 git over HTTPS), 且内置 SSH server 要求
用户名 `forgejo` (不是 `git`) + 非标准端口 5522. `actions/checkout@v4` 硬编码 `git@` 用户
且 SCP-style URL 无法嵌端口, 对此环境完全不兼容.

直接用 git 命令把用户名和端口写在 `ssh://` URL 里 (`ssh://forgejo@git.lambda.lc:5522/...`),
一步到位无黑盒:

- **host key**: `ssh-keyscan -p 5522 git.lambda.lc` 每次动态获取 (runner 在可信 MicroVM, LAN
  可信, 首次即信任).
- **凭据**: 依赖一个 repo-level secret `DEPLOY_KEY` (ed25519 私钥, 公钥在 repo Deploy keys 注册),
  写入 `~/.ssh/id_ed25519` (mode 0600).
- **clone 策略**: `git init` + `git remote add` + `git fetch`. PR 事件 fetch base+head
  (`--no-tags`, 支持三点 diff); 其他事件浅克隆 `--depth 1` 省时.
