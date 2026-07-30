# CI 实现细节 (Forgejo Actions)

> **职责**: `.forgejo/workflows/ci.yml` 的实现细节 SSOT (checkout 策略 / 缓存复用 /
> 并发假设 / 评论写回), 面向 CI 维护者.
> **受众**: 修改 CI 配置 / 需要调整 workflow 的人.
> **接口性质的高层概述** (配置位置 / 触发条件 / CI 做了什么) 在根 `AGENTS.md`
> "## 开发流程 → ### CI (Forgejo Actions)" 段, 改 CI 配置前先读那段了解整体定位.
> 与 ci.yml 不一致时以 ci.yml 为准.

## 触发与去重

CI 配置 `.forgejo/workflows/ci.yml`, 触发: `push` + `pull_request` + `workflow_dispatch`.

双重去重 (节省 runner):

- **事件去重**: 同一 commit 在 feature branch 上会同时触发 push + pull_request, 跑两次
  浪费. PR 事件总是跑 (合并前检查, 主要场景); push 仅 master 跑 (合并后的 commit,
  feature branch 的 push 由 PR 覆盖).
- **内容去重 (skip-if-passed)**: ff-merge 后 commit SHA 不变, master 的 push 会重复
  触发已跑过的 CI. `pre` job 查 Forgejo API (`head_sha` + `status=success`, 限 ci.yml
  workflow), 命中则 `check` job 跳过 (连 checkout 都不执行). 失败退化为不跳过 (不阻断 CI).
  `workflow_dispatch` 直通不查 skip (手动重跑需无条件执行).

## CI 流程 (check job, 测试集只跑一次)

按 ci.yml step 顺序 (本节是导航辅助):

1. **Checkout via SSH** — 见下文"checkout 用 git + SSH". PR 事件 fetch base+head 支持三点
   diff; 其他事件浅克隆 `--depth 1` 省时.
2. **Generate diff breakdown report** (仅 PR 事件, `continue-on-error` 真正非阻塞):
   `rust-diff-analyzer` (runner VM systemPackages 提供) 对 `origin/<base>...HEAD` 跑 diff
   拆解, `--format comment` 输出 markdown. 放在 check 之前让 review 尽早看到膨胀分析.
3. **Upsert PR comment** (仅 PR 事件, `continue-on-error`): 把上一步报告以评论形式贴出,
   upsert 机制见下文"评论写回机制".
4. **consistency-check feature guard** (`just check-features`): clippy + nextest 带
   `consistency-check` feature 跑一次 (视图正确性断言, 详见根 AGENTS.md "视图正确性确保机制").
   单独成步复用 checkout, 在 coverage 的 cargo clean 前, 不影响磁盘峰值控制.
5. **Check + coverage data** (`just check --coverage`): fmt + clippy + machete + 测试,
   用 `cargo llvm-cov nextest` 插桩, 产出 profdata 供下一步消费. **测试集只跑这一次**.
6. **Coverage gate** (`just coverage-gate`): 双阈值 (line% 下限 + 未覆盖行数上限, 阈值
   SSOT 在 justfile), 只做 report 读上一步 profdata, 不重跑测试.
7. **File size gate** (`just check-file-size`): `rust-diff-analyzer` 对每个 .rs 做 AST 分类,
   只统计 prod 行数 (排除 test), 双阈值 (WARN 500 软提醒 / MAX 1600 硬阻断, fail-closed).
8. **WebUI regression (Playwright)** (`just check-webui`, `continue-on-error` 初期非阻塞):
   webServer 自动启动 mock upstream + secret-guard, 复用上一步编译的 debug binary
   (CARGO_TARGET_DIR 指向持久卷, playwright.config.ts 读此环境变量).
9. **Upload Playwright artifacts on failure** (仅 Playwright 失败时, `continue-on-error`):
   上传截图/trace/html 报告. 用 Forgejo 官方 fork `forgejo/upload-artifact@v4`
   (GitHub 官方版会检测非 GitHub 环境报错), retention 14 天.
10. **cargo audit** (`just audit`, `continue-on-error` 非阻塞): CVE 扫描, 输出 tee 到
    audit.txt 供下一步 upsert 到 PR 评论. 非阻塞理由: 新 CVE 不应阻塞正在进行的 PR;
    advisory DB 拉取可能因网络抖动失败. 忽略项配置 `.cargo/audit.toml`, 详见根 AGENTS.md
    "cargo-audit (CVE 监控)" 段.
11. **Upsert cargo audit report to PR** (仅 PR 事件, `continue-on-error`): audit 结果 upsert
    到 PR 评论, 复用 diff-loc 的 marker 机制让非阻塞的 CVE 不只埋在 job log.
12. **cargo-deny** (`just deny`, **阻塞**): license 合规 + 依赖 bans + advisory 二次审查.
    配置 `deny.toml`, 详见根 AGENTS.md "cargo-deny" 段.
13. **typos** (`just typos`, **阻塞**): 拼写检查, 白名单 `_typos.toml`.

> **流程顺序原则**: 真正非阻塞的附加检查 (diff 报告 / WebUI / audit) 用 `continue-on-error`
> 兜底, 即使抽风也不影响 `check` job 状态; 阻塞门禁 (consistency-check / check /
> coverage-gate / file-size / cargo-deny / typos) 失败则 job 失败.

## 非阻塞检查的升级路径

- **cargo audit**: 保持 `continue-on-error` 非阻塞 (非阻塞理由见上 step 10). 结果已 upsert
  到 PR 评论供 review 时看到, 无需进 job log 翻找.
- **WebUI regression (Playwright)**: 初期 `continue-on-error` (CI 环境无 GPU / chromium 渲染
  可能有 flake). **退出条件**: 连续 N=20 次 master 分支 (push 事件) 本 step 跑绿后, 移除
  `continue-on-error` 升级为阻塞. 判定: 翻 Actions 历史筛 master + WebUI step 取最近 20 次
  全绿即达标; 升级前先在 PR 评论记录达标证据 (20 次 run 链接).
- **diff 报告**: 真正非阻塞 (`continue-on-error: true`), 工具/网络/API 失败也不影响合并,
  无升级计划 (附加功能性质).
- **cargo-deny / typos**: 已是阻塞门禁 (无观察期, 见下 blockquote). 新误报出现时更新对应
  配置 (`deny.toml` / `_typos.toml`) 即可, 属正常维护.

> license 合规 (cargo-deny) 与 CVE (cargo audit) 性质不同 — license 违规是真问题 (污染下游),
> 已升级阻塞; CVE 受网络 DB 抖动影响保持非阻塞更稳.

## 评论写回机制 (PR comment upsert)

CI 用纯 `curl` + Forgejo API (`POST/PATCH /repos/{owner}/{repo}/issues/{n}/comments`)
把报告贴到 PR, 不引入 JS action (runner vm-nix 无 node, 零依赖 shell 更轻量).

**upsert 语义**: 用 HTML 注释 marker 标记评论, 找到则 PATCH 更新 (PR 多次 push 不刷屏),
找不到则 POST 新建. 当前两个 marker:

- `<!-- rust-diff-analyzer -->` — diff 拆解报告 (步骤 2/3).
- `<!-- cargo-audit -->` — CVE 扫描结果 (步骤 10/11).

写回步骤都配 `continue-on-error: true`: API/网络失败不影响合并 (附加功能不影响核心职责,
遵循鲁棒性原则). 额外守卫 `steps.report.outcome == 'success'`: 报告没生成就不发空评论.

## 跨 job target 复用 (CARGO_TARGET_DIR 缓存)

`check` job 设 `CARGO_TARGET_DIR=/var/lib/forgejo-runner/cache/cargo-target`, 指向 runner VM
的持久 tmpfs 卷 (宿主侧 10G tmpfs + virtiofs 共享, 见 nixos 仓库
`forgejo-runner-vm.mod.nix`). 跨 job 复用 cargo 编译产物: 依赖 crate 只编一次, 后续 job
增量编译 (秒级).

- **子目录隔离**: clippy/nextest 用 `debug/` 子目录, coverage 用 `llvm-cov-target/` 子目录,
  物理隔离无需全量 `cargo clean`. (注: `just check --coverage` 内部跑
  `cargo llvm-cov clean --workspace` 精准清插桩 artifacts, 不影响 debug/ 缓存.)
- **卷生命周期**: 主机启动期间 (tmpfs, 主机重启才丢).
- **Playwright 复用**: webServer 复用 debug binary (机制见 step 8).

## 并发互斥假设 (runner single-job mode)

跨 job target 复用机制**假设 runner vm-nix 同一时刻只跑一个 job** (runner 注册时
concurrency=1 或 single-job mode, 配置在 nixos 仓库 `forgejo-runner-vm.mod.nix`, 本仓库不可见).

若该假设被打破 (runner 允许并发 job), 两个 job 同时写同一 `CARGO_TARGET_DIR` 会触发 cargo
`Blocking waiting for file lock` (慢) 或产物交错污染.

**应对预案** (见 ci.yml `check` job `env` 段注释):

1. 加 `concurrency: { group: ci-vm-nix, cancel-in-progress: false }` 串行化所有 CI run; 或
2. 改 `CARGO_TARGET_DIR` 按 `run_id` 隔离 (但会丢跨 job 缓存复用, 编译变慢).

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
