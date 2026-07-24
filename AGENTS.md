# secret-guard — Agent 工作指南

> 本文件面向 AI 代码助手 (opencode / claude-code 等), 描述本项目的**项目级**约定与开发流程.
> 模块级实现契约见各模块目录的 `AGENTS.md` 或源文件头部 `//!` 注释 (指针见"模块概览").
> 用户级文档见 `README.md`.

## 项目定位

轻量级 LLM 网关 (本地进程): 透明转发 LLM 请求, 同时检测并替换 body 中的 secret,
防止 agent 不经意把 secret 泄露到 LLM Provider. 响应回传时反向替换, 让本地工具仍能用真 secret.
支持多 provider 配置 (OpenAI / Anthropic / Gemini / Ollama), 通过 URL 路径前缀选择目标.

## 术语表

> 本表是**消除歧义的权威**. 当用户使用"常见异名"列中的口语时, 回应时必须替换为"规范术语"
> 并紧临括注对应关系, 例如: 用户说"把 AI 发的消息居左" → "明白, 我把 role 为 Assistant
> (AI 发的) 的 Bubble 居左". 不要反问"你说的 X 是不是指 Y"——直接纠正, 避免漂移.

| 规范术语 | 定义 | 常见异名 | 归属层 |
|---|---|---|---|
| **Secret** | 需要从 LLM 视野中隐藏的真实敏感值 (API key / token / 密码等) | 密钥、敏感信息、真实值、真值 | 全局 |
| **Redact** | 把 request body 中的 Secret 替换为 Mock 的正向操作 | 脱敏、过滤、打码、替换 | 全局 |
| **Restore** | 把 response body 中的 Mock 还原为 Secret 的反向操作 | 还原、反替换、恢复 | 全局 |
| **Mock** | Redact 时替代 Secret 的占位值 (per-secret 稳定, 不含真 secret 子串) | 假值、替身、占位符 | 全局 |
| **Provider** | 一个上游 LLM 服务端点 (id + protocol + base_url + api_key) | 上游、后端、模型、服务商 | 全局 |
| **Protocol** | LLM API 的协议族 (OpenAI / Anthropic / Gemini / Ollama) | 协议、格式 | 全局 |
| **IR** | 协议无关的中间表示 (IrRequest / IrResponse / IrBlock) | 中间表示 | codec |
| **RedactionMap** | 一次 Redact 产出的 Secret↔Mock 双向映射表 (per-request, 不持久化) | 映射表、redact map | redact |
| **MockStrategy** | 每个 Secret 的 Mock 生成策略 (初始值 + 生成策略两维度) | mock 策略、生成策略 | mock/redact |
| **ForwardRecord** | 一次 HTTP 转发的完整记录 (web 层 DTO, 从 DAG Node 派生) | 请求记录、record、转发记录 | web |
| **Node** | ConversationDAG 中的一个节点 = 一次 API 调用 | 轮次、round、节点 | dag/web |
| **Session** | 由 Merkle 前缀哈希聚类的一组 Node 链 | 会话、对话、conversation | dag/web |
| **req_delta** | 一个 Node 相对其 parent 新增的 messages | 增量、本轮新增、delta | dag/web |
| **resp_parsed** | 流式响应经 StreamScan 累积的 IR 视图 | 解析结果、响应解析 | web |
| **Ingress / Egress** | 请求进入 / 响应离开 secret-guard 时用的协议 | 入站/出站协议 | proxy/codec |
| **Effective view** | 合并 static + dynamic + decision 后的生效配置 | 生效配置、最终配置、合并视图 | config |
| **Bubble** | 前端 timeline 中渲染的单条消息气泡 (= 1 个 IR message) | 气泡、消息块、消息项 | web/index.html |

## 关键技术决策 (SSOT)

- **语言**: Rust 2024 edition (toolchain 1.96, via nixos-unstable, 与 ~/ws/nixos 共享 nixpkgs)
- **Web 框架**: axum 0.8 (不使用 rig.rs / pingora 等高级抽象)
- **HTTP client**: reqwest 0.12 with rustls
- **协议无关**: body 在字节层面流动, secret 改写在 IR 层 (基于 `src/codec/ir`)
- **双层配置**: 声明式 `secret-guard.toml` (static, 只读) + 动态 `secret-guard.state.toml`
  (dynamic, WebUI 写回). 详尽语义见 `src/config.rs` 头部.
- **测试**: cargo-nextest + proptest (property-based) + mockito (集成测试) + Playwright (WebUI)
- **覆盖率**: cargo-llvm-cov (LLVM source-based, 行级精度). 细节见"测试策略".

## 关键不变式与工程纪律

> secret-guard 的核心职责 (转发 + Redact) 必须对任意字节流零失败.
> 围绕核心职责之外、**基于对 LLM 应用层行为模式强假设** 的附加功能
> (preview 提取 / delta 切片 / WebUI 分组渲染 / tool name 推断等) 是"尽力而为"增强,
> 绝不能因假设不成立而让请求失败或进程崩溃.

### 鲁棒性原则 (best-effort, 永不 panic)

对"尝试性解析"功能, 必须同时满足:

1. **鲁棒性处理**: 解析路径用 `Option`/`Result` 传播失败, 缺字段 / 类型不符 / 空数组 / 越界
   都返回 `None` 或空, 由调用方走 fallback (如 preview fallback 到 `method + path`,
   delta 切片 fallback 到空 `Vec`, tool name fallback 到 `'?'`).
   Rust 侧用 `?` 短路; 前端用 `|| []` / `|| '?'` 兜底.
2. **假设声明注释**: 每个解析点必须在注释中显式写出它对输入的假设
   (如 "假设 messages 数组中 user 在 assistant 之前"), 以及假设不成立时的降级行为.

已实践位置: `web::api::extract_preview_and_model` (preview 提取),
`dag::extract_delta_messages` (delta 切片), `index.html::toolNameOfRound` (tool name 推断).

### 视图正确性确保机制 (View-Correctness Discipline)

当用视图 / 引用 / 派生字段替代原始数据存储 (典型场景: 内存优化、去重、lazy 派生) 时:

1. **先断言后删除**: 删除原始数据前, 必须用 `assert_eq!(derived_view, original_data)` 断言两者
   相等 (或写专项测试覆盖). **禁止**仅凭"视图逻辑应该对"就删除原始数据.
2. **断言需有 feature flag 守护**: 对热路径断言用 `#[cfg(feature = "consistency-check")]`
   包裹, 避免生产开销但保留 CI 守卫 (项目已有此 feature 先例).
3. **原始数据是核心功能的真相**: secret-guard 的核心职责是转发 + Redact 的字节准确性.
   任何"派生视图更优雅"的诱惑都不能凌驾于数据准确性之上.

已实践位置: `redactions` 字段从 RedactionMap 派生 (`web/api.rs`)、
`resp_parsed` 从 StreamScan 累积 (`proxy.rs`). 后续 Phase B 删除 parent.response 时
必须走此流程.

### C3 前缀缓存友好性 (经济性契约)

Redact 不应无必要地改变 request body 的字节内容, 避免破坏 LLM Provider 侧的前缀缓存命中
(前缀缓存是 byte-exact 的, 历史 message 中 mock 字节变化会导致从该 message 起的整个前缀
缓存失效, 增加用户的 token 费用负担). 实现: per-request seed 驱动整个 RedactionMap,
保证同一 policy + 同一上下文 → 同一 mock. 详尽契约 (C1-C6) 见 `src/redact.rs` 头部
与 `src/mock.rs` 头部.

## 前端不变量 (UI Invariants)

> 这两条是**跨 web/dag/index.html 的强不变量**, 任何渲染优化或内存重构不得违反.

### I1 — 气泡数 == 上下文数组长度

会话详情页 (timeline) 渲染的 Bubble 数量, 必须等于该 Node 对应 HTTP 请求的 IR messages
数组长度. 任何渲染优化 (折叠、合并、视图派生) 不得改变此等式.

### I2 — sidebar 条目数 == HTTP 请求数

左边栏每个一级条目 (Session) 下, 二级 + 三级条目总数, 必须等于归属该 Session 的 HTTP 请求
数 (即 DAG 中以该 Session 叶子为终点的链上 Node 数).

**回归守卫**: 这两条不变量由 `tests/webui/im-ui.spec.ts` 守卫. 改前端渲染逻辑或后端
delta 切片时, 必须同步跑 `just check-webui`.

## 路由策略 (核心契约)

URL = `/{proto_short}/{provider_id}/*path`. 同时编码 ingress 协议与目标 provider,
为未来跨协议转换预留钩子.

| 路径 | 含义 |
|---|---|
| `/` | Web UI (主入口) |
| `/__sg`, `/__sg/*` | Web UI + JSON API (向后兼容旧入口) |
| `/{o\|a\|g\|l}/{name}` | forward, rest = "/" |
| `/{o\|a\|g\|l}/{name}/{*rest}` | forward, rest 含前导 `/` |
| 其他 | 404 (不再 catch-all 透传) |

`proto_short` 简写映射 (单一事实来源: `Protocol::ALL`):
- `o` = OpenAI, `a` = Anthropic, `g` = Gemini, `l` = oLLama

错误语义:
- 未知 protocol 简写 → 404 `not_found`
- 未知 provider id → 404 `not_found`
- 禁用 provider (`enabled = false`) → 503 `unavailable`
- 跨协议 + `stream=true` → 501 (流式跨协议翻译尚未接入 dispatch)
- Gemini/Ollama 跨协议 → 501 (codec 未覆盖)

详尽的 dispatch 路径选择 (同协议透传 / IR 路径 / 跨协议翻译) 与 fan_out 三路径见
`src/proxy.rs` 头部.

## 模块概览

> 每个模块的**详尽契约**在对应位置. 这里只给一句话职责 + 指针.

| 模块 | 职责 (一句话) | 详尽契约位置 |
|---|---|---|
| `main.rs` / `cli.rs` / `lib.rs` | 二进制入口 + CLI 参数 schema | 文件头部 `//!` |
| `config.rs` | 双层配置 schema + `DynamicTable<T>` 泛型 + 持久化 | 文件头部 `//!` (覆盖 OverrideMode / CRUD / Effective source / 跨表并发) |
| `provider.rs` | Provider 实体 + Effective view + api_key 两来源 | 文件头部 `//!` |
| `secrets.rs` | SecretEntry 实体 + Effective view + value 两来源 | 文件头部 `//!` |
| `mock.rs` | MockStrategy 两维度 (初始值 + 生成策略) + 确定性 seed | 文件头部 `//!` (C3 根基) |
| `dag.rs` | ConversationDAG 内容寻址存储 (BlockPool + Node + Merkle) | 文件头部 `//!` + `docs/design/conversation-dag.md` |
| `record.rs` | ForwardRecord (web 层 DTO, 从 DAG Node 派生) | 文件头部 `//!` |
| `redact.rs` | RedactionMap + redact/restore pipeline + 形式化契约 C1-C6 | 文件头部 `//!` |
| `codec/` | 跨协议 IR + Reader/Writer trait + StreamTranslate | **`src/codec/AGENTS.md`** |
| `proxy.rs` | dispatch 路径选择 + fan_out 三路径 + Provider 鉴权 | 文件头部 `//!` |
| `web/` | JSON API + 单页 WebUI | **`src/web/AGENTS.md`** |
| `server.rs` | router 装配 + 双层状态注入 + graceful shutdown | 文件头部 `//!` |

> `ProviderTable` 与 `SecretTable` 是 `DynamicTable<T>` (`src/config.rs`) 的类型别名,
> 通用合并 / CRUD / 持久化算法都在 config.rs; 各模块只补充类型特定的 EffectiveView
> 映射与 validate 钩子.

## 配置模型 (双层: Static + Dynamic) — 概览

| 文件 | 角色 | 谁写 | 进入 git? |
|---|---|---|---|
| `secret-guard.toml` | **声明式 (static)** 配置: providers / secrets / server. 进程内只读. | 用户手写 | ✅ 推荐 |
| `secret-guard.state.toml` | **动态 (dynamic)** 状态: WebUI 编辑结果 + 对 static 项的 decision. 删除即可重置. | 程序自动 | ❌ 推荐 .gitignore |

合并语义 (OverrideMode: Default / PreferStatic / Disabled)、Effective source 4 种、
CRUD 操作语义、DynamicTable 持久化策略、跨表并发安全的详尽描述见 `src/config.rs` 头部.

Secret / Provider 的两种 value 来源 (`value`/`value_file`、`api_key`/`api_key_file`)
及其 fail-fast vs 热路径差异, 见 `src/secrets.rs` 与 `src/provider.rs` 头部.

## 开发流程

```bash
# 一次性环境
nix develop --impure      # 进入 devShell

# 一键 check (fmt + clippy + machete + nextest + doctest)
just check

# 一键 check 含覆盖率插桩 (CI 用, 会先 cargo clean target/debug 控制磁盘峰值)
just check --coverage

# 覆盖率报告 (HTML 写到 coverage/html/, 需在 devShell 内)
just coverage-html

# WebUI 回归测试 (Playwright)
just check-webui

# 开发热加载
just dev                  # cargo watch -x run

# 手动测试 — 启动 server (需要先在 secret-guard.toml 配置 [[providers]])
cargo run -- run --port 18787
# state.toml 路径默认从 config 派生: secret-guard.toml → secret-guard.state.toml
# 浏览器: http://127.0.0.1:18787/
# OpenAI SDK 配置: base_url = http://127.0.0.1:18787/o/<provider-id>
```

### CI (Forgejo Actions)

CI 配置在 `.forgejo/workflows/ci.yml`, 触发条件: `push` + `pull_request` +
`workflow_dispatch`. 去重逻辑: PR 事件总是跑; push 仅 master 跑.

CI 流程 (测试集只跑一次):
1. **Check + coverage data**: `just check --coverage` (fmt + clippy + machete + doctest + 测试,
   用 `cargo llvm-cov nextest` 插桩).
2. **Coverage gate**: `just coverage-gate` (只做 report, 读上一步 profdata, 不重跑测试).

**磁盘峰值控制**: forgejo-runner-vm 根文件系统是 tmpfs (~3.9GB). `just check --coverage`
在 coverage 编译前 `cargo clean` 释放 `target/debug`, 实测峰值降到 ~1.4GB.

**commit status context**: `ci / check (pull_request)` 或 `ci / check (push)`
(workflow `name: ci` + job_id `check`; **禁止改 workflow name 或 job_id** — 会改变
context 破坏门禁). branch protection status check 规则 `ci / check (*)` 用通配符覆盖两种事件.

**checkout 直接用 git + SSH** (不用 `actions/checkout`): forgejo 禁用 git over HTTPS,
内置 SSH 在端口 5522. workflow 用 `ssh://` URL clone, host key 用 `ssh-keyscan` 动态获取.
依赖 repo-level secret `DEPLOY_KEY`.

### 客户端使用示例

OpenAI Python SDK:
```python
from openai import OpenAI
client = OpenAI(
    base_url="http://127.0.0.1:18787/o/openai-main",
    api_key="ignored",  # 由 provider 配置覆盖
)
```

Anthropic Python SDK:
```python
from anthropic import Anthropic
client = Anthropic(
    base_url="http://127.0.0.1:18787/a/anthropic-main",
    api_key="ignored",  # 由 provider 配置覆盖
)
```

## 测试策略

| 层级 | 工具 | 示例 |
|---|---|---|
| 单元 (纯函数) | `#[test]` | `provider::tests::protocol_short_roundtrip` |
| Property-based | `proptest` | `redact::tests::prop_round_trip_identity` |
| 集成 (端到端) | `mockito` + `axum::serve` | `tests/integration.rs::forwards_streaming_sse` |
| WebUI 回归 | Playwright (TypeScript) | `tests/webui/im-ui.spec.ts` (守卫前端不变量 I1/I2) |
| 覆盖率 | cargo-llvm-cov (LLVM source-based) | `just coverage-html` |

`mockito::Matcher` 在 1.x 没有 `String` 变体, 用 `Exact` 或 `Json` / `PartialJson`.

### 覆盖率工具 (`cargo-llvm-cov`)

集成 cargo-nextest. 工具链与 `LLVM_COV` / `LLVM_PROFDATA` 环境变量由 devShell 注入
(nix rust toolchain 不带 llvm-tools-preview 组件, 见 `flake.nix`). 所有 coverage 命令
需在 `nix develop` 内执行.

- `just coverage`: 终端摘要表格.
- `just coverage-gate`: 覆盖率门禁 (CI 用, 双阈值).
- `just coverage-html`: HTML 报告 → `coverage/html/index.html`.
- `just coverage-lcov`: LCOV 报告 → `coverage/lcov.info`.

产物默认写到 `target/llvm-cov-target/` 与 `coverage/` (均已 .gitignore).
门禁阈值见 justfile (`COVERAGE_MIN_LINES` / `COVERAGE_MAX_UNCOVERED`).

## 部署

NixOS + sops-nix 部署的两种姿势 (LoadCredential / 直接路径) + secret 批量注入方案,
见 **`docs/deployment-nixos.md`**.

> 路径约定见上方"路由策略"表格; `/__sg` 子路由细节 (slash redirect / 未匹配 404 no-forward)
> 见 `src/web/AGENTS.md`.

## 已知限制 (MVP)

- **跨协议 + 流式响应**: OpenAI ⇄ Anthropic 跨协议时 `stream=true` 返回 501
  (StreamTranslate 已实现跨协议翻译, 但尚未接入 dispatch).
- **C5 是概率性契约**: Auto 模式 mock 极大概率不含 real_secret ≥4 字符子串
  (碰撞概率 ≈ 2^-32). `proptest-regressions/redact.txt` 记录历史失败种子.
- **同协议 + Redact 失去 byte-exact**: reader → redact_ir → writer 重序列化, 字段顺序 /
  空字符串归一化可能让 wire 字节略变, 但语义等价. 同协议 + 无 Redact 路径仍 byte-exact.
- **流式 + Redact + 非 2xx 上游错误**: SSE 错误流不是单个 JSON, parse 失败时 fallback
  原样返回 (无 restore), 客户端可能看到 mock.
- **跨协议 ingress 的 timeline delta 切片可能错位**: OpenAI writer 会把 Anthropic 风格的
  混合 Text+ToolResult user 消息拆成 (1+N) 条 wire messages, 导致 `req_body_raw` 的
  messages 数 > IR messages 数. `extract_delta_messages` 切片时跨协议路径的 start 偏小,
  delta 可能包含前序轮消息. 同协议路径不受影响. 详见 `src/web/AGENTS.md`.
- static config 的 `[server]` 段仅在启动时读取一次, WebUI 改 host/port 不会生效.
- WebUI 编辑 provider 时 api_key 始终要求重输 (无法保留旧值).

## 后续工作 (非 MVP 范围)

- **跨协议流式响应翻译**: 在 `cross_proto_forward` 检测 stream=true 时接入
  `StreamTranslate::new(ingress, egress)` 而非返回 501.
- **更多协议**: Gemini / Ollama / Bedrock / Cohere / OpenAI Responses API.
  新增协议只需实现 Reader + Writer trait (~200 行), 不动 dispatch.
- **redact 性能优化**: `redact_ir` 与 `StreamingRestorer::find_safe_end` 对每个 secret
  做全字符串扫描 (K * n 复杂度). 长期用 Aho-Corasick 多模式匹配.
- **redact 测试基线**: criterion bench 测典型场景, 留作回归基线.
- mock_secret 的 category-aware 默认生成 (Password/ApiKey/Cookie 等格式感知).
- 配置热加载; 测试覆盖率自动上报 + fuzzing (cargo-fuzz).
- Web UI 编辑 provider 时保留 api_key (改用 `null` 表示不更新).
