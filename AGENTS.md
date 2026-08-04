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

## 数据流契约 (总览)

> **本节是 normative (尺子), 不是 descriptive (描述现状)**. 定义 secret-guard 数据正确性的理想目标.
> 完整契约 (10 个属性域, ~100 条可测 property) 见 **`docs/design/contracts.md`**.

数据流分三个信任域, 域间有单向承诺:

```
域 A (转发链: client ↔ upstream)  ──字节正确性是根基──►  域 B (派生链: DAG/webapi)
                                                         │
                                                         ▼
                                                  域 C (渲染层: WebUI DOM)
```

**最强契约 FWD-1 (透明中继 byte-exact)**: secret-guard 是客户端与上游之间的字节级透明中继 — **对 wire 的唯一合法修改是 real↔mock 替换**, 除此之外的任何字节差异都是 bug. 两个半段 (请求侧 / 响应侧) 经 normalize (canonical JSON) 后 byte-exact. 这条契约把"难以测的语义等价"转换为"可机械验证的字节相等".

**契约编号速查** (段前缀 → 域, 详见 `docs/design/contracts.md` §0.2):

| 前缀 | 域 | 收纳现有契约 | 一句话职责 |
|---|---|---|---|
| `FWD-*` | A | codec INV-1/2/5, proxy DoD | 透明中继 byte-exact + codec round-trip + HTTP 透传 + 路由 + 鉴权 |
| `RED-*` | A | **C1-C7** (redact/mock) | Redact/Restore 可逆双射 + 不泄漏 + 前缀缓存友好 |
| `STR-*` | A | codec INV-4 + 新增 | 流式 SSE 边界 + 累积 + 错误降级 + reader 多 tool_call 索引 |
| `CDAG-*` | B | **DAG INV-1..5** + 新增 | 内容寻址 + Merkle + refcount + 孤儿节点 + session 稳定 |
| `DTO-*` | B | 新增 | WebUI DTO 派生 (redactions / resp_parsed / preview / delta / title) |
| `CFG-*` | B | 新增 | 双层配置合并 / CRUD / 持久化 / 并发 |
| `SEC-*` | 跨 | 新增 | GET 不泄漏 / panic 不泄漏 / headers 脱敏 / 本地监听 |
| `ROB-*` | 跨 | 鲁棒性原则 | best-effort 永不 panic + 假设声明注释必备 |
| `VIEW-*` | 跨 | 视图正确性机制 | 先断言后删除 + 派生字段 consistency-check 覆盖 |
| `UI-*` | C | **I1-I3** + 新增 | 气泡数 / sidebar 条目数 / DOM 顺序 / reconciliation / drawer |

**核心纪律** (详见 `docs/design/contracts.md` §0.3 Property 设计原则 + §0.4 冗余覆盖原则 + §0.5 漂移处理流程):
- Property 描述**外部可观察行为**, 不依赖内部实现 (避免过拟合).
- 优先 **byte-exact (normalize 后)** 而非语义等价 (可机械验证, 无需 case-by-case 定义"语义").
- **proptest 生成器覆盖度也作为契约要求** (历史 bug 多次出现 property 存在但生成器太窄致漏测).
- **端到端契约 (FWD-1) 与其分解契约 (FWD-2 / RED-6/7) 必须分别独立形式化、独立可测** (测试原则是不信任其他代码).
- 契约编号一经分配永不变更 (删除作废不重用).
- 代码与契约冲突时, **契约不能擅自修改, 必须经过人工授权** (详见 `docs/design/contracts.md` §0.5).

## 关键不变式与工程纪律

> secret-guard 的核心职责 (转发 + Redact) 必须对任意字节流零失败.
> 围绕核心职责之外、**基于对 LLM 应用层行为模式强假设** 的附加功能
> (preview 提取 / delta 切片 / WebUI 分组渲染 / tool name 推断等) 是"尽力而为"增强,
> 绝不能因假设不成立而让请求失败或进程崩溃.

### 鲁棒性原则 (best-effort, 永不 panic) → ROB-* 契约

对"尝试性解析"功能, 必须同时满足:

1. **鲁棒性处理**: 解析路径用 `Option`/`Result` 传播失败, 缺字段 / 类型不符 / 空数组 / 越界
   都返回 `None` 或空, 由调用方走 fallback (如 preview fallback 到 `method + path`,
   delta 切片 fallback 到空 `Vec`, tool name fallback 到 `'?'`).
   Rust 侧用 `?` 短路; 前端用 `|| []` / `|| '?'` 兜底.
2. **假设声明注释**: 每个解析点必须在注释中显式写出它对输入的假设
   (如 "假设 messages 数组中 user 在 assistant 之前"), 以及假设不成立时的降级行为.

已实践位置: `web::api::extract_preview_and_model` (preview 提取),
`dag::extract_delta_messages_from_raw` (delta 切片).
(注: 前端 `toolNameOfRound` 已删除, tool name 推断迁移到后端 `extract_preview_and_model`,
由 `prop_preview_never_panics` 统一守卫, 详见 `docs/design/contracts.md` §8 ROB-1.)

> **例外 — DAG 核心数据结构不用 best-effort**: `dag::BlockPool::intern` 的 collision check
> 用 `assert!` (非 `debug_assert!`), release 也 panic. 理由: collision 属哈希函数 bug,
> 静默覆盖会让两个不同 block 共享 hash 引发难定位的数据损坏, panic 是更优选择. 详见
> **CDAG-6** 契约 (`docs/design/contracts.md` §4).

### 视图正确性确保机制 (View-Correctness Discipline) → VIEW-* 契约

当用视图 / 引用 / 派生字段替代原始数据存储 (典型场景: 内存优化、去重、lazy 派生) 时:

1. **先断言后删除**: 删除原始数据前, 必须用 `assert_eq!(derived_view, original_data)` 断言两者
   相等 (或写专项测试覆盖). **禁止**仅凭"视图逻辑应该对"就删除原始数据.
2. **断言需有 feature flag 守护**: 对热路径断言用 `#[cfg(feature = "consistency-check")]`
   包裹, 避免生产开销但保留 CI 守卫 (项目已有此 feature 先例).
3. **原始数据是核心功能的真相**: secret-guard 的核心职责是转发 + Redact 的字节准确性.
   任何"派生视图更优雅"的诱惑都不能凌驾于数据准确性之上.

已实践位置: `redactions` 字段从 RedactionMap 派生 (`proxy/record.rs::assert_redactions_match_map`)、
`preview`/`model` 从 `req_body_raw` 派生 (`proxy/record.rs::assert_preview_model_match_source`)、
`resp_parsed` (非流式) 从上游响应字节经 codec reader 派生 (`proxy/record.rs::assert_resp_parsed_matches_source_nonstream`)、
`session.title` 从 root node preview 派生 (`dag.rs::assert_session_title_matches_root_preview`)、
`resp_parsed` (流式) 从 StreamScan 累积 (`proxy/fan_out.rs`, Phase A 已删除原始 SSE 字节, 派生与源物理分离, 暂不守卫).
后续 Phase B 删除 parent.response 时必须走此流程.

### C3 前缀缓存友好性 (经济性契约) → RED-3 契约

Redact 不应无必要地改变 request body 的字节内容, 避免破坏 LLM Provider 侧的前缀缓存命中
(前缀缓存是 byte-exact 的, 历史 message 中 mock 字节变化会导致从该 message 起的整个前缀
缓存失效, 增加用户的 token 费用负担). 实现: per-request seed 驱动整个 RedactionMap,
保证同一 policy + 同一上下文 → 同一 mock. 详尽契约 (C1-C7) 见 `src/redact.rs` 头部
与 `src/mock.rs` 头部.

## 前端不变量 (UI Invariants) → UI-1..UI-6 契约

> 以下条目是**跨 web/dag/index.html 的强不变量**, 任何渲染优化或内存重构不得违反.
>
> **编号映射**: AGENTS.md 的 `I*` 是 contracts.md `UI-*` 的前身 (历史编号).
> `I1=UI-1`, `I2=UI-2`, `I3=UI-3`, `I4=UI-6 的 selectedRound 子属性`, `I5=UI-6`.
> contracts.md 收录并扩展为 UI-1..UI-6, 以 contracts.md 为 SSOT; 此处保留 I* 编号便于历史 grep.
### I1 — 气泡数 == 上下文数组长度

会话详情页 (timeline) 渲染的 Bubble 数量, 必须等于该 Node 对应 HTTP 请求的 IR messages
数组长度. 任何渲染优化 (折叠、合并、视图派生) 不得改变此等式.

### I2 — sidebar 条目数 == HTTP 请求数

左边栏每个一级条目 (Session) 下, 二级 + 三级条目总数, 必须等于归属该 Session 的 HTTP 请求
数 (即 DAG 中以该 Session 叶子为终点的链上 Node 数).

### I3 — timeline 轮次 DOM 顺序 == 数据顺序 (oldest-first)

会话详情页 (timeline) 中 `.tl-round` 在 DOM 里的出现顺序, 必须与 `state.timelineRecords`
完全一致 — 即 oldest-first (顶部最老, 底部最新, 与对话流时间线方向一致). 实现层面的陷阱
(anchor 从 DOM 末尾 vs 最前起步) 见 `reconcileTimelineRounds` 函数头部注释 (历史教训).

### I4 — `.tl-round.selected` 类 == `state.selectedRound` SSOT

timeline 中带 `.selected` 类的 `.tl-round` 集合, 必须严格等于 `{state.selectedRound}`
(恰好一个 rid 匹配, 其余均不带; `state.selectedRound = null` 时全无). 该一致性由
`updateSelectedRoundClass` 在 `selectRound` 入口显式同步. 历史 bug: 点击 dot/round-item
时只调 `highlightRound` (负责 `.flash` 闪烁动画), 不重建 DOM, 而
`reconcileTimelineRounds` 复用已有节点时也不更新 class, 导致 `.selected` 滞留在旧轮次
与 `.flash` 错位.

### I5 — timeline 滚动状态机: followMode 是视口位置的纯派生 (↔ UI-6)

timeline 的 follow/pinned 状态由 **视口距底部距离** 机械推导 (SSOT), 不由 "最近点了什么"
显式动作决定. 形式化: `state.timelineFollow == isNearBottom()`, 在每次 scroll 事件
(RAF 合并) + 每次新内容追加后由 `syncFollowMode()` 重算.

- **follow** (距底 ≤ `NEAR_BOTTOM_PX` ≈ 100px): 新 round 到达 → `scrollTimelineToBottomForce`
  锁定视口 (预留 drawerH+GAP, 末轮 request 完整可见, 不被 drawer 遮挡); `unreadCount` 清零.
  **follow 闭合不变量**: follow 状态在新 round 插入下必须保持 (不被翻转, 末轮 request 不被
  drawer 遮挡). 短内容场景下 `updateResponseDrawerLayout` 自动压缩 drawer 保障此不变量;
  几何失效区间 + 实现细节见 contracts.md UI-6 与 src/web/AGENTS.md.
- **pinned** (距底 > `NEAR_BOTTOM_PX`): 新 round 到达 → 不滚动, `unreadCount` 累加,
  `#unread-badge` 浮出显示 "↓ N".

**follow/pinned 视觉指示 (WebUI 反馈1)**: drawer 顶部边缘颜色随状态切换 — follow 淡灰近不可见,
pinned accent (mauve) 细条 (`.pinned` 类, 配色与 unread badge 一致), 用户可一眼区分当前状态.

**`selectedRound` 与 followMode 解耦 (方案 X)**: `selectedRound` 是 "用户最后显式关注的轮次",
**不随 follow 自动推进** (避免 Response 抽屉布局抖动 + `.flash` 反复触发). 仅在 "进入 follow 的显式动作"
(点 Session / 点 unread badge / 初次 `loadTimeline`) 时重置 selected 到最新轮 (`.selected` 持续
高亮, 不触发 `.flash` — 因为这些动作用 `scroll:'bottom'` 滚到底, 与 `highlightRound` 的 70% 定位
冲突). follow 期间新消息到达: selected 不变.

**回归守卫**: 这五条不变量由 `tests/webui/im-ui.spec.ts` 守卫. 改前端渲染逻辑或后端
delta 切片时, 必须同步跑 `just check-webui`.

## 路由策略 (核心契约)

URL = `/{proto_short}/{provider_id}/*path`. 同时编码 ingress 协议与目标 provider,
为未来跨协议转换预留钩子.

| 路径 | 含义 |
|---|---|
| `/` | Web UI (主入口) |
| `/__sg`, `/__sg/*` | Web UI + JSON API (向后兼容旧入口) |
| `/{o\|a\|g\|l\|r}/{name}` | forward, rest = "/" |
| `/{o\|a\|g\|l\|r}/{name}/{*rest}` | forward, rest 含前导 `/` |
| 其他 | 404 (不再 catch-all 透传) |

`proto_short` 简写映射 (单一事实来源: `Protocol::ALL`):
- `o` = OpenAI (Chat Completions), `a` = Anthropic, `g` = Gemini, `l` = oLLama, `r` = Responses (OpenAI Responses API)

错误语义:
- 未知 protocol 简写 → 404 `not_found`
- 未知 provider id → 404 `not_found`
- 禁用 provider (`enabled = false`) → 503 `unavailable`
- 跨协议 + `stream=true` → 501 (流式跨协议翻译尚未接入 dispatch)
- **Responses + Redact + `stream=true`** → 501 (Responses 流式 SSE 事件翻译未实现; 见 "已知限制")
- Gemini/Ollama 跨协议 → 501 (codec 未覆盖)

详尽的 dispatch 路径选择 (同协议透传 / IR 路径 / 跨协议翻译) 与 fan_out 三路径见
`src/proxy/mod.rs` 头部 (拆分为模块目录, 各子路径实现在 `same_proto.rs` / `cross_proto.rs` /
`fan_out.rs`); 路由相关的可测 property 见 `docs/design/contracts.md` **FWD-5**.

## 模块概览

> 每个模块的**详尽契约**在对应位置. 这里只给一句话职责 + 指针.

| 模块 | 职责 (一句话) | 详尽契约位置 |
|---|---|---|
| `main.rs` / `cli.rs` / `lib.rs` | 二进制入口 + CLI 参数 schema | 文件头部 `//!` |
| `auth/` | OIDC 登录 (WebUI) + 本地 API key (SDK 转发) + session | `auth/mod.rs` 头部 `//!` |
| `config.rs` | 双层配置 schema + `DynamicTable<T>` 泛型 + 持久化 | 文件头部 `//!` (覆盖 OverrideMode / CRUD / Effective source / 跨表并发) |
| `provider.rs` | Provider 实体 + Effective view + api_key 两来源 | 文件头部 `//!` |
| `secrets.rs` | SecretEntry 实体 + Effective view + value 两来源 | 文件头部 `//!` |
| `mock.rs` | MockStrategy 两维度 (初始值 + 生成策略) + 确定性 seed + `[redact] global_mock_prefix` 注入 | 文件头部 `//!` (C3 根基) |
| `dag.rs` | ConversationDAG 内容寻址存储 (BlockPool + Node + Merkle) | 文件头部 `//!` + `docs/design/conversation-dag.md` |
| `derive.rs` | 从 request body 派生 preview/model/text 的字节级提取 (域 B 派生链, ROB-1 永不 panic) | 文件头部 `//!` (含 "为什么不在 web::api" 归属论证) |
| `error.rs` | 统一应用错误类型 `AppError` (转发链 + 鉴权层共用, 不反向依赖) | 文件头部 `//!` (含与 `web::api::ApiError` 分工) |
| `record.rs` | ForwardRecord (web 层 DTO, GET /records/{id} 响应 shape) | 文件头部 `//!` |
| `redact.rs` | RedactionMap + redact/restore pipeline + 形式化契约 C1-C7 | 文件头部 `//!` |
| `util.rs` | 集中的哈希工具 (`hash64` SipHash 单值入口) | 文件头部 `//!` |
| `codec/` | 跨协议 IR + Reader/Writer trait + StreamTranslate (OpenAI / Anthropic / Responses) | **`src/codec/AGENTS.md`** |
| `proxy/` | dispatch 路径选择 + fan_out 三路径 + Provider 鉴权 (拆分为 mod/helpers/auth/record/same_proto/cross_proto/fan_out 子模块) | `src/proxy/mod.rs` 头部 `//!` |
| `web/` | JSON API (`api.rs`) + 响应 DTO (`dto.rs`: SessionView/NodeView/.../SyncSnapshot) + 单页 WebUI | **`src/web/AGENTS.md`** |
| `server.rs` | router 装配 + 双层状态注入 + graceful shutdown | 文件头部 `//!` |

> `ProviderTable` 与 `SecretTable` 是 `DynamicTable<T>` (`src/config.rs`) 的类型别名,
> 通用合并 / CRUD / 持久化算法都在 config.rs; 各模块只补充类型特定的 EffectiveView
> 映射与 validate 钩子.

## 配置模型 (双层: Static + Dynamic) — 概览

| 文件 | 角色 | 谁写 | 进入 git? |
|---|---|---|---|
| `secret-guard.toml` | **声明式 (static)** 配置: providers / secrets / server / redact / auth. 进程内只读. | 用户手写 | ✅ 推荐 |
| `secret-guard.state.toml` | **动态 (dynamic)** 状态: WebUI 编辑结果 + 对 static 项的 decision. 删除即可重置. | 程序自动 | ❌ 推荐 .gitignore |

合并语义 (OverrideMode: Default / PreferStatic / Disabled)、Effective source 4 种、
CRUD 操作语义、DynamicTable 持久化策略、跨表并发安全的详尽描述见 `src/config.rs` 头部.

Secret / Provider 的两种 value 来源 (`value`/`value_file`、`api_key`/`api_key_file`)
及其 fail-fast vs 热路径差异, 见 `src/secrets.rs` 与 `src/provider.rs` 头部.

## 开发流程

```bash
# 一次性环境
nix develop --impure      # 进入 devShell

# 一键 check (fmt + clippy + machete + nextest)
# 注: doctest 当前禁用 (唯一 doctest 被 ignored), 需要时在 justfile 取消注释.
just check

# 一键 check 含覆盖率插桩 (CI 用)
just check --coverage

# 覆盖率报告 (HTML 写到 coverage/html/, 需在 devShell 内)
just coverage-html

# WebUI 回归测试 (Playwright)
just check-webui

# 开发热加载
just dev                  # cargo watch -x run (重启进程)
just dev-test             # cargo watch -x nextest run (TDD 红绿循环)

# 依赖审查 (devShell 内)
just audit                # cargo audit (RUSTSec CVE)
just deny                 # cargo deny (license + bans + advisory 二次审查)
just typos                # typos-cli (拼写检查)

# 手动测试 — 启动 server (需要先在 secret-guard.toml 配置 [[providers]])
cargo run -- run --port 18787
# state.toml 路径默认从 config 派生: secret-guard.toml → secret-guard.state.toml
# 浏览器: http://127.0.0.1:18787/
# OpenAI SDK 配置: base_url = http://127.0.0.1:18787/o/<provider-id>
```

### CI (Forgejo Actions)

CI 配置在 `.forgejo/workflows/ci.yml`, 触发条件 `push` + `pull_request` +
`workflow_dispatch`. 双重去重: 事件去重 (push 仅 master, PR 总是跑) + 内容去重
(skip-if-passed, ff-merge 后同 SHA 不重跑). `check` job 测试集只跑一次, 顺序为
checkout → diff 报告 (PR, 非阻塞) → consistency-check → check+coverage → coverage-gate →
file-size → WebUI (非阻塞) → cargo audit (非阻塞) → cargo-deny → typos.
(checkout 策略 / 缓存复用 / 并发假设 / 评论写回 / 各 step 升级路径见 docs/ci.md.)

> CI 实现细节 (checkout 策略 / 缓存复用 / 并发假设 / 评论写回 / 各 step 升级路径) 见
> **docs/ci.md**.

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
| WebUI 回归 | Playwright (TypeScript) | `tests/webui/im-ui.spec.ts` (守卫前端不变量 UI-1..UI-6) |
| 性能基线 | criterion | `benches/redact.rs` (redact_ir / StreamingRestorer 3 场景) |
| 覆盖率 | cargo-llvm-cov (LLVM source-based) | `just coverage-html` |

`mockito::Matcher` 在 1.x 没有 `String` 变体, 用 `Exact` 或 `Json` / `PartialJson`.

### TDD 与可选测试 (ignored tests)

> 为"先写测试、后写实现"的 TDD 流程提供不阻塞 CI 的机制. 关键事实: **`#[ignore]` 是
> libtest 的运行期属性, rustc 编译器不认识它** — 因此 ignored 测试**默认就参与每次
> `cargo build --tests` / `cargo nextest run` 的编译**, 编译漂移已被 `just check` 的
> clippy + nextest 编译阶段守住, 无需额外 CI step.

**ignore reason 命名规范** (两种合法形态):
1. `<标识符>: <一句话说明>` — 标识符为可追踪引用 (契约编号 `L8` / `RED-X` / issue 号 `#42`).
2. `待 <功能> ...` — 长期搁置项, 无契约/issue 编号, 必须在 "## 已知限制" 或
   "## 后续工作" 有对应条目.
现有先例: `L8: usage ...` (形态1)、`待 Gemini codec 实现 ...` (形态2).

**按"被测代码是否已存在"选型**:

| 场景 | 机制 | 适用条件 |
|---|---|---|
| **A: 被测函数已存在, 行为还没对** | `#[ignore = "..."]` | 最常见. 例: `redact_ir` 已实现但某 property 未满足. |
| **B: 被测函数尚未存在** | stub (`todo!()`) + `#[ignore]` | 真正的"测试先行". |
| **B 例外: 涉及新依赖/新模块** | `#[cfg(feature = "todo-X")]` + `[features] todo-X` | stub 若引用未实现的依赖, 会迫使该依赖提前进 Cargo.toml 拖慢默认编译; feature gate 彻底隔离. |

**TDD 循环** (场景 B 为例):
1. 写 stub 函数 (`todo!()`) + 测试, 测试标 `#[ignore = "L8: 待实现 ..."]`
2. `just check` → 绿 (编译通过即可, 运行跳过)
3. 实现真函数, 替换 stub
4. `just test-ignored <测试名子串>` → 看红灯变绿 (如 `just test-ignored openai_response`)
5. 删除 `#[ignore]` 行 + stub → 测试进入常驻集

**日常巡检**: ignored 测试应随对应功能实现而"转正" (删除 `#[ignore]`). 长期未转正的
ignored 测试是"计划但搁置"的信号, 应在 `## 已知限制` 或 `## 后续工作` 中有对应条目.
ignored 测试默认不运行故不计入覆盖率, 转正后自动纳入.
用 `cargo nextest list --run-ignored=only` 列出当前所有 ignored 测试做走查.

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

### `rust-diff-analyzer` (PR diff 拆解 + 文件长度门禁)

区分 diff 中的 prod 代码 vs test 代码, 用于 review 时判断真实膨胀 (测试代码增加不是膨胀,
prod 代码大量增加才需警惕). 工具用 syn AST 解析, 自动识别 `#[cfg(test)]` / `#[test]` /
`tests/` 目录, 不依赖命名约定. 不在 nixpkgs, devShell 用 lazy `cargo install` wrapper
封装 (首次 `just diff-loc` 编译到 `${XDG_CACHE_HOME:-~/.cache}/secret-guard-tools/`, 后续命中).

两处复用 (SSOT):
- `just diff-loc`: 对 `master...HEAD` 跑 human 格式报告 (本地终端用).
- `just check-file-size`: 对每个 .rs 做完整 AST 分类, 只统计 prod 行数 (排除 test),
  双阈值门禁 (WARN 500 软提醒 / MAX 1600 硬阻断). fail-closed: 工具失败时 exit 1 不放行.
- CI: PR 事件的 diff 拆解 + 文件长度门禁都复用此工具 (diff 步 `continue-on-error: true`
  真正非阻塞), 详见 **docs/ci.md**.

### cargo-audit (CVE 监控)

依赖 CVE 扫描 (`cargo audit`). 项目级配置在 `.cargo/audit.toml`, 当前显式忽略项:

- **RUSTSEC-2023-0071** (rsa Marvin Attack): secret-guard 是 OIDC 客户端, 仅走 rsa 公钥
  验证路径, 不持有 RSA 私钥, 不在攻击面. 上游无修复版本. 详尽论证见 `.cargo/audit.toml`.

**走查纪律**: `.cargo/audit.toml` 的 ignore 项每半年走查一次; 上游若已修复, 立即移除忽略项
并升级依赖. 走查触发 = `just audit` 时人工核对 (CI 每 PR 跑, 但 ignore 项不报错, 易遗忘).

### cargo-deny (license + bans + advisory 二次审查)

`cargo audit` 只覆盖 RUSTSec CVE; `cargo-deny` 额外覆盖 license 不兼容 / 重复 crate 多版本 /
禁止依赖 / git 源审计. 项目声明 MIT 且发布到 nixpkgs overlay, license 合规是硬约束 (引入
GPL/AGPL 等 copyleft 会污染下游). 配置在 `deny.toml`, 与 `.cargo/audit.toml` 的 `[advisories.ignore]`
保持同步 (互为冗余兜底).

- **license allow**: MIT / Apache-2.0 / BSD-* / ISC / Zlib / Unicode-* / MPL-2.0 (file-level
  copyleft, 不污染链接产物) / CC0-1.0 / CDLA-Permissive-2.0 (webpki-roots 的 CA 根证书数据协议).
  copyleft (GPL/AGPL/LGPL) 与不明 license 被 deny.
- **multiple-versions = warn**: 重复 crate 只警告不阻断. Rust 生态 duplicate 多为传递依赖
  暂态 (当前 base64/getrandom/syn/thiserror/tower-http/windows-sys 各有 2-3 版本, 已在
  "后续工作" 记录升级计划), 强制 deny 会频繁阻塞.
- **sources**: 只允许 crates.io + 本地 path 源, 禁止私有 registry / git 直链 (难审计).

CI 已升级为阻塞门禁: 当前 `deny.toml` allow 列表已实测覆盖全部依赖 license (本地全绿),
用户决策直接加门禁不设观察期. 新 license 误报出现时更新 `deny.toml` 即可 (属正常维护).

## 部署

NixOS + sops-nix 部署的两种姿势 (LoadCredential / 直接路径) + secret 批量注入方案,
见 **`docs/deployment-nixos.md`**.

> 路径约定见上方"路由策略"表格; `/__sg` 子路由细节 (slash redirect / 未匹配 404 no-forward)
> 见 `src/web/AGENTS.md`.

## 已知限制 (MVP)

- **OpenAI Responses API 支持范围**: Responses 协议 (`/r/` proto_short) 已接入 codec,
  支持 Responses ⇄ Chat Completions 跨协议翻译 (非流式) + Responses 同协议透传 + Redact (非流式).
  **不支持**: Responses 流式 SSE 事件翻译 (Responses + Redact + `stream=true` 返回 501;
  无 Redact 的同协议流式透传正常工作); Responses ⇄ Anthropic 跨协议 (返回 501);
  hosted tools (web_search/file_search/computer_use/mcp → 静默丢弃); namespace tools
  flattening; `previous_response_id` 服务端状态 (secret-guard 是 stateless 代理);
  reasoning items 的 `encrypted_content` (同协议 round-trip 也会丢失, 会破坏 reasoning chain).
- **Responses 协议的 timeline delta 为空**: Responses ingress 的 `req_body_raw` 用 `input[]`
  (而非 `messages[]`), `extract_delta_messages_from_raw` 找不到 messages 字段, 返回空 Vec.
  WebUI timeline 仍能显示 preview / role, 但不渲染增量气泡 (与跨协议 ingress 的 delta 限制一致).
- **跨协议 + 流式响应**: OpenAI ⇄ Anthropic 跨协议时 `stream=true` 返回 501
  (StreamTranslate 已实现跨协议翻译, 但尚未接入 dispatch; 迁移计划见 "后续工作").
- **C5 是实质确定性契约**: Auto 模式 mock 不含 real_secret ≥`k(L)` 字符子串
  (`k(L) = max(4, ⌈L/3⌉)`, 随 secret 长度自适应 — 短 secret 强保护, 长 secret 弱保护,
  信息泄露率上界 ~36%). gen_candidate 内置 10000 次确定性内部重试链
  (`C5_INTERNAL_RETRIES = 10_000`, safety bound), `(1e-5)^10000 = 1e-50000` 远超宇宙原子数,
  因此 C5 在 Auto 模式下实质等价于确定性契约.
  设计论据 (信息论 + 业界 secret scanner 阈值) 见 `src/mock.rs` 头部 "C5" 段落 (SSOT).
  `proptest-regressions/redact.txt` 记录历史失败种子.
- **同协议 + Redact: normalize_json 相等, 非 byte-exact**: reader → redact_ir → writer 重序列化,
  字段顺序 / 空白等无语义差异由 `normalize_json` 吸收, 语义信息通过 wire 形态元数据保留
  (见 `src/codec/AGENTS.md` "wire fidelity"). 已知搁置: 多 system messages 合并 / message-level
  extra / block-level 未知 part / response 侧 usage 字段位置 (详见 codec/AGENTS.md).
  同协议 + 无 Redact 路径仍 byte-exact.
- **流式 + Redact + 非 2xx 上游错误**: SSE 错误流不是单个 JSON, parse 失败时 fallback
  原样返回 (无 restore), 客户端可能看到 mock.
- **同协议 + Redact + 非流式 2xx + 上游响应 parse 失败**: 上游返回的 body 不是合法 JSON 或 codec
  reader 无法 parse 时 (类型不符 / 空数组 / 越界), 转发路径 fallback 为透传含 mock 的字节, 无 restore,
  客户端收到 mock. 同协议路径见 `src/proxy/fan_out.rs` (non-stream 分支), 跨协议路径见
  `src/proxy/cross_proto.rs`. 均走 best-effort 鲁棒性原则 (ROB-*), parse 失败不 panic.
- **跨协议 ingress 的 timeline delta 切片可能错位**: OpenAI writer 会把 Anthropic 风格的
  混合 Text+ToolResult user 消息拆成 (1+N) 条 wire messages, 导致 `req_body_raw` 的
  messages 数 > IR messages 数. `extract_delta_messages_from_raw` 切片时跨协议路径的 start 偏小,
  delta 可能包含前序轮消息. 同协议路径不受影响. 详见 `src/web/AGENTS.md`.
- static config 的 `[server]` / `[redact]` 段仅在启动时读取一次, WebUI 改 host/port/global_mock_prefix 不会生效.
- **DAG 孤儿节点降级**: parent 被 LRU 淘汰后, child 的 `full_request_messages` 返回 None
  (timeline 降级展示, 不 panic). 显式孤儿标记 (CDAG-7) 尚未实现.
- **auth 模块测试覆盖率 (OIDC 登录流程依赖 mock IdP)**: auth 模块的纯逻辑已覆盖
  (`apikey.rs` 100% / `middleware.rs` ~99% / `session.rs` ~98% / `mod.rs` ~99%), 含
  require_api_key 的 Authorization 剥离断言 (SEC 红线) 与 build_session_layer 的
  cookie 配置 (sg.sid + HttpOnly). 但以下部分**整体 0%**, 因强依赖外部 OIDC IdP
  (token exchange / discovery), 强行 mock 会脆弱:
  - `oidc.rs` (0%): `OidcBackend::discover` (Discovery 网络请求) / `exchange_and_verify`
    (token exchange + ID token 验证) / `authorize_url` (PKCE/nonce 生成).
    构造 `OidcBackend` 必须经过真实 Discovery, 无法用纯单测覆盖.
  - `handlers.rs` 的 OIDC 流程 (~36% 整体): `login_start` / `oauth_callback` /
    `logout` / `me` 需要 `AuthState` (含 `OidcBackend`) 或 `AuthSession` extractor,
    均经 axum-login 层 + session, 无法在不起 IdP 的前提下构造.
    (已覆盖的纯逻辑: `sanitize_next_url` 防 open-redirect + CRLF 注入, `error_response`
    JSON envelope + no-store 契约.)
  需引入 mock IdP 集成测试 (起本地 OIDC server 模拟 discovery + token endpoint + JWKS)
  才能覆盖, 当前留作后续工作. `COVERAGE_MIN_LINES` 门禁不受影响 (auth 纯逻辑提升已使
  总覆盖率上升).

## 后续工作 (非 MVP 范围)

- **跨协议流式响应翻译**: 在 `cross_proto_forward` 检测 stream=true 时接入
  `StreamTranslate::new(ingress, egress)` 而非返回 501.
- **更多协议**: Gemini / Ollama / Bedrock / Cohere / OpenAI Responses API.
  新增协议只需实现 Reader + Writer trait (~200 行), 不动 dispatch.
- mock_secret 的 category-aware 默认生成 (Password/ApiKey/Cookie 等格式感知).
- 配置热加载; 测试覆盖率自动上报 + fuzzing (cargo-fuzz).
- **auth/oidc.rs + handlers OIDC 流程的集成测试**: 起本地 mock OIDC IdP server
  (模拟 discovery + token endpoint + JWKS 签名), 覆盖 `OidcBackend::discover` /
  `exchange_and_verify` / `handlers::login_start`+`oauth_callback`+`logout`+`me`
  的完整登录流程. 当前覆盖率见 "已知限制" 对应条目.
- **依赖升级** (滞后是稳态, 非风险; Cargo.lock 锁定保证可复现构建; 触发条件满足时再升,
  默认触发条件 = CVE / 解 duplicate / 需要 feature, 各子项仅标注例外):
  - rand 0.8 → latest (0.10): 0.9/0.10 API 有 breaking (`thread_rng()` → `rng()`,
    `Rng::gen()` → `random()`), 升级时 `src/auth/apikey.rs` 需改 API
    (rand 唯一使用点; mock.rs/redact.rs 用确定性 SipHash 不调 RNG).
  - sha2 0.10 → 0.11: 注意 openidconnect 4.0.1 硬依赖 `sha2 ^0.10` (经 oauth2),
    **升级主依赖也无法解 duplicate**, 直到 openidconnect 上游升级.
  - tower-sessions 0.14 → 0.15: **需与 axum-login 同步升级**
    (axum-login 0.18 当前硬依赖 tower-sessions 0.14, 单独升会 duplicate).
  - reqwest 0.12 → 0.13: 0.13 breaking 较多 (`rustls-tls` feature 改名 `rustls`,
    rustls roots 改用 `rustls-platform-verifier`, 需验证行为);
    升级可解 tower-http 0.6.11 + 0.7 duplicate (reqwest 0.12 传递依赖 0.6).
  - criterion 0.5 → 0.8: 触发条件 = 需要新统计特性 / bench 大改时. 跨 3 个主版本 (0.6/0.7/0.8),
    若升级成本高, 评估迁移到 divan (更轻量, 编译更快). 当前 `benches/redact.rs` 仅一个 bench,
    升级 ROI 低, 暂稳态.
  - parking_lot 0.12.5 (当前最新): 当前最新稳定版. 长期可评估迁移到 `std::sync::Mutex/RwLock`
    (Rust 1.62+ 后 std 锁性能已接近 parking_lot, 可减少一个依赖). 触发条件 = 解 duplicate /
    减少依赖数.

### 已知搁置 (有意识的不做)

- **redact 性能优化 (Aho-Corasick)**: `redact_ir` 与 `StreamingRestorer::find_safe_end`
  对每个 secret 做全字符串扫描 (K * n 复杂度). 性能基线已建立 (`just bench`),
  当前不是瓶颈, 等真有性能问题再做. 详尽设计见 `benches/redact.rs` 头部.
