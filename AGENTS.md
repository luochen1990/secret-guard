# secret-guard — Agent 工作指南

> 本文件面向 AI 代码助手 (opencode / claude-code 等), 描述本项目的**项目级**约定与开发流程.
> 模块级实现契约见各模块目录的 `AGENTS.md` 或源文件头部 `//!` 注释 (指针见"模块概览").
> 用户级文档见 `README.md`.

## 项目定位

轻量级 LLM 网关 (本地进程): 透明转发 LLM 请求, 同时检测并替换 body 中的 secret,
防止 agent 不经意把 secret 泄露到 LLM Provider. 响应回传时反向替换, 让本地工具仍能用真 secret.
支持多 provider 配置 (OpenAI / Anthropic / Gemini / Ollama / Responses), 通过 URL 路径前缀选择目标.

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
| **Protocol** | LLM API 的协议族 (OpenAI / Anthropic / Gemini / Ollama / Responses) | 协议、格式 | 全局 |
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

### 模块依赖方向图 (SSOT — 新增依赖前必查)

> 数据流契约声明 "域 A (转发链) → 域 B (派生链) → 域 C (渲染层)" 单向承诺.
> 本图是其实施层 (#145): 新增 `use crate::...` 前对照此图判断 "新依赖是否扩大偏离" —
> 只允许**向下**依赖 (指向更低层), 反向 / 新横向依赖需先改图并在 PR 中说明理由.

```text
                    ┌──────────── 基础层 (零 / 极低业务依赖) ──────────┐
                    │  util (hash)   error (AppError)   dto (wire     │
                    │  shape)        state (AppState + NO_STORE)      │
                    └─────────────────────────────────────────────────┘
                                      ▲ ▲ ▲ ▲
        ┌─────────────────────────────┘ │ │ └────────────────────────┐
        │                               │ │                          │
   ┌────┴─────┐   ┌────────────┐   ┌────┴──────┐   ┌────────────┐   ┌─┴─────────┐
   │ config   │   │ codec      │◄──│ redact    │   │ dag        │◄──│ derive    │
   │ (双层配置)│   │ (IR+R/W)  │   │ (改写)    │   │ (内容寻址) │   │ (字节派生)│
   └────┬─────┘   └────┬───────┘   └────┬──────┘   └────┬───────┘   └───────────┘
        ▲              ▲                │               │ ▲
        │              │                └───────┬───────┘ │
   ┌────┴──────────────┴────────────────────┐   │  ┌──────┴──────────┐
   │ mock / provider / secrets (实体+表)    │   │  │ record (DTO)    │
   └────┬───────────────────────────────────┘   │  └──────┬──────────┘
        ▲         ▲                            │         │
        │         │       ┌────────────────────┴────┐    │
   ┌────┴─────┐   ┌───────┴──┐        ┌─────────────┴────┴──┐
   │ auth     │   │ proxy    │───────►│ web (api/ + WebUI)  │ 域 C 渲染层
   │ (鉴权)   │   │ (转发)   │        └─────────────────────┘
   └──────────┘   └──────────┘          域 A 转发链 → 域 B 派生链
```

要点 (每条已按 #145 收紧; 完整边以代码为准, 本图标注**意图方向**与例外):
- **codec ⇄ redact 已解环**: redact → codec 单向; codec::stream 经 `StreamRestoreHook`
  接口倒置消费 restore 能力, 生产实现 `redact::StreamingRestorerSet` 由 proxy 注入
  (codec 的 fwd_* property 测试仍 import redact — 测试代码不受此约束).
- **dto / record 是中立 wire shape 层**: dag 构造之, web 序列化之, 两者互不依赖
  (dag 不再触达 web 命名空间, #95 残留落点已纠正). 注: dto → dag 仅引用
  `SessionId` (newtype 标识类型), 视作可接受的纯类型依赖.
- **state (AppState) 是进程级共享状态**: proxy / web / auth 各自单向依赖之,
  彼此之间除 "web → auth (挂载 guard)" 外无横向依赖 (原 ProxyState 落在 proxy 内).
- **已接受的例外** (有 rationale, 勿扩大): redact → secrets (探测 secret 需读 entry);
  dag → codec::ir (IrBlock 是内容寻址单元, 纯类型依赖); proxy → redact (转发即改写,
  同属域 A); web/api → auth::apikey (API key CRUD 无条件挂载, "只认证不隔离");
  config → auth (AuthConfig/ApiKeyEntry 是配置 schema 的一部分, 纯数据依赖);
  mock ↔ secrets 对称引用 (SecretEntry 持 MockStrategy, mock 校验钩子被 SecretEntry
  调用, 纯数据/校验层, 无业务行为).

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

已实践位置: `derive::extract_preview_and_model` (preview 提取),
`derive::extract_tool_use_name` (工具轮次 preview = tool name 提取),
`derive::extract_delta_messages_from_raw` (delta 切片).
(注: 前端 `toolNameOfRound` 已删除, tool name 提取在后端分两路 — sidebar 主标题由
`extract_preview_and_model` 处理, 工具轮次的 sub-dot preview 由 `extract_tool_use_name`
在 `dag::push_messages` 覆盖, 两者均由 `prop_preview_never_panics` 统一守卫 ROB-1.)

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

已实践位置: `redactions` 字段从 RedactionMap 派生 (`proxy/recorder.rs::assert_redactions_match_map`)、
`preview`/`model` 从 `req_body_raw` 派生 (`proxy/recorder.rs::assert_preview_model_match_source`)、
`resp_parsed` (非流式) 从上游响应字节经 codec reader 派生 (`proxy/recorder.rs::assert_resp_parsed_matches_source_nonstream`)、
`session.title` 从 root node preview 派生 (`dag/mod.rs::assert_session_title_matches_root_preview`)、
`resp_parsed` (流式) 从 StreamScan 累积 (`proxy/fan_out.rs`, Phase A 已删除原始 SSE 字节, 派生与源物理分离, 暂不守卫).
后续 Phase B 删除 parent.response 时必须走此流程.

### C3 前缀缓存友好性 (经济性契约) → RED-3 契约

Redact 不应无必要地改变 request body 的字节内容, 避免破坏 LLM Provider 侧的前缀缓存命中
(前缀缓存是 byte-exact 的, 历史 message 中 mock 字节变化会导致从该 message 起的整个前缀
缓存失效, 增加用户的 token 费用负担). 实现: per-request seed 驱动整个 RedactionMap,
保证同一 policy + 同一上下文 → 同一 mock. 详尽契约 (C1-C7) 见 `src/redact.rs` 头部
与 `src/mock.rs` 头部.

> 例外 (RED-3 裁决, #143): pre-replace IR 已含该 secret 的旧 mock 时 (客户端把 mock
> 回传进历史), mock 允许变化 (probing counter 推进). 理由: 复用旧 mock 会让 restore
> 错替历史中的旧 mock, 破坏 RED-6 round-trip — restore 正确性优先于缓存稳定性.
> 代价是经济性 (前缀缓存失效), 非安全性. 详见 contracts.md RED-3 例外场景裁决.

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

timeline 的 follow/pinned 状态由**视口距底部距离**机械推导 (纯派生), 不由 "最近点了什么"
显式动作决定; `selectedRound` 与 followMode 解耦 (方案 X: 仅 "进入 follow 的显式动作" —
点 Session / 点 unread badge / 初次 loadTimeline — 才重置 selected 到最新轮).
完整状态机 (NEAR_BOTTOM_PX 阈值 / follow 闭合不变量 / 短内容 drawer 压缩 / 几何失效区间)
的 SSOT 是 contracts.md **UI-6**; 视觉指示 (drawer 边缘配色 / `.pinned` 类) 与前端实现
细节 (syncFollowMode 入口 / handleNewRounds / jumpToLatest) 见 `src/web/AGENTS.md`
"timeline 滚动状态机" 段.

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

`proto_short` 简写映射的 SSOT 是 `Protocol::ALL` (协议家族清单见术语表 Protocol 行),
文档与代码注释一律引用该常量, 不维护手抄清单.

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
| `config.rs` | 双层配置 schema + `DynamicTable<T>` 泛型 + 持久化 + 静态配置预检审计 (未知 section/字段 → 启动 WARN, #159) | 文件头部 `//!` (覆盖 OverrideMode / CRUD / Effective source / 跨表并发) |
| `provider.rs` | Provider 实体 + Effective view + api_key 两来源 | 文件头部 `//!` |
| `secrets.rs` | SecretEntry 实体 + Effective view + value 两来源 | 文件头部 `//!` |
| `mock.rs` | MockStrategy 两维度 (初始值 + 生成策略) + 确定性 seed + `[redact] global_mock_prefix` 注入 | 文件头部 `//!` (C3 根基) |
| `dag/` (模块目录: mod/pool/types/view/timeline) | ConversationDAG 内容寻址存储 (BlockPool + Node + Merkle) | `src/dag/mod.rs` 头部 `//!` + `docs/design/conversation-dag.md` |
| `derive.rs` | 从 request body 派生 preview/model/text 的字节级提取 + delta messages 切片 (域 B 派生链, ROB-1 永不 panic) | 文件头部 `//!` (含 "为什么不在 web::api" 归属论证) |
| `dto.rs` | WebUI 响应 DTO 中立类型层 (SessionView/NodeView/.../SyncSnapshot, 域 B → 域 C wire shape; 构造逻辑留 dag) | 文件头部 `//!` (含 "为什么是顶层中立模块" 归属论证) |
| `error.rs` | 统一应用错误类型 `AppError` (转发链 + 鉴权层共用, 不反向依赖) | 文件头部 `//!` (含与 `web::api::ApiError` 分工 + Upstream/UpstreamTimeout message 净化回传契约) |
| `record.rs` | ForwardRecord (web 层 DTO, GET /records/{id} 响应 shape) | 文件头部 `//!` |
| `redact.rs` | RedactionMap + redact/restore pipeline + 形式化契约 C1-C7 | 文件头部 `//!` |
| `util.rs` | 集中的哈希工具 (`hash64` SipHash 单值入口) | 文件头部 `//!` |
| `codec/` | 跨协议 IR + Reader/Writer trait + StreamTranslate (OpenAI / Anthropic / Responses) | **`src/codec/AGENTS.md`** + `docs/design/ir-fields-roadmap.md` (IR 字段建模路线图: extra 边界 + 字段提升判定准则 + 实施批次) |
| `proxy/` | dispatch 路径选择 + fan_out 三路径 + Provider 鉴权 (拆分为 mod/helpers/auth/recorder/same_proto/cross_proto/fan_out 子模块) | `src/proxy/mod.rs` 头部 `//!` |
| `state.rs` | 进程级共享状态 `AppState` (原 ProxyState, 上移见 #145) + HTTP 共享常量 `NO_STORE` | 文件头部 `//!` |
| `web/` | JSON API (`api/` 目录) + 单页 WebUI | **`src/web/AGENTS.md`** |
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

### `[server]` 段字段 (static, 启动时读取一次)

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `host` | string | `"127.0.0.1"` | 监听地址. SEC-6: 默认回环, 防意外暴露到 LAN/WAN. |
| `port` | u16 | `8787` | 监听端口. |
| `records_capacity` | usize | `1024` | 内存中保留的转发记录条数上限 (FIFO 淘汰). |
| `upstream_connect_timeout_secs` | u64 | `15` | 上游 TCP+TLS 握手超时 (秒). `0` = 无限 (向后兼容, 不建议). 覆盖 reqwest `connect_timeout`. |
| `upstream_response_header_timeout_secs` | u64 | `60` | 上游响应头到达超时 (秒). `0` = 无限. 超时记 504 record (防 `send().await` 永久阻塞). |
| `upstream_stream_idle_timeout_secs` | u64 | `120` | 流式 chunk 空闲超时 (秒). `0` = 无限. 防上游发完响应头后 body 卡住. |

> 注: `[server]` / `[redact]` / `[auth]` 段仅在启动时读取一次, WebUI 修改不生效 (restart
> 才生效). 这是为了保持转发核心路径的零运行时配置开销.

### `[redact]` 段字段 (static, 启动时读取一次)

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `global_mock_prefix` | string | `""` | Auto 模式 mock 的统一前缀 (注入到每个 secret 的 `gen_spec.prefix`). 详见 `src/redact.rs` C5 契约. |
| `on_probe_exhausted` | `"fail_open"` \| `"fail_closed"` | `"fail_open"` | Mock probing 耗尽时 (弱配置 + 对抗性 IR 无法生成唯一 mock) 的策略. `fail_open` (向后兼容) 跳过该 secret 原样转发; `fail_closed` 拒绝转发整个请求 (返回 503), 防止 secret 泄露. 详见 `src/redact.rs::redact_ir_checked` 与 `src/config.rs::OnProbeExhausted`. |

### `[auth]` 段字段 (static, 启动时读取一次)

> Schema SSOT: `AuthConfig`; OIDC / session / API key 的完整行为契约: 均见
> `src/auth/mod.rs` 与其子模块头部. `[auth]` 是对象数组 + 嵌套表的混合段,
> 故用树形列表而非扁平表.

- `enabled` (bool, 默认 `false`): 双轨认证总开关. `false` = 单用户模式 (所有路由无认证,
  向后兼容); `true` = 浏览器 WebUI 走 OIDC, SDK 转发走本地 API key (`Authorization: Bearer sg_...`).
  注意: ApiKeyStore 与 `/api/api-keys` CRUD 总是可用 ("只认证, 不隔离" 哲学, 见 `src/auth/mod.rs` 头部).
- `oidc` (可选嵌套表, 默认缺席): OIDC 登录配置 (`enabled = true` 时浏览器侧必需).
  字段:
  - `issuer_url` (string, 必填): IdP 的 OIDC issuer URL, 启动时 Discovery 拉取端点 (fail-fast).
  - `client_id` (string, 必填): OIDC client id.
  - `client_secret_file` (string, 可选): client secret 文件路径, 启动时读取 (public client
    + PKCE 场景可不配).
  - `redirect_url` (string, 可选): 覆盖由 host+port 派生的默认回调
    (`http://{host}:{port}/__sg/oauth2/callback`); path 必须保持 `/__sg/oauth2/callback`,
    只能换 scheme/host/port (如经反向代理暴露时).
- `api_keys` (`[[auth.api_keys]]` 数组, 默认空): 静态预设 API key 列表 (如 CI/CD 场景),
  启动时 hash 后注入 ApiKeyStore, 与 WebUI 签发的 key 共用同一池. 元素字段:
  - `label` (string, 必填): 显示名.
  - `key` (string) / `key_file` (string): 明文或文件路径, 二选一 (互斥语义同
    `[secrets]` 的 `value`/`value_file`, 见 `src/secrets.rs`).
  静态 key 不可删除, 只能 disable/enable.

配置示例 (`secret-guard.toml`):
```toml
[redact]
global_mock_prefix = "sgm_"
on_probe_exhausted = "fail_closed"
```

## 开发流程

```bash
# 一次性环境
nix develop --impure      # 进入 devShell

# 一键 check (fmt + clippy + machete + doc + nextest + typos + deny-offline)
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
(skip-if-passed, ff-merge 后同 SHA 不重跑) + PR 并发去旧 (concurrency 取消同 PR 旧 run).
`check` job 测试集只跑一次, 顺序为
lock 守卫 → checkout → diff 报告 (PR, 非阻塞) → consistency-check → check+coverage
(含 doc 门禁 + --locked + typos + deny-offline, 阻塞) → coverage-gate → bench (非阻塞) →
file-size → WebUI (非阻塞) → cargo audit (非阻塞) → nix build cargoHash 校验 (非阻塞) →
lock 校验.
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

### cargo-deny (license + bans + sources 离线门禁; advisories 归 audit)

`cargo audit` 只覆盖 RUSTSec CVE; `cargo-deny` 额外覆盖 license 不兼容 / 重复 crate 多版本 /
禁止依赖 / git 源审计. 项目声明 MIT 且发布到 nixpkgs overlay, license 合规是硬约束 (引入
GPL/AGPL 等 copyleft 会污染下游). 配置在 `deny.toml`, 与 `.cargo/audit.toml` 的 `[advisories.ignore]`
保持同步 (互为冗余兜底).

- **CI 阻塞门禁是纯离线的** (`just deny-offline` = `cargo deny --offline check licenses
  bans sources`, 在 `just check` 链尾随 coverage step 执行, 不设独立 CI step): advisories
  检查需联网拉 advisory DB, 网络抖动会让阻塞门禁随机失败, 故归给 continue-on-error 的
  cargo audit. 本地 `just check` 链尾跑同一命令 (含 typos), 保证本地全绿 ⇒ CI 阻塞项必绿.
  全量检查 (含 advisories) 用 `just deny`.

- **license allow**: MIT / Apache-2.0 / BSD-* / ISC / Zlib / Unicode-* / MPL-2.0 (file-level
  copyleft, 不污染链接产物) / CC0-1.0 / CDLA-Permissive-2.0 (webpki-roots 的 CA 根证书数据协议).
  copyleft (GPL/AGPL/LGPL) 与不明 license 被 deny.
- **multiple-versions = warn**: 重复 crate 只警告不阻断. Rust 生态 duplicate 多为传递依赖
  暂态, 强制 deny 会频繁阻塞. 当前重复清单 (2026-08 实测, 删 time 死依赖后), 两个口径:
  - linux 构建图 (`cargo tree -d`): **9 个家族** — base64 / getrandom (3 版) / rand /
    rand_chacha / rand_core / syn / thiserror + thiserror-impl / tower-http;
  - Cargo.lock 全平台口径: **15 个家族** — 上述 9 个再加 cpufeatures / hashbrown /
    indexmap / r-efi / schemars / windows-sys.
  lock-only 家族的归因 (两类): ① indexmap 1.9 + schemars 0.9 + hashbrown 0.12 孤立
  老版本簇是 serde_with 的 legacy optional feature (serde_with 本身在 linux 构建
  图内, 经 openidconnect 引入; 簇成员不进构建图), cpufeatures 0.3.0 同理源自
  reqwest 未启用的 http3 → rand 0.10 → chacha20 — 消解时点取决于上游移除对应
  optional feature (serde_with legacy feature / reqwest http3), openidconnect /
  reqwest 自身升级只是载体, 均无独立升级条目; ② r-efi / windows-sys 为
  windows/UEFI target 专属暂态.
  构建图内家族的解法已记录于 "后续工作": tower-http (reqwest 0.13) / rand 簇
  (rand 条目, 注意升级后 0.8/0.9 传递仍留存); base64/getrandom/syn/thiserror 为
  生态暂态, 无独立条目.
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
- **Mock probing 耗尽可配置 fail-open / fail-closed**: 弱配置 (charset/length 仅产生
  极少候选) + 对抗性 IR 可能让 `redact_ir` 的 mock probing 耗尽 (`MOCK_PROBE_LIMIT`).
  历史行为是 **fail-open** (warn + 跳过该 secret, 原样转发到上游, 见 `redact_ir`).
  新增 `[redact] on_probe_exhausted = "fail_closed"` 让 proxy 在这种情况下**拒绝转发**
  (返回 503), 防止 secret 泄露到 LLM provider (见 `redact_ir_checked`). 默认仍
  `fail_open` 以保持升级兼容. 注意 fail_closed 拒绝时返回的 503 body 不含 secret 明文
  (变量部分只含 secret id + reason 枚举, 语义由 SEC-2 契约锁定).
- **C5 是实质确定性契约**: Auto 模式 mock 不含 real_secret 的 ≥`k(L)` 字符连续子串,
  阈值 `k(L)` 随 secret 长度自适应 (短 secret 强保护, 长 secret 弱保护), 内部重试链
  使契约在 Auto 模式下实质等价于确定性 (失败概率天文级小).
  完整数学定义 (`k(L)` 公式 / 信息泄露率上界 / 重试链 safety bound) 的 SSOT 在
  `src/mock.rs` 头部 "C5" 段落 (= contracts.md **RED-5**), 此处不重述数字.
  `proptest-regressions/redact.txt` 记录历史失败种子.
- **同协议 + Redact: normalize_json 相等, 非 byte-exact**: reader → redact_ir → writer 重序列化,
  字段顺序 / 空白等无语义差异由 `normalize_json` 吸收, 语义信息通过 wire 形态元数据保留
  (见 `src/codec/AGENTS.md` "wire fidelity"). 已知搁置: 多 system messages 合并 / message-level
  extra / block-level 未知 part / response 侧 usage 字段位置 (详见 codec/AGENTS.md).
  同协议 + 无 Redact 路径仍 byte-exact.
- **流式 + Redact + 非 2xx 上游错误**: SSE 错误流不是单个 JSON, parse 失败时 fallback
  原样返回 (无 restore), 客户端可能看到 mock. 该 fallback 现在打 WARN
  (`mock not restored; client will see mock values`, #158).
- **流式 + Redact + 上游 Content-Type 非 text/event-stream**: 判型跳过流式 restore,
  mock 逃逸到客户端 (与上一条同类, #158 发现的第三条逃逸路径). 行为不变 (透传),
  但有两层 WARN: 判型处 (`non-SSE content-type for a stream=true request`) +
  parse 失败 fallback (`mock not restored`).
  后续效应: 客户端把 mock 回传进下一轮历史时, 触发 RED-3 例外场景 (mock 跨轮变化,
  见 contracts.md RED-3 例外裁决 / #143).
- **同协议 + Redact + 非流式 2xx + 上游响应 parse 失败**: 上游返回的 body 不是合法 JSON 或 codec
  reader 无法 parse 时 (类型不符 / 空数组 / 越界), 转发路径 fallback 为透传含 mock 的字节, 无 restore,
  客户端收到 mock. 同协议路径见 `src/proxy/fan_out.rs` (non-stream 分支), 跨协议路径见
  `src/proxy/cross_proto.rs`. 均走 best-effort 鲁棒性原则 (ROB-*), parse 失败不 panic.
  同协议路径在 redaction map 非空时打 WARN (`mock not restored`, #158); 跨协议路径仅
  reader 拒绝时打通用 parse 失败 WARN, 非 JSON fallback 静默 (mock-not-restored 信号
  缺失, 补齐是后续工作).
- **provider 协议与上游实际协议错配 → 静默空响应 (有 WARN)**: provider protocol=anthropic
  但上游实为 OpenAI shape 时, 2xx 响应被 reader 宽松解析为空 content + 全零 usage
  (reader 对缺字段 `unwrap_or_default` 降级, 不报错). 行为不变 (仍翻译返回), 但打 WARN
  (`parsed to empty content and zero usage; does the upstream actually speak ...`,
  #162) — 配置错误可从日志发现.
  后续效应同上 (RED-3 例外场景).
- **跨协议 ingress 的 timeline delta 切片可能错位**: OpenAI writer 会把 Anthropic 风格的
  混合 Text+ToolResult user 消息拆成 (1+N) 条 wire messages, 导致 `req_body_raw` 的
  messages 数 > IR messages 数. `extract_delta_messages_from_raw` 切片时跨协议路径的 start 偏小,
  delta 可能包含前序轮消息. 同协议路径不受影响. 详见 `src/web/AGENTS.md`.
- static config 的 `[server]` (含 `upstream_*_timeout_secs`) / `[redact]` / `[auth]` 段仅在启动时读取一次, WebUI 改不生效 (restart 才生效).
- **redact_headers 名单硬编码 (SEC-4)**: `proxy/helpers.rs::redact_headers` 的敏感 header
  脱敏名单是硬编码黑名单 (显式枚举主流 provider auth header + 含 "token" / "secret"
  子串匹配, 完整名单以 `is_sensitive_header` 为 SSOT). 未在名单内的 header 会原样
  记录到 WebUI DAG record. 用户若使用自定义 auth header (如 `x-my-service-key`),
  当前无法在不改代码的情况下追加. 后续工作: 暴露为 `[redact] redacted_headers = [...]`
  配置项.
- **session cookie Secure flag 硬编码 false**: `auth/session.rs::build_session_layer`
  硬编码 `with_secure(false)` (本地 HTTP dev 必须). 经反向代理暴露 HTTPS 时 cookie 不带
  Secure flag, 详见 `docs/deployment-nixos.md` "HTTPS 反向代理" 段. 根治方案 (配置开关 /
  X-Forwarded-Proto 推断) 是后续工作.
- **DAG 孤儿节点降级**: parent 被 LRU 淘汰后, child 的 `full_request_messages` 返回 None
  (timeline 降级展示, 不 panic). 显式孤儿标记 (CDAG-7) 尚未实现.
- **auth 模块测试覆盖率 (OIDC 登录流程)**: auth 模块的纯逻辑已覆盖
  (`apikey.rs` 100% / `middleware.rs` ~99% / `session.rs` ~98% / `mod.rs` ~99%), 含
  require_api_key 的 Authorization 剥离断言 (SEC 红线) 与 build_session_layer 的
  cookie 配置 (sg.sid + HttpOnly).
  OIDC 流程的集成测试 (`tests/auth_oidc.rs`) 已通过本地 mock IdP server 覆盖
  (起 axum server 模拟 discovery + token + jwks + RS256 签 id_token), 覆盖率:
  - `oidc.rs` ~86%: `OidcBackend::discover` (含 issuer 字符串校验 / JWKS 拉取) /
    `exchange_and_verify` happy + 5 个错误路径 (CSRF mismatch / token HTTP 4xx /
    NoIdToken / WrongSignature / WrongNonce) / `authorize_url` PKCE verifier round-trip.
  - `handlers.rs` ~64%: `login_start` (重定向 + session 写入 + sanitize_next_url) /
    `oauth_callback` 错误路径 (IdP error 参数 / 缺 session 凭证) / `logout` / `me`.
  **仍未覆盖** (~36% handlers + ~14% oidc 残留): `oauth_callback` happy path 的
  PKCE verifier + nonce 完整端到端 round-trip — nonce 是 client-only 凭证存 server-side
  session, 外部 HTTP 测试无法读取; 这部分核心逻辑由 `exchange_and_verify_happy` 间接
  覆盖, 完整端到端需 mocking AuthSession (axum-login extractor), 留作后续工作.

## 后续工作 (非 MVP 范围)

- **跨协议路径的 mock-not-restored WARN**: cross_proto 响应 parse 失败 fallback
  (reader 拒绝 / 非 JSON) 时, 与同协议路径 (`fan_out.rs::warn_mock_not_restored`)
  对称地在 redaction map 非空时打 `mock not restored` WARN (#158 只覆盖了
  同协议路径; 见 "已知限制" 对应条目).
- **跨协议流式响应翻译**: 在 `cross_proto_forward` 检测 stream=true 时接入
  `StreamTranslate::new(ingress, egress)` 而非返回 501.
- **更多协议**: Gemini / Ollama / Bedrock / Cohere / OpenAI Responses API.
  新增协议只需实现 Reader + Writer trait (~200 行), 不动 dispatch.
- **redact_headers 名单可配置**: 加 `[redact] redacted_headers = [...]` 配置项,
  默认值是现有硬编码名单, 用户可扩展自定义 auth header. 当前硬编码黑名单见
  `proxy/helpers.rs::is_sensitive_header` (SEC-4 已知限制).
- **session cookie Secure flag 可配置**: 给 `build_session_layer` 加配置开关
  (`[auth] secure_cookie = true`) 或从 `X-Forwarded-Proto` header 动态推断.
  当前硬编码 false (本地 HTTP dev 必须), 见 `docs/deployment-nixos.md` "HTTPS 反向代理" 段.
- mock_secret 的 category-aware 默认生成 (Password/ApiKey/Cookie 等格式感知).
- 配置热加载; 测试覆盖率自动上报 + fuzzing (cargo-fuzz).
- **auth/oidc.rs + handlers OIDC 流程的集成测试 (已完成 happy + 错误路径)**:
  `tests/auth_oidc.rs` 起本地 mock OIDC IdP server (axum, 模拟 discovery + token +
  jwks + RS256 签 id_token), 覆盖 `OidcBackend::discover` / `exchange_and_verify` /
  `handlers::login_start` + `oauth_callback` (错误路径) + `logout` + `me`.
  详见 "已知限制" 对应条目的当前覆盖率数字.
  **Followup (未完成)**: `oauth_callback` happy path 的 PKCE verifier + nonce 完整
  端到端 round-trip — 需 mocking AuthSession (axum-login extractor) 或在 server 端
  加 testing-only nonce 注入钩子 (生产代码改动).
- **依赖升级** (滞后是稳态, 非风险; Cargo.lock 锁定保证可复现构建; 触发条件满足时再升,
  默认触发条件 = CVE / 解 duplicate / 需要 feature, 各子项仅标注例外):
  - rand 0.8 → latest (0.10): 0.9/0.10 API 有 breaking (`thread_rng()` → `rng()`,
    `Rng::gen()` → `random()`), 升级时 `src/auth/apikey.rs` + `tests/auth_oidc.rs`
    两处需改 (rand 使用点全集; mock.rs/redact.rs 用确定性 SipHash 不调 RNG).
    注意两处迁移不对称: apikey.rs 随迁 0.10 API; auth_oidc.rs 的 OsRng 喂给
    `rsa::RsaPrivateKey::new`, 而 rsa 0.9 钉死 rand_core 0.6 trait bounds (且 0.10
    已无 `rand::rngs::OsRng`), 须改用 `rsa::rand_core::OsRng` (rsa re-export,
    零新增依赖), 不能随迁 0.10 API.
    **预期管理**: tower-sessions-core / oauth2 / openidconnect (直接 + 经 rsa)
    也引用 rand 0.8, mockito / proptest (dev) 用 rand 0.9 — 升级后 0.8/0.9 作为传递
    依赖仍留存 (Cargo.lock 中 rand 0.8/0.9/0.10 三版本共存), 勿误判 "升级未生效".
  - sha2 0.10 → 0.11: 注意 openidconnect 4.0.1 **直接**依赖 `sha2 ^0.10.6`, 且经
    oauth2 5.0.0 再依赖 `sha2 ^0.10` (双重阻塞), **升级主依赖也无法解 duplicate**,
    直到 openidconnect 上游升级.
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

- **redact 性能优化 (Aho-Corasick 多模式匹配)**: `redact_ir` 的 `gen_mock_for_ir` 已
  做 P2-1 优化 (hybrid 延迟预拼接 IR 叶子缓存, 消除 P×L 因子, 详见 `src/redact.rs`
  `gen_mock_for_ir` 头部); `StreamingRestorer::find_safe_end` + `restore_str_inplace`
  仍对每个 mock 朴素 find+replace (K 次扫描). P2-2 曾尝试合并两者扫描 (缓存命中 mock
  列表 + restore 复用), 实测因 `restore_str_inplace` 的 `if s.contains(mock)` 预检查
  已避免无命中 mock 的 replace 开销, 而缓存命中列表需重新扫描 head (与 contains 等价)
  或 clone pair (分配开销), 净收益为负, 已回退. 真正的合并优化需要 Aho-Corasick 单次
  多模式扫描 (消除 K 因子), 当前不是瓶颈, 性能基线已建立 (`just bench`), 等真有性能
  问题再做. 详尽设计见 `benches/redact.rs` 头部.
- **`hash_block` memoize (DAG)**: `serde_json::to_string` 在 `intern` 入口每 ToolUse
  block 重算一次 (历史 message 的 block 在每次 `push_messages` 都被重新 intern).
  未 memoize 因 `IrBlock` 加 `OnceCell<BlockHash>` 破坏 derive + 跨 clone 不共享缓存
  + blast radius 大. 若 profiling 显示为瓶颈, 选项: (1) 手写 `Value` walk+hash 省
  String 分配; (2) `OnceCell` 局部缓存 + 手写 PartialEq. 见 `src/dag/pool.rs::hash_block`.
