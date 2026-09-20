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
| **Provider** | 一个 provider 条目 (sum type: Direct 直连实体 \| Router 路由 \| Pool 套餐池, #187 + Pool 延伸) | 上游、后端、模型、服务商 | 全局 |
| **Router Provider** | `ProviderKind::Router` 构造的路由端点 (`routes` 路由列表必填) — 自身不转发, 按请求 model 匹配路由链式解析到链尾实体 provider (per-request, WebUI 即席改路由, #179 多规则化; sum type 化 #187) | 虚拟 endpoint、virtual provider、路由 provider、别名 | provider/proxy |
| **Pool Provider** | `ProviderKind::Pool` 构造的套餐池端点 (`members` 有序成员列表必填) — 自身不转发, 顺序 failover: 正常全打第一个可用成员, 检测到窗口限额耗尽信号后自动切下一个成员, 耗尽成员按恢复闹钟自动回归; 运行时状态内存态不持久化 (契约 POOL-*) | 套餐轮换、配额池、账号池、用完了切下一个 | provider/proxy/pool |
| **Member (成员)** | Pool 的 `members[]` 指向的一个 Direct provider id (= 一份独立套餐凭证) | 池成员、成员账号 | pool |
| **闹钟 (alarm)** | 成员耗尽时记录的恢复时刻 (`Exhausted{until}`) — 来自上游精确信号解析 (`resume_at`) 或 `now + cooldown_secs` 兜底 (恒有时刻, 无永久形态) | 恢复时间、冷却时间 | pool |
| **三通道 (exhaust signal channels)** | 耗尽信号的三条独立匹配线 (HTTP status / body 码 / response header, OR 关系), 判定 SSOT = `pool::detect_exhaustion` | 信号通道、触发线 | pool |
| **Route** | 路由四元组 (`model_pattern` model 通配符 / `target` 目标 / `upstream_model` 重写 / `priority` 优先级) — model_pattern 匹配请求 model 时路由到 target, priority 越大越优先 (None = 禁用) | 规则、路由规则 | provider/proxy |
| **Common URI** | secret-guard 自建请求 (fetch_model_list) 的公共 URI 前缀 — 三段式 `base_url + common_uri + request_uri` 的中段. 值域: `"/v1"` 裸根布局 / `""` 版本前缀已含 (智谱等国产系) / 缺省未探测 (fetch 按 `V1_COMMON_URIS` 顺序懒回退现场推导). 持久化在 `DirectProvider.common_uri` (Detect 探测自动填充, WebUI badge 回显), **不影响转发** (转发 rest 原样流过). 运行时记忆在 `CacheEntry.common_uri_hit` | common_uri、版本前缀、布局前缀 | provider/proxy |
| **Protocol** | LLM API 的协议族 (OpenAI / Anthropic / Gemini / Ollama / Responses) | 协议、格式 | 全局 |
| **IR** | 协议无关的中间表示 (IrRequest / IrResponse / IrBlock) | 中间表示 | codec |
| **RedactionMap** | 一次 Redact 产出的 Secret↔Mock 双向映射表 (per-request, 不持久化) | 映射表、redact map | redact |
| **MockStrategy** | 每个 Secret 的 Mock 生成策略 (初始值 + 生成策略两维度) | mock 策略、生成策略 | mock/redact |
| **ForwardRecord** | 一次 HTTP 转发的完整记录 (web 层 DTO, 从 DAG Node 派生) | 请求记录、record、转发记录 | web |
| **Node** | ConversationDAG 中的一个节点 = 一次 API 调用 | 轮次、round、节点 | dag/web |
| **Session** | 由 Merkle 前缀哈希聚类的一组 Node 链 | 会话、对话、conversation | dag/web |
| **req_delta** | 一个 Node 相对其 parent 新增的 messages | 增量、本轮新增、delta | dag/web |
| **RoundKind** | 轮次展示类别三态 (Normal 常规 \| Retry IR 等价重发 \| NoMessages 无 messages), push 时从 (split_at, msgs) 预计算, UI-1 渲染分发的 SSOT (contracts.md DTO-9) | 重试标记、轮次类型 | dag/web |
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
- **格式化**: treefmt 全仓 (nixfmt / rustfmt / taplo / ruff-format), 配置 SSOT =
  根 `treefmt.toml`; 门禁 = `just check-fmt` (treefmt --fail-on-change). 细节见
  "nix flake 布局 (flake-fhs)" 段.

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
| `SEC-*` | 跨 | 新增 | GET 不泄漏 / panic 不泄漏 / headers 脱敏 / 本地监听 / Host·Origin 校验 (SEC-7, 防 DNS rebinding) / 敏感落盘 owner-only (SEC-8) / API nosniff (SEC-9) / 降级偏安全 (SEC-10) |
| `ROB-*` | 跨 | 鲁棒性原则 | best-effort 永不 panic + 假设声明注释必备 |
| `VIEW-*` | 跨 | 视图正确性机制 | 先断言后删除 + 派生字段 consistency-check 覆盖 |
| `UI-*` | C | **I1-I3** + 新增 | 气泡数 / sidebar 条目数 / DOM 顺序 / reconciliation / drawer |
| `USAGE-*` | B | 新增 (usage-stats) | 回显保真 + 聚合一致性 + 成本纯函数 + 缺失显式 + 计入判据 + model SEC 扫描 |
| `POOL-*` | A | 新增 (Pool Provider, 待人工授权) | 套餐池顺序 failover + 三通道耗尽检测 + 闹钟自愈 + 全耗尽本地 503 + 检测旁路 + 默认表语义域 |

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
> 图只画主干; 完整例外边以下方 "已接受的例外" 清单为准.

```text
                    ┌──────────── 基础层 (零 / 极低业务依赖) ──────────┐
                    │  util (hash + 0600 + 截断族)  error (AppError)   │
                    │  dto (wire shape)  state (AppState + NO_STORE)   │
                    │  server_host_guard (Host/Origin 校验, SEC-7)     │
                    └─────────────────────────────────────────────────┘
                                      ▲ ▲ ▲ ▲
        ┌─────────────────────────────┘ │ │ └────────────────────────┐
        │                               │ │                          │
   ┌────┴─────┐   ┌────────────┐   ┌────┴──────┐   ┌────────────┐   ┌─┴─────────┐
   │ config   │   │ codec      │◄──│ redact    │   │ dag        │◄──│ derive    │
   │ (双层配置)│   │ (IR+R/W)  │   │ (改写)    │   │ (内容寻址) │   │ (字节派生)│
   └────┬─────┘   └────┬───────┘   └────┬──────┘   └────┬───────┘   └───────────┘
        ▲              │                │               │ ▲
        │              │                └───────┬───────┘ │
   ┌────┴──────────────▼────────────────────┐   │  ┌──────┴──────────┐
   │ mock / provider / secrets / pool       │   │  │ record (DTO)    │
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
  (dag 不再触达 web 命名空间, #95 残留落点已纠正). 注: dto → {dag, codec::ir}
  仅纯类型 (前者 `SessionId` newtype 标识, 后者 `IrRole`/`IrUsage`), 视作可接受的
  纯类型依赖.
- **state (AppState) 是进程级共享状态**: proxy / web / auth 各自单向依赖之,
  彼此之间除 "web → auth (挂载 guard)" 与 "web/api/providers → proxy::models" (probe
  端点, 见下方例外清单) 外无横向依赖 (原 ProxyState 落在 proxy 内).
- **pool 与 provider 同格** (图上同格, 层级在 provider 之上): `src/pool.rs` 的
  套餐池运行时 (成员状态机 + 耗尽检测器) 只向下依赖 provider 的**类型**
  (`PoolProvider`/`ExhaustConfig` 定义在 provider.rs; `PoolPicker` trait 接口倒置 —
  trait 定义在 provider.rs 供 `resolve_route` 图遍历消费, 生产实现 `PoolStates` 在
  pool, 由 proxy dispatch 注入, 先例同 codec::StreamRestoreHook — 保持
  pool → provider 单向)。消费边 proxy → pool / state → pool 见例外清单。
- **已接受的例外** (有 rationale, 勿扩大): redact → secrets (探测 secret 需读 entry);
  redact → config (仅 `OnProbeExhausted` 枚举 — `[redact] on_probe_exhausted` 的
  消费点, 纯数据枚举); dag → codec (IrBlock 是内容寻址单元, 纯类型依赖; 另
  dag/types 的 `ingress_protocol` 字段引用 codec::Protocol 枚举, 同性质); codec →
  provider (仅 Protocol 枚举做 from_native 映射, 纯类型依赖; 长期归宿: 若
  codec/provider 拆 crate, Protocol 全局枚举应下沉基础层, 桥接函数自然消失);
  proxy → redact (转发即改写,
  同属域 A); proxy → config (仅降级 gate / 超时快照的纯数据枚举与结构 —
  `OnProbeExhausted` / `OnUnsupportedProtocol` / `OnFallbackRestore` /
  `UpstreamTimeouts`: 转发路径降级决策的输入, 消费点 same_proto from_native-None
  分支 / helpers restore 门控 / recorder redact_and_derive, 纯数据依赖无 config
  行为依赖, 性质同 redact → config); web/api → auth::apikey (API key CRUD 无条件挂载, "只认证不隔离");
  config → {auth, provider, secrets} (AuthConfig/ApiKeyEntry 与 Provider/SecretEntry
  均是配置 schema 的组成部分 — static 加载期组合 + validate 钩子调用, 纯数据依赖;
  provider/secrets 同 auth 型, 走查补登记);
  mock ↔ secrets 对称引用 (SecretEntry 持 MockStrategy, mock 校验钩子被 SecretEntry
  调用, 纯数据/校验层, 无业务行为); provider → secrets (仅 validate_id/mask_value
  两个校验/脱敏工具函数复用, 纯函数借用, 无实体耦合); state → proxy::ModelListCache
  (#196: AppState
  聚合 router /models 的上游清单缓存, 纯数据 store 无 proxy 行为依赖, 组合根先例同
  state → auth 的 ApiKeyStore — 见 `src/state.rs` 字段注释) + state → usage
  (usage-stats: AppState 聚合 UsageStore / PricingCache 两个纯数据 store, 同一先例;
  usage 模块未画入图 (聚合根旁的纯数据+派生层, 主干外), 图外另有 web/api/usage.rs →
  usage (GET /api/usage/summary 直读 UsageStore 聚合 + summary 纯函数派生, 域 B
  派生链消费). usage 模块自身仅依赖 codec::ir / secrets / dag::RoundKind 纯类型 /
  config schema 纯数据类型, 见 `src/usage/` 头部 — usage→config 是向下合法边,
  非例外, 性质同 provider→config; usage→dag 仅引用 RoundKind 枚举, 同 dto→dag 的
  纯类型依赖先例)
  + proxy → auth::AuthenticatedTenant (v4b redact 审计归因: proxy 从 request
  extension 提取 API key label 注入 usage 采集, 纯类型依赖, 性质同 config→auth
  的 AuthConfig 纯数据边, 无 auth 行为依赖)
  + web/api/providers → proxy::models (probe 端点复用上游模型清单探测基建 +
    models 预览端点复用模型清单 fetch/合成基建 — `provider_model_preview`;
    行为借用 — `probe_provider_upstream` / `provider_model_preview` 均执行出站
    HTTP 探测/fetch, 非纯数据/纯函数, 但复用同款 fetch 防御 (整体超时/有界累积/
    错误净化) 且无转发链状态依赖, handler 只是薄壳, 无独立实现 — 勿以此为先例
    扩张 web → proxy 的行为依赖)
  + proxy → pool (套餐池转发即状态机驱动: dispatch 经 `PoolPicker` 注入候选解析
  (active_members), 响应侧 `PoolWatch::detect_and_mark` 旁路检测 —
  同属域 A 转发链, 性质同 proxy → redact 的 "转发即改写")
  + state → pool (AppState.pools 聚合 `PoolStates` 纯数据+状态机 store,
  组合根先例同 state → usage 的 UsageStore / state → auth 的 ApiKeyStore —
  见 `src/state.rs` 字段注释; web 观察面 list_providers 的 pool_status 与
  pool-reset 端点经 AppState 读同一份).

> secret-guard 的核心职责 (转发 + Redact) 必须对任意字节流零失败.
> 围绕核心职责之外、**基于对 LLM 应用层行为模式强假设** 的附加功能
> (preview 提取 / delta 切片 / WebUI 分组渲染 / tool name 推断等) 是"尽力而为"增强,
> 绝不能因假设不成立而让请求失败或进程崩溃.

### 鲁棒性原则 (best-effort, 永不 panic) → ROB-* 契约

对"尝试性解析"功能, 必须同时满足:

1. **鲁棒性处理**: 解析路径用 `Option`/`Result` 传播失败, 缺字段 / 类型不符 / 空数组 / 越界
   都返回 `None` 或空, 由调用方走 fallback (如 preview 为 None 时前端降级到占位文本,
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

### Host / Origin 校验 (SEC-7, 防 DNS rebinding + CSRF 纵深)

默认单用户模式 (auth disabled) 下无认证, "同源策略兜底" 的旧假设会被 DNS rebinding
击穿 — 攻击页面的域名 rebind 到 127.0.0.1 后, 浏览器发出的请求对本地 server 是
"同源"的, 可读 `/api/sync`、可写 provider base_url / secret decision。server 层以
最外层 middleware 对**所有**路由做两类校验 (实现 `src/server_host_guard.rs`,
挂载 `src/server.rs`, 失败一律 403):

1. **Host 白名单** (所有请求): Host 的显式 port 必须等于监听 port (无 port 仅当
   监听 80 时合法 — 浏览器默认省略); host 部分放行: loopback IP 字面量
   (127.0.0.0/8, `[::1]`) / 配置 host / `localhost` / 空 host; 配置 host 非
   loopback (`0.0.0.0` / `::` / LAN IP — 本机非环回地址无法枚举) 时放行任意
   **IP 字面量**; **未声明的域名形式 Host 一律拒绝** — 例外:
   `[server] allowed_domains` 显式声明的信任域名按名字精确匹配且**端口宽松**
   (反代 + 域名部署形态, 攻击者的域名进不了这份用户手写的名单; 条目归一化
   trim + 小写, 含 `:` 形态 (host:port/裸 IPv6)/IP 字面量/localhost/空串条目 WARN 跳过)。生产 `serve()` 要求
   host 可解析为 SocketAddr, 域名 host 启动即报错 (仅 Host header 侧有白名单)。
   缺 Host header 放行 (rebinding 必带域名 Host)。
2. **`/api/*` 非安全方法 (POST/PUT/DELETE/PATCH) 的 Origin / Sec-Fetch-Site 校验**:
   带 Origin 则其 host:port 必须在白名单 (`Origin: null` 拒绝;
   `allowed_domains` 声明域名同享且端口宽松); 带
   Sec-Fetch-Site 则必须是 same-origin / same-site / none; 两者都缺放行
   (非浏览器 SDK)。GET/HEAD 等安全方法豁免 (读端泄漏由 SEC-1 守卫)。
   转发路径 (`/{o|a|g|l|r}/...`) 不做 Origin 校验 (SDK 场景, Host 校验已覆盖)。

测试: 单元 (`src/server_host_guard.rs::tests`) + 集成 (`tests/integration.rs`
SEC-7 段); 可测 property 见 `docs/design/contracts.md` **SEC-7**。

## 降级偏安全原则 (fail-safe degradation) → SEC-10 契约

secret-guard 在无法维持核心保证 (real secret 不出现在未授权位置) 的降级路径上,
**默认不扩散真实 secret** — 请求侧降级默认拒绝转发 (503), 响应侧降级默认保留 Mock
透传; real 进入更大暴露面 (上游 / 易被日志采集的失败响应体) 必须显式 opt-in.
rationale 是不对称性: 可用性损失可重试恢复, 机密性损失不可逆. 三个开关
(`[redact] on_probe_exhausted` / `on_unsupported_protocol` / `on_fallback_restore`,
2026-09 起默认全部安全侧) 是本原则的配置面; 完整陈述与 property 见
`docs/design/contracts.md` **SEC-10**.

## 前端不变量 (UI Invariants) → UI-1..UI-7 契约

> 以下条目是**跨 web/dag/index.html 的强不变量**, 任何渲染优化或内存重构不得违反.
>
> **编号映射**: AGENTS.md 的 `I*` 是 contracts.md `UI-*` 的前身 (历史编号).
> `I1=UI-1`, `I2=UI-2`, `I3=UI-3`, `I4=UI-6 的 selectedRound 子属性`, `I5=UI-6`, `I6=UI-7`.
> contracts.md 收录并扩展为 UI-1..UI-7, 以 contracts.md 为 SSOT; 此处保留 I* 编号便于历史 grep.
### I1 — 气泡数 == req_delta messages 长度

会话详情页 (timeline) 渲染的 Bubble 数量, 必须等于该 Node 的 req_delta messages
数组长度. 空 delta 轮按 `round_kind` 三态分发 (DTO-9, push 时预计算): `retry`
(IR 等价重发) → 0 气泡 + retry 徽章 (不捏造用户消息); `no_messages` → preview
fallback 单气泡. 任何渲染优化 (折叠、合并、视图派生) 不得改变此等式.

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

### I6 — sidebar rounds 回填时序 + timeline 并发一致性 (↔ UI-7)

点击 sidebar 会话头 (toggleSession 展开) 后, 三级菜单的 "Loading rounds…" 占位符由
toggleSession 内触发的**主动 sync** 覆盖 (不依赖 3s 轮询 tick; auto-refresh 关闭时
占位符不得无限期停留). timeline 并发一致性由**代数 (gen) 对账**保证:
`state.timelineGen` 只增不减, 换世界者 (loadTimeline / clearTimeline) bump; 一切写
`timelineRecords` / `tail` / `timelineReachedTop` 的在途响应落地前对账, 代数不匹配即
丢弃 timeline 数据 (sidebar 数据照常应用). sync 构造 `selected` 游标前校验
`timelineSession === selectedSession` (loadTimeline 落地对账通过后才认领归属),
不一致发 null 游标, 防止矛盾游标触发后端 "after 不属于本 session → 全链重放" 契约.
详尽形式化见 contracts.md **UI-7**.

**回归守卫**: 这些不变量由 `tests/webui/im-ui.spec.ts` 守卫. 改前端渲染逻辑或后端
delta 切片时, 必须同步跑 `just check-webui`.

## 路由策略 (核心契约)

URL = `/{proto_short}/{provider_id}/*path`. 同时编码 ingress 协议与目标 provider,
为未来跨协议转换预留钩子. **完整 URI 分配规划 (顶级保留字 / 命名空间不相交论证 /
变更流程) 的 SSOT 见 `docs/design/url-layout.md`**, 下列路由改动必须同步该文档.

| 路径 | 含义 |
|---|---|
| `/` | Web UI (主入口) |
| `/api/*` | Web UI JSON API (未匹配子路径 404, 绝不进 forward) |
| `/login`, `/oauth2/callback`, `/logout` | OIDC 认证 (auth 启用时) |
| `/{o\|a\|g\|l\|r}/{name}` | forward, rest = "/" |
| `/{o\|a\|g\|l\|r}/{name}/{*rest}` | forward, rest 为子路径 ({*rest} 捕获不含前导 `/`, 消费方容错处理, 见 `ForwardPath` 注释) |
| 其他 | 404 (不再 catch-all 透传) |

`proto_short` 简写映射的 SSOT 是 `Protocol::ALL` (协议家族清单见术语表 Protocol 行),
文档与代码注释一律引用该常量, 不维护手抄清单.

错误语义:
- 未知 protocol 简写 → 404 `not_found`
- 未知 provider id → 404 `not_found`
- 禁用 provider (`enabled = false`) → 503 `unavailable`
- 路由 provider (routes) 坏路由: 无匹配路由 (NoMatch) / 目标缺失 / 目标 disabled / 成环 → 503
  `unavailable` (message 只含 id + model 名 + reason 枚举, SEC-2 同型; 解析 per-request —
  body 收集后按请求 model 匹配路由, 切换只影响新请求 — FWD-5, #179)
- 套餐池 provider (pool) 全耗尽: 全部成员耗尽/missing/disabled →
  503 `unavailable`, **本地快速失败 (零上游请求)**, message 只含 pool id + reason 枚举 +
  最早恢复剩余秒 (SEC-2 同型); 顺序 failover + 耗尽信号检测的语义见 contracts.md
  **POOL-*** 与 `src/pool.rs` 头部
- **跨协议 + `stream=true`**: OpenAI ⇄ Anthropic 走 StreamTranslate 流式翻译 (含
  Redact 场景的响应侧 restore); **Responses (任一侧) 例外** → 501 (Responses 流式
  SSE 事件翻译未实现, 跨协议翻译依赖其产出 IR 事件, 放行会翻译出空流; 见 "已知限制")
- **Responses + Redact 命中 + `stream=true`** → 501 (Responses 流式 SSE 事件翻译未实现, 放行会让
  mock 静默外流; 仅路由 model 重写 (map 空, 响应无需 restore) 时流式放行 SSE 字节透传 — #183 D5
  收窄; 见 "已知限制")
- Gemini/Ollama 跨协议 → 501 (codec 未覆盖)

**router provider 的模型列表 GET 请求本地终结 (#196)**: `GET /{o|a|g|l|r}/{router}` + 模型列表端点
(o/r/a: `/models` 或 `/v1/models`; g 另含 `/v1beta/models`; l: `/api/tags`) 时, 响应本地合成 =
别名清单 (exact pattern, 路由表序) ∪ 过滤后的上游模型清单 (per-Direct-provider 缓存,
TTL 300s + serve-stale-on-error + single-flight; exact-only router 零上游请求 — N6 gate),
不进转发链 / 不记 DAG (D5); Direct provider 的 /models 透传行为不变 (D6)。
Pool 不进此本地终结分支 (Router 专属) — pool 入口的 /models 经 resolve_route 打到当前
成员, Direct 透传语义 (成员耗尽的 failover 语义对 GET /models 同样生效)。
可测 property 见 `docs/design/contracts.md` **FWD-7**; 实现见 `src/proxy/models.rs` 头部。

详尽的 dispatch 路径选择 (同协议透传 / IR 路径 / 跨协议翻译) 与 fan_out 四路径见
`src/proxy/mod.rs` 头部 (拆分为模块目录, 各子路径实现在 `same_proto.rs` / `cross_proto.rs` /
`fan_out.rs`); 路由相关的可测 property 见 `docs/design/contracts.md` **FWD-5**.

## 模块概览

> 每个模块的**详尽契约**在对应位置. 这里只给一句话职责 + 指针.

| 模块 | 职责 (一句话) | 详尽契约位置 |
|---|---|---|
| `main.rs` / `cli.rs` / `lib.rs` | 二进制入口 + CLI 参数 schema | 文件头部 `//!` |
| `auth/` (模块目录: mod/oidc/handlers/session/apikey/middleware) | OIDC 登录 (WebUI) + 本地 API key (SDK 转发) + session | `auth/mod.rs` 头部 `//!` |
| `config.rs` | 双层配置 schema + `DynamicTable<T>` 泛型 + 持久化 + 静态配置预检审计 (未知 section/字段 → 启动 WARN, #159) | 文件头部 `//!` (覆盖 OverrideMode / CRUD / Effective source / 跨表并发) |
| `provider.rs` | Provider sum type (Direct 直连 \| Router 路由 \| Pool 套餐池) + Route (model_pattern 通配 / priority / 路由级 upstream_model 重写) + PoolProvider/ExhaustConfig 与内置默认信号表常量 + Effective view + api_key 两来源 + `resolve_route` 路由链解析 (per-request; Router 跳按请求 model 匹配 + model 重写 pipeline, Pool 跳经 `PoolPicker` 状态机选成员) | 文件头部 `//!` |
| `pool.rs` | Pool Provider 运行时: 成员状态机 `PoolStates` (顺序 failover pick + 耗尽闹钟 + 配置对齐重建, 内存态不持久化) + 三通道耗尽信号检测器 `detect_exhaustion` (纯函数, ROB) + `PoolWatch` 响应侧旁路检测编排 + 观察面 (member_status / reset) | 文件头部 `//!` (含内置默认信号表语义域 + "提取宽判别严" 设计依据) + contracts.md **POOL-*** |
| `secrets.rs` | SecretEntry 实体 + Effective view + value 两来源 | 文件头部 `//!` |
| `mock.rs` | MockStrategy 两维度 (初始值 + 生成策略) + 确定性 seed + `[redact] global_mock_prefix` 注入 + GenSpec 候选空间配置期 lint (WARN, 弱 mock 策略前置暴露) | 文件头部 `//!` (C3 根基) |
| `dag/` (模块目录: mod/pool/types/view/timeline) | ConversationDAG 内容寻址存储 (BlockPool + Node + Merkle) | `src/dag/mod.rs` 头部 `//!` + `docs/design/conversation-dag.md` |
| `derive.rs` | 从 request body 派生 preview/model/text 的字节级提取 + delta messages 切片 (域 B 派生链, ROB-1 永不 panic) | 文件头部 `//!` (含 "为什么不在 web::api" 归属论证) |
| `dto.rs` | WebUI 响应 DTO 中立类型层 (SessionView/NodeView/.../SyncSnapshot, 域 B → 域 C wire shape; 构造逻辑留 dag) | 文件头部 `//!` (含 "为什么是顶层中立模块" 归属论证) |
| `error.rs` | 统一应用错误类型 `AppError` (转发链 + 鉴权层共用, 不反向依赖) | 文件头部 `//!` (含与 `web::api::ApiError` 分工 + Upstream/UpstreamTimeout message 净化回传契约) |
| `record.rs` | ForwardRecord (web 层 DTO, GET /records/{id} 响应 shape) | 文件头部 `//!` |
| `usage/` (模块目录: mod/store/pricing/summary) | 模型用量统计 + redact 审计: 上游回显 usage 采集 (UsageCtx, rounds 三态 + status 原始码) + SQLite 持久化 (writer 线程批量事务) + SQL 聚合 (hour 粒度) + models.dev 定价 + summary 派生 (设计 `docs/design/usage-stats.md`, 契约 USAGE-*) | `src/usage/mod.rs` 头部 `//!` |
| `redact.rs` | RedactionMap + redact/restore pipeline + 形式化契约 C1-C7 | 文件头部 `//!` |
| `util.rs` | 集中的哈希工具 + 文件权限收紧 (SEC-8) + 字符串截断族 (char boundary 安全, ROB-1) | 文件头部 `//!` |
| `codec/` | 跨协议 IR + Reader/Writer trait + StreamTranslate (OpenAI / Anthropic / Responses) | **`src/codec/AGENTS.md`** + `docs/design/ir-fields-roadmap.md` (IR 字段建模路线图: extra 边界 + 字段提升判定准则 + 实施批次) |
| `proxy/` | dispatch 路径选择 + fan_out 四路径 + Provider 鉴权 + router GET /models 本地合成 + provider 协议探测 (拆分为 mod/helpers/auth/models/recorder/same_proto/cross_proto/fan_out 子模块) | `src/proxy/mod.rs` 头部 `//!` |
| `state.rs` | 进程级共享状态 `AppState` (原 ProxyState, 上移见 #145) + HTTP 共享常量 `NO_STORE` | 文件头部 `//!` |
| `web/` | JSON API (`api/` 目录) + 单页 WebUI | **`src/web/AGENTS.md`** |
| `server.rs` | router 装配 + 双层状态注入 + graceful shutdown + Host/Origin guard 最外层挂载 | 文件头部 `//!` |
| `server_host_guard.rs` | Host 白名单 + Origin/Sec-Fetch-Site 校验 middleware (SEC-7: 防 DNS rebinding + CSRF 纵深; 白名单语义见文件头) | 文件头部 `//!` |

> `ProviderTable` 与 `SecretTable` 是 `DynamicTable<T>` (`src/config.rs`) 的类型别名,
> 通用合并 / CRUD / 持久化算法都在 config.rs; 各模块只补充类型特定的 EffectiveView
> 映射与 validate 钩子.

## 配置模型 (双层: Static + Dynamic) — 概览

| 文件 | 角色 | 谁写 | 进入 git? |
|---|---|---|---|
| `secret-guard.toml` | **声明式 (static)** 配置: providers / secrets / server / redact / auth. 进程内只读. | 用户手写 | ✅ 推荐 |
| `secret-guard.state.toml` | **动态 (dynamic)** 状态: WebUI 编辑结果 + 对 static 项的 decision. 删除即可重置. **含明文敏感数据** (dynamic secret value / 显式写入的 api_key), 敏感级别与 static 同级 (#157). | 程序自动 | ❌ 推荐 .gitignore |

合并语义 (OverrideMode: Default / PreferStatic / Disabled)、Effective source 4 种、
CRUD 操作语义、DynamicTable 持久化策略、跨表并发安全的详尽描述见 `src/config.rs` 头部.

> 用户向的配置字段参考在 **`docs/configuration.md`** (README 已链接). 改配置 schema
> (增删字段 / 改默认值) 时须同步更新该文档, 保持两份字段表一致.

Secret / Provider 的两种 value 来源 (`value`/`value_file`、`api_key`/`api_key_file`)
及其 fail-fast vs 热路径差异, 见 `src/secrets.rs` 与 `src/provider.rs` 头部.

### `[server]` 段字段 (static, 启动时读取一次)

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `host` | string | `"127.0.0.1"` | 监听地址. SEC-6: 默认回环, 防意外暴露到 LAN/WAN. |
| `port` | u16 | `8787` | 监听端口. |
| `records_capacity` | usize | `1024` | 内存中保留的转发记录条数上限 (FIFO 淘汰). |
| `upstream_connect_timeout_secs` | u64 | `15` | 上游 TCP+TLS 握手超时 (秒). `0` = 无限 (向后兼容, 不建议). 覆盖 reqwest `connect_timeout`. |
| `upstream_response_header_timeout_secs` | u64 | `60` | 上游响应头到达超时 (秒), **流式请求档** (TTFT 语义): 只对显式 `stream: true` 的请求生效. `0` = 无限. 超时记 504 record (防 `send().await` 永久阻塞). |
| `upstream_nonstream_response_header_timeout_secs` | u64 | `300` | 上游响应头到达超时 (秒), **非流式请求档** (整响应语义): 对其余请求生效 (缺 `stream` 字段也算非流式). 非流式响应头要等整个响应生成完, 60s 对它是错误量纲 (#175 事故: 74k token 上下文被 9 连续 504 误杀). 语义 SSOT = "显式顶层布尔 true 才算流式" (实现: `proxy::helpers::requests_stream` + codec reader, 两处等价). |
| `upstream_stream_idle_timeout_secs` | u64 | `120` | 流式 chunk 空闲超时 (秒). `0` = 无限. 防上游发完响应头后 body 卡住. |
| `allowed_domains` | string[] | `[]` | SEC-7 Host guard 信任域名 (反代 + 域名部署). 命中按名字精确匹配且端口宽松; 未声明域名仍 403. 含 `:` 形态/IP 字面量/localhost/空串条目 WARN 跳过. |

> 注: `[server]` / `[redact]` / `[auth]` 段仅在启动时读取一次, WebUI 修改不生效 (restart
> 才生效). 这是为了保持转发核心路径的零运行时配置开销.

### `[redact]` 段字段 (static, 启动时读取一次)

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `global_mock_prefix` | string | `""` | Auto 模式 mock 的统一前缀 (注入到每个 secret 的 `gen_spec.prefix`). 详见 `src/redact.rs` C5 契约. |
| `on_probe_exhausted` | `"fail_open"` \| `"fail_closed"` | `"fail_closed"` | Mock probing 耗尽时 (弱配置 + 对抗性 IR 无法生成唯一 mock) 的策略. `fail_closed` (默认, SEC-10 降级偏安全, 2026-09 翻转) 拒绝转发整个请求 (返回 503), 防止 secret 泄露; `fail_open` (显式 opt-in, 历史行为) 跳过该 secret 原样转发. 详见 `src/redact.rs::redact_ir_checked` 与 `src/config.rs::OnProbeExhausted`. |
| `on_unsupported_protocol` | `"fail_open"` \| `"fail_closed"` | `"fail_closed"` | codec 不覆盖的协议 (gemini/ollama) 上配置了 secrets 时的策略. `fail_closed` (默认, SEC-10, 2026-09 翻转) 拒绝转发整个请求 (返回 503), 停损防泄露 (message 只含协议名 + provider id + 出路提示, SEC-2 同型); `fail_open` (显式 opt-in, 历史行为) WARN + 放行透传 — secret 原样出站. **只管 secret 安全性**: 仅 model 重写降级 (无 secret) 时两模式都维持 WARN 透传. 详见 `src/proxy/same_proto.rs` from_native-None 分支与 `src/config.rs::OnUnsupportedProtocol`. |
| `on_fallback_restore` | `"withhold"` \| `"restore"` | `"withhold"` | codec 无法 parse 上游响应的 fallback 路径上 (body 仍是合法 JSON), 是否把 Mock 还原为 real 发给客户端. `withhold` (默认, SEC-10 降级偏安全) 保留 Mock 透传 — 失败/降级响应体是最高概率被客户端日志系统采集的内容, real 不默认投放进去, Mock 按 RED-5 可安全暴露; `restore` (显式 opt-in, RED-8 行为) 还原 mock → real (本地工具直接可用, 但 real 可能随日志扩散). 非 JSON 分支不受影响. 详见 `src/proxy/helpers.rs::restore_via_json_leaf_fallback` 与 `src/config.rs::OnFallbackRestore`. |
| `redacted_headers` | string[] | `[]` | 追加进 WebUI record header 脱敏名单的 header 名 (SEC-4): 启动时归一化 (trim + lowercase, 空串条目跳过, 见 `state.rs::normalize_redacted_headers`) 后按 lowercase header 名**精确匹配**, 与硬编码黑名单 (`proxy::helpers::is_sensitive_header`) 并集生效, 请求/响应两侧 record 记录点统一取 `AppState::redacted_headers`. 用于自定义 auth header (如 `x-my-service-key`). 默认空 = 行为不变. |

### `[usage]` 段字段 (static, 启动时读取一次)

> 完整字段表 (pricing_url / pricing_override 等) 见 `docs/configuration.md`;
> 模块契约见 `src/usage/` 头部 + `docs/design/usage-stats.md` + contracts.md `USAGE-*`.

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `true` | 模型用量统计总开关; false = 不采集不落盘 (零开销). |
| `retention_days` | u32 | `90` | 明细 SQLite 行保留天数; 0 = 永久. |
| `pricing_url` | string | models.dev | 定价数据源 (可自托管镜像). |
| `pricing_refresh_secs` | u64 | `86400` | 定价表 TTL (秒). |
| `pricing_override` | model → 价格表 | 空 | 自定义模型定价 ($/1M, 优先于 models.dev). |

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
    (`http://{host}:{port}/oauth2/callback`); path 必须保持 `/oauth2/callback`,
    只能换 scheme/host/port (如经反向代理暴露时).
- `api_keys` (`[[auth.api_keys]]` 数组, 默认空): 静态预设 API key 列表 (如 CI/CD 场景),
  启动时 hash 后注入 ApiKeyStore, 与 WebUI 签发的 key 共用同一池. 元素字段:
  - `label` (string, 必填): 显示名.
  - `key` (string) / `key_file` (string): 明文或文件路径, 二选一 (互斥语义同
    `[secrets]` 的 `value`/`value_file`, 见 `src/secrets.rs`).
  静态 key 不可删除, 只能 disable/enable.
- `secure_cookie` (bool, 默认 `false`): session cookie 是否带 Secure flag (本地 HTTP dev
  必须 false — true 时浏览器不回传 cookie); 经反向代理以 HTTPS 暴露时应设 true
  (见 `docs/deployment-nixos.md` "HTTPS 反向代理" 段).

配置示例 (`secret-guard.toml`):
```toml
[redact]
global_mock_prefix = "sgm_"
on_probe_exhausted = "fail_closed"          # 默认即 fail_closed (SEC-10); 显式写出便于审计
on_unsupported_protocol = "fail_closed"     # 同上
on_fallback_restore = "restore"             # opt-in: fallback 路径还原 mock → real (默认 withhold)
```

## 开发流程

```bash
# 一次性环境
nix develop --impure      # 进入 devShell

# 一键 check (fmt + clippy + machete + doc + nextest + typos + deny-offline)
# 注: doctest 当前禁用 (唯一 doctest 被 ignored), 需要时在 justfile 取消注释.
#     check 链内还含 check-webui-syntax (index.html 内嵌 JS 语法) 与
#     check-contracts (contracts.md property 落地标注 lint, #144).
just check

# 一键复现 CI P0 门禁全链 (check-features + check 主链 + file-size; "本地全绿 ⇒ CI 必绿" 的锚)
just ci-merge

# check 含覆盖率插桩 (P2 ci-periodic 档内容; 本地按需)
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

v3.0 三档 (org 分级契约, 见 lc-studio/forgejo-actions README; 命名即门禁):

| 档 | workflow | 触发 | 阻塞 | 内容 |
|---|---|---|---|---|
| P0 `ci-merge.yml` | PR + master push + 手动 | PR 合入 | check-features + check 主链 (fmt/clippy/machete/doc/测试/typos/deny-offline/check-contracts) + file-size |
| P1 `ci-deploy.yml` | master push + nightly + 手动 | 部署 | audit (CVE, 阻塞) + bench compare-save + nix build cargoHash (canary 探针, runner 无 nix-daemon 恒失败) (**非超集**偏差, 见 workflow 头声明) |
| P2 `ci-periodic.yml` | nightly per-SHA 去重 + 手动 (无 push) | 无 | check --coverage + coverage-gate + WebUI Playwright |

跳过/去重机制: 事件去重 (push 仅 master; PR 总是跑 — draft/WIP PR 除外) + 内容去重
(skip-if-passed 共享 action, ff-merge 后同 SHA 不重跑; P2 按 SHA 去重次晚自愈) + PR
并发去旧 (concurrency). WIP 门禁 (#204): draft PR 不触发 CI, 去 WIP 前缀时经 `edited`
事件自动补跑 (机制见 docs/ci.md "WIP 门禁")。

**本地复现锚点**: `just ci-merge` = P0 全链 ("本地全绿 ⇒ CI 阻塞项必绿"); P1/P2 的
本地近似入口见 justfile `ci-deploy` / `ci-periodic` recipe 注释。

> CI 实现细节 (checkout 策略 / 缓存复用 / 并发假设 / 评论写回 / 三档 step 明细与
> 迁移去向表 / 各 step 升级路径) 见 **docs/ci.md**。

### 客户端使用示例

OpenAI Python SDK:
```python
from openai import OpenAI
client = OpenAI(
    base_url="http://127.0.0.1:18787/o/openai-main/v1",  # SDK 不自动补 /v1, 需自带
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
| WebUI 回归 | Playwright (TypeScript) | `tests/webui/im-ui.spec.ts` (守卫前端不变量 UI-1..UI-7) |
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
(nix rust toolchain 不带 llvm-tools-preview 组件, 见 `nix/shells/default.nix`). 所有 coverage 命令
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
  暂态, 强制 deny 会频繁阻塞. 当前重复清单 (2026-09 实测, rand 0.10 + criterion 0.8
  升级 + CVE 批量 update 后), 两个口径:
  - linux 构建图 (`cargo tree -d`): **11 个家族** — base64 / cpufeatures / getrandom
    (3 版) / itertools / rand (3 版) / rand_chacha / rand_core (3 版) / syn /
    thiserror + thiserror-impl / tower-http;
  - Cargo.lock 全平台口径: **17 个家族** — 上述 11 个再加 bitflags / hashbrown /
    indexmap / r-efi / schemars / windows-sys.
  归因 (三类): ① **rand 簇** (rand / rand_core / rand_chacha / getrandom /
  cpufeatures): 我方 rand 0.8→0.10 (2026-09) 后的固有 spread — openidconnect /
  oauth2 钉 0.8, proptest / mockito (dev) 用 0.9, 我方 0.10; rand 0.10 的 default
  feature 链 (default → `std_rng` / `thread_rng` → chacha20) 把 chacha20 +
  cpufeatures 0.3 带进构建图 (ThreadRng 以 chacha20 为核心, 无法在保留 thread_rng
  的前提下裁掉), cpufeatures 0.2 来自 sha2 0.10 时代 crypto 链. 消解时点 =
  rand 0.8 侧持有者 (openidconnect / oauth2 / tower-sessions-core /
  rsa→num-bigint-dig 链) 集体升级.
  ② **itertools**: criterion 0.8 (dev) 用 0.13 vs openidconnect 钉 0.10
  (2026-09 criterion 0.5→0.8 引入), dev-only, 发布二进制无感.
  ③ lock-only 家族: indexmap 1.9 + schemars 0.9 + hashbrown 0.12 孤立老版本簇
  是 serde_with 的 legacy optional feature (serde_with 本身在 linux 构建图内,
  经 openidconnect 引入; 簇成员不进构建图); base64 0.23 / bitflags 1 /
  hashbrown 0.16 / r-efi / windows-sys 为禁用 optional feature 或非 linux
  target (wasm / windows / UEFI) 专属暂态 — 消解时点取决于上游移除对应
  optional feature, openidconnect / reqwest 自身升级只是载体, 均无独立升级条目.
  构建图内家族的解法已记录于 "后续工作": tower-http (reqwest 0.13 条目, 但 oauth2
  钉 reqwest 0.12, 实际被上游阻塞); base64 0.21 (openidconnect 钉) / getrandom /
  syn / thiserror 为生态暂态, 无独立条目.
- **sources**: 只允许 crates.io + 本地 path 源, 禁止私有 registry / git 直链 (难审计).

CI 已升级为阻塞门禁: 当前 `deny.toml` allow 列表已实测覆盖全部依赖 license (本地全绿),
用户决策直接加门禁不设观察期. 新 license 误报出现时更新 `deny.toml` 即可 (属正常维护).

## 部署

NixOS 部署两代姿势: 结构化选项 (`services.secret-guard` 的 providers/secrets.entries/redact/auth,
未显式设 configFile 时经 `nix/render.nix` 自动生成 toml, eval 期校验 fail-fast) + 手写
configFile (escape hatch, 互斥). 凭据注入 (LoadCredential / sops 直接路径) 与 secret
批量注入方案见 **`docs/deployment-nixos.md`**.

### nix flake 布局 (flake-fhs)

flake outputs 由 [flake-fhs](https://github.com/luochen1990/flake-fhs) 按目录树生成
(`layout.roots = ["/nix"]`, embed 布局), 目录约定:

- `nix/pkgs/<name>.nix` → `packages.<sys>.<name>` (callPackage 注入)
- `nix/modules/<name>.nix` → `nixosModules.<name>` (单文件 module, 无 enable 注入)
- `nix/shells/<name>.nix` → `devShells.<sys>.<name>` (evalContext 注入 pkgs/system)
- `nix/checks/<name>.nix` → `checks.<sys>.<name>` (callPackage; `nix/checks/scope.nix`
  补注 lib — scope 默认的 `pkgs.lib` 不含 `nixosSystem`, 见该文件头)

flake-fhs 不生成的 output 由 flake.nix 手动补: `overlays.default` (SSOT 在
`nix/overlay.nix`, module 内注入与 packages 共用), `packages.default` 别名.
`nixpkgs.config = {}` 显式清零框架默认的 `allowUnfree = true` (license 合规由
deny 体系把关, unfree 应被拒绝). `formatter` output = 裸 `pkgs.treefmt`
(flake-fhs 探测到仓库根 `treefmt.toml` 后自动切换) — 注意 `nix fmt` 仅在
devShell 内可用 (treefmt 调用的 nixfmt/taplo/ruff 需在 PATH; devShell 已备齐).
全仓格式化 SSOT = 根 `treefmt.toml` (覆盖 nix/rust/toml/py; 排除 md/yaml/ts
的理由见其头部), devShell `treefmt` 与 CI `just check-fmt` 读同一份配置;
CI runner VM 未预装 treefmt 时 check-fmt 降级 rust-only (见 justfile).
扫描名单目录之外的散件 (`nix/module.nix` / `nix/render.nix` / `nix/tests/`) 不被
收集 — 测试辅助库因此必须留在 `nix/tests/` (checks 目录内的裸 .nix 会被当 check).
`nix/modules/secret-guard.nix` 是薄组装层 (imports `nix/module.nix` 本体 + overlay
注入), 保持 `nixosModules.secret-guard` 的 "module + overlay" 语义.

- toml 渲染 SSOT: `nix/render.nix` (纯函数, 与 src serde schema 的同步契约见其文件头,
  契约测试 `nix/tests/render.nix` 锁定); 模块接线冒烟 `nix/tests/module-eval.nix`
  (build 期经 `nix/tests/assert-toml.py` 用 python tomllib 对生成的 configFile 做
  TOML 语法 + 结构 round-trip 断言, 与 render.nix 的 eval 期断言互补, 共同锁定
  "模块选项 → configFile 生成" 链路).
  两者经 `just nix-check` 接入验证链 (挂在 `just check` 链尾, recipe 内探测
  nix-daemon — CI runner 架构禁止 nix 求值故自动跳过, serde 漂移门禁由本地纪律承担)
  — src serde schema 变更时本地先红.

> 路径约定见上方"路由策略"表格; `/api/*` 子路由细节 (未匹配 404 no-forward)
> 见 `src/web/AGENTS.md`; 完整 URI 分配规划见 `docs/design/url-layout.md`.

## 已知限制 (MVP)

> **呈现策略 (2026-09 用户决策)**: 本段是限制项的**完整 SSOT** (面向维护者);
> README 不再维护负面清单, 以"协议支持矩阵 (正面) + Roadmap & 贡献 (机会框架)"
> 呈现同一事实 (`Protocol::codec_covered()` 是代码侧谓词 SSOT)。WebUI 新建
> provider 表单的协议词表只引导 codec 覆盖族 (`webui_protocols`, gemini/ollama
> 后端能力保留 — 存量编辑/探测推荐经前端 append "(experimental)" 选项)。
> 新增限制条目时同步评估: README 矩阵/Roadmap 与 probe note (`PROBE_NOTE_*`)
> 是否需要联动。

- **协议支持范围未经真实上游实地测试** (2026-09 用户决策, 开源诚实边界): Gemini /
  Ollama (仅透传, 无 codec) 与 Anthropic 协议及其参与的跨协议翻译, 测试覆盖全部基于
  mockito 模拟上游; 真实 Provider 上的实地验证尚未进行。README "协议支持" 与
  文档站已对用户声明此边界。后续实地验证时按协议逐族补集成测试 + 更新声明。
- **OpenAI 流式请求未开 `include_usage` 时无 token 统计** (usage-stats, USAGE-5):
  OpenAI 流式默认不回显 usage, 需客户端设 `stream_options.include_usage = true`;
  网关不代为注入 (FWD-1 未授权). 此类请求在 Usage 页只计请求数 (`requests_without_usage`
  / `cost_coverage` 指标可见), 页面有提示文案. Gemini / Ollama (无 codec) 同样无
  usage 回显提取 (P2 浅提取). 详见 `docs/design/usage-stats.md` §5.4.
- **usage 成本恒为估算**: models.dev 价目表 ≠ 实际合同价; 未列 cache 价的模型按宽松
  近似回退 (cache_read → input 价, cache_write → 1.25×input); 历史成本按当前价目表实时
  重算 (会随价目表漂移, UI 明示). session 徽章 (Records tab) 是进程内口径, restart
  归零; Usage tab 是持久账本 (SQLite) — 两套口径不同, 页脚说明.
- **reasoning_content (思考原文) 跨协议丢弃** (#176, 契约 STR-6): OpenAI 兼容 provider 的
  思考原文 (`delta.reasoning_content` 流式 / `message.reasoning_content` 非流式 /
  assistant 历史回传) 已建模为 `IrBlock::ReasoningContent`, 同协议路径 (含 Redact) 三路径
  reader↔writer 对称 + 流式 restore 覆盖. **跨协议翻译时丢弃 (有 WARN)** — Anthropic
  thinking block 需要 signature (无法合法合成), Responses reasoning item 依赖
  `encrypted_content` (rationale 见 `src/codec/AGENTS.md` 支持矩阵注记). 丢弃时
  `cross_proto_forward` 按 block 计数打 WARN (请求侧历史 / 响应侧各一条, 只记计数
  不记内容, 见 `proxy/cross_proto.rs::count_reasoning_blocks` 的假设声明).
  边界: 请求侧 assistant 历史的显式空串/null 由 `reasoning_content_form` wire 元数据保真;
  **响应侧** `IrResponse` 无对应元数据 — 上游非流式响应显式返回 `"reasoning_content": ""`
  时, redact 路径 round-trip 后该字段会变为缺席 (信息无损失, 形态有差异).
- **OpenAI Responses API 支持范围**: Responses 协议 (`/r/` proto_short) 已接入 codec,
  支持 Responses ⇄ Chat Completions / Anthropic 跨协议翻译 (非流式, 经通用 IR 路径,
  双向各有集成测试锁定) + Responses 同协议透传 + Redact (非流式).
  **不支持**: Responses 流式 SSE 事件翻译 (Responses + **Redact 命中** (map 非空) + `stream=true`
  返回 501, 防止 mock 静默外流; 仅路由 model 重写 (map 空, 响应无需 restore) 时流式放行 SSE 字节
  透传 — #183 D5 收窄, `resp_parsed` 因事件未解码降级 None, 前端占位;
  跨协议 Responses 任一侧 + `stream=true` 同样 501 — 含 Responses⇄Anthropic pair);
  hosted tools (web_search/file_search/computer_use/mcp → reader 读取时丢弃并有 WARN
  (`dropping tool definition(s) not representable in IR`, responses reader 丢弃点 —
  同协议 IR 重建路径同样丢弃, 仅纯字节透传不受影响; hosted tools 不进 IR 也不进
  extra, tools 是 collect_extra 的 modeled 排除键); MCP 在客户端 LLM 请求中
  的呈现形态与协议约束边界调研见 `docs/research/mcp-notes.md`); namespace tools
  flattening; `previous_response_id` 服务端状态 (secret-guard 是 stateless 代理);
  reasoning items 的 `encrypted_content` (同协议 round-trip 也会丢失, 会破坏 reasoning chain).
- **Responses 协议的 timeline delta 为空**: Responses ingress 的 `req_body_raw` 用 `input[]`
  (而非 `messages[]`), `extract_delta_messages_from_raw` 找不到 messages 字段, 返回空 Vec.
  WebUI timeline 仍能显示 preview / role, 但不渲染增量气泡 (与跨协议 ingress 的 delta 限制一致).
- **Mock probing 耗尽 (默认 fail-closed 拒绝转发, SEC-10)**: 弱配置 (charset/length 仅产生
  极少候选) + 对抗性 IR 可能让 `redact_ir` 的 mock probing 耗尽 (`MOCK_PROBE_LIMIT`).
  配置写入时 (static 加载 / WebUI upsert) 会对 GenSpec 候选空间做 lint WARN
  (`MockStrategy::lint_candidate_space`, 阈值 `MIN_CANDIDATE_SPACE_WARN` = 2^20,
  低于即 WARN, 不拒绝) — 把这类弱配置前置暴露.
  默认 `[redact] on_probe_exhausted = "fail_closed"` (**拒绝转发**, 返回 503, 防止
  secret 泄露到 LLM provider, SEC-10 降级偏安全 — 2026-09 自 fail_open 翻转; 配置期
  lint 已把弱配置拦截在写入时, 运行时残余正是对抗场景). 历史 fail-open 行为 (warn +
  跳过该 secret 原样转发) 需显式配 `"fail_open"` opt-in. 注意 fail_closed 拒绝时返回
  的 503 body 不含 secret 明文 (变量部分只含 secret id + reason 枚举, 语义由 SEC-2
  契约锁定).
  **显式 `fail_open` opt-in 的 WebUI 回显边界 (2026-09-15 走查明确)**: 被跳过的 secret
  随请求原样转发, 该轮 record 的 `req_body_raw` 与派生 `preview` 含**未脱敏的真实
  secret**, 经读端点族 (`GET /api/records/{id}` / `GET /api/sessions` timeline /
  `POST /api/sync`) 回显到 WebUI. 其中 GET 端点族与 SEC-1 契约 ("任意 GET 响应不含
  真实 secret", 其扫描测试只覆盖 redact 成功路径) 直接冲突; `POST /api/sync` 是读
  语义端点, 泄漏事实同源. **SEC-10 默认翻转后该边界仅影响显式 opt-in `fail_open`
  的部署** (默认配置下 probing 耗尽走 503 拒绝, record 不含未脱敏 secret — 冲突面
  在默认配置下消失); 默认 Auto 模式下 probing 耗尽概率本身天文级小 (C5 重试链).
  安全敏感部署应保持默认 `fail_closed`. SEC-1 契约例外条款是否为显式 opt-in 路径
  正式登记 (含陈述范围是否从 GET 扩到读端点族), 留待人工裁决 (contracts.md §0.5
  流程; 默认已安全, 优先级低).
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
  按 `[redact] on_fallback_restore` 分流 (SEC-10): 默认 withhold 保留 Mock 透传
  (real 不还原 — 失败响应体高概率进客户端日志); 显式 `"restore"` opt-in 时先尝试
  JSON 叶子级 restore 兜底 (RED-8, body 仍是单个 JSON error envelope 时可还原 mock),
  仅当兜底也失败 (如 SSE-shaped 多帧 body) 才原样返回. 两形态都打 WARN
  (`mock not restored; client will see mock values`, #158 — WARN detail 的 opt-in
  提示只在 reader-拒绝 + 单 JSON 臂出现 (restore 唯一有意义的地方); 非 JSON 臂
  (含本条目的 SSE 多帧场景) 无提示, restore 本就无意义).
- **流式 + Redact + 上游 Content-Type 非 text/event-stream**: 判型跳过流式 restore,
  落入 buffered fallback. 该 fallback 同按 `on_fallback_restore` 分流 (SEC-10):
  默认 withhold 保留 Mock 透传; 显式 `"restore"` 时 body 是单个 JSON Value 的 mock
  可被还原 (RED-8), 仅当兜底也失败 (如 SSE-shaped 多帧 body, #158 发现的第三条
  逃逸路径) 才透传 (客户端看到 mock).
  兜底失败时有两层 WARN: 判型处 (`non-SSE content-type for a stream=true request`) +
  parse 失败 fallback (`mock not restored`).
  后续效应: 客户端把 mock 回传进下一轮历史时, 触发 RED-3 例外场景 (mock 跨轮变化,
  见 contracts.md RED-3 例外裁决 / #143).
- **同协议 + Redact + 非流式 2xx + 上游响应 parse 失败**: 上游返回的 body 不是合法 JSON 或 codec
  reader 无法 parse 时 (类型不符 / 空数组 / 越界), 转发路径 fallback 为透传含 mock 的字节, 无 restore,
  客户端收到 mock. 同协议路径见 `src/proxy/fan_out.rs` (non-stream 分支), 跨协议路径见
  `src/proxy/cross_proto.rs`. 均走 best-effort 鲁棒性原则 (ROB-*), parse 失败不 panic.
  **JSON 叶子级 restore 兜底 (RED-8, opt-in)**: 默认 `on_fallback_restore = "withhold"`
  (SEC-10) — reader-拒绝但 body 仍是单个合法 JSON 的分支**保留 Mock 透传** (real 不
  还原 + `mock not restored` WARN 含 opt-in 提示); 显式配 `"restore"` 时两路径的
  fallback 分支才会先尝试 `redact::restore_json_leaves_fallback` (在字符串值叶子上
  还原 mock + `mocks restored via JSON leaf fallback` WARN), 且仅当兜底也失败 (非
  JSON / SSE-shaped 多帧 / 无命中) 才透传 + `mock not restored` WARN (同协议 #158;
  跨协议已对称补齐, 含此前静默的非 JSON 分支). 非 JSON 分支不受开关影响 (restore
  本就无意义).
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
- **router /models 合并清单的上游数据最旧可 stale 300s (#196, FWD-7)**: 上游清单缓存 TTL = 300s
  常量 (不进配置), TTL 内上游新增/下线的模型不会反映在 router /models 响应中; 刷新失败时继续
  serve 旧数据 (serve-stale-on-error), 且失败后 30s 退避窗口内不重试 (期间查询立即返回, 不被
  dead upstream 逐查询阻塞)。exact-only router 不 fetch (只返回别名, N6 gate)。
  缓存按 provider id 键控: WebUI 修改 provider 的 base_url/protocol 后, 最长 300s 内继续 serve
  旧上游的清单 (TTL 到期自然收敛)。
- **未声明域名 Host 一律 403 (SEC-7 Host guard)**: server 层对所有路由做 Host 白名单
  校验 (防 DNS rebinding, 语义见 "Host / Origin 校验" 段), 未声明的域名 Host 拒绝。
  经反向代理以域名 (如 `sg.example.com`) 暴露 secret-guard 的部署, 需在
  `[server] allowed_domains` 声明该域名 (反代保留原始 Host, 见
  `docs/deployment-nixos.md` "HTTPS 反向代理" 段的推荐配置), 或直接用
  IP / localhost 访问。声明域名端口宽松 (按名字精确匹配)。
- **敏感落盘文件收紧为 0600 (SEC-8)**: state.toml / usage.sqlite3 (含 `-wal`/`-shm`
  侧车, writer 线程每批落库后收紧) / pricing.json 在 unix 下创建即 owner-only,
  启动加载时对旧版本残留文件 best-effort chmod 收紧 (helper
  `src/util.rs::tighten_file_permissions`, 设备文件与更严形态 (0400 等) 跳过)。
  依赖 group/other 读这些文件的部署 (如共享目录跑第三方读取器) 会受影响。
- **redact_headers 名单 = 硬编码黑名单 ∪ `[redact] redacted_headers` (SEC-4)**:
  `proxy/helpers.rs::redact_headers` 的敏感 header 脱敏名单以硬编码黑名单为基础
  (显式枚举主流 provider auth header + 含 "token" / "secret" 子串匹配, 完整名单以
  `is_sensitive_header` 为 SSOT), 用户可用 `[redact] redacted_headers = [...]`
  追加自定义 auth header (如 `x-my-service-key`) — 条目启动时归一化 (trim +
  lowercase, 空串跳过) 后按 lowercase header 名**精确匹配**, 并集生效; 默认空 =
  行为不变。注意精确匹配非子串匹配 (`x-my-key` 不波及 `x-my-key-v2`)。
- **session cookie Secure flag 需手动配置 (`secure_cookie`, 无自动推断)**: HTTPS
  反代部署需手动设 `[auth] secure_cookie = true` (NixOS 结构化选项
  `services.secret-guard.auth.secureCookie`, 2026-09-16 已暴露 — 此前须 configFile
  escape hatch). 残余缺口: 无 `X-Forwarded-Proto` 动态推断 (见
  `docs/deployment-nixos.md` "HTTPS 反向代理" 段). 忘设的缓解 = 反代 HTTP→HTTPS
  301 重定向.
- **DAG 孤儿节点降级**: parent 被 LRU 淘汰后, child 的 `full_request_messages` 返回 None
  (timeline 降级展示, 不 panic). 显式孤儿标记 `NodeView::is_orphan` 已实现 (CDAG-7,
  读时纯派生: parent 有值但在 nodes 缺席); wire DTO (ForwardRecord / TimelineRound)
  传播与前端徽章利用留后续 — 打通前该字段仅在 NodeView 层可见.
- **static 基线下 PUT 空串 api_key 无法清空 key (#157 已知限制)**: dynamic override 的
  `api_key` 落盘形态无法区分 "未记录" (PUT null → 空串, effective 继承 static) 与
  "显式清空" (PUT `""` → 空串) — 两种空都会被 `inherit_from_static` 继承 static 旧 key.
  停用 provider 请用 `PATCH .../decision {"mode":"disabled"}`. WebUI 编辑留空发 null
  (保留语义), 仅 SDK 显式发空串可见. 根治需 schema 演进 (请求字段 Option 化或 sentinel
  值), 属后续工作.
- **dynamic-only 条目 Direct ↔ Router/Pool 构造切换往返丢 api_key (#187 已知限制)**:
  sum type 下 Router/Pool 构造无处存放鉴权字段, 切回 Direct 时无恢复来源 (static 基线
  条目不受影响 — `inherit_from_static` Direct↔Direct 从 static 复原; Direct↔Pool 与
  Direct↔Router 同型)。失败是静默的 (空 key 出站 → 上游 401 才暴露), WebUI 表单
  placeholder 变化 ("(optional)" 而非 "unchanged") 是唯一提示。根治需虚拟构造携带被
  遮蔽的 Direct 字段 (违背 sum type 简洁性) 或 WebUI 本地暂存, 均不划算。
- **pool 成员 missing/disabled 在解析时跳过, 无持久标记**: resolve_route 对
  missing/disabled 候选**跳过但不写状态机** (配置可用性不进耗尽闹钟 — GET /models
  的可解析性探针复用同一解析路径, 无持久副作用); 成员重新启用/补建后下一次解析即
  自动回归列表头, 无需 reset / 重启。
- **pool 耗尽检测不覆盖流式 2xx 的 mid-stream SSE 错误事件**: 检测挂在 "上游错误
  响应 (4xx/5xx, body 已缓冲)" 的位置, `PoolWatch` 对 2xx 直接短路 — 假设: 智谱/Claude
  撞窗在 HTTP 层拒绝 (429 + 错误信封), 不在 SSE 流中 (假设声明见
  `pool.rs::detect_and_mark`)。若某上游改为在 2xx SSE 流内报告窗口耗尽, 该信号不可见
  (成员不会被标记, 不切换)。
- **pool 内置默认信号表是发布时点快照**: 常量 `DEFAULT_WINDOW_EXHAUST_CODES/HEADERS`
  编译进二进制 (智谱 1308/1310 + Claude unified headers), 各家可能新增/变更窗口限额
  错误码 — 网关不感知, 表现为该信号下不切换成员。用户可经 `[providers.exhaust]`
  自行补码 (字段级替换语义, opt-in 姿势清单见 `docs/configuration.md`)。
- **路由 model 重写生效时放弃 byte-exact (#183, FWD-1 修订; 规则级化 2026-08-25)**:
  路由链命中了携带 `upstream_model` 的路由的请求, 其同协议无-secret 分支从字节直传降级为 IR 改写
  路径 (normalize 等价; 上游前缀缓存失效 — 用户主动选择的降级, 契约层面已由 FWD-1
  修订授权, §99 登记). Gemini/Ollama + 重写无法改写: WARN + 原样透传 (body 不变).
- **Gemini/Ollama 同协议 + secrets: 无 codec 无法 Redact (默认 fail_closed 停损, SEC-10)**:
  codec 只覆盖 OpenAI/Anthropic/Responses; gemini/ollama provider 上配置了 secrets 时,
  默认 `[redact] on_unsupported_protocol = "fail_closed"` (**拒绝转发** — 返回 503,
  message 只含协议名 + provider id + 出路提示, SEC-2 同型, 上游零请求; 2026-09 自
  fail_open 翻转, SEC-10 降级偏安全). 历史 WARN + 降级字节透传行为 (secret 原样出站,
  静默降级放行) 需显式配 `"fail_open"` opt-in. 仅 model 重写降级 (无 secret) 不受
  开关影响, 两模式都维持 WARN 透传.
- **路由 provider 跨条目环的残余缺口仅剩启动后 TOCTOU 窗口 (#179)**: 自环在
  `Provider::validate` (static 加载 fail-fast) 拒绝; 跨条目环的拦截点: WebUI upsert
  (`would_cycle`, 边集 = 启用路由的 target) / 运行时 (`resolve_route` visited-set,
  503) / **启动诊断** (`ProviderTable::find_cycles`, `serve()` 对 merged 视图整体做
  环检查, 每个检测到的环一条 WARN 含环路径; 存在性完备 — 有环必有 WARN — 但不枚举
  全部简单环, 修复已报告环后重启暴露残余环 — 手改 state.toml 漏网的环在启动日志即暴露, 不必
  等首个请求 503; 不阻塞启动, 环只影响该 provider 的请求, state.toml 永远可删除
  重置, fail-fast 会把可恢复状态变成启动死锁). 残余缺口: 并发 upsert 的 TOCTOU
  (环检查与落库非同一临界区) — 启动后动态产生的环 (启动检查天然覆盖不到) 只有
  运行时 503 兜底 — 单用户本地工具的可接受假设, 与 #157 的 update TOCTOU 声明同型.
  pool 侧同型声明: dispatch 构造 `PoolWatch` 时对 pool 条目的二次 `get_effective`
  与并发 pick/mark 交错的 TOCTOU 由 `PoolStates` 按位置对齐自愈 (stale 标记暂态,
  下次耗尽信号纠正 — 见 `src/pool.rs` PoolStates 并发声明确认).
- **auth 模块测试覆盖率 (OIDC 登录流程)**: auth 模块纯逻辑 (apikey / middleware /
  session / mod) 高覆盖, 含 require_api_key 的 Authorization 剥离断言 (SEC 红线) 与
  build_session_layer 的 cookie 配置 (sg.sid + HttpOnly). OIDC 集成测试
  (`tests/auth_oidc.rs`) 已通过本地 mock IdP server 覆盖 (起 axum server 模拟
  discovery + token + jwks + RS256 签 id_token, 支持密钥轮换与 discovery 故障注入):
  - `oidc.rs`: `OidcBackend::discover` (含 issuer 字符串校验 / JWKS 拉取) /
    `exchange_and_verify` happy + 5 个错误路径 (CSRF mismatch / token HTTP 4xx /
    NoIdToken / WrongSignature / WrongNonce) / `authorize_url` PKCE verifier round-trip /
    **JWKS 轮换恢复** (SEC-AUTH-3, #198: 轮换后无需重启登录成功 + 刷新失败返回
    原始错误且 IdP 恢复后自愈; 重验仍失败不放行坏签名由 WrongSignature 兼守).
  - `handlers.rs`: `login_start` (重定向 + session 写入 + sanitize_next_url) /
    `oauth_callback` 错误路径 (IdP error 参数 / 缺 session 凭证 / PKCE 验证失败) /
    `logout` / `me` / **`oauth_callback` happy path 完整端到端 round-trip** (mock
    IdP `/authorize` 记录 nonce + code_challenge, code-绑定 `/token` 真实执行 PKCE
    S256 比对并用 stored nonce 签发 id_token; 测试经 sg.sid cookie 驱动
    login → authorize → callback → /api/me 全链, PKCE 负对照
    `oauth_callback_rejects_pkce_verification_failure` 守卫比对非摆设).
  (精确百分比是 `just coverage-html` 实时产物的职责, 此处不维护快照数字.)

## 后续工作 (非 MVP 范围)

- **更多协议**: Gemini / Ollama / Bedrock / Cohere / OpenAI Responses API.
  新增协议只需实现 Reader + Writer trait (~200 行), 不动 dispatch.
- mock_secret 的 category-aware 默认生成 (Password/ApiKey/Cookie 等格式感知).
- 配置热加载; 测试覆盖率自动上报 + fuzzing (cargo-fuzz).
- **依赖升级** (滞后是稳态, 非风险; Cargo.lock 锁定保证可复现构建; 触发条件满足时再升,
  默认触发条件 = CVE / 解 duplicate / 需要 feature, 各子项仅标注例外;
  2026-09 已完成: CVE 批量 update (rustls 0.23.45, RUSTSEC-2026-0285) / rand 0.10 /
  criterion 0.8:
  - sha2 0.10 → 0.11: 注意 openidconnect 4.0.1 **直接**依赖 `sha2 ^0.10.6`, 且经
    oauth2 5.0.0 再依赖 `sha2 ^0.10` (双重阻塞), **升级主依赖也无法解 duplicate**,
    直到 openidconnect 上游升级.
  - tower-sessions 0.14 → 0.15: **需与 axum-login 同步升级**
    (axum-login 0.18 当前硬依赖 tower-sessions 0.14, 单独升会 duplicate).
  - reqwest 0.12 → 0.13: **被 oauth2 上游阻塞** — oauth2 5.0.0 (2025-01, 仍是最新)
    的 reqwest 集成 (openidconnect 的 `reqwest` feature 所启用) 钉 `^0.12`; 单独升
    我方会形成双 HTTP 栈 (OIDC 走 0.12 / 转发走 0.13, hyper 连接池与 TLS 各两套),
    解 tower-http duplicate 的收益不抵双栈成本. 升级时点 = oauth2 上游支持 0.13.
    届时注意 0.13 breaking 较多 (`rustls-tls` feature 改名 `rustls`, rustls roots
    改用 `rustls-platform-verifier`, 需验证行为).
  - parking_lot 0.12.5 (当前最新): 当前最新稳定版. 长期可评估迁移到 `std::sync::Mutex/RwLock`
    (Rust 1.62+ 后 std 锁性能已接近 parking_lot, 可减少一个依赖). 触发条件 = 解 duplicate /
    减少依赖数.

### 已知搁置 (有意识的不做)

- **OIDC JWKS 刷新无退避/negative-cache (#198)**: `OidcBackend::exchange_and_verify`
  遇签名类验签失败时每次都重跑 discovery (对比 #196 的 ModelListCache 有 TTL +
  serve-stale + 30s 退避). 不做的原因: 登录是人工低频操作 + 重试严格有界 (只一次,
  且触发前置是 token exchange 成功, 伪造 token 无法触发放大) + 真实轮换 (月频)
  只有首个请求付代价. 若未来出现 IdP 异常期间的 discovery 压力, 再补"上次刷新
  失败后 X 秒内不重试"的单时间戳退避.
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
