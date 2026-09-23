# 模块依赖方向图 (SSOT)

> 职责边界: 本文件是 secret-guard crate 内模块依赖方向的**唯一事实来源** — ASCII 依赖图、
> 分层要点、已接受的例外清单. 数据流契约 (域 A 转发链 → 域 B 派生链 → 域 C 渲染层)
> 的单向承诺见根 `AGENTS.md` "数据流契约" 段; 本文件是其实施层 (#145).
>
> **何时读**: 新增任何 `use crate::...` 依赖前. 只允许**向下**依赖 (指向更低层);
> 反向 / 新横向依赖需先改本文件 (图或例外清单) 并在 PR 中说明理由.
>
> 维护约定: 例外清单是登记类 — 每条例外一个单行 bullet, 按 "源 → 目标" 边名字母序插入,
> 必附 rationale; 无 rationale 的边不接受.

## 依赖图 (主干)

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

## 分层要点 (每条已按 #145 收紧; 完整边以代码为准, 本图标注**意图方向**与例外)

- **codec ⇄ redact 已解环**: redact → codec 单向; codec::stream 经 `StreamRestoreHook` 接口倒置消费 restore 能力, 生产实现 `redact::StreamingRestorerSet` 由 proxy 注入 (codec 的 fwd_* property 测试仍 import redact — 测试代码不受此约束).
- **dto / record 是中立 wire shape 层**: dag 构造之, web 序列化之, 两者互不依赖 (dag 不再触达 web 命名空间, #95 残留落点已纠正). 注: dto → {dag, codec::ir} 仅纯类型 (前者 `SessionId` newtype 标识, 后者 `IrRole`/`IrUsage`), 视作可接受的纯类型依赖.
- **state (AppState) 是进程级共享状态**: proxy / web / auth 各自单向依赖之, 彼此之间除 "web → auth (挂载 guard)" 与 "web/api/providers → proxy::models" (probe 端点, 见例外清单) 外无横向依赖 (原 ProxyState 落在 proxy 内).
- **pool 与 provider 同格** (图上同格, 层级在 provider 之上): `src/pool.rs` 的套餐池运行时 (成员状态机 + 耗尽检测器) 只向下依赖 provider 的**类型** (`PoolProvider`/`ExhaustConfig` 定义在 provider.rs; `PoolPicker` trait 接口倒置 — trait 定义在 provider.rs 供 `resolve_route` 图遍历消费, 生产实现 `PoolStates` 在 pool, 由 proxy dispatch 注入, 先例同 codec::StreamRestoreHook — 保持 pool → provider 单向). 消费边 proxy → pool / state → pool 见例外清单.

## 已接受的例外 (有 rationale, 勿扩大; 按边名字母序)

- **codec → provider**: 仅 Protocol 枚举做 from_native 映射, 纯类型依赖; 长期归宿: 若 codec/provider 拆 crate, Protocol 全局枚举应下沉基础层, 桥接函数自然消失.
- **config → {auth, provider, secrets}**: AuthConfig/ApiKeyEntry 与 Provider/SecretEntry 均是配置 schema 的组成部分 — static 加载期组合 + validate 钩子调用, 纯数据依赖; provider/secrets 同 auth 型, 走查补登记.
- **dag → codec**: IrBlock 是内容寻址单元, 纯类型依赖; 另 dag/types 的 `ingress_protocol` 字段引用 codec::Protocol 枚举, 同性质.
- **dag → config (类型)**: #273 errors 档 — `CallEvent.capture_mode` 引用 `config::AuditCaptureMode` (纯数据 enum + 纯函数决策 capture_req/retain, 无 config schema/机制依赖); 与既有 dag→codec 纯类型边同性质.
- **derive → redact**: B1 timeline blocks 派生 — `rebuild_real_to_mock_pairs` / `apply_real_to_mock_messages(_blocks)` 纯函数借用 (real→mock 替换原语 `replace_in_place` 与 redact_ir_inner 同一实现, 保证派生与当年改写字节等价), 无 redact 状态依赖; 域 B 派生链内横向边, 拒绝以此为先例引入 derive → redact 的行为依赖 (如 StreamingRestorer).
- **mock ↔ secrets 对称引用**: SecretEntry 持 MockStrategy, mock 校验钩子被 SecretEntry 调用, 纯数据/校验层, 无业务行为.
- **provider → secrets**: 仅 validate_id/mask_value 两个校验/脱敏工具函数复用, 纯函数借用, 无实体耦合.
- **proxy → auth::AuthenticatedTenant**: v4b redact 审计归因 — proxy 从 request extension 提取 API key label 注入 usage 采集, 纯类型依赖, 性质同 config→auth 的 AuthConfig 纯数据边, 无 auth 行为依赖.
- **proxy → config**: 仅降级 gate / 超时快照的纯数据枚举与结构 (`OnProbeExhausted` / `OnUnsupportedProtocol` / `OnFallbackRestore` / `UpstreamTimeouts`): 转发路径降级决策的输入, 消费点 same_proto from_native-None 分支 / helpers restore 门控 / recorder redact_and_derive, 纯数据依赖无 config 行为依赖, 性质同 redact → config.
- **proxy → pool**: 套餐池转发即状态机驱动 — dispatch 经 `PoolPicker` 注入候选解析 (active_members), 响应侧 `PoolWatch::detect_and_mark` 旁路检测, 同属域 A 转发链, 性质同 proxy → redact 的 "转发即改写".
- **proxy → redact**: 转发即改写, 同属域 A.
- **redact → config**: 仅 `OnProbeExhausted` 枚举 — `[redact] on_probe_exhausted` 的消费点, 纯数据枚举.
- **redact → secrets**: 探测 secret 需读 entry.
- **state → config (行为)**: B2 — AuditCapture 的开关持久化复用 config 的 DynamicState RMW 机制 (load_or_empty + to_toml + atomic_write), 与 provider/secret/apikey 表的 set_decision 同型 (纯机制复用, 无 config schema 之外的行为依赖); 基线已有的 `OnProbeExhausted` 等纯类型枚举边为存量走查补登 (性质同 usage→config / proxy→config, 因 state 位于基础层而升级为例外).
- **state → pool**: AppState.pools 聚合 `PoolStates` 纯数据+状态机 store, 组合根先例同 state → usage 的 UsageStore / state → auth 的 ApiKeyStore — 见 `src/state.rs` 字段注释; web 观察面 list_providers 的 pool_status 与 pool-reset 端点经 AppState 读同一份.
- **state → proxy::ModelListCache**: #196 — AppState 聚合 router /models 的上游清单缓存, 纯数据 store 无 proxy 行为依赖, 组合根先例同 state → auth 的 ApiKeyStore — 见 `src/state.rs` 字段注释.
- **state → usage**: usage-stats — AppState 聚合 UsageStore / PricingCache 两个纯数据 store, 同一先例; usage 模块未画入图 (聚合根旁的纯数据+派生层, 主干外), 图外另有 web/api/usage.rs → usage (GET /api/usage/summary 直读 UsageStore 聚合 + summary 纯函数派生, 域 B 派生链消费). usage 模块自身仅依赖 codec::ir / secrets / dag::RoundKind 纯类型 / config schema 纯数据类型, 见 `src/usage/` 头部 — usage→config 是向下合法边, 非例外, 性质同 provider→config; usage→dag 仅引用 RoundKind 枚举, 同 dto→dag 的纯类型依赖先例.
- **web/api → auth::apikey**: API key CRUD 无条件挂载, "只认证不隔离".
- **web/api/providers → proxy::models**: probe 端点复用上游模型清单探测基建 + models 预览端点复用模型清单 fetch/合成基建 — `provider_model_preview`; 行为借用 — `probe_provider_upstream` / `provider_model_preview` 均执行出站 HTTP 探测/fetch, 非纯数据/纯函数, 但复用同款 fetch 防御 (整体超时/有界累积/错误净化) 且无转发链状态依赖, handler 只是薄壳, 无独立实现 — 勿以此为先例扩张 web → proxy 的行为依赖.
