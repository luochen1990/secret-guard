# secret-guard 数据正确性契约

> Status: **normative (尺子)** — 本文档定义 secret-guard 数据正确性的**理想目标**.
> 每条契约是断言式的"应该是什么", 不是描述性的"现在是什么".
> 现状符合度由源文件头部 `//!` 注释 + 设计文档的 implementation drift 标注负责.
>
> Scope: client ↔ upstream 转发链 + upstream → DAG → webapi → WebUI 派生链 的全部数据正确性属性.
>
> 与本文档的关系:
> - 源文件头部 / 模块 AGENTS.md 的局部契约 (C1-C7, INV-*, I1-I3 等) 是**模块级细化**, 本文档**收录并重新编号**, 不替换原位置.
> - 编号映射见 [§0.2 编号映射](#02-编号映射).
> - 当本文档与源文件头部冲突时, **本文档为准** (源文件头部需同步修正, 见 [§0.3 漂移处理流程](#03-漂移处理流程)).

---

## 0. 导读

### 0.1 数据流与信任域

```text
┌─────────────────────── 信任域 A: 转发链 (forward pipeline) ───────────────────────┐
│                                                                                   │
│   client ──► ingress ──► codec.reader ──► redact ──► codec.writer ──► egress ──► upstream
│     ▲                                                                       │
│     │                                                                       ▼
│   client ◄── ingress ◄── codec.writer ◄── restore ◄── codec.reader ◄── egress ◄── upstream
│                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼ (proxy 层 fan_out 累积)
┌─────────────────────── 信任域 B: 派生链 (derivation pipeline) ───────────────────┐
│                                                                                   │
│   upstream bytes ──► StreamScan ──► resp_parsed                                   │
│   upstream bytes ──► DAG Node (req_delta + response)                              │
│   RedactionMap    ──► redactions 字段                                              │
│   req_body        ──► preview / model                                              │
│   req_body_raw    ──► req_delta_messages                                           │
│                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼ (webapi 序列化为 JSON)
┌─────────────────────── 信任域 C: 渲染层 (rendering) ─────────────────────────────┐
│                                                                                   │
│   webapi JSON ──► index.html DOM                                                  │
│     sessions       ──► sidebar 一级                                               │
│     timeline       ──► sidebar 二/三级 + timeline .tl-round                        │
│     parsed view    ──► response drawer                                            │
│                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

**三域分工**:
- **域 A (转发链)**: secret-guard 核心职责. 对任意字节流零失败. byte-exact 是最高目标.
- **域 B (派生链)**: 附加功能, best-effort 永不 panic. 派生字段必须与原始数据视图一致.
- **域 C (渲染层)**: WebUI 可视化. DOM 状态必须与数据模型一致.

**域间契约**: 每个域向下游域承诺不变量, 下游域不得违反. 域 A 的字节正确性是域 B/C 一切派生的根基.

### 0.2 编号映射

本文档采用 **段前缀 + 序号** 的契约编号 (如 `FWD-1`, `RED-3`). 现有局部契约完整收纳, 映射如下:

| 段前缀 | 域 | 现有编号 → 新编号 | 原位置 |
|---|---|---|---|
| `FWD-*` | 转发忠实性 (域 A) | codec INV-1/2/5 → FWD-1/2/5; proxy DoD → FWD-4/6 | `src/proxy/mod.rs` 头部 + `src/codec/AGENTS.md` |
| `RED-*` | Redact/Restore (域 A) | C1→RED-1, C2→RED-2, C3→RED-3, C4→RED-4, C5→RED-5, C6→RED-6, C7→RED-7, C8→RED-8 | `src/redact.rs` + `src/mock.rs` 头部 |
| `STR-*` | 流式 SSE (域 A) | codec INV-4 → STR-5 | `src/codec/stream/` (目录, 拆分见 `src/codec/AGENTS.md`) |
| `CDAG-*` | Conversation DAG (域 B) | INV-1→CDAG-1, INV-2→CDAG-2, INV-3→CDAG-3, INV-4→CDAG-4, INV-5→CDAG-5 | `src/dag/mod.rs` 头部 + `docs/design/conversation-dag.md` |
| `DTO-*` | WebUI DTO 派生 (域 B) | (新增) | `src/web/AGENTS.md` + `src/record.rs` 头部 |
| `CFG-*` | 双层配置 (域 B) | (新增) | `src/config.rs` 头部 |
| `SEC-*` | 安全姿态 (跨域) | (新增) | `src/web/AGENTS.md` + `src/secrets.rs` + `src/provider.rs` + `src/server_host_guard.rs` (SEC-7) + `src/util.rs` (SEC-8) |
| `ROB-*` | 鲁棒性 (跨域) | (新增) | 根 `AGENTS.md` "鲁棒性原则" |
| `VIEW-*` | 视图正确性机制 (跨域) | (新增) | 根 `AGENTS.md` "视图正确性确保机制" |
| `UI-*` | WebUI 渲染 (域 C) | I1→UI-1, I2→UI-2, I3→UI-3, I4→UI-6 (selectedRound 子属性), I5→UI-6 | 根 `AGENTS.md` "前端不变量" |
| `USAGE-*` | 模型用量统计 (域 B, usage-stats) | (新增) | `docs/design/usage-stats.md` + `src/usage/` 头部 |
| `POOL-*` | 套餐池 failover (域 A, Pool Provider) | (新增) | `src/pool.rs` 头部 + `src/provider.rs` (PoolProvider / resolve_route Pool 跳) + `tests/pool_failover.rs` |

**编号稳定性**: 契约编号一经分配**永不变更** (即使内容演进). 删除契约时编号作废不重用.

### 0.3 Property 设计原则

每条契约的可测 property 必须遵循:

1. **描述外部可观察行为, 不依赖内部实现**. 例如"客户端收到的 wire 经 normalize 后 byte-exact"是好的; "writer 必须保留 IR 的 block index 字段"是过拟合的 (block index 是 IR 内部表示, 将来换实现就失效).
2. **优先 byte-exact (normalize 后) 而非语义等价**. 语义等价要求 case-by-case 定义"语义", 永远追不完; byte-exact 是可机械验证的最强 property. normalize = canonical JSON (BTreeMap key 排序 + 紧凑序列化 + 无空白), 消除对语义无影响的字节差异 (字段顺序 / 空白), 剩下的差异全部是真正的信息差异.
3. **测试生成器覆盖度也作为契约要求**. 历史 bug 多次出现"property 存在但生成器太窄导致漏测" (9712c52 只测单 tool_call, 229b2cb 没测 choices:[] 空数组). 因此 proptest 生成器必须覆盖已知边界场景, 列在对应 property 下.

### 0.4 冗余覆盖原则

**强契约 (端到端) 与其分解契约 (单步) 必须分别独立形式化、独立可测**.

理由: 测试原则是"不信任其他代码". 端到端契约 (如 FWD-1 透明中继 byte-exact) 测试通过, 不代表其分解步骤 (codec / redact / restore) 各自正确 — 可能是两个 bug 互相抵消. 端到端契约失败时, 也需要单步契约来定位根因 (是 codec 还是 redact 出错).

因此本文档中:
- FWD-1 (透明中继) 是端到端最强尺子.
- FWD-2 (纯 codec round-trip) + RED-6/7 (redact/restore 可逆性) 是 FWD-1 的分解, **独立形式化, 不因被覆盖而省略**.

### 0.5 漂移处理流程

**契约不能擅自修改, 必须经过人工授权.**

当发现代码与契约冲突时:
1. 编码人员 (含 AI agent) 修代码使其符合契约, commit msg 引用契约 ID.
2. 若认为契约本身过时, **必须先报告人工 (项目维护者) 审批**, 批准后才能改契约. 改契约的 commit msg 注明 "docs(contracts): <ID> 因为 <原因> 调整", 重大调整 (语义变化) 在 [§99 变更日志](#99-变更日志) 记录.

**免授权例外 (2026-09-23 用户授权, 政策依据 = 根 AGENTS.md "契约演进原则")**:
两类方向的契约修订**免人工授权** (同步更新契约正文与 property 断言即可, 重大调整
仍在 §99 记录) — ① **诚实化**: 诚实呈现数据的缺失/来源/粒度 (如 usage 缺失时写
null 而非伪造全零对象); ② **精确化**: 协议间互译把粗粒度映射改精确、消除信息损失
(如 stop_reason 按 output 推断). 契约锁定的断言可能只是之前实现阶段的折衷, 这两类
演进不受其阻碍. 其余方向 (行为弱化、语义收窄等) 仍走人工授权.

### 0.6 Property 落地状态标注 + traceability lint (#144)

每条 property 行尾**必须**带三种落地状态标注之一, 由 `just check-contracts` (进 `just check`
阻塞链) 机械守卫. **行格式契约**: property 行必须顶格 `- \`prop_...\`` (无缩进, 非表格),
缩进/表格形式不被 lint 扫描.

| 标注 | 语义 | lint 校验 |
|---|---|---|
| `✅` | 同名落地: property 名在 `src/+tests/` (*.rs/*.ts) 有**测试载体级**字面命中 | 名字 word-match 且命中行含 fn/test 定义形态 (纯注释提及不算, 防注释伪造 ✅) |
| `🔁→\`锚点\`` | 改名落地 / 弱形式覆盖: 锚点 (通常是实际测试名) 在 `src/+tests/+justfile+ci.yml` grep 命中 | 🔁→ 起的全部反引号锚点 (排除 \`路径\` 形态) `grep -F` 命中 |
| `⏳` | 待补: 真零测试 (语义核验后确认无近似落地) | 免 grep, 仅计数报告 |

标注格式细节: 🔁 的锚点 = `🔁→` 之后行内反引号对 (排除文件路径形态; 前置说明如
"🔁→人工审查项: `锚点`" 合法); 弱形式覆盖 (如仅部分维度 / 间接断言) 应在锚点后注明.
UI 段的 Playwright 测试用中文标题, 锚点即标题子串 (须避开反引号; 可含空格与括号 —
lint 按 while-read 整串字面校验, glob 字符 `* ? [` 亦安全).

**⏳ 项补齐优先级** (按风险排序, 排期依据 — 剩 10 条 = 9 条 property (lint 口径) + VIEW-2 表格注记, 2026-09-17; 原始 23 条见 2026-08-15 版变更日志):

1. **待裁决 / 架构受限 (3 条)** — 补齐前需先做实现路线裁决或架构改动:
   STR-3 `prop_non_2xx_sse_no_mock_to_client` (已知实现 gap, 见 STR-3 "理想 vs 现状" 注记,
   出路与 SEC-10 opt-in 哲学纠缠, 需维护者拍板); DTO-6
   `prop_cross_proto_delta_no_silent_misalignment` (理想方案需在 web 层重建 redactMap,
   有 secret 泄露顾虑, 见 web/AGENTS.md TODO); VIEW-2 流式 `resp_parsed`
   (Phase A 已物理删除源字节, 需 Phase B 或 consistency-check 双累积).
2. **UI e2e 类 (5 条: DTO-4 + UI-3×3 + UI-7)** — 后端半边多已覆盖, 缺 Playwright
   专项 e2e (fallback 占位 / prepend / replace / 乱序自愈 / 重复 append 幂等);
   构造确定性有成本, 随前端改动顺带补齐.
3. **可排期 (2 条: FWD-2 流式双 round-trip + RED-7 block 隔离)** — 生成器/基建齐全,
   FWD-2 流式条初期可能红灯 (writer 的 id/created 合成不确定性), 红灯本身即定位价值.

> 2026-09-17 集中补齐批次 (9 条 ⏳→✅): RED-1 charset/length + RED-5 确定性 +
> RED-6 extra + STR-3 timeout/disconnect (断连双防线实证: StreamingRestorer::flush
> restore + mpsc 保序) + CDAG-7 (is_orphan 后端落地, wire 传播留后续) + DTO-1 +
> SEC-4 set-cookie; 另补 CFG-4 跨表失败回滚 (原 "后续工作" 注记关闭) 与
> dto::UsageView 饱和边界 (DTO 未编号加固).

新增契约条目时必须同步给 property 标注 (lint 强制), 杜绝 "愿望清单" 再现
(#144: 走查发现 ~85/156 条零落地标注, 全量标注后剩 23 条真 ⏳).

---

## 1. FWD: 转发忠实性 (Forwarding Fidelity)

> 信任域 A. 适用于 client ↔ upstream 的完整字节流路径.

### FWD-1 透明中继 byte-exact (半段式, normalize 后)

**陈述**: secret-guard 是客户端与上游之间的字节级透明中继. **两个半段各自满足 byte-exact**:

- **请求半段** (client → upstream): 客户端发送的请求 wire 经 secret-guard redact 后发往上游, 要求
  `normalize(发往上游的 wire) == normalize(客户端请求 wire).replace(real, mock)`; 若路由链上命中了携带
  `upstream_model` 的路由 (#183 语义被 `Route.upstream_model` 吸收), 额外允许 model 字段重写:
  `normalize(发往上游的 wire) == normalize(客户端请求 wire).replace(real, mock).replace(model, rewrite)`
  (rewrite = 链上最后一次命中的路由 `upstream_model`, pipeline 语义).
- **响应半段** (upstream → client): secret-guard 收到上游响应 wire 后经 restore 返回客户端, 要求
  `normalize(返回客户端的 wire) == normalize(上游响应 wire).replace(mock, real)`.

等价表述: **secret-guard 对 wire 的合法修改有且仅有三种: real↔mock 替换; model 字段重写 (仅当路由链上命中了携带 `upstream_model` 的路由); 以及 Anthropic egress 的顶层自动缓存标记注入 (仅当 `[redact] inject_cache_control = true` 显式 opt-in, 且请求内不存在任何 cache_control — 见下方 M3 注记)**, 除此之外的任何字节差异 (字段丢失 / 顺序错乱 / 重序列化改变 / 任意字段值变化) 都是 bug.

> **路由 model 重写代价明示** (2026-08-24 修订 / 2026-08-25 措辞随多规则化同步, §99 登记): 重写生效时,
> 同协议无-secret 请求从字节直传 (passthrough) 降级为 IR 改写路径 — 前者对无 redact 请求是 byte-exact
> 的, 后者经 reader→IR→writer 重序列化, 仅保证 normalize 后等价 (与 "同协议 + Redact" 的既有降级同型).
> 这是用户配置 route.upstream_model 时**主动选择的降级**, 非 bug. 经济性代价: 重写值与客户端请求的
> model 不同时, 上游前缀缓存从该请求起失效. 解析语义 (链上 pipeline / 无 codec 协议降级) 见
> FWD-5 `prop_model_rewrite_*` 系列.

> **router /models 本地终结** (2026-08-31 登记修订, **待人工授权** — §99): router provider 的模型列表
> GET 请求 (端点清单见 FWD-7) 在 dispatch 内本地终结, 对这类请求 FWD-1 **不适用** — 响应为本地合成
> (别名 + 可含缓存的上游清单, 非实时中继, 最旧可 stale 300s), 不存在 "发往上游的 wire" 半段.
> Direct provider 的 /models 仍受 FWD-1 约束 (透传, 见 FWD-7 的 D6 回归守卫). #196.

> **Anthropic messages[].role=system 位置保真** (2026-09-23 修正, **取代同日的"正规化"决策** —
> §99, issue #269): `messages[]` 数组内的 `role=system` 条目 (中途 system 消息, claude code
> 实测发送 billing header 与消息级 effort 切换) 是 **Anthropic 官方已正式支持的合法 wire 形态**
> (无需 beta header; 官方文档明确此形态正是"追加指令不失效缓存前缀"的推荐方式, 支持范围见
> 官方模型清单 — Claude Sonnet 5 等部分模型不支持, 由客户端按目标上游自行选择形态).
> IR 路径 (redact / model 重写强制) 对该形态**按原位保留与写回**: reader 不再提升合并到顶层
> system, writer 按原位输出 role=system — FWD-1 字面等式对该形态成立 (无位置搬移).
>
> **修正记录**: 同日早前的"正规化"决策 (reader 提升合并 + 契约例外注记) 定性为错误 —
> ① 提升改变指令生效位置 (从中途变为开头), ② 顶层 system 增长使缓存前缀从该点整体失效
> (官方文档正是为此推荐留在 messages[]), ③ 消息级字段 (如 `output_config.effort`) 在提升
> 中丢失. 该例外注记随之删除, FWD-1 等式无例外. 实现与测试锚点:
> `src/codec/anthropic.rs` read_request 位置保留 + `read_request_keeps_system_role_message_in_place`
> / `system_role_message_round_trips_in_place` / 端到端 `anthropic_messages_system_role_position_fidelity`
> (tests/integration.rs); FWD-2 生成器已解除 role=system 排除, 位置保真由 property 机械锁定.
> 兼容性边界: 形态是客户端自选的 — 目标上游/模型不支持时 400 属客户端形态选择问题,
> 网关不代为改写 (字节透明原则); passthrough 路径行为不变 (字节透传).
> 跨协议路径 (Anthropic ingress → 非 Anthropic egress) system 消息按 egress 协议惯例
> 原位落位 (OpenAI messages[].system / Responses message item, FWD-3 语义保留管辖).

> **Anthropic 缓存友好性保真** (2026-09-23 登记, issue #269, FWD-2 wire-fidelity 扩展 +
> M3 注入): IR 路径不得损失请求的缓存相关信息 —
> ① **block 级/工具级 `cache_control`** (claude code 每请求 2-4 个缓存断点): 经 wire-fidelity
> extra (message/tool/block 级) 原样保真, FWD-2 生成器锁定; ② **显式 `is_error: false`**:
> Option<bool> 建模, 显式形态不省略; ③ **顶层 `system` 字段形态** (string/array): `system_form`
> 元数据保真, 单 block array 不折叠为 string; ④ **消息级未建模字段** (如消息级
> `output_config.effort`): message-level extra 保真. ⑤ 顶层 `extra` (含客户端自发的顶层
> automatic `cache_control`) 既有透传不变. 以上均系"不丢客户端已有的信息", 非 FWD-1 合法
> 修改类别 (等式约束成立).
>
> **M3 注入** (合法修改第三类, 显式 opt-in): `[redact] inject_cache_control = true` (默认
> false) 时, Anthropic egress (same-proto IR 路径 + cross-proto) 对**不存在任何 cache_control**
> 的请求注入顶层 `cache_control: {"type":"ephemeral"}` (automatic caching 模式). 守卫: body
> 内已有任何 cache_control 时不注入 (Anthropic 显式断点上限 4 个, 满槽时顶层标记 400).
> 目的: 不发缓存标记的客户端经 IR 路径后仍能吃到前缀缓存 (Anthropic 缓存为显式 opt-in,
> 无标记 = 不写不读; IR 路径若无此注入, 长 agent 会话 input 成本约放大一个数量级).
> 实现与测试锚点: `src/proxy/helpers.rs` inject_auto_cache_control +
> `anthropic_ir_path_injects_top_level_cache_control_when_enabled` /
> `anthropic_ir_path_no_cache_injection_by_default` (tests/integration.rs).
> 已知边界: 对顶层 cache_control 返 400 的旧版 Bedrock 集成 (Opus 4.6 及更早) 需保持默认关闭.

`normalize` = canonical JSON (BTreeMap key 排序 + 紧凑序列化 + 无空白). 消除对语义无影响的字节差异, 剩下的差异全部是真正的信息差异.

**适用范围**: 同协议路径. 非流式 wire JSON + 流式 SSE wire.

**不适用**: 跨协议路径 (ingress wire 与 egress wire 是不同协议格式, 由 FWD-3 单独约束).

**Properties**:
- `prop_request_half_byte_exact` (非流式, 请求侧): 对任意合法请求 wire 含 real secret, `normalize(secret-guard 发往上游的 wire) == normalize(原始 wire).replace(real, mock)` (无路由 model 重写时). 🔁→`openai_request_redact_preserves_wire_except_secret` + `anthropic_request_redact_preserves_wire_except_secret` (半段式含 redact, `src/codec/fwd_property.rs`; 端到端 `redact_strips_secret_from_upstream_request`)
- `prop_request_half_byte_exact_with_model_rewrite` (非流式, 请求侧; 2026-08-25 前名 `prop_request_half_byte_exact_with_model_override`): 路由链命中携带 `upstream_model` 的路由时, `normalize(secret-guard 发往上游的 wire) == normalize(原始 wire).replace(real, mock).replace(model, rewrite)` — 无-secret 场景亦成立 (重写强制 IR 路径). 🔁→`model_rewrite_reaches_upstream` + `model_rewrite_no_secret_forces_ir_path` + `model_rewrite_with_secret_joint` (联合公式端到端) (`tests/integration.rs`)
- `prop_response_half_byte_exact` (非流式, 响应侧): 对任意合法响应 wire 含 mock, `normalize(secret-guard 返回客户端的 wire) == normalize(上游 wire).replace(mock, real)`. 🔁→`prop_response_round_trip_identity` / `prop_response_tool_use_input_restored` (redact.rs 响应侧) + 端到端 `restore_inserts_secret_back_for_client` (非流式) — 流式半段见 FWD-1 `prop_streaming_response_half_byte_exact` 弱化形式注记
- `prop_streaming_response_half_byte_exact` (流式, 响应侧): 流式响应的 restore, 经任意 chunk 切分, 同上. 🔁→`prop_streaming_response_half_byte_exact_openai` + `prop_streaming_response_half_byte_exact_anthropic` + `prop_streaming_response_half_byte_exact_responses` + `prop_streaming_response_byte_by_byte_responses` (`src/codec/fwd_streaming_property.rs`; 语义等价弱化形式, 见下方 "理想 vs 现状" 注记; Responses 侧 done 族全量帧由 writer 从 restore 后 IR 重合成, no-mock-leak 扫描覆盖)

> **理想 vs 现状**: `prop_streaming_response_half_byte_exact` 的字面形式 (byte-exact) 在
> `StreamTranslate::new_same_proto_restore` 路径下**不成立** — 该路径显式放弃 byte-exact 走
> IR re-serialize (见 `src/codec/stream/translate.rs` 头部注释 "失去 byte-exact, 但语义等价"). 已知结构
> 差异 (除 mock→real 替换外): ① id/created 重新生成 (writer 合成); ② chunk 重组 (StreamingRestorer
> sliding window 在 mock 边界拆/并 chunk); ③ usage input_tokens backfill (terminal delta 填回
> MessageStart 锁定值); ④ 元数据字段去重 (OpenAI writer 仅 MessageStart chunk 输出 id/created/model).
> 当前 property (`fwd_streaming_property.rs`) 守卫**语义等价弱化形式**: no mock leak + content
> fidelity + tool input fidelity + usage output fidelity. 完整 byte-exact 需重新设计
> same_proto_restore 为字节级扫描替换 (避免 IR re-serialize), 作为独立架构改动.
- `prop_proptest_generator_covers_edge_cases`: wire 生成器必须覆盖: 🔁→`arb_openai_request_with_embedded_secret` 等生成器组 (`src/codec/fwd_property.rs` L555 起覆盖清单注释 + `fwd_streaming_property.rs` 的 byte_by_byte 用例)
  - 多个并行 tool_call (≥2)        [9712c52: writer 硬编码 index=0 致 N→1 合并]
  - 空 choices 数组                 [229b2cb: 3 处独立 bug 联合丢失 usage]
  - usage chunk (terminal delta)    [229b2cb]
  - 跨字段重复 secret
  - 流式 chunk 任意切分 (1-byte 切分)

### FWD-2 同协议 codec round-trip byte-exact (FWD-1 的分解)

**陈述**: 同协议下, codec 的 reader/writer 互为镜像. 任意合法 IrRequest 经 `Writer → 字节 → Reader → IrRequest' → Writer → 字节'` 的两次 round-trip 后, 两次的字节输出经 normalize 后 byte-exact:
`normalize(Writer(ir)) == normalize(Writer(Reader(Writer(ir))))`.

**等价表述**: Writer 对同一 IrRequest 的输出是字节级确定的; Reader → Writer 不丢信息.

**与 FWD-1 的关系**: FWD-1 (端到端) 失败时, 跑 FWD-2 可定位是 codec 还是 redact/restore 的问题. FWD-2 失败 → codec bug; FWD-2 过但 FWD-1 失败 → redact/restore bug.

**适用范围**: 非流式 wire JSON (IrRequest / IrResponse) + 流式 SSE wire (IrStreamEvent 序列).

**Properties**:
- `prop_codec_round_trip_byte_exact_after_normalize` (非流式): `normalize(Writer(Reader(Writer(ir)))) == normalize(Writer(ir))`. 🔁→`openai_request_preserves_wire_semantics` + `anthropic_request_preserves_wire_semantics` (`src/codec/fwd_property.rs`; 响应侧 `openai_response_preserves_wire_semantics` 因 L8 `#[ignore]`)
- `prop_codec_stream_round_trip_byte_exact_after_normalize` (流式): 流式 reader → writer → 字节 → reader → writer → 字节, 两次最终字节 normalize 后 byte-exact. ⏳
- 生成器覆盖要求见 FWD-1 的 `prop_proptest_generator_covers_edge_cases` (两契约共享同一组生成器要求).

### FWD-3 跨协议翻译: 建模范围内语义保留 + 范围外显式丢弃

**陈述**: 跨协议路径 (ingress != egress) 通过 IR 中介翻译 (ingress Reader → IR → egress Writer). 翻译契约分两层:

1. **建模范围内语义保留**: 在 chat completion 建模范围 (messages / tools / tool_use / tool_result / usage 总数 / stop_reason) 内, 翻译保留语义.
2. **范围外显式丢弃**: 建模范围外的字段 (reasoning / thinking / citations / logprobs / prompt caching / usage 细分如 cache_hit_input_tokens 等) **必须显式丢弃**, 不允许源协议独有字段以 `extra` 形式泄漏到 egress.

**为什么不要求 byte-exact**: 跨协议时 ingress wire 与 egress wire 是不同协议格式 (OpenAI Chat Completions JSON vs Anthropic Messages JSON), 字节层面本就不同. 契约只能落在"建模范围内语义保留".

**语义损失的显式清单** (人工审查项, 维护在 `src/codec/AGENTS.md`):
- reasoning / thinking 字段不建模, 丢弃.
- citations / logprobs 不建模, 丢弃.
- prompt caching 字段不建模, 丢弃.
- usage 只保留 input/output 总数 + cache_read/cache_creation 4 个字段, 细分字段丢弃.
- Anthropic `disable_parallel_tool_use` 通过 tool_choice 载体映射, 语义脆弱.

**Properties**:
- `prop_cross_proto_modeled_fields_preserved`: 建模范围内的字段 (messages/tools/tool_use/tool_result/usage 总数/stop_reason) 跨协议 round-trip 后保留. 🔁→`prop_cross_proto_modeled_fields_preserved_openai_to_anthropic` + `prop_cross_proto_modeled_fields_preserved_anthropic_to_openai` (`src/codec/fwd_cross_proto_property.rs`)
- `prop_cross_proto_stream_content_fidelity` (2026-09-15, 流式半段; 2026-09-23 起覆盖 Responses 任一侧): 跨协议流式翻译 (StreamTranslate 跨协议模式, 任意 chunk 切分含 1-byte) 内容保真 — text / tool input 拼接相等, tool_use id/name 保真, usage output_tokens 透传; wire 帧顺序合法性由确定性单测守卫 (双方向: Anthropic ingress 的 message_delta-before-message_stop + 跳过 block 配对, OpenAI ingress 的 content-before-finish_reason + restore 尾部及时冲刷). Responses 组合 (r→o / o→r / r→a / a→r + r→o 1-byte) 覆盖 Responses reader 状态机跨 chunk 稳定性 + Responses writer 有状态合成 (item+part 两帧 / done 族全量帧 / deferred stop). 🔁→`prop_cross_proto_stream_openai_to_anthropic` + `prop_cross_proto_stream_byte_by_byte_openai_to_anthropic` + `prop_cross_proto_stream_byte_by_byte_anthropic_to_openai` + `prop_cross_proto_stream_responses_to_openai` + `prop_cross_proto_stream_openai_to_responses` + `prop_cross_proto_stream_responses_to_anthropic` + `prop_cross_proto_stream_anthropic_to_responses` + `prop_cross_proto_stream_byte_by_byte_responses_to_openai` + `cross_proto_reasoning_block_yields_no_unpaired_block_stop` + `cross_proto_defers_message_stop_until_post_stop_usage` + `cross_proto_flushes_pending_stop_at_finish_without_usage_chunk` + `cross_proto_openai_ingress_flushes_skipped_block_tail_before_finish_reason`
- `prop_cross_proto_unmodeled_fields_explicitly_dropped`: 范围外字段 (如 reasoning_content) 不出现在 egress wire. ✅
- `prop_cross_proto_extra_cleared`: 跨协议路径下 ingress IR 的 extra 字段必须清空, 不允许源协议独有字段泄漏到 egress. ✅
- `prop_documented_semantic_loss_list`: 所有已知的语义损失点必须在 `src/codec/AGENTS.md` 显式列出 (人工审查项). ✅

### FWD-4 HTTP 语义透传 + 客户端响应与 record 累积分离

**陈述**: 除 hop-by-hop header 外, HTTP 语义 (method / status / headers / stream 模式) 透传. **客户端响应路径与 record 累积路径是两条独立路径**: 客户端响应永远流式透传无大小上限, record 累积受 `MAX_RESP_BODY_RECORD` (32 MiB) 上限保护.

**响应头超时分档 (#175; 默认值 2026-09-23 用户授权再放宽)**: send().await 的"响应头到达"超时按请求的 stream 语义分两档 — 显式 `stream=true` → TTFT 档 (`upstream_response_header_timeout_secs`); 其余 (含缺字段 / 非布尔 / 非 JSON, OpenAI/Anthropic/Responses 均默认非流式) → 整响应档 (`upstream_nonstream_response_header_timeout_secs`). 语义 SSOT = "显式顶层布尔 true 才算流式", 两处实现须保持等价: `proxy::helpers::requests_stream` (passthrough 路径, 字节扫描) 与 codec reader 的 stream 解析 (IR 路径, `ir.stream`). 已知盲区: Gemini `alt=sse` / Ollama 默认流式经 body 检测不可见, 落非流式档 (保守方向, 可接受).

**超时职责分工 (2026-09-23 用户裁决, 授权记录见对应 PR)**: 应用层超时 (响应头两档 + `upstream_stream_idle_timeout_secs`) 的角色是**防挂兜底** (默认统一 3600s, 保证 record 最终有终态), 不再兼任"正常时长上界" — 深度思考 / 大上下文 prefill / relay 伪流式 / 思考期静默均为合法慢, 误杀代价 = 3 倍账单 (上游已付 + 客户端零产出 + 重试重付). **连接活性的精确检测归 TCP keepalive** (`build_upstream_client` 显式设置 idle 15s + interval 15s + retries 3; Linux TCP_USER_TIMEOUT 30s 来自锁定的 reqwest 0.12.28 默认值, Linux 亚分钟级 ~45s 判死, macOS 的 reqwest 无此选项): 网络分区 / NAT 黑洞下探测包无响应 → 内核判死 → 网络错误 → 502, 活着的慢连接永不误伤; keepalive 探测不到的 "进程活着但死锁" 残余场景由 3600s 兜底. 建连超时 (15s) 量纲自信, 保持设紧. 历史: 流式档 60s / 非流式档 300s (#175) / idle 120s 均有误杀合法慢请求的事故记录.

**Properties**:
- `prop_status_code_preserved`: 上游响应 status code 透传给客户端 (任意 status, 含错误码). 🔁→`upstream_non_2xx_is_forwarded` (`tests/integration.rs`)
- `prop_headers_preserved_except_hop_by_hop`: 上游响应 header 透传, 除 RFC 7230 §6.1 定义的 hop-by-hop header 外不丢失. 🔁→`sanitize_strips_hop_by_hop_and_host` + `strips_custom_connection_listed_header`
- `prop_stream_mode_preserved`: 上游若返回 SSE/chunked, 客户端也以流式收到 (非 buffered). 🔁→`forwards_streaming_sse` (弱形式: 断言 chunk 语义透传, 未断言非 buffered 到达时序)
- `prop_client_response_not_capped_even_when_record_truncated`: 即使 record 累积超过 MAX_RESP_BODY_RECORD 被截断 (写入 TRUNCATED_BANNER), 客户端响应仍收到完整上游字节. 此契约禁止有人把 MAX_RESP_BODY_RECORD 改成"客户端响应上限" (会静默截断用户响应). 🔁→`fan_out_streaming_truncates_record_but_not_client_response` (`src/proxy/fan_out.rs`)
- `prop_header_timeout_matches_stream_semantics`: 响应头超时按 stream 语义选档 (显式 `stream=true` → TTFT 档; 缺字段 / 非布尔 / 非 JSON / 嵌套 stream → 整响应档), 且 504 错误消息内嵌实际生效的超时值. ✅ (选档本体同名单测; 畸形形态半句由同文件 `requests_stream_malformed_bodies_fall_back_to_nonstream` + `prop_requests_stream_strict_bool_gate` 守卫; "504 消息内嵌实际超时值" 半句由 🔁→`stream_request_still_killed_by_stream_timeout_with_observable_message` 覆盖)

### FWD-5 路由分发契约

**陈述**: URL = `/{proto_short}/{provider_id}/*path`. 未知 protocol / 未知 provider / 禁用 provider / 不支持的协议组合 必须返回明确错误码. provider 可能是**路由的** (Router 构造, `routes` 路由列表, #179 多规则化): dispatch 在**请求 body 收集后**提取顶层 `model` 字段, router 按**请求 model** 匹配路由并链式解析到链尾实体 provider — 解析是 per-request 的, 切换路由只影响新请求. ingress 协议由 URL 决定; egress 协议由链尾 Direct 实体的**选定端点**决定 (multi-endpoint, 2026-09-20 增补): Direct 条目可含多协议端点 (`endpoints` 有序数组, 每协议至多一条 — validate 强制; 数组序 = fallback 序), dispatch 经 `select_endpoint(ingress)` 选端点 (**D2**): ingress 精确匹配 → (该端点, exact) 同协议路径; 无匹配 → (首端点, fallback) 跨协议翻译 (单端点配置下行为与演进前逐字节一致); 空 endpoints (绕过 validate 的非法配置) → 503. Router 构造无 protocol 字段 (其 egress = 链尾实体的选定端点).

**路由选择** (`RouterProvider::select_route`): 启用 (`priority` 非 None) 且 model_pattern 匹配 in-flight model 的路由中 `priority` **最大**者; 同值并列按**列表出现顺序**取先者 (确定性 tie-break). model_pattern 是 model 名通配符: 仅 `*` 是元字符 (匹配任意串, 含空串), 其余字符字面匹配 (大小写敏感). **model 重写 pipeline 语义** (`resolve_route`): 命中路由的 `upstream_model` 为 Some 时改写**立即生效** — in-flight model 被改写, 后续跳 router 按改写后的 model 匹配路由; 多跳重写后者覆盖前者; `ResolvedRoute.model_rewrite` = 最后一次命中的 route.upstream_model (全链未配置 = 透传客户端 model).

**路由错误语义** (全部 503, message 只含 provider id / model 名 + reason 枚举, SEC-2 同型): 无匹配路由 (NoMatch — 启用路由中无 model_pattern 匹配请求 model) / 链上目标缺失 (Missing, 含被 decision-disabled 排除) / 链上目标 entry-level disabled (Disabled) / 成环 (Cycle, `resolve_route` visited-set 运行时兜底, 有限步终止). 悬空 `target` 写入放行 (创建顺序无关), 运行时 503 兜底; upsert 侧环检查 (`would_cycle`) 的边集 = 所有**启用**路由的 `target` (禁用路由不构成边), 任一分支成环 → 400.

**Properties**:
- `prop_unknown_protocol_returns_404`: 未知 proto_short → 404 not_found. 🔁→`unknown_protocol_returns_404` (`tests/integration.rs`)
- `prop_unknown_provider_returns_404`: 未知 provider_id → 404 not_found. 🔁→`unknown_provider_returns_404` (`tests/integration.rs`)
- `prop_disabled_provider_returns_503`: provider.enabled=false → 503 unavailable. 🔁→`disabled_provider_returns_503` (`tests/integration.rs`)
- `prop_cross_proto_streaming_responses_translates` (2026-09-23 翻转; 前身 `prop_cross_proto_streaming_responses_returns_501` 随 Responses 流式 writer 落地 + proxy 501 门解除作废): 跨协议 + stream=true 含 **Responses 任一侧** → 200 流式翻译 (StreamTranslate 跨协议模式, 不再 501) — Responses ingress 侧客户端收到合法 Responses SSE (response.created 开头 / response.completed 结尾, 无 [DONE]), OpenAI/Anthropic ingress 侧收到各自原生终止符; 文本与 usage 总数保真. 🔁→`cross_protocol_streaming_translates_responses_ingress_from_openai_upstream` + `cross_protocol_streaming_translates_openai_ingress_from_responses_upstream` + `cross_protocol_streaming_translates_anthropic_ingress_from_responses_upstream` (`tests/integration.rs`)
- `prop_unsupported_codec_returns_501`: Gemini/Ollama 跨协议 → 501 (codec 未覆盖). 🔁→`cross_protocol_unknown_pair_returns_501` (`tests/integration.rs`)
- `prop_internal_url_404_no_forward`: `/api/*` 未匹配子路径 → 404, 绝不进入 forward (防止内部 URL 泄漏到上游; 同 SEC-6 的 property 名). 🔁→`web_namespace_not_forwarded_to_upstream` + `unmatched_path_returns_404` (`tests/integration.rs`)
- `prop_route_resolution_per_request` (#179): 路由 provider 的路由解析是 per-request 的 (body 收集后携带本请求 model) — 修改路由 / 切换指向只影响新请求, in-flight 请求按已解析目标完成; 每轮 record 的 upstream_id 如实记录该轮实际归属, 历史轮次不随切换改写. 🔁→`router_provider_switches_routes_mid_session` (`tests/integration.rs`)
- `prop_router_request_model_extraction` (#179): 路由匹配的输入 model 取自请求 body 的 **JSON 顶层** string `model` 字段; 非 JSON / 顶层非 object / 无字段 / 非 string / 空 body → `""` (此时仅 `*` 类 model_pattern 可命中); 嵌套结构 (如 `messages` 内) 的 model 不误取. 🔁→`router_routes_route_by_model` (`tests/integration.rs`) + `request_model_extracts_top_level_string` / `request_model_nested_model_not_picked_up` / `request_model_malformed_bodies_fall_back_to_empty` (`src/proxy/helpers.rs`)
- `prop_router_pattern_wildcard_semantics` (#179): model_pattern 通配语义: 仅 `*` 是元字符 (匹配任意串, 含空串), 其余字符字面匹配 (大小写敏感); `"*"` 匹配一切; 连续 `**` 折叠为单个 `*`; 无 `*` 的 model_pattern 退化为全等比较. 🔁→`prop_wildcard_split_pattern_matches_concat` + `prop_wildcard_star_matches_anything` (`src/provider.rs` proptest) + `wildcard_match_star_matches_all_including_empty` / `wildcard_match_consecutive_stars_collapse` (确定性边界用例)
- `prop_router_rule_priority_ordering` (#179; ID 保留 rules→routes 重命名前的历史命名): 路由选择 = 启用路由中 model_pattern 匹配者的 priority 最大者; 同值并列按列表出现顺序取先者 (确定性 tie-break). 🔁→`router_routes_priority_decides_winner` (`tests/integration.rs`) + `select_route_highest_priority_wins` / `select_route_tie_breaks_by_list_order` (`src/provider.rs`)
- `prop_router_disabled_rule_skipped` (#179; ID 保留 rules→routes 重命名前的历史命名): `priority = None` 的路由**禁用** — 不参与匹配 (让位给列表中更后的通配路由), 也不构成环检查边集. 🔁→`router_routes_disabled_route_skipped` (`tests/integration.rs`) + `select_route_skips_disabled_routes` (`src/provider.rs`)
- `prop_router_no_match_returns_503` (#179): router 的启用路由中无 model_pattern 匹配请求 model → 503, message 形如 `router provider '{id}' has no route matching model '{model}'` (只含 id + model 名, SEC-2 同型). 🔁→`router_routes_no_match_returns_503` (`tests/integration.rs`) + `resolve_route_no_matching_route` (`src/provider.rs`)
- `prop_route_broken_returns_503` (#179): 链上目标缺失 / entry-level disabled / 成环 → 503, message 只含 provider id 与 reason 枚举 (SEC-2 同型, 无 secret). 🔁→`router_provider_dangling_returns_503` + `router_provider_disabled_target_returns_503` (`tests/integration.rs`) + `resolve_route_missing_target` / `resolve_route_disabled_target` / `resolve_route_detects_cycles` (`src/provider.rs`)
- `prop_route_cycle_termination` (#179): 任意 route 图 (含环 / 悬空 / 自环), `resolve_route` 有限步返回 (Ok ⇒ 链尾必为 Direct 构造 — #187 起由 `ResolvedRoute.provider: DirectProvider` 类型保证, proptest 断言随之弱化为纯终止性). 🔁→`prop_resolve_route_terminates_on_random_graphs` (`src/provider.rs`, proptest; 生成器覆盖环与悬空)
- `prop_route_cycle_rejected_at_upsert` (#179): upsert 形成环 (含自环) → 400 validation; 环检查边集 = **启用**路由的 `target` (禁用路由不构成边; 汇聚型 diamond 分支不误报); 悬空目标放行 (创建顺序无关, 运行时 503 兜底). 🔁→`router_provider_cycle_upsert_rejected` (`tests/integration.rs`) + `would_cycle_rejects_indirect_cycle` / `would_cycle_updates_entry_in_place` / `would_cycle_checks_every_enabled_route_branch` / `would_cycle_diamond_convergence_is_not_a_cycle` / `validate_router_semantics` (`src/provider.rs`)
- `prop_upstream_id_observable` (#179): 每轮 record 携带 upstream_id = 路由链解析后的链尾实体 provider id (非路由请求 = URL provider id), 经 NodeView / TimelineRound / ForwardRecord 暴露给 WebUI. 🔁→`router_provider_switches_routes_mid_session` (`tests/integration.rs`, latest_upstream_id 断言)
- `prop_model_rewrite_pipeline_feeds_next_hop` (#183; 2026-08-25 前身 `prop_model_override_first_hop_wins` 已随 first-wins 语义作废): 命中路由的 `upstream_model` 重写对**下一跳路由**可见 — in-flight model 被改写后, 后续 router 按改写后的 model 匹配路由 (pipeline 语义, 非 first-wins). 🔁→`resolve_route_model_rewrite_pipeline_feeds_next_hop` (`src/provider.rs`)
- `prop_model_rewrite_later_overrides_earlier` (#183): 多跳命中携带 `upstream_model` 的路由时, 后者重写值覆盖前者 — `ResolvedRoute.model_rewrite` = 最后一次命中; 全链未配置 = 透传客户端 model. 🔁→`resolve_route_later_rewrite_overrides_earlier` (`src/provider.rs`)
- `prop_model_rewrite_injects_into_egress_ir` (#183; 2026-08-25 前名 `prop_model_override_injects_into_egress_ir`): 路由 upstream_model 重写生效且 codec 可用时, egress IR 的 model 字段被无条件改写为重写值 (客户端 body 缺 model 字段亦注入); 无-secret 请求因重写强制走 IR 路径 (不再字节直传). 🔁→`model_rewrite_reaches_upstream` + `model_rewrite_no_secret_forces_ir_path` + `model_rewrite_switch_via_put` (`tests/integration.rs`)
- `prop_model_rewrite_no_codec_passthrough` (#183; 2026-08-25 前名 `prop_model_override_no_codec_passthrough`): 无 codec 协议 (Gemini/Ollama) + 路由 upstream_model 重写 → 不改写 body, 字节透传 + WARN (与 "codec 缺失 + secrets" 降级同型). 🔁→`model_rewrite_gemini_passthrough_unrewritten` (`tests/integration.rs`)
- `prop_endpoint_selection_membership_and_exactness` (multi-endpoint D2, 2026-09-20): 对任意 endpoints (协议唯一, 可空 — 空 = 绕过 validate 的非法配置) 与任意 ingress: `select_endpoint(ingress)` 要么 None (仅当空), 要么 `(e, exact)` 且 e ∈ endpoints ∧ `exact ⟺ ∃ x ∈ endpoints. x.protocol == ingress` (双向蕴含) ∧ exact 时 e 为列表序首个匹配者 ∧ ¬exact 时 e == 首端点 (fallback 序, **声明序**而非协议位阶). dispatch 层的外部可观察形态 (同协议 byte-exact 透传 / fallback 翻译到首端点 / 空 503; router 链尾与 pool 成员同型) 由 e2e 锚定. 🔁→`prop_select_endpoint_membership_exactness_fallback` (`src/provider.rs` proptest; 生成器覆盖 多端点/单端点/无匹配 ingress/空数组 + 子集随机排列) + `multi_endpoint_dual_ingress_same_proto_byte_exact` + `multi_endpoint_fallback_cross_proto_to_first_endpoint` + `multi_endpoint_fallback_uses_declaration_order_not_protocol_rank` + `router_tail_multi_endpoint_selects_endpoint_by_ingress` + `pool_member_multi_endpoint_selects_endpoint_by_ingress` (`tests/integration.rs`)

### FWD-6 Provider 鉴权注入

**陈述**: secret-guard 用 provider 配置的 api_key 覆盖客户端可能误传的 auth header, 注入对应协议的 auth header. 发往上游的请求**只含 ingress 协议对应的 auth header**, 其他协议的 auth header (`Authorization` / `x-api-key` / `x-goog-api-key` 三者中非 ingress 的两个) 必须剥离.

**Properties**:
- `prop_only_ingress_protocol_auth_header_sent`: 发往上游的请求只含 ingress 协议对应的 auth header, 非 ingress 协议的 auth header 被剥离 (避免客户端误传对手协议 header 干扰上游). 🔁→`apply_provider_auth_strips_competing_headers` (`src/proxy/auth.rs`)
- `prop_correct_auth_injected_per_protocol`: OpenAI/Ollama → `Authorization: Bearer`; Anthropic → `x-api-key`; Gemini → `x-goog-api-key`. 🔁→`provider_api_key_overrides_client_auth` (OpenAI Bearer) + `anthropic_provider_uses_x_api_key`; Gemini `x-goog-api-key` 注入无专项
- `prop_api_key_two_sources_resolved`: api_key 来自 `api_key` (直接值) 或 `api_key_file` (运行时读文件) 任一来源, 解析为同一 effective value. 🔁→`provider_api_key_file_reads_secret_from_path` + `provider_api_key_file_missing_falls_through_to_no_auth` + `put_static_fork_null_api_key_inherits_api_key_file`

### FWD-7 Router provider 模型列表本地合成 (GET /models, #196)

**陈述**: router provider (`ProviderKind::Router`) 的模型列表类 GET 请求 (按 ingress 协议: o/r/a 的 `/models` 与 `/v1/models`; g 另含 `/v1beta/models`; l 的 `/api/tags`; query 参数忽略, rest 前导 `/` 形态容错) 在 dispatch 内**本地终结**, 不进转发链 (无 body 收集 / 无路由解析 / 无 DAG 记录 — D5)。响应 = **别名清单 ∪ 过滤后的上游模型清单**:

- **别名段** (N2): 启用路由中不含 `*` 的 model_pattern (exact pattern), 按路由表序去重; 经 `resolve_route` 校验**可解析**才广告 (D2: advertised ⇒ resolvable)。
- **合并段** (N1): `advertise(M) ⟺ resolve_route(router, M) = (T, E) ∧ E ∈ cached(T)` — E = 链上生效的 `model_rewrite` ∨ M; **广告名是 M** (客户端可寻址名), 不是 E。列表序 = 可达 Direct 的 walk 序 (DFS 按路由表序首达; 悬空 / disabled target 分支终止不贡献) × 各 provider 清单的**上游响应数组序**, 跨 provider 及与别名段去重。
- **N6 顶层 wildcard gate**: 被查询 router 的**启用**路由中存在含 `*` 的 model_pattern 才 fetch+merge; 否则只返回别名 (**零上游请求**)。gate 只看顶层 (不看链上更深处) — exact-only 顶层 ⇒ 准入名 ⊆ 别名集 ⇒ merge 贡献 ≡ ∅。顺带修复 exact-only router 对 GET /models 的历史 503 (GET 无 body → `request_model=""` → NoMatch)。
- **上游清单缓存** (N3/N4): per-(Direct-provider, 选定端点 egress 协议) 条目 (`{models, fetched_at, common_uri_hit}`; multi-endpoint 增补 2026-09-20: 缓存键 = (provider id, `select_endpoint(ingress)` 选定端点的协议) — 不同 ingress 入口对同一 Direct 各自缓存各自清单, 广告的模型必须真能被该入口的服务端点提供; 单端点配置下 egress 恒一, 键退化为裸 id), union 查询时现算 (不做 flat union 缓存); TTL 300s 常量 (不进配置); serve-stale-on-error (刷新失败保留旧数据); single-flight (持缓存锁串行 refresh, 等锁者读新鲜缓存); 懒加载 (首个查询触发 fetch); **失败退避** (fetch 失败后 30s 常量窗口内的过期/从未成功条目不再重试 — 窗口内查询立即 serve stale 或无贡献, 不阻塞不占锁重试, 防 dead target 逐查询阻塞 × 全局锁串行的可用性放大)。fetch 端点选择与 dispatch 转发路径**同一语义** (`select_endpoint(ingress)`: 精确匹配 ingress 协议的端点, 无匹配 → 首端点, D2), 按选定端点的 egress 协议请求 (单端点配置下 = 目标 provider 自身 protocol): o/a/r → `{base_url}{common_uri}/models` `{data:[{id}]}` — common_uri 候选序 = `DirectProvider.common_uri` (detect 固化, fast path) > 缓存 `common_uri_hit` > 默认序 `["/v1", ""]`, **仅 404|405 触发下一候选** (懒回退, 2026-09-19 修订 / 待人工授权 — §99), 命中值记进 `common_uri_hit` 供下轮 fast path; g → `/v1beta/models` `{models:[{name:"models/X"}]}` (剥前缀); l → `/api/tags` `{models:[{name}]}`。
- **ROB (best-effort 永不 fail 查询)**: 上游 fetch 失败 / 超时 (10s) / 非 2xx / 响应畸形 → 该 provider 跳过 + warn (只含 provider id + reason, 永不含 key/secret), 查询仍 200 (从未成功过则该 provider 无贡献 → 仅别名)。
- **N5**: 所有条目 `owned_by: "router"` (统一, 不泄漏内部 provider id)。
- **D1**: wildcard pattern 本身不列入响应 (其覆盖的真实模型名经 merge 自然出现)。
- **D6 (回归守卫)**: Direct provider 的模型列表请求**不进此路径**, 透传行为完全不变 (byte-exact, 不进缓存)。
- **锁纪律**: walk 可达集快照 (触碰 ProviderTable 读锁) 必须在持有缓存 Mutex 之前完成 (持缓存锁跨 await 期间不得再取 ProviderTable 读锁)。实现级锁纪律的完整 SSOT (含 api_key 锁外预解析, #196 review L2) 见 `src/proxy/models.rs` 模块头 "锁纪律" 段。

**Properties**:
- `prop_router_models_advertise_matches_cached_oracle` (#196): 以缓存快照为 oracle, 合并段广告集恰为 {M ∈ ∪cached : resolve_route(M)=(T,E) ∧ E ∈ cached(T)}; 三边界成立 — 遮蔽 (更高 priority 路由夺走但目标清单无该名 → 过滤) / 重写 (判定看 egress E 是否在目标清单, 不看 M) / 解析失败 (NoMatch / 悬空 / 环 → 不广告); 列表序 = 别名 (路由表序) → walk 序 × 上游响应数组序, 全程去重。🔁→`router_models_default_plan_merge` + `n1_shadowing_and_fallback_boundaries` + `n1_rewrite_judges_egress_model_not_client_model` + `n1_broken_chain_not_advertised`
- `prop_router_models_exact_only_zero_fetch` (#196, N6): exact-only router (启用路由均无 `*`) 的 /models 查询**零上游请求** (上游 mock 命中数为 0), 响应只含别名。🔁→`router_models_exact_only_skips_upstream` + `advertised_names_exact_only_returns_aliases_without_merge`
- `prop_router_models_fetch_never_fails_query` (#196, ROB): 上游 fetch 失败 (非 2xx / 超时 / 畸形) 时 /models 查询仍 200 — 从未成功过则仅别名; 曾成功且 TTL 过期后刷新失败则 serve-stale 旧数据; TTL 过期后上游恢复则重新 fetch 覆盖。🔁→`router_models_upstream_error_serves_aliases_only` + `model_list_cache_stale_on_error_and_refresh_after_ttl`
- `prop_router_models_fetch_failure_backoff` (#196, N4/M1): fetch 失败后的退避窗口 (30s 常量) 内, 过期/从未成功的条目**不再重试** — 窗口内后续查询立即 serve stale (或无贡献), 上游恰命中一次失败请求; 窗口过后允许重试 (上游恢复则拿到数据)。🔁→`model_list_cache_failure_backoff_blocks_retry_within_window`
- `prop_router_models_single_flight` (#196, N4/M2): 并发 /models 查询 (首个 fetch 进行中到达第二个) 对同一 provider 的上游只发起**一次** fetch (等锁者随后读新鲜缓存, 不 stampede), 两查询响应一致。🔁→`router_models_single_flight_under_concurrency`
- `prop_direct_models_passthrough_unchanged` (#196, D6 回归): Direct provider 的 GET /models 仍上游字节原样透传 (byte-exact), 且不进 router 的清单缓存 (每次查询都触达上游)。🔁→`direct_provider_models_passthrough_byte_exact`
- `prop_router_models_alias_advertised_implies_resolvable` (#196, D2): 出现在响应别名段的 exact pattern 必可经 resolve_route 完整解析 (悬空 / 链上 NoMatch / disabled target 的 pattern 不广告); 禁用路由与 wildcard pattern 不进别名段。🔁→`alias_names_requires_full_chain_resolvable` + `alias_names_order_dedup_skip_disabled_and_wildcard`
- `prop_router_models_no_dag_records` (#196, D5): /models 本地终结与上游 cache-fill fetch 均不产生 DAG session / node (查询后 /api/sessions total=0)。🔁→`router_models_default_plan_merge`
- `prop_router_models_cache_keyed_by_egress_protocol` (multi-endpoint, 2026-09-20): 上游清单缓存条目键控 (provider id, 选定端点 egress 协议) — 不同 ingress 入口对同一 Direct provider 各自缓存各自清单: 同一入口 TTL 内重复查询零上游请求 (N4 复用), 另一入口的首次查询触发其各自端点的独立 fetch (不共享条目, 清单不串台)。🔁→`router_models_multi_endpoint_cache_per_ingress` (`tests/router_models.rs`) + `model_list_cache_keyed_by_id_and_egress_protocol` (`src/proxy/models.rs`)
- `prop_router_models_fetch_selects_endpoint_by_ingress` (multi-endpoint, 2026-09-20): /models 的上游 fetch 端点选择与 dispatch 转发路径同一语义 (`select_endpoint(ingress)`): ingress 精确匹配 → 该端点 + 其 egress 协议方言的请求 (anthropic 端点 fetch 带 anthropic-version header); 无匹配 → 首端点 (D2)。🔁→`router_models_multi_endpoint_cache_per_ingress` (match_header 锁定 egress 方言) + `router_tail_multi_endpoint_selects_endpoint_by_ingress` + `pool_member_multi_endpoint_selects_endpoint_by_ingress` (`tests/integration.rs`, dispatch 层同型语义)

---

## 2. RED: Redact / Restore

> 信任域 A. secret-guard 的核心安全功能. 来自原 C1-C7 契约.
> **独立形式化** (不因被 FWD-1 覆盖而省略, 见 §0.4 冗余覆盖原则).

### RED-1 mock 非空性

**陈述**: 每个 mock 必须非空, 且满足其 `GenSpec` 的 prefix/charset/length 约束.

**Properties**:
- `prop_mock_non_empty`: 对任意 (secret, strategy), 生成的 mock 非空. ✅
- `prop_mock_matches_gen_spec_charset`: mock 字符全部来自 gen_spec.charset ∪ gen_spec.prefix. ✅
- `prop_mock_length_in_range`: mock 长度 ∈ gen_spec.length_range. ✅ (长度含 prefix — 与 mock.rs `body_length_range` 归一化语义一致)

### RED-2 上下文唯一性 (in-context uniqueness)

**陈述**: 一次 `redact_ir` 调用内, 每个 mock 必须不出现在 pre-replace IR 中 (traverse IR 检查), 也不出现在已分配 mock 集合中.

**Properties**:
- `prop_mock_not_in_pre_redact_ir`: 对任意 (ir, secret), gen 出的 mock 不在 ir 的任何字符串叶子中. ✅
- `prop_mock_not_in_allocated`: 一次 redact_ir 调用内, 不同 secret 得到不同 mock. 🔁→`prop_redact_produces_distinct_mocks` (`src/redact.rs`; N secret → N mock 即 "不在已分配集合"的加强形式)

### RED-3 前缀缓存友好性 (确定性)

**陈述**: redact 不应无必要改变 request body 字节. 同一 (policy, OriginRecord, seed) 三元组 → 同一 RedactionMap.

**例外场景 (裁决, #143)**: pre-replace IR 已含该 secret 的**旧 mock** 时, 允许 (且实质必然, counter 候选哈希碰撞概率 ~26⁻ᴸ 可忽略 — "实质确定性" 术语先例见 RED-5) 生成不同 mock (probing counter 推进换候选). 现实触发路径: 上游响应 parse 失败 → fallback 透传含 mock 的字节 (根 AGENTS.md "已知限制") → 客户端把 mock 回传进历史 → 下一轮 IR 含旧 mock.

**裁决理由**: 若复用旧 mock, restore 会把历史中自然出现的旧 mock 错替成 real, 破坏 RED-6 round-trip — RED-2 (in-context uniqueness) 保护 restore 正确性**优先于** RED-3 缓存稳定性. 后果是 token 缓存费用 (经济性), 非 secret 泄漏 (安全性). 例外路径仍确定性 (counter 推进可复现); 若旧 mock 消失, mock 回退 counter=0 候选 (跨轮振荡是本裁决的已知代价).

**Properties**:
- `prop_c3_redact_ir_idempotent`: 对同一 (IrRequest, SecretTable, init_seed), 两次 `redact_ir` 产出语义相等的 RedactionMap. (legacy C3 命名) ✅ `src/redact.rs::prop_c3_redact_ir_idempotent`.
- `prop_same_policy_same_messages_same_mock`: 在多轮对话中 (IR 前缀增长, 历史不含旧 mock), 同一 secret 得到同一 mock (mock 在会话全程稳定, 前缀缓存友好核心声明). ✅ `src/redact.rs::prop_same_policy_same_messages_same_mock` + 多 secret 交互变体 `prop_same_policy_same_messages_same_mock_multi_secret`.
- `prop_policy_change_invalidates_all_mocks`: policy 变动 (添加/删除/编辑任一 secret) 改变 init_seed → 所有 mock 变化 (此为 per-request seed 模型的已知代价). ✅ `src/redact.rs::prop_policy_change_invalidates_all_mocks`.
- `prop_mock_changes_when_ir_contains_old_mock_exception`: 例外场景锁定 — IR 含旧 mock 时新 mock 实质必然不同 (碰撞概率可忽略), 但 RED-2 (新 mock 不在 pre-replace IR) + RED-6 (round-trip 恒等, 旧 mock 不被触碰) + 确定性仍成立. ✅ `src/redact.rs::prop_mock_changes_when_ir_contains_old_mock_exception`.

### RED-4 单射性 + 降级 (可配置: fail_open / fail_closed)

**陈述**: 一次 `redact_ir` 内不同 secret → 不同 mock. 极端弱配置下探测耗尽时的降级行为由 `[redact] on_probe_exhausted` 配置 (默认 `fail_closed`, SEC-10 降级偏安全 — 2026-09 翻转, 见 §99):

- **fail_closed (默认)**: **拒绝转发整个请求** (proxy 返回 503, body 的变量部分只含 secret id + reason 枚举, 不含 secret 明文), 防止 secret 泄露到 LLM provider.
- **fail_open (显式 opt-in, 历史行为)**: **跳过该 secret** (原样发往上游) 而非 panic, 优先保进程存活.

**Properties**:
- `prop_distinct_secrets_distinct_mocks`: 对 N 个不同 secret, 得到 N 个不同 mock. ✅ `src/redact.rs::prop_distinct_secrets_distinct_mocks` + `prop_redact_produces_distinct_mocks`.
- `prop_probing_exhausted_skips_not_panics` (fail_open 模式下): 弱配置 (charset=1 char, length=1) 耗尽候选时, 跳过该 secret, 进程存活. 🔁→`redact_ir_skips_secret_when_probing_exhausted_instead_of_panicking` + `redact_ir_checked_fail_open_skips_exhausted_secret` + `redact_ir_legacy_remains_fail_open_after_refactor` (`src/redact.rs`)
- `prop_probing_exhausted_fail_closed_refuses_forward` (fail_closed 模式下): 弱配置 + 对抗性 IR 耗尽候选时, 返回 503 + 上游未被调用 + 503 body 无 secret 明文 (载荷卫生交叉引用 SEC-2 — fail_closed 使 RedactError 首次在转发路径可达, SEC-2 重要性上升). 🔁→`fail_closed_mode_returns_503_when_probing_exhausted` (`tests/integration.rs`) + `redact_ir_checked_fail_closed_returns_err_on_exhaustion` 系列 (`src/redact.rs`)
- `prop_redact_error_never_carries_secret_value`: RedactError 只携带 secret_id + reason, 不含 secret 明文. 🔁→`redaction_map_insert_collision_returns_err_without_leaking_secret` + `prop_redact_error_debug_no_secret_leak` (`src/redact.rs`; SEC-2 property 形式化)

### RED-5 mock 不含 real_secret 子串 (实质确定性)

**陈述**: mock 不含 real_secret 的 ≥ `k(L)=max(4, ⌈L/3⌉)` 字符连续子串. 阈值随 secret 长度 L 自适应 (短 secret 强保护, 长 secret 弱保护, 信息泄露率上界 ~36%).

**Properties**:
- `prop_no_real_substring_ascii`: 对任意 ASCII secret, mock 不含其 ≥ k(L) 子串. 🔁→`prop_no_real_substring` (`src/redact.rs`) + `prop_c5_gen_candidate_auto_body_no_real_substring` (`src/mock.rs`)
- `prop_no_real_substring_multibyte`: 对任意 UTF-8 secret (中文/emoji), 同上, char-level 而非 byte-level. ✅
- `prop_c5_auto_mode_deterministic`: Auto 模式下, 内部重试链 (C5_INTERNAL_RETRIES=10000) 使失败概率 ~(1e-5)^10000 ≈ 0, 实质等价于确定性契约. ✅
- `prop_c5_fixed_mode_validated_on_upsert`: Fixed 模式 / 用户 prefix 在 `validate_against_real` (upsert 时) 校验, 不合格的 secret 拒绝入库. 🔁→`mock_strategy_validate_against_real_rejects_fixed_equals_real` 等 mock.rs validate 组 (upsert 链路经 `SecretEntry::validate_and_resolve` 调用)
- `prop_secret_with_mock_prefix_rejected`: secret value 含 `global_mock_prefix` 时被 `validate_value` 拒绝 (前缀非空时生效). 🔁→`validate_value_rejects_short_pua_and_mock_prefix` (`src/secrets.rs`) + `validate_value_rejects_mock_prefix` (`tests/integration.rs`)

### RED-6 可逆性 (round-trip identity, 非流式)

**陈述**: `restore_ir_response(redact_ir(req).0)` 后 IR 语义等价于原 IR. redact + restore 是可逆双射 (real ↔ mock 一一对应).

**Properties**:
- `prop_round_trip_identity_text`: text block 中 secret 的 round-trip identity. 🔁→`prop_round_trip_identity` (`src/redact.rs`, text 场景)
- `prop_round_trip_identity_tool_use_input`: tool_use input JSON 中 secret 的 round-trip identity. 🔁→`prop_response_tool_use_input_restored` (`src/redact.rs`)
- `prop_round_trip_identity_tool_result`: tool_result 嵌套 text 中 secret 的 round-trip identity. 🔁→`prop_round_trip_identity_all_positions` (`src/redact.rs`)
- `prop_round_trip_identity_system`: system prompt 中 secret 的 round-trip identity. 🔁→`prop_round_trip_identity_all_positions` (`src/redact.rs`)
- `prop_round_trip_identity_extra`: extra 字段 (未建模 JSON) 中 secret 的 round-trip identity. ✅
- `prop_round_trip_identity_multi_secret`: 多 secret (1..10) 同时出现的 round-trip identity. 🔁→`prop_multi_secret_round_trip` + `prop_response_multi_secret_round_trip` (`src/redact.rs`)
- `prop_round_trip_identity_repeated_secret`: 同 secret 在多字段重复出现的 round-trip identity. 🔁→`prop_repeated_secret_round_trip` (`src/redact.rs`)

### RED-7 流式可逆性 (streaming restorability)

**陈述**: `StreamingRestorer` 在任意 chunk 切分下保证 round-trip identity — `concat(push(c_1..n), flush().1)` 严格等于 `content.replace(mock, real)`. UTF-8 安全. 同协议路径 (StreamTranslate 同协议 restore 模式) 与跨协议路径 (StreamTranslate 跨协议模式注入 hook, 2026-09-15 起接入 dispatch) 均适用.

**Properties**:
- `prop_streaming_restorer_round_trip`: 对任意 chunk_size (1..N), round-trip identity 成立. ✅
- `prop_streaming_restorer_utf8_safe`: 多字节字符不在 char boundary 中间切的 round-trip identity. 🔁→`prop_streaming_restorer_round_trip_utf8` (`src/redact.rs`)
- `prop_streaming_restorer_multi_mock`: 多 mock 在同一段文本中的 round-trip identity. 🔁→`prop_streaming_restorer_round_trip_multi_mock` + `restorer_round_trip_on_multiple_mocks_in_one_chunk` (`src/redact.rs`)
- `prop_streaming_restorer_per_block_isolated`: 不同 block 的 restorer 状态独立 (block 间 mock 边界互不干扰). ⏳
- `prop_cross_proto_streaming_no_mock_leak_dispatch_integrated` (2026-09-15): 跨协议流式 + restore (生产 dispatch 同型构造) 下, 客户端 SSE 不含 mock 且 content / tool input == 上游拼接 `.replace(mock, real)` (端到端 HTTP 层由集成测试 `cross_protocol_streaming_redact_restores_mock_no_leak` 覆盖). ✅
- `prop_cross_proto_streaming_no_mock_leak_responses_combos` (2026-09-23, T5): Responses 任一侧的跨协议流式 + restore (r→o / o→r / r→a / a→r, 生产 dispatch 同型构造) 下, 客户端 SSE 不含 mock 且 content / tool input == 上游拼接 `.replace(mock, real)`; r→a 组合的 reasoning 块被 Anthropic ingress 显式丢弃 (STR-6 裁决), 其中 mock 一并消失属预期; o→r 组合的 Responses done 族全量帧由 writer 从 restore 后 IR 重合成 (no-mock-leak 扫描整条字节流覆盖). 🔁→`prop_cross_proto_streaming_no_mock_leak_responses_egress` + `prop_cross_proto_streaming_no_mock_leak_responses_ingress` + `prop_cross_proto_streaming_no_mock_leak_responses_to_anthropic` + `prop_cross_proto_streaming_no_mock_leak_anthropic_to_responses`
- `prop_same_proto_streaming_responses_restore_no_leak` (2026-09-23): Responses 同协议 + redact 命中 + stream=true (生产 dispatch 同型构造) 下, 客户端 SSE 不含 mock 且 delta / done 族帧文本 == 上游对应文本 `.replace(mock, real)` (done 帧由 writer 从 restore 后的 IR delta 重合成); 事件序列 response.created 开头 / response.completed 结尾; 流式 resp_parsed (LLM 视角, 含 mock) 经 StreamScan 累积非 None. 🔁→`responses_streaming_with_secret_hit_restores_mock` (`tests/integration.rs`)

### RED-8 JSON 叶子级兜底 restore (fallback restorability, opt-in)

**陈述**: **仅当 `[redact] on_fallback_restore = "restore"` (显式 opt-in, SEC-10)** 时: codec 无法 parse 上游响应 (`fan_out_buffered_ir` / `cross_proto_forward` 的 reader-拒绝 fallback 分支), 若 body 仍是**单个合法 JSON Value**, `restore_json_leaves_fallback` 必须在字符串**值叶子**上把 mock 还原为 real (JSON 树遍历, 非 byte find/replace — real 含 `"`/反斜杠/非 ASCII 时字节级替换会产出非法 JSON); 未命中任何 mock / parse 失败 (含 SSE-shaped 多帧 body) / map 空时返回 None, 调用方保持**原字节透传** (byte-exact 优先). Object key 不在遍历范围. 兜底**命中**时的输出为 normalize_json 等价 (serde_json 未启 preserve_order, key 按字母序重排), 非 byte-exact — 该路径本就以"codec 已拒绝 body"为前提, byte-exact 不成立, 由 restored-via-fallback WARN 保持可观测.

**默认行为 (withhold) 归 SEC-10**: 默认 `on_fallback_restore = "withhold"` 下 reader-拒绝分支**不尝试 restore** — 保留 Mock 原字节透传 + mock-not-restored WARN (detail 含 opt-in 提示), real 不进入降级响应体. 非 JSON 分支两模式行为一致 (恒透传 + WARN, restore 本就无意义). 裁决 rationale (失败/降级响应体是最高概率被客户端日志系统 / 错误追踪 / 会话记录采集的内容, 把 real 还原进去等于精准投放泄露) 见 **SEC-10**.

**Properties** (opt-in 模式下; 对应测试均显式配 `restore`):
- `prop_json_leaf_fallback_restores_mock`: 任意 JSON 树的任一字符串值叶子嵌入 mock → 兜底后输出可 parse 且叶子列表 == [嵌入位置的预期串 (含 real)] ++ [其余原叶子] (同时锁定 "对应位置含 real" / "无 mock 残留" / "其他叶子不变"); 未嵌入 → None. 生成器: string/bool/number/null 叶子 + 嵌套 array/object, 字符串字母表与 mock 不相交 (无残留断言严格成立); real 含 `"`/反斜杠/中文. ✅ `src/redact.rs::prop_json_leaf_fallback_restores_mock`.
- `prop_json_leaf_fallback_escaped_real`: real 含 `"`/反斜杠/中文时, 兜底输出仍是合法 JSON 且叶子 == real 原文 (wire 上正确转义 — 字节级替换会破坏 JSON, 本 helper 的差异化价值). 🔁→`restore_json_leaves_fallback_escapes_real_secret_correctly` (`src/redact.rs`)
- `prop_json_leaf_fallback_none_paths`: 未命中 / 非法 JSON / SSE-shaped 多帧 / map 空 → None (原字节透传, FWD-1 byte-exact 保持). 🔁→`restore_json_leaves_fallback_no_mock_returns_none` + `restore_json_leaves_fallback_empty_map_returns_none` (`src/redact.rs`) + `non_json_body_with_mock_still_passes_through_when_fallback_fails` (`tests/integration.rs`, 端到端行为守卫)
- `prop_json_leaf_fallback_wired_in_fallback_branches`: 同协议 reader 拒绝 / 跨协议 reader 拒绝的端到端场景 (显式 `restore` 配置), 客户端收到还原后的 JSON + restored-via-fallback WARN (不带 secret 明文). 🔁→`buffered_reader_reject_restores_mock_via_json_leaf_fallback` + `cross_proto_reader_reject_restores_mock_via_json_leaf_fallback` (`tests/integration.rs`)
- `prop_json_leaf_fallback_keys_untouched`: 只遍历字符串**值**叶子, Object key 不被改写. 🔁→`restore_json_leaves_fallback_leaves_object_keys_untouched` (`src/redact.rs`)

---

## 3. STR: 流式 SSE

> 信任域 A. SSE/chunked 流式响应的边界处理与累积.

### STR-1 chunk 边界透明

**陈述**: StreamTranslate 必须正确处理 TCP 切片 — 一个 SSE 帧可能被切成多个 chunk, 一个 chunk 也可能含多帧. 客户端最终看到的帧序列与上游发出的帧序列语义等价.

**Properties**:
- `prop_arbitrary_chunk_split_equivalence`: 对任意 chunk 切分 (含 1-byte 切分), StreamScan 累积结果 == 整体一次性 feed 结果. ✅
- `prop_stream_translate_chunk_split_equivalence`: 对任意 chunk 切分, StreamTranslate 输出 == 整体一次性 feed 结果. ✅
- `prop_crlf_lf_both_accepted`: SSE 帧终止符 CRLF 和 LF 都被正确识别. 🔁→`find_terminator_crlf_crlf` + `translate_handles_crlf_sse_frames` (`src/codec/stream/mod.rs`)
- `prop_responses_translate_chunk_split_equivalence` (2026-09-23, T5): Responses 同协议 restore 模式 (含 mock restore), 任意切分 feed 的累积输出 == 一次性 feed (writer 合成的 `resp_` id / `created_at` 归一化后字节级; 切分不变性机理 — reassembly 保证只有完整帧进 reader, IR 事件序列与切分无关). ✅
- `prop_responses_scan_chunk_split_equivalence` (2026-09-23, T5): StreamScan(Responses) 任意切分 snapshot == 整体一次性 feed snapshot (双行帧 `event:`+`data:` 的跨 chunk 重组). ✅
- `prop_cross_proto_stream_responses_combos` (2026-09-23, T5): Responses 任一侧的跨协议流式翻译 (r→o / o→r / r→a / a→r, 任意切分含 r→o 1-byte) chunk 边界透明 — 语义保真断言见 FWD-3 `prop_cross_proto_stream_content_fidelity` 的 Responses 锚点组. 🔁→`prop_cross_proto_stream_responses_to_openai` + `prop_cross_proto_stream_openai_to_responses` + `prop_cross_proto_stream_responses_to_anthropic` + `prop_cross_proto_stream_anthropic_to_responses` + `prop_cross_proto_stream_byte_by_byte_responses_to_openai`

### STR-2 StreamScan 累积正确

**陈述**: 流式 SSE 经 StreamScan 累积的 IrResponse 必须与非流式路径的 IrResponse 语义等价 (即: 流式累积是 resp_parsed 字段的真相来源).

**Properties**:
- `prop_stream_scan_equals_non_streaming_parse`: 对任意合法 SSE 流, StreamScan snapshot == reader.read_response(累积的完整 SSE 字节). ✅
- `prop_stream_scan_accumulates_text`: 文本 token 跨 chunk 累积正确. ✅
- `prop_stream_scan_accumulates_tool_use`: tool_use input JSON 部分片段跨 chunk 累积正确. ✅
- `prop_stream_scan_include_usage_chunk`: OpenAI include_usage chunk 正确更新 usage (terminal delta input_tokens=0 时 backfill). ✅
- `prop_stream_scan_ignores_post_stop_noise`: stop event 后的噪声 chunk 被忽略. ✅
- `prop_responses_stream_scan_matches_expected_ir` (2026-09-23, T5): Responses SSE 流 (reasoning summary / text / function_call args delta / 可选 usage) 经 StreamScan 累积的 snapshot == 生成器同步构造的预期 IrResponse. 字面 "scan ≡ 非流式 read_response" 在 Responses 侧不成立 — 一个已知建模分歧: reasoning 双变体 (流式 ReasoningContent vs 非流式 Reasoning{summary}) (历史另一分歧 stop_reason 推断不对称已于 2026-09-23 消除: 非流式 "completed" 统一为按 output 推断); 故取生成器预期形式 (与 OpenAI 实现同型, 见 `src/codec/fwd_streaming_property.rs` 头部 "已声明缺口"). ✅

### STR-3 流式错误降级 (best-effort, 不泄漏)

**陈述**: 上游流式响应出错 (non-2xx / 断连 / 超时) 时, secret-guard 必须保证 mock 字符串**不出现**在最终返回给客户端的响应 body 中.

> **理想 vs 现状**: 此契约是理想目标. 当前实现中 non-2xx SSE fallback 路径会原样返回上游字节 (含 mock), 是已知 gap.

**Properties**:
- `prop_non_2xx_sse_no_mock_to_client`: non-2xx SSE 响应的客户端可见 body 中不含任何 mock 字符串. ⏳
- `prop_upstream_disconnect_no_mock_leak`: 上游断连后, 客户端可见 body 中不含 mock. ✅ (断连场景需 chunk 间 gap 保证 head 先 flush — 见 `spawn_upstream_sse_then_disconnect` helper 注释; 双防线: `StreamingRestorer::flush` 对残留做 restore + mpsc 保序使 Err 后 tail 不可达)
- `prop_upstream_timeout_no_mock_leak`: 上游超时后, 客户端可见 body 中不含 mock. ✅

### STR-4 缓冲溢出 abort

**陈述**: reassembly 缓冲超过 MAX_BUF (16 MiB) 时, StreamTranslate 必须 abort 而非 OOM.

**Properties**:
- `prop_max_buf_overflow_aborts`: 上游发送无终止符字节流超过 MAX_BUF 时, StreamTranslate abort, 进程存活. 🔁→`prop_max_buf_overflow_aborts_openai_ingress` + `prop_max_buf_overflow_aborts_anthropic_ingress` (`src/codec/fwd_streaming_property.rs`)

### STR-5 流式 reader 多 tool_call 索引分配

**陈述**: OpenAI 流式响应中多个并行 tool_call 必须被 reader 分配独立的 IR block index (用于后续 writer 透传到 wire 的 `tool_calls[].index`, 保证客户端按 index 聚合时不合并).

**Properties**:
- `prop_stream_reader_assigns_distinct_block_index`: 流式响应中 N (≥2) 个并行 tool_call 经 reader 解析后, 每个 tool_call 在 IR 中有独立的 block index. ✅
- `prop_stream_reader_mixed_text_and_tool_call_indices_correct`: 文本 + 多 tool_call 混合流的 block index 不冲突. ✅

> **历史 bug**: 9712c52. 注意此契约只覆盖 reader 侧. writer 侧"把 IR block index 透传到 wire `tool_calls[].index`"由 FWD-1/FWD-2 的 byte-exact property 守卫.

### STR-6 流式 reasoning_content 建模与 restore

**陈述**: 思考型模型 (OpenAI 兼容 provider 的 `delta.reasoning_content` / `message.reasoning_content`) 的思考增量必须建模为 IR 流事件 (`IrDelta::ReasoningDelta` / `IrBlock::ReasoningContent`) 并流经与 text 完全相同的 redact/restore 路径. 客户端在思考阶段持续收到 reasoning 增量 (非零字节), 且 reasoning 中的 mock 被 restore 为 real.

> **历史 bug** (#176): reader 不解码 `delta.reasoning_content` → redact 流式路径 (IR 重建) 思考期零字节 → 客户端空闲看门狗超时断连 (Chatbox 30s, 生产 499 事故). 非流式路径的 `message.reasoning_content` 与请求侧 assistant 历史回传同因丢失 (违反 FWD-1: redact 路径除 real↔mock 外不得改 wire).

**跨协议处置** (FWD-3 "范围外显式丢弃" 的新条目): ReasoningContent block 跨协议翻译时, 按目标协议能力区分 — Anthropic egress **丢弃** (thinking block 需要 signature, secret-guard 无法合法合成, 伪造会被 Anthropic API 拒收); Responses egress **流式保留** (2026-09-23 用户裁决授权: 合成为 reasoning item 的 `reasoning_summary_text.delta` 事件族 — 合法 Responses wire 形态, 语义降档为 summary 字段承载思考原文; 覆盖 property 见 o→r 组合的 `prop_cross_proto_streaming_no_mock_leak_responses_ingress` has_reasoning 分支), **非流式仍丢弃** (lossy-by-target, `write_response` 跳过 — 统一为 summary 合成留后续跟进). 不发明非法 wire 形态.

**Properties**:
- `prop_streaming_reasoning_restored_like_text`: 任意 chunk 切分下, 客户端 reasoning 拼接 == 上游拼接.replace(mock, real) + 无 mock 泄漏 + 思考期非零字节. ✅
- `prop_stream_scan_accumulates_reasoning`: StreamScan 把 reasoning delta 累积为 ReasoningContent block (与预期 IrResponse 一致). ✅
- `prop_stream_reader_reasoning_text_tool_indices_correct`: reasoning / text / tool 三类 block 的 IR index 互不冲突. ✅

**生成器覆盖** (§0.3 第 3 条): reasoning delta (含 mock, 跨 chunk 累积) 已加入 `arb_openai_sse_with_expected` (stream/mod.rs, has_reasoning 分支) 与 `arb_openai_sse_stream_with_mock` (fwd_streaming_property.rs); Responses 侧的 reasoning summary delta (含 mock) 由 `arb_responses_sse_stream_with_mock` (fwd_streaming_property.rs, has_reasoning 分支) 覆盖, r→r 同协议 restore 的 reasoning fidelity 断言随共享断言集生效; 非流式 `message.reasoning_content` / 请求侧 assistant 历史回传由 openai.rs 单测覆盖.

---

## 4. CDAG: Conversation DAG

> 信任域 B. 内容寻址的对话历史存储. 来自原 DAG INV-1..5.

### CDAG-1 req_delta 与 response 独立存储

**陈述**: 一个 Node 的 request 增量 (req_delta) 与 response 必须独立存储, 不捏造等式. response 完成与否不影响 req_delta 的可用性.

**Properties**:
- `prop_node_has_req_delta_even_without_response`: 即使 response 未完成 / 失败, req_delta 仍可查询. 🔁→`nodeview_defaults_when_no_response_attached` (`src/dag/mod.rs`)
- `prop_response_attached_independently`: attach_response 不修改 req_delta. 🔁→`attach_response_populates_nodeview_and_response` + `attach_response_can_be_called_twice_overwrites` (`src/dag/mod.rs`)

### CDAG-2 Merkle prefix hash 只基于 req_delta

**陈述**: Node 的 own_hash 与 prefix_hash 只从 req_delta (MessageRef 序列) 计算, response 不参与 parent 查找.

**Properties**:
- `prop_prefix_hash_invariant_to_response`: 同一 req_delta + 不同 response → 同一 prefix_hash. ✅
- `prop_parent_found_by_prefix_hash`: push 时 Merkle prefix hash 找 parent 正确 (线性链 / 多跳链 / fork). 🔁→`dag_push_linear_extension_finds_parent` / `dag_push_single_node_no_parent` / `dag_push_unrelated_messages_creates_new_root` / `dag_multi_hop_parent_chain` (`src/dag/mod.rs`)

### CDAG-3 Block refcount 一致

**陈述**: BlockPool 的引用计数在 intern 时 ++, 淘汰时按 req_delta + response message 分别递减. 任何时刻 refcount ≥ 0.

**Properties**:
- `prop_refcount_positive_after_push_sequence`: 任意 push 序列后, 所有 block refcount ≥ 0. 🔁→`prop_dag_refcount_positive_after_push_sequence` (`src/dag/mod.rs`)
- `prop_refcount_zero_blocks_reclaimed`: refcount=0 的 block 被回收. 🔁→`dag_prefix_block_refcount_no_leak_after_evict` + `dag_fifo_eviction_releases_blocks` (`src/dag/mod.rs`)

### CDAG-4 req_delta 不可变

**陈述**: Node 的 req_delta 入 DAG 后永不修改 (类型系统强制 `Arc<[MessageRef]>`).

**Properties**:
- `prop_req_delta_immutable_after_push`: push 后任意时刻查询 req_delta, 内容恒等于 push 时的内容. 🔁→`Arc<[MessageRef]>` 类型级保证 (无 mut API, 陈述自带); 运行时专项测试缺失

### CDAG-5 redact_seed 可重现

**陈述**: 给定 (req_delta, policy, seed) 三元组, RedactionMap 完全确定. seed=0 表示 passthrough (无 redact).

**Properties**:
- `prop_redact_map_reproducible_from_seed`: 给定三元组, derive_redact_map 产出同一 RedactionMap. ✅

### CDAG-6 hash collision 处置

**陈述**: BlockPool hash collision (概率 ~2^-64) 必须被检测且不静默覆盖. 检测方式可以是 panic (debug) / log+skip (release) / runtime Result, 但**绝不能**静默覆盖导致数据损坏.

> **实现**: `BlockPool::intern` 用 `assert!` (非 `debug_assert!`) 比对 hash 命中时的 block 内容, 不一致即 panic. 选择 panic 而非 log+skip: collision 属哈希函数 bug, 一旦真发生宁可暴露也不要静默继续 (静默会让两个不同 block 共享 hash, 引发难定位的数据损坏).

**Properties**:
- `prop_collision_detected_in_release`: release build 下 hash collision 也被检测 (不静默覆盖). 🔁→`block_pool_intern` 的 `assert!` (release 也运行, `src/dag/pool.rs`; 非 debug_assert)

### CDAG-7 孤儿节点可识别

**陈述**: 当 parent 被 LRU 淘汰后, child 节点必须能被识别为孤儿 (is_orphan), WebUI 据此降级展示而非显示残缺数据.

> **现状 (2026-09-17)**: `NodeView::is_orphan` 已实现 (dto 字段 + view 派生, 直查 parent 存活性, 不做链完整性 walk — 孙节点 parent 存活恒 false, delta 无损无需标记)。降级展示半边由 `full_request_messages → None` + preview fallback 承载; **wire 传播尚未接通** (NodeView 无 Serialize, ForwardRecord / TimelineRound 未携带该字段), 前端徽章利用留后续。

**Properties**:
- `prop_orphan_node_identifiable`: parent 不存在的 node 被标记为 is_orphan. ✅
- `prop_orphan_node_degrades_gracefully`: 孤儿节点的 timeline 查询返回降级视图 (而非 panic / 残缺数据). ✅ (白盒构造孤儿态 — 公共 eviction 被 child_count 保护正常不可达; 断言 full_request_messages → None + timeline 截断到存活轮次, 不 panic)

### CDAG-8 session 聚类稳定

**陈述**: Session id 由根 node 的 prefix_hash 决定 (稳定标识). 同一会话的 N 轮请求, 其 leaf node 前移时 session id 不变.

**Properties**:
- `prop_session_id_stable_across_rounds`: 同一会话 N (≥3) 轮 push 后, session id 恒等于根 node 决定的 id. ✅
- `prop_session_fork_creates_new_session`: fork (前缀相同但后续不同) 创建新 session. 🔁→`prop_session_fork_creates_new_session_id` (`src/dag/mod.rs`)

---

## 5. DTO: WebUI DTO 派生

> 信任域 B. proxy → DAG → webapi 派生字段的正确性.

### DTO-1 ForwardRecord JSON shape 稳定

**陈述**: ForwardRecord 的 JSON shape 必须稳定, 不随 DAG 内部结构变化漂移.

**Properties**:
- `prop_forward_record_json_shape_backward_compat`: 旧版序列化数据 (无 resp_parsed / redactions 字段) 仍能反序列化为合法 ForwardRecord. 🔁→`legacy_json_without_redactions_deserializes_to_empty_vec` (`src/record.rs`; 仅 redactions 字段, resp_parsed 缺省兼容由 serde default 承载无专测)
- `prop_forward_record_no_internal_leak`: ForwardRecord 不暴露 DAG 内部类型 (BlockHash / MessageRef 等). ✅ (marker 填充 + 序列化扫描禁词; 灵敏度由 `dto1_scanner_detects_internal_field_when_present` 守卫)

### DTO-2 redactions 字段 SSOT 派生

**陈述**: `redactions: Vec<(mock, secret_id)>` 必须从 RedactionMap SSOT 派生, 永不在前端 / API 层重新计算.

**Properties**:
- `prop_redactions_match_redaction_map`: redactions 字段的内容与 RedactionMap 一一对应 (consistency-check feature flag 守卫). 🔁→`redact_populates_record_redactions_field` (`tests/integration.rs`) + consistency-check 守卫 `assert_redactions_match_map` (`src/proxy/recorder.rs`, VIEW-2 表)
- `prop_redactions_no_real_secret_value`: redactions 字段不含真实 secret value, 仅 (mock, secret_id) tuple. 🔁→`redact_populates_record_redactions_field` 内嵌断言 "redactions must not leak real secret" (`tests/integration.rs`)

### DTO-3 resp_parsed 从 StreamScan 派生

**陈述**: 流式响应的 `resp_parsed` 必须从 StreamScan 累积派生. 非流式响应从 reader.read_response(raw_body) 计算.

**Properties**:
- `prop_streaming_resp_parsed_equals_stream_scan_snapshot`: 流式 resp_parsed == StreamScan snapshot. 🔁→`streaming_parsed_view_accumulates_text` (`tests/integration.rs`; 仅 text 累积维度)
- `prop_non_streaming_resp_parsed_equals_reader_parse`: 非流式 resp_parsed == reader.read_response(raw_resp_body). 🔁→`assert_resp_parsed_matches_source_nonstream` (`src/proxy/recorder.rs`, consistency-check) + `web_api_records_view_parsed_openai_returns_structured`
- `prop_resp_parsed_consistency_check`: resp_parsed 字段必须能通过 consistency-check 断言 (与原始数据视图一致). 🔁→`assert_resp_parsed_matches_source_nonstream` (`src/proxy/recorder.rs`, CI `just check-features` 执行)

### DTO-4 preview 提取 best-effort

**陈述**: `preview` 字段从 req_body 提取 (sidebar 主标题). 必须满足 best-effort 永不 panic, 假设不成立时降级.

**Properties**:
- `prop_preview_extracts_last_user_message`: 优先取最后一条 user message (前 48 chars). 🔁→`extract_preview_picks_last_user_message` (`src/derive.rs`)
- `prop_preview_fallback_when_no_user`: 无 user 时回退到最后一条有文本的 message. 🔁→`extract_preview_no_user_falls_back_to_tool_result` (`src/derive.rs`)
- `prop_preview_fallback_compression_marker`: 压缩 marker ("What did we do so far?") 命中时回退到最后一条 assistant 摘要. 🔁→`extract_preview_compressed_session_falls_back_to_last_assistant` (`src/derive.rs`)
- `prop_preview_none_degrades_to_placeholder`: 提取失败 (非 JSON / 缺 messages) → preview=None; 前端降级到占位文本 (sidebar round-item `(no preview)` / sub-dot tooltip `?` / timeline 气泡 `(no content)`, session 级先试 `path`). ⏳
- `prop_preview_push_time_snapshot_matches_reextract`: push 时存的 preview 与之后从 req_body_raw 重新提取的结果一致 (consistency-check 守卫). 例外: `round_role = Tool` 的轮次, `push_messages` 会用 `extract_tool_use_name` 覆盖 preview 为 tool name, 覆盖后不再等于 req_body_raw 提取结果 — 此 drift 是预期的 (详见 VIEW-2 脚注 ¹). 🔁→`assert_preview_model_match_source` (`src/proxy/recorder.rs`, consistency-check, VIEW-2 表 ¹脚注)

### DTO-5 req_delta_messages 切片正确

**陈述**: timeline 路径的 `req_delta_messages` 必须是本轮新增的 messages (从 req_body_raw 末尾截取), 同协议路径下与 IR req_delta 一致.

**Properties**:
- `prop_delta_slice_correct_same_proto`: 同协议路径下, req_delta_messages 与 IR req_delta (resolve + ingress writer 重序列化) 一致. ✅
- `prop_delta_includes_system_at_root`: 根节点 (start > 0) 的 delta 补回 system prompt. ✅
- `prop_delta_handles_non_json_body`: 非 JSON body 时返回空 vec (不 panic). ✅
- `prop_delta_handles_count_mismatch`: messages 数 < req_delta_count 时返回空 vec. ✅

### DTO-6 跨协议 delta 切片行为定义

**陈述**: 跨协议路径下, OpenAI writer 把 Anthropic 风格的混合 Text+ToolResult user 消息拆成 (1+N) 条 wire messages, 导致 req_body_raw messages 数 > IR messages 数. 此场景下 delta 切片的**期望行为**必须被定义 (而非静默错位).

> **理想 vs 现状**: 当前实现 delta 可能包含前序轮消息 (静默错位), 是已知 gap. 理想目标是从 IR req_delta resolve + ingress writer 重序列化.

**Properties**:
- `prop_cross_proto_delta_no_silent_misalignment`: 跨协议路径下 delta 切片要么正确, 要么显式标记降级 (不静默错位). ⏳

### DTO-7 session title 取根 node

**陈述**: session title 必须取会话根 node (最早 round) 的首条 user msg preview. 多轮对话中 title 不随每轮新问题漂移.

**Properties**:
- `prop_session_title_from_root_node`: session.title == 根 node 的首条 user msg preview. 🔁→`assert_session_title_matches_root_preview` (`src/dag/mod.rs`, consistency-check, VIEW-2 表) + `需求 6+7` (`tests/webui/im-ui.spec.ts`)
- `prop_session_title_stable_across_rounds`: 同一 session N (≥3) 轮 push 后 title 不变. 🔁→`I3 守卫` (`tests/webui/im-ui.spec.ts`; 3 轮后仍按根 marker 定位会话 = title 不随轮次漂移)

### DTO-8 RecordSummary 轻量化 (**已作废**)

> **作废 (2026-08-15, #147)**: 引用的 `GET /records` 列表 API 与 property
> `prop_record_summary_excludes_body` 均已随 session-aware sync API (`POST /api/sync`)
> 取代删除而消亡 — 全仓 (src/ + tests/) 零同名实现, 条目长期未标作废属文档漂移.
> 按 §0.2 "编号作废不重用" 规则, DTO-8 编号永久作废, 不再分配.
> 现行轻量化语义由 NodeView (`src/dto.rs`) 承载.

### DTO-9 round_kind 三态派生

**陈述**: 轮次展示类别 `round_kind` 是 `(split_at, msgs)` 的纯函数, 在 `push_messages` 内一次性预计算 (与 round_role 同位置修正, SSOT), TimelineRound / RoundBrief / NodeView 零成本透传, 前端按其分发渲染 (UI-1). 三态:
- delta 非空 (`split_at < msgs.len()`) → `normal`
- msgs 非空但全前缀重复 (`split_at == msgs.len()`) → `retry` (客户端重发 IR 等价请求 — 判定在 IR 哈希层, 字节级相同是典型场景; session 归属: 重发对象是当前 leaf → 延续同 session (**重试合并**语义, 人工授权 2026-08-26); 重发较旧轮次 → 按 CDAG-8 fork 语义开新 session. retry 轮继承 parent 的 round_role + preview — parent 的完整 messages == 本请求 body, 工具轮重试呈 sub-dot 同型展示而非伪组首)
- msgs 为空 → `no_messages` (空 body / Responses ingress 的 `input[]`)

**Properties**:
- `prop_round_kind_retry_on_identical_repeat`: 字节级相同请求重复 push (leaf 场景) → 第二轮 `retry` 且延续同一 session. 🔁→`round_kind_retry_on_identical_repeat_request` (`src/dag/mod.rs`)
- `prop_round_kind_retry_on_stale_prefix_forks_new_session`: 重发非 leaf 前缀 → `retry` 且按 CDAG-8 fork 开新 session. 🔁→`round_kind_retry_on_stale_prefix_forks_new_session` (`src/dag/mod.rs`)
- `prop_round_kind_retry_inherits_parent_role_preview`: retry 轮继承 parent 的 round_role + preview (工具轮重试呈 Tool + tool name). 🔁→`round_kind_retry_inherits_parent_role_and_preview` (`src/dag/mod.rs`)
- `prop_round_kind_normal_on_superset`: 超集延续 (delta 非空) → `normal`. 🔁→`round_kind_normal_on_superset_extension` (`src/dag/mod.rs`)
- `prop_round_kind_no_messages_on_empty`: msgs 为空 → `no_messages`. 🔁→`round_kind_no_messages_on_empty_messages` (`src/dag/mod.rs`)
- `prop_round_kind_carried_by_dtos`: TimelineRound 与 RoundBrief 均携带 round_kind. 🔁→`timeline_and_brief_carry_round_kind` (`src/dag/mod.rs`)

---

## 6. CFG: 双层配置

> 信任域 B. static + dynamic 双层配置的合并 / CRUD / 持久化正确性.

### CFG-1 OverrideMode 合并语义

**陈述**: 对每个 id, 实际生效值由 OverrideMode 决定:
- `Default`: dynamic 优先于 static.
- `PreferStatic`: 强制 static, 忽略 dynamic.
- `Disabled`: 从 effective view 完全排除.

**Properties**:
- `prop_default_dynamic_wins`: Default 模式下, static + dynamic 都有同 id → 用 dynamic. ✅
- `prop_default_static_fallback`: Default 模式下, 仅 static 有 → 用 static. ✅
- `prop_prefer_static_ignores_dynamic`: PreferStatic 模式下, 用 static 原值. ✅
- `prop_disabled_excluded`: Disabled 模式下, id 不出现在 effective view. ✅

### CFG-2 Effective source 4 种标签正确

**陈述**: 每个 effective item 的 source 标签必须正确反映其来源:
- `static`: 仅 static 有此 id.
- `dynamic`: 仅 dynamic 有此 id.
- `dynamic_override`: static + dynamic 都有, decision=Default → 用 dynamic.
- `static_preferred`: static + dynamic 都有, decision=PreferStatic → 用 static.

**Properties**:
- `prop_source_label_matches_actual_origin`: source 标签 == 实际生效值的来源. ✅
- `prop_runtime_assert_effective_value_matches_source`: 在 consistency-check 模式下, 断言 effective_view[i].value == 对应来源的 value. ✅

### CFG-3 CRUD 操作语义

**陈述**:
- POST 创建 dynamic-only item, id 与 static 冲突 → 409.
- PUT 编辑: id 在 static 中 → 自动 fork dynamic override (git-style).
- DELETE 仅作用于 dynamic-only item; **只要 static 基线存在 (无论有无 dynamic override), 一律 409** (#156: 旧 "删 override 露出 static 返回 204" 语义让用户误以为删除成功, 而 item 仍存活, 在"下线止血"场景下是安全事故; 撤销 override 的正道是 decision).
- PATCH `/{id}/decision` 切换对 static id 的决策.

**Properties**:
- `prop_post_conflict_with_static_returns_409`: POST 创建与 static 冲突的 id → 409. ✅
- `prop_put_forks_dynamic_when_id_in_static`: PUT 编辑 static id → 创建 dynamic override. ✅
- `prop_delete_static_baseline_rejected`: DELETE static 基线存在的 id (static-only / static+override) → 409; dynamic-only → 204 且从 effective 消失. ✅
- `prop_patch_decision_toggles_override_mode`: PATCH decision 正确切换 OverrideMode. ✅

### CFG-4 持久化原子性

**陈述**: 先写 state.toml (atomic write + fsync), 再更新内存. 写失败时内存回滚.

**Properties**:
- `prop_persist_failure_rolls_back_memory`: state.toml 写失败时, 内存层不留下半提交状态. ✅
- `prop_atomic_write_no_corrupt_file`: atomic_write 用 tmp + rename, 中途崩溃不留下损坏的 state.toml. ✅
- `prop_persist_failure_rollback_under_concurrency`: 跨表并发写时, 一表 persist 失败回滚不影响另一表 in-flight 写入. ✅
- `prop_persist_failure_rollback_under_concurrency_cross_table`: 跨表完整覆盖 (装配 SecretTable + ProviderTable 共享 persist_lock + Decisions + 同一 state_path, 与 server.rs 一致): 只读窗口内双表并发写全失败 → 内存各自回滚互不污染 + 共享 Decisions 完全回滚且跨子表隔离 + state.toml 字节级不变; 窗口恢复后另一表写入成功提交, 终态内存/磁盘精确集合断言. ✅ (2026-09-17 补齐, 原 "单表降级 + 跨表作为后续工作" 注记关闭; 共享 state_path 下只读窗口对两表对称失败, "窗口内一表失败 + 另一表并发成功" 经锁序论证结构性不可达, 故按三确定性阶段覆盖)

### CFG-5 跨表并发安全

**陈述**: SecretTable 与 ProviderTable 共享 persist_lock (串行 RMW) 与 Decisions (同一份内存). 跨表并发写不丢更新.

**Properties**:
- `prop_concurrent_upserts_no_lost_update`: 单表 N 线程并发 upsert 不丢更新 (persist_lock 串行 RMW 基线). ✅
- `prop_concurrent_writes_serialized_via_persist_lock`: 跨表 (SecretTable + ProviderTable 共享 persist_lock + 同一 state_path + 同一 Decisions Arc, 与 server.rs 启动装配一致) 并发 upsert — 两表 effective 各含全部项 (跨表不丢更新) + 从磁盘 `load_or_empty` 重载得到的 DynamicState 同时含两表 dynamic 段 (persist_lock 串行 RMW, state.toml 不撕裂, 无跨表段覆盖). ✅
- `prop_cross_table_shared_decisions_isolation`: 共享 Decisions Arc 的跨表并发 `set_decision` (各改自己子表) 互不串扰 — secret id 的 decision 不误写到 providers 子表, 反之亦然; 合并后 state.toml 同时保留两子表 decision. ✅

> **覆盖现状**: CFG-5 的两个 property (`prop_concurrent_writes_serialized_via_persist_lock` + `prop_cross_table_shared_decisions_isolation`) 已实现跨表完整覆盖 — 装配方式与 `server.rs` 生产路径一致 (共享 `Arc<Mutex<()>>` persist_lock + 共享 `Arc<RwLock<Decisions>>` + 同一 state_path); CFG-4 的跨表失败回滚由 `prop_persist_failure_rollback_under_concurrency_cross_table` (CFG-4 节) 覆盖.

### CFG-6 悬空 decision 清理 (prune)

**陈述**: decision 仅作用于当前 static 层存在的 id. state.toml 中指向已不存在 static id 的悬空 decision 在启动时被清除 (内存 + 尽力持久化, 逐条 WARN), 防 "static id 删除后重新加入时静默继承旧 decision" (如 disabled → 条目从 WebUI 消失且无提示, 2026-09-13 排查).

**Properties**:
- `prop_prune_dangling_decisions`: 任意 (id 池 × static 存活子集 × 子表归属 × mode) 组合下, prune 清除的恰是全部悬空条目 (有非 Default decision 且不在对应 static 集合), 存活 id 的 decision (mode + 归属) 原样保留. ✅
- 场景回归: `prune_disabled_secret_id_revive_no_longer_shadowed` (`src/config.rs`) — static id 复活后查询回退 Default (未被残留条目遮蔽). ✅

---

## 7. SEC: 安全姿态

> 跨域. secret-guard 的安全不变量, 任何路径不得违反.

### SEC-1 GET 永不返回真实敏感值

**陈述**: GET API 永不返回 secret 的 `value` / provider 的 `api_key` 真实值, 用 mask_value 占位.

**Properties**:
- `prop_get_secret_masks_value`: GET /secrets 返回的 value 字段是 mask (如 `sk-****`), 非真实值. 🔁→`mask_value_hides_full_content` (`src/secrets.rs`) + `secrets_api_create_lists_update_delete` 内嵌 value_masked 断言 (`tests/integration.rs`)
- `prop_get_provider_masks_api_key`: GET /providers 返回的 api_key 字段是 mask. 🔁→`effective_snapshot_includes_provenance_and_masks_api_key` (`src/provider.rs`) + `providers_api_lists_existing` 内嵌 api_key_masked 断言 (`tests/integration.rs`)
- `prop_no_real_secret_in_any_json_response`: 任意 GET 响应 (含 ForwardRecord / EffectiveSnapshot / SessionSummary 等) 不含真实 secret value. ✅ (穷举式扫描: 遍历全部读端点, 非 2xx 即断言失败)
- `prop_no_real_api_key_in_any_json_response`: 同上, 不含真实 api_key. ✅ (同上, api_key 维度)

### SEC-2 RedactError 不携带 secret 明文

**陈述**: RedactError 只携带 secret_id + reason, 类型系统级保证不含 secret value.

**Properties**:
- `prop_redact_error_struct_has_no_value_field`: RedactError struct 字段集合不含 value. 🔁→`RedactError` 类型级保证 (enum 无 value 变体, 陈述自带); 运行时专项测试缺失
- `prop_redact_error_debug_no_secret_leak`: RedactError 的 Debug 输出不含 secret 明文. ✅

### SEC-3 assert/panic/log 不泄漏 secret

**陈述**: 任何 assert / panic / log 消息不得包含 secret 明文.

**Properties**:
- `prop_assert_messages_no_secret`: assert/panic 消息中不含 secret.value (即使用于诊断). ✅ (consistency-check feature gate, CI `just check-features` 执行)
- `prop_log_messages_no_secret`: tracing log 不输出 secret.value. ✅
- `prop_trace_span_no_query_string`: HTTP trace span 只记 path 不记 query — query 可能携带 key/token 类敏感参数 (SEC-C4a, 2026-09 扩展边界). 🔁→`trace_span_no_query_string` + `trace_span_omits_query_string` (`src/server.rs` / `tests/integration.rs`)

### SEC-4 headers 脱敏

**陈述**: 记录存储的 HTTP headers 中, auth/cookie 类敏感 header 必须脱敏为 `<redacted>`. 名单 = 硬编码黑名单 ∪ `[redact] redacted_headers` (用户追加, 归一化后精确匹配, 默认空 = 行为不变).

**Properties**:
- `prop_auth_headers_redacted_in_record`: Authorization / x-api-key / x-goog-api-key / cookie 类 header 在 record 中为 `<redacted>`. 🔁→`redact_headers_masks_secrets` (`src/proxy/helpers.rs`; authorization / x-api-key / x-goog-api-key)
- `prop_set_cookie_redacted`: 上游 Set-Cookie header 在 record 中脱敏. ✅ (`prop_set_cookie_redacted` + `prop_set_cookie_redacted_multi_value`, `src/proxy/helpers.rs`)
- `prop_custom_token_headers_redacted`: 含 "token" / "secret" 关键词的自定义 header 也脱敏. ✅
- `prop_configured_headers_redacted`: `[redact] redacted_headers` 配置的 header (归一化: trim + lowercase) 在 record 的 req_headers / resp_headers 中为 `<redacted>`; 未配置的无关 header 不受影响; 匹配为精确匹配非子串. 🔁→`redact_headers_extra_config_hits_custom_header` + `redact_headers_extra_is_exact_match_not_substring` (`src/proxy/helpers.rs`) + `normalize_trims_lowercases_and_skips_empty` (`src/state.rs`) + `redacted_headers_config_masks_custom_header_in_record` (`tests/integration.rs`, 端到端)

  注: "key" 关键词过于宽泛 (会误伤 `x-request-key-hash` 等正常 header), 故不纳入关键词匹配; 已知 key 类 header (如 `x-api-key` / `x-goog-api-key` / `api-key` / `x-anthropic-api-key`) 由 `prop_auth_headers_redacted_in_record` 的显式黑名单覆盖.

### SEC-5 PolicySnapshot 不进 WebUI DTO

**陈述**: DAG Node 持有的 PolicySnapshot (含 secret value) 仅后端用, 永不序列化进 WebUI DTO.

**Properties**:
- `prop_policy_snapshot_not_in_forward_record`: ForwardRecord JSON 不含 PolicySnapshot 字段. ✅
- `prop_policy_snapshot_not_in_session_summary`: SessionSummary JSON 不含 PolicySnapshot. ✅

### SEC-6 本地监听 + 内部 URL 不外泄

**陈述**: 默认监听 127.0.0.1. `/api/*` 未匹配子路径返回 404, 绝不进入 forward.

**Properties**:
- `prop_default_host_localhost`: 默认 host=127.0.0.1. ✅
- `prop_internal_url_404_no_forward`: `/api/unknown` → 404, 不发送到上游. 🔁→`web_namespace_not_forwarded_to_upstream` + `unmatched_path_returns_404` (`tests/integration.rs`)

### SEC-7 Host 白名单 + Origin/Sec-Fetch-Site 校验 (防 DNS rebinding)

**陈述**: server 层最外层 middleware 对所有请求校验 Host 白名单 (防 DNS rebinding
— 单用户模式下 "同源策略兜底" 的假设被 rebinding 击穿); 对 `/api/*` 非安全方法
校验 Origin / Sec-Fetch-Site (CSRF 纵深). 白名单语义 SSOT 见
`src/server_host_guard.rs` 头部: 显式 port 必须匹配; **未声明**的域名 Host 一律
拒绝; loopback IP 字面量 / 配置 host / `localhost` / 空 host 放行; 配置 host 非
loopback 时任意 IP 字面量放行; `[server] allowed_domains` 声明的信任域名按名字
精确匹配且端口宽松 (反代 + 域名部署形态).

**Properties**:
- `prop_host_whitelist_rejects_domain_host`: 域名形式 Host (rebinding 载体) 对任意路由 (`/`, `/api/*`) 返回 403; port 不匹配 / 畸形 Host 同样 403. 🔁→`host_guard_rejects_domain_host_on_all_routes` (`tests/integration.rs`) + `loopback_config_rejects_domain_and_foreign_ip` (`src/server_host_guard.rs`)
- `prop_host_whitelist_allows_loopback`: loopback IP / localhost / 配置 host / 空 host (port 匹配) 放行; 配置 host 非 loopback (0.0.0.0 / LAN IP) 时任意 IP 字面量放行、域名仍拒. 🔁→`host_guard_allows_loopback_host` + `non_loopback_config_allows_any_ip_literal` + `portless_host_only_allowed_on_default_port`
- `prop_allowed_domains_declared_pass_undeclared_reject`: 声明域名 (含无端口/$http_host 端口形态/大小写) 放行且 Origin 同享; 未声明域名 / 后缀拼接 / 前缀拼接仍拒; IP 字面量条目跳过 ≠ 放行. 🔁→`allowed_domains_lets_declared_domain_pass_and_others_reject` (`tests/integration.rs`) + `declared_domain_ignores_port_and_case` + `undeclared_domain_still_rejected_even_with_allowlist` + `allow_domains_skips_ip_literals_and_noise` + `origin_with_declared_domain_allowed` (`src/server_host_guard.rs`)
- `prop_api_write_requires_browser_same_origin`: 非安全方法的 `/api/*` 请求带恶意 Origin / `Origin: null` / `Sec-Fetch-Site: cross-site` → 403; 两 header 缺席 (SDK 场景) 或同源值 (same-origin / same-site / none) 放行; GET 豁免. 🔁→`api_post_rejects_cross_origin` + `api_post_allows_missing_or_same_origin_headers` (`tests/integration.rs`)

### SEC-8 敏感落盘文件 owner-only (0600)

**陈述**: state 目录内的敏感工件 (state.toml 明文 secret/api_key, #157;
usage.sqlite3 redact 审计 **及其 `-wal`/`-shm` 侧车**; pricing.json) 在 unix 下权限
owner-only (0600): 新建即 0600 (`util::create_owner_only` / 写后收紧), 启动加载时
对旧版本残留文件 best-effort chmod 收紧 (失败 WARN 不阻塞; 设备文件跳过).
sqlite 侧车在首个写事务时才创建 (open 处收紧追不上), 由 writer 线程在每批
落库后收紧 (`tighten_wal_sidecars`, 幂等). 非 unix 平台无 POSIX mode, no-op.

**Properties**:
- `prop_state_file_owner_only`: `atomic_write` 写出的文件 mode & 0o777 == 0o600 (rename 重写后不回退); 0644 残留在 `load_or_empty` 时被收紧. 🔁→`atomic_write_creates_owner_only_mode` + `load_or_empty_tightens_loose_permissions` (`src/config.rs`)
- `prop_usage_sqlite_owner_only`: `open_file_db` 创建/打开的 usage 库文件 0600 (含新建即收紧); `-wal`/`-shm` 侧车在首批写入后 0600. 🔁→`open_file_db_creates_owner_only_mode` + `wal_sidecars_tightened_after_first_write` (`src/usage/store.rs`)
- `prop_pricing_cache_owner_only`: `write_disk` 落盘的 pricing 缓存 0600. 🔁→`write_disk_owner_only_mode` (`src/usage/pricing.rs`)

### SEC-9 API/WebUI 响应携带 nosniff

**陈述**: 所有 WebUI / JSON API / auth 响应带 `x-content-type-options: nosniff`
(`crate::state::NO_STORE` header 组成员, SEC-S1) — 阻止浏览器 MIME sniffing, 对
`escapeHtml` 纪律的纵深兜底。转发链响应**不带** — FWD-1 byte-exact 禁止网关向上游
响应追加 header, 由 fwd_* property 族隐式守卫。

**Properties**:
- `prop_response_nosniff_header`: `/` (HTML) / `/api/*` (JSON) / `/api/*` 404 兜底响应均含 `x-content-type-options: nosniff`. 🔁→`webui_and_api_responses_carry_nosniff` (`tests/integration.rs`)

### SEC-10 降级偏安全 (fail-safe degradation)

**陈述**: 在 secret-guard 无法维持核心保证 (real secret 不出现在未授权位置) 的降级
路径上, 默认策略必须**不扩散 real secret** — 请求侧降级 (mock probing 耗尽 /
codec-less 协议 + secrets) 默认拒绝转发 (503, 上游零请求); 响应侧降级 (codec parse
失败 fallback) 默认保留 Mock 透传 (Mock 按 RED-5 设计为可安全暴露). real 进入更大
暴露面 (上游 / 易被日志采集的失败响应体) 必须显式 opt-in (`on_probe_exhausted =
"fail_open"` / `on_unsupported_protocol = "fail_open"` / `on_fallback_restore =
"restore"`). 三个开关: `[redact] on_probe_exhausted` / `[redact]
on_unsupported_protocol` / `[redact] on_fallback_restore`.

**Rationale (不对称性)**: 可用性损失 (请求被拒 / 客户端看到 Mock) 可重试恢复 —
重试 / 换协议路径 / opt-in; 机密性损失 (real 随上游请求或客户端日志扩散) 不可逆.
失败/降级响应体是最高概率被客户端日志系统 / 错误追踪 / 会话记录采集的内容, 把
real 还原进去等于精准投放泄露. 故默认"偏安全", 暴露侧行为一律显式 opt-in.

**Properties**:
- `prop_degradation_defaults_are_safe_side`: 三个降级开关 (`OnProbeExhausted` / `OnUnsupportedProtocol` / `OnFallbackRestore`) 的 `Default::default()` 均为安全侧 (FailClosed / FailClosed / Withhold), 且 `RedactConfig::default()` ([redact] 段缺字段时的 serde 回退) 与之一致 — 任一默认翻回暴露侧都是安全姿态回归. ✅ `src/config.rs::prop_degradation_defaults_are_safe_side`
- `prop_degradation_request_side_refused_by_default`: 默认配置下, 请求侧降级路径出站无 real secret — codec-less 协议 (gemini) + secrets → 503 + 上游零请求; probing 耗尽 → 503 + 上游零请求 (后者测试显式配 fail_closed, 默认值等价由 `prop_degradation_defaults_are_safe_side` 锁定). 🔁→`gemini_secrets_fail_closed_returns_503_zero_upstream_hits` (默认路径) + `fail_closed_mode_returns_503_when_probing_exhausted` (显式 fail_closed 行为) (`tests/integration.rs`)
- `prop_degradation_response_side_withholds_real_by_default`: 默认配置 (withhold) 下, 响应侧降级路径 (reader-拒绝 fallback) 的客户端 body 含 Mock 不含 real (原字节透传) + mock-not-restored WARN (detail 含 opt-in 提示), 同协议 / 跨协议两路径对称. 🔁→`reader_reject_withholds_real_secret_by_default_same_proto` + `reader_reject_withholds_real_secret_by_default_cross_proto` (`tests/integration.rs`)

---

## 8. ROB: 鲁棒性 (best-effort 永不 panic)

> 跨域. 对"尝试性解析"功能的鲁棒性要求.

### ROB-1 解析路径永不 panic

**陈述**: 对 preview / delta / tool_name 等尝试性解析, 缺字段 / 类型不符 / 空数组 / 越界 都返回 None 或空, 由调用方走 fallback.

**Properties**:
- `prop_preview_never_panics`: extract_preview_and_model 对任意字节输入 (含非 JSON / 空 / 损坏) 不 panic. 🔁→`prop_preview_never_panics_arbitrary_bytes` + `prop_preview_never_panics_perturbed_json` (`src/derive.rs`)
- `prop_delta_never_panics`: extract_delta_messages_from_raw 同上. 🔁→`prop_delta_never_panics_arbitrary` + `prop_delta_never_panics_chat_json_edge_slice` (`src/derive.rs`)
- `prop_tool_name_never_panics`: toolNameOfRound 对任意输入返回合法字符串 (含 '?'). 🔁→`extract_tool_use_name_empty_returns_none` / `extract_tool_use_name_no_tool_use_returns_none` (`src/derive.rs`; 纯 find_map 无 panic 路径)

> **理想 vs 现状**: tool name 推断由后端 `extract_preview_and_model` 承担,
> 其永不 panic 由 `prop_preview_never_panics` 守卫. 原 property 文本保留以维持编号稳定 (§0.5).

### ROB-2 假设声明注释必备

**陈述**: 每个尝试性解析点必须在函数级注释显式写出:
1. 对输入的假设 (如 "假设 messages 数组中 user 在 assistant 之前").
2. 假设不成立时的降级行为.

**Properties** (人工审查项):
- `prop_extract_delta_messages_has_assumption_comment`: extract_delta_messages_from_raw 函数级注释含假设声明. 🔁→人工审查项: `extract_delta_messages_from_raw` 函数级注释含假设声明与降级行为 (`src/derive.rs`)
- `prop_extract_preview_has_assumption_comment`: 同上. 🔁→人工审查项: `extract_preview_and_model` doc 含失败容错声明 (`src/derive.rs`)
- `prop_tool_name_has_assumption_comment`: 同上. 🔁→人工审查项: `extract_tool_use_name` doc 含降级声明 (`src/derive.rs`)

> **理想 vs 现状**: 假设声明载体是 `extract_preview_and_model` 的函数级注释,
> 由 `prop_extract_preview_has_assumption_comment` 覆盖. 原 property 文本保留以维持编号稳定 (§0.5).

---

## 9. VIEW: 视图正确性机制

> 跨域. 当用视图/引用/派生字段替代原始数据存储时的纪律.

### VIEW-1 先断言后删除

**陈述**: 删除原始数据前, 必须用 `assert_eq!(derived_view, original_data)` 断言两者相等, 或写专项测试覆盖. 禁止仅凭"视图逻辑应该对"就删除原始数据.

**Properties** (人工审查项 + feature flag):
- `prop_view_deletion_has_assertion`: 任何"删除原始数据改用派生视图"的重构 commit 必须含 consistency-check 断言. 🔁→人工审查项 + 既有断言 `assert_redactions_match_map` 等 (`src/proxy/recorder.rs`, VIEW-2 表)
- `prop_consistency_check_feature_runs_in_ci`: consistency-check feature flag 在 CI 中独立运行. 🔁→CI step `consistency-check feature guard` (`.forgejo/workflows/ci-merge.yml`) + `just check-features`

### VIEW-2 派生字段 consistency-check 覆盖

**陈述**: 所有从原始数据派生的字段必须有 consistency-check 守卫. 当前已知派生字段:

| 派生字段 | 来源 | 守卫状态 |
|---|---|---|
| `redactions` | RedactionMap | ✅ `proxy/recorder.rs::assert_redactions_match_map` |
| `preview` / `model` | extract_preview_and_model | ✅ `proxy/recorder.rs::assert_preview_model_match_source` ¹ |
| `resp_parsed` (非流式) | reader.read_response | ✅ `proxy/recorder.rs::assert_resp_parsed_matches_source_nonstream` |
| `resp_parsed` (流式) | StreamScan snapshot | ⏳ Phase A 已删除原始 SSE 字节, 派生与源物理分离, 暂无法守卫 |
| `req_delta_messages` | extract_delta_messages_from_raw (derive.rs) | (每次 timeline 请求重算, 无 drift 风险) |
| `session.title` | find_root_title | ✅ `dag/mod.rs::assert_session_title_matches_root_preview` |

> ¹ `preview` 守卫只覆盖 `build_call_event` 阶段 (event 构造时). `push_messages` 在
> `round_role = Tool` 时会用 `extract_tool_use_name` 覆盖 preview 为首个 ToolUse 的 name
> (前端 sidebar 三级菜单 tooltip + 颜色哈希依赖 tool name). 覆盖后的 preview 不等于
> `extract_preview_and_model(req_body_raw)` 的结果 — 此 drift 是预期的修正, 不属于守卫失败.

**Properties**:
- `prop_each_derived_field_has_consistency_check`: 上表中每个"待补"字段最终都有 consistency-check 断言. 🔁→`assert_redactions_match_map` 守卫状态表 (本节 VIEW-2 表格即 SSOT, 派生字段增删走表)

### VIEW-3 原始数据是核心功能真相

**陈述**: secret-guard 核心职责 (转发 + Redact) 的字节准确性是最高优先级. 任何"派生视图更优雅"的诱惑不得凌驾于数据准确性之上.

---

## 10. UI: WebUI 渲染

> 信任域 C. 跨 web/dag/index.html 的强不变量.

### UI-1 气泡数 == req_delta messages 长度 (空 delta 轮按 round_kind 分发)

**陈述**: 会话详情页 (timeline) 渲染的 Bubble 数量必须等于该 Node 的 req_delta messages 数组长度. 空 delta 轮的渲染语义按 `round_kind` (DTO-9, 后端 push 时预计算) 分发, 前端不做推断:
- `normal` → 渲染 delta 气泡 (气泡数 == delta messages 长度)
- `retry` → **0 个消息气泡** + retry 徽章 (重试轮用户没有发新消息, 渲染气泡会捏造 "用户把同一句话说了一遍")
- `no_messages` → preview fallback 单气泡 (空 body 等真无消息可渲染场景)

**Properties**:
- `prop_bubble_count_equals_ir_messages_length`: 对 N (≥1) 条 IR messages, timeline 渲染 N 个 Bubble. 🔁→`I1 守卫` (`tests/webui/im-ui.spec.ts`, 参数化 N=1/3/5)
- `prop_retry_round_renders_badge_not_bubble`: 字节级相同请求重发 → 同 session 2 轮, 仅 1 个 user 气泡 + retry 徽章 + sidebar retry 条目带 ↻ 前缀. 🔁→`UI-1 retry 守卫` (`tests/webui/im-ui.spec.ts`)

### UI-2 sidebar 条目数 == HTTP 请求数

**陈述**: 左边栏每个一级条目 (Session) 下, 二级 + 三级条目总数必须等于归属该 Session 的 HTTP 请求数 (DAG 中以该 Session 叶子为终点的链上 Node 数).

**Properties**:
- `prop_sidebar_item_count_equals_http_request_count`: 对 M (≥1) 个 HTTP 请求的 Session, sidebar 二级+三级条目总数 == M. 🔁→`I2 守卫` (`tests/webui/im-ui.spec.ts`)

### UI-3 timeline 轮次 DOM 顺序 == 数据顺序 (oldest-first)

**陈述**: timeline 中 `.tl-round` 在 DOM 里的出现顺序必须与 `state.timelineRecords` 完全一致 (oldest-first: 顶部最老, 底部最新).

**Properties**:
- `prop_timeline_dom_order_append`: append 模式 (新轮次追加) 下 DOM 顺序正确. 🔁→`I3 守卫` (`tests/webui/im-ui.spec.ts`, append 路径)
- `prop_timeline_dom_order_prepend`: prepend 模式 (滚到顶加载更早轮次) 下 DOM 顺序正确. ⏳
- `prop_timeline_dom_order_replace`: replace 模式 (切换会话) 下 DOM 顺序正确. ⏳
- `prop_timeline_dom_order_concurrent_fingerprint_mismatch`: 并发请求导致 fingerprint 错配时 DOM 顺序仍正确. ⏳

### UI-4 keyed reconciliation 不破坏 DOM 状态

**陈述**: 自动刷新触发 timeline 更新时, 公共节点的 DOM 完全保留 (scrollTop + 气泡展开状态), 仅新节点插入 / 消失节点删除.

**Properties**:
- `prop_reconcile_preserves_scrolltop`: 自动刷新前后 scrollTop Δ < 10px. 🔁→`自动刷新期间 scrollTop 保持` (`tests/webui/im-ui.spec.ts` "需求 1 (B1/B2 根治)")
- `prop_reconcile_preserves_bubble_expand_state`: 已展开的气泡在 reconcile 后仍展开. ✅ `im-ui.spec.ts` "UI-4 prop_reconcile_preserves_bubble_expand_state".
- `prop_reconcile_correct_for_all_change_modes`: keyed reconciliation 对 append/prepend/replace/完全不同 四种变动模式都正确. ✅ append (I3 守卫) + replace (切换会话, "需求 4") + 完全不同 ("UI-4 prop_reconcile_correct_for_all_change_modes"); prepend (滚到顶 lazy load) 待补.

### UI-5 末轮 response 独立 drawer

**陈述**: response 渲染为独立的 `.response-drawer` (overlay 架构), 不在 `.tl-round` 内. `#detail` 高度必须固定 (= wrapH), 禁止改为 `height: wrapH - drawerH` 或引入 flex 分栏.

**Properties**:
- `prop_detail_height_fixed`: `#detail` height == wrapH, 不依赖 drawerH. ✅ `im-ui.spec.ts` "UI-5 prop_detail_height_fixed".
- `prop_drawer_overlay_not_in_round`: response drawer DOM 不在 `.tl-round` 子树内. 🔁→`需求 3: response 抽屉固定底部` (`tests/webui/im-ui.spec.ts`, 间接覆盖)

### UI-6 timeline 滚动状态机: followMode 是视口位置的纯派生 (↔ AGENTS.md I5)

**陈述**: timeline 的 follow/pinned 状态由 "视口距底部距离" 机械推导 (SSOT), 不由 "最近点了什么" 显式动作决定. `selectedRound` 与 followMode 解耦 (方案 X): selected 不随 follow 自动推进, 仅 "进入 follow 的显式动作" (点 Session / 点 unread badge / 初次 loadTimeline) 才重置.

**核心不变量**: `state.timelineFollow == isNearBottom()`, 即 `scrollHeight - scrollTop - clientHeight <= NEAR_BOTTOM_PX` (≈ 100px). 此判定在每次 scroll 事件 (RAF 合并) + 每次新 round 追加后由 `syncFollowMode()` 重算.

**follow 闭合不变量** (UI-6 强化): follow 状态在新 round 插入下必须保持. 形式化: 若插入前 `state.timelineFollow == true`, 则 `scrollTimelineToBottomForce()` 执行 + RAF 合并的 `syncFollowMode()` 重算后, `state.timelineFollow` 仍为 `true`. 这要求 `bottomScrollTarget` 的计算结果必须把末轮真正送到视口底附近 (`isNearBottom()` 成立), 而不是被 clamp / drawerH 错误时序带回 pinned 区. 进一步, 末轮 request 底部必须出现在 drawer 上边缘之上 (不被遮挡), 让用户能看见刚插入的 round.

**已知限制 (几何失效区间)**: `contentEnd > wrapH - DRAWER_GAP - DRAWER_MIN_RATIO * wrapH` (短内容 + drawer 已显示) 时, drawer 压到 `minH` 仍遮挡末轮 ≤ `minH + GAP` (≈81px) — 几何上 contentEnd + minH + GAP > wrapH 不可兼得. 由 ROB-* best-effort 兜底, drawer 仍压到 minH 让遮挡最小化.

**Properties**:
- `prop_follow_initial_on_session_click`: 点 Session → follow + selected 在最新轮. 🔁→`UI-6: 点 Session → follow (滚到底), 无 unread badge` (`tests/webui/im-ui.spec.ts`)
- `prop_pinned_on_manual_scroll_up`: follow 状态下手动向上滚 → pinned. 🔁→`UI-6: 手动向上滚 → pinned (距底部 > NEAR_BOTTOM_PX)` (`tests/webui/im-ui.spec.ts`)
- `prop_pinned_new_round_no_scroll`: pinned 期间新 round 到达 → scrollTop 不变 + unread badge 显示. 🔁→`UI-6: pinned 状态下新 round 到达 → unread badge 显示 + selected 不变` (`tests/webui/im-ui.spec.ts`)
- `prop_unread_badge_resets_selected`: 点 unread badge → follow + selected 重置到最新轮 + badge 消失. 🔁→`UI-6: 点 unread badge → follow + selected 重置到最新轮 + badge 消失` (`tests/webui/im-ui.spec.ts`)
- `prop_follow_new_round_auto_scroll`: follow 期间新 round 到达 → 自动滚到底, 无 badge. 🔁→`UI-6: follow 状态下新 round 到达 → 自动滚到底, 无 badge` (`tests/webui/im-ui.spec.ts`)
- `prop_selected_stable_during_pinned`: pinned 期间点历史轮, 新 round 到达时 selected 不变. 🔁→`UI-6: pinned 期间点历史轮 → selected 停在该轮; 新 round 到达时 selected 不变` (`tests/webui/im-ui.spec.ts`)
- `prop_follow_invariant_under_new_round`: follow 状态在任意新 round 插入后必须保持 (不被翻转、末轮 request 不被 drawer 遮挡). 🔁→`UI-6: follow 状态在新 round 插入下不变` (`tests/webui/im-ui.spec.ts`, 短内容 + 长内容稳态双用例)

### UI-7 sidebar rounds 回填时序 + timeline 并发一致性 (gen)

**陈述**: 两个子性质:
1. **回填时延**: 点击 sidebar 会话头 (toggleSession 展开) 后, 三级菜单的 "Loading rounds…" 占位符必须在点击触发的主动 sync 返回时被覆盖, 不得依赖 3s 轮询 tick (否则占位符存活 0~3s; auto-refresh 关闭时无限期).
2. **timeline 世界一致性**: 以 `state.timelineGen` (代数, 只增不减) 划分 "timeline 世界". 核心不变量: **一个响应能写 `timelineRecords` / `state.tail` / `timelineReachedTop`, 当且仅当它描述的世界与当前世界同代**. 换世界者 bump (loadTimeline / clearTimeline); 写入者捕获出发时代数并在落地前对账 (sync 的 timeline 段 / loadOlder 全部落地路径含 !ok / loadTimeline 自身).

**矛盾游标守卫** (UI-7 前置): sync 构造 `selected` 游标前必须校验 `timelineSession === selectedSession` (records 归属与选中一致). 不一致 (loadTimeline 在途) 时发 null 游标 — 否则矛盾游标触发后端 `build_timeline_diff_inner` 的 "after 不属于本 session → 全链重放" 契约, 把整条链 append 进旧 records. `timelineSession` 由 loadTimeline 在**落地对账通过后**认领 (入口只 bump gen, 不预置归属, 否则守卫失效).

**幂等去重** (UI-7 补充): sync 的 `new_rounds` append 前按 round id 过滤已存在条目 (双 sync 并发时各自可能带回相同增量; node id 全局唯一, 去重安全).

**Properties**:
- `prop_rounds_immediate_fill_on_toggle`: auto-refresh 关闭时点击会话头, sidebar 三级菜单在 1s 内渲染实际条目 (非 loading 占位). 🔁→`UI-7: 点击会话后 sidebar rounds 立即回填 (不等 3s 轮询)` (`tests/webui/im-ui.spec.ts`)
- `prop_sync_no_contradictory_cursor`: loadTimeline 在途时触发的 sync 不携带矛盾游标 (发 null); 落地后 records 纯净无跨会话 round. 🔁→`UI-7: 点击会话后 sync 不发矛盾游标 (timelineGen 守卫)` (`tests/webui/im-ui.spec.ts`)
- `prop_stale_sync_diff_dropped`: 出发合法但迟到的 sync diff, 在世界切换后落地, timeline 段被丢弃, records 不被污染. 🔁→`UI-7: 在途 sync 的迟到 diff 不污染已切换的 timeline (gen 对账)` (`tests/webui/im-ui.spec.ts`)
- `prop_rounds_append_idempotent`: 相同 new_rounds 重复 append 后 records 无重复 id. ⏳ (由 gen 对账 + Set 去重共同保证, 专项 e2e 待补)

---

## 11. USAGE: 模型用量统计
### USAGE-1 聚合一致性 (hour 粒度 + rounds 三态)

**陈述**: 对任意查询窗口, `summary.totals` == 窗口内明细行 fold; `by_bucket` /
`by_model` / `by_provider` 各自分项之和 == totals. 聚合键是**本地时区 hour**
(`YYYY-MM-DDTHH`); 窗口 ≤14 天按 hour 粒度, 更长按 day 折叠 (bucket 前缀). rounds
三态满足 `requests == Σ(normal + retry + no_messages)`; `round_kind` 存储值 ==
dag `push_messages` 判定值的真值透传 (proxy 经 `round_kind_of` 回读刚 push 节点).

**Properties**:
- `prop_usage_aggregation_consistency`: 三向相等 (totals / by_bucket / by_model / by_provider) + 窗口过滤 (bucket >= cutoff). 🔁→`summary_sums_match_totals_across_all_views` (`src/usage/summary.rs`) + `open_reuses_existing_db_and_restores_aggregation` (`src/usage/store.rs`; 持久维度)
- `prop_usage_by_model_key_unique`: by_model 的 (model, provider) 键唯一 — 跨 bucket 折叠 (时间维度只在 by_bucket, 设计 §8 DTO 无 bucket 字段). 🔁→`by_model_folds_buckets_into_one_row_per_model_provider` (`src/usage/summary.rs`)
- `prop_usage_zero_filled_buckets`: by_bucket 是窗口内连续 bucket 序列 (无数据补零), 粒度随窗口自适应. 🔁→`empty_store_yields_zeroed_buckets_and_none_rates` + `long_window_folds_to_day_granularity` (`src/usage/summary.rs`)
- `prop_usage_hour_bucket_separation`: 相互间隔整小时的事件落入不同 hour bucket; day 折叠求和守恒. 🔁→`hour_granularity_separates_buckets_within_one_day` (`src/usage/store.rs`)
- `prop_usage_round_dimensions`: round_kind 三态 (retries / no_messages) + status 分类 (429 / 4xx / 5xx) 独立计数, 总和关系成立. 🔁→`record_response_counts_retry_and_429_dimensions` (`src/usage/mod.rs`)

### USAGE-2 回显保真 (presence + 归一化)

**陈述**: 存储的 usage 四元组 == 上游回显经 codec reader 归一化的值 (OpenAI
`prompt_tokens` 含 cached 总和, reader `saturating_sub`; cr/cw 的 `None` 按
`unwrap_or(0)` 落盘). presence 位忠实区分 "wire 无 usage 对象" 与 "显式全零回显"
(P-3 缺失显式): 非流式由 reader 判定, 流式由 MessageDelta.usage_present 位精确传递
(与 STR-2 scan ≡ 非流式 parse 的等价性联动).

**Properties**:
- `prop_usage_presence_distinguishes_absent_and_zero`: 三 reader (openai/anthropic/responses) 非流式 + anthropic 流式 message_delta: usage 对象缺席 → present=false; 显式全零 → present=true. 🔁→`read_response_usage_present_true_when_usage_object_in_wire` (`src/codec/openai.rs` + `src/codec/anthropic.rs`; 同名两处) + `stream_message_delta_usage_presence_distinguishes_absent_and_zero` (`src/codec/anthropic.rs`)
- `prop_usage_echo_fidelity_openai_normalization`: 端到端: 上游回显 prompt_tokens=100 + cached=30 → 存储与聚合 input=70 / cr=30 / output=50; 回显 model 优先于请求 model 作为聚合键. 🔁→`usage_stats_end_to_end_records_replayed_and_served` (`tests/integration.rs`)
- `prop_usage_quanta_none_cache_normalized`: IrUsage 的 cr/cw None 落盘归一为 0. 🔁→`quanta_from_ir_normalizes_none_cache_fields` (`src/usage/store.rs`)

### USAGE-3 成本纯函数与可复算

**陈述**: `cost(event, price)` 是确定性纯函数 (同明细 + 同价目表 ⇒ 同 cost; 无价 ⇒
None, UI 显示 "—" 而非 $0.00, P-4); 对聚合线性 (逐事件算再求和 == fold 后再算).
明细行不存 cost, 查询时按当前价目表实时重算 (历史随价目漂移, UI 明示 — 设计 §7 快照语义).

**Properties**:
- `prop_usage_cost_linear_in_aggregation`: fold 后算 == 逐事件算再求和. 🔁→`cost_is_linear_in_aggregation` (`src/usage/summary.rs`)
- `prop_usage_pricing_match_rule`: 匹配规则 SSOT: override 精确 > remote 精确 (多 vendor 消歧: hint host 的 vendor 集与候选集交集非空则收缩到交集; 池内确定性偏好序 = 无 `-plan` 段 > 名短 > 字母序; 结果与上游数据键序无关, #202) > 剥 `-YYYY-MM-DD` 后缀重试 > None. 🔁→`match_override_wins_over_remote` (`src/usage/pricing.rs`) + `match_strips_date_suffix` (`src/usage/pricing.rs`) + `match_host_collision_prefers_non_plan_vendor` (`src/usage/pricing.rs`) + `match_host_pool_shrinks_to_own_host_vendors` (`src/usage/pricing.rs`) + `match_length_tiebreak_prefers_shorter_name` (`src/usage/pricing.rs`) + `plan_vendor_detection_uses_segment_match` (`src/usage/pricing.rs`) + `match_ambiguous_hint_miss_falls_back_to_preference_order` (`src/usage/pricing.rs`)
- `prop_usage_pricing_schema_snapshot`: models.dev api.json 解析: cost 四价 + vendor api 域名提取; 无 cost 条目跳过; 解析成功但零价 (schema 漂移) 拒绝采信. 🔁→`parse_extracts_prices_and_vendor_domains` (`src/usage/pricing.rs`)

### USAGE-4 缺失显式

**陈述**: `requests == Σ(有 usage 行) + requests_without_usage`; usage 为空的行对
token / cost 贡献恒 0; `cost_coverage` 只以有 usage 的请求为分母; 无价 model 进
`unpriced_models` 清单; 有价但四价全零的 model (免费档 / 套餐 vendor 计量口径, 含
override 显式置零) 进 `zero_priced_models` 清单 —— "$0 已知价"与"无价"分开显式,
零价仍计入 coverage 分子 (零价是已知的价), 但单独列出防 cost=0 + coverage=1.0
掩盖 (#202).

**Properties**:
- `prop_usage_missing_explicit_accounting`: without_usage 计数独立 + token 贡献为零 + coverage 分母口径. 🔁→`record_accumulates_per_key_and_counts_missing_usage` (`src/usage/store.rs`) + `summary_sums_match_totals_across_all_views` (`src/usage/summary.rs`; coverage=0.5 断言内嵌)
- `prop_usage_unpriced_models_listed`: 无价 model 显示在 unpriced_models (提示配 override), 不产生 cost. 🔁→`summary_sums_match_totals_across_all_views` (`src/usage/summary.rs`; unpriced 断言内嵌) + `match_unpriced_returns_none` (`src/usage/pricing.rs`)
- `prop_usage_zero_priced_models_listed`: 全零价 model 显示在 zero_priced_models (提示按量估算口径可能失真), coverage 口径不变. 🔁→`zero_priced_models_listed_without_breaking_coverage` (`src/usage/summary.rs`)

### USAGE-5 计入判据 + status 原始事实

**陈述**: 仅 **POST 且收到上游响应** 的转发请求产生 UsageEvent:
- GET 请求被方法过滤 (GET /models 透传不计; router /models 本地终结无转发, 天然不计);
- dispatch 前置拒绝 (404/503/501) 与上游 send 失败 (502/504, 无响应) 不计 —
  "requests" 语义 = "上游实际返回了响应的 POST 请求数";
- 流式中断 (响应头已到达) 计入, complete=false + usage=None;
- `status` 存**原始 HTTP 状态码** (SSOT: 一列原始事实, 2xx/429/其余 4xx/5xx 的分类
  在 summary 派生层完成 — 回答所有 "某类错误多不多" 的问题, 不落 per-class flag).

**Properties**:
- `prop_usage_inclusion_post_only`: 非 POST → 零事件; 端到端 GET /models 透传不进 summary. 🔁→`record_response_filters_non_post` (`src/usage/mod.rs`) + `usage_stats_end_to_end_records_replayed_and_served` (`tests/integration.rs`; GET 不计入断言内嵌)
- `prop_usage_disabled_store_zero_overhead`: `[usage] enabled = false` → record no-op, 聚合恒空. 🔁→`disabled_store_is_noop` (`src/usage/store.rs`)
- `prop_usage_retention_expiry`: retention_days 过期行启动时清理 (SQL DELETE, 聚合不含). 🔁→`open_drops_expired_by_retention` (`src/usage/store.rs`)

### USAGE-6 SEC 边界: 自由字符串扫描 (关联 SEC 域)

**陈述**: `model` / `model_req` / redact 的 `mock` 是自由字符串 (非受控 id) —
fail_open passthrough 场景下 secret 理论可出现在 model 中 (mock 虽由 C5 保证不含
secret 子串, 仍做防御纵深), 且 SQLite 会**持久化** (比内存 DAG 更严重). 落账前
必须过 active secrets 扫描 (命中 → `<redacted:...>` 整体替换 + WARN) 并截断 256
chars (char boundary 安全); 其余事件字段为受控类型, 天然无 secret.

**Properties**:
- `prop_usage_model_secret_scan`: 含 secret 的 model → 整体替换 + 无残留; 干净 model 保留 + 超长截断在 char boundary. 🔁→`sanitize_redacts_model_containing_secret` (`src/usage/mod.rs`) + `sanitize_keeps_clean_model_and_truncates_at_char_boundary` (`src/usage/mod.rs`)

### USAGE-7 redact 审计持久化 (B 级 + 治理三问)

**陈述**: 每次请求侧 redact 持久化审计事件, 粒度 = 每请求 × 每命中 secret × 每
非零位置分类, 列集: ts / secret_id / mock / **category** / **count** / **node** /
**api_key_label** / provider / model_req / proto — 治理三问齐备:
- "何时何地泄了什么": ts / secret_id / mock / provider / model (B 级基线);
- "哪个环节塞进来的": category = 结构化位置分类 (system / tools / user /
  history / other, 语义与判定 SSOT 见 `codec::ir::HitLocations`; **C 级位置元数据
  的结构化落地 — 只存位置不存内容**), count = 该分类出现次数;
- "谁": node = DAG node 关联 (溯源到 mock 化请求原文, **悬空容忍** — restart /
  淘汰后 GET 404, UI 降级提示) + api_key_label = auth 归因 (API key 人类可读名,
  单用户模式 null).

**红线**: **永不**持久化 real secret 明文或上下文文本片段 (片段可能含未声明的
敏感信息, 持久化它们 = 泄露放大器; 事后取证走 node 关联的内存态 record 或显式
手动导出, 不做静默全量落盘). 落账点在请求侧 (redact 已实际发生, 即使响应失败也
不丢); 不过滤 method (redact 只发生在 body 改写路径, 审计语义与 method 无关).

**一致性**: `map.hits` 的分类计数 == 替换遍历覆盖的叶子集 (`StringLeafOps` 单一
实现), 统计于替换前的只读遍历.

**Properties**:
- `prop_usage_redact_persist_no_secret`: 持久化行 (含 mock) 过 active secrets 扫描永不命中 — 命中 secret 子串的 mock 整体替换为 `<redacted:mock>` (C5 防御纵深). 🔁→`record_redactions_expands_categories_and_sanitizes_mock` (`src/usage/mod.rs`)
- `prop_usage_redact_category_expansion`: per (secret, category) 展开保真 — hits 之和 == 分类计数之和, categories 聚合 == 明细 fold, 全零 locations → 零行. 🔁→`record_redactions_expands_categories_and_sanitizes_mock` + `record_redactions_noop_on_disabled_or_zero_locations` (`src/usage/mod.rs`)
- `prop_usage_redact_governance_attribution`: node / api_key_label 透传落列 (悬空容忍不 panic). 🔁→`record_redactions_carries_node_and_api_key_label` (`src/usage/mod.rs`)
- `prop_usage_hit_locations_classification`: 位置分类 (system/tools/user/history/other) 与 contains_user_text 联动; 分类总和 == 替换前 needle 总出现数. 🔁→`hit_locations_classifies_system_tools_user_history_other` + `hit_locations_matches_actual_replacement_total` (`src/redact.rs`)
- `prop_usage_redact_governance_e2e`: 端到端: secret 在 user message → summary.redactions 的 categories.user 计数 + node 非空 + mock 不泄漏. 🔁→`usage_stats_redact_audit_and_retry_round_recorded` (`tests/integration.rs`)

---

## 12. POOL: 套餐池 failover (Pool Provider)

> 信任域 A (转发链的路由面). Pool provider (`ProviderKind::Pool`) = 编码订阅套餐的
> 窗口限额轮换端点: 有序成员列表 (每成员 = 一份独立凭证的 Direct provider), 检测到
> "窗口限额耗尽"信号后自动 failover, 耗尽成员按恢复闹钟自动回归.
>
> **状态: 待人工授权** (§0.5) — 本段为 Pool Provider 特性 (T4 文档同步) 的契约起草,
> 编号 POOL-1..6 已预分配; 授权通过前, 模块级 SSOT 是 `src/pool.rs` 头部契约.

### POOL-1 顺序 failover (无游标列表序)

**陈述**: pick 无游标 — `members` 配置列表序即优先级, 每次请求解析 (`resolve_route` 的 Pool 跳, per-request) 选第一个 Active 成员。

- **闹钟回归**: 闹钟到期成员被解析顺带清除, 自然回归**列表头** (前缀缓存最大化命中, 无游标状态); 全部成员在闹钟期内 → `AllMembersExhausted` (含最早到期闹钟)。
- **配置对齐重建**: 配置随时可改 (WebUI) — 同位置同 id 保留耗尽状态, id 变化 (含长度/顺序变化导致的错位) 视为新成员 (Active)。
- **missing/disabled 成员**: 解析时**跳过但不标记** (配置可用性不进状态机 — 无持久副作用: GET /models 的可解析性探针复用同一解析路径亦安全); 重新 enable / 补上实体后下一次解析即自动回归列表头。
- **持久化**: 运行时状态仅存内存不持久化 (真相在上游, 重启重新探测)。
- **嵌套与环**: Router→Pool / Pool→Router 天然支持; pool members 构成新图边 — `would_cycle` / `find_cycles` 边集含**全部** members (与 route target 的 "仅启用路由构成边" 不同, members 无禁用等价物), `resolve_route` visited-set 运行时兜底。

**Properties**:
- `prop_pool_pick_first_active_list_order`: 解析恒取候选列表 (列表序) 的第一个配置可用成员 (重复解析稳定 — 无游标, 状态不变则结果不变); 闹钟过期成员回归列表头. 🔁→`active_members_returns_in_list_order` + `active_members_skips_exhausted_until_alarm_expires_then_head_returns` + `resolve_route_pool_skips_missing_and_disabled_members` (`src/pool.rs` / `src/provider.rs`)
- `prop_pool_all_exhausted_earliest_alarm`: 全部成员在闹钟期内 → Err 携带最早到期闹钟 + pool_id 回显; 候选全为配置不可用 (missing/disabled) → 同 Err 但 earliest = None (无闹钟可期 — 配置可用性不进状态机, 重新 enable 即时回归). 🔁→`active_members_all_exhausted_reports_earliest_alarm` + `resolve_route_pool_all_unavailable_sanitized_message` (`src/pool.rs` / `src/provider.rs`)
- `prop_pool_config_realignment_positional`: 配置对齐 — 完全一致保留 / 同位置同 id 保留耗尽状态 / id 变化视为新成员 (长度变化 / 顺序变化). 🔁→`align_rebuilds_on_member_changes_preserving_same_position_same_id` + `member_status_aligns_with_current_config_members` (`src/pool.rs`)
- `prop_pool_missing_disabled_skip_no_persistent_mark`: missing/disabled 成员被跳过 (取下一候选, 不报错, **无持久标记** — 补上实体后回归列表头). 🔁→`resolve_route_pool_skips_missing_and_disabled_members` + `resolve_route_pool_picks_first_member` (`src/provider.rs`)
- `prop_pool_nesting_and_cycle_edges`: Router→Pool 嵌套解析; pool 成员边参与三层环检测 (visited-set 运行时 / would_cycle upsert / find_cycles 启动诊断). 🔁→`resolve_route_router_to_pool_nesting` + `resolve_route_pool_cycle_detected` + `would_cycle_covers_pool_member_edges` + `find_cycles_detects_pool_edges` (`src/provider.rs`)
- `prop_pool_states_arbitrary_sequences_never_panic`: 任意耗尽/恢复/配置变更序列下解析永不 panic 且返回值 sound (Ok ⇒ 非空下标列表且全部 < members.len(); Err ⇒ pool_id 回显) — 状态机全态空间鲁棒性; 生成器覆盖 mark 闹钟与配置重组 (长度/顺序/重复成员). ✅
- `prop_pool_failover_end_to_end`: 端到端 — 成员 1 收到耗尽信号 (智谱码形态 / Claude header 形态) 后, 下一请求打到成员 2 上游; 闹钟到期后成员 1 回归列表头. 🔁→`zhipu_window_exhaust_switches_to_second_member` + `claude_subscription_header_exhaust_switches_member` + `exhausted_member_returns_to_head_after_cooldown_alarm` (`tests/pool_failover.rs`)

### POOL-2 三通道信号判定纯函数性

**陈述**: `detect_exhaustion` 是纯函数 (无副作用, 状态更新由调用方做), 匹配语义 = 三通道 OR:

- **status 通道**: 上游 HTTP status ∈ `exhaust.statuses` (默认空 = 关闭);
- **header 通道**: 任一 `exhaust.headers` 条目 `"name=value"` 精确匹配 (name 大小写不敏感 — HeaderName 规范化; value 精确匹配, 双侧容忍周边空白; 畸形条目静默跳过);
- **code 通道**: `status.is_error()` 且 body JSON parse 成功, 且四候选位置 (`error.code` / `error.type` / `error.status` / 顶层 `code` — 宽松收集, 覆盖 OpenAI/智谱/Anthropic/Gemini/DashScope 包装形态) 提取的**字符串**码 ∩ `exhaust.codes` ≠ ∅ (非字符串值跳过 — Gemini 的数字 `error.code` 天然过滤).

**提取宽 + 判别严** (设计依据, 勿 "修复"): 各家码值命名空间正交, 并集默认表在每家身上的投影恰好等于该家专属表, 无跨家歧义. 对任意输入 (非 JSON body / 畸形 UTF-8 / 非法 header 规则 / 越界时间值) 零 panic (ROB 族), 失败走 None/跳过.

**Properties**:
- `prop_pool_three_channel_or_semantics`: 三通道各自命中 (智谱码 / Claude header / 用户 opt-in 的 status 通道 / DashScope 顶层 code 位置) + resume_at 解析源正确. 🔁→`detect_zhipu_window_exhaust_hits_with_next_flush_time` + `detect_claude_subscription_header_channel_hits` + `detect_deepseek_status_channel` + `detect_dashscope_top_level_code_position` (`src/pool.rs`; 六家真实 fixture 表)
- `prop_pool_default_table_negative_cases`: 默认表不命中清单 — 瞬态码 (智谱 1302) / 付费语义 (OpenAI insufficient_quota) / Gemini 数字码与 SCREAMING status / 2xx 闸门 (200 + body 含 "1308" 不命中); 用户 opt-in 配置后命中. 🔁→`detect_zhipu_transient_code_not_in_default_table` + `detect_openai_paid_signal_default_off_configurable_on` + `detect_gemini_numeric_code_skipped_string_status_optional` + `detect_2xx_never_hits_even_with_matching_code` (`src/pool.rs`)
- `prop_pool_detection_never_panics`: 任意字节 body (空 / 非 UTF-8 / 畸形 JSON / error 非对象 / code 非字符串) + 畸形 header 规则 (无 `=` / 非法 name) 零 panic, 不命中即 None. 🔁→`detect_arbitrary_bytes_never_panics` + `detect_malformed_header_rules_skipped` (`src/pool.rs`)

### POOL-3 闹钟自愈 (精确信号优先, cooldown 兜底)

**陈述**: 命中耗尽信号后, 恢复时刻按优先序取第一个可解析的: ① `Retry-After` header (非负整数秒 / HTTP-date) → ② body `next_flush_time` (智谱; `error` 对象内 / 顶层两位置; RFC3339 或 naive 本地时区) → ③ `anthropic-ratelimit-*-reset` header 族 (RFC3339 / unix 秒均尝试, 多个可解析值取**最晚** — 5h 与 weekly 同时 blocked 按晚者). 全部失败 → `resume_at = None`, 调用方挂 `now + cooldown_secs` 兜底闹钟. 解析出的时刻 clamp 到 `[now + cooldown_secs, now + 7d]`, 且 **cap 优先于下限** (cooldown > 7d 时下限折叠到 7d 封顶; 下限防 `Retry-After: 0` 探测风暴; 封顶防天文数字 → 成员永久休眠); 兜底闹钟的 cooldown 溢出 (超单调钟表示域) 同按 7d 封顶. 全部解析 best-effort (ROB, 失败回落下一来源).

**Properties**:
- `prop_pool_resume_priority_order`: Retry-After (秒数 / HTTP-date 两形态) 优先于 body 恢复源. 🔁→`resume_retry_after_seconds_wins_over_body_sources` + `resume_retry_after_http_date` (`src/pool.rs`)
- `prop_pool_resume_next_flush_time_forms`: next_flush_time 两位置 (顶层 / error 对象内) × 两格式 (RFC3339 / naive 本地时区). 🔁→`resume_next_flush_time_naive_local_and_error_position` (`src/pool.rs`)
- `prop_pool_resume_clamp_bounds`: 封顶 7d / 下限 cooldown / 过去时刻折叠到下限 / cap 优先于越界下限 (cooldown > 7d 折叠) / 兜底闹钟极端 cooldown 溢出封顶不 panic. 🔁→`resume_capped_at_seven_days` + `resume_floored_at_cooldown` + `resume_cap_wins_when_cooldown_exceeds_cap` + `watch_fallback_alarm_with_absurd_cooldown_caps_at_7d_no_panic` (`src/pool.rs`)
- `prop_pool_resume_anthropic_reset_latest_wins`: anthropic reset 族 RFC3339 / unix 秒两格式, 多值取最晚. 🔁→`resume_anthropic_reset_headers_rfc3339_unix_and_latest_wins` (`src/pool.rs`)
- `prop_pool_watch_alarm_precise_or_fallback`: PoolWatch 命中时 mark 的闹钟 = 精确信号 (可解析) 或 now+cooldown (不可解析兜底). 🔁→`watch_marks_member_with_parsed_resume_at` + `watch_marks_member_on_exhaust_signal_with_cooldown_fallback` (`src/pool.rs`)

### POOL-4 全耗尽快速失败 (本地 503, SEC-2)

**陈述**: 全部成员不可用 (耗尽 / missing / disabled) 时, dispatch 在路由解析阶段本地返回 503 `unavailable` — **零上游请求** (停损; sg 不做内部重发). message (`RouteError::AllMembersExhausted`) 只含 pool id + reason 枚举 + 最早恢复剩余秒 (或 "无计划恢复"), 绝不含上游 body 原文 (SEC-2 同型). 触发切换的那个请求**原样透传上游错误** (FWD-1 不破坏 — 靠客户端 SDK 对 429 的自动重试落到新成员).

**Properties**:
- `prop_pool_all_exhausted_local_503_zero_upstream`: 全耗尽 → 本地 503 + 上游 mock 零命中. 🔁→`all_members_exhausted_returns_local_503_without_upstream_request` (`tests/pool_failover.rs`)
- `prop_pool_exhausted_message_sanitized`: AllMembersExhausted 的 Display 只含 pool id + reason + 恢复时刻, 无 body 原文. 🔁→`resolve_route_pool_all_unavailable_sanitized_message` (`src/provider.rs`)

### POOL-5 检测旁路性 (FWD-1 附属)

**陈述**: 耗尽检测是**旁路动作** — 挂载点 (same_proto 字节透传 / same_proto IR redact 路径 / cross_proto; 流式请求的错误响应 (4xx/5xx) body 已缓冲) 调用 `PoolWatch::detect_and_mark` 不修改转发响应的**任何字节** (FWD-1: 客户端收到的错误 body 与上游返回逐字节一致); 非 pool 流量 (`PoolWatch` = None) 检测点零开销短路. 检测/切换日志与 WebUI member_status 只含 pool id / 成员 id / 时刻秒数 (SEC-2 / SEC-1: 无 body 原文, 无 secret). 已知不覆盖: 流式 2xx mid-stream SSE 错误事件 (假设: 智谱/Claude 撞限在 HTTP 层拒绝, 见根 AGENTS.md 已知限制).

**Properties**:
- `prop_pool_detection_side_effect_free_bytes`: 检测命中时客户端收到的错误 body 与上游返回逐字节一致 (刻意用非常规空白/键序形态锁定字节级, 而非语义级). 🔁→`detection_does_not_alter_response_bytes` (`tests/pool_failover.rs`)
- `prop_pool_detection_covers_all_forward_paths`: 三挂载点全覆盖 — IR redact 路径 / 跨协议路径 / 流式请求收到非 2xx. 🔁→`exhaust_detection_covers_ir_redact_path` + `exhaust_detection_covers_cross_proto_path` + `streaming_request_receiving_429_triggers_switch` (`tests/pool_failover.rs`)
- `prop_pool_watch_short_circuit`: 2xx (含 mid-stream SSE 语义) 与非信号错误 (瞬态码 / 5xx html) 不动状态. 🔁→`watch_short_circuits_on_success_and_non_signal_errors` (`src/pool.rs`)

### POOL-6 默认表语义域 (窗口限额) + 配置语义

**陈述**: 内置默认信号表 (常量 SSOT: `DEFAULT_WINDOW_EXHAUST_CODES` / `DEFAULT_WINDOW_EXHAUST_HEADERS`, serde default 与之共享) 的语义域 = **订阅窗口限额耗尽** (5h 滚动窗 / 周限 / 月限 — 会自动恢复): codes = 智谱 GLM Coding Plan `["1308","1310"]`, headers = Claude Pro/Max 订阅 unified 两项, statuses = 空 (关闭 — 无一家窗口限额可用纯 status 判别, 429 混杂瞬态限速). 付费/账单/瞬态类信号一律不进默认 (误切风险由用户 opt-in 自担, 姿势清单见 `docs/configuration.md`). 配置语义: `[providers.exhaust]` **字段级替换** — 显式配某字段 = 替换该字段默认值 (空数组 = 显式关闭该通道), "删默认表某个码" = 重抄剩余; 省略整段 = 内置默认表 (serde 字段级 default 与 `ExhaustConfig::default` 产出一致, 单一事实). 配置校验: 空 members / 自环 (member 含自身 id) / 非法成员 id 拒绝 (`Provider::validate`); 畸形 header 规则写入时 lint WARN (检测器对这类条目静默跳过, lint 前置暴露 — WARN 不 reject).

**Properties**:
- `prop_pool_exhaust_config_field_replacement`: ExhaustConfig toml roundtrip 三态 — 省略段 = 内置默认表 / 部分字段 override (字段级替换, 空数组关闭通道) / 全量显式. 🔁→`toml_pool_roundtrip_full_and_defaults` (`src/provider.rs`)
- `prop_pool_config_validation`: validate 拒绝空 members / 自环 / 非法成员 id. 🔁→`validate_pool_rejects_empty_members_self_ref_and_bad_ids` (`src/provider.rs`)
- `prop_pool_malformed_header_rules_linted`: 畸形 header 规则被 lint 捕获 (干净条目不报, 空白条目跳过). 🔁→`exhaust_lint_flags_malformed_header_rules_only` (`src/provider.rs`)

---

## 99. 变更日志

记录契约的重大语义调整 (编号永不变更/重用, 仅作废).

| 日期 | 契约 ID | 调整 | 原因 |
|---|---|---|---|
| 2026-09-23 | FWD-4 | **超时职责分工重构 (默认值变更, 用户授权)**: 应用层超时三档 (响应头流式档 60s / 响应头非流式档 300s / stream_idle 120s) 默认统一放宽为 **3600s 防挂兜底** — 角色从 "正常时长上界" 归位为 "保证 record 最终有终态"; 连接活性的精确检测归 TCP keepalive (`build_upstream_client` 显式钉住 reqwest 0.12.28 默认参数, 亚分钟级 ~45s 判死 → 502; 注: reqwest 0.12.x 默认已开启 keepalive, 钉住是防升级漂移), 应用层超时只兜 "进程活但死锁" 残余. 分档语义与 Properties 清单零变更. FWD-4 正文新增 "超时职责分工" 段 | 用户授权裁决 (会话 2026-09-23): 误杀合法慢请求 (深度思考 / 大上下文 prefill / relay 伪流式 / 思考期静默) 代价 = 3 倍账单 (上游已付 + 零产出 + 重试重付), 远大于晚报 504; "连接活着但无数据" 不构成 hang 证据. 事故记录: 流式档 60s (2026-09-23 会话), 非流式档 300s (#175, agent-service#130 重试风暴) |
| 2026-09-20 | FWD-5 + FWD-7 | **multi-endpoint 契约增补** (Direct Provider 多协议端点特性, T2): FWD-5 陈述新增端点选择语义 — Direct 条目 `endpoints` 有序数组 (每协议至多一条, validate 强制), dispatch 经 `select_endpoint(ingress)` 选端点 (精确匹配 → 同协议; 无匹配 → 首端点跨协议翻译 D2; 空 → 503), egress 协议 = 选定端点协议; 新增 property `prop_endpoint_selection_membership_and_exactness`. FWD-7 上游清单缓存键控 per-Direct-provider → **per-(provider, 选定端点 egress 协议)** (不同 ingress 入口各自缓存各自清单), fetch 措辞 "按目标 provider 自身 protocol" → "与 dispatch 同一 `select_endpoint(ingress)` 语义, 按选定端点的 egress 协议" (单端点配置下两者等价, 行为零变化); 新增 2 条 property (`prop_router_models_cache_keyed_by_egress_protocol` / `prop_router_models_fetch_selects_endpoint_by_ingress`) | 特性设计已获用户确认 (D1-D3 裁决, 2026-09-20, 特性设计文档 §8 增补点清单): 同一上游多协议兼容端点已是行业标配 (智谱/Kimi/DeepSeek); 裸 id 键控会让 /a 入口串台 /o 入口的清单 — 广告的模型未必能被该入口的服务端点提供 |
| 2026-09-19 | FWD-7 (N3/N4) | 上游清单 fetch 路径从固定 `/v1/models` 改为 **common_uri 候选序懒回退**: `GET {base_url}{common_uri}/models`, 候选序 = `DirectProvider.common_uri` (detect 固化的布局断言, 新增字段: `"/v1"` 裸根 / `""` 版本前缀已含 / 任意 `/` 开头自定义前缀 / None 未探测) > 缓存条目新增字段 `common_uri_hit` (运行时发现) > 默认序 `["/v1", ""]`; **仅 404|405 触发下一候选** (鉴权/连通/parse 失败立即终止), 命中值记进 `common_uri_hit` 供下轮 fast path. **待人工授权** (登记后实施, 同 POOL-1..6 先例) | 智谱 GLM coding plan 实测: base=`.../api/coding/paas/v4` 时 `base + /v1/models` 404 而 `base + /models` 200 — 固定路径假设对 "版本前缀已含" 布局 (智谱/DeepSeek/Moonshot 等国产系) 不成立, router /models 合并清单对这类 provider 恒空. common_uri 不影响转发 (FWD-1: 转发 rest 原样流过), 仅作用于 secret-guard 自建请求 |
| 2026-09-15 | SEC-10 (新增) + RED-4 | 新增 **SEC-10 降级偏安全 (fail-safe degradation)**: 请求侧降级 (probing 耗尽 / codec-less 协议 + secrets) 默认拒绝转发 (503), 响应侧降级 (codec parse 失败 fallback) 默认保留 Mock 透传, real 进入更大暴露面必须显式 opt-in. 配套默认值翻转 ×2 (用户授权): `[redact] on_probe_exhausted` / `on_unsupported_protocol` 默认 fail_open → fail_closed (RED-4 陈述同步: fail_closed 为默认, fail_open 显式 opt-in); 新增开关 `[redact] on_fallback_restore` (默认 withhold). 三开关默认值 + 默认配置下降级路径出站无 real 由 SEC-10 property 锁定 | 用户授权的安全裁决 (PR #222 增量反馈): 失败/降级响应体是最高概率被客户端日志系统 / 错误追踪 / 会话记录采集的内容, 把 real 还原进去等于精准投放泄露; 可用性损失可重试恢复, 机密性损失不可逆 — 一切降级路径默认偏安全; 自用项目无兼容负担 |
| 2026-09-15 | RED-8 | 陈述改写为条件式: JSON 叶子级兜底 restore 仅在 `[redact] on_fallback_restore = "restore"` (显式 opt-in) 时生效; 默认 (withhold) 行为移交 SEC-10 (保留 Mock 原字节透传 + mock-not-restored WARN 含 opt-in 提示, real 不进入降级响应体). 5 条 property 标注不变 (对应测试改为显式 restore 配置后仍成立); 非 JSON 分支两模式行为一致 (恒透传 + WARN). 编号不变 | 同上 (SEC-10 裁决): RED-8 的兜底 restore 把 real 还原进降级响应体, 与降级偏安全默认相悖, 转为 opt-in; 默认行为归 SEC-10 统一陈述 |
| 2026-09-14 | RED-8 | 新增 JSON 叶子级兜底 restore 契约 (C8): codec parse 失败的 fallback 分支 (fan_out_buffered_ir / cross_proto_forward) 先尝试 JSON 树叶子级 restore, 尽力不让 mock 逃逸到客户端; 未命中/parse 失败返回 None 保持原字节透传. 同步补齐 cross_proto 非 JSON fallback 的 mock-not-restored WARN (#158 遗留). | parse-失败 fallback 透传含 mock 字节是已知逃逸路径; body 仍是合法 JSON (eg 字段类型错配) 时叶子级替换可堵住, byte-exact 仅在确有替换时让位 |
| 2026-07-26 | (initial) | 建立本文档, 收纳 C1-C7 / INV-1..5 / I1-I3 为 RED-1..7 / CDAG-1..5 / UI-1..3 | QA 系统梳理, 边界契约先行 |
| 2026-09-11 | USAGE-1/5/6/7 | 人工授权 (usage-stats v4): 存储层 JSONL → SQLite (USAGE-1 聚合一致性改为 SQL 直查, "重放恢复" 重述为 "持久恢复"; 无内存双份簿记); 聚合粒度 day → **hour** (≤14 天 hour bucket, 更长 day 折叠, by_day → by_bucket); USAGE-1 新增 rounds 三态维度 (round_kind 真值透传自 dag push 判定); USAGE-5 新增 status 原始状态码语义 (429/4xx/5xx 派生分类, 不落 per-class flag); USAGE-6 扫描范围扩至 mock; 新增 **USAGE-7** redact 审计持久化 + 治理三问扩展 (B 级: 事件明细 + mock; 位置元数据 category/count (C 级结构化落地, 只存位置不存内容) + 归因 api_key_label + 溯源 node 关联 (悬空容忍); 永不含 real secret 与上下文片段). | 用户需求: 小时精度 / SQLite / rounds 与 retry 可见性 / 429 独立统计 / redact 审计记录 |
| 2026-07-26 | FWD-1 / FWD-2 | FWD-1 升级为透明中继半段式 byte-exact (端到端最强契约); FWD-2 降为 FWD-1 的分解 (纯 codec round-trip byte-exact, 便于 bug 定位); 增加 §0.3 Property 设计原则 + §0.4 冗余覆盖原则 | 讨论中意识到 semantic_equiv 难以测, normalize 后 byte-exact 是可机械验证的最强 property |
| 2026-07-26 | FWD-3 | 重写为"建模范围内语义保留 + 范围外显式丢弃", 不再承诺"保留 chat completion 语义" | 讨论中意识到跨协议翻译有不可避免的语义损失 (reasoning/citations/logproms 等), 契约必须显式声明建模范围 |
| 2026-07-26 | FWD-4 | `prop_response_never_size_capped` 改名为 `prop_client_response_not_capped_even_when_record_truncated`, 陈述精确化 | 讨论中澄清"客户端响应路径与 record 累积路径是两条独立路径" |
| 2026-07-26 | FWD-6 | `prop_competing_headers_stripped` 改名为 `prop_only_ingress_protocol_auth_header_sent`, 陈述精确化 | 讨论中澄清"剥离对手协议 auth header"的真实含义 |
| 2026-07-26 | RED-6/7 | 保持独立形式化, 不因被 FWD-1 覆盖而省略 | 测试原则是"不信任其他代码", 端到端测试通过不代表单步正确; 端到端失败时需单步契约定位根因 |
| 2026-07-26 | STR-5 | 描述收窄为"流式 reader 端 index 分配" (writer 侧由 FWD-1/FWD-2 byte-exact 守卫) | 讨论中意识到原 STR-5 与 9712c52 bug 的 reader/writer 侧职责混淆 |
| 2026-07-26 | §0.5 | 强化漂移处理流程: 契约不能擅自修改, 必须经过人工授权 | 契约是 normative 尺子, 不能让被测物自己定义尺子的弯曲方向 |
| 2026-07-28 | CDAG-6/7/8 | 新增 CDAG-6 hash collision 处置 + CDAG-7 孤儿节点可识别 + CDAG-8 session 聚类稳定 | DAG 落地后细化内容寻址存储的边界契约 (collision/eviction/session 稳定性) |
| 2026-07-28 | UI-4/5/6 | 新增 UI-4 keyed reconciliation + UI-5 末轮 response 独立 drawer + UI-6 timeline 滚动状态机 | 前端不变量从 AGENTS.md I1-I3 扩展为 UI-1..UI-6, 完整收录 keyed reconciliation / drawer overlay / followMode 状态机 |
| 2026-07-29 | FWD-1 | FWD-1 流式响应半段式 (`prop_streaming_response_half_byte_exact`) 追加 "理想 vs 现状" 注记: 字面 byte-exact 在 `same_proto_restore` 路径不成立, 当前守卫语义等价弱化形式 | 按 §0.5 漂移处理流程存档; 完整 byte-exact 需独立架构改动 (字节级扫描替换) |
| 2026-08-02 | UI-6 | 新增 `prop_follow_invariant_under_new_round` (follow 闭合不变量): follow 状态在任意新 round 插入下不被翻转 + 末轮 request 不被 drawer 遮挡 (几何允许区间内); 声明 `contentEnd > wrapH - GAP - minH` 区间豁免 | 现有 `prop_follow_new_round_auto_scroll` 只在"长内容稳态"断言结果 (距底 < 100), 不守卫机制本身; 历史 bug: 短内容 (`contentEnd ≤ wrapH`) + drawer 已显示时, placeholder=0 不提供滚动空间, `bottomScrollTarget` 想预留 `drawerH+GAP` 但被 `maxScroll=0` clamp, 末轮被 drawer 遮挡; 修复方案: `updateResponseDrawerLayout` 在 follow + 短内容 + drawer 遮挡时压缩 drawer 到 `wrapH - contentEnd - GAP` (派生属性, 无外部 state) |
| 2026-08-15 | RED-4 | 陈述参数化: 降级行为从单一 fail-open 变为 `[redact] on_probe_exhausted` 可配置二选一 (fail_open 跳过该 secret / fail_closed 拒绝转发 503); property 按模式二分并挂实际测试名 (原 `prop_probing_exhausted_skips_not_panics` / `prop_redact_error_never_carries_secret_value` 为幻影名); `prop_redact_error_never_carries_secret_value` 交叉引用 SEC-2 | #150: `on_probe_exhausted = "fail_closed"` 已实现且测试锁定, 但契约仍只描述 fail-open 分支, 在 fail_closed 配置下字面为假 (§0.5 漂移处理流程真空案例); 编号不变, 属"调整"非"作废" |
| 2026-08-15 | RED-3 | 新增例外场景裁决: pre-replace IR 含旧 mock 时允许 mock 变化 (probing counter 推进), 理由是 RED-2/RED-6 保护 restore 正确性优先于缓存稳定性; 补 3 条跨轮次 property (原 3 条契约 property 名零同名测试, 幂等性仅有 legacy C3 命名的同 IR 重复调用等价物, 跨轮次稳定性零覆盖) | #143: RED-2↔RED-3 设计张力未裁决 — 客户端把 mock 回传进历史 (上游 parse 失败 fallback 路径) 后, 同一 secret 的 mock 跨轮振荡, 上游前缀缓存反复失效; 定性为经济性代价 (token 费用) 而非安全泄露, 裁决维持现状 (restore 正确性优先), 例外由 `prop_mock_changes_when_ir_contains_old_mock_exception` 锁定 |
| 2026-08-15 | DTO-8 | **作废** (编号永久作废不重用): 引用的 `GET /records` 列表 API 与 `prop_record_summary_excludes_body` 已随 session-aware sync API 取代删除而消亡, 全仓零同名实现 | #147: 契约文档漂移走查 — 条目未随 API 删除同步标作废, 违反 §0.2 "删除作废不重用" 规则 |
| 2026-08-15 | CFG-3 | DELETE 语义收紧: static 基线存在 (含 static+dynamic override) 一律 409, 仅 dynamic-only 可 DELETE (204); 原 property `prop_delete_dynamic_only_succeeds` 改名 `prop_delete_static_baseline_rejected` 并扩展三态断言 | #156: 旧 "删 override 露出 static 返回 204" 语义让用户以为删除成功, provider 仍存活继续转发, "下线止血"场景下是安全事故; 且与 secrets 侧 "首次即 409" 行为不一致. 人工授权 (issue 给出方案 A/B 二选一, 采纳 A) |
| 2026-08-15 | 全部 | 建立 property 落地状态标注机制 (§0.6): 156 条 property 全量标注 ✅ 同名 53 / 🔁 改名 80 / ⏳ 待补 23, 并新增 `just check-contracts` lint (进 `just check` 阻塞链) 机械守卫 (✅ 须同名测试载体命中 / 🔁 全部锚点须可 grep / 每条必有标注 + 输入侧 fail-closed); ⏳ 项按风险排 P0-P2 补齐优先级 (§0.6) | #144: 走查发现 ~85/156 条 property 名零字面命中且无状态标注, 契约 Properties 列表部分沦为"愿望清单"; 其中改名落地断链占多数, 真零测试 23 条 |
| 2026-08-16 | UI-7 | 新增 UI-7 sidebar rounds 回填时序 + timeline 并发一致性 (gen): 点击会话头后 "Loading rounds…" 占位符由主动 sync 覆盖 (不依赖 3s tick); `timelineGen` 代数对账消灭跨会话脏 append (矛盾游标守卫 + 迟到 diff 丢弃 + round-id 幂等去重) | 排查 "点击 sidebar 一级菜单后 loading rounds 卡数秒": 后端实测 12ms/0.6ms 非瓶颈, 根因是前端回填依赖轮询 tick; 修复主动 sync 时暴露两类并发交错 (矛盾游标 / 迟到 diff), 一并形式化 |
| 2026-08-23 | STR-6 | 新增: 流式 reasoning_content 建模与 restore (reader 解码 / writer 写回 / StreamScan 累积 / streaming restore / 三类 block index 互斥); 跨协议处置显式登记为 FWD-3 已知损失 (Anthropic signature / Responses encrypted_content 不可合成) | #176: redact 流式路径思考期零字节, 客户端空闲看门狗超时断连 (生产 499) |
| 2026-09-23 | STR-6 | 跨协议处置修订 (用户裁决授权, §0.5 流程): Responses-egress 流式**保留** (reasoning_summary_text 事件族合成, 语义降档); Anthropic egress 与非流式路径维持丢弃 | Responses 流式落地 (PR #265) 引入的行为分叉合法化 |
| 2026-08-23 | FWD-4 | 新增"响应头超时分档"段 + property `prop_header_timeout_matches_stream_semantics`: send().await 响应头超时按请求 stream 语义分两档 (显式 stream=true → TTFT 档 60s; 其余 → 整响应档 300s) | #175: 非流式大上下文请求 (响应头等整响应生成完) 被单一 60s TTFT 量纲超时结构性误杀 (hermes cron 9 连续 504 事故) |
| 2026-08-24 | FWD-5 | 新增虚拟 provider 路由 5 条 property: per-request 解析 (`prop_route_resolution_per_request`) / 坏路由 503 (`prop_route_broken_returns_503`) / 环终止 (`prop_route_cycle_termination`) / upsert 环拒绝 (`prop_route_cycle_rejected_at_upsert`) / upstream_id 可观测 (`prop_upstream_id_observable`) | #179: 虚拟 endpoint (route_to) — 客户端固定连虚拟端点, WebUI 即席切换上游; 语义裁决 (per-request / 悬空放行 / 三层环防护) 经人工授权 |
| 2026-08-24 | FWD-1 | **语义修订**: "对 wire 的唯一合法修改是 real↔mock 替换" → 扩为两种: real↔mock 替换 + **model 字段重写 (仅当生效 provider 配置 `model_override`)**; 请求半段等式追加条件项 `.replace(model, override)`; 新增 property `prop_request_half_byte_exact_with_model_override`. 代价明示: override 生效时同协议无-secret 请求从字节直传降级为 IR 改写 (normalize 等价, 前缀缓存失效 — 用户主动选择的降级). 配套 FWD-5 新增 `prop_model_override_*` 4 条 (first-wins 解析 / egress 注入 / 无 codec 降级) | #183: 虚拟 endpoint P2 — 跨模型名切换 (切换 = target+model 二元组); 修订经人工授权 (2026-08-24, issue #183 记录裁决与 D1-D5 设计决策) |
| 2026-08-25 | FWD-5 | **多规则路由 (router rules) 契约修订**: 虚拟 provider (单 `route_to` + provider 级 `model_override`) → Router 构造 (`rules` 规则列表: pattern 通配符 / route_to / 规则级 model / priority); 规则按**请求 model** 匹配 (per-request, body 收集后解析); model 重写改 **pipeline** 语义 (改写值参与下一跳匹配, 后者覆盖前者 — 作废 first-wins 的 `prop_model_override_first_hop_wins`, 新增 `prop_model_rewrite_pipeline_feeds_next_hop` + `prop_model_rewrite_later_overrides_earlier`); 错误清单新增 NoMatch (无匹配规则 → 503); 环检查边集 = 启用规则; 新增 property: 请求 model 提取 / 通配符语义 / priority 序 + 同值列表序 tie-break / 禁用规则跳过 / no-match 503. FWD-1 措辞同步: `model_override` → 规则级 `model` 重写 (`prop_request_half_byte_exact_with_model_override` 更名 `..._with_model_rewrite`) | 虚拟 provider 多规则化: model 通配符路由 + 规则级 model 改写 (pipeline) + 删除 model_override 配置字段 |
| 2026-08-26 | UI-1 + DTO-9 | UI-1 精确化: "气泡数 == IR messages 长度" → "气泡数 == req_delta messages 长度, 空 delta 轮按 round_kind 分发" (retry → 0 气泡 + 徽章 / no_messages → preview fallback); 新增 DTO-9 round_kind 三态派生 (push 时预计算) + 6 条 property. 语义裁决 (人工授权): IR 等价的相同请求判定为重试, 重发对象是当前 leaf 时**合并保留** (延续同 session), 重发较旧轮次按 CDAG-8 fork 开新 session; retry 轮继承 parent 的 round_role + preview (工具轮重试呈 sub-dot 同型, 不捏造伪组首); 仅修展示 — 前端 fallback 曾把重试轮捏造为重复的用户消息气泡 | 用户报告: 多次发送相同请求 → timeline 出现多个重复用户消息, 不符合事实. 链路缺口 = 渲染规格的输入枚举不完备 (空 delta 轮未分类) + fallback 成 de facto 规格未审视 |
| 2026-08-27 | DTO-4 | property `prop_preview_fallback_method_path` 更名 `prop_preview_none_degrades_to_placeholder` 并改陈述: 原 "提取失败回退到 method+path" 描述的是已随 session-aware API 消亡的旧行为 (旧 RecordSummary 含 method/path, 现行 TimelineRound 不含), 实际降级链 = preview=None → 前端占位文本 (round 级 `(no preview)` / `(no content)`; session 级先试 `path` 字段). 同步修正 derive.rs 头注释/函数注释 + 根 AGENTS.md 鲁棒性段 + web/AGENTS.md 共 5 处散文残留 | 用户追问 NoMessages fallback 气泡内容时发现的文档漂移 (陈述与实现不符, 人工授权修正, PR #194 补充提交) |
| 2026-08-31 | FWD-7 | 新增: router provider 模型列表 GET 请求本地合成 (别名 ∪ 过滤后上游清单), 收纳 N1 合并过滤 (以缓存快照为 oracle) / N6 exact-only 零 fetch / 上游 fetch best-effort 永不 fail 查询 / fetch 失败退避 (30s 窗口内不重试, 窗口内查询立即 serve stale) / single-flight 并发去重 / Direct 透传回归守卫 (D6) / 别名 advertised ⇒ resolvable (D2) / DAG 零记录 (D5) 共 8 条 property | #196: open-webui 等消费方依赖 /models 发现模型, 别名不在透传列表导致 taskModel 静默回退; exact-only router 对 GET /models 直接 503 |
| 2026-09-03 | USAGE-1..6 | 新增模型用量统计 (usage-stats) 契约域: 聚合一致性 (三向相等 + 重放恢复) / 回显保真 (presence 位区分无回显与显式零, 联动 STR-2) / 成本纯函数与可复算 (models.dev 匹配规则 SSOT + 实时重算快照语义) / 缺失显式 (without_usage + coverage 口径) / 计入判据 (仅 POST 且收到上游响应; GET /models 与 send 失败不计) / SEC 边界 (model 字符串扫描 + 截断) | 模型用量统计功能 (设计 `docs/design/usage-stats.md`, 网关计量位势: wire 层回显消费, 零 tokenizer) |
| 2026-08-31 | FWD-1 | **适用范围修订 (待人工授权)**: router provider 的模型列表 GET 请求 (FWD-7 域) 本地终结, 不转发上游 — 对这类请求 FWD-1 不适用 (响应为本地合成, 可含缓存上游清单, 非实时中继); Direct provider 的 /models 仍受 FWD-1 约束 (先例: 2026-08-24 #183 的 FWD-1 修订) | #196: 模型列表发现是网关自身的元数据职责, 透传上游列表无法承载路由别名 |
| 2026-09-04 | USAGE-3 + USAGE-4 | USAGE-3 多 vendor 消歧语义澄清 (人工授权, #202): 原文"域名消歧, 仍歧义字母序"未规定同 host 多 vendor 碰撞行为, 实现为 last-wins (结果静默依赖上游 JSON 键序, 套餐 vendor 胜出 → cost 恒 0). 修订为: hint host 的 vendor 集与候选集交集非空则收缩到交集, 池内确定性偏好序 (无 `-plan` 段 > 名短 > 字母序), 结果与数据键序无关; 偏好序是启发式策略而非正确性保证. USAGE-4 新增 `zero_priced_models` 显式清单 (零价 ≠ 无价, coverage 口径不变) | #202: 套餐入口部署 est_cost_usd 恒 0 且 cost_coverage=1.0 掩盖异常; 链路缺口 = 消歧规则对碰撞场景欠规定 + 零价缺少显式观测信号 |
| 2026-09-15 | FWD-5 + FWD-3 + RED-7 | **跨协议流式接入 dispatch**: OpenAI⇄Anthropic + stream=true 从 501 改为 StreamTranslate 跨协议模式流式翻译 (redact 场景注入 restore hook, 响应侧 mock→real); FWD-5 的 `prop_cross_proto_streaming_returns_501` 作废, 收窄为 `prop_cross_proto_streaming_responses_returns_501` (Responses 任一侧仍 501 — read_response_events 未实现, 放行会翻译出空流); FWD-3 新增 `prop_cross_proto_stream_content_fidelity` (流式半段内容保真 + wire 帧顺序合法性); RED-7 适用范围扩至跨协议路径 + 新增 `prop_cross_proto_streaming_no_mock_leak_dispatch_integrated`. 配套实现: StreamTranslate 跨协议模式新增跳过 block 配对过滤 (writer 跳过 BlockStart 的 index 其 BlockStop 一并跳过, 不产生未配对 content_block_stop) + deferred message_stop (message_delta[usage] 先于 message_stop, Anthropic wire 合法顺序) | 跨协议流式翻译已实现且有 property 守卫, 但从未接入 dispatch (501 占位); dispatch 接入任务授权 (评审设计 2026-09-15) |
| 2026-09-17 | 多域 (ROB/工具+测试补齐) | **帕累托改进集中批次** (⏳ 9 条→✅): RED-1 charset/length + RED-5 确定性 + RED-6 extra + STR-3 timeout/disconnect + CDAG-7 + DTO-1 + SEC-4 set-cookie; CFG-4 补跨表失败回滚 `prop_persist_failure_rollback_under_concurrency_cross_table` (关闭 "后续工作" 注记); §0.6 清单同步 (剩 10 条: 待裁决/架构受限 3 + UI e2e 5 + 可排期 2). 配套生产修复: cross_proto 错误消息截断守 char boundary (原字节直切在多字节切点 panic, ROB-1 违例) + util 公共截断族 DRY (4 处合一); CDAG-7 `NodeView::is_orphan` 后端落地 (wire 传播留后续, 见 CDAG-7 现状注记) | 项目走查 (帕累托改进点集中实施): 走查发现 panic bug + 契约 ⏳ 清单 + 代码重复/热路径冗余 |
| 2026-09-19 | POOL-1..6 (新增, 待人工授权) | 新增套餐池 failover 契约域: POOL-1 顺序 failover (无游标列表序 + 闹钟回归列表头 + 位置对齐重建 + missing/disabled 跳过无持久标记 — 配置可用性不进状态机) / POOL-2 三通道信号判定纯函数性 (status/header/code OR + 四位置字符串码 + ROB 零 panic) / POOL-3 闹钟自愈 (Retry-After → next_flush_time → anthropic reset 优先序, clamp [cooldown, 7d], cooldown 兜底) / POOL-4 全耗尽本地 503 快速失败 (零上游请求 + SEC-2 净化) / POOL-5 检测旁路性 (不改转发响应任何字节, FWD-1 附属) / POOL-6 默认表窗口限额语义域 (付费/瞬态不进默认) + 字段级替换配置语义. 全部 property 挂现有测试 (`src/pool.rs` / `src/provider.rs` / `tests/pool_failover.rs`), 1 条 ✅ + 22 条 🔁 | Pool Provider 特性 (编码订阅套餐窗口限额轮换, spec 已与用户确认 2026-09-18); 本段为 T4 文档同步的契约起草, 按 §0.5 流程待用户登记授权 |
| 2026-09-23 | FWD-5 + RED-7 | **Responses 流式 501 解除**: Responses 流式 writer 落地 (T3) 后解除 proxy 层 501 门 (same_proto 的 redact+stream 门 + cross_proto 的 Responses 任一侧门) — 同协议 + redact 命中 + stream 走 StreamTranslate 同协议 restore 模式, 跨协议 Responses 任一侧走跨协议翻译模式 (codec 覆盖族内任意 pair 流式均翻译); FWD-5 的 `prop_cross_proto_streaming_responses_returns_501` 作废, 翻转为 `prop_cross_proto_streaming_responses_translates`; RED-7 新增 `prop_same_proto_streaming_responses_restore_no_leak` (同协议端到端). Responses 流式已知损失 (D5: hosted tools/refusal 丢弃, reasoning delta 归一, 多 content part 折叠等) 的 known-limitations 登记待 T6 | Responses 流式 SSE 完整支持方案 T4 (前置: codec 流式 reader T2 / writer T3) |
| 2026-09-23 | STR-1/STR-2 + FWD-1/FWD-3 + RED-7 (T5) | **Responses 流式纳入 property 机械验证**: 新增 `arb_responses_sse_stream_with_mock` 生成器 (reasoning summary / text / function_call args 三类 mock 载体 + 同步构造 STR-2 oracle); STR-1 新增 r→r 同协议 restore 字节级切分等价 (`resp_` id/`created_at` 归一化) + StreamScan(Responses) 切分等价 + 跨协议四组合 (r⇄o / r⇄a) 断言锚点; STR-2 新增生成器预期形式 (字面 scan≡非流式在 Responses 侧有两个建模分歧 — stop_reason 推断不对称 + reasoning 双变体, 显式登记为缺口而非放宽断言); FWD-1 流式半段 + RED-7 跨协议 restore 扩至 Responses 组合. T3 移交的两个已知漂移 (usage_present false→true / stop_reason=Other→failed) 按方案 D5 从生成器排除 (终止事件只产 response.completed; usage 只断言 output_tokens 值), 登记于 fwd_streaming_property.rs 头部供后续裁决 | Responses 流式 SSE 完整支持方案 T5 (前置: T4 proxy 解除) |
| 2026-09-23 | FWD-3 (Responses stop_reason) | **精确化演进 (免授权, §0.5 例外①)**: Responses 非流式 `read_response_status` 的 "completed" 分支从恒 EndTurn 改为按 output 推断 (有 function_call item → ToolUse, 无 → EndTurn), 与流式 reader 的 `saw_function_call` 推断对齐 — 流式/非流式粒度分叉消除, Chat tool_calls 经 Responses round-trip 精确保真; 单测 `responses_stop_reason_granularity_loss_cross_proto` 更名 `responses_stop_reason_tool_use_preserved_cross_proto` (断言从锁定降级翻转为锁定保真) | 用户裁决 (2026-09-23): 互译精确化是无需授权的演进方向, 契约锁定断言只是之前实现阶段的折衷 |
| 2026-09-23 | FWD-3 (Responses usage presence + Other 映射) | **诚实化 + 误导消除演进 (用户裁决)**: ① Responses writer (非流式 `write_response` + 流式终止事件) 对 `usage_present=false` 写 `"usage": null` 而非合成全零对象 — 上游未报用量不再被翻译成 "网关报了 0", round-trip presence 保真 (流式 round-trip 断言收紧为完全一致, Responses ingress 组合新增 `assert_responses_usage_presence_fidelity`); ② `write_status_str(Other)` 从 "failed" 改 "completed" — 未知停止原因大多是正常结束的变体, 伪装 failed 会触发客户端错误处理路径 (弹错/重试); 读侧 "failed"→Other 保持, round-trip failed→Other→completed 有损 (已知折衷: 未知不伪装成确定错误) | 用户裁决 (2026-09-23): 尊重事实是通用原则 (usage 缺失不伪造), 误导性错误信号必须消除 |
| 2026-09-23 | FWD-1 | **适用范围澄清 (用户授权, 2026-09-23)**: FWD-1 等式约束协议合法 wire; Anthropic 非法形态 `messages[].role=system` (claude code billing header 实测) 在 IR 路径被 reader 提升合并到顶层 system (与 OpenAI reader 对称), 该形态的 system 内容从 messages[] 搬移到顶层 — 字面 byte-exact 对其不成立 (位置搬移非丢失). 修复前 writer 静默丢弃该条目 (真信息丢失: 上游收不到 system 内容 + req_delta 计数与写回 body 错位致 timeline 气泡退化为 preview 截断). 原样写回替代方案会被 schema 严格上游 400 拒绝 | 用户报告 claude code `-p` 请求 timeline 只显示 48 字符 preview (2026-09-23 排查): AnthropicReader/Writer 对 messages[] 内 system 条目不对称 (reader 留在 ir.messages / writer filter 丢弃) — reader 提升为唯一既保内容又保可用性的选项 |
| 2026-09-23 | FWD-1 (修正) | **推翻同日"正规化"决策 (用户裁决, issue #269): Anthropic `messages[].role=system` 按原位保留写回** — 该形态是官方已正式支持的合法 wire (官方文档明言其为缓存友好的指令注入方式), "提升合并到顶层 system" 改变指令生效位置 + 顶层 system 增长使缓存前缀整体失效 + 消息级字段丢失, 三重损害均系错误; FWD-1 等式恢复无例外, reader/writer 位置保真, FWD-2 生成器解除 role=system 排除机械锁定; 同日登记的"适用范围澄清"行随之作废 (历史记录保留于上, 行为以本行 + FWD-1 注记为准) | issue #269 评估 (截图分析经代码与官方文档逐项核实属实): 同日 "原样写回会被 400" 的判断对当前旗舰模型已过时; 兼容边界 (Sonnet 5 等不支持该形态) 由客户端按目标上游自选形态, 网关不代改写 |
| 2026-09-23 | FWD-2 (wire-fidelity 扩展, L4/L5) | **wire fidelity 下沉到 message/tool/block 级 (#269 M1)**: `IrMessage`/`IrTool`/四个 wire 来源 `IrBlock` variant 增 `extra` 字段 (未建模字段逃生舱, 同协议透传/跨协议清空契约与顶层 extra 同型, `clear_wire_fidelity` 统一清空); Anthropic codec 收集/回写 block 级+工具级 `cache_control`、消息级 `output_config` 等; `tool_result.is_error` 改 `Option<bool>` (显式 false 不再静默省略); 顶层 `system` 字段形态元数据 `system_form` (单 block array 不折叠); dag BlockPool 内容寻址 hash 纳入 extra; redact 双轨遍历 (StringLeafOps + collect_ir_str_leaves) 同步覆盖 extra 叶子 (SEC 扫描无新盲区); FWD-2 生成器扩展 (system 形态+cache_control / tools extra / 消息级 output_config / block cache_control / is_error 显式 false / 响应侧 block extra) 机械锁定 | issue #269: Anthropic 缓存是显式 opt-in, IR 路径剥离缓存标记 = 长 agent 会话 input 成本约放大一个数量级; 仓库 C3 契约 (mock 确定性) 的缓存友好投入因此被完全抵消, 本修复是补完既有设计目标而非新特性 |
| 2026-09-23 | FWD-1 (M3) | **合法修改第三类: Anthropic egress 顶层自动缓存标记注入 (显式 opt-in, issue #269)**: `[redact] inject_cache_control = true` (默认 false) 时, same-proto IR 路径与 cross-proto 的 Anthropic egress 对不存在任何 cache_control 的请求注入顶层 `cache_control: {"type":"ephemeral"}` (automatic caching); 守卫: body 内已有任何缓存标记时不注入 (显式断点上限 4, 满槽顶层标记 400); 对顶层标记返 400 的旧版 Bedrock 集成保持默认关闭. 等价表述从"两种"修订为"三种" (见 FWD-1) | 同上 (#269): claude code 等自带 block 标记的客户端由 M1 保真, 本项服务不发标记的客户端; 注入是主动改写 wire 故走 opt-in, 默认关闭下 FWD-1 等式字面成立 |
