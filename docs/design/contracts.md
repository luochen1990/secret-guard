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
| `RED-*` | Redact/Restore (域 A) | C1→RED-1, C2→RED-2, C3→RED-3, C4→RED-4, C5→RED-5, C6→RED-6, C7→RED-7 | `src/redact.rs` + `src/mock.rs` 头部 |
| `STR-*` | 流式 SSE (域 A) | codec INV-4 → STR-5 | `src/codec/stream/` (目录, 拆分见 `src/codec/AGENTS.md`) |
| `CDAG-*` | Conversation DAG (域 B) | INV-1→CDAG-1, INV-2→CDAG-2, INV-3→CDAG-3, INV-4→CDAG-4, INV-5→CDAG-5 | `src/dag/mod.rs` 头部 + `docs/design/conversation-dag.md` |
| `DTO-*` | WebUI DTO 派生 (域 B) | (新增) | `src/web/AGENTS.md` + `src/record.rs` 头部 |
| `CFG-*` | 双层配置 (域 B) | (新增) | `src/config.rs` 头部 |
| `SEC-*` | 安全姿态 (跨域) | (新增) | `src/web/AGENTS.md` + `src/secrets.rs` + `src/provider.rs` |
| `ROB-*` | 鲁棒性 (跨域) | (新增) | 根 `AGENTS.md` "鲁棒性原则" |
| `VIEW-*` | 视图正确性机制 (跨域) | (新增) | 根 `AGENTS.md` "视图正确性确保机制" |
| `UI-*` | WebUI 渲染 (域 C) | I1→UI-1, I2→UI-2, I3→UI-3, I4→UI-6 (selectedRound 子属性), I5→UI-6 | 根 `AGENTS.md` "前端不变量" |

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

**⏳ 项补齐优先级** (按风险排序, 排期依据 — 23 条, 2026-08-15):

1. **P0 安全 (5 条: SEC-1 穷举 2 + STR-3 泄漏 3)** — secret 泄漏类:
   `prop_no_real_secret_in_any_json_response` / `prop_no_real_api_key_in_any_json_response`
   (SEC-1, 穷举式"任意 GET 响应扫描真实值", 现有个别字段 assert 不足); STR-3 的
   `prop_upstream_disconnect_no_mock_leak` / `prop_upstream_timeout_no_mock_leak`
   (`prop_non_2xx_sse_no_mock_to_client` 属已知 gap, 见 STR-3 "理想 vs 现状" 注记,
   补齐前需先裁决实现路线). mock 泄漏非 secret 泄漏但会破坏下游工具.
2. **P1 行为语义无守卫 (4 条: DTO-4 优先级链 1 + UI-3 DOM 顺序 3)** — ROB-1 只守
   never-panic, 行为语义 (fallback 链末端 / prepend 顺序 / replace 顺序 / 乱序自愈)
   无回归守卫, 重构时易静默回归.
3. **P2 边界补强 (其余 14 条)** — 已有实现遵循 + 邻近 property 间接覆盖, 专项断言
   缺 (RED-1 charset/length, RED-5 重试链确定性, RED-6 tool_result/system/extra,
   RED-7 block 隔离, CDAG-2/7, DTO-1 internal leak, DTO-6, FWD-2 流式双 round-trip,
   SEC-4 set-cookie); 随相关模块改动顺带补齐.

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

等价表述: **secret-guard 对 wire 的合法修改有且仅有两种: real↔mock 替换, 以及 model 字段重写 (仅当路由链上命中了携带 `upstream_model` 的路由)**, 除此之外的任何字节差异 (字段丢失 / 顺序错乱 / 重序列化改变 / 任意字段值变化) 都是 bug.

> **路由 model 重写代价明示** (2026-08-24 修订 / 2026-08-25 措辞随多规则化同步, §99 登记): 重写生效时,
> 同协议无-secret 请求从字节直传 (passthrough) 降级为 IR 改写路径 — 前者对无 redact 请求是 byte-exact
> 的, 后者经 reader→IR→writer 重序列化, 仅保证 normalize 后等价 (与 "同协议 + Redact" 的既有降级同型).
> 这是用户配置 route.upstream_model 时**主动选择的降级**, 非 bug. 经济性代价: 重写值与客户端请求的
> model 不同时, 上游前缀缓存从该请求起失效. 解析语义 (链上 pipeline / 无 codec 协议降级) 见
> FWD-5 `prop_model_rewrite_*` 系列.

`normalize` = canonical JSON (BTreeMap key 排序 + 紧凑序列化 + 无空白). 消除对语义无影响的字节差异, 剩下的差异全部是真正的信息差异.

**适用范围**: 同协议路径. 非流式 wire JSON + 流式 SSE wire.

**不适用**: 跨协议路径 (ingress wire 与 egress wire 是不同协议格式, 由 FWD-3 单独约束).

**Properties**:
- `prop_request_half_byte_exact` (非流式, 请求侧): 对任意合法请求 wire 含 real secret, `normalize(secret-guard 发往上游的 wire) == normalize(原始 wire).replace(real, mock)` (无路由 model 重写时). 🔁→`openai_request_redact_preserves_wire_except_secret` + `anthropic_request_redact_preserves_wire_except_secret` (半段式含 redact, `src/codec/fwd_property.rs`; 端到端 `redact_strips_secret_from_upstream_request`)
- `prop_request_half_byte_exact_with_model_rewrite` (非流式, 请求侧; 2026-08-25 前名 `prop_request_half_byte_exact_with_model_override`): 路由链命中携带 `upstream_model` 的路由时, `normalize(secret-guard 发往上游的 wire) == normalize(原始 wire).replace(real, mock).replace(model, rewrite)` — 无-secret 场景亦成立 (重写强制 IR 路径). 🔁→`model_rewrite_reaches_upstream` + `model_rewrite_no_secret_forces_ir_path` + `model_rewrite_with_secret_joint` (联合公式端到端) (`tests/integration.rs`)
- `prop_response_half_byte_exact` (非流式, 响应侧): 对任意合法响应 wire 含 mock, `normalize(secret-guard 返回客户端的 wire) == normalize(上游 wire).replace(mock, real)`. 🔁→`prop_response_round_trip_identity` / `prop_response_tool_use_input_restored` (redact.rs 响应侧) + 端到端 `restore_inserts_secret_back_for_client` (非流式) — 流式半段见 FWD-1 `prop_streaming_response_half_byte_exact` 弱化形式注记
- `prop_streaming_response_half_byte_exact` (流式, 响应侧): 流式响应的 restore, 经任意 chunk 切分, 同上. 🔁→`prop_streaming_response_half_byte_exact_openai` + `prop_streaming_response_half_byte_exact_anthropic` (`src/codec/fwd_streaming_property.rs`; 语义等价弱化形式, 见下方 "理想 vs 现状" 注记)

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
- `prop_cross_proto_unmodeled_fields_explicitly_dropped`: 范围外字段 (如 reasoning_content) 不出现在 egress wire. ✅
- `prop_cross_proto_extra_cleared`: 跨协议路径下 ingress IR 的 extra 字段必须清空, 不允许源协议独有字段泄漏到 egress. ✅
- `prop_documented_semantic_loss_list`: 所有已知的语义损失点必须在 `src/codec/AGENTS.md` 显式列出 (人工审查项). ✅

### FWD-4 HTTP 语义透传 + 客户端响应与 record 累积分离

**陈述**: 除 hop-by-hop header 外, HTTP 语义 (method / status / headers / stream 模式) 透传. **客户端响应路径与 record 累积路径是两条独立路径**: 客户端响应永远流式透传无大小上限, record 累积受 `MAX_RESP_BODY_RECORD` (32 MiB) 上限保护.

**响应头超时分档 (#175)**: send().await 的"响应头到达"超时按请求的 stream 语义分两档 — 显式 `stream=true` → TTFT 档 (`upstream_response_header_timeout_secs`, 默认 60s: 响应头在首 token 生成后即返回); 其余 (含缺字段 / 非布尔 / 非 JSON, OpenAI/Anthropic/Responses 均默认非流式) → 整响应档 (`upstream_nonstream_response_header_timeout_secs`, 默认 300s: 非流式响应头要等整个响应生成完, 74k token 上下文晚高峰可超 60s, 旧单一 60s 档会结构性误杀 — #175 hermes cron 504 事故). 语义 SSOT = "显式顶层布尔 true 才算流式", 两处实现须保持等价: `proxy::helpers::requests_stream` (passthrough 路径, 字节扫描) 与 codec reader 的 stream 解析 (IR 路径, `ir.stream`). 已知盲区: Gemini `alt=sse` / Ollama 默认流式经 body 检测不可见, 落非流式档 (保守方向, 可接受).

**Properties**:
- `prop_status_code_preserved`: 上游响应 status code 透传给客户端 (任意 status, 含错误码). 🔁→`upstream_non_2xx_is_forwarded` (`tests/integration.rs`)
- `prop_headers_preserved_except_hop_by_hop`: 上游响应 header 透传, 除 RFC 7230 §6.1 定义的 hop-by-hop header 外不丢失. 🔁→`sanitize_strips_hop_by_hop_and_host` + `strips_custom_connection_listed_header`
- `prop_stream_mode_preserved`: 上游若返回 SSE/chunked, 客户端也以流式收到 (非 buffered). 🔁→`forwards_streaming_sse` (弱形式: 断言 chunk 语义透传, 未断言非 buffered 到达时序)
- `prop_client_response_not_capped_even_when_record_truncated`: 即使 record 累积超过 MAX_RESP_BODY_RECORD 被截断 (写入 TRUNCATED_BANNER), 客户端响应仍收到完整上游字节. 此契约禁止有人把 MAX_RESP_BODY_RECORD 改成"客户端响应上限" (会静默截断用户响应). 🔁→`fan_out_streaming_truncates_record_but_not_client_response` (`src/proxy/fan_out.rs`)
- `prop_header_timeout_matches_stream_semantics`: 响应头超时按 stream 语义选档 (显式 `stream=true` → TTFT 档; 缺字段 / 非布尔 / 非 JSON / 嵌套 stream → 整响应档), 且 504 错误消息内嵌实际生效的超时值. ✅ (选档本体同名单测; 畸形形态半句由同文件 `requests_stream_malformed_bodies_fall_back_to_nonstream` + `prop_requests_stream_strict_bool_gate` 守卫; "504 消息内嵌实际超时值" 半句由 🔁→`stream_request_still_killed_by_stream_timeout_with_observable_message` 覆盖)

### FWD-5 路由分发契约

**陈述**: URL = `/{proto_short}/{provider_id}/*path`. 未知 protocol / 未知 provider / 禁用 provider / 不支持的协议组合 必须返回明确错误码. provider 可能是**路由的** (Router 构造, `routes` 路由列表, #179 多规则化): dispatch 在**请求 body 收集后**提取顶层 `model` 字段, router 按**请求 model** 匹配路由并链式解析到链尾实体 provider — 解析是 per-request 的, 切换路由只影响新请求. ingress 协议由 URL 决定, egress 协议由链尾实体决定 (不同则走跨协议翻译; Router 构造无 protocol 字段).

**路由选择** (`RouterProvider::select_route`): 启用 (`priority` 非 None) 且 model_pattern 匹配 in-flight model 的路由中 `priority` **最大**者; 同值并列按**列表出现顺序**取先者 (确定性 tie-break). model_pattern 是 model 名通配符: 仅 `*` 是元字符 (匹配任意串, 含空串), 其余字符字面匹配 (大小写敏感). **model 重写 pipeline 语义** (`resolve_route`): 命中路由的 `upstream_model` 为 Some 时改写**立即生效** — in-flight model 被改写, 后续跳 router 按改写后的 model 匹配路由; 多跳重写后者覆盖前者; `ResolvedRoute.model_rewrite` = 最后一次命中的 route.upstream_model (全链未配置 = 透传客户端 model).

**路由错误语义** (全部 503, message 只含 provider id / model 名 + reason 枚举, SEC-2 同型): 无匹配路由 (NoMatch — 启用路由中无 model_pattern 匹配请求 model) / 链上目标缺失 (Missing, 含被 decision-disabled 排除) / 链上目标 entry-level disabled (Disabled) / 成环 (Cycle, `resolve_route` visited-set 运行时兜底, 有限步终止). 悬空 `target` 写入放行 (创建顺序无关), 运行时 503 兜底; upsert 侧环检查 (`would_cycle`) 的边集 = 所有**启用**路由的 `target` (禁用路由不构成边), 任一分支成环 → 400.

**Properties**:
- `prop_unknown_protocol_returns_404`: 未知 proto_short → 404 not_found. 🔁→`unknown_protocol_returns_404` (`tests/integration.rs`)
- `prop_unknown_provider_returns_404`: 未知 provider_id → 404 not_found. 🔁→`unknown_provider_returns_404` (`tests/integration.rs`)
- `prop_disabled_provider_returns_503`: provider.enabled=false → 503 unavailable. 🔁→`disabled_provider_returns_503` (`tests/integration.rs`)
- `prop_cross_proto_streaming_returns_501`: 跨协议 + stream=true → 501 (翻译未接入). 🔁→`cross_protocol_streaming_returns_501` (`tests/integration.rs`)
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

### FWD-6 Provider 鉴权注入

**陈述**: secret-guard 用 provider 配置的 api_key 覆盖客户端可能误传的 auth header, 注入对应协议的 auth header. 发往上游的请求**只含 ingress 协议对应的 auth header**, 其他协议的 auth header (`Authorization` / `x-api-key` / `x-goog-api-key` 三者中非 ingress 的两个) 必须剥离.

**Properties**:
- `prop_only_ingress_protocol_auth_header_sent`: 发往上游的请求只含 ingress 协议对应的 auth header, 非 ingress 协议的 auth header 被剥离 (避免客户端误传对手协议 header 干扰上游). 🔁→`apply_provider_auth_strips_competing_headers` (`src/proxy/auth.rs`)
- `prop_correct_auth_injected_per_protocol`: OpenAI/Ollama → `Authorization: Bearer`; Anthropic → `x-api-key`; Gemini → `x-goog-api-key`. 🔁→`provider_api_key_overrides_client_auth` (OpenAI Bearer) + `anthropic_provider_uses_x_api_key`; Gemini `x-goog-api-key` 注入无专项
- `prop_api_key_two_sources_resolved`: api_key 来自 `api_key` (直接值) 或 `api_key_file` (运行时读文件) 任一来源, 解析为同一 effective value. 🔁→`provider_api_key_file_reads_secret_from_path` + `provider_api_key_file_missing_falls_through_to_no_auth` + `put_static_fork_null_api_key_inherits_api_key_file`

---

## 2. RED: Redact / Restore

> 信任域 A. secret-guard 的核心安全功能. 来自原 C1-C7 契约.
> **独立形式化** (不因被 FWD-1 覆盖而省略, 见 §0.4 冗余覆盖原则).

### RED-1 mock 非空性

**陈述**: 每个 mock 必须非空, 且满足其 `GenSpec` 的 prefix/charset/length 约束.

**Properties**:
- `prop_mock_non_empty`: 对任意 (secret, strategy), 生成的 mock 非空. ✅
- `prop_mock_matches_gen_spec_charset`: mock 字符全部来自 gen_spec.charset ∪ gen_spec.prefix. ⏳
- `prop_mock_length_in_range`: mock 长度 ∈ gen_spec.length_range. ⏳

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

**陈述**: 一次 `redact_ir` 内不同 secret → 不同 mock. 极端弱配置下探测耗尽时的降级行为由 `[redact] on_probe_exhausted` 配置 (默认 `fail_open`):

- **fail_open (默认, 向后兼容)**: **跳过该 secret** (原样发往上游) 而非 panic, 优先保进程存活.
- **fail_closed**: **拒绝转发整个请求** (proxy 返回 503, body 的变量部分只含 secret id + reason 枚举, 不含 secret 明文), 防止 secret 泄露到 LLM provider.

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
- `prop_c5_auto_mode_deterministic`: Auto 模式下, 内部重试链 (C5_INTERNAL_RETRIES=10000) 使失败概率 ~(1e-5)^10000 ≈ 0, 实质等价于确定性契约. ⏳
- `prop_c5_fixed_mode_validated_on_upsert`: Fixed 模式 / 用户 prefix 在 `validate_against_real` (upsert 时) 校验, 不合格的 secret 拒绝入库. 🔁→`mock_strategy_validate_against_real_rejects_fixed_equals_real` 等 mock.rs validate 组 (upsert 链路经 `SecretEntry::validate_and_resolve` 调用)
- `prop_secret_with_mock_prefix_rejected`: secret value 含 `global_mock_prefix` 时被 `validate_value` 拒绝 (前缀非空时生效). 🔁→`validate_value_rejects_short_pua_and_mock_prefix` (`src/secrets.rs`) + `validate_value_rejects_mock_prefix` (`tests/integration.rs`)

### RED-6 可逆性 (round-trip identity, 非流式)

**陈述**: `restore_ir_response(redact_ir(req).0)` 后 IR 语义等价于原 IR. redact + restore 是可逆双射 (real ↔ mock 一一对应).

**Properties**:
- `prop_round_trip_identity_text`: text block 中 secret 的 round-trip identity. 🔁→`prop_round_trip_identity` (`src/redact.rs`, text 场景)
- `prop_round_trip_identity_tool_use_input`: tool_use input JSON 中 secret 的 round-trip identity. 🔁→`prop_response_tool_use_input_restored` (`src/redact.rs`)
- `prop_round_trip_identity_tool_result`: tool_result 嵌套 text 中 secret 的 round-trip identity. ⏳
- `prop_round_trip_identity_system`: system prompt 中 secret 的 round-trip identity. ⏳
- `prop_round_trip_identity_extra`: extra 字段 (未建模 JSON) 中 secret 的 round-trip identity. ⏳
- `prop_round_trip_identity_multi_secret`: 多 secret (1..10) 同时出现的 round-trip identity. 🔁→`prop_multi_secret_round_trip` + `prop_response_multi_secret_round_trip` (`src/redact.rs`)
- `prop_round_trip_identity_repeated_secret`: 同 secret 在多字段重复出现的 round-trip identity. 🔁→`prop_repeated_secret_round_trip` (`src/redact.rs`)

### RED-7 流式可逆性 (streaming restorability)

**陈述**: `StreamingRestorer` 在任意 chunk 切分下保证 `concat(push(c_1..n), flush().1)` 严格等于 `content.replace(mock, real)`. UTF-8 安全.

**Properties**:
- `prop_streaming_restorer_round_trip`: 对任意 chunk_size (1..N), round-trip identity 成立. ✅
- `prop_streaming_restorer_utf8_safe`: 多字节字符不在 char boundary 中间切的 round-trip identity. 🔁→`prop_streaming_restorer_round_trip_utf8` (`src/redact.rs`)
- `prop_streaming_restorer_multi_mock`: 多 mock 在同一段文本中的 round-trip identity. 🔁→`prop_streaming_restorer_round_trip_multi_mock` + `restorer_round_trip_on_multiple_mocks_in_one_chunk` (`src/redact.rs`)
- `prop_streaming_restorer_per_block_isolated`: 不同 block 的 restorer 状态独立 (block 间 mock 边界互不干扰). ⏳

---

## 3. STR: 流式 SSE

> 信任域 A. SSE/chunked 流式响应的边界处理与累积.

### STR-1 chunk 边界透明

**陈述**: StreamTranslate 必须正确处理 TCP 切片 — 一个 SSE 帧可能被切成多个 chunk, 一个 chunk 也可能含多帧. 客户端最终看到的帧序列与上游发出的帧序列语义等价.

**Properties**:
- `prop_arbitrary_chunk_split_equivalence`: 对任意 chunk 切分 (含 1-byte 切分), StreamScan 累积结果 == 整体一次性 feed 结果. ✅
- `prop_stream_translate_chunk_split_equivalence`: 对任意 chunk 切分, StreamTranslate 输出 == 整体一次性 feed 结果. ✅
- `prop_crlf_lf_both_accepted`: SSE 帧终止符 CRLF 和 LF 都被正确识别. 🔁→`find_terminator_crlf_crlf` + `translate_handles_crlf_sse_frames` (`src/codec/stream/mod.rs`)

### STR-2 StreamScan 累积正确

**陈述**: 流式 SSE 经 StreamScan 累积的 IrResponse 必须与非流式路径的 IrResponse 语义等价 (即: 流式累积是 resp_parsed 字段的真相来源).

**Properties**:
- `prop_stream_scan_equals_non_streaming_parse`: 对任意合法 SSE 流, StreamScan snapshot == reader.read_response(累积的完整 SSE 字节). ✅
- `prop_stream_scan_accumulates_text`: 文本 token 跨 chunk 累积正确. ✅
- `prop_stream_scan_accumulates_tool_use`: tool_use input JSON 部分片段跨 chunk 累积正确. ✅
- `prop_stream_scan_include_usage_chunk`: OpenAI include_usage chunk 正确更新 usage (terminal delta input_tokens=0 时 backfill). ✅
- `prop_stream_scan_ignores_post_stop_noise`: stop event 后的噪声 chunk 被忽略. ✅

### STR-3 流式错误降级 (best-effort, 不泄漏)

**陈述**: 上游流式响应出错 (non-2xx / 断连 / 超时) 时, secret-guard 必须保证 mock 字符串**不出现**在最终返回给客户端的响应 body 中.

> **理想 vs 现状**: 此契约是理想目标. 当前实现中 non-2xx SSE fallback 路径会原样返回上游字节 (含 mock), 是已知 gap.

**Properties**:
- `prop_non_2xx_sse_no_mock_to_client`: non-2xx SSE 响应的客户端可见 body 中不含任何 mock 字符串. ⏳
- `prop_upstream_disconnect_no_mock_leak`: 上游断连后, 客户端可见 body 中不含 mock. ⏳
- `prop_upstream_timeout_no_mock_leak`: 上游超时后, 客户端可见 body 中不含 mock. ⏳

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

**跨协议处置** (FWD-3 "范围外显式丢弃" 的新条目): ReasoningContent block 跨协议翻译时丢弃 — Anthropic thinking block 需要 signature (secret-guard 无法合法合成, 伪造会被 Anthropic API 拒收), Responses reasoning item 依赖 `encrypted_content` (provider-opaque). 不发明非法 wire 形态.

**Properties**:
- `prop_streaming_reasoning_restored_like_text`: 任意 chunk 切分下, 客户端 reasoning 拼接 == 上游拼接.replace(mock, real) + 无 mock 泄漏 + 思考期非零字节. ✅
- `prop_stream_scan_accumulates_reasoning`: StreamScan 把 reasoning delta 累积为 ReasoningContent block (与预期 IrResponse 一致). ✅
- `prop_stream_reader_reasoning_text_tool_indices_correct`: reasoning / text / tool 三类 block 的 IR index 互不冲突. ✅

**生成器覆盖** (§0.3 第 3 条): reasoning delta (含 mock, 跨 chunk 累积) 已加入 `arb_openai_sse_with_expected` (stream/mod.rs, has_reasoning 分支) 与 `arb_openai_sse_stream_with_mock` (fwd_streaming_property.rs); 非流式 `message.reasoning_content` / 请求侧 assistant 历史回传由 openai.rs 单测覆盖.

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
- `prop_prefix_hash_invariant_to_response`: 同一 req_delta + 不同 response → 同一 prefix_hash. ⏳
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

> **理想 vs 现状**: `NodeView::is_orphan` 未实现, 当前孤儿节点的 full_request_messages 返回 None.

**Properties**:
- `prop_orphan_node_identifiable`: parent 不存在的 node 被标记为 is_orphan. ⏳
- `prop_orphan_node_degrades_gracefully`: 孤儿节点的 timeline 查询返回降级视图 (而非 panic / 残缺数据). ⏳

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
- `prop_forward_record_no_internal_leak`: ForwardRecord 不暴露 DAG 内部类型 (BlockHash / MessageRef 等). ⏳

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
- `prop_preview_fallback_method_path`: 提取失败回退到 method + path. ⏳
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

> **理想 vs 现状**: 本 property 的完整"跨表"覆盖 (装配 SecretTable + ProviderTable 共享 persist_lock + Decisions + 同一 state_path) 尚未实现; 当前测试降级为单表 N 线程并发, 覆盖 "persist_lock 串行 RMW + 失败回滚" 核心不变量, 但未触及跨表 state.toml 文件交互 (一表 atomic_write 留下损坏文件会让另一表 load_or_empty 读到错误状态) 与共享 Decisions Arc 的跨表隔离. 跨表完整覆盖作为后续工作. 成功路径的"并发不丢更新"由 CFG-5 `prop_concurrent_upserts_no_lost_update` 覆盖.

### CFG-5 跨表并发安全

**陈述**: SecretTable 与 ProviderTable 共享 persist_lock (串行 RMW) 与 Decisions (同一份内存). 跨表并发写不丢更新.

**Properties**:
- `prop_concurrent_upserts_no_lost_update`: 单表 N 线程并发 upsert 不丢更新 (persist_lock 串行 RMW 基线). ✅
- `prop_concurrent_writes_serialized_via_persist_lock`: 跨表 (SecretTable + ProviderTable 共享 persist_lock + 同一 state_path + 同一 Decisions Arc, 与 server.rs 启动装配一致) 并发 upsert — 两表 effective 各含全部项 (跨表不丢更新) + 从磁盘 `load_or_empty` 重载得到的 DynamicState 同时含两表 dynamic 段 (persist_lock 串行 RMW, state.toml 不撕裂, 无跨表段覆盖). ✅
- `prop_cross_table_shared_decisions_isolation`: 共享 Decisions Arc 的跨表并发 `set_decision` (各改自己子表) 互不串扰 — secret id 的 decision 不误写到 providers 子表, 反之亦然; 合并后 state.toml 同时保留两子表 decision. ✅

> **覆盖现状**: CFG-5 的两个 property (`prop_concurrent_writes_serialized_via_persist_lock` + `prop_cross_table_shared_decisions_isolation`) 已实现跨表完整覆盖 — 装配方式与 `server.rs` 生产路径一致 (共享 `Arc<Mutex<()>>` persist_lock + 共享 `Arc<RwLock<Decisions>>` + 同一 state_path). 上方 CFG-4 "理想 vs 现状" 注记中提到的 "跨表 state.toml 文件交互" 与 "共享 Decisions Arc 的跨表隔离" 现由本节两个 property 覆盖; CFG-4 自身的跨表失败回滚 (`prop_persist_failure_rollback_under_concurrency`) 仍作为后续工作.

---

## 7. SEC: 安全姿态

> 跨域. secret-guard 的安全不变量, 任何路径不得违反.

### SEC-1 GET 永不返回真实敏感值

**陈述**: GET API 永不返回 secret 的 `value` / provider 的 `api_key` 真实值, 用 mask_value 占位.

**Properties**:
- `prop_get_secret_masks_value`: GET /secrets 返回的 value 字段是 mask (如 `sk-****`), 非真实值. 🔁→`mask_value_hides_full_content` (`src/secrets.rs`) + `secrets_api_create_lists_update_delete` 内嵌 value_masked 断言 (`tests/integration.rs`)
- `prop_get_provider_masks_api_key`: GET /providers 返回的 api_key 字段是 mask. 🔁→`effective_snapshot_includes_provenance_and_masks_api_key` (`src/provider.rs`) + `providers_api_lists_existing` 内嵌 api_key_masked 断言 (`tests/integration.rs`)
- `prop_no_real_secret_in_any_json_response`: 任意 GET 响应 (含 ForwardRecord / EffectiveSnapshot / SessionSummary 等) 不含真实 secret value. ⏳
- `prop_no_real_api_key_in_any_json_response`: 同上, 不含真实 api_key. ⏳

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

### SEC-4 headers 脱敏

**陈述**: 记录存储的 HTTP headers 中, auth/cookie 类敏感 header 必须脱敏为 `<redacted>`.

**Properties**:
- `prop_auth_headers_redacted_in_record`: Authorization / x-api-key / x-goog-api-key / cookie 类 header 在 record 中为 `<redacted>`. 🔁→`redact_headers_masks_secrets` (`src/proxy/helpers.rs`; authorization / x-api-key / x-goog-api-key)
- `prop_set_cookie_redacted`: 上游 Set-Cookie header 在 record 中脱敏. ⏳
- `prop_custom_token_headers_redacted`: 含 "token" / "secret" 关键词的自定义 header 也脱敏. ✅

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
- `prop_consistency_check_feature_runs_in_ci`: consistency-check feature flag 在 CI 中独立运行. 🔁→CI step `consistency-check feature guard` (`.forgejo/workflows/ci.yml`) + `just check-features`

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

### UI-1 气泡数 == IR messages 长度

**陈述**: 会话详情页 (timeline) 渲染的 Bubble 数量必须等于该 Node 对应 HTTP 请求的 IR messages 数组长度.

**Properties**:
- `prop_bubble_count_equals_ir_messages_length`: 对 N (≥1) 条 IR messages, timeline 渲染 N 个 Bubble. 🔁→`I1 守卫` (`tests/webui/im-ui.spec.ts`, 参数化 N=1/3/5)

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

## 99. 变更日志

记录契约的重大语义调整 (编号永不变更/重用, 仅作废).

| 日期 | 契约 ID | 调整 | 原因 |
|---|---|---|---|
| 2026-07-26 | (initial) | 建立本文档, 收纳 C1-C7 / INV-1..5 / I1-I3 为 RED-1..7 / CDAG-1..5 / UI-1..3 | QA 系统梳理, 边界契约先行 |
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
| 2026-08-23 | FWD-4 | 新增"响应头超时分档"段 + property `prop_header_timeout_matches_stream_semantics`: send().await 响应头超时按请求 stream 语义分两档 (显式 stream=true → TTFT 档 60s; 其余 → 整响应档 300s) | #175: 非流式大上下文请求 (响应头等整响应生成完) 被单一 60s TTFT 量纲超时结构性误杀 (hermes cron 9 连续 504 事故) |
| 2026-08-24 | FWD-5 | 新增虚拟 provider 路由 5 条 property: per-request 解析 (`prop_route_resolution_per_request`) / 坏路由 503 (`prop_route_broken_returns_503`) / 环终止 (`prop_route_cycle_termination`) / upsert 环拒绝 (`prop_route_cycle_rejected_at_upsert`) / upstream_id 可观测 (`prop_upstream_id_observable`) | #179: 虚拟 endpoint (route_to) — 客户端固定连虚拟端点, WebUI 即席切换上游; 语义裁决 (per-request / 悬空放行 / 三层环防护) 经人工授权 |
| 2026-08-24 | FWD-1 | **语义修订**: "对 wire 的唯一合法修改是 real↔mock 替换" → 扩为两种: real↔mock 替换 + **model 字段重写 (仅当生效 provider 配置 `model_override`)**; 请求半段等式追加条件项 `.replace(model, override)`; 新增 property `prop_request_half_byte_exact_with_model_override`. 代价明示: override 生效时同协议无-secret 请求从字节直传降级为 IR 改写 (normalize 等价, 前缀缓存失效 — 用户主动选择的降级). 配套 FWD-5 新增 `prop_model_override_*` 4 条 (first-wins 解析 / egress 注入 / 无 codec 降级) | #183: 虚拟 endpoint P2 — 跨模型名切换 (切换 = target+model 二元组); 修订经人工授权 (2026-08-24, issue #183 记录裁决与 D1-D5 设计决策) |
| 2026-08-25 | FWD-5 | **多规则路由 (router rules) 契约修订**: 虚拟 provider (单 `route_to` + provider 级 `model_override`) → Router 构造 (`rules` 规则列表: pattern 通配符 / route_to / 规则级 model / priority); 规则按**请求 model** 匹配 (per-request, body 收集后解析); model 重写改 **pipeline** 语义 (改写值参与下一跳匹配, 后者覆盖前者 — 作废 first-wins 的 `prop_model_override_first_hop_wins`, 新增 `prop_model_rewrite_pipeline_feeds_next_hop` + `prop_model_rewrite_later_overrides_earlier`); 错误清单新增 NoMatch (无匹配规则 → 503); 环检查边集 = 启用规则; 新增 property: 请求 model 提取 / 通配符语义 / priority 序 + 同值列表序 tie-break / 禁用规则跳过 / no-match 503. FWD-1 措辞同步: `model_override` → 规则级 `model` 重写 (`prop_request_half_byte_exact_with_model_override` 更名 `..._with_model_rewrite`) | 虚拟 provider 多规则化: model 通配符路由 + 规则级 model 改写 (pipeline) + 删除 model_override 配置字段 |
