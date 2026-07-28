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
| `FWD-*` | 转发忠实性 (域 A) | codec INV-1/2/5 → FWD-1/2/5; proxy DoD → FWD-4/6 | `src/proxy.rs` 头部 + `src/codec/AGENTS.md` |
| `RED-*` | Redact/Restore (域 A) | C1→RED-1, C2→RED-2, C3→RED-3, C4→RED-4, C5→RED-5, C6→RED-6, C7→RED-7 | `src/redact.rs` + `src/mock.rs` 头部 |
| `STR-*` | 流式 SSE (域 A) | codec INV-4 → STR-4 | `src/codec/stream.rs` + `src/codec/AGENTS.md` |
| `CDAG-*` | Conversation DAG (域 B) | INV-1→CDAG-1, INV-2→CDAG-2, INV-3→CDAG-3, INV-4→CDAG-4, INV-5→CDAG-5 | `src/dag.rs` 头部 + `docs/design/conversation-dag.md` |
| `DTO-*` | WebUI DTO 派生 (域 B) | (新增) | `src/web/AGENTS.md` + `src/record.rs` 头部 |
| `CFG-*` | 双层配置 (域 B) | (新增) | `src/config.rs` 头部 |
| `SEC-*` | 安全姿态 (跨域) | (新增) | `src/web/AGENTS.md` + `src/secrets.rs` + `src/provider.rs` |
| `ROB-*` | 鲁棒性 (跨域) | (新增) | 根 `AGENTS.md` "鲁棒性原则" |
| `VIEW-*` | 视图正确性机制 (跨域) | (新增) | 根 `AGENTS.md` "视图正确性确保机制" |
| `UI-*` | WebUI 渲染 (域 C) | I1→UI-1, I2→UI-2, I3→UI-3 | 根 `AGENTS.md` "前端不变量" |

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

---

## 1. FWD: 转发忠实性 (Forwarding Fidelity)

> 信任域 A. 适用于 client ↔ upstream 的完整字节流路径.

### FWD-1 透明中继 byte-exact (半段式, normalize 后)

**陈述**: secret-guard 是客户端与上游之间的字节级透明中继. **两个半段各自满足 byte-exact**:

- **请求半段** (client → upstream): 客户端发送的请求 wire 经 secret-guard redact 后发往上游, 要求
  `normalize(发往上游的 wire) == normalize(客户端请求 wire).replace(real, mock)`.
- **响应半段** (upstream → client): secret-guard 收到上游响应 wire 后经 restore 返回客户端, 要求
  `normalize(返回客户端的 wire) == normalize(上游响应 wire).replace(mock, real)`.

等价表述: **secret-guard 对 wire 的唯一合法修改是 real↔mock 替换**, 除此之外的任何字节差异 (字段丢失 / 顺序错乱 / 重序列化改变 / 任意字段值变化) 都是 bug.

`normalize` = canonical JSON (BTreeMap key 排序 + 紧凑序列化 + 无空白). 消除对语义无影响的字节差异, 剩下的差异全部是真正的信息差异.

**适用范围**: 同协议路径. 非流式 wire JSON + 流式 SSE wire.

**不适用**: 跨协议路径 (ingress wire 与 egress wire 是不同协议格式, 由 FWD-3 单独约束).

**Properties**:
- `prop_request_half_byte_exact` (非流式, 请求侧): 对任意合法请求 wire 含 real secret, `normalize(secret-guard 发往上游的 wire) == normalize(原始 wire).replace(real, mock)`.
- `prop_response_half_byte_exact` (非流式, 响应侧): 对任意合法响应 wire 含 mock, `normalize(secret-guard 返回客户端的 wire) == normalize(上游 wire).replace(mock, real)`.
- `prop_streaming_response_half_byte_exact` (流式, 响应侧): 流式响应的 restore, 经任意 chunk 切分, 同上.

> **理想 vs 现状**: `prop_streaming_response_half_byte_exact` 的字面形式 (byte-exact) 在
> `StreamTranslate::new_same_proto_restore` 路径下**不成立** — 该路径显式放弃 byte-exact 走
> IR re-serialize (见 `src/codec/stream.rs` 头部注释 "失去 byte-exact, 但语义等价"). 已知结构
> 差异 (除 mock→real 替换外): ① id/created 重新生成 (writer 合成); ② chunk 重组 (StreamingRestorer
> sliding window 在 mock 边界拆/并 chunk); ③ usage input_tokens backfill (terminal delta 填回
> MessageStart 锁定值); ④ 元数据字段去重 (OpenAI writer 仅 MessageStart chunk 输出 id/created/model).
> 当前 property (`fwd_streaming_property.rs`) 守卫**语义等价弱化形式**: no mock leak + content
> fidelity + tool input fidelity + usage output fidelity. 完整 byte-exact 需重新设计
> same_proto_restore 为字节级扫描替换 (避免 IR re-serialize), 作为独立架构改动.
- `prop_proptest_generator_covers_edge_cases`: wire 生成器必须覆盖:
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
- `prop_codec_round_trip_byte_exact_after_normalize` (非流式): `normalize(Writer(Reader(Writer(ir)))) == normalize(Writer(ir))`.
- `prop_codec_stream_round_trip_byte_exact_after_normalize` (流式): 流式 reader → writer → 字节 → reader → writer → 字节, 两次最终字节 normalize 后 byte-exact.
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
- `prop_cross_proto_modeled_fields_preserved`: 建模范围内的字段 (messages/tools/tool_use/tool_result/usage 总数/stop_reason) 跨协议 round-trip 后保留.
- `prop_cross_proto_unmodeled_fields_explicitly_dropped`: 范围外字段 (如 reasoning_content) 不出现在 egress wire.
- `prop_cross_proto_extra_cleared`: 跨协议路径下 ingress IR 的 extra 字段必须清空, 不允许源协议独有字段泄漏到 egress.
- `prop_documented_semantic_loss_list`: 所有已知的语义损失点必须在 `src/codec/AGENTS.md` 显式列出 (人工审查项).

### FWD-4 HTTP 语义透传 + 客户端响应与 record 累积分离

**陈述**: 除 hop-by-hop header 外, HTTP 语义 (method / status / headers / stream 模式) 透传. **客户端响应路径与 record 累积路径是两条独立路径**: 客户端响应永远流式透传无大小上限, record 累积受 `MAX_RESP_BODY_RECORD` (32 MiB) 上限保护.

**Properties**:
- `prop_status_code_preserved`: 上游响应 status code 透传给客户端 (任意 status, 含错误码).
- `prop_headers_preserved_except_hop_by_hop`: 上游响应 header 透传, 除 RFC 7230 §6.1 定义的 hop-by-hop header 外不丢失.
- `prop_stream_mode_preserved`: 上游若返回 SSE/chunked, 客户端也以流式收到 (非 buffered).
- `prop_client_response_not_capped_even_when_record_truncated`: 即使 record 累积超过 MAX_RESP_BODY_RECORD 被截断 (写入 TRUNCATED_BANNER), 客户端响应仍收到完整上游字节. 此契约禁止有人把 MAX_RESP_BODY_RECORD 改成"客户端响应上限" (会静默截断用户响应).

### FWD-5 路由分发契约

**陈述**: URL = `/{proto_short}/{provider_id}/*path`. 未知 protocol / 未知 provider / 禁用 provider / 不支持的协议组合 必须返回明确错误码.

**Properties**:
- `prop_unknown_protocol_returns_404`: 未知 proto_short → 404 not_found.
- `prop_unknown_provider_returns_404`: 未知 provider_id → 404 not_found.
- `prop_disabled_provider_returns_503`: provider.enabled=false → 503 unavailable.
- `prop_cross_proto_streaming_returns_501`: 跨协议 + stream=true → 501 (翻译未接入).
- `prop_unsupported_codec_returns_501`: Gemini/Ollama 跨协议 → 501 (codec 未覆盖).
- `prop_internal_url_not_forwarded`: `/__sg/*` 未匹配子路径 → 404, 绝不进入 forward (防止内部 URL 泄漏到上游).

### FWD-6 Provider 鉴权注入

**陈述**: secret-guard 用 provider 配置的 api_key 覆盖客户端可能误传的 auth header, 注入对应协议的 auth header. 发往上游的请求**只含 ingress 协议对应的 auth header**, 其他协议的 auth header (`Authorization` / `x-api-key` / `x-goog-api-key` 三者中非 ingress 的两个) 必须剥离.

**Properties**:
- `prop_only_ingress_protocol_auth_header_sent`: 发往上游的请求只含 ingress 协议对应的 auth header, 非 ingress 协议的 auth header 被剥离 (避免客户端误传对手协议 header 干扰上游).
- `prop_correct_auth_injected_per_protocol`: OpenAI/Ollama → `Authorization: Bearer`; Anthropic → `x-api-key`; Gemini → `x-goog-api-key`.
- `prop_api_key_two_sources_resolved`: api_key 来自 `api_key` (直接值) 或 `api_key_file` (运行时读文件) 任一来源, 解析为同一 effective value.

---

## 2. RED: Redact / Restore

> 信任域 A. secret-guard 的核心安全功能. 来自原 C1-C7 契约.
> **独立形式化** (不因被 FWD-1 覆盖而省略, 见 §0.4 冗余覆盖原则).

### RED-1 mock 非空性

**陈述**: 每个 mock 必须非空, 且满足其 `GenSpec` 的 prefix/charset/length 约束.

**Properties**:
- `prop_mock_non_empty`: 对任意 (secret, strategy), 生成的 mock 非空.
- `prop_mock_matches_gen_spec_charset`: mock 字符全部来自 gen_spec.charset ∪ gen_spec.prefix.
- `prop_mock_length_in_range`: mock 长度 ∈ gen_spec.length_range.

### RED-2 上下文唯一性 (in-context uniqueness)

**陈述**: 一次 `redact_ir` 调用内, 每个 mock 必须不出现在 pre-replace IR 中 (traverse IR 检查), 也不出现在已分配 mock 集合中.

**Properties**:
- `prop_mock_not_in_pre_redact_ir`: 对任意 (ir, secret), gen 出的 mock 不在 ir 的任何字符串叶子中.
- `prop_mock_not_in_allocated`: 一次 redact_ir 调用内, 不同 secret 得到不同 mock.

### RED-3 前缀缓存友好性 (确定性)

**陈述**: redact 不应无必要改变 request body 字节. 同一 (policy, OriginRecord, seed) 三元组 → 同一 RedactionMap.

**Properties**:
- `prop_redact_ir_idempotent`: 对同一 (IrRequest, SecretTable, init_seed), 两次 `redact_ir` 产出语义相等的 RedactionMap.
- `prop_same_policy_same_messages_same_mock`: 在多轮对话中, 同一 secret 在同一上下文下得到同一 mock (mock 在会话全程稳定).
- `prop_policy_change_invalidates_all_mocks`: policy 变动 (添加/删除/编辑任一 secret) 改变 init_seed → 所有 mock 变化 (此为 per-request seed 模型的已知代价).

### RED-4 单射性 + 降级跳过

**陈述**: 一次 `redact_ir` 内不同 secret → 不同 mock. 极端弱配置下探测耗尽时**跳过该 secret** (原样发往上游) 而非 panic.

**Properties**:
- `prop_distinct_secrets_distinct_mocks`: 对 N 个不同 secret, 得到 N 个不同 mock.
- `prop_probing_exhausted_skips_not_panics`: 弱配置 (charset=1 char, length=1) 耗尽候选时, 跳过该 secret, 进程存活.
- `prop_redact_error_never_carries_secret_value`: RedactError 只携带 secret_id + reason, 不含 secret 明文.

### RED-5 mock 不含 real_secret 子串 (实质确定性)

**陈述**: mock 不含 real_secret 的 ≥ `k(L)=max(4, ⌈L/3⌉)` 字符连续子串. 阈值随 secret 长度 L 自适应 (短 secret 强保护, 长 secret 弱保护, 信息泄露率上界 ~36%).

**Properties**:
- `prop_no_real_substring_ascii`: 对任意 ASCII secret, mock 不含其 ≥ k(L) 子串.
- `prop_no_real_substring_multibyte`: 对任意 UTF-8 secret (中文/emoji), 同上, char-level 而非 byte-level.
- `prop_c5_auto_mode_deterministic`: Auto 模式下, 内部重试链 (C5_INTERNAL_RETRIES=10000) 使失败概率 ~(1e-5)^10000 ≈ 0, 实质等价于确定性契约.
- `prop_c5_fixed_mode_validated_on_upsert`: Fixed 模式 / 用户 prefix 在 `validate_against_real` (upsert 时) 校验, 不合格的 secret 拒绝入库.
- `prop_secret_with_mock_prefix_rejected`: secret value 含 `global_mock_prefix` 时被 `validate_value` 拒绝 (前缀非空时生效).

### RED-6 可逆性 (round-trip identity, 非流式)

**陈述**: `restore_ir_response(redact_ir(req).0)` 后 IR 语义等价于原 IR. redact + restore 是可逆双射 (real ↔ mock 一一对应).

**Properties**:
- `prop_round_trip_identity_text`: text block 中 secret 的 round-trip identity.
- `prop_round_trip_identity_tool_use_input`: tool_use input JSON 中 secret 的 round-trip identity.
- `prop_round_trip_identity_tool_result`: tool_result 嵌套 text 中 secret 的 round-trip identity.
- `prop_round_trip_identity_system`: system prompt 中 secret 的 round-trip identity.
- `prop_round_trip_identity_extra`: extra 字段 (未建模 JSON) 中 secret 的 round-trip identity.
- `prop_round_trip_identity_multi_secret`: 多 secret (1..10) 同时出现的 round-trip identity.
- `prop_round_trip_identity_repeated_secret`: 同 secret 在多字段重复出现的 round-trip identity.

### RED-7 流式可逆性 (streaming restorability)

**陈述**: `StreamingRestorer` 在任意 chunk 切分下保证 `concat(push(c_1..n), flush().1)` 严格等于 `content.replace(mock, real)`. UTF-8 安全.

**Properties**:
- `prop_streaming_restorer_round_trip`: 对任意 chunk_size (1..N), round-trip identity 成立.
- `prop_streaming_restorer_utf8_safe`: 多字节字符不在 char boundary 中间切的 round-trip identity.
- `prop_streaming_restorer_multi_mock`: 多 mock 在同一段文本中的 round-trip identity.
- `prop_streaming_restorer_per_block_isolated`: 不同 block 的 restorer 状态独立 (block 间 mock 边界互不干扰).

---

## 3. STR: 流式 SSE

> 信任域 A. SSE/chunked 流式响应的边界处理与累积.

### STR-1 chunk 边界透明

**陈述**: StreamTranslate 必须正确处理 TCP 切片 — 一个 SSE 帧可能被切成多个 chunk, 一个 chunk 也可能含多帧. 客户端最终看到的帧序列与上游发出的帧序列语义等价.

**Properties**:
- `prop_arbitrary_chunk_split_equivalence`: 对任意 chunk 切分 (含 1-byte 切分), StreamScan 累积结果 == 整体一次性 feed 结果.
- `prop_stream_translate_chunk_split_equivalence`: 对任意 chunk 切分, StreamTranslate 输出 == 整体一次性 feed 结果.
- `prop_crlf_lf_both_accepted`: SSE 帧终止符 CRLF 和 LF 都被正确识别.

### STR-2 StreamScan 累积正确

**陈述**: 流式 SSE 经 StreamScan 累积的 IrResponse 必须与非流式路径的 IrResponse 语义等价 (即: 流式累积是 resp_parsed 字段的真相来源).

**Properties**:
- `prop_stream_scan_equals_non_streaming_parse`: 对任意合法 SSE 流, StreamScan snapshot == reader.read_response(累积的完整 SSE 字节).
- `prop_stream_scan_accumulates_text`: 文本 token 跨 chunk 累积正确.
- `prop_stream_scan_accumulates_tool_use`: tool_use input JSON 部分片段跨 chunk 累积正确.
- `prop_stream_scan_include_usage_chunk`: OpenAI include_usage chunk 正确更新 usage (terminal delta input_tokens=0 时 backfill).
- `prop_stream_scan_ignores_post_stop_noise`: stop event 后的噪声 chunk 被忽略.

### STR-3 流式错误降级 (best-effort, 不泄漏)

**陈述**: 上游流式响应出错 (non-2xx / 断连 / 超时) 时, secret-guard 必须保证 mock 字符串**不出现**在最终返回给客户端的响应 body 中.

> **理想 vs 现状**: 此契约是理想目标. 当前实现中 non-2xx SSE fallback 路径会原样返回上游字节 (含 mock), 是已知 gap.

**Properties**:
- `prop_non_2xx_sse_no_mock_to_client`: non-2xx SSE 响应的客户端可见 body 中不含任何 mock 字符串.
- `prop_upstream_disconnect_no_mock_leak`: 上游断连后, 客户端可见 body 中不含 mock.
- `prop_upstream_timeout_no_mock_leak`: 上游超时后, 客户端可见 body 中不含 mock.

### STR-4 缓冲溢出 abort

**陈述**: reassembly 缓冲超过 MAX_BUF (16 MiB) 时, StreamTranslate 必须 abort 而非 OOM.

**Properties**:
- `prop_max_buf_overflow_aborts`: 上游发送无终止符字节流超过 MAX_BUF 时, StreamTranslate abort, 进程存活.

### STR-5 流式 reader 多 tool_call 索引分配

**陈述**: OpenAI 流式响应中多个并行 tool_call 必须被 reader 分配独立的 IR block index (用于后续 writer 透传到 wire 的 `tool_calls[].index`, 保证客户端按 index 聚合时不合并).

**Properties**:
- `prop_stream_reader_assigns_distinct_block_index`: 流式响应中 N (≥2) 个并行 tool_call 经 reader 解析后, 每个 tool_call 在 IR 中有独立的 block index.
- `prop_stream_reader_mixed_text_and_tool_call_indices_correct`: 文本 + 多 tool_call 混合流的 block index 不冲突.

> **历史 bug**: 9712c52. 注意此契约只覆盖 reader 侧. writer 侧"把 IR block index 透传到 wire `tool_calls[].index`"由 FWD-1/FWD-2 的 byte-exact property 守卫.

---

## 4. CDAG: Conversation DAG

> 信任域 B. 内容寻址的对话历史存储. 来自原 DAG INV-1..5.

### CDAG-1 req_delta 与 response 独立存储

**陈述**: 一个 Node 的 request 增量 (req_delta) 与 response 必须独立存储, 不捏造等式. response 完成与否不影响 req_delta 的可用性.

**Properties**:
- `prop_node_has_req_delta_even_without_response`: 即使 response 未完成 / 失败, req_delta 仍可查询.
- `prop_response_attached_independently`: attach_response 不修改 req_delta.

### CDAG-2 Merkle prefix hash 只基于 req_delta

**陈述**: Node 的 own_hash 与 prefix_hash 只从 req_delta (MessageRef 序列) 计算, response 不参与 parent 查找.

**Properties**:
- `prop_prefix_hash_invariant_to_response`: 同一 req_delta + 不同 response → 同一 prefix_hash.
- `prop_parent_found_by_prefix_hash`: push 时 Merkle prefix hash 找 parent 正确 (线性链 / 多跳链 / fork).

### CDAG-3 Block refcount 一致

**陈述**: BlockPool 的引用计数在 intern 时 ++, 淘汰时按 req_delta + response message 分别递减. 任何时刻 refcount ≥ 0.

**Properties**:
- `prop_refcount_positive_after_push_sequence`: 任意 push 序列后, 所有 block refcount ≥ 0.
- `prop_refcount_zero_blocks_reclaimed`: refcount=0 的 block 被回收.

### CDAG-4 req_delta 不可变

**陈述**: Node 的 req_delta 入 DAG 后永不修改 (类型系统强制 `Arc<[MessageRef]>`).

**Properties**:
- `prop_req_delta_immutable_after_push`: push 后任意时刻查询 req_delta, 内容恒等于 push 时的内容.

### CDAG-5 redact_seed 可重现

**陈述**: 给定 (req_delta, policy, seed) 三元组, RedactionMap 完全确定. seed=0 表示 passthrough (无 redact).

**Properties**:
- `prop_redact_map_reproducible_from_seed`: 给定三元组, derive_redact_map 产出同一 RedactionMap.

### CDAG-6 hash collision 处置

**陈述**: BlockPool hash collision (概率 ~2^-64) 必须被检测且不静默覆盖. 检测方式可以是 panic (debug) / log+skip (release) / runtime Result, 但**绝不能**静默覆盖导致数据损坏.

> **实现**: `BlockPool::intern` 用 `assert!` (非 `debug_assert!`) 比对 hash 命中时的 block 内容, 不一致即 panic. 选择 panic 而非 log+skip: collision 属哈希函数 bug, 一旦真发生宁可暴露也不要静默继续 (静默会让两个不同 block 共享 hash, 引发难定位的数据损坏).

**Properties**:
- `prop_collision_detected_in_release`: release build 下 hash collision 也被检测 (不静默覆盖). ✅ `assert!` 在 release 也运行.

### CDAG-7 孤儿节点可识别

**陈述**: 当 parent 被 LRU 淘汰后, child 节点必须能被识别为孤儿 (is_orphan), WebUI 据此降级展示而非显示残缺数据.

> **理想 vs 现状**: `NodeView::is_orphan` 未实现, 当前孤儿节点的 full_request_messages 返回 None.

**Properties**:
- `prop_orphan_node_identifiable`: parent 不存在的 node 被标记为 is_orphan.
- `prop_orphan_node_degrades_gracefully`: 孤儿节点的 timeline 查询返回降级视图 (而非 panic / 残缺数据).

### CDAG-8 session 聚类稳定

**陈述**: Session id 由根 node 的 prefix_hash 决定 (稳定标识). 同一会话的 N 轮请求, 其 leaf node 前移时 session id 不变.

**Properties**:
- `prop_session_id_stable_across_rounds`: 同一会话 N (≥3) 轮 push 后, session id 恒等于根 node 决定的 id.
- `prop_session_fork_creates_new_session`: fork (前缀相同但后续不同) 创建新 session.

---

## 5. DTO: WebUI DTO 派生

> 信任域 B. proxy → DAG → webapi 派生字段的正确性.

### DTO-1 ForwardRecord JSON shape 稳定

**陈述**: ForwardRecord 的 JSON shape 必须稳定, 不随 DAG 内部结构变化漂移.

**Properties**:
- `prop_forward_record_json_shape_backward_compat`: 旧版序列化数据 (无 resp_parsed / redactions 字段) 仍能反序列化为合法 ForwardRecord.
- `prop_forward_record_no_internal_leak`: ForwardRecord 不暴露 DAG 内部类型 (BlockHash / MessageRef 等).

### DTO-2 redactions 字段 SSOT 派生

**陈述**: `redactions: Vec<(mock, secret_id)>` 必须从 RedactionMap SSOT 派生, 永不在前端 / API 层重新计算.

**Properties**:
- `prop_redactions_match_redaction_map`: redactions 字段的内容与 RedactionMap 一一对应 (consistency-check feature flag 守卫).
- `prop_redactions_no_real_secret_value`: redactions 字段不含真实 secret value, 仅 (mock, secret_id) tuple.

### DTO-3 resp_parsed 从 StreamScan 派生

**陈述**: 流式响应的 `resp_parsed` 必须从 StreamScan 累积派生. 非流式响应从 reader.read_response(raw_body) 计算.

**Properties**:
- `prop_streaming_resp_parsed_equals_stream_scan_snapshot`: 流式 resp_parsed == StreamScan snapshot.
- `prop_non_streaming_resp_parsed_equals_reader_parse`: 非流式 resp_parsed == reader.read_response(raw_resp_body).
- `prop_resp_parsed_consistency_check`: resp_parsed 字段必须能通过 consistency-check 断言 (与原始数据视图一致).

### DTO-4 preview 提取 best-effort

**陈述**: `preview` 字段从 req_body 提取 (sidebar 主标题). 必须满足 best-effort 永不 panic, 假设不成立时降级.

**Properties**:
- `prop_preview_extracts_last_user_message`: 优先取最后一条 user message (前 48 chars).
- `prop_preview_fallback_when_no_user`: 无 user 时回退到最后一条有文本的 message.
- `prop_preview_fallback_compression_marker`: 压缩 marker ("What did we do so far?") 命中时回退到最后一条 assistant 摘要.
- `prop_preview_fallback_method_path`: 提取失败回退到 method + path.
- `prop_preview_push_time_snapshot_matches_reextract`: push 时存的 preview 与之后从 req_body_raw 重新提取的结果一致 (consistency-check 守卫).

### DTO-5 req_delta_messages 切片正确

**陈述**: timeline 路径的 `req_delta_messages` 必须是本轮新增的 messages (从 req_body_raw 末尾截取), 同协议路径下与 IR req_delta 一致.

**Properties**:
- `prop_delta_slice_correct_same_proto`: 同协议路径下, req_delta_messages 与 IR req_delta (resolve + ingress writer 重序列化) 一致.
- `prop_delta_includes_system_at_root`: 根节点 (start > 0) 的 delta 补回 system prompt.
- `prop_delta_handles_non_json_body`: 非 JSON body 时返回空 vec (不 panic).
- `prop_delta_handles_count_mismatch`: messages 数 < req_delta_count 时返回空 vec.

### DTO-6 跨协议 delta 切片行为定义

**陈述**: 跨协议路径下, OpenAI writer 把 Anthropic 风格的混合 Text+ToolResult user 消息拆成 (1+N) 条 wire messages, 导致 req_body_raw messages 数 > IR messages 数. 此场景下 delta 切片的**期望行为**必须被定义 (而非静默错位).

> **理想 vs 现状**: 当前实现 delta 可能包含前序轮消息 (静默错位), 是已知 gap. 理想目标是从 IR req_delta resolve + ingress writer 重序列化.

**Properties**:
- `prop_cross_proto_delta_no_silent_misalignment`: 跨协议路径下 delta 切片要么正确, 要么显式标记降级 (不静默错位).

### DTO-7 session title 取根 node

**陈述**: session title 必须取会话根 node (最早 round) 的首条 user msg preview. 多轮对话中 title 不随每轮新问题漂移.

**Properties**:
- `prop_session_title_from_root_node`: session.title == 根 node 的首条 user msg preview.
- `prop_session_title_stable_across_rounds`: 同一 session N (≥3) 轮 push 后 title 不变.

### DTO-8 RecordSummary 轻量化

**陈述**: `GET /records` 列表返回的 RecordSummary 不含 body 字段 (req_body / resp_body / resp_parsed), 由详情接口按需拉取.

**Properties**:
- `prop_record_summary_excludes_body`: RecordSummary JSON 不含 req_body / resp_body / resp_parsed 字段.

---

## 6. CFG: 双层配置

> 信任域 B. static + dynamic 双层配置的合并 / CRUD / 持久化正确性.

### CFG-1 OverrideMode 合并语义

**陈述**: 对每个 id, 实际生效值由 OverrideMode 决定:
- `Default`: dynamic 优先于 static.
- `PreferStatic`: 强制 static, 忽略 dynamic.
- `Disabled`: 从 effective view 完全排除.

**Properties**:
- `prop_default_dynamic_wins`: Default 模式下, static + dynamic 都有同 id → 用 dynamic.
- `prop_default_static_fallback`: Default 模式下, 仅 static 有 → 用 static.
- `prop_prefer_static_ignores_dynamic`: PreferStatic 模式下, 用 static 原值.
- `prop_disabled_excluded`: Disabled 模式下, id 不出现在 effective view.

### CFG-2 Effective source 4 种标签正确

**陈述**: 每个 effective item 的 source 标签必须正确反映其来源:
- `static`: 仅 static 有此 id.
- `dynamic`: 仅 dynamic 有此 id.
- `dynamic_override`: static + dynamic 都有, decision=Default → 用 dynamic.
- `static_preferred`: static + dynamic 都有, decision=PreferStatic → 用 static.

**Properties**:
- `prop_source_label_matches_actual_origin`: source 标签 == 实际生效值的来源.
- `prop_runtime_assert_effective_value_matches_source`: 在 consistency-check 模式下, 断言 effective_view[i].value == 对应来源的 value.

### CFG-3 CRUD 操作语义

**陈述**:
- POST 创建 dynamic-only item, id 与 static 冲突 → 409.
- PUT 编辑: id 在 static 中 → 自动 fork dynamic override (git-style).
- DELETE 仅作用于 dynamic.
- PATCH `/{id}/decision` 切换对 static id 的决策.

**Properties**:
- `prop_post_conflict_with_static_returns_409`: POST 创建与 static 冲突的 id → 409.
- `prop_put_forks_dynamic_when_id_in_static`: PUT 编辑 static id → 创建 dynamic override.
- `prop_delete_dynamic_only_succeeds`: DELETE 仅作用于 dynamic, static id → 409.
- `prop_patch_decision_toggles_override_mode`: PATCH decision 正确切换 OverrideMode.

### CFG-4 持久化原子性

**陈述**: 先写 state.toml (atomic write + fsync), 再更新内存. 写失败时内存回滚.

**Properties**:
- `prop_persist_failure_rolls_back_memory`: state.toml 写失败时, 内存层不留下半提交状态.
- `prop_atomic_write_no_corrupt_file`: atomic_write 用 tmp + rename, 中途崩溃不留下损坏的 state.toml.
- `prop_persist_failure_rollback_under_concurrency`: 跨表并发写时, 一表 persist 失败回滚不影响另一表 in-flight 写入.

> **理想 vs 现状**: 本 property 的完整"跨表"覆盖 (装配 SecretTable + ProviderTable 共享 persist_lock + Decisions + 同一 state_path) 尚未实现; 当前测试降级为单表 N 线程并发, 覆盖 "persist_lock 串行 RMW + 失败回滚" 核心不变量, 但未触及跨表 state.toml 文件交互 (一表 atomic_write 留下损坏文件会让另一表 load_or_empty 读到错误状态) 与共享 Decisions Arc 的跨表隔离. 跨表完整覆盖作为后续工作. 成功路径的"并发不丢更新"由 CFG-5 `prop_concurrent_upserts_no_lost_update` 覆盖.

### CFG-5 跨表并发安全

**陈述**: SecretTable 与 ProviderTable 共享 persist_lock (串行 RMW) 与 Decisions (同一份内存). 跨表并发写不丢更新.

**Properties**:
- `prop_concurrent_upserts_no_lost_update`: 跨表并发 upsert 不丢更新.
- `prop_concurrent_writes_serialized_via_persist_lock`: persist_lock 串行所有 RMW, state.toml 不出现撕裂.

---

## 7. SEC: 安全姿态

> 跨域. secret-guard 的安全不变量, 任何路径不得违反.

### SEC-1 GET 永不返回真实敏感值

**陈述**: GET API 永不返回 secret 的 `value` / provider 的 `api_key` 真实值, 用 mask_value 占位.

**Properties**:
- `prop_get_secret_masks_value`: GET /secrets 返回的 value 字段是 mask (如 `sk-****`), 非真实值.
- `prop_get_provider_masks_api_key`: GET /providers 返回的 api_key 字段是 mask.
- `prop_no_real_secret_in_any_json_response`: 任意 GET 响应 (含 ForwardRecord / EffectiveSnapshot / SessionSummary 等) 不含真实 secret value.
- `prop_no_real_api_key_in_any_json_response`: 同上, 不含真实 api_key.

### SEC-2 RedactError 不携带 secret 明文

**陈述**: RedactError 只携带 secret_id + reason, 类型系统级保证不含 secret value.

**Properties**:
- `prop_redact_error_struct_has_no_value_field`: RedactError struct 字段集合不含 value.
- `prop_redact_error_debug_no_secret_leak`: RedactError 的 Debug 输出不含 secret 明文.

### SEC-3 assert/panic/log 不泄漏 secret

**陈述**: 任何 assert / panic / log 消息不得包含 secret 明文.

**Properties**:
- `prop_assert_messages_no_secret`: assert/panic 消息中不含 secret.value (即使用于诊断).
- `prop_log_messages_no_secret`: tracing log 不输出 secret.value.

### SEC-4 headers 脱敏

**陈述**: 记录存储的 HTTP headers 中, auth/cookie 类敏感 header 必须脱敏为 `<redacted>`.

**Properties**:
- `prop_auth_headers_redacted_in_record`: Authorization / x-api-key / x-goog-api-key / cookie 类 header 在 record 中为 `<redacted>`.
- `prop_set_cookie_redacted`: 上游 Set-Cookie header 在 record 中脱敏.
- `prop_custom_token_headers_redacted`: 含 "token" / "secret" 关键词的自定义 header 也脱敏.

  注: "key" 关键词过于宽泛 (会误伤 `x-request-key-hash` 等正常 header), 故不纳入关键词匹配; 已知 key 类 header (如 `x-api-key` / `x-goog-api-key` / `api-key` / `x-anthropic-api-key`) 由 `prop_auth_headers_redacted_in_record` 的显式黑名单覆盖.

### SEC-5 PolicySnapshot 不进 WebUI DTO

**陈述**: DAG Node 持有的 PolicySnapshot (含 secret value) 仅后端用, 永不序列化进 WebUI DTO.

**Properties**:
- `prop_policy_snapshot_not_in_forward_record`: ForwardRecord JSON 不含 PolicySnapshot 字段.
- `prop_policy_snapshot_not_in_session_summary`: SessionSummary JSON 不含 PolicySnapshot.

### SEC-6 本地监听 + 内部 URL 不外泄

**陈述**: 默认监听 127.0.0.1. `/__sg/*` 未匹配子路径返回 404, 绝不进入 forward.

**Properties**:
- `prop_default_host_localhost`: 默认 host=127.0.0.1.
- `prop_internal_url_404_no_forward`: `/__sg/unknown` → 404, 不发送到上游.

---

## 8. ROB: 鲁棒性 (best-effort 永不 panic)

> 跨域. 对"尝试性解析"功能的鲁棒性要求.

### ROB-1 解析路径永不 panic

**陈述**: 对 preview / delta / tool_name 等尝试性解析, 缺字段 / 类型不符 / 空数组 / 越界 都返回 None 或空, 由调用方走 fallback.

**Properties**:
- `prop_preview_never_panics`: extract_preview_and_model 对任意字节输入 (含非 JSON / 空 / 损坏) 不 panic.
- `prop_delta_never_panics`: extract_delta_messages_from_raw 同上.
- `prop_tool_name_never_panics`: toolNameOfRound 对任意输入返回合法字符串 (含 '?').

> **理想 vs 现状**: tool name 推断由后端 `extract_preview_and_model` 承担,
> 其永不 panic 由 `prop_preview_never_panics` 守卫. 原 property 文本保留以维持编号稳定 (§0.5).

### ROB-2 假设声明注释必备

**陈述**: 每个尝试性解析点必须在函数级注释显式写出:
1. 对输入的假设 (如 "假设 messages 数组中 user 在 assistant 之前").
2. 假设不成立时的降级行为.

**Properties** (人工审查项):
- `prop_extract_delta_messages_has_assumption_comment`: extract_delta_messages_from_raw 函数级注释含假设声明.
- `prop_extract_preview_has_assumption_comment`: 同上.
- `prop_tool_name_has_assumption_comment`: 同上.

> **理想 vs 现状**: 假设声明载体是 `extract_preview_and_model` 的函数级注释,
> 由 `prop_extract_preview_has_assumption_comment` 覆盖. 原 property 文本保留以维持编号稳定 (§0.5).

---

## 9. VIEW: 视图正确性机制

> 跨域. 当用视图/引用/派生字段替代原始数据存储时的纪律.

### VIEW-1 先断言后删除

**陈述**: 删除原始数据前, 必须用 `assert_eq!(derived_view, original_data)` 断言两者相等, 或写专项测试覆盖. 禁止仅凭"视图逻辑应该对"就删除原始数据.

**Properties** (人工审查项 + feature flag):
- `prop_view_deletion_has_assertion`: 任何"删除原始数据改用派生视图"的重构 commit 必须含 consistency-check 断言.
- `prop_consistency_check_feature_runs_in_ci`: consistency-check feature flag 在 CI 中独立运行.

### VIEW-2 派生字段 consistency-check 覆盖

**陈述**: 所有从原始数据派生的字段必须有 consistency-check 守卫. 当前已知派生字段:

| 派生字段 | 来源 | 守卫状态 |
|---|---|---|
| `redactions` | RedactionMap | ✅ `proxy.rs::assert_redactions_match_map` |
| `preview` / `model` | extract_preview_and_model | ✅ `proxy.rs::assert_preview_model_match_source` |
| `resp_parsed` (非流式) | reader.read_response | ✅ `proxy.rs::assert_resp_parsed_matches_source_nonstream` |
| `resp_parsed` (流式) | StreamScan snapshot | ⏳ Phase A 已删除原始 SSE 字节, 派生与源物理分离, 暂无法守卫 |
| `req_delta_messages` | extract_delta_messages_from_raw | (每次 timeline 请求重算, 无 drift 风险) |
| `session.title` | find_root_title | ✅ `dag.rs::assert_session_title_matches_root_preview` |

**Properties**:
- `prop_each_derived_field_has_consistency_check`: 上表中每个"待补"字段最终都有 consistency-check 断言.

### VIEW-3 原始数据是核心功能真相

**陈述**: secret-guard 核心职责 (转发 + Redact) 的字节准确性是最高优先级. 任何"派生视图更优雅"的诱惑不得凌驾于数据准确性之上.

---

## 10. UI: WebUI 渲染

> 信任域 C. 跨 web/dag/index.html 的强不变量.

### UI-1 气泡数 == IR messages 长度

**陈述**: 会话详情页 (timeline) 渲染的 Bubble 数量必须等于该 Node 对应 HTTP 请求的 IR messages 数组长度.

**Properties**:
- `prop_bubble_count_equals_ir_messages_length`: 对 N (≥1) 条 IR messages, timeline 渲染 N 个 Bubble.

### UI-2 sidebar 条目数 == HTTP 请求数

**陈述**: 左边栏每个一级条目 (Session) 下, 二级 + 三级条目总数必须等于归属该 Session 的 HTTP 请求数 (DAG 中以该 Session 叶子为终点的链上 Node 数).

**Properties**:
- `prop_sidebar_item_count_equals_http_request_count`: 对 M (≥1) 个 HTTP 请求的 Session, sidebar 二级+三级条目总数 == M.

### UI-3 timeline 轮次 DOM 顺序 == 数据顺序 (oldest-first)

**陈述**: timeline 中 `.tl-round` 在 DOM 里的出现顺序必须与 `state.timelineRecords` 完全一致 (oldest-first: 顶部最老, 底部最新).

**Properties**:
- `prop_timeline_dom_order_append`: append 模式 (新轮次追加) 下 DOM 顺序正确.
- `prop_timeline_dom_order_prepend`: prepend 模式 (滚到顶加载更早轮次) 下 DOM 顺序正确.
- `prop_timeline_dom_order_replace`: replace 模式 (切换会话) 下 DOM 顺序正确.
- `prop_timeline_dom_order_concurrent_fingerprint_mismatch`: 并发请求导致 fingerprint 错配时 DOM 顺序仍正确.

### UI-4 keyed reconciliation 不破坏 DOM 状态

**陈述**: 自动刷新触发 timeline 更新时, 公共节点的 DOM 完全保留 (scrollTop + 气泡展开状态), 仅新节点插入 / 消失节点删除.

**Properties**:
- `prop_reconcile_preserves_scrolltop`: 自动刷新前后 scrollTop Δ < 10px. ✅ `im-ui.spec.ts` "需求 1 (B1/B2 根治)".
- `prop_reconcile_preserves_bubble_expand_state`: 已展开的气泡在 reconcile 后仍展开. ✅ `im-ui.spec.ts` "UI-4 prop_reconcile_preserves_bubble_expand_state".
- `prop_reconcile_correct_for_all_change_modes`: keyed reconciliation 对 append/prepend/replace/完全不同 四种变动模式都正确. ✅ append (I3 守卫) + replace (切换会话, "需求 4") + 完全不同 ("UI-4 prop_reconcile_correct_for_all_change_modes"); prepend (滚到顶 lazy load) 待补.

### UI-5 末轮 response 独立 drawer

**陈述**: response 渲染为独立的 `.response-drawer` (overlay 架构), 不在 `.tl-round` 内. `#detail` 高度必须固定 (= wrapH), 禁止改为 `height: wrapH - drawerH` 或引入 flex 分栏.

**Properties**:
- `prop_detail_height_fixed`: `#detail` height == wrapH, 不依赖 drawerH. ✅ `im-ui.spec.ts` "UI-5 prop_detail_height_fixed".
- `prop_drawer_overlay_not_in_round`: response drawer DOM 不在 `.tl-round` 子树内. ✅ `im-ui.spec.ts` "需求 3: response 抽屉固定底部" 间接覆盖.

### UI-6 timeline 滚动状态机: followMode 是视口位置的纯派生 (↔ AGENTS.md I5)

**陈述**: timeline 的 follow/pinned 状态由 "视口距底部距离" 机械推导 (SSOT), 不由 "最近点了什么" 显式动作决定. `selectedRound` 与 followMode 解耦 (方案 X): selected 不随 follow 自动推进, 仅 "进入 follow 的显式动作" (点 Session / 点 unread badge / 初次 loadTimeline) 才重置.

**核心不变量**: `state.timelineFollow == isNearBottom()`, 即 `scrollHeight - scrollTop - clientHeight <= NEAR_BOTTOM_PX` (≈ 100px). 此判定在每次 scroll 事件 (RAF 合并) + 每次新 round 追加后由 `syncFollowMode()` 重算.

**Properties**:
- `prop_follow_initial_on_session_click`: 点 Session → follow + selected 在最新轮. ✅ `im-ui.spec.ts` "UI-6: 点 Session → follow + selected 在最新轮".
- `prop_pinned_on_manual_scroll_up`: follow 状态下手动向上滚 → pinned. ✅ `im-ui.spec.ts` "UI-6: 手动向上滚 → pinned".
- `prop_pinned_new_round_no_scroll`: pinned 期间新 round 到达 → scrollTop 不变 + unread badge 显示. ✅ `im-ui.spec.ts` "UI-6: pinned 状态下新 round 到达".
- `prop_unread_badge_resets_selected`: 点 unread badge → follow + selected 重置到最新轮 + badge 消失. ✅ `im-ui.spec.ts` "UI-6: 点 unread badge".
- `prop_follow_new_round_auto_scroll`: follow 期间新 round 到达 → 自动滚到底, 无 badge. ✅ `im-ui.spec.ts` "UI-6: follow 状态下新 round 到达".
- `prop_selected_stable_during_pinned`: pinned 期间点历史轮, 新 round 到达时 selected 不变. ✅ `im-ui.spec.ts` "UI-6: pinned 期间点历史轮".

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
