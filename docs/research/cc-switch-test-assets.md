# cc-switch 协议转换测试资产盘点 — secret-guard 吸收评估

> **一句话结论**: cc-switch 的测试资产核心价值不在测试架构 (内联 example-based, 与我们
> proptest+golden 栈不可直接移植), 而在 **~1,400 个内联 fixture 锁定的"真实世界 wire 边角
> 形态"场景矩阵** — 其中 2 项击中 secret-guard 已确认的测试空洞 (a→r 流式无专属测试 /
> DeepSeek usage cache 字段), 建议最小吸收 PR 直接搬 fixture 数据补齐; 其余按"借场景清单、
> 不搬代码"分级吸收。
>
> **plan B**: 若裁定不搬任何 fixture, 至少把本报告 §3 的场景矩阵归档到
> `docs/research/` 作为后续 STR/USAGE 契约的验收清单 — 场景知识不依赖 license, 零成本。

| | |
|---|---|
| 归档状态 | **A4 + A12 已吸收** (2026-10-01 最小吸收 PR — A4: `codec/openai.rs::read_usage` DeepSeek 双读 + 生成器扩展; A12: a→r 流式 2 集成测试, fixture 搬运含 attribution); 其余场景矩阵按 §4/§8 处置 (A1/A3/A5 借场景、暂不实施, 见 "暂不做") |
| 三篇关系 | 本文与 `docs/research/mcp-notes.md` (MCP 呈现形态) + cc-switch codec 实现差距审计 (T1-T9, 报告本体未归档 — 落地痕迹 = `docs/known-limitations.md` codec 节各 T 条目 + contracts.md FWD 注记) 构成 protocol 调研三篇 |
| 盘点日期 | 2026-10-01 |
| 证据基线 | cc-switch @ `846de29c` (2026-09-28, "Fix/skills new icon (#7727)"), worktree @ `/tmp/opencode/cc-switch-audit/repo` |
| 姊妹篇 | 实现差距审计: `docs/research/cc-switch-codec-gap-audit.md` (T1-T9 已全部落地) — 本文聚焦**测试**, 与其互补 |
| 对照物 | secret-guard @ master (codec ~350 测试函数 + integration.rs 12,862 行 + proptest 生成器契约) |
| license | **MIT** (Jason Young, 2025) — 实测 LICENSE 文件, 非猜测的 Apache-2.0; 与 secret-guard (MIT) 双向兼容, 见 §5 |

---

## 1. 执行摘要

| 排序 | 资产 | 价值 | 一句话理由 |
|---|---|---|---|
| 1 | **A4: usage 解析边角矩阵** (DeepSeek cache 字段 + 流式 cache pair 累积) | 高 | 击中 USAGE 回显保真的真实空洞: 我们 `read_usage` 只认 `prompt_tokens_details.cached_tokens`, DeepSeek 系 `prompt_cache_hit_tokens` 全丢 |
| 2 | **A12: a→r 流式 Anthropic SSE 输入 fixture 族** | 高 | codec AGENTS.md 自认 "Responses ingress ← Anthropic upstream 走同一翻译路径但**暂无专属测试**" — 17 个现成 fixture 直接堵洞 |
| 3 | **A3: 流截断/错误终态三分类矩阵** (failed/incomplete/completed 边界) | 中高 | cc-switch 用实战撞出的终态判定边界 (有输出截断→incomplete vs 无输出→failed 等 ~15 个 case), 借场景扩我们的 STR property |
| 4 | **A1: T10 反向嗅探聚合场景矩阵** (~40 tests) | 中高 (条件) | T10 按用户裁决"保留观察", 但这份是现成验收清单 — 实施之日即 P0 输入 |
| 5 | **A5: tool_call 索引畸形聚类矩阵** | 中 | index 缺失时的 id 回退聚合策略, 喂 proptest 生成器扩展覆盖度 (生成器覆盖度是我们自己的契约要求) |
| 6 | **A14: Responses writer 帧形态官方对照** | 中 | "reasoning item done 无 status 字段"等官方帧形态锁定, 对照我们的 synth 帧防漂移 |
| 7 | **A2/A13: SSE 聚合鲁棒 + 错误信封形态库** | 中 | BOM/CRLF/无尾空行/HTML 误判 + minimax base_resp 等国产错误信封变体 |
| 8 | **A6: Responses keyed/unkeyed delta alias 状态机测试** | 中 (待验证) | 若我们 reader 假设帧序严格而真实网关违反 (item_id 缺失/output_index 重排), 则升为高 — 需 POC |

**总体判断**: 值得做一次**最小吸收 PR** (A4 + A12, 合计 ~1 天工作量), 其余以场景清单形式归档, 不搬代码。

---

## 2. 覆盖表

| 来源 | 查到什么 | 盲区 |
|---|---|---|
| cc-switch @ 846de29c 全仓 `#[test]`/`#[tokio::test]` 计数 | Rust 侧 3,175 个测试函数; proxy 域 1,388 (44 文件) | 未逐一读非 proxy 域 (UI/config 服务 ~1,800 个, 与 codec 无关, 按目录名+抽样排除) |
| src-tauri/tests/ + golden/ | 15 个集成测试文件 + golden 快照 harness (config 渲染域, MCP 投影/深链/文件权限字节锁) | 未逐文件读 — golden 快照内容抽验 4 个均为 config 行, 与协议转换无关 |
| transform_responses.rs 测试名全量 (121) | 请求/响应映射 + web_search 矩阵 + usage 边角 + billing header fixtures | 仅精读 ~8 个测试体 |
| streaming_responses.rs (85) | 40 个 concat! SSE fixture; StreamedTextState alias 状态机 ~15 测试 | 精读 ~4 个 fixture 体 |
| streaming_codex_anthropic.rs (21) | 17 个 concat! a→r 流式 fixture (thinking/tool_use/截断/错误) | 精读 2 个 |
| streaming_codex_chat.rs (26) / handlers.rs (50) / transform_codex_anthropic.rs (73) | 测试名矩阵 + 抽读 SSE 聚合/嗅探 fixture | 未全读 |
| claude.rs (69) / codex.rs (44) / transform_codex_chat.rs (101) / transform_gemini.rs (30) / tool_media (16) / media_sanitizer (36) / thinking_rectifier (32) / usage/parser.rs (28) | 测试名矩阵 | 精读 usage parser 相关 |
| LICENSE + 凭证扫描 | MIT; rg 扫 sk-/ghp_/AKIA/xox/JWT 无命中; token 均占位符 | 正则扫描非穷尽 (短/形态特殊 token 理论上可漏) |
| secret-guard 对照: src/codec (含 AGENTS.md), tests/integration.rs, usage/ | a→r 流式无专属测试 (AGENTS.md 自认); read_usage 仅标准字段; T1-T9 各带回归守卫 | 未跑 coverage 量化对等度; STR property 断言细节未逐条比对 |

---

## 3. 测试全景概览

### 3.1 规模与结构

```
cc-switch (Tauri 应用: React 前端 + Rust 后端)
├── src-tauri/tests/           15 文件 — 配置/app 域集成测试 (profile/deeplink/MCP/skill 同步)
│   └── golden/                重构守卫: 字节锁快照 (CC_SWITCH_UPDATE_GOLDEN=1 更新) + 字段锁断言
├── src-tauri/src/proxy/       1,388 个内嵌测试 (44 文件) — 协议转换域, 全部 #[cfg(test)] 内联
│   └── providers/             transform×8 + streaming×5 + 共享模块×N
├── tests/ (前端)              138 个 TS 文件 — vitest + msw (UI 域, 全部无关)
└── fixture 形态               无外部 fixture 文件; ~2,023 个 json!() + ~85 个 concat! SSE 内联
```

### 3.2 方法论画像

- **纯 example-based 单测**: `json!({...})` 输入 → 手写断言, 无 property-based testing,
  无双跳 round-trip 自动化 (对比: 我们 proptest + FWD-1 normalize byte-exact 是代差优势)。
- **SSE fixture 组织**: `concat!("event: response.created\n", "data: {...}\n\n", ...)` 内联
  完整事件序列, 断言多为 `merged.contains(...)` 子串匹配 (弱于我们的逐帧 golden, 但 fixture
  本身是资产)。代表性样本: `streaming_responses.rs:5639` (web_search 全生命周期 12 帧)。
- **golden harness 值得一提的设计** (src-tauri/tests/golden/main.rs:1-18): 按字节锁 (快照) 与
  按字段锁 (断言) 分层 + env 开关更新快照 + "快照变了 = 行为变了, 要能说清楚为什么" 的
  纪律声明 — 与我们 golden 思路同源, 无新增可抄。
- **round-trip 意识**: reasoning_bridge.rs:100-130 是仅有的显式 encode→decode identity 断言
  (即我们 T7 sg-thinking envelope 的 cc-switch 原型); usage clamp `input >= cache` 不变量。

### 3.3 协议转换域测试密度 (top)

| 文件 | 测试数 | 域 |
|---|---|---|
| transform_responses.rs | 121 | a⇄r 请求/响应映射 + web_search + usage |
| transform_codex_chat.rs | 101 | r⇄o 映射 + reasoning 重组 + media 提取 |
| streaming_responses.rs | 85 | r→a 流式 (含 alias 状态机) |
| forwarder.rs | 79 | 请求侧 dispatch |
| transform_codex_anthropic.rs | 73 | a→r 映射 + SSE 聚合 |
| transform.rs | 70 | a⇄o (OpenRouter, 默认关) |
| claude.rs / codex.rs | 69/44 | provider 特定修正 (DeepSeek/codex-oauth) |
| handlers.rs | 50 | 响应侧 dispatch + **SSE 嗅探聚合** |

---

## 4. 可吸收资产清单 (按价值排序)

> 每项: 位置 (file:line) / 内容 / 价值 / 适配建议 / 覆盖对照。
> "借思路" = 重写为我们的测试 (无法律义务); "搬数据" = fixture JSON/SSE 序列直接复制
> (MIT 允许, 需文件头 attribution, 见 §5)。

### A4 — usage 解析边角矩阵 ★ 高价值

- **位置**: `src-tauri/src/proxy/usage/parser.rs` (28 tests); 关联
  `transform_codex_chat.rs::chat_usage_to_responses_usage_*` (3) 与
  `transform_responses.rs::test_build_usage_*` (12)。
- **内容**:
  - DeepSeek 变体字段: `prompt_cache_hit_tokens` / `prompt_cache_miss_tokens`
    (`test_openai_response_deepseek_cache_hit_fields` / `..._stream_...`), 且
    **标准字段优先于 DeepSeek 专有字段** (`openai_cache_read_prefers_standard_field_over_deepseek_specific`)。
  - 流式 cache pair 累积策略: 后到的 `message_delta` usage 覆盖更新
    (`test_claude_stream_updates_cache_pair_from_later_delta_input`), delta input 更大时保留
    message_start 值 (`..._keeps_start_when_delta_is_larger` / `..._prefers_smaller_delta...`)。
  - 杂项: 空 usage 门禁 (`test_has_billable_tokens_gates_empty_usage` — 诚实呈现缺失)、
    id 去重 scope、流 envelope chunk 恢复 id。
- **覆盖对照**: **无对等**。secret-guard `codec/openai.rs::read_usage` (openai.rs:900-922)
  只读 `prompt_tokens_details.cached_tokens`; DeepSeek 系上游 (DeepSeek/Kimi/GLM 官方端点,
  我们 known-limitations 已登记其 anthropic 兼容形态) 的 cache 计数在跨协议翻译中静默丢失
  — 违反 USAGE 回显保真精神。流式侧 pair 累积策略未比对 (不确定项, 见 §7)。
- **适配**: **搬场景 + 少量搬数据**。落点: `codec/openai.rs::read_usage` 扩展 DeepSeek 双读
  (标准优先) + `fwd_property.rs` 生成器加 DeepSeek 字段分支 + 2-3 个 example 断言。
  ~0.5 天。

### A12 — a→r 流式 Anthropic SSE 输入 fixture 族 ★ 高价值

- **位置**: `src-tauri/src/proxy/providers/streaming_codex_anthropic.rs:1044-1090`
  (`test_thinking_stream` / `test_thinking_signature_is_preserved`) 及全文件 17 个 concat!。
- **内容**: Anthropic 上游 SSE 完整事件序列 — thinking block (thinking_delta + signature_delta
  分帧) / tool_use (input 仅在 start + partial_json 分片) / message_delta 带
  `server_tool_use.web_search_requests` usage / 截断流 (有输出 vs 无输出) / 错误后 message_stop
  / 无尾空行终帧。
- **覆盖对照**: **无对等 — 已确认空洞**。codec AGENTS.md 支持矩阵原文: "Responses ingress ←
  Anthropic upstream 走同一翻译路径但**暂无专属测试**"。我们 a→r 非流式与 r→a 流式都有锁,
  唯独这条流式路径裸奔 (翻译逻辑与 r→a 共享, 但 fixture 视角的输入形态覆盖为零)。
- **适配**: **搬数据**。把 thinking/tool_use 两个 fixture 的输入侧 SSE 序列改造为
  `tests/integration.rs` 的 mockito 上游 body (参照既有 `RESPONSES_SSE_TEXT_FLOW`
  integration.rs:2625 的组织方式), 断言 a 协议 fixture → r 协议 egress 帧序列。
  注意 cc-switch 的 a→r 输入 fixture 不含 claude code billing header 形态 (非流式才有),
  无需联动 T9。~0.5 天。

### A3 — 流截断/错误终态三分类矩阵

- **位置**: `streaming_codex_anthropic.rs` (`test_truncated_stream_with_output_reports_incomplete`
  / `test_truncated_stream_without_output_reports_failed` / `test_error_after_message_stop_...` /
  `test_stop_reason_without_message_stop_completes` / `test_final_event_without_blank_line_is_processed`
  / `test_empty_read_input_finishes_as_empty_object`) + `streaming_codex_chat.rs`
  (`stream_end_without_output_or_finish_reason_emits_failed_without_completed` /
  `..._with_output_..._incomplete_...` / `truncated_turn_stays_incomplete_instead_of_failed`)。
- **内容**: 终态判定边界全集 — 三分类 (completed / incomplete / failed) 在 {有输出, 无输出,
  有 finish_reason, 无 finish_reason, error 后续 delta, 双终态事件} 组合下的期望值。
  cc-switch 把 "completed 里带 failed status" / "incomplete 里非 token reason" 都锁了
  (transform_responses.rs:5599-5636)。
- **覆盖对照**: **部分对等**。我们 STR-* 契约有错误降级 + 边界项, synth.rs 9 测试锁合成;
  但 "completed 事件携带 failed status" / "有输出截断 vs 无输出截断分档" 这类组合边界
  未逐条锁。T4 (incomplete_details) 已对等。
- **适配**: **借思路** — 把矩阵转成 STR 契约下的表驱动测试 (放进
  `fwd_streaming_property.rs` 或 responses/stream.rs 内嵌), fixture 自造即可 (形态简单)。
  ~1 天。注意 cc-switch 的分类目标是 Responses `status` 枚举, 我们对应 IR 终态 + 各协议
  stop_reason/status 写出, 断言落点需按我们契约重新表述, 不能照抄期望值。

### A1 — T10 反向嗅探聚合场景矩阵 (条件性高价值)

- **位置**: `src-tauri/src/proxy/handlers.rs:2871-2887` (`body_looks_like_sse_detects_*`) +
  ~30 个 `chat_sse_to_response_value_*` + 7 个 `responses_sse_to_response_value_*`。
- **内容**: 上游对非流式请求返回未标记 SSE 时的嗅探+聚合全集: 前缀识别
  (data:/event:/id:/retry:/OpenRouter 注释行 `: OPENROUTER PROCESSING`/BOM+前导空白;
  HTML 拦截页与 "Bad Gateway" 反例), CRLF 分隔, 缺尾空行, 缩进 data 行, Azure 占位信封,
  null error 字段, 截断残留, 无 chunk 流拒绝, 巨大 tool_call index 不 OOM,
  legacy function_call, message snapshot 覆盖 deltas, empty-delta scaffold。
- **覆盖对照**: **无对等** — T10 (反向嗅探聚合) 按用户裁决 "暂不实施保留观察"
  (gap-audit 终评)。我们只有正向 (请求 stream:true 上游回 JSON → synth SSE, T5 已实施)。
- **适配**: **现在只归档, 不实施**。把场景清单收进 `docs/research/` (或
  known-limitations 的 T10 观察条目旁), 标注 "实施 T10 时此为验收清单 + P0 输入"。
  归档 ~0.1 天。若实施, 嗅探判定 (BOM/注释行/误判反例) 可搬数据, 聚合逻辑借思路。

### A5 — tool_call 索引畸形聚类矩阵

- **位置**: `streaming_codex_chat.rs` (~10 tests): `missing_index_argument_fragments_stay_in_one_call`
  / `missing_index_repeated_same_id_stays_in_one_call` / `missing_index_with_distinct_ids_keeps_calls_separate`
  / `finalization_keeps_non_contiguous_tool_index` / `preserves_parallel_tool_order_when_earlier_name_arrives_late`
  / `preserves_tool_identity_across_empty_continuation_deltas` /
  `whitespace_only_tool_name_is_dropped` / `finalization_keeps_valid_call_after_unnamed_earlier_call`。
- **内容**: Chat 流式 tool_calls delta 在 index 缺失/乱序/间断时的身份聚类策略 (id 优先回退),
  以及不可恢复畸形 (全 unnamed / 空白 name) 的失败语义。
- **覆盖对照**: **部分对等**。STR 契约明列 "reader 多 tool_call 索引" (openai.rs flat stream
  有 state 处理), 但 "index 缺失时按 id 聚类" 的畸形输入族在生成器覆盖度上存疑
  (我们自己的历史教训: property 存在但生成器太窄致漏测)。
- **适配**: **借思路喂生成器** — 扩展 `fwd_streaming_property.rs` 的 arb 生成器让 tool_call
  delta 流可生成 {缺 index, 同 id, 异 id, 间断 index, 晚到 name} 组合, 断言按我们
  openai.rs 的聚类契约表述。~0.5 天。

### A14 — Responses writer 帧形态官方对照

- **位置**: `src-tauri/src/proxy/providers/codex_responses_sse.rs:346-399` (5 tests)。
- **内容**: Responses SSE 合成帧的官方形态锁定 — `reasoning_close` 的 done item **无 status
  字段** (官方行为), `message_item_added` 带 `status:"in_progress"` + role, done 帧参数
  (`arguments` 为 JSON 字符串转义), 3 帧 close 序列 (text.done→part.done→item.done)。
  该文件是 cc-switch 自己的 "wire fix 落地一次防双文件镜像漂移" 共享模块。
- **覆盖对照**: **部分对等**。我们 `responses/stream.rs` writer 有 official_text_frames 等帧
  形态测试 + integration fixture; 但 "reasoning item done 无 status" 这类逐字段形态未逐条
  对照官方 (未验证, 见 §7)。
- **适配**: **借思路** — diff 一次我们 synth/write 帧与 cc-switch 锁的形态清单, 差异处
  (若有) 先查官方文档再定是补测试还是修 writer。~0.5 天 (纯对照)。

### A2 — Anthropic SSE 聚合鲁棒矩阵

- **位置**: `transform_codex_anthropic.rs:2913-2955` (`test_anthropic_sse_aggregation_*` 10 tests)。
- **内容**: Anthropic SSE → 非流式 message 聚合: 缺 message_start 报错 / 非对象 content_block
  不 panic / 非对象 message 报错不 panic / 容忍缺尾空行 / tool_use input 仅在 start /
  partial_json 累积 / 截断分类。
- **覆盖对照**: **部分对等**。我们 StreamScan 有 ROB-1 永不 panic property 守卫, 但 "缺
  message_start" 等结构性错误的**分类** (error vs best-effort 空) 未显式锁。
- **适配**: 借思路, 2-3 个 case 进 `stream/scan.rs` 测试。~0.25 天。

### A13 — 错误信封形态库

- **位置**: `transform_codex_chat.rs::chat_error_to_response_error_*` (5) +
  `streaming_responses.rs:37-54` (`responses_error_details` fallback 链: message→str→fallback,
  type→code→"upstream_error") + `handlers.rs::codex_proxy_upstream_error_normalizes_nonstandard_body`。
- **内容**: 上游错误体变体 — 标准 OpenAI shape / minimax `base_resp` 嵌套 / 纯文本 body /
  缺 body / 空 message 占位 / null error 字段。
- **覆盖对照**: **部分对等**。我们 `write_error` 有 "优先解析上游 error.message + 4KiB 截断"
  (codec 不变式 5), 但国产信封变体 (base_resp) 无覆盖。
- **适配**: 借思路 — error envelope 解析的 example 测试扩 3-4 个变体, 或在 error.rs 的
  Upstream message 净化处加断言。~0.25 天。

### A6 — Responses keyed/unkeyed delta alias 状态机测试 (待验证)

- **位置**: `streaming_responses.rs` StreamedTextState 系列测试 (fn 名见
  `test_streamed_text_binds_output_and_item_aliases_to_one_aggregate` 等 ~15 个)。
- **内容**: 防御 "网关丢弃 item_id / output_index 与 item_id 别名交叉 / delta 乱序" 的
  文本聚合状态机 — keyed (item_id) 与 unkeyed (仅 output_index) 增量的归并、别名绑定、
  交叉别名拒绝、terminal 后 unkeyed 尾巴。
- **覆盖对照**: **未验证**。我们 `responses/stream.rs::read_responses_stream_event` 的 reader
  状态机对同款畸形输入 (item_id 缺失、index 重排) 的行为未知 — 若我们假设官方严格帧序而
  cc-switch 的防御来自真实网关 (他们的注释明说来自实战), 则存在脆弱面。
- **适配**: 先 POC — 用 2-3 个畸形 fixture 喂我们 reader, 观察是 panic/丢字/正确聚合;
  有问题则升为高价值吸收。~0.5 天验证。

### 其余顺手项 (低价值, 列此存档)

- **A8-web_search 矩阵** (~30 tests): hosted web_search 工具全生命周期翻译 — 我们契约性
  丢弃 hosted tools (known-limitations 登记), 吸收 = 功能决策非测试补齐。若未来支持, 这套
  是完整规格。**价值: 低 (现状)**。
- **A7-thinking 签名错误检测 fixtures** (`thinking_rectifier.rs` 32 tests): claude code 用户
  实测的 "invalid signature / thinking expected / cannot be modified" 错误信封变体库 —
  cc-switch 用于**自动修正重试** (与 FWD-1 冲突, 不吸收功能), 但错误信封样本可充实
  known-limitations 的 "上游为何 400" 知识。**价值: 低-中, 归档**。
- **A15-codex_responses_sse 的双文件防漂移组织模式**: 单一 envelope 模块 + 两侧复用 —
  我们 IR 架构天然免疫此问题, 无需吸收。**价值: 无**。

---

## 5. License 与安全注记

- **License = MIT** (LICENSE 文件: "MIT License, Copyright (c) 2025 Jason Young") —
  非任务背景猜测的 Apache-2.0。secret-guard 声明 MIT 且发布 nixpkgs overlay, MIT↔MIT
  完全兼容, `deny.toml` license 门禁无阻碍。
- **吸收方式法律面**:
  - **借思路重写** (场景矩阵 → 自家 property/表驱动): 无任何义务。
  - **直接搬 fixture 数据 / 测试代码** (A12/A4 可能触及): MIT 唯一实质条件是保留版权
    与许可声明 — 在吸收文件头部加 attribution 注释即可, 例:
    `// fixture 形态 derived from cc-switch (MIT, https://github.com/farion1231/cc-switch) @ 846de29c`。
    fixture 是事实性 wire 数据 (协议行为描述), 版权保护本就弱, attribution 是稳妥做法而非
    严格义务边界; 建议一律加。
- **安全扫描**: 全 proxy 域 + tests rg 扫描 `sk-[a-z0-9]{20,}` / `ghp_` / `gho_` / `AKIA` /
  `xox` / JWT 前缀 / Bearer 长串 — **零命中**。token 类 fixture 全为占位符 (`sk-old`/
  `sk-new`/`rt-abc`/`upstream-secret`/`legacy-live-only-token`); billing header fixture 中
  `cch=a7754` 为截断 hash 片段, 无敏感价值。**结论: 搬运无需脱敏**, 但建议吸收时统一换成
  secret-guard 测试自己的占位符约定 (如 `sk-test-*`), 便于将来 secret-scan 白名单。

---

## 6. 不值得吸收的与理由

| 资产 | 规模 | 理由 |
|---|---|---|
| copilot_optimizer / copilot_auth / copilot_model_map / xai_oauth / codex_oauth 系 | ~150 tests | provider 特定功能 (GitHub Copilot token 换取 / xAI OAuth), secret-guard 无此功能面; 其中 codex-oauth 的 store/include/strip-temperature 改写与 FWD-1 (原始形状保持) 直接冲突, gap-audit 已裁决不跟 |
| cache_injector / prompt_cache_key 注入 | ~20 tests | FWD-1 显式列举例外之外, 姊妹篇 §4.2-C 已论证需裁决, 不跟 |
| text_with_url_citations 渲染族 | ~15 tests | 把 url_citation 注解改写成 "Sources:" 脚注 — 内容改写违反 FWD-1 (对 wire 的唯一合法修改是 real↔mock 替换); citations 语义建模已在我们 known-limitations (响应侧 block 未知字段按 extra 保真) |
| web_search 翻译矩阵 | ~30 tests | hosted tools 契约性丢弃 (见 A8); 何时支持是功能决策, 不是测试吸收 |
| transform_gemini + streaming_gemini + gemini_schema/url/shadow | ~90 tests | Gemini codec 未实现 (501); 未来实现走 IR 路线 (~200 行/协议), cc-switch 的点对点手写测试无法迁移; shadow-replay (客户端截断历史后的 id 对账) 知识点已在姊妹篇 |
| 前端 vitest/msw 套件 | 138 files | UI 域, 无关 |
| golden config 快照 harness | ~15 files | 域不符 (我们的 config 是 serde SSOT, 无手写投影漂移面); 分层锁思路我们 golden 已有 |
| hermes/profile/deeplink/skill/mcp 等 src-tauri/tests | 15 files | 配置管理域, 与 codec 无关 |
| "unknown 字段透传" roundtrip 模式 (hermes_roundtrip.rs) | 1 file | 思路已被我们 wire-fidelity extra 机制 (L4/L5) 更强覆盖 |

---

## 7. 不确定性声明

1. **A6 (alias 状态机) 与 A14 (帧形态) 的对等性未验证** — 只核对了测试名与我们支持矩阵
   的声明, 未逐字段 diff 两侧实现行为; 已列为 POC 项。
2. **流式 usage pair 累积策略** (A4 子项): 我们 StreamScan/synth 对后到 usage 覆盖的策略
   未与 cc-switch 的 "小值优先/后值覆盖" 矩阵比对 — 吸收时需先写探针测试确认现状。
3. **测试计数是 `#[test]` 属性计数**, 少数 helper 函数可能被误计/漏计 (±5% 量级), 不影响
   结论。
4. **"真实世界形态"的代表性是 cc-switch 用户群的代表性** — 其主力用户是 claude code /
   codex CLI + 国产中转站 (DeepSeek/Kimi/GLM/OpenRouter) 组合; 与 secret-guard 目标流量
   高度重叠但非同一集合, 例如我们 OpenAI Responses 官方直连场景他们覆盖更少。
5. cc-switch 行号随其快速迭代漂移 (姊妹篇同款提示); 引用均带 @ 846de29c 基线。

---

## 8. 可验证的下一步 (最小吸收 PR 建议)

**PR 范围 = A4 + A12 (合计 ~1 天, 两者均为已确认空洞 + 确定性收益)**:

1. **A12** (先行): `tests/integration.rs` 新增 r-ingress/a-upstream 流式翻译 2 个用例
   (thinking+signature 流 / tool_use partial_json 流), fixture 输入侧 SSE 搬运自
   streaming_codex_anthropic.rs:1044-1090 并加 attribution; 断言 r 侧 egress 帧序列。
   (归档注: 原文此处误写 "a-ingress/r-upstream", 与 §4 A12 的 "Responses ingress ←
   Anthropic upstream" 矛盾, 归档时按 §4 方向校正。)
   若红灯 → 翻译路径有 bug (该路径零测试保护至今), 先修后绿。
2. **A4**: `codec/openai.rs::read_usage` 双读 DeepSeek `prompt_cache_hit_tokens`
   (标准字段优先) + `fwd_property.rs` 生成器扩展 + USAGE 契约断言; 对照
   usage/parser.rs 的期望值语义 (input = prompt - cached) 保持我们既有 SSOT 收敛逻辑。
3. **顺手归档** (不占 PR 额度): 本报告 §4 的 A1/A3/A5 场景矩阵已在案 — T10 实施或
   STR 生成器扩展时直接引用本文件路径。
4. **验证链**: `just check` 全绿 (新测试进常驻集, 不用 ignore 机制 — 被测路径已存在)。

**暂不做**: A3/A5/A14/A6 的场景化改造 — 待 A4/A12 合入后按 §7 的验证结论再排期。
