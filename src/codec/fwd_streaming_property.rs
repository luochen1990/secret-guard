//! FWD-1 流式响应半段式 property test.
//!
//! # 契约
//!
//! [`docs/design/contracts.md`] FWD-1 (L110-137, 流式响应半段式) +
//! STR-1 (chunk 边界透明, L299-306) + STR-4 (缓冲溢出 abort, L330-335).
//!
//! ## FWD-1 流式响应半段式
//!
//! 流式响应的 restore, 经任意 chunk 切分, 要求
//!
//! ```text
//! normalize(返回客户端的 wire) == normalize(上游响应 wire).replace(mock, real)
//! ```
//!
//! 即: secret-guard 对流式响应 wire 的唯一合法修改是 mock→real 替换.
//!
//! # 契约字面 vs 实现现状 (漂移, 已记录)
//!
//! `StreamTranslate::new_same_proto_restore` 的实现 (生产路径
//! [`crate::proxy::fan_out_streaming_with_restore`]) **显式放弃 byte-exact**, 见
//! `stream/translate.rs` 头部注释:
//!
//! > 工作流: egress SSE → parse IR events → StreamingRestorer (跨 chunk restore)
//! > → 序列化回 SSE. **失去 byte-exact (因为 IR re-serialize), 但语义等价**.
//!
//! 因此 FWD-1 流式半段式字面上的 byte-exact 在 `same_proto_restore` 路径下**不成立**.
//! 已知结构差异 (除 mock→real 替换外):
//!
//! 1. **id/created 重新生成**: `StreamTranslate::translate_event` 无条件清空
//!    `MessageStart.id/created` (跨协议身份剥离逻辑, 同协议 restore 模式也共用),
//!    ingress writer 合成新的随机 id (`chatcmpl-<base62>` / `msg_01<base62>`) 和
//!    当前 epoch `created`.
//! 2. **chunk 结构重组**: `StreamingRestorer` 的 sliding window 在 mock 跨 chunk 时
//!    会重组 chunk 边界 (eg 把一个长 delta 拆成"restore 完的前半" + "hold 的后半"),
//!    导致客户端看到的 chunk 划分与上游不同.
//! 3. **usage input_tokens backfill**: terminal delta (MessageDelta) 的 usage 在
//!    `input_tokens==0` 时用 MessageStart 锁定的 input_tokens 填回, 使客户端看到
//!    `usage.input_tokens` (OpenAI include_usage 路径的兼容性补丁).
//! 4. **元数据字段去重** (OpenAI): 上游每个 chunk 都带 `id/created/model/object`,
//!    writer 仅在 MessageStart chunk 输出这些字段, 其他 chunk 不重复.
//!
//! # 本模块的 property 形式 (语义等价, 非 byte-exact)
//!
//! 按 §0.5 漂移处理流程, 契约不能擅自修改. 这里实现的 property 是契约**精神**的
//! 弱化形式 (语义等价), 守卫以下不变量:
//!
//! 1. **content fidelity**: 客户端收到的所有 TextDelta 拼接 == 上游 TextDelta 拼接
//!    `.replace(mock, real)`. (chunk 重组不丢内容.)
//! 2. **tool input fidelity**: 客户端收到的所有 InputJsonDelta 拼接 == 上游拼接
//!    `.replace(mock, real)`.
//! 3. **no mock leak** (安全核心): 客户端收到的字节中不含 mock 字符串.
//! 4. **usage output fidelity**: 客户端收到的 usage.output_tokens == 上游.
//!
//! 这些 property 弱于契约的字面形式 (byte-exact), 但守住了 secret-guard 的核心
//! 安全职责 (不泄漏 mock) + 核心数据职责 (内容不丢). 把契约字面形式完整实现需要
//! 重新设计 `same_proto_restore` 路径 (eg 避免 IR re-serialize, 改为字节级扫描替换),
//! 属于重大架构改动, 应作为独立 issue 讨论 (见 PR 描述).
//!
//! # 生成器覆盖
//!
//! 按契约 FWD-1 `prop_proptest_generator_covers_edge_cases` (L131-136) + §0.3 第 3 条,
//! 生成器覆盖:
//! - text delta (连续多 chunk, 含 mock)
//! - tool_use input JSON 部分片段 (InputJsonDelta, 含 mock)
//! - include_usage chunk (terminal usage, choices=[])
//! - 跨字段重复 mock (mock 出现在多个 text delta + tool input)
//! - 流式 chunk 任意切分 (1-byte 切分 + 随机切分点)
//! - Responses 双行帧流 (text / reasoning summary / function_call args delta 三类
//!   mock 载体, 见 `arb_responses_sse_stream_with_mock`)
//!
//! # Responses 流式覆盖 (2026-09-23, T5)
//!
//! Responses 流式 reader/writer 落地 (T2/T3) + proxy 501 解除 (T4) 后, 本模块把
//! Responses 纳入 STR-* / FWD-1 流式契约的机械验证范围:
//!
//! - **STR-1 (chunk 切分等价)**: r→r 同协议 restore 字节级切分等价
//!   (`prop_responses_translate_chunk_split_equivalence`) + StreamScan(Responses)
//!   任意切分 == 一次性 feed (`prop_responses_scan_chunk_split_equivalence`) +
//!   跨协议四个组合 (r→o / o→r / r→a / a→r) 任意切分下的内容保真
//!   (`prop_cross_proto_stream_responses_to_*` / `*_to_responses`).
//! - **FWD-1 流式响应半段 (restore 无泄漏)**: r→r 同协议 restore
//!   (`prop_streaming_response_half_byte_exact_responses` + byte-by-byte 变体) +
//!   Responses 任一侧跨协议 + restore (`prop_cross_proto_streaming_no_mock_leak_responses_*`).
//! - **STR-2 累积等价**: StreamScan(Responses) snapshot == 生成器同步构造的预期
//!   IrResponse (`prop_responses_stream_scan_matches_expected_ir`).
//!
//! ## 已声明缺口 (不放宽断言掩盖, 维度从生成器排除)
//!
//! 1. **STR-2 字面形式 (scan ≡ 非流式 `read_response`) 在 Responses 侧不成立**,
//!    有两个已知建模分歧 (与 `docs/known-limitations.md` / 方案 D5 一致):
//!    - stop_reason 推断不对称: 流式 reader 由 `saw_function_call` 推断 ToolUse,
//!      非流式 `read_response_status("completed")` 恒 EndTurn (status 粒度粗);
//!    - reasoning 双变体: 流式产 `IrBlock::ReasoningContent{text}` (summary delta
//!      与思考原文归一), 非流式产 `IrBlock::Reasoning{summary}` (仅 summary).
//!
//!    故 STR-2 取生成器预期形式 (与 stream/mod.rs 的 OpenAI 实现
//!    `arb_openai_sse_with_expected` 同型 — 那里的字面形式同样以语义等价回避).
//! 2. **usage_present false→true 单向漂移** (T3 移交, 方案 D5): Responses writer
//!    无条件写全零 usage 对象 — upstream `usage:null` 经 restore 重合成后成为
//!    `{"input_tokens":0,...}`. 本模块的 usage 断言只比较 `output_tokens` 值
//!    (0==0 两边恒等), **不断言 usage presence 的字节形态**.
//! 3. **stop_reason=Other 往返漂移为 failed** (T3 移交, 方案 D5): 生成器只产
//!    `response.completed` 终止事件, 不产 incomplete/failed 终止形态 — 该维度的
//!    往返行为由 responses.rs 的确定性单测
//!    (`stream_round_trip_incomplete_max_tokens_scenario` 等) 锁定. 生成器内
//!    function_call 恒出现 → 流式 stop_reason 恒 ToolUse (EndTurn 分支同由
//!    responses.rs 单测覆盖, 与 openai/anthropic 生成器恒含 tool 段同款偏差).

use proptest::prelude::*;
use serde_json::{Value, json};

use crate::codec::ir::{IrBlock, IrStopReason, IrUsage};
use crate::codec::stream::{StreamScan, StreamTranslate, parse_sse_frame};
use crate::codec::{IrResponse, Protocol};
use crate::redact::RedactionMap;

// ─── 公共 proptest 入口 ─────────────────────────────────────────────────────

proptest! {
    /// FWD-1 `prop_streaming_response_half_byte_exact` (OpenAI, 语义形式):
    ///
    /// 守卫 `same_proto_restore` 路径在任意 chunk 切分下的语义等价性:
    /// - content fidelity: TextDelta 拼接 == 上游拼接.replace(mock, real)
    /// - tool input fidelity: InputJsonDelta 拼接 == 上游拼接.replace(mock, real)
    /// - no mock leak: 客户端字节不含 mock
    /// - usage output fidelity: output_tokens 透传
    ///
    /// 注: 字面 byte-exact 不成立 (见模块头注释"契约字面 vs 实现现状").
    #[test]
    fn prop_streaming_response_half_byte_exact_openai(
        case in arb_openai_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock) = case;
        let map = build_redaction_map(&real, &mock);
        let client_sse = run_same_proto_restore(Protocol::OpenAI, map, &upstream_sse, &splits);

        assert_streaming_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// FWD-1 `prop_streaming_response_half_byte_exact` (Anthropic, 语义形式):
    ///
    /// 同上, Anthropic 协议的 SSE 流 (event: 风格).
    #[test]
    fn prop_streaming_response_half_byte_exact_anthropic(
        case in arb_anthropic_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock) = case;
        let map = build_redaction_map(&real, &mock);
        let client_sse = run_same_proto_restore(Protocol::Anthropic, map, &upstream_sse, &splits);

        assert_streaming_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// FWD-1 `prop_streaming_response_half_byte_exact` (Responses, 语义形式):
    ///
    /// Responses 协议的同协议 restore (双行帧 `event: + data:` 风格). 除共享断言集
    /// (text / tool input / reasoning / usage.output_tokens / no-mock-leak) 外,
    /// Responses 的 done 族帧 (output_text.done / output_item.done /
    /// response.completed) 携带**全量**内容 — 由 writer 从 restore 后的 IR delta
    /// 重合成, 全量文本中的 mock 同样被 restore (no-mock-leak 扫描整条客户端字节流
    /// 已覆盖此路径).
    #[test]
    fn prop_streaming_response_half_byte_exact_responses(
        case in arb_responses_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock, _expected_scan) = case;
        let map = build_redaction_map(&real, &mock);
        let client_sse =
            run_same_proto_restore(Protocol::OpenAIResponses, map, &upstream_sse, &splits);

        assert_streaming_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// FWD-1 极端切分: 1-byte 切分 (退化情形, 每个 feed 只推进 1 字节).
    ///
    /// 覆盖 StreamingRestorer 的 sliding window 在每个 chunk 只有 1 字节时的正确性.
    /// 与 stream/mod.rs 里的 `stream_scan_byte_by_byte_split_equivalence` 同类, 但
    /// 那个测 StreamScan, 这里测 StreamTranslate restore 路径.
    #[test]
    fn prop_streaming_response_byte_by_byte_openai(
        case in arb_openai_sse_stream_with_mock()
    ) {
        let (upstream_sse, real, mock) = case;
        let map = build_redaction_map(&real, &mock);
        // 1-byte 切分: [1, 2, 3, ..., len].
        let splits: Vec<usize> = (1..=upstream_sse.len()).collect();
        let client_sse = run_same_proto_restore(Protocol::OpenAI, map, &upstream_sse, &splits);

        assert_streaming_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// FWD-1 极端切分: 1-byte 切分 (Anthropic).
    #[test]
    fn prop_streaming_response_byte_by_byte_anthropic(
        case in arb_anthropic_sse_stream_with_mock()
    ) {
        let (upstream_sse, real, mock) = case;
        let map = build_redaction_map(&real, &mock);
        let splits: Vec<usize> = (1..=upstream_sse.len()).collect();
        let client_sse = run_same_proto_restore(Protocol::Anthropic, map, &upstream_sse, &splits);

        assert_streaming_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// FWD-1 极端切分: 1-byte 切分 (Responses).
    ///
    /// Responses 帧是双行形态 (event: + data:), 1-byte 切分覆盖两类行的跨 chunk
    /// 重组 + StreamingRestorer 滑窗在最小 chunk 下的 mock 边界处理.
    #[test]
    fn prop_streaming_response_byte_by_byte_responses(
        case in arb_responses_sse_stream_with_mock()
    ) {
        let (upstream_sse, real, mock, _expected_scan) = case;
        let map = build_redaction_map(&real, &mock);
        let splits: Vec<usize> = (1..=upstream_sse.len()).collect();
        let client_sse =
            run_same_proto_restore(Protocol::OpenAIResponses, map, &upstream_sse, &splits);

        assert_streaming_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// STR-6 `prop_streaming_reasoning_restored_like_text` (#176):
    /// 思考阶段 reasoning_content delta 中的 mock 必须被 restore (与 text 同算法),
    /// 客户端拼接 == 上游拼接.replace(mock, real); 任意 chunk 切分下成立.
    ///
    /// 这是 #176 的核心回归守卫: 修复前 reader 不解码 reasoning_content → redact
    /// 流式路径 (IR 重建) 思考期零字节, 客户端空闲看门狗超时断连 (生产 499).
    /// 生成器 has_reasoning 强制为 true (直接构造, 排除随机 false 分支).
    #[test]
    fn prop_streaming_reasoning_restored_like_text(
        mock_body in "[a-z]{4,12}",
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let mock = format!("MOCK{mock_body}");
        let real = format!("sk-real-{mock_body}");
        // 构造思考流: role chunk (附带首个 reasoning delta 含 mock) → 第二个 reasoning
        // delta (mock 跨 chunk 候选) → finish → [DONE].
        let frames = [
            json!({
                "id":"chatcmpl-r","object":"chat.completion.chunk","created":1700000000,
                "model":"glm-5.3",
                "choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":format!("secret is {mock}")},"finish_reason":Value::Null}]
            }),
            json!({
                "id":"chatcmpl-r","object":"chat.completion.chunk","created":1700000000,
                "model":"glm-5.3",
                "choices":[{"index":0,"delta":{"reasoning_content":format!(" and more {mock} tail")},"finish_reason":Value::Null}]
            }),
            json!({
                "id":"chatcmpl-r","object":"chat.completion.chunk","created":1700000000,
                "model":"glm-5.3",
                "choices":[{"index":0,"delta":{},"finish_reason":"stop"}]
            }),
        ];
        let mut upstream_sse: Vec<u8> = frames
            .iter()
            .map(openai_chunk_frame)
            .collect::<String>()
            .into_bytes();
        upstream_sse.extend_from_slice(b"data: [DONE]\n\n");

        let map = build_redaction_map(&real, &mock);
        let client_sse = run_same_proto_restore(Protocol::OpenAI, map, &upstream_sse, &splits);

        // 思考期零字节回归: 客户端必须实际收到 reasoning 字节 (修复前为空).
        // 放在 fidelity 断言前: 空串也是 fidelity 等式的一种 "平凡解", 先排除.
        prop_assert!(
            !collect_reasoning_deltas(&client_sse).is_empty(),
            "STR-6: 客户端思考期零字节 (#176 回归)",
        );
        // reasoning fidelity: 客户端拼接 == 上游拼接.replace(mock, real).
        let client_reasoning = collect_reasoning_deltas(&client_sse);
        let upstream_reasoning = collect_reasoning_deltas(&upstream_sse);
        prop_assert_eq!(
            client_reasoning,
            upstream_reasoning.replace(&mock, &real),
            "STR-6 reasoning restore 违反 (mock={:?}, real={:?})",
            mock,
            real,
        );
        // no mock leak.
        let client_str = String::from_utf8_lossy(&client_sse);
        prop_assert!(
            !client_str.contains(&mock),
            "STR-6: 客户端 SSE 泄漏 mock={:?}\nclient={:?}",
            mock,
            client_str,
        );
    }
}

// ─── 辅助: 跑 StreamTranslate same-proto restore 路径 ──────────────────────

/// 用 same_proto_restore 模式跑一次 StreamTranslate, 返回客户端收到的完整 SSE 字节.
///
/// splits: 任意切分点序列 (与 stream/mod.rs `scan_chunked` 一致: 切分点把 [0,len) 切成
/// |splits|+1 段, 越界 / 乱序由 clamp + 单调化兜底).
fn run_same_proto_restore(
    proto: Protocol,
    map: RedactionMap,
    upstream: &[u8],
    splits: &[usize],
) -> Vec<u8> {
    let mut t = StreamTranslate::new_same_proto_restore(
        proto,
        Box::new(crate::redact::StreamingRestorerSet::new(map)),
    );
    feed_split_translator(&mut t, upstream, splits)
}

/// 按 `splits` 切分点序列把 `upstream` 分段喂给 translator, 收集所有输出 (含 finish()).
///
/// 切分点语义 (与 stream/mod.rs `scan_chunked` 一致): 切分点把 [0,len) 切成 |splits|+1 段,
/// 越界 / 乱序由 clamp + 单调化兜底. 两个 caller (same-proto restore / cross-proto
/// translate) 共用此逻辑, 仅 translator 构造方式不同.
fn feed_split_translator(t: &mut StreamTranslate, upstream: &[u8], splits: &[usize]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut prev = 0usize;
    for &sp in splits {
        let sp = sp.min(upstream.len()).max(prev);
        if sp > prev {
            out.extend_from_slice(&t.feed(&upstream[prev..sp]));
        }
        prev = sp;
    }
    if prev < upstream.len() {
        out.extend_from_slice(&t.feed(&upstream[prev..]));
    }
    out.extend_from_slice(&t.finish());
    out
}

/// 手造一个 RedactionMap { real → mock }. 不走 redact_ir 的 mock 生成路径,
/// 直接指定 mock 值, 让测试对 mock 字符串完全可控 (生成器可以任意选 mock).
fn build_redaction_map(real: &str, mock: &str) -> RedactionMap {
    let mut map = RedactionMap::default();
    map.insert(real.to_string(), mock.to_string(), "id-test")
        .expect("单个 mock 不冲突");
    map
}

// ─── 语义等价断言 (FWD-1 流式弱化形式) ─────────────────────────────────────

/// 断言 `same_proto_restore` 路径的语义等价性 (FWD-1 流式弱化形式):
///
/// 1. **no mock leak** (安全核心): 客户端字节中不含 mock 字符串.
/// 2. **content fidelity**: 客户端 TextDelta 拼接 == 上游 TextDelta 拼接.replace(mock, real).
/// 3. **tool input fidelity**: 客户端 InputJsonDelta 拼接 == 上游拼接.replace(mock, real).
/// 4. **reasoning fidelity** (#176): 客户端 reasoning_content delta 拼接 == 上游拼接
///    .replace(mock, real) (思考原文是 secret 可能泄漏的位置, 必须与 text 同样 restore).
/// 5. **usage output fidelity**: 客户端 usage.output_tokens == 上游 (允许 input_tokens
///    backfill, 故只比较 output_tokens).
///
/// 注: chunk 结构重组 (StreamingRestorer sliding window 拆/并 chunk) 不影响语义,
/// 此断言用拼接后的完整文本比较, 吸收 chunk 边界差异.
fn assert_streaming_restore_fidelity(
    upstream: &[u8],
    client: &[u8],
    real: &str,
    mock: &str,
) -> Result<(), proptest::test_runner::TestCaseError> {
    let upstream_text = collect_text_deltas(upstream);
    let upstream_json = collect_input_json_deltas(upstream);
    let upstream_reasoning = collect_reasoning_deltas(upstream);
    let client_text = collect_text_deltas(client);
    let client_json = collect_input_json_deltas(client);
    let client_reasoning = collect_reasoning_deltas(client);
    let upstream_usage = collect_usage_output_tokens(upstream);
    let client_usage = collect_usage_output_tokens(client);

    // 1. no mock leak (安全核心): 客户端字节中不含 mock.
    let client_str = String::from_utf8_lossy(client);
    prop_assert!(
        !client_str.contains(mock),
        "FWD-1 流式 no-mock-leak 违反: 客户端 SSE 含 mock={:?}\nclient={:?}",
        mock,
        client_str,
    );

    // 2. content fidelity: 客户端 text == 上游 text.replace(mock, real).
    let expected_text = upstream_text.replace(mock, real);
    prop_assert_eq!(
        client_text,
        expected_text,
        "FWD-1 流式 content fidelity 违反\nmock={:?}, real={:?}",
        mock,
        real,
    );

    // 3. tool input fidelity: 客户端 input_json == 上游 input_json.replace(mock, real).
    let expected_json = upstream_json.replace(mock, real);
    prop_assert_eq!(
        client_json,
        expected_json,
        "FWD-1 流式 tool input fidelity 违反\nmock={:?}, real={:?}",
        mock,
        real,
    );

    // 4. reasoning fidelity (#176): 客户端 reasoning == 上游 reasoning.replace(mock, real).
    let expected_reasoning = upstream_reasoning.replace(mock, real);
    prop_assert_eq!(
        client_reasoning,
        expected_reasoning,
        "FWD-1 流式 reasoning fidelity 违反 (STR-6)\nmock={:?}, real={:?}",
        mock,
        real,
    );

    // 5. usage output_tokens fidelity.
    prop_assert_eq!(
        client_usage,
        upstream_usage,
        "FWD-1 流式 usage.output_tokens fidelity 违反",
    );
    Ok(())
}

/// 从 SSE 字节流中收集所有 TextDelta 的 text 内容并拼接.
///
/// 解析每个 SSE 帧 → JSON, 用 OpenAI + Anthropic + Responses reader 兼容的路径提取 text:
/// - OpenAI: `choices[].delta.content` (string)
/// - Anthropic: `delta.text` (在 content_block_delta 里, delta.type=="text_delta")
/// - Responses: `delta` (顶层 type=="response.output_text.delta" 时是 string)
fn collect_text_deltas(sse_bytes: &[u8]) -> String {
    let mut acc = String::new();
    for data in iter_sse_data_payloads(sse_bytes) {
        // Responses: type=response.output_text.delta, delta 是裸 string.
        // (Anthropic 分支的 delta 是 object, Responses 的 string 在 as_object 处
        // 自然落空, 两个分支互不干扰.)
        if data.get("type").and_then(Value::as_str) == Some("response.output_text.delta")
            && let Some(t) = data.get("delta").and_then(Value::as_str)
        {
            acc.push_str(t);
        }
        // Anthropic: event_type=content_block_delta, data.delta.type=text_delta, data.delta.text.
        if let Some(delta) = data.get("delta").and_then(Value::as_object)
            && delta.get("type").and_then(Value::as_str) == Some("text_delta")
            && let Some(t) = delta.get("text").and_then(Value::as_str)
        {
            acc.push_str(t);
        }
        // OpenAI: choices[].delta.content (string).
        if let Some(choices) = data.get("choices").and_then(Value::as_array) {
            for ch in choices {
                if let Some(content) = ch
                    .get("delta")
                    .and_then(|d| d.get("content"))
                    .and_then(Value::as_str)
                {
                    acc.push_str(content);
                }
            }
        }
    }
    acc
}

/// 收集所有 InputJsonDelta 的 partial_json 并拼接 (tool_use arguments).
///
/// - OpenAI: `choices[].delta.tool_calls[].function.arguments` (每个 tool_call 的
///   arguments 是 partial JSON string, 多 chunk 拼接).
/// - Anthropic: `delta.partial_json` (delta.type=="input_json_delta").
/// - Responses: `delta` (顶层 type=="response.function_call_arguments.delta" 时是
///   partial JSON string).
fn collect_input_json_deltas(sse_bytes: &[u8]) -> String {
    let mut acc = String::new();
    for data in iter_sse_data_payloads(sse_bytes) {
        // Responses: type=response.function_call_arguments.delta, delta 是裸 string.
        if data.get("type").and_then(Value::as_str)
            == Some("response.function_call_arguments.delta")
            && let Some(p) = data.get("delta").and_then(Value::as_str)
        {
            acc.push_str(p);
        }
        // Anthropic: delta.partial_json.
        if let Some(delta) = data.get("delta").and_then(Value::as_object)
            && delta.get("type").and_then(Value::as_str) == Some("input_json_delta")
            && let Some(p) = delta.get("partial_json").and_then(Value::as_str)
        {
            acc.push_str(p);
        }
        // OpenAI: choices[].delta.tool_calls[].function.arguments.
        if let Some(choices) = data.get("choices").and_then(Value::as_array) {
            for ch in choices {
                if let Some(tcs) = ch
                    .get("delta")
                    .and_then(|d| d.get("tool_calls"))
                    .and_then(Value::as_array)
                {
                    for tc in tcs {
                        if let Some(args) = tc
                            .get("function")
                            .and_then(|f| f.get("arguments"))
                            .and_then(Value::as_str)
                        {
                            acc.push_str(args);
                        }
                    }
                }
            }
        }
    }
    acc
}

/// 收集所有 reasoning delta 并拼接 (#176, 思考内容).
///
/// - OpenAI: `choices[].delta.reasoning_content` (string).
/// - Responses: `delta` (顶层 type=="response.reasoning_summary_text.delta" 时是
///   string — summary 与思考原文在流式路径归一, D5 已知损失 4).
/// - Anthropic: thinking_delta (本 property 不覆盖 — Anthropic egress 无 reasoning_content,
///   same_proto_restore 的 Anthropic 路径上游不产 reasoning, 恒为空串, 断言自然成立).
fn collect_reasoning_deltas(sse_bytes: &[u8]) -> String {
    let mut acc = String::new();
    for data in iter_sse_data_payloads(sse_bytes) {
        // Responses: type=response.reasoning_summary_text.delta, delta 是裸 string.
        if data.get("type").and_then(Value::as_str) == Some("response.reasoning_summary_text.delta")
            && let Some(rc) = data.get("delta").and_then(Value::as_str)
        {
            acc.push_str(rc);
        }
        if let Some(choices) = data.get("choices").and_then(Value::as_array) {
            for ch in choices {
                if let Some(rc) = ch
                    .get("delta")
                    .and_then(|d| d.get("reasoning_content"))
                    .and_then(Value::as_str)
                {
                    acc.push_str(rc);
                }
            }
        }
    }
    acc
}

/// 收集 usage.output_tokens (terminal usage chunk).
///
/// - OpenAI: `usage.completion_tokens` (顶层 usage).
/// - Anthropic: `usage.output_tokens` (在 message_delta 的 usage 里).
/// - Responses: `response.usage.output_tokens` (终止事件的 response 对象内).
///
/// 取所有 chunk 里 output_tokens 的最大值 (terminal usage chunk 可能晚于 finish_reason
/// chunk 到达, 取最大值避免中间 chunk 的 0 值干扰).
fn collect_usage_output_tokens(sse_bytes: &[u8]) -> u64 {
    let mut max = 0u64;
    for data in iter_sse_data_payloads(sse_bytes) {
        let mut scan_usage = |usage: &Value| {
            if let Some(usage) = usage.as_object() {
                // OpenAI: completion_tokens.
                if let Some(n) = usage.get("completion_tokens").and_then(Value::as_u64) {
                    max = max.max(n);
                }
                // Anthropic / Responses: output_tokens.
                if let Some(n) = usage.get("output_tokens").and_then(Value::as_u64) {
                    max = max.max(n);
                }
            }
        };
        // OpenAI / Anthropic: 顶层 usage.
        if let Some(usage) = data.get("usage") {
            scan_usage(usage);
        }
        // Responses: 终止事件的 response.usage (嵌套).
        if let Some(usage) = data.get("response").and_then(|r| r.get("usage")) {
            scan_usage(usage);
        }
    }
    max
}

/// 遍历 SSE 字节流, 逐帧解析出 data JSON payload.
///
/// 用 [`StreamTranslate`] 的内部 de-frame 逻辑不可 (private), 这里用 `parse_sse_frame`
/// 配合简单的"按空行切分". 假设: 输入是完整 SSE (已 reassembled), 不含跨 chunk 半帧.
/// 非法 JSON 静默跳过 (best-effort, 不 panic — 契约 ROB-1).
fn iter_sse_data_payloads(sse_bytes: &[u8]) -> impl Iterator<Item = Value> {
    // 按 `\n\n` 切帧 (LF; 测试生成的 SSE 都是 LF).
    let text = String::from_utf8_lossy(sse_bytes);
    text.split("\n\n")
        .filter_map(|frame| {
            // 解析帧为 (event_type, data_str).
            let frame_bytes = frame.as_bytes();
            // 补齐末尾 \n\n 让 parse_sse_frame 能识别 (它要求帧以空行结尾; split 已剥).
            let mut padded = frame_bytes.to_vec();
            padded.extend_from_slice(b"\n\n");
            let (_event_type, data_str) = parse_sse_frame(&padded)?;
            if data_str.is_empty() || data_str == "[DONE]" {
                return None;
            }
            serde_json::from_str::<Value>(&data_str).ok()
        })
        .collect::<Vec<_>>()
        .into_iter()
}

// ─── 生成器: 含 mock 的 OpenAI SSE 流 ───────────────────────────────────────

/// 生成 OpenAI SSE 流 (含 mock), 覆盖契约要求的流形态.
///
/// 返回 (sse_bytes, real_secret, mock_string). sse_bytes 中的 text delta 和 tool_use
/// input JSON 片段里都含 mock (跨字段重复, 守卫 FWD-1 L135).
///
/// 流形态覆盖:
/// - reasoning delta (含 mock, 思考阶段; #176 STR-6)
/// - text delta (含 mock, 单 / 跨 chunk 候选)
/// - tool_use 开始 + input JSON 片段 (含 mock)
/// - finish_reason chunk
/// - include_usage chunk (terminal usage, choices=[])
/// - [DONE] 终止符
fn arb_openai_sse_stream_with_mock() -> impl Strategy<Value = (Vec<u8>, String, String)> {
    (
        "[a-z]{4,12}",       // mock 的非空主体
        "[a-z]{4,12}",       // text content 前缀
        "[a-z]{3,8}",        // tool name
        "[a-z]{3,8}",        // tool_call id 主体
        any::<bool>(),       // 是否有 include_usage chunk
        any::<bool>(),       // 是否有 text content
        any::<bool>(),       // 是否有 reasoning 阶段 (#176)
    )
        .prop_map(|(mock_body, text_prefix, tool_name, tc_id_body, has_usage, has_text, has_reasoning)| {
            // mock 与 real 都不含 SSE / JSON 特殊字符, 避免 JSON 转义干扰.
            let mock = format!("MOCK{mock_body}");
            let real = format!("sk-real-{mock_body}");
            let tc_id = format!("call_{tc_id_body}");

            let mut frames: Vec<String> = Vec::new();

            // 帧 0 (可选, #176): 思考阶段首 chunk (MessageStart + BlockStart{ReasoningContent} + ReasoningDelta 含 mock).
            // 覆盖 "mock 跨 reasoning/text 两类 block 重复" 的 restore 场景 (STR-6).
            if has_reasoning {
                frames.push(openai_chunk_frame(&json!({
                    "id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,
                    "model":"gpt-4o",
                    "choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":format!("thinking about {mock}...")},"finish_reason":Value::Null}]
                })));
            }

            // 帧 1: 第一个 chunk (fan-out: MessageStart + BlockStart + BlockDelta).
            let first_content = if has_text {
                format!("{text_prefix} {mock} tail")
            } else {
                String::new()
            };
            let first_delta = if first_content.is_empty() {
                json!({"role":"assistant"})
            } else {
                json!({"role":"assistant","content":first_content})
            };
            frames.push(openai_chunk_frame(&json!({
                "id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,
                "model":"gpt-4o",
                "choices":[{"index":0,"delta":first_delta,"finish_reason":Value::Null}]
            })));

            // 帧 2 (可选): 第二个 text delta (模拟跨 chunk 的 text + mock).
            if has_text {
                frames.push(openai_chunk_frame(&json!({
                    "id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,
                    "model":"gpt-4o",
                    "choices":[{"index":0,"delta":{"content":format!("more {mock} here")},"finish_reason":Value::Null}]
                })));
            }

            // 帧 3: tool_call 开始 (index=1, id+name).
            frames.push(openai_chunk_frame(&json!({
                "id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,
                "model":"gpt-4o",
                "choices":[{"index":0,"delta":{
                    "role":"assistant","content":Value::Null,
                    "tool_calls":[{"index":1,"id":tc_id,"type":"function",
                        "function":{"name":tool_name,"arguments":""}}]
                },"finish_reason":Value::Null}]
            })));

            // 帧 4: tool_call arguments delta (partial JSON, 含 mock).
            // OpenAI arguments 是 JSON 字符串, mock 注入到合法 JSON 的 string value.
            let partial = format!(r#"{{"secret":"{mock}","x":1}}"#);
            frames.push(openai_chunk_frame(&json!({
                "id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,
                "model":"gpt-4o",
                "choices":[{"index":0,"delta":{
                    "tool_calls":[{"index":1,"function":{"arguments":partial}}]
                },"finish_reason":Value::Null}]
            })));

            // 帧 5: finish_reason chunk (无 usage).
            frames.push(openai_chunk_frame(&json!({
                "id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,
                "model":"gpt-4o",
                "choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]
            })));

            // 帧 6 (可选): include_usage chunk (terminal usage, choices=[]).
            if has_usage {
                frames.push(openai_chunk_frame(&json!({
                    "id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,
                    "model":"gpt-4o",
                    "choices":[],
                    "usage":{"prompt_tokens":15,"completion_tokens":3,"total_tokens":18}
                })));
            }

            // 帧 7: [DONE] 终止符.
            frames.push("data: [DONE]\n\n".to_string());

            let sse: String = frames.concat();
            (sse.into_bytes(), real, mock)
        })
}

/// 生成 Anthropic SSE 流 (含 mock).
///
/// 流形态: message_start → content_block_start(text) → text_delta(含 mock) →
/// content_block_stop → content_block_start(tool_use) → input_json_delta(含 mock) →
/// content_block_stop → message_delta(stop_reason+usage) → message_stop.
fn arb_anthropic_sse_stream_with_mock() -> impl Strategy<Value = (Vec<u8>, String, String)> {
    (
        "[a-z]{4,12}",          // mock 的非空主体
        "[a-z]{4,12}",          // text content
        "[a-z]{3,8}",           // tool name
        "toolu_[a-z0-9]{5,10}", // tool_use id
        any::<bool>(),          // 是否有第二个 text delta
    )
        .prop_map(
            |(mock_body, text_prefix, tool_name, tu_id, has_second_text)| {
                let mock = format!("MOCK{mock_body}");
                let real = format!("sk-real-{mock_body}");

                let mut frames: Vec<String> = Vec::new();

                // message_start (含 input usage).
                frames.push(anthropic_frame("message_start", &json!({
                "type":"message_start",
                "message":{
                    "id":"msg_01test","type":"message","role":"assistant","content":[],
                    "model":"claude-3","stop_reason":Value::Null,"stop_sequence":Value::Null,
                    "usage":{"input_tokens":10,"output_tokens":1}
                }
            })));

                // content_block_start (text block, index=0).
                frames.push(anthropic_frame(
                    "content_block_start",
                    &json!({
                        "type":"content_block_start","index":0,
                        "content_block":{"type":"text","text":""}
                    }),
                ));

                // text_delta (含 mock).
                frames.push(anthropic_frame(
                    "content_block_delta",
                    &json!({
                        "type":"content_block_delta","index":0,
                        "delta":{"type":"text_delta","text":format!("{text_prefix} {mock} tail")}
                    }),
                ));

                // 第二个 text_delta (可选, 跨 chunk 的 text + mock).
                if has_second_text {
                    frames.push(anthropic_frame(
                        "content_block_delta",
                        &json!({
                            "type":"content_block_delta","index":0,
                            "delta":{"type":"text_delta","text":format!("more {mock} here")}
                        }),
                    ));
                }

                // content_block_stop (index=0).
                frames.push(anthropic_frame(
                    "content_block_stop",
                    &json!({
                        "type":"content_block_stop","index":0
                    }),
                ));

                // content_block_start (tool_use, index=1).
                frames.push(anthropic_frame(
                    "content_block_start",
                    &json!({
                        "type":"content_block_start","index":1,
                        "content_block":{"type":"tool_use","id":tu_id,"name":tool_name,"input":{}}
                    }),
                ));

                // input_json_delta (含 mock, partial JSON).
                let partial = format!(r#"{{"secret":"{mock}","x":1}}"#);
                frames.push(anthropic_frame(
                    "content_block_delta",
                    &json!({
                        "type":"content_block_delta","index":1,
                        "delta":{"type":"input_json_delta","partial_json":partial}
                    }),
                ));

                // content_block_stop (index=1).
                frames.push(anthropic_frame(
                    "content_block_stop",
                    &json!({
                        "type":"content_block_stop","index":1
                    }),
                ));

                // message_delta (stop_reason + usage).
                frames.push(anthropic_frame(
                    "message_delta",
                    &json!({
                        "type":"message_delta",
                        "delta":{"stop_reason":"tool_use","stop_sequence":Value::Null},
                        "usage":{"output_tokens":42}
                    }),
                ));

                // message_stop.
                frames.push(anthropic_frame(
                    "message_stop",
                    &json!({"type":"message_stop"}),
                ));

                let sse: String = frames.concat();
                (sse.into_bytes(), real, mock)
            },
        )
}

// ─── SSE 帧工具 ─────────────────────────────────────────────────────────────

/// 把一个 JSON 封装为 OpenAI 风格的 SSE 帧 (`data: {...}\n\n`).
fn openai_chunk_frame(data: &Value) -> String {
    format!("data: {data}\n\n")
}

/// 把一个 JSON 封装为 Anthropic 风格的 SSE 帧 (`event: {type}\ndata: {...}\n\n`).
fn anthropic_frame(event_type: &str, data: &Value) -> String {
    format!("event: {event_type}\ndata: {data}\n\n")
}

// ─── 生成器: 含 mock 的 Responses SSE 流 (T5) ───────────────────────────────
//
// 形态对齐官方 Responses 流式文档 + responses.rs tests 的 official_*_frames fixture
// (双行帧 `event: <type>\ndata: <json>\n\n`). 流骨架:
//
//   response.created
//     → (可选 reasoning item: added → summary part added → summary delta 含 mock
//        → done 族 → item done)
//     → message item added → content_part added → text delta×2 (含 mock)
//        → done 族 (output_text.done / content_part.done / output_item.done)
//     → function_call item added → args delta (含 mock) → done 族
//     → response.completed (usage 可选)
//
// 生成器同步构造 expected_scan (StreamScan(Responses) snapshot 的预期 IrResponse),
// 作为 STR-2 property 的 oracle — 与 stream/mod.rs `arb_openai_sse_with_expected`
// 同型 (生成器是两边语义的唯一真相, 回避 SSE 字节 vs 非流式 JSON 的形态不可比).

/// 生成 Responses SSE 流 (含 mock), 覆盖契约要求的流形态.
///
/// 返回 (sse_bytes, real_secret, mock_string, expected_scan). mock 出现在 reasoning
/// summary delta / text delta / tool args delta 三类载体 (跨字段重复, FWD-1 生成器
/// 覆盖要求), expected_scan 是与该 SSE 语义等价的 IrResponse (确定性构造).
///
/// 维度 (对齐 openai/anthropic 生成器): mock 主体 / 文本前缀 / tool name / call id /
/// 是否有 usage / 是否有文本 / 是否有 reasoning.
///
/// 已排除维度 (模块头 "已声明缺口"): 终止事件只产 response.completed — incomplete/
/// failed 形态不进生成器 (stop_reason=Other 往返漂移, 由 responses.rs 确定性单测锁定).
/// 注: 只产 summary delta 变体 (`reasoning_summary_text.delta`), 不产思考原文变体
/// (`reasoning_text.delta`) — 两者共享同一 reader 分支 (归一为 ReasoningDelta),
/// 变体差异由 responses.rs 单测覆盖.
fn arb_responses_sse_stream_with_mock()
-> impl Strategy<Value = (Vec<u8>, String, String, IrResponse)> {
    (
        "[a-z]{4,12}", // mock 的非空主体
        "[a-z]{4,12}", // text content 前缀
        "[a-z]{3,8}",  // tool name
        "[a-z]{3,8}",  // call_id 主体
        any::<bool>(), // response.completed 是否携带 usage
        any::<bool>(), // 是否有 text delta
        any::<bool>(), // 是否有 reasoning 阶段
    )
        .prop_map(
            |(
                mock_body,
                text_prefix,
                tool_name,
                call_id_body,
                has_usage,
                has_text,
                has_reasoning,
            )| {
                // mock 与 real 都不含 SSE/JSON 特殊字符, 避免 JSON 转义干扰 (与
                // openai/anthropic 生成器同款约束).
                let mock = format!("MOCK{mock_body}");
                let real = format!("sk-real-{mock_body}");
                let call_id = format!("call_{call_id_body}");
                // 身份/时戳常量单一来源 (wire JSON 与 expected IrResponse 共用, 与
                // 下方 u_in/u_out 同型 — 两处手写漂移只会造成 STR-2 假红).
                let (resp_id, resp_model, resp_created) = ("resp_1", "gpt-5", 1700000000u64);

                let mut frames: Vec<String> = Vec::new();
                let mut expected_blocks: Vec<IrBlock> = Vec::new();
                // output_index 游标 (Responses 的 output_index 是 item 级序号).
                let mut out_idx = 0u64;

                // 帧 0: response.created (response 骨架, usage=null — 官方形态:
                // 完整 usage 只在 completed 携带).
                frames.push(responses_frame(
                    "response.created",
                    &json!({
                        "type": "response.created",
                        "response": {
                            "id": resp_id, "object": "response", "created_at": resp_created,
                            "model": resp_model, "status": "in_progress", "output": [], "usage": null,
                        },
                    }),
                ));

                // 可选 reasoning item (官方 reasoning 场景形态; reader 只消费
                // summary delta, part/done 帧被忽略 — 覆盖 "忽略路径不吞内容").
                if has_reasoning {
                    let reasoning_text = format!("think {mock} now");
                    frames.push(responses_frame(
                        "response.output_item.added",
                        &json!({
                            "type": "response.output_item.added", "output_index": out_idx,
                            "item": {"id": "rs_1", "type": "reasoning",
                                      "status": "in_progress", "summary": []},
                        }),
                    ));
                    frames.push(responses_frame(
                        "response.reasoning_summary_part.added",
                        &json!({
                            "type": "response.reasoning_summary_part.added", "item_id": "rs_1",
                            "output_index": out_idx, "summary_index": 0,
                            "part": {"type": "summary_text", "text": ""},
                        }),
                    ));
                    frames.push(responses_frame(
                        "response.reasoning_summary_text.delta",
                        &json!({
                            "type": "response.reasoning_summary_text.delta", "item_id": "rs_1",
                            "output_index": out_idx, "summary_index": 0, "delta": reasoning_text,
                        }),
                    ));
                    frames.push(responses_frame(
                        "response.reasoning_summary_text.done",
                        &json!({
                            "type": "response.reasoning_summary_text.done", "item_id": "rs_1",
                            "output_index": out_idx, "summary_index": 0, "text": reasoning_text,
                        }),
                    ));
                    frames.push(responses_frame("response.output_item.done", &json!({
                        "type": "response.output_item.done", "output_index": out_idx,
                        "item": {"id": "rs_1", "type": "reasoning", "status": "completed",
                                  "summary": [{"type": "summary_text", "text": reasoning_text}]},
                    })));
                    // 流式归一: summary delta → IrBlock::ReasoningContent (非流式是
                    // Reasoning{summary} 双变体, 见模块头已声明缺口 1).
                    expected_blocks.push(IrBlock::ReasoningContent {
                        text: reasoning_text,
                    });
                    out_idx += 1;
                }

                // message item: added → part added → text delta×2 (含 mock) → done 族.
                // full_text 由两个 delta 变量拼接派生 (与 arb_openai_sse_with_expected
                // 的 full_text = t1 + t2 同款结构化 oracle — done 帧全量 == delta 拼接
                // 是构造即正确, 不靠肉眼维护).
                let text_d1 = format!("{text_prefix} {mock} tail");
                let text_d2 = format!("more {mock} here");
                let full_text = if has_text {
                    format!("{text_d1}{text_d2}")
                } else {
                    String::new()
                };
                frames.push(responses_frame(
                    "response.output_item.added",
                    &json!({
                        "type": "response.output_item.added", "output_index": out_idx,
                        "item": {"id": "msg_1", "type": "message", "status": "in_progress",
                                  "role": "assistant", "content": []},
                    }),
                ));
                frames.push(responses_frame(
                    "response.content_part.added",
                    &json!({
                        "type": "response.content_part.added", "item_id": "msg_1",
                        "output_index": out_idx, "content_index": 0,
                        "part": {"type": "output_text", "text": "", "annotations": []},
                    }),
                ));
                if has_text {
                    frames.push(responses_frame(
                        "response.output_text.delta",
                        &json!({
                            "type": "response.output_text.delta", "item_id": "msg_1",
                            "output_index": out_idx, "content_index": 0,
                            "delta": text_d1,
                        }),
                    ));
                    frames.push(responses_frame(
                        "response.output_text.delta",
                        &json!({
                            "type": "response.output_text.delta", "item_id": "msg_1",
                            "output_index": out_idx, "content_index": 0,
                            "delta": text_d2,
                        }),
                    ));
                    expected_blocks.push(IrBlock::Text {
                        text: full_text.clone(),
                    });
                }
                // done 族全量帧 (text="" 时也发 — 覆盖空内容 block 的关闭路径;
                // reader 忽略之, 内容已由 delta 流入 IR).
                frames.push(responses_frame(
                    "response.output_text.done",
                    &json!({
                        "type": "response.output_text.done", "item_id": "msg_1",
                        "output_index": out_idx, "content_index": 0, "text": full_text,
                    }),
                ));
                frames.push(responses_frame(
                    "response.content_part.done",
                    &json!({
                        "type": "response.content_part.done", "item_id": "msg_1",
                        "output_index": out_idx, "content_index": 0,
                        "part": {"type": "output_text", "text": full_text, "annotations": []},
                    }),
                ));
                frames.push(responses_frame(
                    "response.output_item.done",
                    &json!({
                        "type": "response.output_item.done", "output_index": out_idx,
                        "item": {"id": "msg_1", "type": "message", "status": "completed",
                                  "role": "assistant",
                                  "content": [{"type": "output_text", "text": full_text}]},
                    }),
                ));
                out_idx += 1;

                // function_call item (恒出现, 与 openai/anthropic 生成器对齐):
                // added → args delta (partial JSON 含 mock) → done 族.
                let args = format!(r#"{{"secret":"{mock}","x":1}}"#);
                frames.push(responses_frame(
                    "response.output_item.added",
                    &json!({
                        "type": "response.output_item.added", "output_index": out_idx,
                        "item": {"id": "fc_1", "call_id": call_id, "type": "function_call",
                                  "name": tool_name, "arguments": "", "status": "in_progress"},
                    }),
                ));
                frames.push(responses_frame(
                    "response.function_call_arguments.delta",
                    &json!({
                        "type": "response.function_call_arguments.delta", "item_id": "fc_1",
                        "output_index": out_idx, "delta": args,
                    }),
                ));
                frames.push(responses_frame(
                    "response.function_call_arguments.done",
                    &json!({
                        "type": "response.function_call_arguments.done", "item_id": "fc_1",
                        "output_index": out_idx, "arguments": args,
                    }),
                ));
                frames.push(responses_frame(
                    "response.output_item.done",
                    &json!({
                        "type": "response.output_item.done", "output_index": out_idx,
                        "item": {"id": "fc_1", "call_id": call_id, "type": "function_call",
                                  "name": tool_name, "arguments": args, "status": "completed"},
                    }),
                ));
                let tool_input: Value = serde_json::from_str(&args).unwrap_or_else(|_| json!({}));
                expected_blocks.push(IrBlock::ToolUse {
                    id: call_id,
                    name: tool_name,
                    input: tool_input,
                });

                // 终止: response.completed (usage 可选; has_usage=false 时 null —
                // usage presence 的字节形态不在断言范围, 见模块头已声明缺口 2).
                // 常量单一来源 (wire JSON 与 expected IrUsage 共用, 与
                // arb_openai_sse_with_expected 的 usage_input/output 派生同型).
                let (u_in, u_out) = (15u64, 7u64);
                let usage_json = if has_usage {
                    json!({"input_tokens": u_in, "output_tokens": u_out,
                           "total_tokens": u_in + u_out})
                } else {
                    Value::Null
                };
                frames.push(responses_frame(
                    "response.completed",
                    &json!({
                        "type": "response.completed",
                        "response": {"id": resp_id, "status": "completed", "usage": usage_json},
                    }),
                ));

                // 预期 snapshot: function_call 恒出现 → 流式 reader 推断 ToolUse.
                let expected = IrResponse {
                    content: expected_blocks,
                    stop_reason: Some(IrStopReason::ToolUse),
                    stop_sequence: None,
                    usage: if has_usage {
                        IrUsage {
                            input_tokens: u_in,
                            output_tokens: u_out,
                            ..Default::default()
                        }
                    } else {
                        IrUsage::default()
                    },
                    usage_present: has_usage,
                    model: Some(resp_model.to_string()),
                    id: Some(resp_id.to_string()),
                    created: Some(resp_created),
                };

                let sse: String = frames.concat();
                (sse.into_bytes(), real, mock, expected)
            },
        )
}

/// 把一个 JSON 封装为 Responses 风格的 SSE 帧 (双行, 与 `anthropic_frame` 同形态;
/// Responses 的 event 名带 `response.` 前缀, 独立函数保留语义可读性).
fn responses_frame(event_type: &str, data: &Value) -> String {
    format!("event: {event_type}\ndata: {data}\n\n")
}

// ─── Responses STR-1 / STR-2 property (T5) ─────────────────────────────────

proptest! {
    /// STR-1: StreamTranslate (Responses 同协议 restore, 含 mock restore) 的
    /// chunk 边界透明 — 任意切分 feed 的累积输出 (feed + finish) == 一次性 feed,
    /// writer 合成的 `resp_<base62>` id / `created_at` 归一化后字节级比较.
    ///
    /// 与 stream/mod.rs 的 `prop_stream_translate_chunk_split_equivalence` (OpenAI)
    /// 同型; Responses 的 volatile 字段是 `"id":"resp_..."` + `"created_at":<epoch>`
    /// (MessageStart id/created 被 translate 层剥离后由 writer 合成).
    ///
    /// 切分不改变语义的机理: reassembly 保证只有完整帧才进 reader, IR 事件序列与
    /// 切分无关; restore hook 按事件序列确定性处理 (滑窗 hold 状态是 delta 序列的
    /// 确定性函数), 故归一化后输出字节恒等.
    #[test]
    fn prop_responses_translate_chunk_split_equivalence(
        case in arb_responses_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock, _expected_scan) = case;

        // 一次性 feed baseline (feed + finish).
        let mut whole = StreamTranslate::new_same_proto_restore(
            Protocol::OpenAIResponses,
            Box::new(crate::redact::StreamingRestorerSet::new(
                build_redaction_map(&real, &mock),
            )),
        );
        let mut baseline = whole.feed(&upstream_sse);
        baseline.extend_from_slice(&whole.finish());

        // 任意切分 feed (run_same_proto_restore 内含 finish).
        let chunked = run_same_proto_restore(
            Protocol::OpenAIResponses,
            build_redaction_map(&real, &mock),
            &upstream_sse,
            &splits,
        );

        let baseline_norm = normalize_responses_sse_volatile(&String::from_utf8_lossy(&baseline));
        // 非空守卫: 排除 "writer 整体回归为零帧输出" 的平凡通过 (空 == 空).
        prop_assert!(
            !baseline_norm.is_empty(),
            "STR-1 (Responses): baseline 零输出 (writer 整体回归?)"
        );
        let chunked_norm = normalize_responses_sse_volatile(&String::from_utf8_lossy(&chunked));
        prop_assert_eq!(
            &baseline_norm, &chunked_norm,
            "Responses StreamTranslate chunk-boundary violation for splits {:?}\n\
             baseline(norm): {}\n\
             chunked(norm):  {}",
            splits, baseline_norm, chunked_norm,
        );
    }

    /// STR-1: StreamScan(Responses) 的 chunk 边界透明 — 任意切分 feed 的 snapshot
    /// == 一次性 feed 的 snapshot (IrResponse 严格相等, 无 volatile 字段 — id/model
    /// 来自上游 resp_1 / gpt-5, 不经 writer 合成).
    #[test]
    fn prop_responses_scan_chunk_split_equivalence(
        case in arb_responses_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, _real, _mock, _expected_scan) = case;

        let mut whole = StreamScan::new(Protocol::OpenAIResponses);
        whole.feed(&upstream_sse);
        let baseline = whole.snapshot();

        let chunked = scan_responses_chunked(&splits, &upstream_sse);

        prop_assert_eq!(
            baseline, chunked,
            "Responses StreamScan chunk-boundary violation for splits {:?}",
            splits
        );
    }

    /// STR-2 (Responses, 生成器预期形式): Responses SSE 流经 StreamScan 累积的
    /// snapshot == 生成器同步构造的预期 IrResponse — 覆盖 reasoning (ReasoningContent
    /// 归一) / text 跨 delta 累积 / tool_use args JSON 拼接 / usage_present 四个维度.
    ///
    /// 字面 "scan ≡ 非流式 read_response" 的两个已知建模分歧 (stop_reason 推断
    /// 不对称 / reasoning 双变体) 见模块头 "已声明缺口" 1.
    #[test]
    fn prop_responses_stream_scan_matches_expected_ir(
        case in arb_responses_sse_stream_with_mock()
    ) {
        let (sse, _real, _mock, expected) = case;
        let mut scan = StreamScan::new(Protocol::OpenAIResponses);
        scan.feed(&sse);
        let got = scan.snapshot();
        prop_assert_eq!(
            &got, &expected,
            "STR-2 (Responses): StreamScan snapshot != 生成器预期 IrResponse"
        );
    }
}

// ─── Responses STR-1/STR-2 辅助 ─────────────────────────────────────────────

/// 把字节流按切分点序列分段喂入 StreamScan(Responses), 返回最终 snapshot
/// (与 stream/mod.rs `scan_chunked` 同一切分语义 — 那里硬编码 OpenAI, 这里
/// Responses 版本留在本模块避免跨 test 模块引用).
fn scan_responses_chunked(splits: &[usize], full: &[u8]) -> IrResponse {
    let mut scan = StreamScan::new(Protocol::OpenAIResponses);
    let mut prev = 0usize;
    for &sp in splits {
        let sp = sp.min(full.len()).max(prev);
        if sp > prev {
            scan.feed(&full[prev..sp]);
        }
        prev = sp;
    }
    if prev < full.len() {
        scan.feed(&full[prev..]);
    }
    scan.snapshot()
}

/// 把 Responses SSE 输出里 writer 合成的时敏/随机字段归一化, 使输出可做字节级比较
/// (与 stream/mod.rs `normalize_sse_volatile_fields` 同型, 字段集换为 Responses 的):
///
/// - `"id":"resp_<base62>"` → `"id":"resp_<n>` (writer `synth_response_id` 每次随机;
///   MessageStart 的 id 被 translate 层剥离后由 writer 合成, fixture 的 resp_1 不会
///   出现在输出 — 但统一归一化无害: 归一化函数是输入的确定性函数)
/// - `"created_at":<digits>` → `"created_at":<n>` (writer `current_epoch` 时敏)
fn normalize_responses_sse_volatile(input: &str) -> String {
    // Pass 1: `"id":"resp_<payload>"` → `"id":"resp_<n>`.
    const ID_PREFIX: &str = "\"id\":\"resp_";
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find(ID_PREFIX) {
        out.push_str(&rest[..start]);
        out.push_str("\"id\":\"resp_<n>");
        let after = &rest[start + ID_PREFIX.len()..];
        match after.find('"') {
            Some(end) => rest = &after[end..],
            None => {
                out.push_str(after);
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);

    // Pass 2: `"created_at":<digits>` → `"created_at":<n>`.
    const CREATED_PREFIX: &str = "\"created_at\":";
    let mut out2 = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(start) = rest.find(CREATED_PREFIX) {
        out2.push_str(&rest[..start]);
        out2.push_str("\"created_at\":<n>");
        let after = &rest[start + CREATED_PREFIX.len()..];
        let end = after
            .bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(after.len());
        rest = &after[end..];
    }
    out2.push_str(rest);
    out2
}

// ─── 跨协议流式翻译 property (STR-1 × FWD-3, RED-7 交集) ────────────────
//
// # 背景 (与同协议 restore property 的差异)
//
// 同协议 restore property (本文件上半部分) 守卫 `StreamTranslate::new_same_proto_restore`
// 路径: egress SSE → IR events → StreamingRestorer (mock→real) → ingress SSE.
// 该路径 ingress == egress, 不做协议翻译, 只做 restore.
//
// 跨协议翻译路径 (`StreamTranslate::new_cross_proto`, ingress != egress) 已接入
// 生产 dispatch (`cross_proto_forward` 的流式分支): egress SSE → IR events →
// (可选 restore hook) → ingress SSE. 纯翻译 (无 redact) 的内容保真由本段
// property 守卫; + restore 的 no-mock-leak 由
// `prop_cross_proto_streaming_no_mock_leak_dispatch_integrated` 守卫 (端到端
// HTTP 层再由 `tests/integration.rs` 的 `cross_protocol_streaming_*` 覆盖).

proptest! {
    /// STR-1 × FWD-3: OpenAI egress SSE → Anthropic ingress SSE, 任意 chunk 切分下
    /// 内容保真.
    ///
    /// 守卫:
    /// - content fidelity: 客户端 (Anthropic) text_delta 拼接 == 上游 (OpenAI)
    ///   choices[].delta.content 拼接.
    /// - tool input fidelity: 客户端 input_json_delta 拼接 == 上游 tool_calls[].arguments 拼接.
    /// - usage output fidelity: output_tokens 透传.
    ///
    /// 注: 此 property 不守卫 "no mock leak" — 纯翻译模式不做 restore, 上游若回显
    /// mock 则客户端会看到. no-mock-leak 的 property 见
    /// `prop_cross_proto_streaming_no_mock_leak_dispatch_integrated` (+restore,
    /// 生产 dispatch 同型构造).
    #[test]
    fn prop_cross_proto_stream_openai_to_anthropic(
        case in arb_openai_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, _real, _mock) = case;
        // 跨协议翻译: OpenAI egress → Anthropic ingress.
        let client_sse = run_cross_proto_translate(
            Protocol::Anthropic, // ingress
            Protocol::OpenAI,    // egress
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_streaming_content_fidelity(&upstream_sse, &client_sse)?;
    }

    /// STR-1 × FWD-3: Anthropic egress SSE → OpenAI ingress SSE, 任意 chunk 切分下
    /// 内容保真. (反向)
    #[test]
    fn prop_cross_proto_stream_anthropic_to_openai(
        case in arb_anthropic_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, _real, _mock) = case;
        let client_sse = run_cross_proto_translate(
            Protocol::OpenAI,    // ingress
            Protocol::Anthropic, // egress
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_streaming_content_fidelity(&upstream_sse, &client_sse)?;
    }

    /// STR-1 极端切分: 1-byte 切分 (OpenAI → Anthropic).
    ///
    /// 覆盖 StreamTranslate 跨协议模式的 reassembly buffer 在 1-byte 切分下的正确性
    /// (与同协议 restore 路径的 `prop_streaming_response_byte_by_byte_*` 对称).
    #[test]
    fn prop_cross_proto_stream_byte_by_byte_openai_to_anthropic(
        case in arb_openai_sse_stream_with_mock()
    ) {
        let (upstream_sse, _real, _mock) = case;
        let splits: Vec<usize> = (1..=upstream_sse.len()).collect();
        let client_sse = run_cross_proto_translate(
            Protocol::Anthropic,
            Protocol::OpenAI,
            &upstream_sse,
            &splits,
        );
        assert_cross_proto_streaming_content_fidelity(&upstream_sse, &client_sse)?;
    }

    /// STR-1 极端切分: 1-byte 切分 (Anthropic → OpenAI).
    #[test]
    fn prop_cross_proto_stream_byte_by_byte_anthropic_to_openai(
        case in arb_anthropic_sse_stream_with_mock()
    ) {
        let (upstream_sse, _real, _mock) = case;
        let splits: Vec<usize> = (1..=upstream_sse.len()).collect();
        let client_sse = run_cross_proto_translate(
            Protocol::OpenAI,
            Protocol::Anthropic,
            &upstream_sse,
            &splits,
        );
        assert_cross_proto_streaming_content_fidelity(&upstream_sse, &client_sse)?;
    }

    /// STR-1 × FWD-3: Responses egress SSE → OpenAI ingress SSE, 任意 chunk 切分下
    /// 内容保真 (T5: Responses 纳入跨协议流式契约).
    ///
    /// reasoning 经 OpenAI ingress 以 `reasoning_content` delta 存活 (#176 STR-6),
    /// 不在跨协议断言范围 (与 o⇄a 组合一致 — 跨协议断言集只比较 text / tool /
    /// usage 四维).
    #[test]
    fn prop_cross_proto_stream_responses_to_openai(
        case in arb_responses_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, _real, _mock, _expected_scan) = case;
        let client_sse = run_cross_proto_translate(
            Protocol::OpenAI,          // ingress
            Protocol::OpenAIResponses, // egress
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_streaming_content_fidelity(&upstream_sse, &client_sse)?;
    }

    /// STR-1 × FWD-3: OpenAI egress SSE → Responses ingress SSE (反向, T5).
    ///
    /// 覆盖 Responses ingress writer 的有状态合成: BlockStart→item+part 两帧 /
    /// BlockStop→done 族全量帧 / deferred MessageStop (post-stop usage 先于
    /// response.completed) — 语义保真由协议无关收集器断言.
    #[test]
    fn prop_cross_proto_stream_openai_to_responses(
        case in arb_openai_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, _real, _mock) = case;
        let client_sse = run_cross_proto_translate(
            Protocol::OpenAIResponses, // ingress
            Protocol::OpenAI,          // egress
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_streaming_content_fidelity(&upstream_sse, &client_sse)?;
    }

    /// STR-1 × FWD-3: Responses egress SSE → Anthropic ingress SSE (T5).
    ///
    /// 执行到 Anthropic ingress 对 ReasoningContent 的显式丢弃路径 (STR-6 裁决:
    /// thinking signature 无法合成 → 跳过 block 配对过滤 — reasoning 不在跨协议
    /// 断言集内, 丢弃行为本身由 translate.rs 确定性单测锁定), text / tool / usage
    /// 保真由断言集守卫.
    #[test]
    fn prop_cross_proto_stream_responses_to_anthropic(
        case in arb_responses_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, _real, _mock, _expected_scan) = case;
        let client_sse = run_cross_proto_translate(
            Protocol::Anthropic,        // ingress
            Protocol::OpenAIResponses, // egress
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_streaming_content_fidelity(&upstream_sse, &client_sse)?;
    }

    /// STR-1 × FWD-3: Anthropic egress SSE → Responses ingress SSE (反向, T5).
    #[test]
    fn prop_cross_proto_stream_anthropic_to_responses(
        case in arb_anthropic_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, _real, _mock) = case;
        let client_sse = run_cross_proto_translate(
            Protocol::OpenAIResponses, // ingress
            Protocol::Anthropic,       // egress
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_streaming_content_fidelity(&upstream_sse, &client_sse)?;
    }

    /// STR-1 极端切分: 1-byte 切分 (Responses → OpenAI, T5).
    ///
    /// 覆盖双行帧 (event: + data:) 在 1-byte 切分下的重组 + Responses reader
    /// 状态机 (items / part_ir_index 映射) 的跨 chunk 稳定性.
    #[test]
    fn prop_cross_proto_stream_byte_by_byte_responses_to_openai(
        case in arb_responses_sse_stream_with_mock()
    ) {
        let (upstream_sse, _real, _mock, _expected_scan) = case;
        let splits: Vec<usize> = (1..=upstream_sse.len()).collect();
        let client_sse = run_cross_proto_translate(
            Protocol::OpenAI,
            Protocol::OpenAIResponses,
            &upstream_sse,
            &splits,
        );
        assert_cross_proto_streaming_content_fidelity(&upstream_sse, &client_sse)?;
    }
}

// STR-1 × FWD-3 × RED-7: 跨协议流式 + redact restore 端到端 no-mock-leak.
//
// dispatch 已接入跨协议流式翻译 (`cross_proto_forward` 不再对 stream=true 返回
// 501), StreamTranslate 跨协议模式支持 restore hook 注入 — 本 property 用与生产
// dispatch 相同的构造方式 (`StreamTranslate::new_cross_proto` + `StreamingRestorerSet`)
// 直接验证 codec 层管线, 端到端 (HTTP 层) 覆盖见 `tests/integration.rs` 的
// `cross_protocol_streaming_*` 系列.
//
// 守卫:
// - 客户端 SSE 不含 mock 字符串 (no mock leak, 安全核心).
// - 客户端 content / tool input == 上游对应拼接 `.replace(mock, real)`.
// - tool_use id/name / usage output_tokens 保真 (透传).
proptest! {
    #[test]
    fn prop_cross_proto_streaming_no_mock_leak_dispatch_integrated(
        case in arb_openai_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock) = case;
        let map = build_redaction_map(&real, &mock);
        // 跨协议 + restore: OpenAI egress → Anthropic ingress (生产 dispatch 同型).
        let client_sse = run_cross_proto_restore(
            Protocol::Anthropic, // ingress
            Protocol::OpenAI,    // egress
            map,
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// 反向: Anthropic egress → OpenAI ingress + restore.
    #[test]
    fn prop_cross_proto_streaming_no_mock_leak_dispatch_integrated_reverse(
        case in arb_anthropic_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock) = case;
        let map = build_redaction_map(&real, &mock);
        let client_sse = run_cross_proto_restore(
            Protocol::OpenAI,    // ingress
            Protocol::Anthropic, // egress
            map,
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// RED-7 (T5): Responses egress → OpenAI ingress + restore — mock 在 reasoning
    /// summary / text / tool args 三类载体中注入, 客户端字节流不得含 mock.
    #[test]
    fn prop_cross_proto_streaming_no_mock_leak_responses_egress(
        case in arb_responses_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock, _expected_scan) = case;
        let map = build_redaction_map(&real, &mock);
        let client_sse = run_cross_proto_restore(
            Protocol::OpenAI,          // ingress
            Protocol::OpenAIResponses, // egress
            map,
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// RED-7 (T5): OpenAI egress → Responses ingress + restore — Responses writer
    /// 的 done 族帧 (output_text.done / response.completed) 携带 restore 后的全量
    /// 内容, no-mock-leak 扫描整条客户端字节流覆盖该重合成路径.
    #[test]
    fn prop_cross_proto_streaming_no_mock_leak_responses_ingress(
        case in arb_openai_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock) = case;
        let map = build_redaction_map(&real, &mock);
        let client_sse = run_cross_proto_restore(
            Protocol::OpenAIResponses, // ingress
            Protocol::OpenAI,          // egress
            map,
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// RED-7 (T5): Responses egress → Anthropic ingress + restore — reasoning 块
    /// 被 Anthropic ingress 显式丢弃 (STR-6 裁决), 其中的 mock 一并消失; text /
    /// tool args 中的 mock 必须被 restore (无泄漏 + 内容保真).
    #[test]
    fn prop_cross_proto_streaming_no_mock_leak_responses_to_anthropic(
        case in arb_responses_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock, _expected_scan) = case;
        let map = build_redaction_map(&real, &mock);
        let client_sse = run_cross_proto_restore(
            Protocol::Anthropic,        // ingress
            Protocol::OpenAIResponses, // egress
            map,
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }

    /// RED-7 (T5): Anthropic egress → Responses ingress + restore (反向).
    #[test]
    fn prop_cross_proto_streaming_no_mock_leak_anthropic_to_responses(
        case in arb_anthropic_sse_stream_with_mock(),
        splits in proptest::collection::vec(0usize..4096, 1..=16)
    ) {
        let (upstream_sse, real, mock) = case;
        let map = build_redaction_map(&real, &mock);
        let client_sse = run_cross_proto_restore(
            Protocol::OpenAIResponses, // ingress
            Protocol::Anthropic,       // egress
            map,
            &upstream_sse,
            &splits,
        );

        assert_cross_proto_restore_fidelity(&upstream_sse, &client_sse, &real, &mock)?;
    }
}

// ─── 辅助: 跑 StreamTranslate 跨协议翻译 ──────────────────────────────────

/// 用跨协议翻译模式跑一次 StreamTranslate, 返回客户端收到的完整 SSE 字节.
///
/// `ingress` 是客户端协议 (翻译目标), `egress` 是上游协议 (翻译源).
/// splits: 任意切分点序列 (与 run_same_proto_restore 一致的语义).
fn run_cross_proto_translate(
    ingress: Protocol,
    egress: Protocol,
    upstream: &[u8],
    splits: &[usize],
) -> Vec<u8> {
    let mut t = StreamTranslate::new(ingress, egress)
        .expect("ingress != egress required for cross-proto translate");
    feed_split_translator(&mut t, upstream, splits)
}

/// 用跨协议 + restore 模式 (生产 dispatch 同型: `new_cross_proto` +
/// `StreamingRestorerSet`) 跑一次翻译, 返回客户端收到的完整 SSE 字节.
fn run_cross_proto_restore(
    ingress: Protocol,
    egress: Protocol,
    map: RedactionMap,
    upstream: &[u8],
    splits: &[usize],
) -> Vec<u8> {
    let mut t = StreamTranslate::new_cross_proto(
        ingress,
        egress,
        Some(Box::new(crate::redact::StreamingRestorerSet::new(map))),
    )
    .expect("ingress != egress required for cross-proto translate");
    feed_split_translator(&mut t, upstream, splits)
}

/// 断言跨协议 + restore 路径的语义保真 (FWD-1 流式弱化形式 × FWD-3 跨协议):
///
/// 1. **no mock leak** (安全核心): 客户端字节中不含 mock 字符串.
/// 2. content / tool input / tool_use 身份 / usage 保真: 期望值经 `.replace(mock, real)`
///    (共享断言核心 [`assert_cross_proto_content_fidelity_with`], expect = restore 映射).
///
/// 与同协议版 ([`assert_streaming_restore_fidelity`]) 的差异: **不比较 reasoning**
/// — ReasoningContent 跨协议显式丢弃 (STR-6 裁决: thinking signature 无法合法合成),
/// 上游 reasoning 拼接非空时客户端恒为空是**预期行为**.
fn assert_cross_proto_restore_fidelity(
    upstream: &[u8],
    client: &[u8],
    real: &str,
    mock: &str,
) -> Result<(), proptest::test_runner::TestCaseError> {
    // 1. no mock leak (安全核心).
    let client_str = String::from_utf8_lossy(client);
    prop_assert!(
        !client_str.contains(mock),
        "跨协议流式 no-mock-leak 违反: 客户端 SSE 含 mock={:?}\nclient={:?}",
        mock,
        client_str,
    );

    // 2-5. 共享断言集, 期望值经 mock→real 映射.
    assert_cross_proto_content_fidelity_with(upstream, client, |s| s.replace(mock, real))
}

/// 跨协议保真断言集的共享核心 (content / tool input / tool_use 身份 / usage 四维,
/// 纯翻译与 restore 两版 property 必须协同演化的 SSOT).
///
/// `expect`: 期望值的字符串映射 — 纯翻译版传 identity ([`str::to_string`]),
/// restore 版传 `.replace(mock, real)`.
fn assert_cross_proto_content_fidelity_with(
    upstream: &[u8],
    client: &[u8],
    expect: impl Fn(&str) -> String,
) -> Result<(), proptest::test_runner::TestCaseError> {
    // content fidelity (跨协议文本透传).
    let upstream_text = collect_text_deltas(upstream);
    let client_text = collect_text_deltas(client);
    prop_assert_eq!(
        client_text,
        expect(&upstream_text),
        "STR-1×FWD-3 流式 content fidelity 违反 (跨协议文本损失)\nupstream={:?}\nclient={:?}",
        String::from_utf8_lossy(upstream),
        String::from_utf8_lossy(client),
    );

    // tool_use id/name fidelity (跨协议 tool_use 身份透传).
    // 守卫 FWD-3 建模范围内的 tool_use (id + name + input) 完整保留, 不仅是 input JSON.
    let upstream_tools = collect_tool_use_ids_names(upstream);
    let client_tools = collect_tool_use_ids_names(client);
    prop_assert_eq!(
        client_tools,
        upstream_tools,
        "STR-1×FWD-3 流式 tool_use id/name fidelity 违反 (跨协议 tool 身份损失)"
    );

    // tool input fidelity (跨协议 tool arguments 透传).
    let upstream_json = collect_input_json_deltas(upstream);
    let client_json = collect_input_json_deltas(client);
    prop_assert_eq!(
        client_json,
        expect(&upstream_json),
        "STR-1×FWD-3 流式 tool input fidelity 违反 (跨协议 tool arguments 损失)",
    );

    // usage output_tokens fidelity (terminal usage 透传).
    let upstream_usage = collect_usage_output_tokens(upstream);
    let client_usage = collect_usage_output_tokens(client);
    prop_assert_eq!(
        client_usage,
        upstream_usage,
        "STR-1×FWD-3 流式 usage.output_tokens fidelity 违反",
    );
    Ok(())
}

/// 断言跨协议流式翻译的内容保真度 (STR-1 × FWD-3 流式路径):
///
/// 四维断言集 (content / tool_use 身份 / tool input / usage, 期望值恒等映射) 见
/// 共享核心 [`assert_cross_proto_content_fidelity_with`].
///
/// 不比较 id/created/model (跨协议时 StreamTranslate 会剥离 foreign 身份, 由
/// ingress writer 合成本地格式). 不断言 "no mock leak" — 纯翻译模式不做 restore
/// (restore 版见 [`assert_cross_proto_restore_fidelity`]).
///
/// 不需要协议参数: `collect_text_deltas` / `collect_input_json_deltas` /
/// `collect_usage_output_tokens` 都是协议无关的 SSE 帧扫描器, 对任意协议的 SSE 都能工作.
fn assert_cross_proto_streaming_content_fidelity(
    upstream_sse: &[u8],
    client_sse: &[u8],
) -> Result<(), proptest::test_runner::TestCaseError> {
    // 纯翻译: 期望值恒等映射 (identity).
    assert_cross_proto_content_fidelity_with(upstream_sse, client_sse, str::to_string)
}

/// 从 SSE 字节流中收集所有 tool_use 的 (id, name) 对, 按出现顺序.
///
/// 协议无关扫描 (与 collect_text_deltas 同类):
/// - OpenAI: `choices[].delta.tool_calls[].id` + `tool_calls[].function.name`
///   (BlockStart 等价 chunk 里, id 和 name 同帧出现).
/// - Anthropic: `content_block_start.content_block.{id,name}` (type=tool_use).
/// - Responses: `output_item.added` 的 `item.{call_id,id}` + `item.name`
///   (item.type=function_call; writer 的 call_id = IR id, round-trip 关联键).
///
/// 用于跨协议流式翻译的 tool_use 身份保真断言 (FWD-3 建模范围包含 tool_use.id/name).
fn collect_tool_use_ids_names(sse_bytes: &[u8]) -> Vec<(String, String)> {
    let mut acc: Vec<(String, String)> = Vec::new();
    for data in iter_sse_data_payloads(sse_bytes) {
        // OpenAI: choices[].delta.tool_calls[].{id, function.name}.
        if let Some(choices) = data.get("choices").and_then(Value::as_array) {
            for ch in choices {
                if let Some(tcs) = ch
                    .get("delta")
                    .and_then(|d| d.get("tool_calls"))
                    .and_then(Value::as_array)
                {
                    for tc in tcs {
                        let id = tc.get("id").and_then(Value::as_str).map(String::from);
                        let name = tc
                            .get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(Value::as_str)
                            .map(String::from);
                        if let (Some(id), Some(name)) = (id, name) {
                            acc.push((id, name));
                        }
                    }
                }
            }
        }
        // Anthropic: content_block_start.content_block.{id,name} (type=tool_use).
        if data.get("type").and_then(Value::as_str) == Some("content_block_start")
            && let Some(cb) = data.get("content_block")
            && cb.get("type").and_then(Value::as_str) == Some("tool_use")
        {
            let id = cb.get("id").and_then(Value::as_str).map(String::from);
            let name = cb.get("name").and_then(Value::as_str).map(String::from);
            if let (Some(id), Some(name)) = (id, name) {
                acc.push((id, name));
            }
        }
        // Responses: output_item.added 的 item.{call_id,id} + item.name.
        if data.get("type").and_then(Value::as_str) == Some("response.output_item.added")
            && let Some(item) = data.get("item")
            && item.get("type").and_then(Value::as_str) == Some("function_call")
        {
            let id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .map(String::from);
            let name = item.get("name").and_then(Value::as_str).map(String::from);
            if let (Some(id), Some(name)) = (id, name) {
                acc.push((id, name));
            }
        }
    }
    acc
}

// ─── STR-4 缓冲溢出 abort 降级 property (L330-335) ──────────────────────────
//
// # 契约 STR-4
//
// reassembly 缓冲超过 MAX_BUF (16 MiB) 时, StreamTranslate 必须 abort 而非 OOM.
// abort 后:
//   1. finish() emit ingress 协议的原生 Error event (见 stream/translate.rs 的 finish 实现).
//   2. 后续 feed 是 no-op (aborted flag 置位, feed 直接返回空).
//   3. (同协议 restore 模式) finish() flush_all_restorers 产物不含 mock — 因为
//      abort 只清 buf, restorers 可能残留 mock tail, flush 会 restore.
//
// # 测试策略
//
// MAX_BUF = 16 MiB, 用真实阈值测一次 (固定 #[test], 不进 proptest 避免慢).
// 16 MiB 内存分配 + 线性扫描在现代机器上 < 1s, 可接受. 不引入测试专用阈值常量
// (任务约束: 不改生产代码; 引入 #[cfg(test)] 阈值会污染生产模块).

/// STR-4 `prop_max_buf_overflow_aborts`: 无终止符字节流超过 MAX_BUF 时,
/// StreamTranslate abort, 进程存活, finish() emit Error event.
#[test]
fn prop_max_buf_overflow_aborts_openai_ingress() {
    let tail_str = run_str4_cross_proto_abort(Protocol::OpenAI, Protocol::Anthropic);
    // OpenAI writer 把 IrStreamEvent::Error 写成 data: {"error":{"message":...}} 帧
    // + finish() 追加 [DONE] 终止符 (emits_sse_done_terminator=true).
    assert!(
        tail_str.contains("\"error\"") && tail_str.contains("upstream_error"),
        "STR-4 违反: OpenAI ingress finish() 应含 error data 帧 ({{\"error\":{{...,\"type\":\"upstream_error\"}}}}), 实际: {tail_str}"
    );
    assert!(
        tail_str.contains("[DONE]"),
        "STR-4 违反: OpenAI ingress finish() 应追加 [DONE] 终止符, 实际: {tail_str}"
    );
}

/// STR-4 `prop_max_buf_overflow_aborts` (Anthropic ingress).
#[test]
fn prop_max_buf_overflow_aborts_anthropic_ingress() {
    let tail_str = run_str4_cross_proto_abort(Protocol::Anthropic, Protocol::OpenAI);
    // Anthropic writer 把 IrStreamEvent::Error 写成 `event: error\ndata: {"type":"error",...}`.
    // 精确匹配 "event: error" — 不用宽泛的 "error" 子串或正常终止的 "message_stop"
    // (那些会掩盖 STR-4 违反).
    assert!(
        tail_str.contains("event: error") && tail_str.contains("upstream_error"),
        "STR-4 违反: Anthropic ingress finish() 应含 error event 帧 (event: error + upstream_error), 实际: {tail_str}"
    );
}

/// 触发 STR-4 abort 并返回 finish() tail, 供 caller 做协议特化的 error 帧断言.
///
/// 共享 setup: 构造超过 MAX_BUF 的无终止符字节流 → feed 触发 abort → 验证后续 feed
/// no-op → finish() 非空 (有降级输出). caller 只保留协议特化的 error 帧形态断言.
fn run_str4_cross_proto_abort(ingress: Protocol, egress: Protocol) -> String {
    let mut t = StreamTranslate::new(ingress, egress)
        .expect("ingress != egress required for cross-proto translate");
    let overflow_bytes = vec![b'a'; crate::codec::stream::MAX_BUF + 1];
    // feed 一次: 内部 buf 累积到 overflow_size, 触发 abort (out 可能含完整帧的翻译输出,
    // 不做强断言, 关键是进程存活).
    let _ = t.feed(&overflow_bytes);

    // abort 后继续 feed 是 no-op (STR-4 property: 后续 feed 直接返回空).
    let out2 = t.feed(b"more bytes after abort");
    assert!(
        out2.is_empty(),
        "STR-4 违反: abort 后 feed 应是 no-op (返回空), 实际返回 {} bytes",
        out2.len()
    );

    // finish() 应 emit Error event (STR-4 abort 降级). tail 非空是 caller 做精确
    // error 帧断言的前提.
    let tail = t.finish();
    let tail_str = String::from_utf8_lossy(&tail);
    assert!(
        !tail_str.is_empty(),
        "STR-4 违反: abort 后 finish() 应 emit Error event, 实际返回空"
    );
    tail_str.into_owned()
}

/// STR-4 同协议 restore 模式: abort 后 finish() flush 产物不含 mock.
///
/// 构造场景: 同协议 restore 模式下, 先 feed 一个含 mock 的完整 text delta 帧
/// (restorer.push 走 sliding window, mock 在 hold window 内被 restore, buffer 残留
/// mock 之后的 "suffix" 安全内容), 再 feed 超过 MAX_BUF 的无终止符流触发 abort,
/// 最后 finish(). finish() 的 flush_all_restorers 应正确 restore 任何残留内容,
/// 故产物不含 mock. 守卫 abort 路径不泄漏 mock 的安全核心.
#[test]
fn prop_max_buf_abort_no_mock_leak_same_proto_restore() {
    let mock = "MOCKsecret".to_string();
    let map = build_redaction_map("sk-real-secret12345", &mock);

    let mut t = StreamTranslate::new_same_proto_restore(
        Protocol::OpenAI,
        Box::new(crate::redact::StreamingRestorerSet::new(map)),
    );

    // 帧 1: 含 mock 的 text delta (restorer.push 走 sliding window, mock 被完整 restore,
    // buffer 残留 mock 之后的 "suffix" 安全内容).
    let frame1 = format!(
        "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":\"prefix {mock} suffix\"}},\"finish_reason\":null}}]}}\n\n"
    );
    let _ = t.feed(frame1.as_bytes());

    // 触发 abort: feed 一个超过 MAX_BUF 的无终止符流.
    let overflow_bytes = vec![b'a'; crate::codec::stream::MAX_BUF + 1];
    let _ = t.feed(&overflow_bytes);

    // abort 后 feed 是 no-op.
    let noop = t.feed(b"tail");
    assert!(noop.is_empty(), "abort 后 feed 应 no-op");

    // finish() flush_all_restorers 产物不含 mock.
    let tail = t.finish();
    let tail_str = String::from_utf8_lossy(&tail);
    assert!(
        !tail_str.contains(&mock),
        "STR-4 违反: abort 后 finish() flush 产物含 mock (泄漏): {tail_str}"
    );
}
