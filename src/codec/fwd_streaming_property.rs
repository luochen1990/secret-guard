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
//! `stream.rs` 头部注释:
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

use proptest::prelude::*;
use serde_json::{Value, json};

use crate::codec::Protocol;
use crate::codec::stream::{StreamTranslate, parse_sse_frame};
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

    /// FWD-1 极端切分: 1-byte 切分 (退化情形, 每个 feed 只推进 1 字节).
    ///
    /// 覆盖 StreamingRestorer 的 sliding window 在每个 chunk 只有 1 字节时的正确性.
    /// 与 stream.rs 里的 `stream_scan_byte_by_byte_split_equivalence` 同类, 但
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
}

// ─── 辅助: 跑 StreamTranslate same-proto restore 路径 ──────────────────────

/// 用 same_proto_restore 模式跑一次 StreamTranslate, 返回客户端收到的完整 SSE 字节.
///
/// splits: 任意切分点序列 (与 stream.rs `scan_chunked` 一致: 切分点把 [0,len) 切成
/// |splits|+1 段, 越界 / 乱序由 clamp + 单调化兜底).
fn run_same_proto_restore(
    proto: Protocol,
    map: RedactionMap,
    upstream: &[u8],
    splits: &[usize],
) -> Vec<u8> {
    let mut t = StreamTranslate::new_same_proto_restore(proto, map);
    feed_split_translator(&mut t, upstream, splits)
}

/// 按 `splits` 切分点序列把 `upstream` 分段喂给 translator, 收集所有输出 (含 finish()).
///
/// 切分点语义 (与 stream.rs `scan_chunked` 一致): 切分点把 [0,len) 切成 |splits|+1 段,
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
/// 4. **usage output fidelity**: 客户端 usage.output_tokens == 上游 (允许 input_tokens
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
    let client_text = collect_text_deltas(client);
    let client_json = collect_input_json_deltas(client);
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

    // 4. usage output_tokens fidelity.
    prop_assert_eq!(
        client_usage,
        upstream_usage,
        "FWD-1 流式 usage.output_tokens fidelity 违反",
    );
    Ok(())
}

/// 从 SSE 字节流中收集所有 TextDelta 的 text 内容并拼接.
///
/// 解析每个 SSE 帧 → JSON, 用 OpenAI + Anthropic reader 兼容的路径提取 text:
/// - OpenAI: `choices[].delta.content` (string)
/// - Anthropic: `delta.text` (在 content_block_delta 里, delta.type=="text_delta")
fn collect_text_deltas(sse_bytes: &[u8]) -> String {
    let mut acc = String::new();
    for data in iter_sse_data_payloads(sse_bytes) {
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
fn collect_input_json_deltas(sse_bytes: &[u8]) -> String {
    let mut acc = String::new();
    for data in iter_sse_data_payloads(sse_bytes) {
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

/// 收集 usage.output_tokens (terminal usage chunk).
///
/// - OpenAI: `usage.completion_tokens` (顶层 usage).
/// - Anthropic: `usage.output_tokens` (在 message_delta 的 usage 里).
///
/// 取所有 chunk 里 output_tokens 的最大值 (terminal usage chunk 可能晚于 finish_reason
/// chunk 到达, 取最大值避免中间 chunk 的 0 值干扰).
fn collect_usage_output_tokens(sse_bytes: &[u8]) -> u64 {
    let mut max = 0u64;
    for data in iter_sse_data_payloads(sse_bytes) {
        if let Some(usage) = data.get("usage").and_then(Value::as_object) {
            // OpenAI: completion_tokens.
            if let Some(n) = usage.get("completion_tokens").and_then(Value::as_u64) {
                max = max.max(n);
            }
            // Anthropic: output_tokens.
            if let Some(n) = usage.get("output_tokens").and_then(Value::as_u64) {
                max = max.max(n);
            }
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
    )
        .prop_map(|(mock_body, text_prefix, tool_name, tc_id_body, has_usage, has_text)| {
            // mock 与 real 都不含 SSE / JSON 特殊字符, 避免 JSON 转义干扰.
            let mock = format!("MOCK{mock_body}");
            let real = format!("sk-real-{mock_body}");
            let tc_id = format!("call_{tc_id_body}");

            let mut frames: Vec<String> = Vec::new();

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

// ─── 跨协议流式翻译 property (STR-1 × FWD-3, RED-7 交集盲区) ────────────────
//
// # 背景 (与同协议 restore property 的差异)
//
// 同协议 restore property (本文件上半部分) 守卫 `StreamTranslate::new_same_proto_restore`
// 路径: egress SSE → IR events → StreamingRestorer (mock→real) → ingress SSE.
// 该路径 ingress == egress, 不做协议翻译, 只做 restore.
//
// 跨协议翻译路径 (`StreamTranslate::new(ingress, egress)`, ingress != egress) 当前
// 生产 dispatch (cross_proto_forward) 对 stream=true 返回 501 — 跨协议流式翻译尚未
// 接入 dispatch. 但 `StreamTranslate::new` 的纯翻译逻辑 (egress SSE → IR events →
// ingress SSE) 是存在的, 可以在单元/property 层面直接测.
//
// # Redact 在跨协议流式响应中的位置
//
// 跨协议时 redact 发生在**请求侧** (cross_proto.rs:104), 响应侧的非流式路径有
// `restore_ir_response` (cross_proto.rs:271-273). 但流式响应侧的 restore **未接入**
// (StreamTranslate 跨协议模式 redaction_map = None, 不做 restore). 故:
//
// - **能测** (本模块): 跨协议流式翻译的**内容保真度** — 上游 egress content 经
//   `.replace(mock, real)` 后, 与翻译出的 ingress content 语义等价. 这守卫 STR-1
//   (chunk 边界透明) + FWD-3 (建模范围内语义保留) 在流式路径的交集.
// - **暂搁置** (需 dispatch 接入): "客户端 SSE 不含 mock" 的端到端 property — 需要
//   dispatch 层把 StreamTranslate 跨协议模式与 restore 组合 (或在 IR 事件层插入
//   restore 步骤). 当前用 `#[ignore]` 标记 (AGENTS.md "TDD 与可选测试" 场景 B).

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
    /// 注: 此 property 不守卫 "no mock leak" — 跨协议模式不做 restore, 上游若回显
    /// mock 则客户端会看到. no-mock-leak 的端到端 property 见
    /// `prop_cross_proto_streaming_no_mock_leak_dispatch_integrated` (ignored, 待
    /// dispatch 接入).
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
}

/// STR-1 × FWD-3 × RED-7: 跨协议流式 + redact restore 端到端 no-mock-leak.
///
/// **当前 ignored**: 生产路径 `cross_proto_forward` 对 stream=true 返回 501
/// (StreamTranslate 跨协议模式未接入 dispatch, 且跨协议模式下 redaction_map=None
/// 不做 restore). 此 property 是 TDD 场景 B: 生成器和断言已就绪, 待 dispatch 层
/// 把跨协议流式翻译与 restore 组合后启用.
///
/// 启用条件:
/// 1. dispatch 层 cross_proto_forward 在 stream=true 时调用 StreamTranslate (而非 501).
/// 2. StreamTranslate 跨协议模式支持 redaction_map 注入 (或 dispatch 在 IR 事件层
///    插入 restore 步骤), 使响应侧 mock → real.
///
/// 守卫 (启用后):
/// - 客户端 SSE 不含 mock 字符串 (no mock leak, 安全核心).
/// - 客户端 content == 上游 content.replace(mock, real).
#[test]
#[ignore = "待 StreamTranslate 跨协议模式接入 dispatch + restore (cross_proto_forward stream=true 当前 501)"]
fn prop_cross_proto_streaming_no_mock_leak_dispatch_integrated() {
    // 此测试是 TDD 占位: 当 dispatch 接入跨协议流式 + restore 后, 把 run_cross_proto_translate
    // 替换为含 restore 的变体 (或走真实 dispatch), 并启用 assert_streaming_restore_fidelity.
    //
    // 当前用同协议 restore runner 做形态校验 (验证测试骨架可编译), 真正语义待启用.
    let upstream_sse: Vec<u8> = Vec::new();
    let map = build_redaction_map("sk-real-test", "MOCKtest");
    let client_sse = run_same_proto_restore(Protocol::OpenAI, map, &upstream_sse, &[]);
    let client_str = String::from_utf8_lossy(&client_sse);
    assert!(!client_str.contains("MOCKtest"), "no mock leak");
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

/// 断言跨协议流式翻译的内容保真度 (STR-1 × FWD-3 流式路径):
///
/// 1. content fidelity: 双方 TextDelta 拼接相等 (跨协议翻译不丢文本).
/// 2. tool input fidelity: 双方 InputJsonDelta 拼接相等.
/// 3. usage output fidelity: output_tokens 透传.
///
/// 不比较 id/created/model (跨协议时 StreamTranslate 会剥离 foreign 身份, 由
/// ingress writer 合成本地格式). 不断言 "no mock leak" — 跨协议模式不做 restore.
///
/// 不需要协议参数: `collect_text_deltas` / `collect_input_json_deltas` /
/// `collect_usage_output_tokens` 都是协议无关的 SSE 帧扫描器, 对任意协议的 SSE 都能工作.
fn assert_cross_proto_streaming_content_fidelity(
    upstream_sse: &[u8],
    client_sse: &[u8],
) -> Result<(), proptest::test_runner::TestCaseError> {
    // content fidelity (跨协议文本透传).
    let upstream_text = collect_text_deltas(upstream_sse);
    let client_text = collect_text_deltas(client_sse);
    prop_assert_eq!(
        client_text,
        upstream_text,
        "STR-1×FWD-3 流式 content fidelity 违反 (跨协议文本损失)\nupstream={:?}\nclient={:?}",
        String::from_utf8_lossy(upstream_sse),
        String::from_utf8_lossy(client_sse),
    );

    // tool_use id/name fidelity (跨协议 tool_use 身份透传).
    // 守卫 FWD-3 建模范围内的 tool_use (id + name + input) 完整保留, 不仅是 input JSON.
    let upstream_tools = collect_tool_use_ids_names(upstream_sse);
    let client_tools = collect_tool_use_ids_names(client_sse);
    prop_assert_eq!(
        client_tools,
        upstream_tools,
        "STR-1×FWD-3 流式 tool_use id/name fidelity 违反 (跨协议 tool 身份损失)"
    );

    // tool input fidelity (跨协议 tool arguments 透传).
    let upstream_json = collect_input_json_deltas(upstream_sse);
    let client_json = collect_input_json_deltas(client_sse);
    prop_assert_eq!(
        client_json,
        upstream_json,
        "STR-1×FWD-3 流式 tool input fidelity 违反 (跨协议 tool arguments 损失)",
    );

    // usage output_tokens fidelity (terminal usage 透传).
    let upstream_usage = collect_usage_output_tokens(upstream_sse);
    let client_usage = collect_usage_output_tokens(client_sse);
    prop_assert_eq!(
        client_usage,
        upstream_usage,
        "STR-1×FWD-3 流式 usage.output_tokens fidelity 违反",
    );
    Ok(())
}

/// 从 SSE 字节流中收集所有 tool_use 的 (id, name) 对, 按出现顺序.
///
/// 协议无关扫描 (与 collect_text_deltas 同类):
/// - OpenAI: `choices[].delta.tool_calls[].id` + `tool_calls[].function.name`
///   (BlockStart 等价 chunk 里, id 和 name 同帧出现).
/// - Anthropic: `content_block_start.content_block.{id,name}` (type=tool_use).
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
    }
    acc
}

// ─── STR-4 缓冲溢出 abort 降级 property (L330-335) ──────────────────────────
//
// # 契约 STR-4
//
// reassembly 缓冲超过 MAX_BUF (16 MiB) 时, StreamTranslate 必须 abort 而非 OOM.
// abort 后:
//   1. finish() emit ingress 协议的原生 Error event (stream.rs:183-187).
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

    let mut t = StreamTranslate::new_same_proto_restore(Protocol::OpenAI, map);

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
