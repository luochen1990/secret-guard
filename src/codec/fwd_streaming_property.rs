//! FWD-1 流式响应半段式 property test.
//!
//! # 契约
//!
//! [`docs/design/contracts.md`] FWD-1 (L110-137, 流式响应半段式):
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
    map.insert(real.to_string(), mock.to_string())
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
