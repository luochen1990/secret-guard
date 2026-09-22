//! FWD-2 property test for OpenAI Responses API codec.
//!
//! # 契约
//!
//! 同协议下, Responses wire → IR → wire' 经 normalize 后应该相等:
//!
//! ```text
//! normalize(v) == normalize(Writer(Reader(v)))
//! ```
//!
//! # 生成器覆盖
//!
//! 生成器只覆盖 **可 round-trip 的字段子集** (MVP 范围). 已知 lossy 场景
//! (hosted tools 丢弃 / reasoning encrypted_content 丢弃 / previous_response_id
//! 服务端状态) 由独立的 `responses_lossy_fields_dropped_correctly` 测试守卫.
//!
//! # 不覆盖
//!
//! - FWD-1 (含 redact 的半段式): redact 路径与 OpenAI/Anthropic 共用同一份
//!   `redact_ir` + `StringLeafOps`, 已由 fwd_property.rs 的 openai/anthropic
//!   FWD-1 property 覆盖 redact 核心逻辑. Responses 特有的字符串叶子 (reasoning
//!   summary) 由 `redact_reasoning_summary_is_replaced` 单测守卫.
//! - 流式翻译: Responses 流式 writer 未实现 (流式 → 501; reader 侧已实现).
use proptest::prelude::*;
use serde_json::{Value, json};

use crate::codec::normalize::normalize_json;
use crate::codec::responses::{ResponsesReader, ResponsesWriter};
use crate::codec::{Reader, Writer};

fn responses_reader() -> ResponsesReader {
    ResponsesReader
}
fn responses_writer() -> ResponsesWriter {
    ResponsesWriter
}

// ─── 生成器: 仅覆盖可 round-trip 的字段子集 ──────────────────────────────────

fn arb_model_name() -> impl Strategy<Value = String> {
    prop_oneof![Just("gpt-4o".to_string()), Just("o1".to_string())]
}

fn arb_instructions_opt() -> impl Strategy<Value = Option<String>> {
    prop::option::of(Just("You are helpful.".to_string()))
}

/// 生成 Responses input items 数组 (可 round-trip 子集).
///
/// 覆盖的 item type: message (user/assistant) / function_call / function_call_output.
/// 不覆盖: reasoning (encrypted_content 丢失, 但 summary 可 round-trip — 单独测) /
/// hosted tool items (computer_call 等, 静默丢弃 — 单独测).
fn arb_input_items(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Value>> {
    prop::collection::vec(arb_input_item(), count)
}

fn arb_input_item() -> impl Strategy<Value = Value> {
    prop_oneof![
        // user message (最常见)
        arb_message_item("user"),
        // assistant message (history)
        arb_message_item("assistant"),
        // function_call (历史工具调用)
        arb_function_call_item(),
        // function_call_output (工具结果)
        arb_function_call_output_item(),
    ]
}

fn arb_message_item(role: &str) -> impl Strategy<Value = Value> {
    // assistant 消息的 content part 用 output_text (模型输出);
    // user 消息的 content part 用 input_text (用户输入).
    // 这是 Responses API 的语义约定, 不区分会导致 round-trip 信息损失.
    let part_type = if role == "assistant" {
        "output_text"
    } else {
        "input_text"
    };
    let role = role.to_string();
    prop::collection::vec(
        arb_text_string().prop_map(move |s| json!({"type": part_type, "text": s})),
        1..3,
    )
    .prop_map(move |content_parts| {
        json!({
            "type": "message",
            "role": role,
            "content": content_parts,
        })
    })
}

fn arb_function_call_item() -> impl Strategy<Value = Value> {
    (arb_id(), arb_name(), arb_arguments_json()).prop_map(|(id, name, args)| {
        json!({
            "type": "function_call",
            "call_id": id,
            "name": name,
            "arguments": args,
        })
    })
}

fn arb_function_call_output_item() -> impl Strategy<Value = Value> {
    (arb_id(), arb_text_string()).prop_map(|(id, output)| {
        json!({
            "type": "function_call_output",
            "call_id": id,
            "output": output,
        })
    })
}

fn arb_function_tool_def() -> impl Strategy<Value = Value> {
    (arb_name(), arb_text_string()).prop_map(|(name, desc)| {
        json!({
            "type": "function",
            "name": name,
            "description": desc,
            "parameters": {"type": "object", "properties": {}}
        })
    })
}

fn arb_text_string() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,30}" // 非空 (空文本会被 reader 丢弃, 不 round-trip)
}

fn arb_id() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_]{1,15}"
}

fn arb_name() -> impl Strategy<Value = String> {
    "[a-z_]{1,12}"
}

fn arb_arguments_json() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("{}".to_string()),
        Just("{\"q\":\"test\"}".to_string()),
        Just("{\"city\":\"SF\"}".to_string()),
    ]
}

fn arb_max_tokens_opt() -> impl Strategy<Value = Option<u32>> {
    prop::option::of(1u32..1000)
}

fn arb_temperature_opt() -> impl Strategy<Value = Option<f64>> {
    prop::option::of(0.0f64..2.0)
}

fn arb_tools_opt(count: std::ops::Range<usize>) -> impl Strategy<Value = Option<Vec<Value>>> {
    prop::option::of(prop::collection::vec(arb_function_tool_def(), count))
}

fn arb_responses_request_value() -> impl Strategy<Value = Value> {
    (
        arb_model_name(),
        arb_instructions_opt(),
        arb_input_items(1..5),
        arb_max_tokens_opt(),
        arb_temperature_opt(),
        arb_tools_opt(0..3),
        any::<bool>(),
    )
        .prop_map(
            |(model, instructions, input_items, max_tokens, temperature, tools, stream)| {
                // tool_choice 仅在 tools 非空时才有意义 (tools 为空时 writer 会跳过, 不 round-trip).
                let tool_choice = tools
                    .as_ref()
                    .filter(|t| !t.is_empty())
                    .map(|_| json!("auto"));
                let mut req = serde_json::Map::new();
                req.insert("model".to_string(), json!(model));
                if let Some(instr) = instructions {
                    req.insert("instructions".to_string(), json!(instr));
                }
                req.insert("input".to_string(), Value::Array(input_items));
                if let Some(mt) = max_tokens {
                    req.insert("max_output_tokens".to_string(), json!(mt));
                }
                if let Some(t) = temperature {
                    req.insert("temperature".to_string(), json!(t));
                }
                if let Some(ts) = tools {
                    req.insert("tools".to_string(), json!(ts));
                }
                if let Some(tc) = tool_choice {
                    req.insert("tool_choice".to_string(), tc);
                }
                if stream {
                    req.insert("stream".to_string(), json!(true));
                }
                Value::Object(req)
            },
        )
}

// ─── property: FWD-2 同协议 round-trip ─────────────────────────────────────

proptest! {
    /// FWD-2 (Responses 非流式请求): wire → IR → wire' 语义保留.
    #[test]
    fn responses_request_preserves_wire_semantics(v in arb_responses_request_value()) {
        let ir = responses_reader().read_request(&v).expect("read_request should succeed");
        let out = responses_writer().write_request(&ir);
        prop_assert_eq!(
            normalize_json(&v),
            normalize_json(&out),
            "wire 语义损失: 见 responses.rs 头部 lossy 清单"
        );
    }
}

// ─── 单测: lossy 字段的丢弃行为正确 (不 round-trip, 但行为可预测) ──────────

/// hosted tools (web_search/computer/mcp/...) 应被静默丢弃, 不进入 IR.tools.
#[test]
fn responses_lossy_hosted_tools_dropped() {
    let body = json!({
        "model": "gpt-4o",
        "input": "hi",
        "tools": [
            {"type": "function", "name": "f1", "parameters": {}},
            {"type": "web_search"},
            {"type": "computer_use_preview"},
            {"type": "mcp", "server_label": "x"},
            {"type": "file_search"},
            {"type": "image_generation"},
        ]
    });
    let ir = responses_reader().read_request(&body).unwrap();
    // 只剩 function 类型.
    assert_eq!(ir.tools.len(), 1);
    assert_eq!(ir.tools[0].name, "f1");
    // tools_present 仍为 true (wire 含 tools 字段).
    assert!(ir.tools_present);
}

/// reasoning item 的 encrypted_content 应被丢弃, 仅保留 summary 文本.
#[test]
fn responses_lossy_reasoning_encrypted_content_dropped() {
    let body = json!({
        "model": "o1",
        "input": [{
            "type": "reasoning",
            "summary": [{"type": "summary_text", "text": "thinking step 1"}],
            "encrypted_content": "opaque-encrypted-bytes-should-not-leak"
        }]
    });
    let ir = responses_reader().read_request(&body).unwrap();
    assert_eq!(ir.messages.len(), 1);
    match &ir.messages[0].content[0] {
        crate::codec::ir::IrBlock::Reasoning { summary } => {
            assert_eq!(summary, &vec!["thinking step 1".to_string()]);
        }
        other => panic!("expected Reasoning, got {other:?}"),
    }
    // encrypted_content 位于 input[].encrypted_content (嵌套字段), collect_extra 只捕获顶层 key,
    // 故 encrypted_content 在 reader 解析时即丢失, 同协议 round-trip 也不保留.
    // 这里验证 IR first-class 字段不含 encrypted_content (符合预期).
}

/// 未知 input item type 应被静默丢弃 (ROB-1).
#[test]
fn responses_lossy_unknown_item_dropped() {
    let body = json!({
        "model": "gpt-4o",
        "input": [
            {"type": "computer_call", "action": {"type": "click", "x": 0, "y": 0}},
            {"type": "file_search_call", "queries": ["test"]},
            {"type": "web_search_call", "action": {"type": "search"}},
            {"type": "image_generation_call"},
            {"type": "unknown_future_type", "data": "..."},
            {"type": "message", "role": "user", "content": "hi"},
        ]
    });
    let ir = responses_reader().read_request(&body).unwrap();
    // 只剩 message.
    assert_eq!(ir.messages.len(), 1);
}

// ─── 单测: redact 覆盖 Responses 特有的字符串叶子 ──────────────────────────

/// reasoning summary 是 secret 可能出现的位置, redact 必须扫描并替换.
///
/// 复用 redact.rs 已有的 sample 构造模式: 用 mock_strategy 显式配置避免依赖 resolve_against.
#[test]
fn redact_reasoning_summary_is_replaced() {
    use crate::codec::ir::{IrBlock, IrMessage, IrRequest, IrRole};
    use crate::mock::{GenSpec, InitialValue, MockStrategy};
    use crate::redact::{StringLeafOps, redact_ir};
    use crate::secrets::{SecretCategory, SecretEntry};

    let secret_value = "MY_SECRET_TOKEN_12345";
    // 构造一个已 resolve 的 MockStrategy (Auto + 显式 gen_spec, 避免依赖 resolve_against).
    let mock_strategy = MockStrategy {
        initial: InitialValue::Auto,
        gen_spec: Some(GenSpec::default()),
    };

    let secret = SecretEntry {
        id: "test-secret".to_string(),
        name: None,
        category: SecretCategory::ApiKey,
        value: secret_value.to_string(),
        value_file: None,
        mock_strategy,
    };

    let mut ir = IrRequest {
        messages: vec![IrMessage {
            role: IrRole::Assistant,
            content: vec![IrBlock::Reasoning {
                summary: vec![format!("I should use {secret_value} here")],
            }],
            ..Default::default()
        }],
        model: "o1".to_string(),
        ..Default::default()
    };

    let (map, _) = redact_ir(&mut ir, &[secret]);
    // redact 应该找到并替换 secret.
    assert!(
        !map.is_empty(),
        "redact should have replaced the secret in reasoning summary"
    );
    // 验证 IR 中不再含 secret.
    let mut leaked = false;
    ir.for_each_str_leaf(&mut |s| {
        if s.contains(secret_value) {
            leaked = true;
        }
    });
    assert!(!leaked, "secret leaked in reasoning summary after redact");
}

// ─── FWD-3 跨协议 property: Responses ⇄ Chat Completions (请求 + 响应) ──────
//
// # 契约 FWD-3 (建模范围内语义保留 + 范围外显式丢弃) 在 Responses 方向的盲区
//
// `fwd_cross_proto_property.rs` 只覆盖 OpenAI ⇄ Anthropic. Responses ⇄ Chat 方向
// 的跨协议翻译 (生产路径 cross_proto_forward 支持, 见 codec/AGENTS.md 支持矩阵)
// 此前完全没有 property. 本节补齐.
//
// # 生产路径 (与 cross_proto_forward 一致)
//
// ```text
// ingress_wire ──ingress_reader──► IrRequest
//                                  │ ir.extra.clear()        ← FWD-3 清空 extra
//                                  │ ir.clear_wire_fidelity() ← 清 ingress wire 形态
//                                  ▼
// egress_wire ◄──egress_writer──── IrRequest'
// ```
//
// # 守卫范围
//
// 建模范围内字段 (契约 FWD-3 L168): messages / tools / tool_use / tool_result /
// stop_reason. 跨协议 round-trip 后语义保留. 已知语义损失 (reasoning summary
// round-trip / hosted tools 丢弃 / previous_response_id 服务端状态) 由独立单测守卫.
//
// 覆盖的 Responses item type (重点, 任务要求):
// - function_call (历史工具调用, Responses input item → IR ToolUse)
// - function_call_output (工具结果, Responses input item → IR ToolResult)
// - message (user/assistant, 含多 content part)
// 多 tool_call 交错 (一条 assistant message 含多个 ToolUse 块) 由生成器随机组合覆盖.

use crate::codec::IrBlock;
use crate::codec::openai::{OpenAiReader, OpenAiWriter};

proptest! {
    /// FWD-3 `prop_responses_to_chat_request_preserves_modeled_fields`:
    /// Responses wire → IR → Chat wire, 建模范围内字段语义保留.
    ///
    /// 步骤 (与生产 cross_proto_forward 一致):
    /// 1. responses_reader.read_request(responses_wire) → ir
    /// 2. ir.extra.clear() + ir.clear_wire_fidelity()
    /// 3. chat_writer.write_request(ir) → chat_wire
    /// 4. chat_reader.read_request(chat_wire) → ir'
    /// 5. ir'.extra.clear() + ir'.clear_wire_fidelity()
    /// 6. 断言 ir 与 ir' 建模范围内字段等价.
    ///
    /// 重点覆盖: function_call / function_call_output item type, 多 tool_call 交错
    /// (由 arb_input_items 的 prop_oneof! 随机组合).
    #[test]
    fn prop_responses_to_chat_request_preserves_modeled_fields(
        wire in arb_responses_request_value()
    ) {
        let mut ir_in = responses_reader().read_request(&wire).expect("合法 Responses wire");
        // 与生产 cross_proto_forward 一致: 清空 extra + wire_fidelity.
        ir_in.extra.clear();
        ir_in.clear_wire_fidelity();
        // max_tokens 注入 (Chat writer 不要求, 但若 IR 已有则保留).
        let chat_wire = OpenAiWriter.write_request(&ir_in);
        let mut ir_out = OpenAiReader.read_request(&chat_wire).expect("合法 Chat egress");
        ir_out.extra.clear();
        ir_out.clear_wire_fidelity();

        assert_responses_chat_modeled_fields_equivalent(&ir_in, &ir_out, "Responses → Chat")?;
    }

    /// FWD-3 `prop_chat_to_responses_request_preserves_modeled_fields` (反向):
    /// Chat wire → IR → Responses wire, 建模范围内字段语义保留.
    ///
    /// 生成器: 复用 fwd_cross_proto_property 的 OpenAI modeled 生成器设计, 但内联
    /// (避免跨 mod 依赖). 覆盖 user / assistant+tool_calls / tool result 三种 message.
    #[test]
    fn prop_chat_to_responses_request_preserves_modeled_fields(
        wire in arb_chat_request_for_responses_egress()
    ) {
        let mut ir_in = OpenAiReader.read_request(&wire).expect("合法 Chat wire");
        ir_in.extra.clear();
        ir_in.clear_wire_fidelity();
        let responses_wire = responses_writer().write_request(&ir_in);
        let mut ir_out = responses_reader().read_request(&responses_wire).expect("合法 Responses egress");
        ir_out.extra.clear();
        ir_out.clear_wire_fidelity();

        assert_responses_chat_modeled_fields_equivalent(&ir_in, &ir_out, "Chat → Responses")?;
    }

    /// FWD-3 `prop_chat_to_responses_response_preserves_modeled_fields`:
    /// Chat 响应 wire → IR → Responses 响应 wire, 建模范围内字段 (content blocks /
    /// tool_use / stop_reason / usage 总数) 语义保留.
    #[test]
    fn prop_chat_to_responses_response_preserves_modeled_fields(
        resp in arb_chat_response_value()
    ) {
        let ir_in = OpenAiReader.read_response(&resp).expect("合法 Chat response");
        let responses_resp = responses_writer().write_response(&ir_in);
        let ir_out = responses_reader().read_response(&responses_resp).expect("合法 Responses response");

        assert_responses_chat_response_modeled_equivalent(&ir_in, &ir_out, "Chat → Responses (response)")?;
    }
}

/// FWD-3 已知限制守卫 (hosted tools 静默丢弃): 跨协议 Responses → Chat 时, hosted
/// tools (web_search/file_search/computer/mcp) 不进入 IR.tools, 故不泄漏到 Chat egress.
#[test]
fn prop_responses_to_chat_hosted_tools_dropped_cross_proto() {
    let body = json!({
        "model": "gpt-4o",
        "input": "hi",
        "tools": [
            {"type": "function", "name": "f1", "parameters": {}},
            {"type": "web_search"},
            {"type": "computer_use_preview"},
            {"type": "mcp", "server_label": "x"},
            {"type": "file_search"},
            {"type": "image_generation"},
        ]
    });
    let mut ir = responses_reader().read_request(&body).unwrap();
    ir.extra.clear();
    ir.clear_wire_fidelity();
    let chat_wire = OpenAiWriter.write_request(&ir);
    let tools = chat_wire
        .get("tools")
        .and_then(Value::as_array)
        .expect("chat wire has tools");
    // Chat writer 输出 OpenAI tools 风格 ({"type":"function","function":{...}}).
    // hosted tools (web_search/computer/mcp/...) 不应出现.
    assert_eq!(tools.len(), 1, "hosted tools 应被丢弃, 只剩 function 类型");
    let tool_fn = tools[0]
        .get("function")
        .or_else(|| Some(&tools[0]))
        .unwrap();
    assert_eq!(tool_fn.get("name").unwrap(), "f1");
}

/// FWD-3 已知语义损失守卫: Chat → Responses 响应跨协议时, stop_reason 粒度变粗.
///
/// Chat 的 `finish_reason` 区分 `"stop"` (自然结束, → IR EndTurn) 和 `"tool_calls"`
/// (工具调用结束, → IR ToolUse). Responses 的 `status` 只有 `completed`/`incomplete`/
/// `failed` 三态, 不区分 "自然结束" 和 "工具调用结束" (write_status 把 ToolUse 也写
/// `completed`). 故 Chat → Responses → IR' round-trip 后, `tool_calls` 的 ToolUse
/// 降级为 EndTurn (语义损失, 已知).
///
/// 此单测**精确锁定**当前降级行为, 防止 write_status / read_response_status 映射逻辑
/// 静默回归 (例如某天 completed 被映射成 MaxTokens, 应被此测试抓住). 与
/// `prop_chat_to_responses_response_preserves_modeled_fields` 的弱 stop_reason 断言
/// (只比较 Some vs None) 配合, 形成完整覆盖.
#[test]
fn responses_stop_reason_granularity_loss_cross_proto() {
    use crate::codec::ir::IrStopReason;

    // 场景 1: finish_reason="tool_calls" → IR ToolUse → Responses "completed" → IR' EndTurn.
    let tool_calls_resp = json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{"id":"call_1","type":"function",
                    "function":{"name":"f","arguments":"{}"}}]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
    });
    let ir_in = OpenAiReader.read_response(&tool_calls_resp).unwrap();
    assert_eq!(ir_in.stop_reason, Some(IrStopReason::ToolUse));
    let responses_wire = responses_writer().write_response(&ir_in);
    // write_status(ToolUse) → "completed".
    assert_eq!(responses_wire.get("status").unwrap(), "completed");
    let ir_out = responses_reader().read_response(&responses_wire).unwrap();
    // 已知损失: ToolUse → EndTurn (Responses status 粒度粗).
    assert_eq!(
        ir_out.stop_reason,
        Some(IrStopReason::EndTurn),
        "Chat tool_calls 经 Responses round-trip 后 stop_reason 应回退为 EndTurn (已知语义损失)"
    );

    // 场景 2: finish_reason="stop" → IR EndTurn → Responses "completed" → IR' EndTurn (无损).
    let stop_resp = json!({
        "id": "chatcmpl-2",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "done"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
    });
    let ir_in = OpenAiReader.read_response(&stop_resp).unwrap();
    assert_eq!(ir_in.stop_reason, Some(IrStopReason::EndTurn));
    let responses_wire = responses_writer().write_response(&ir_in);
    let ir_out = responses_reader().read_response(&responses_wire).unwrap();
    assert_eq!(
        ir_out.stop_reason,
        Some(IrStopReason::EndTurn),
        "Chat stop 经 Responses round-trip 后 stop_reason 应保持 EndTurn (无损)"
    );
}

// ─── 建模字段等价断言 (Responses ⇄ Chat 特化) ──────────────────────────────

/// 断言 Responses ⇄ Chat 跨协议 round-trip 前后 IR 的建模范围内字段等价.
///
/// **建模范围** (契约 FWD-3 L168): messages (含 text / tool_use / tool_result) +
/// tools + system (instructions ↔ system message). 这与 fwd_cross_proto_property 的
/// assert_modeled_fields_equivalent 同类, 但针对 Responses 的 item 形态特化.
///
/// 不比较 (协议约束差异 / 非建模范围):
/// - max_tokens: Responses 用 max_output_tokens, Chat 用 max_tokens; 缺失 vs 注入不算损失.
/// - temperature: Responses 允许 [0, 2], Chat 也允许; 但跨协议时若 IR 缺失则两边都不写.
/// - stop / stream / user: Responses 不支持 stop, Chat 支持; 跨协议丢失不算 FWD-3 违反.
/// - top_k: Responses 无, Chat 无 (两边都不建模, 不比较).
fn assert_responses_chat_modeled_fields_equivalent(
    ir_in: &crate::codec::IrRequest,
    ir_out: &crate::codec::IrRequest,
    direction: &str,
) -> Result<(), proptest::test_runner::TestCaseError> {
    // system blocks (Responses instructions ↔ Chat system message).
    let in_system_texts: Vec<&str> = ir_in
        .system
        .iter()
        .filter_map(|b| match b {
            IrBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let out_system_texts: Vec<&str> = ir_out
        .system
        .iter()
        .filter_map(|b| match b {
            IrBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    prop_assert_eq!(
        in_system_texts,
        out_system_texts,
        "{}: system prompt 文本语义损失\nin={:?}\nout={:?}",
        direction,
        ir_in.system,
        ir_out.system,
    );

    // messages: 按 (role, block 序列) 扁平比较.
    //
    // Responses ↔ Chat 跨协议时 message 边界可能变化: Chat 允许一条 assistant message
    // 含 Text + ToolUse 多 block, 而 Responses 的 write_input_items 会把 Text 和 ToolUse
    // 拆成两个独立 items (message item + function_call item), Responses reader 读回时
    // 重建为 2 条 messages. 这是 Responses wire 形态的固有约束 (非 bug, 已知限制).
    //
    // 契约 FWD-3 "建模范围内语义保留" 的精神是**内容**语义保留, 不强求 message 边界
    // 1:1. 故这里按扁平化 block 序列比较 (role 相同的连续 messages 合并 block 序列).
    let in_flat = flatten_messages_by_role(&ir_in.messages);
    let out_flat = flatten_messages_by_role(&ir_out.messages);
    prop_assert_eq!(
        in_flat.len(),
        out_flat.len(),
        "{}: 扁平化 (role, blocks) 序列长度损失\nin={:?}\nout={:?}",
        direction,
        ir_in.messages,
        ir_out.messages,
    );
    for (i, ((r_in, blocks_in), (r_out, blocks_out))) in
        in_flat.iter().zip(out_flat.iter()).enumerate()
    {
        prop_assert_eq!(r_in, r_out, "{}: 扁平化序列[{}] role 损失", direction, i,);
        prop_assert_eq!(
            blocks_in.len(),
            blocks_out.len(),
            "{}: 扁平化序列[{}] blocks 数量损失\nin={:?}\nout={:?}",
            direction,
            i,
            blocks_in,
            blocks_out,
        );
        for (j, (b_in, b_out)) in blocks_in.iter().zip(blocks_out.iter()).enumerate() {
            match (b_in, b_out) {
                (IrBlock::Text { text: t_in }, IrBlock::Text { text: t_out }) => {
                    prop_assert_eq!(
                        t_in,
                        t_out,
                        "{}: 扁平化序列[{}].blocks[{}] Text 损失",
                        direction,
                        i,
                        j,
                    );
                }
                (IrBlock::ToolUse { .. }, IrBlock::ToolUse { .. }) => {
                    assert_tool_use_equivalent(
                        b_in,
                        b_out,
                        direction,
                        &format!("扁平化序列[{i}].blocks[{j}]"),
                    )?;
                }
                (
                    IrBlock::ToolResult {
                        tool_use_id: id_in,
                        content: c_in,
                        is_error: e_in,
                        ..
                    },
                    IrBlock::ToolResult {
                        tool_use_id: id_out,
                        content: c_out,
                        is_error: e_out,
                        ..
                    },
                ) => {
                    prop_assert_eq!(
                        id_in,
                        id_out,
                        "{}: 扁平化序列[{}].blocks[{}] ToolResult.tool_use_id 损失",
                        direction,
                        i,
                        j,
                    );
                    prop_assert_eq!(
                        e_in,
                        e_out,
                        "{}: 扁平化序列[{}].blocks[{}] ToolResult.is_error 损失",
                        direction,
                        i,
                        j,
                    );
                    let in_texts: Vec<String> = c_in
                        .iter()
                        .filter_map(|b| match b {
                            IrBlock::Text { text } => Some(text.clone()),
                            _ => None,
                        })
                        .collect();
                    let out_texts: Vec<String> = c_out
                        .iter()
                        .filter_map(|b| match b {
                            IrBlock::Text { text } => Some(text.clone()),
                            _ => None,
                        })
                        .collect();
                    prop_assert_eq!(
                        in_texts,
                        out_texts,
                        "{}: 扁平化序列[{}].blocks[{}] ToolResult.content 文本损失",
                        direction,
                        i,
                        j,
                    );
                }
                (in_b, out_b) => panic!(
                    "{}: 扁平化序列[{}].blocks[{}] block 类型不匹配: in={:?} out={:?}",
                    direction, i, j, in_b, out_b,
                ),
            }
        }
    }

    // tools: 数量 + name + input_schema (normalize 后比较).
    prop_assert_eq!(
        ir_in.tools.len(),
        ir_out.tools.len(),
        "{}: tools 数量损失",
        direction,
    );
    for (i, (t_in, t_out)) in ir_in.tools.iter().zip(ir_out.tools.iter()).enumerate() {
        prop_assert_eq!(
            t_in.name.clone(),
            t_out.name.clone(),
            "{}: tools[{}].name 损失",
            direction,
            i,
        );
        prop_assert_eq!(
            normalize_json(&t_in.input_schema),
            normalize_json(&t_out.input_schema),
            "{}: tools[{}].input_schema 语义损失",
            direction,
            i,
        );
    }
    Ok(())
}

/// 断言 Responses ⇄ Chat 响应跨协议 round-trip 前后建模字段等价.
///
/// 建模范围: content blocks (Text / ToolUse) + stop_reason + usage 总数.
/// 不比较: id / created / model (跨协议时由 writer 合成本地格式).
fn assert_responses_chat_response_modeled_equivalent(
    ir_in: &crate::codec::IrResponse,
    ir_out: &crate::codec::IrResponse,
    direction: &str,
) -> Result<(), proptest::test_runner::TestCaseError> {
    // content blocks: 数量 + 每块类型 + 语义.
    prop_assert_eq!(
        ir_in.content.len(),
        ir_out.content.len(),
        "{}: content blocks 数量损失\nin={:?}\nout={:?}",
        direction,
        ir_in.content,
        ir_out.content,
    );
    for (i, (b_in, b_out)) in ir_in.content.iter().zip(ir_out.content.iter()).enumerate() {
        match (b_in, b_out) {
            (IrBlock::Text { text: t_in }, IrBlock::Text { text: t_out }) => {
                prop_assert_eq!(t_in, t_out, "{}: content[{}] Text 损失", direction, i,);
            }
            (IrBlock::ToolUse { .. }, IrBlock::ToolUse { .. }) => {
                assert_tool_use_equivalent(b_in, b_out, direction, &format!("content[{i}]"))?;
            }
            (in_b, out_b) => panic!(
                "{}: content[{}] block 类型不匹配: in={:?} out={:?}",
                direction, i, in_b, out_b,
            ),
        }
    }

    // stop_reason: Responses wire 的 status 粒度粗 (只有 completed/incomplete/failed),
    // 不区分 Chat 的 "stop" vs "tool_calls". Chat 的 tool_calls → IR ToolUse → Responses
    // write_status 写 "completed" → read_response_status 读回 EndTurn (语义损失, 已知).
    // 这里只比较 "都终止" 的弱语义 (Some vs None), 不强求 stop_reason 枚举值 1:1.
    if ir_in.stop_reason.is_some() {
        prop_assert!(
            ir_out.stop_reason.is_some(),
            "{}: stop_reason Some→None 损失 (in={:?} out={:?})",
            direction,
            ir_in.stop_reason,
            ir_out.stop_reason,
        );
    }

    // usage 总数 (input_tokens + output_tokens; cache 细分不在建模范围).
    prop_assert_eq!(
        ir_in.usage.input_tokens,
        ir_out.usage.input_tokens,
        "{}: usage.input_tokens 损失",
        direction,
    );
    prop_assert_eq!(
        ir_in.usage.output_tokens,
        ir_out.usage.output_tokens,
        "{}: usage.output_tokens 损失",
        direction,
    );
    Ok(())
}

/// 断言两个 `IrBlock::ToolUse` 的建模字段 (id / name / normalize(input)) 等价.
///
/// `where_label` 是出错消息中的定位串 (eg `"content[3]"` / `"扁平化序列[2].blocks[1]"`),
/// 由 caller 按自己所在循环的索引格式化. 两个 caller (request 扁平化 / response content)
/// 的断言逻辑完全相同, 抽出共享以避免三处断言 (id / name / input) 的复制.
///
/// caller 必须先 match 出两个 block 都是 `ToolUse` 变体 (否则不会调到此函数).
fn assert_tool_use_equivalent(
    b_in: &IrBlock,
    b_out: &IrBlock,
    direction: &str,
    where_label: &str,
) -> Result<(), proptest::test_runner::TestCaseError> {
    let (
        IrBlock::ToolUse {
            id: id_in,
            name: n_in,
            input: v_in,
        },
        IrBlock::ToolUse {
            id: id_out,
            name: n_out,
            input: v_out,
        },
    ) = (b_in, b_out)
    else {
        panic!("{direction}: {where_label} assert_tool_use_equivalent 收到非 ToolUse block");
    };
    prop_assert_eq!(
        id_in,
        id_out,
        "{}: {} ToolUse.id 损失",
        direction,
        where_label,
    );
    prop_assert_eq!(
        n_in,
        n_out,
        "{}: {} ToolUse.name 损失",
        direction,
        where_label,
    );
    prop_assert_eq!(
        normalize_json(v_in),
        normalize_json(v_out),
        "{}: {} ToolUse.input 语义损失",
        direction,
        where_label,
    );
    Ok(())
}

// ─── Chat wire 生成器 (供 Chat → Responses 跨协议 property 用) ──────────────

/// 生成 Chat Completions 请求 wire (建模范围内字段), 用于 Chat → Responses 跨协议测试.
fn arb_chat_request_for_responses_egress() -> impl Strategy<Value = Value> {
    (
        arb_model_name(),
        arb_chat_messages_modeled(1..4),
        prop::option::of(1u32..8000),
        prop::option::of(0.0..2.0),
        prop::option::of(0.0..1.0),
        arb_chat_tools_opt(0..3),
        any::<bool>(),
    )
        .prop_map(
            |(model, messages, max_tokens, temperature, top_p, tools, stream)| {
                let mut req = serde_json::Map::new();
                req.insert("model".to_string(), json!(model));
                req.insert("messages".to_string(), Value::Array(messages));
                if let Some(mt) = max_tokens {
                    req.insert("max_tokens".to_string(), json!(mt));
                }
                if let Some(t) = temperature {
                    req.insert("temperature".to_string(), json!(t));
                }
                if let Some(p) = top_p {
                    req.insert("top_p".to_string(), json!(p));
                }
                if let Some(ts) = tools {
                    req.insert("tools".to_string(), json!(ts));
                }
                if stream {
                    req.insert("stream".to_string(), json!(true));
                }
                Value::Object(req)
            },
        )
}

fn arb_chat_messages_modeled(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Value>> {
    prop::collection::vec(arb_chat_message_modeled(), count)
}

fn arb_chat_message_modeled() -> impl Strategy<Value = Value> {
    prop_oneof![
        // user 消息 (string content).
        arb_text_string().prop_map(|s| json!({"role":"user","content":s})),
        // user 消息 (array content — 多 block).
        prop::collection::vec(arb_text_string(), 1..2)
            .prop_map(|parts| { json!({"role":"user","content":parts}) }),
        // assistant 消息 + tool_calls (历史工具调用, 重点覆盖).
        (arb_text_string(), arb_chat_tool_call(1..2)).prop_map(|(text, tcs)| {
            json!({"role":"assistant","content":text,"tool_calls":tcs})
        }),
        // tool result 消息 (function_call_output 的 Chat 对偶).
        (arb_id(), arb_text_string()).prop_map(|(id, content)| {
            json!({"role":"tool","tool_call_id":id,"content":content})
        }),
    ]
}

fn arb_chat_tool_call(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Value>> {
    prop::collection::vec((arb_id(), arb_name(), arb_arguments_json()), count).prop_map(|triples| {
        triples
            .into_iter()
            .map(|(id, name, args)| {
                json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": args,
                    }
                })
            })
            .collect()
    })
}

fn arb_chat_tools_opt(count: std::ops::Range<usize>) -> impl Strategy<Value = Option<Vec<Value>>> {
    prop::option::of(prop::collection::vec(arb_chat_tool_def(), count))
}

fn arb_chat_tool_def() -> impl Strategy<Value = Value> {
    (arb_name(), arb_text_string()).prop_map(|(name, desc)| {
        json!({
            "type": "function",
            "function": {
                "name": name,
                "description": desc,
                "parameters": {"type": "object", "properties": {}}
            }
        })
    })
}

// ─── Chat 响应生成器 (供 Chat → Responses 响应跨协议 property 用) ────────────

/// 生成 Chat Completions 响应 wire (非流式), 用于 Chat → Responses 响应跨协议测试.
///
/// 覆盖: 纯文本响应 / tool_use 响应 (单 tool_call) / 多 block 交错 (Text + 2 tool_calls).
fn arb_chat_response_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        // 纯文本响应.
        arb_text_string().prop_map(|text| {
            json!({
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            })
        }),
        // tool_use 响应 (单 tool_call).
        (arb_id(), arb_name(), arb_arguments_json()).prop_map(|(id, name, args)| {
            json!({
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": id,
                            "type": "function",
                            "function": {"name": name, "arguments": args}
                        }]
                    },
                    "finish_reason": "tool_calls"
                }],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
            })
        }),
        // 多 block 交错: Text + 2 tool_calls (重点覆盖多 tool_call 交错).
        (
            arb_text_string(),
            arb_id(),
            arb_name(),
            arb_arguments_json(),
            arb_id(),
            arb_name(),
            arb_arguments_json()
        )
            .prop_map(|(text, id1, n1, a1, id2, n2, a2)| {
                json!({
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "created": 1700000000,
                    "model": "gpt-4o",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": text,
                            "tool_calls": [
                                {"id": id1, "type": "function",
                                 "function": {"name": n1, "arguments": a1}},
                                {"id": id2, "type": "function",
                                 "function": {"name": n2, "arguments": a2}}
                            ]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 15, "completion_tokens": 10, "total_tokens": 25}
                })
            }),
    ]
}

/// 把 messages 序列按 role 分组, 同 role 的连续 messages 合并为 (role, blocks[]) 元组序列.
///
/// 用于跨协议 round-trip 的语义比较: Responses wire 每个 item 独立, Chat 允许一条
/// message 含多 block. 跨协议翻译时 message 边界可能变化 (一条 Chat assistant message
/// 含 Text+ToolUse → Responses 两个独立 items → 读回 2 条 messages), 但同 role 连续
/// messages 的 block 序列语义不变. 此 helper 把这种边界差异归一化.
fn flatten_messages_by_role(
    messages: &[crate::codec::ir::IrMessage],
) -> Vec<(crate::codec::ir::IrRole, Vec<&IrBlock>)> {
    let mut out: Vec<(crate::codec::ir::IrRole, Vec<&IrBlock>)> = Vec::new();
    for m in messages {
        if let Some(last) = out.last_mut()
            && last.0 == m.role
        {
            last.1.extend(m.content.iter());
            continue;
        }
        out.push((m.role, m.content.iter().collect()));
    }
    out
}
