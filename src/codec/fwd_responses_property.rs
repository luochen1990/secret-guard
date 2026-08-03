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
//! - 流式翻译: Responses 流式 SSE 事件翻译未实现 (MVP 范围外).

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
