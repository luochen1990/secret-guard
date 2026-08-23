//! FWD-3 跨协议翻译 property test.
//!
//! # 契约
//!
//! [`docs/design/contracts.md`] FWD-3 (L154-174): 跨协议路径 (ingress != egress) 通过 IR
//! 中介翻译. 翻译契约分两层:
//!
//! 1. **建模范围内语义保留**: 在 chat completion 建模范围 (messages / tools / tool_use /
//!    tool_result / usage 总数 / stop_reason) 内, 翻译保留语义.
//! 2. **范围外显式丢弃**: 建模范围外的字段 (reasoning / thinking / citations / logprobs /
//!    prompt caching / usage 细分如 cache_hit_input_tokens 等) **必须显式丢弃**, 不允许
//!    源协议独有字段以 `extra` 形式泄漏到 egress.
//!
//! # 生产路径 (与 [`crate::proxy::cross_proto_forward`] 完全一致)
//!
//! ```text
//! ingress_wire ──ingress_reader──► IrRequest
//!                                  │ ir.extra.clear()        ← FWD-3 清空 extra (防泄漏)
//!                                  │ ir.clear_wire_fidelity() ← 清掉 ingress wire 形态
//!                                  ▼
//! egress_wire ◄──egress_writer──── IrRequest'
//! ```
//!
//! `extra.clear()` 是 FWD-3 的核心安全操作: [`crate::codec::collect_extra`] 把 reader 未
//! 建模的字段塞进 `extra`, 同协议路径会透传 extra (FWD-1/FWD-2), 但跨协议路径必须清空
//! (否则源协议独有字段如 OpenAI `reasoning_effort` 会污染 Anthropic egress wire).
//!
//! 注: `reasoning_content` (思考原文) 已建模为 first-class block (#176:
//! `IrBlock::ReasoningContent`), 但**跨协议仍丢弃** (Anthropic thinking 需 signature /
//! Responses reasoning 依赖 encrypted_content, 无法合法合成) — 属 FWD-3
//! "范围外显式丢弃"的已知损失, 见 `src/codec/AGENTS.md` 支持矩阵.
//!
//! # 生成器覆盖
//!
//! 按契约 §0.3 第 3 条, 生成器覆盖度本身是契约要求. 本模块的生成器覆盖:
//! - OpenAI ingress 独有字段: `reasoning_content` (顶层弃用形态) / `logprobs` / `logit_bias` /
//!   `response_format` / `seed` / `store` / `metadata` (顶层) / `n` / `presence_penalty` /
//!   `frequency_penalty`
//! - Anthropic ingress 独有字段: `thinking` / `citations` / `cache_control` /
//!   `service_tier` / `top_k` (OpenAI 无) / `metadata`(顶层)
//! - 建模范围内字段: messages (user/assistant/system/tool) / tools / tool_choice /
//!   max_tokens / temperature / top_p / stop / stream / user

use proptest::prelude::*;
use serde_json::{Value, json};

use crate::codec::anthropic::{AnthropicReader, AnthropicWriter};
use crate::codec::normalize::normalize_json;
use crate::codec::openai::{OpenAiReader, OpenAiWriter};
use crate::codec::{Reader, Writer};

// ─── 公共 proptest 入口 ─────────────────────────────────────────────────────

proptest! {
    /// FWD-3 `prop_cross_proto_extra_cleared`: 跨协议路径下, ingress IR 的 extra 字段
    /// 必须清空, 不允许源协议独有字段泄漏到 egress.
    ///
    /// 步骤 (与生产 `proxy/cross_proto.rs::cross_proto_forward` 一致):
    /// 1. ingress_reader.read_request(wire_with_extra) → ir (extra 非空)
    /// 2. ir.extra.clear() + ir.clear_wire_fidelity()
    /// 3. egress_writer.write_request(ir) → egress_wire
    /// 4. 期望: ingress wire 的 extra 字段 (任意 key) 不出现在 egress wire 顶层
    #[test]
    fn prop_cross_proto_extra_cleared(
        case in arb_openai_ingress_with_unmodeled_extra()
    ) {
        let (wire, extra_keys) = case;
        let mut ir = OpenAiReader.read_request(&wire).expect("合法 OpenAI wire");
        // 与生产 cross_proto_forward 一致: 清空 extra + wire_fidelity.
        ir.extra.clear();
        ir.clear_wire_fidelity();
        let egress = AnthropicWriter.write_request(&ir);
        for key in &extra_keys {
            prop_assert!(
                !egress.as_object().map(|o| o.contains_key(key)).unwrap_or(false),
                "FWD-3 违反: OpenAI ingress 独有字段 `{key}` 泄漏到 Anthropic egress wire. \
                 egress = {}",
                normalize_json(&egress),
            );
        }
    }

    /// FWD-3 `prop_cross_proto_extra_cleared` (反向): Anthropic → OpenAI.
    #[test]
    fn prop_cross_proto_extra_cleared_anthropic_to_openai(
        case in arb_anthropic_ingress_with_unmodeled_extra()
    ) {
        let (wire, extra_keys) = case;
        let mut ir = AnthropicReader.read_request(&wire).expect("合法 Anthropic wire");
        ir.extra.clear();
        ir.clear_wire_fidelity();
        let egress = OpenAiWriter.write_request(&ir);
        for key in &extra_keys {
            prop_assert!(
                !egress.as_object().map(|o| o.contains_key(key)).unwrap_or(false),
                "FWD-3 违反: Anthropic ingress 独有字段 `{key}` 泄漏到 OpenAI egress wire. \
                 egress = {}",
                normalize_json(&egress),
            );
        }
    }

    /// FWD-3 `prop_cross_proto_unmodeled_fields_explicitly_dropped`: 范围外字段
    /// (reasoning_content / citations / logprobs) 不出现在 egress wire.
    ///
    /// 与 `prop_cross_proto_extra_cleared` 的区别: 这里用**命名具体字段** (契约 L172 列举),
    /// 守卫已知的高危泄漏场景 (而非任意 extra key). 双向都测.
    #[test]
    fn prop_cross_proto_unmodeled_fields_explicitly_dropped(
        wire in arb_openai_ingress_with_known_unmodeled_fields()
    ) {
        let unmodeled = [
            "reasoning_content",
            "logprobs",
            "logit_bias",
            "response_format",
            "seed",
            "store",
            "n",
            "presence_penalty",
            "frequency_penalty",
        ];
        let mut ir = OpenAiReader.read_request(&wire).expect("合法 OpenAI wire");
        ir.extra.clear();
        ir.clear_wire_fidelity();
        let egress = AnthropicWriter.write_request(&ir);
        let egress_obj = egress.as_object().expect("egress 是 JSON object");
        for key in unmodeled {
            prop_assert!(
                !egress_obj.contains_key(key),
                "FWD-3 违反: OpenAI 已知未建模字段 `{key}` 出现在 Anthropic egress wire. \
                 egress = {}",
                normalize_json(&egress),
            );
        }
    }

    /// FWD-3 `prop_cross_proto_unmodeled_fields_explicitly_dropped` (反向): Anthropic → OpenAI.
    #[test]
    fn prop_cross_proto_unmodeled_fields_explicitly_dropped_anthropic_to_openai(
        wire in arb_anthropic_ingress_with_known_unmodeled_fields()
    ) {
        // top_k 是 Anthropic 已建模字段 (IR first-class), 会在 OpenAI 被 drop (不在 known
        // unmodeled 列表里, 单独在 modeled_fields_preserved 中验证 OpenAI 不输出 top_k).
        let unmodeled = [
            "thinking",
            "citations",
            "cache_control",
            "service_tier",
        ];
        let mut ir = AnthropicReader.read_request(&wire).expect("合法 Anthropic wire");
        ir.extra.clear();
        ir.clear_wire_fidelity();
        let egress = OpenAiWriter.write_request(&ir);
        let egress_obj = egress.as_object().expect("egress 是 JSON object");
        for key in unmodeled {
            prop_assert!(
                !egress_obj.contains_key(key),
                "FWD-3 违反: Anthropic 已知未建模字段 `{key}` 出现在 OpenAI egress wire. \
                 egress = {}",
                normalize_json(&egress),
            );
        }
    }

    /// FWD-3 `prop_cross_proto_modeled_fields_preserved`: 建模范围内字段跨协议 round-trip
    /// 后保留语义.
    ///
    /// 步骤: ingress_wire → IR → egress_wire → egress_reader → IR' → 重新对照 IR.
    /// 在建模范围内 (messages / tools / tool_use / tool_result — 契约 FWD-3 L171 明确
    /// 列举的字段) 语义保留.
    ///
    /// **不在建模范围** (契约 §163-168 语义损失清单外的采样参数):
    /// - temperature: OpenAI 允许 [0, 2], Anthropic writer clamp 到 [0, 1] (有损转换,
    ///   不在 FWD-3 建模范围, 也不在 §163-168 已知损失清单 — 属于协议约束差异).
    /// - max_tokens: OpenAI 可选, Anthropic 必填; 缺失时注入默认 (不算损失).
    /// - top_p / stop / stream / user: 协议共有但 wire 位置可能不同 (eg stop 在 OpenAI
    ///   是 `stop`, Anthropic 是 `stop_sequences`); 这些字段两边都建模, round-trip 后保留.
    ///
    /// 注: usage / stop_reason 是响应侧字段, 不在请求 wire 里; 这里不覆盖 (由集成测试
    /// `cross_protocol_translates_*` 系列守卫).
    #[test]
    fn prop_cross_proto_modeled_fields_preserved_openai_to_anthropic(
        wire in arb_openai_request_modeled_only()
    ) {
        let mut ir_in = OpenAiReader.read_request(&wire).expect("合法 OpenAI wire");
        // 与生产一致: 清空 extra + wire_fidelity.
        ir_in.extra.clear();
        ir_in.clear_wire_fidelity();
        // 写 egress + max_tokens 注入 (Anthropic 必填).
        if ir_in.max_tokens.is_none() {
            ir_in.max_tokens = Some(crate::codec::DEFAULT_MAX_TOKENS);
        }
        let egress_wire = AnthropicWriter.write_request(&ir_in);
        // egress_reader 重建 IR'.
        let mut ir_out = AnthropicReader.read_request(&egress_wire).expect("合法 Anthropic egress");
        ir_out.extra.clear();
        ir_out.clear_wire_fidelity();

        assert_modeled_fields_equivalent(&ir_in, &ir_out, "OpenAI → Anthropic");
    }

    /// FWD-3 `prop_cross_proto_modeled_fields_preserved` (反向): Anthropic → OpenAI.
    #[test]
    fn prop_cross_proto_modeled_fields_preserved_anthropic_to_openai(
        wire in arb_anthropic_request_modeled_only()
    ) {
        let mut ir_in = AnthropicReader.read_request(&wire).expect("合法 Anthropic wire");
        ir_in.extra.clear();
        ir_in.clear_wire_fidelity();
        let egress_wire = OpenAiWriter.write_request(&ir_in);
        let mut ir_out = OpenAiReader.read_request(&egress_wire).expect("合法 OpenAI egress");
        ir_out.extra.clear();
        ir_out.clear_wire_fidelity();

        assert_modeled_fields_equivalent(&ir_in, &ir_out, "Anthropic → OpenAI");
    }
}

/// FWD-3 `prop_documented_semantic_loss_list` (人工审查项, 非随机 property):
/// 所有已知的语义损失点必须在 `src/codec/AGENTS.md` 显式列出.
///
/// 此测试是固定断言: 读 AGENTS.md 文本, 验证包含每个已知损失点的关键词.
/// 若 codec 新增了语义损失 (eg 新协议 / 新字段丢弃), 此测试会 fail, 提醒维护者
/// 更新文档 — 防止"悄悄丢弃字段"的回归.
#[test]
fn prop_documented_semantic_loss_list() {
    let agents_md = include_str!("AGENTS.md");

    // 契约 FWD-3 (L163-168) 列出的语义损失点. 每条必须在 AGENTS.md 中显式声明.
    // 关键词取每条语义损失的核心名词 (允许在文档中用不同的句子表达, 只要关键词出现).
    let documented_loss_keywords: &[&str] = &[
        // 支持矩阵显式声明不支持的特性 (codec/AGENTS.md "支持矩阵" 段).
        "reasoning",
        "thinking",
        "citations",
        "logprobs",
        "prompt caching",
        // "搁置" 段显式列出未实现的 wire fidelity 项.
        "L8",
    ];

    for keyword in documented_loss_keywords {
        assert!(
            agents_md.contains(keyword),
            "FWD-3 违反: 语义损失点 `{keyword}` 未在 src/codec/AGENTS.md 显式列出. \
             按 FWD-3 契约要求, 所有已知语义损失必须在 AGENTS.md 中声明 (人工审查项)."
        );
    }
}

// ─── 建模范围内字段等价断言 (helper) ───────────────────────────────────────

/// 断言两个 IR (跨协议 round-trip 前后) 的建模范围内字段等价.
///
/// **建模范围** (契约 FWD-3 L158, L171): messages (含 text / tool_use / tool_result) +
/// tools. 这是 FWD-3 明确列举的建模字段.
///
/// 不比较 (契约 §163-168 语义损失清单外的协议差异, 不在建模范围内):
/// - temperature: Anthropic writer clamp [0,1] (协议约束, 非建模范围).
/// - top_p / stop / stream / user / model: 协议共有但 wire 形态差异 (eg stop vs
///   stop_sequences), 跨协议 round-trip 后保留是合理的, 但严格不在 FWD-3 建模范围
///   (契约只列 messages/tools/tool_use/tool_result/usage/stop_reason). 为避免过拟合,
///   不在此 property 守卫.
/// - top_k: Anthropic 独有, OpenAI writer drop.
/// - extra (已 clear) / wire_fidelity 字段 (已 clear).
/// - parallel_tool_calls: 通过 Anthropic tool_choice.disable_parallel_tool_use 载体映射,
///   语义脆弱 (契约 §168 显式声明), 单独在集成测试验证.
/// - tool_choice: 契约 §168 显式声明 disable_parallel_tool_use 语义脆弱; 跨协议时
///   tool_choice 本身是 typed enum (IrToolChoice), round-trip 保留, 但避免过拟合不在此比较.
fn assert_modeled_fields_equivalent(
    ir_in: &crate::codec::IrRequest,
    ir_out: &crate::codec::IrRequest,
    direction: &str,
) {
    use crate::codec::IrBlock;

    // system blocks (只比较 text 内容, 跨协议可能形态变化).
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
    assert_eq!(
        in_system_texts, out_system_texts,
        "{direction}: system prompt 文本语义损失\nin={:?}\nout={:?}",
        ir_in.system, ir_out.system,
    );

    // messages: 数量 + 每条 role + 文本/tool_use/tool_result 语义.
    assert_eq!(
        ir_in.messages.len(),
        ir_out.messages.len(),
        "{direction}: messages 数量损失\nin={:?}\nout={:?}",
        ir_in.messages,
        ir_out.messages,
    );
    for (i, (m_in, m_out)) in ir_in
        .messages
        .iter()
        .zip(ir_out.messages.iter())
        .enumerate()
    {
        assert_eq!(
            m_in.role, m_out.role,
            "{direction}: messages[{i}].role 损失",
        );
        // content blocks 数量 (跨协议 round-trip 时不应合并/拆分建模块).
        assert_eq!(
            m_in.content.len(),
            m_out.content.len(),
            "{direction}: messages[{i}].content.len 损失\nin={:?}\nout={:?}",
            m_in.content,
            m_out.content,
        );
        for (j, (b_in, b_out)) in m_in.content.iter().zip(m_out.content.iter()).enumerate() {
            match (b_in, b_out) {
                (IrBlock::Text { text: t_in }, IrBlock::Text { text: t_out }) => {
                    assert_eq!(
                        t_in, t_out,
                        "{direction}: messages[{i}].content[{j}] Text 损失",
                    );
                }
                (
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
                ) => {
                    assert_eq!(
                        id_in, id_out,
                        "{direction}: messages[{i}].content[{j}] ToolUse.id 损失"
                    );
                    assert_eq!(
                        n_in, n_out,
                        "{direction}: messages[{i}].content[{j}] ToolUse.name 损失"
                    );
                    assert_eq!(
                        normalize_json(v_in),
                        normalize_json(v_out),
                        "{direction}: messages[{i}].content[{j}] ToolUse.input 语义损失",
                    );
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
                    assert_eq!(
                        id_in, id_out,
                        "{direction}: messages[{i}].content[{j}] ToolResult.tool_use_id 损失",
                    );
                    assert_eq!(
                        e_in, e_out,
                        "{direction}: messages[{i}].content[{j}] ToolResult.is_error 损失"
                    );
                    // ToolResult.content 是 Vec<IrBlock>, 递归比较文本.
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
                    assert_eq!(
                        in_texts, out_texts,
                        "{direction}: messages[{i}].content[{j}] ToolResult.content 文本损失",
                    );
                }
                (in_b, out_b) => panic!(
                    "{direction}: messages[{i}].content[{j}] block 类型不匹配: in={in_b:?} out={out_b:?}"
                ),
            }
        }
    }

    // tools: 数量 + name + input_schema (normalize 后比较).
    assert_eq!(
        ir_in.tools.len(),
        ir_out.tools.len(),
        "{direction}: tools 数量损失",
    );
    for (i, (t_in, t_out)) in ir_in.tools.iter().zip(ir_out.tools.iter()).enumerate() {
        assert_eq!(t_in.name, t_out.name, "{direction}: tools[{i}].name 损失");
        assert_eq!(
            normalize_json(&t_in.input_schema),
            normalize_json(&t_out.input_schema),
            "{direction}: tools[{i}].input_schema 语义损失",
        );
    }
}

// ─── 生成器: OpenAI ingress + extra 字段 ────────────────────────────────────

/// 生成 OpenAI wire 含任意未建模 extra 字段.
///
/// 返回 (wire, extra_keys): extra_keys 是 wire 中出现的非建模顶层 key 名, 供断言用.
///
/// 覆盖 (按 FWD-1 `prop_proptest_generator_covers_edge_cases` 的边界场景要求):
/// - 任意合法 messages (user / assistant + tool_calls / tool result)
/// - 任意 extra 字段名 + 任意 JSON 值
fn arb_openai_ingress_with_unmodeled_extra() -> impl Strategy<Value = (Value, Vec<String>)> {
    (arb_openai_request_basic(), arb_extra_fields(1..4)).prop_map(|(mut wire, extras)| {
        let obj = wire.as_object_mut().unwrap();
        let mut keys = Vec::new();
        for (k, v) in extras {
            obj.insert(k.clone(), v);
            keys.push(k);
        }
        (wire, keys)
    })
}

/// 生成 Anthropic wire 含任意未建模 extra 字段.
fn arb_anthropic_ingress_with_unmodeled_extra() -> impl Strategy<Value = (Value, Vec<String>)> {
    (arb_anthropic_request_basic(), arb_extra_fields(1..4)).prop_map(|(mut wire, extras)| {
        let obj = wire.as_object_mut().unwrap();
        let mut keys = Vec::new();
        for (k, v) in extras {
            obj.insert(k.clone(), v);
            keys.push(k);
        }
        (wire, keys)
    })
}

/// 生成 OpenAI wire 含契约列举的已知未建模字段 (reasoning_content / logprobs / ...).
fn arb_openai_ingress_with_known_unmodeled_fields() -> impl Strategy<Value = Value> {
    arb_openai_request_basic().prop_flat_map(|wire| {
        prop::collection::vec(
            prop_oneof![
                Just(("reasoning_content".to_string(), json!({"effort":"high"}))),
                Just(("logprobs".to_string(), json!(true))),
                Just(("logit_bias".to_string(), json!({"50456": 10}))),
                Just(("response_format".to_string(), json!({"type":"json_object"}))),
                Just(("seed".to_string(), json!(42))),
                Just(("store".to_string(), json!(false))),
                Just(("n".to_string(), json!(2))),
                Just(("presence_penalty".to_string(), json!(0.5))),
                Just(("frequency_penalty".to_string(), json!(0.3))),
            ],
            1..4,
        )
        .prop_map(move |fields| {
            let mut w = wire.clone();
            let obj = w.as_object_mut().unwrap();
            for (k, v) in fields {
                obj.insert(k, v);
            }
            w
        })
    })
}

/// 生成 Anthropic wire 含契约列举的已知未建模字段.
fn arb_anthropic_ingress_with_known_unmodeled_fields() -> impl Strategy<Value = Value> {
    arb_anthropic_request_basic().prop_flat_map(|wire| {
        prop::collection::vec(
            prop_oneof![
                Just((
                    "thinking".to_string(),
                    json!({"type": "enabled", "budget_tokens": 10000}),
                )),
                Just(("citations".to_string(), json!({"enabled": true}))),
                Just(("cache_control".to_string(), json!({"type": "ephemeral"}),)),
                Just(("service_tier".to_string(), json!("priority"))),
            ],
            1..4,
        )
        .prop_map(move |fields| {
            let mut w = wire.clone();
            let obj = w.as_object_mut().unwrap();
            for (k, v) in fields {
                obj.insert(k, v);
            }
            w
        })
    })
}

/// 生成仅含建模范围内字段的 OpenAI wire (用于 modeled_fields_preserved 测试).
///
/// 不含 extra 字段 (避免 extra 干扰), 保证 reader 解析出的 IR 在建模范围内完整.
fn arb_openai_request_modeled_only() -> impl Strategy<Value = Value> {
    (
        "[a-z0-9-]{3,15}",
        arb_openai_messages_modeled(1..4),
        prop::option::of(1u32..8000),
        prop::option::of(0.0..2.0),
        prop::option::of(0.0..1.0),
        prop::collection::vec("[a-z]{2,8}", 0..3),
        arb_tools_opt_modeled(0..3),
        any::<bool>(),
    )
        .prop_map(
            |(model, messages, max_tokens, temperature, top_p, stop, tools, stream)| {
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
                if !stop.is_empty() {
                    req.insert(
                        "stop".to_string(),
                        Value::Array(stop.into_iter().map(Value::String).collect()),
                    );
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

/// 生成仅含建模范围内字段的 Anthropic wire.
fn arb_anthropic_request_modeled_only() -> impl Strategy<Value = Value> {
    (
        "[a-z0-9-]{3,15}",
        arb_anthropic_messages_modeled(1..4),
        1u32..8000,
        prop::option::of(0.0..1.0),
        prop::option::of(0.0..1.0),
        prop::option::of(1u32..1000),
        prop::collection::vec("[a-z]{2,8}", 0..3),
        arb_tools_opt_modeled(0..3),
        any::<bool>(),
    )
        .prop_map(
            |(model, messages, max_tokens, temperature, top_p, top_k, stop, tools, stream)| {
                let mut req = serde_json::Map::new();
                req.insert("model".to_string(), json!(model));
                req.insert("messages".to_string(), Value::Array(messages));
                req.insert("max_tokens".to_string(), json!(max_tokens));
                if let Some(t) = temperature {
                    req.insert("temperature".to_string(), json!(t));
                }
                if let Some(p) = top_p {
                    req.insert("top_p".to_string(), json!(p));
                }
                if let Some(k) = top_k {
                    req.insert("top_k".to_string(), json!(k));
                }
                if !stop.is_empty() {
                    req.insert(
                        "stop_sequences".to_string(),
                        Value::Array(stop.into_iter().map(Value::String).collect()),
                    );
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

// ─── 基础请求生成器 (复用 fwd_property.rs 的设计但内联, 避免跨 mod 依赖) ─────

/// OpenAI wire 基础骨架 (messages + 必要字段), 不含 extra.
fn arb_openai_request_basic() -> impl Strategy<Value = Value> {
    ("[a-z0-9-]{3,15}", arb_openai_messages_modeled(1..3)).prop_map(|(model, messages)| {
        json!({
            "model": model,
            "messages": messages,
            "max_tokens": 1000,
        })
    })
}

/// Anthropic wire 基础骨架.
fn arb_anthropic_request_basic() -> impl Strategy<Value = Value> {
    ("[a-z0-9-]{3,15}", arb_anthropic_messages_modeled(1..3)).prop_map(|(model, messages)| {
        json!({
            "model": model,
            "messages": messages,
            "max_tokens": 1000,
        })
    })
}

/// OpenAI messages, 仅建模范围内 (user / assistant+tool_calls / tool result).
fn arb_openai_messages_modeled(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Value>> {
    prop::collection::vec(arb_openai_message_modeled(), count)
}

fn arb_openai_message_modeled() -> impl Strategy<Value = Value> {
    prop_oneof![
        // user 消息 (string content).
        "[a-z ]{1,30}".prop_map(|s| json!({"role":"user","content":s})),
        // user 消息 (array content — 多 block).
        prop::collection::vec("[a-z ]{1,15}", 1..2)
            .prop_map(|parts| { json!({"role":"user","content":parts}) }),
        // assistant 消息 + tool_calls (带 arguments).
        ("[a-z ]{1,20}", arb_tool_call_modeled(1..2)).prop_map(|(text, tcs)| {
            json!({"role":"assistant","content":text,"tool_calls":tcs})
        }),
        // tool result 消息.
        ("tool_[a-z]{3,8}", "[a-z ]{1,20}").prop_map(|(id, content)| {
            json!({"role":"tool","tool_call_id":id,"content":content})
        }),
    ]
}

fn arb_anthropic_messages_modeled(
    count: std::ops::Range<usize>,
) -> impl Strategy<Value = Vec<Value>> {
    prop::collection::vec(arb_anthropic_message_modeled(), count)
}

fn arb_anthropic_message_modeled() -> impl Strategy<Value = Value> {
    prop_oneof![
        // user (string content).
        "[a-z ]{1,30}".prop_map(|s| json!({"role":"user","content":s})),
        // user 含 tool_result block.
        ("toolu_[a-z0-9]{5,10}", "[a-z ]{1,20}").prop_map(|(id, text)| {
            json!({"role":"user","content":[{"type":"tool_result","tool_use_id":id,"content":text}]})
        }),
        // assistant (text + tool_use).
        (
            "[a-z ]{1,20}",
            "toolu_[a-z0-9]{5,10}",
            "[a-z]{3,10}",
            arb_nested_json_value()
        ).prop_map(|(text, id, name, input)| {
            json!({"role":"assistant","content":[
                {"type":"text","text":text},
                {"type":"tool_use","id":id,"name":name,"input":input}
            ]})
        }),
    ]
}

/// OpenAI tool_call (带合法 JSON arguments).
fn arb_tool_call_modeled(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Value>> {
    prop::collection::vec(
        ("call_[a-z]{3,8}", "[a-z]{3,10}", arb_nested_json_value()),
        count,
    )
    .prop_map(|triples| {
        triples
            .into_iter()
            .map(|(id, name, input)| {
                json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": serde_json::to_string(&input).unwrap(),
                    }
                })
            })
            .collect()
    })
}

/// extra 字段生成器: key 是任意标识符 (避免与建模字段冲突), value 是任意 JSON.
fn arb_extra_fields(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<(String, Value)>> {
    prop::collection::vec(
        ("x_[a-z]{3,10}".prop_map(|s| s), arb_nested_json_value()),
        count,
    )
}

fn arb_tools_opt_modeled(
    count: std::ops::Range<usize>,
) -> impl Strategy<Value = Option<Vec<Value>>> {
    prop::option::of(prop::collection::vec(arb_tool_def_modeled(), count))
}

fn arb_tool_def_modeled() -> impl Strategy<Value = Value> {
    "[a-z]{3,10}".prop_map(|name| {
        json!({
            "type": "function",
            "function": {
                "name": name,
                "description": "do something",
                "parameters": {
                    "type": "object",
                    "properties": {},
                }
            }
        })
    })
}

fn arb_nested_json_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        "[a-z]{1,15}".prop_map(Value::String),
        (0i64..1000).prop_map(|n| json!(n)),
        prop::collection::vec("[a-z]{1,8}", 1..3)
            .prop_map(|v| Value::Array(v.into_iter().map(Value::String).collect())),
        ("[a-z]{3,8}", "[a-z]{1,10}").prop_map(|(k, v)| {
            let mut m = serde_json::Map::new();
            m.insert(k, Value::String(v));
            Value::Object(m)
        }),
    ]
}
