//! FWD-1 + FWD-2 端到端 property test.
//!
//! # 契约
//!
//! [`crate::codec::normalize::normalize_json`] 是语义的 canonical form.
//!
//! ## FWD-2 (纯 codec round-trip, 不含 redact)
//!
//! 同协议下, wire → IR → wire' 经 normalize 后应该相等:
//!
//! ```text
//! normalize(v) == normalize(Writer(Reader(v)))
//! ```
//!
//! 任何差异都是 reader/writer 的信息损失 (字段丢失 / 类型变化 / 形态归一化等).
//!
//! ## FWD-1 (半段式, 含 redact)
//!
//! secret-guard 对 wire 的唯一合法修改是 real↔mock 替换. 同协议 + redact 路径:
//!
//! ```text
//! normalize(发往上游 wire) == normalize(原始 wire).replace_leaf(real, mock)
//! ```
//!
//! `.replace_leaf(real, mock)` = 遍历 JSON tree 所有字符串叶子, 做 `s.replace(real, mock)`.
//! (比字符串 replace 更精确: 只替换字符串叶子值, 不破坏 JSON key / 结构.)
//!
//! # 生成器覆盖
//!
//! 按契约 §0.3 第 3 条, 生成器覆盖度本身是契约要求. 本模块的生成器必须覆盖
//! 已知信息损失场景 (L1-L8), 见各 `arb_*` 函数注释.

use proptest::prelude::*;
use serde_json::{Value, json};

use crate::codec::anthropic::{AnthropicReader, AnthropicWriter};
use crate::codec::normalize::normalize_json;
use crate::codec::openai::{OpenAiReader, OpenAiWriter};
use crate::codec::{IrReasoning, IrReasoningEffort, Reader, Writer};
use crate::redact::StringLeafOps;
use crate::redact::redact_ir;
use crate::secrets::{SecretCategory, SecretEntry};

// ─── 公共 proptest 入口 ─────────────────────────────────────────────────────

proptest! {
    /// FWD-2 (OpenAI 非流式): wire → IR → wire' 语义保留.
    #[test]
    fn openai_request_preserves_wire_semantics(v in arb_openai_request_value()) {
        let ir = OpenAiReader.read_request(&v).unwrap();
        let out = OpenAiWriter.write_request(&ir);
        assert_eq!(
            normalize_json(&v),
            normalize_json(&out),
            "wire 语义损失: 见 codec L1-L8 损失清单"
        );
    }

    /// FWD-2 (Anthropic 非流式): wire → IR → wire' 语义保留.
    #[test]
    fn anthropic_request_preserves_wire_semantics(v in arb_anthropic_request_value()) {
        let ir = AnthropicReader.read_request(&v).unwrap();
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(
            normalize_json(&v),
            normalize_json(&out),
            "wire 语义损失: 见 codec L1-L8 损失清单"
        );
    }

    /// FWD-1 (OpenAI 请求半段式, 含 redact): secret-guard 对 wire 的唯一合法修改是 real→mock.
    ///
    /// 对任意合法 OpenAI wire + 注入的 secret:
    /// 1. wire → reader → IR
    /// 2. redact_ir(IR, [secret]) → 替换 IR 字符串叶子 real→mock
    /// 3. writer → wire_out
    /// 4. 期望: normalize(wire_out) == normalize(wire.replace_leaf(real, mock))
    ///
    /// 共享逻辑见 [`assert_fwd1_half_segment`].
    #[test]
    fn openai_request_redact_preserves_wire_except_secret(
        wire_with_secret in arb_openai_request_with_embedded_secret()
    ) {
        let (v, secret_value) = wire_with_secret;
        assert_fwd1_half_segment(&OpenAiReader, &OpenAiWriter, v, &secret_value);
    }

    /// FWD-1 (Anthropic 请求半段式, 含 redact): 同上, Anthropic 协议.
    ///
    /// 共享逻辑见 [`assert_fwd1_half_segment`].
    #[test]
    fn anthropic_request_redact_preserves_wire_except_secret(
        wire_with_secret in arb_anthropic_request_with_embedded_secret()
    ) {
        let (v, secret_value) = wire_with_secret;
        assert_fwd1_half_segment(&AnthropicReader, &AnthropicWriter, v, &secret_value);
    }

    /// FWD-2 (OpenAI 响应): wire → IR → wire' 语义保留.
    ///
    /// usage `prompt_tokens_details.cached_tokens` 已双向保真 (#284 — IrUsage 走
    /// first-class `cache_read_input_tokens` 路线而非 extra, L8 的 OpenAI response
    /// 半面消除, 本 property 转正常驻).
    #[test]
    fn openai_response_preserves_wire_semantics(v in arb_openai_response_value()) {
        let ir = OpenAiReader.read_response(&v).unwrap();
        let out = OpenAiWriter.write_response(&ir);
        assert_eq!(
            normalize_json(&v),
            normalize_json(&out)
        );
    }

    /// FWD-2 (Anthropic 响应): wire → IR → wire' 语义保留.
    ///
    /// 当前已知失败: L8 (usage 字段位置: 顶层 input_tokens vs usage.input_tokens;
    /// writer 多出 stop_sequence:null; tokens 归零).
    /// 等 IrUsage 重构后启用.
    #[test]
    #[ignore = "L8: usage 字段位置迁移 + stop_sequence:null, 待 IrUsage 重构"]
    fn anthropic_response_preserves_wire_semantics(v in arb_anthropic_response_value()) {
        let ir = AnthropicReader.read_response(&v).unwrap();
        let out = AnthropicWriter.write_response(&ir);
        assert_eq!(
            normalize_json(&v),
            normalize_json(&out)
        );
    }

    /// reasoning 投影 round-trip (roadmap A1 property): 任意 effort 档位经
    /// o → a → o 跨协议往返后恢复原档位 (表值精确命中, nearest 无损).
    #[test]
    fn cross_proto_reasoning_effort_round_trips_through_budget(
        effort in arb_ir_reasoning_effort()
    ) {
        let mut ir = OpenAiReader
            .read_request(&json!({
                "model": "gpt-5",
                "messages": [{"role": "user", "content": "hi"}],
                "reasoning_effort": effort.as_str(),
                // 足够大, 不触发 budget clamp (clamp 语义由 anthropic 单测锁定).
                "max_tokens": 65536,
            }))
            .unwrap();
        ir.extra.clear();
        ir.clear_wire_fidelity();

        let a_wire = AnthropicWriter.write_request(&ir);
        let budget = a_wire
            .get("thinking")
            .and_then(|t| t.get("budget_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("thinking.budget_tokens 缺失: {}", normalize_json(&a_wire)));
        prop_assert_eq!(budget, u64::from(effort.budget_tokens()));

        let mut ir2 = AnthropicReader.read_request(&a_wire).unwrap();
        ir2.extra.clear();
        ir2.clear_wire_fidelity();
        let o_wire = OpenAiWriter.write_request(&ir2);
        prop_assert_eq!(o_wire.get("reasoning_effort"), Some(&json!(effort.as_str())));
    }

    /// IrReasoning 4 variant 全域 → 三协议 writer wire 形态 (roadmap A1):
    /// o writer 恒写 `to_effort()` 投影 (Disabled 不写); r writer 同投影写
    /// `reasoning {effort}`; a writer 按 variant 写 disabled / adaptive /
    /// enabled+budget (max_tokens 足够大, 无 clamp — clamp 语义由 anthropic.rs
    /// 单测锁定).
    #[test]
    fn cross_proto_reasoning_ir_writes_both_wire_forms(reasoning in arb_ir_reasoning()) {
        let ir = crate::codec::ir::IrRequest {
            model: "m".to_string(),
            messages: vec![crate::codec::ir::IrMessage {
                role: crate::codec::ir::IrRole::User,
                content: vec![crate::codec::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    extra: Default::default(),
                }],
                ..Default::default()
            }],
            max_tokens: Some(65536),
            reasoning: Some(reasoning),
            ..Default::default()
        };

        // o writer: to_effort 投影 (Disabled → 不写字段).
        let o_wire = OpenAiWriter.write_request(&ir);
        match reasoning.to_effort() {
            Some(e) => assert_eq!(o_wire.get("reasoning_effort"), Some(&json!(e.as_str()))),
            None => assert!(o_wire.get("reasoning_effort").is_none()),
        }

        // r writer: 同投影, 载体为 reasoning {effort}.
        let r_wire = crate::codec::responses::ResponsesWriter.write_request(&ir);
        match reasoning.to_effort() {
            Some(e) => assert_eq!(
                r_wire.get("reasoning"),
                Some(&json!({"effort": e.as_str()}))
            ),
            None => assert!(r_wire.get("reasoning").is_none()),
        }

        // a writer: variant → 三形态.
        let a_wire = AnthropicWriter.write_request(&ir);
        let thinking = a_wire.get("thinking").cloned().unwrap_or(Value::Null);
        match reasoning {
            IrReasoning::Disabled => {
                assert_eq!(thinking, json!({"type": "disabled"}));
            }
            IrReasoning::Adaptive => {
                assert_eq!(thinking, json!({"type": "adaptive"}));
            }
            IrReasoning::Budget(n) => {
                assert_eq!(
                    thinking,
                    json!({"type": "enabled", "budget_tokens": n.min(65535)})
                );
            }
            IrReasoning::Effort(e) => {
                assert_eq!(
                    thinking,
                    json!({"type": "enabled", "budget_tokens": e.budget_tokens().min(65535)})
                );
            }
        }
    }

    /// Budget → effort 降维幂等性 (roadmap A1 nearest 语义): 任意精确预算 n,
    /// o writer 注入 nearest(n) 档位; 该档位再经 a writer 查表回到
    /// nearest(n).budget_tokens() — 投影一次后进入不动点, 二次往返不再变化
    /// (连续 → 离散的信息损失一次性发生, 不随跳数放大).
    #[test]
    fn cross_proto_reasoning_budget_nearest_projection_idempotent(budget in any::<u32>()) {
        let mut ir = AnthropicReader
            .read_request(&json!({
                "model": "claude-x",
                "messages": [{"role": "user", "content": "hi"}],
                "thinking": {"type": "enabled", "budget_tokens": budget},
                "max_tokens": 65536,
            }))
            .unwrap();
        ir.extra.clear();
        ir.clear_wire_fidelity();

        let o_wire = OpenAiWriter.write_request(&ir);
        let projected = IrReasoningEffort::nearest_budget(budget);
        prop_assert_eq!(
            o_wire.get("reasoning_effort"),
            Some(&json!(projected.as_str())),
            "budget {} 应投影到 nearest 档位 {}",
            budget,
            projected.as_str()
        );

        // 投影后的 effort 再查表 (≤ 32768 < max_tokens, 无 clamp), round-trip 不动点.
        let mut ir2 = OpenAiReader.read_request(&o_wire).unwrap();
        ir2.extra.clear();
        ir2.clear_wire_fidelity();
        let a_wire = AnthropicWriter.write_request(&ir2);
        prop_assert_eq!(
            a_wire.get("thinking").and_then(|t| t.get("budget_tokens")),
            Some(&json!(projected.budget_tokens()))
        );
    }
}

/// IrReasoning 生成器 (roadmap A1): 4 variant × Budget 宽域 (0 / 1024..40000 /
/// u32 边界), 供跨协议投影 property 消费.
fn arb_ir_reasoning() -> impl Strategy<Value = IrReasoning> {
    prop_oneof![
        Just(IrReasoning::Disabled),
        arb_ir_reasoning_effort().prop_map(IrReasoning::Effort),
        prop_oneof![Just(0u32), 1024u32..40000, Just(u32::MAX),].prop_map(IrReasoning::Budget),
        Just(IrReasoning::Adaptive),
    ]
}

/// IrReasoningEffort 生成器: 6 档全覆盖.
fn arb_ir_reasoning_effort() -> impl Strategy<Value = IrReasoningEffort> {
    prop_oneof![
        Just(IrReasoningEffort::Minimal),
        Just(IrReasoningEffort::Low),
        Just(IrReasoningEffort::Medium),
        Just(IrReasoningEffort::High),
        Just(IrReasoningEffort::Xhigh),
        Just(IrReasoningEffort::Max),
    ]
}

// ─── 生成器: OpenAI 请求 (覆盖 L1-L8) ──────────────────────────────────────

/// reasoning 配置跨协议 golden (roadmap A1): OpenAI `reasoning_effort:"high"`
/// → 跨协议 → Anthropic `thinking:{type:"enabled",budget_tokens:8192}` →
/// 回 OpenAI 恢复 `reasoning_effort:"high"` (投影表精确命中, 无损往返).
///
/// 步骤与生产 `cross_proto_forward` 一致 (extra.clear + clear_wire_fidelity).
/// (定值测试, 不进 proptest! 块 — 宏只接受参数化形态.)
#[test]
fn cross_proto_reasoning_golden_o_to_a_to_o() {
    let wire = json!({
        "model": "gpt-5",
        "messages": [{"role": "user", "content": "hi"}],
        "reasoning_effort": "high",
        "max_tokens": 40000,
    });
    let mut ir = OpenAiReader.read_request(&wire).unwrap();
    assert_eq!(
        ir.reasoning,
        Some(IrReasoning::Effort(IrReasoningEffort::High))
    );
    // 跨协议 seam (与生产一致).
    ir.extra.clear();
    ir.clear_wire_fidelity();

    // → Anthropic egress: high 查表 8192 (< max_tokens 40000, 无 clamp).
    let a_wire = AnthropicWriter.write_request(&ir);
    assert_eq!(
        a_wire.get("thinking"),
        Some(&json!({"type": "enabled", "budget_tokens": 8192})),
        "golden: effort high → thinking budget 8192, got {}",
        normalize_json(&a_wire)
    );

    // → 回 OpenAI: budget 8192 反查精确命中 high.
    let mut ir2 = AnthropicReader.read_request(&a_wire).unwrap();
    ir2.extra.clear();
    ir2.clear_wire_fidelity();
    let o_wire = OpenAiWriter.write_request(&ir2);
    assert_eq!(o_wire.get("reasoning_effort"), Some(&json!("high")));
}

// ─── T7: thinking / encrypted_content passthrough (同协议保真 + a⇄r envelope) ─
//
// 契约: STR-6 跨协议处置的 T7 精确化 (envelope 搬运消除 a⇄r 信息损失);
// 安全链: RED-1/2 (envelope 打包在 writer 侧 = post-redact, 解包在 reader 侧
// = pre-redact — 见 codec/thinking.rs 头注)。

// redact 安全链 property: thinking 原文是文本叶子必须扫描 (secret 被 mock),
// opaque (signature / redacted data) 是签名/密文不扫描 (verbatim 透传),
// redacted_thinking 的 data 同样不受 redact 影响。
proptest! {
#[test]
fn prop_redact_thinking_scans_text_not_opaque(
    secret in "sk-live-[a-z0-9]{8,16}",
    sig in "[A-Z0-9]{8,40}",
    prefix in "[a-z ]{1,10}",
    suffix in "[a-z ]{1,10}",
) {
    let ir = json!({
        "model": "claude-x",
        "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": format!("{prefix}{secret}{suffix}"),
                 "signature": sig},
                {"type": "redacted_thinking", "data": format!("DATA{sig}")},
                {"type": "text", "text": "answer"}
            ]},
        ],
    });
    let mut parsed = AnthropicReader.read_request(&ir).unwrap();
    let entry = make_secret_entry(&secret);
    let (map, _) = redact_ir(&mut parsed, &[entry]);

    let out = AnthropicWriter.write_request(&parsed);
    let blocks = out["messages"][1]["content"].as_array().unwrap();
    // 1. thinking 原文中的 secret 被 mock 化 (C1: 明文叶子必须扫描)。
    let out_str = serde_json::to_string(&out).unwrap();
    assert!(!out_str.contains(&secret), "secret leaked in thinking text");
    let mock = map.mock_for(&secret).expect("secret must be mapped").to_string();
    assert!(
        blocks[0]["thinking"].as_str().unwrap().contains(mock.as_str()),
        "thinking text must contain mock: {}",
        blocks[0]["thinking"]
    );
    // 2. signature verbatim 透传 (签名非明文, 不在扫描集 — 同协议 fidelity)。
    assert_eq!(blocks[0]["signature"].as_str().unwrap(), sig);
    // 3. redacted_thinking data verbatim 透传。
    assert_eq!(blocks[1]["data"].as_str().unwrap(), format!("DATA{sig}"));
    // 4. block 类型保真 (thinking ≠ redacted_thinking, 形态标记不漂移)。
    assert_eq!(blocks[0]["type"], "thinking");
    assert_eq!(blocks[1]["type"], "redacted_thinking");
}
}

// envelope 安全链 (请求方向): a→r 跨协议时打包的 envelope 不含 real secret
// (打包点在 writer = post-redact) — 构造 thinking 原文含 secret 的请求, redact
// 后经 r writer 打包, 解包 envelope 断言文本是 mock; 解包发生在 reader =
// pre-redact 的对偶验证 (再读回 + 再 redact 后 secret 仍被 mock)。
proptest! {
#[test]
fn prop_envelope_packs_redacted_text_never_real(
    secret in "sk-live-[a-z0-9]{8,16}",
    sig in "[A-Z0-9]{8,40}",
) {
    use crate::codec::responses::ResponsesReader;
    use crate::codec::responses::ResponsesWriter;
    let ir = json!({
        "model": "claude-x",
        "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": format!("key is {secret} here"),
                 "signature": sig},
            ]},
        ],
    });
    let mut parsed = AnthropicReader.read_request(&ir).unwrap();
    let entry = make_secret_entry(&secret);
    let (map, _) = redact_ir(&mut parsed, std::slice::from_ref(&entry));
    let mock = map.mock_for(&secret).unwrap().to_string();

    // a→r: r writer 打包 envelope (post-redact — 文本已是 mock)。
    let r_wire = ResponsesWriter.write_request(&parsed);
    let ec = r_wire["input"][1]["encrypted_content"]
        .as_str()
        .expect("envelope present");
    // envelope 是 base64(明文 JSON): raw secret 不得以任何形态出现。
    assert!(
        !ec.contains(&secret) && !ec.contains(&mock),
        "envelope is base64 — neither real nor mock should appear verbatim: {ec}"
    );
    // 解包验证: 内文本是 mock (不是 real)。
    let unpacked = crate::codec::thinking::unpack(ec).expect("envelope must unpack");
    match &unpacked {
        crate::codec::ir::IrBlock::ReasoningContent { text, opaque, .. } => {
            assert!(text.contains(mock.as_str()), "envelope text must be mock: {text}");
            assert!(!text.contains(&secret), "envelope text must not contain real");
            assert_eq!(
                opaque.as_ref().unwrap(),
                &crate::codec::ir::ThinkingOpaque::Signature(sig.clone())
            );
        }
        other => panic!("expected ReasoningContent, got {other:?}"),
    }

    // 回传方向 (r client echo): r reader 解包 (pre-redact) → 内文本以叶子身份
    // 进入扫描 → 再 redact 后 secret (若解包内容是 real) 会被 mock。构造 real
    // 文本的 envelope 模拟恶意/异常上游, 验证解包路径的扫描闭环。
    let malicious_ec = crate::codec::thinking::pack_reasoning_content(
        &format!("key is {secret} here"),
        &Some(crate::codec::ir::ThinkingOpaque::Signature(sig.clone())),
    );
    let echo = json!({
        "model": "o1",
        "input": [
            {"type": "message", "role": "user", "content": "hi"},
            {"type": "reasoning", "summary": [], "encrypted_content": malicious_ec},
        ],
    });
    let mut parsed2 = ResponsesReader.read_request(&echo).unwrap();
    let _ = redact_ir(&mut parsed2, &[entry]);
    let out2 = AnthropicWriter.write_request(&parsed2);
    let out2_str = serde_json::to_string(&out2).unwrap();
    assert!(
        !out2_str.contains(&secret),
        "secret inside envelope must be redacted after reader-side unpack: {out2_str}"
    );
}
}

/// T7 golden (a→r→a, 非流式请求): a 客户端回传 thinking+signature history →
/// r egress (envelope 搬运) → r 客户端原样 echo 回来 → r reader 解包 → a egress
/// 原生写回 — thinking 原文与 signature 双双恢复 (stateless tool loop 闭合)。
#[test]
fn cross_proto_thinking_golden_a_to_r_to_a() {
    use crate::codec::responses::{ResponsesReader, ResponsesWriter};
    let wire = json!({
        "model": "claude-x",
        "max_tokens": 4096,
        "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "internal deliberation", "signature": "SIGgolden01"},
                {"type": "text", "text": "answer"},
            ]},
        ],
    });
    let mut ir = AnthropicReader.read_request(&wire).unwrap();
    ir.extra.clear();
    ir.clear_wire_fidelity();

    // → r egress: envelope 搬运 (正文 + signature 都不丢)。
    let r_wire = ResponsesWriter.write_request(&ir);
    let item = &r_wire["input"][1];
    assert_eq!(item["type"], "reasoning");
    assert_eq!(item["summary"][0]["text"], "internal deliberation");

    // → r 客户端 echo (原样回传, codex 形态) → r reader 解包 → a egress 原生写回。
    // (r reader 按 item 粒度产 message — thinking 与 text 分属两条 assistant
    // 消息, 与 r input item 扁平结构一致, 属既有跨协议粒度而非 T7 行为。)
    let mut ir2 = ResponsesReader.read_request(&r_wire).unwrap();
    ir2.extra.clear();
    ir2.clear_wire_fidelity();
    let a_wire = AnthropicWriter.write_request(&ir2);
    let blocks0 = a_wire["messages"][1]["content"].as_array().unwrap();
    assert_eq!(blocks0[0]["type"], "thinking");
    assert_eq!(blocks0[0]["thinking"], "internal deliberation");
    assert_eq!(blocks0[0]["signature"], "SIGgolden01");
    let blocks1 = a_wire["messages"][2]["content"].as_array().unwrap();
    assert_eq!(blocks1[0]["type"], "text");
    assert_eq!(blocks1[0]["text"], "answer");
}

/// T7 golden (r→a→r, 非流式请求): r 客户端回传 reasoning+encrypted_content →
/// a egress (envelope 搬进 signature) → a 客户端 echo → a reader 解包 → r egress
/// 原生写回 — summary 与 encrypted_content 双双恢复。
#[test]
fn cross_proto_reasoning_golden_r_to_a_to_r() {
    use crate::codec::responses::{ResponsesReader, ResponsesWriter};
    let wire = json!({
        "model": "gpt-5",
        "input": [
            {"type": "message", "role": "user", "content": "hi"},
            {"type": "reasoning",
             "summary": [{"type": "summary_text", "text": "summary text"}],
             "encrypted_content": "ECgolden-opaque-0123456789"},
        ],
    });
    let mut ir = ResponsesReader.read_request(&wire).unwrap();
    ir.extra.clear();
    ir.clear_wire_fidelity();

    // → a egress: envelope 搬进 signature (thinking 正文承载 summary)。
    let a_wire = AnthropicWriter.write_request(&ir);
    let blocks = a_wire["messages"][1]["content"].as_array().unwrap();
    assert_eq!(blocks[0]["type"], "thinking");
    assert_eq!(blocks[0]["thinking"], "summary text");
    let sig = blocks[0]["signature"].as_str().unwrap();
    assert!(sig.starts_with(crate::codec::thinking::ENVELOPE_PREFIX));

    // → a 客户端 echo → a reader 解包 → r egress 原生写回 (ec verbatim 恢复)。
    let mut ir2 = AnthropicReader.read_request(&a_wire).unwrap();
    ir2.extra.clear();
    ir2.clear_wire_fidelity();
    let r_wire = ResponsesWriter.write_request(&ir2);
    let item = &r_wire["input"][1];
    assert_eq!(item["type"], "reasoning");
    assert_eq!(item["summary"][0]["text"], "summary text");
    assert_eq!(item["encrypted_content"], "ECgolden-opaque-0123456789");
}

/// T7 golden (r→a 响应侧, 非流式): 上游 r 响应 reasoning item → a ingress 合成
/// thinking block (signature=envelope); a 客户端 echo 回来 → 解包 → 原生恢复。
#[test]
fn cross_proto_reasoning_response_golden_r_to_a_echo() {
    use crate::codec::responses::ResponsesReader;
    let resp = json!({
        "id": "resp_1", "object": "response", "created_at": 1700000000,
        "model": "gpt-5", "status": "completed",
        "output": [
            {"type": "reasoning", "id": "rs_1",
             "summary": [{"type": "summary_text", "text": "deliberation"}],
             "encrypted_content": "EC-resp-golden"},
        ],
        "usage": {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8},
    });
    let ir = ResponsesReader.read_response(&resp).unwrap();
    let a_resp = AnthropicWriter.write_response(&ir);
    let blocks = a_resp["content"].as_array().unwrap();
    assert_eq!(blocks[0]["type"], "thinking");
    assert_eq!(blocks[0]["thinking"], "deliberation");
    // 客户端把该响应 block 回传进下一轮请求 history → 解包 → 原生 r item 恢复。
    let echo_req = json!({
        "model": "claude-x", "max_tokens": 4096,
        "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [
                blocks[0].clone(),
                {"type": "text", "text": "answer"},
            ]},
        ],
    });
    let mut ir2 = AnthropicReader.read_request(&echo_req).unwrap();
    ir2.extra.clear();
    ir2.clear_wire_fidelity();
    let r_wire = crate::codec::responses::ResponsesWriter.write_request(&ir2);
    let item = &r_wire["input"][1];
    assert_eq!(item["type"], "reasoning");
    assert_eq!(item["summary"][0]["text"], "deliberation");
    assert_eq!(item["encrypted_content"], "EC-resp-golden");
}

/// OpenAI Chat Completions 请求生成器.
///
/// 覆盖已知信息损失场景:
/// - L1 content 形态多样性 (string / array / null)
/// - L2 system 消息位置多样性 (开头/中间/末尾/缺失/多个)
/// - L3 空字符串 content
/// - L4 message-level 未建模字段 (name 等)
/// - L5 block-level 未建模字段 (logprobs 等)
/// - L6 tool_use input 嵌套 JSON
/// - L7 stop string vs array
/// - L8 usage details (不在请求里, 不覆盖)
/// - max_tokens 双读别名字段名 (max_tokens / max_completion_tokens, #283)
/// - reasoning_effort (A1): 已知 6 档 + 未知档位值 (extra 兜底) + 缺失
fn arb_openai_request_value() -> impl Strategy<Value = Value> {
    (
        arb_model_name(),
        arb_openai_messages(1..5),
        arb_openai_max_tokens_field(),
        arb_temperature_opt(),
        arb_stop_opt(), // L7
        arb_tools_opt(0..3),
        any::<bool>(),
        arb_openai_reasoning_effort_wire(),
    )
        .prop_map(
            |(model, messages, max_tokens, temperature, stop, tools, stream, reasoning_effort)| {
                let mut req = serde_json::Map::new();
                req.insert("model".to_string(), json!(model));
                req.insert("messages".to_string(), Value::Array(messages));
                if let Some((field, mt)) = max_tokens {
                    req.insert(field.to_string(), json!(mt));
                }
                if let Some(t) = temperature {
                    req.insert("temperature".to_string(), json!(t));
                }
                if let Some(s) = stop {
                    req.insert("stop".to_string(), s);
                }
                if let Some(ts) = tools {
                    req.insert("tools".to_string(), json!(ts));
                }
                if stream {
                    req.insert("stream".to_string(), json!(true));
                }
                if let Some(effort) = reasoning_effort {
                    req.insert("reasoning_effort".to_string(), json!(effort));
                }
                Value::Object(req)
            },
        )
}

/// OpenAI wire 的 reasoning_effort 值 (A1): None (缺失) / 已知 6 档 / 未知档位值 /
/// 显式 null (ROB — reader 建不出 enum, extra 兜底原样回写, FWD-2 同协议不丢).
fn arb_openai_reasoning_effort_wire() -> impl Strategy<Value = Option<Value>> {
    prop::option::of(prop_oneof![
        Just(json!("minimal")),
        Just(json!("low")),
        Just(json!("medium")),
        Just(json!("high")),
        Just(json!("xhigh")),
        Just(json!("max")),
        // 未知档位: same-proto round-trip 靠 extra 保真 (ROB-1).
        Just(json!("banana-effort")),
        // 显式 null: 非法类型, 同样靠 extra 兜底.
        Just(Value::Null),
    ])
}

/// L2: 生成 system 消息 (暂只 0 或 1 条; 多 system 待 L2 实现后恢复).
fn arb_openai_messages(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Value>> {
    prop::collection::vec(arb_openai_message(), count).prop_flat_map(|msgs| {
        // 可选在最前面插入 1 条 system 消息 (多 system 合并是 L2 待修, 不放入)
        any::<bool>().prop_flat_map(move |has_system| {
            let mut result = Vec::new();
            if has_system {
                result.push(json!({"role": "system", "content": "system prompt"}));
            }
            result.extend(msgs.clone());
            Just(result)
        })
    })
}

fn arb_openai_message() -> impl Strategy<Value = Value> {
    prop_oneof![
        // user 消息: 覆盖 L1 (string / array / null) + L3 (空字符串)
        arb_openai_user_message(),
        // assistant 消息: 可能含 tool_calls
        arb_openai_assistant_message(),
        // tool 结果消息: 独立 role:"tool"
        arb_openai_tool_result_message(),
        // NOTE: system 消息不放入 messages 池, 走 arb_openai_messages 的 has_system 单独路径.
        //       多 system messages 是 L2 待修, 不放入.
    ]
}

fn arb_openai_user_message() -> impl Strategy<Value = Value> {
    prop_oneof![
        // L1.a: content 为 string
        "[a-z ]{1,30}".prop_map(|s| json!({"role":"user","content":s})),
        // L1.b: content 为 array of parts (多模态 / 多 block)
        prop::collection::vec(arb_openai_content_part(), 1..3)
            .prop_map(|parts| { json!({"role":"user","content":parts}) }),
        // L1.d: content 为空数组 (与 content:"" 和缺失字段语义不同, round-trip 守卫)
        Just(json!({"role":"user","content":[]})),
        // L1.c: content 为 null
        Just(json!({"role":"user","content":null})),
        // L3: content 为空字符串
        Just(json!({"role":"user","content":""})),
        // NOTE: L4 (message-level extra 如 name 字段) 暂未实现, 不放入生成器.
        //       等 IrMessage 加 extra 字段后恢复.
    ]
}

fn arb_openai_assistant_message() -> impl Strategy<Value = Value> {
    // reasoning_content 形态 (思考型模型的历史回传, #176): 非空 string / 空串 / null.
    // 空串与 null 覆盖 FWD-1 边界: reader 丢弃后 writer 是否恢复 wire 形态.
    let arb_reasoning_opt = prop::option::of(prop_oneof![
        "[a-z ]{1,25}".prop_map(|s| json!(s)),
        Just(json!("")),
        Just(Value::Null),
    ]);
    prop_oneof![
        // 纯文本 assistant (string 形态)
        "[a-z ]{1,30}".prop_map(|s| json!({"role":"assistant","content":s})),
        // L1: assistant content 为 string 数组 (OpenAI 风格, 多段文本)
        prop::collection::vec("[a-z ]{1,20}", 1..2).prop_map(|parts| {
            let arr: Vec<Value> = parts.into_iter().map(Value::String).collect();
            json!({"role":"assistant","content":arr})
        }),
        // L1: assistant content 为 null (调用工具时)
        arb_tool_call(1..3)
            .prop_map(|tcs| { json!({"role":"assistant","content":null,"tool_calls":tcs}) }),
        // assistant + 文本 + tool_calls
        ("[a-z ]{1,20}", arb_tool_call(1..2)).prop_map(|(text, tcs)| {
            json!({"role":"assistant","content":text,"tool_calls":tcs})
        }),
        // L1: assistant + string array content + tool_calls
        (
            prop::collection::vec("[a-z ]{1,15}", 1..2),
            arb_tool_call(1..2)
        )
            .prop_map(|(parts, tcs)| {
                let arr: Vec<Value> = parts.into_iter().map(Value::String).collect();
                json!({"role":"assistant","content":arr,"tool_calls":tcs})
            }),
        // #176: assistant + 思考原文回传 (非空 / 空串 / null 三形态; null 内层 =
        // 显式 `"reasoning_content": null`, 外层 None = 字段缺席).
        ("[a-z ]{1,20}", arb_reasoning_opt).prop_map(|(text, rc)| {
            let mut msg = serde_json::Map::new();
            msg.insert("role".to_string(), json!("assistant"));
            msg.insert("content".to_string(), json!(text));
            if let Some(rc) = rc {
                msg.insert("reasoning_content".to_string(), rc);
            }
            Value::Object(msg)
        }),
    ]
}

fn arb_openai_tool_result_message() -> impl Strategy<Value = Value> {
    prop_oneof![
        // 基础 tool result
        ("tool_[a-z]{3,8}", "[a-z ]{1,30}").prop_map(|(id, content)| {
            json!({"role":"tool","tool_call_id":id,"content":content})
        }),
        // NOTE: L4 (tool result + name 字段) 暂未实现, 不放入生成器.
    ]
}

/// L6: tool_call input 嵌套 JSON.
fn arb_tool_call(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Value>> {
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

fn arb_openai_content_part() -> impl Strategy<Value = Value> {
    prop_oneof![
        // text part
        "[a-z ]{1,20}".prop_map(|s| json!({"type":"text","text":s})),
        // L5: text part + 未建模字段 (logprobs 等) — 需要 IrBlock 支持 extra, 暂未实现
        // "[a-z ]{1,20}".prop_map(|s| json!({"type":"text","text":s,"logprobs":{"tokens":["a","b"]}})),
        // image_url part
        "https://example.com/[a-z]{3,8}.png"
            .prop_map(|u| { json!({"type":"image_url","image_url":{"url":u}}) }),
        // NOTE: 未知 part type (audio 等) 需要 IrBlock::Unknown, 暂未实现, 不放入生成器.
    ]
}

// ─── 生成器: OpenAI 响应 ───────────────────────────────────────────────────

fn arb_openai_response_value() -> impl Strategy<Value = Value> {
    (
        "chatcmpl-[a-z0-9]{6,12}",
        "[a-z0-9-]{3,15}",
        prop::collection::vec(arb_openai_response_choice(), 1..2),
        arb_openai_usage(),
    )
        .prop_map(|(id, model, choices, usage)| {
            json!({
                "id": id,
                "object": "chat.completion",
                "created": 1234567890_u64,
                "model": model,
                "choices": choices,
                "usage": usage,
            })
        })
}

fn arb_openai_response_choice() -> impl Strategy<Value = Value> {
    (
        "[a-z ]{1,40}",                             // content text
        prop::option::of(arb_stop_reason_openai()), // finish_reason
        prop::option::of(arb_tool_call(0..2)),      // tool_calls (0..2)
    )
        .prop_map(|(text, finish, tcs)| {
            let mut message = serde_json::Map::new();
            message.insert("role".to_string(), json!("assistant"));
            message.insert("content".to_string(), json!(text));
            if let Some(tcs) = tcs
                && !tcs.is_empty()
            {
                message.insert("tool_calls".to_string(), Value::Array(tcs));
            }
            let mut choice = serde_json::Map::new();
            choice.insert("index".to_string(), json!(0));
            choice.insert("message".to_string(), Value::Object(message));
            choice.insert(
                "finish_reason".to_string(),
                finish.unwrap_or_else(|| json!("stop")),
            );
            Value::Object(choice)
        })
}

/// L8: usage details 字段. cached 维度三形态 — 缺席 / `cached_tokens: 0` /
/// `cached_tokens: n>0` — 显式生成 0 值形态是 presence 保真轴 (#284 review 裁决):
/// writer 对 `Some(0)` 写回 `cached_tokens: 0` (而非坍缩为无 details 键) 的行为
/// 必须被 round-trip 断言覆盖, 防止未来被 "简化" 为 `if c > 0` 静默回退.
fn arb_openai_usage() -> impl Strategy<Value = Value> {
    (
        0u32..1_000_000,
        0u32..1_000_000,
        prop::option::of(prop_oneof![Just(0u32), 1u32..1_000_000]),
    )
        .prop_map(|(prompt, completion, cached)| {
            let mut usage = serde_json::Map::new();
            let prompt = prompt.max(cached.unwrap_or(0)); // prompt >= cached
            usage.insert("prompt_tokens".to_string(), json!(prompt));
            usage.insert("completion_tokens".to_string(), json!(completion));
            // saturating_add 避免生成器自身溢出 panic
            usage.insert(
                "total_tokens".to_string(),
                json!(prompt.saturating_add(completion)),
            );
            if let Some(cached) = cached {
                usage.insert(
                    "prompt_tokens_details".to_string(),
                    json!({
                        "cached_tokens": cached
                    }),
                );
            }
            Value::Object(usage)
        })
}

fn arb_stop_reason_openai() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!("stop")),
        Just(json!("length")),
        Just(json!("tool_calls")),
        Just(json!("content_filter")),
    ]
}

// ─── 生成器: Anthropic 请求/响应 ────────────────────────────────────────────

fn arb_anthropic_request_value() -> impl Strategy<Value = Value> {
    (
        "[a-z0-9-]{3,15}",
        prop::collection::vec(arb_anthropic_message(), 1..4),
        arb_max_tokens_opt(),
        // 顶层 system: 缺席 / string / array (array block 可带 cache_control, #269).
        prop::option::of(prop_oneof![
            "[a-z ]{1,30}".prop_map(|s| json!(s)),
            prop::collection::vec(arb_anthropic_system_block(), 1..3)
                .prop_map(|blocks| json!(blocks)),
        ]),
        // tools: 缺席 / 工具数组 (工具可带 cache_control / defer_loading 等 extra, #269).
        prop::option::of(prop::collection::vec(arb_anthropic_tool_def(), 1..2)),
        // thinking (A1): 缺席 / 三合法形态 / 未知 type (extra 兜底).
        prop::option::of(arb_anthropic_thinking_wire()),
    )
        .prop_map(|(model, messages, max_tokens, system, tools, thinking)| {
            let mut req = serde_json::Map::new();
            req.insert("model".to_string(), json!(model));
            req.insert("messages".to_string(), Value::Array(messages));
            req.insert("max_tokens".to_string(), json!(max_tokens.unwrap_or(100)));
            if let Some(system) = system {
                req.insert("system".to_string(), system);
            }
            if let Some(tools) = tools {
                req.insert("tools".to_string(), Value::Array(tools));
            }
            if let Some(t) = thinking {
                req.insert("thinking".to_string(), t);
            }
            Value::Object(req)
        })
}

/// Anthropic wire 的 thinking 对象 (A1): 合法三形态 (disabled / enabled+budget /
/// adaptive, budget 取宽域含 clamp 边界) + 未知 type / enabled 缺 budget / null
/// (非法形态, reader 建不出 → extra 兜底保真).
fn arb_anthropic_thinking_wire() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!({"type": "disabled"})),
        (1024u32..40000).prop_map(|n| json!({"type": "enabled", "budget_tokens": n})),
        Just(json!({"type": "adaptive"})),
        Just(json!({"type": "banana", "budget_tokens": 4096})),
        Just(json!({"type": "enabled"})),
        Just(Value::Null),
    ]
}

/// 顶层 system array 的 block (text + 可选 cache_control).
fn arb_anthropic_system_block() -> impl Strategy<Value = Value> {
    ("[a-z ]{1,30}", prop::option::of(arb_cache_control())).prop_map(|(s, cc)| {
        let mut b = json!({"type": "text", "text": s});
        if let Some(cc) = cc {
            b["cache_control"] = cc;
        }
        b
    })
}

/// Anthropic 工具定义 (含 L5 工具级 extra: cache_control / defer_loading, #269).
fn arb_anthropic_tool_def() -> impl Strategy<Value = Value> {
    (
        "[a-z]{3,10}",
        "[a-z ]{1,30}",
        prop::option::of(arb_cache_control()),
        prop::option::of(Just(true)),
    )
        .prop_map(|(name, desc, cc, defer)| {
            let mut t = json!({
                "name": name,
                "description": desc,
                "input_schema": {"type": "object", "properties": {}},
            });
            if let Some(cc) = cc {
                t["cache_control"] = cc;
            }
            if let Some(d) = defer {
                t["defer_loading"] = json!(d);
            }
            t
        })
}

/// block 级 `cache_control` 的合法 wire 值 (#269): ephemeral 是当前唯一支持的 type.
pub(crate) fn arb_cache_control() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!({"type": "ephemeral"})),
        Just(json!({"type": "ephemeral", "ttl": "1h"})),
    ]
}

fn arb_anthropic_message_base() -> impl Strategy<Value = Value> {
    // role=system 条目 (Anthropic 中途 system 消息, claude code 实测发送) 参与生成:
    // 2026-09-23 修正 (#269) 后 reader/writer 按原位保留, round-trip normalize 相等,
    // 因此可以被 FWD-1/FWD-2 property 机械锁定 (旧实现提升合并到顶层 system, 生成器
    // 曾被迫排除该形态)。
    prop_oneof![
        // user 消息 (content: string / 空字符串 / null / array)
        prop_oneof![
            "[a-z ]{1,30}".prop_map(|s| json!({"role":"user","content":s})),
            // L1: 空字符串 content (P0-3 守卫)
            Just(json!({"role":"user","content":""})),
            // L1: null content
            Just(json!({"role":"user","content":null})),
            prop::collection::vec(arb_anthropic_block(), 1..3)
                .prop_map(|blocks| { json!({"role":"user","content":blocks}) }),
        ],
        // assistant 消息 (thinking / text / tool_use — T7: thinking 族参与
        // round-trip property; signature/data 用大写数字 charset, 结构上不可能
        // 产生小写 `sg-thinking-v1:` 前缀 — envelope 解包路径由专项测试覆盖,
        // 生成器只生成 plain opaque 保证 FWD-2 的 verbatim 断言可机械验证)
        (
            "[a-z ]{1,20}",
            prop::option::of(arb_anthropic_thinking_block()),
            prop::option::of(arb_anthropic_tool_use()),
        )
            .prop_map(|(text, thinking, tu)| {
                let mut blocks = Vec::new();
                if let Some(t) = thinking {
                    blocks.push(t);
                }
                blocks.push(json!({"type":"text","text":text}));
                if let Some(t) = tu {
                    blocks.push(t);
                }
                json!({"role":"assistant","content":blocks})
            }),
        // 中途 system 消息 (string 或 array content 两种形态; 位置保真锁定)
        "[a-z ]{1,25}".prop_map(|s| json!({"role":"system","content":s})),
        prop::collection::vec(arb_anthropic_block(), 1..2)
            .prop_map(|blocks| json!({"role":"system","content":blocks})),
    ]
}

/// 消息级 extra 包装 (L4, #269): 部分消息携带消息级未建模字段 (实测形态:
/// claude code 的消息级 `output_config.effort`), round-trip 须原样保留.
fn arb_anthropic_message() -> impl Strategy<Value = Value> {
    (arb_anthropic_message_base(), prop::option::of("[a-z]{4,8}")).prop_map(|(mut m, effort)| {
        if let Some(e) = effort {
            m["output_config"] = json!({"effort": e});
        }
        m
    })
}

fn arb_anthropic_block() -> impl Strategy<Value = Value> {
    prop_oneof![
        // L5 (#269): text block 可携带 cache_control (claude code 的 system/末尾消息断点).
        ("[a-z ]{1,20}", prop::option::of(arb_cache_control())).prop_map(|(s, cc)| {
            let mut b = json!({"type": "text", "text": s});
            if let Some(cc) = cc {
                b["cache_control"] = cc;
            }
            b
        }),
        // tool_result (含空字符串 content 的 P0-4 守卫) + cache_control + is_error 形态.
        (
            "toolu_[a-z0-9]{5,10}",
            arb_anthropic_tool_result_content(),
            prop::option::of(arb_cache_control()),
            prop::option::of(Just(false)),
        )
            .prop_map(|(id, content, cc, is_error)| {
                let mut b = json!({"type": "tool_result", "tool_use_id": id, "content": content});
                if let Some(cc) = cc {
                    b["cache_control"] = cc;
                }
                // is_error: false 显式形态与 true 一样合法 (writer 须按原样保留, 省略非保真).
                if let Some(e) = is_error {
                    b["is_error"] = json!(e);
                }
                b
            }),
    ]
}

/// Anthropic tool_result 的 content: 空字符串 / 单字符 / 普通文本 (覆盖 P0-4 边界).
fn arb_anthropic_tool_result_content() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("a".to_string()),
        "[a-z ]{1,20}".prop_map(|s| s),
    ]
}

fn arb_anthropic_tool_use() -> impl Strategy<Value = Value> {
    (
        "toolu_[a-z0-9]{5,10}",
        "[a-z]{3,10}",
        arb_nested_json_value(),
    )
        .prop_map(|(id, name, input)| json!({"type":"tool_use","id":id,"name":name,"input":input}))
}

/// Anthropic thinking 族 block (T7): thinking{thinking 原文, signature} /
/// redacted_thinking{data}; T7 修复轮补 L5 轴 — 可携带 cache_control (扩展思考
/// 场景官方推荐断点恰在此, FWD-2 round-trip property 机械锁定收集/回写)。
/// signature/data 用 `[A-Z0-9]` charset — 结构上
/// 排除小写 `sg-thinking-v1:` envelope 前缀 (envelope 路径会解包改写 block,
/// 与 FWD-2 的 verbatim 断言不兼容, 由专项 golden 测试覆盖; 见生成处注释)。
fn arb_anthropic_thinking_block() -> impl Strategy<Value = Value> {
    use proptest::prelude::prop_oneof;
    prop_oneof![
        (
            "[a-z ]{1,25}",
            "[A-Z0-9]{8,40}",
            prop::option::of(arb_cache_control()),
        )
            .prop_map(|(text, sig, cc)| {
                let mut b = json!({"type": "thinking", "thinking": text, "signature": sig});
                if let Some(cc) = cc {
                    b["cache_control"] = cc;
                }
                b
            }),
        // 空 thinking 原文 + signature (redact 后的退化形态 / 官方允许)。
        ("[A-Z0-9]{8,40}", prop::option::of(arb_cache_control())).prop_map(|(sig, cc)| {
            let mut b = json!({"type": "thinking", "thinking": "", "signature": sig});
            if let Some(cc) = cc {
                b["cache_control"] = cc;
            }
            b
        }),
        ("[A-Z0-9]{16,48}", prop::option::of(arb_cache_control())).prop_map(|(data, cc)| {
            let mut b = json!({"type": "redacted_thinking", "data": data});
            if let Some(cc) = cc {
                b["cache_control"] = cc;
            }
            b
        }),
    ]
}

fn arb_anthropic_response_value() -> impl Strategy<Value = Value> {
    (
        "msg_[a-z0-9]{5,15}",
        "[a-z0-9-]{3,15}",
        prop::collection::vec(arb_anthropic_response_block(), 1..3),
        arb_anthropic_stop_reason(),
        (any::<u32>(), any::<u32>()),
    )
        .prop_map(
            |(id, model, content, stop_reason, (input_tokens, output_tokens))| {
                json!({
                    "id": id,
                    "type": "message",
                    "role": "assistant",
                    "content": content,
                    "model": model,
                    "stop_reason": stop_reason,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                })
            },
        )
}

fn arb_anthropic_response_block() -> impl Strategy<Value = Value> {
    prop_oneof![
        // L5 (#269): 响应侧 block 未知字段同样保真 (read_block/write_block 与请求侧共享).
        ("[a-z ]{1,30}", prop::option::of(arb_cache_control())).prop_map(|(s, cc)| {
            let mut b = json!({"type": "text", "text": s});
            if let Some(cc) = cc {
                b["cache_control"] = cc;
            }
            b
        }),
        (
            "toolu_[a-z0-9]{5,10}",
            "[a-z]{3,10}",
            arb_nested_json_value()
        )
            .prop_map(|(id, name, input)| {
                json!({"type":"tool_use","id":id,"name":name,"input":input})
            }),
    ]
}

fn arb_anthropic_stop_reason() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!("end_turn")),
        Just(json!("max_tokens")),
        Just(json!("stop_sequence")),
        Just(json!("tool_use")),
    ]
}

// ─── FWD-1 半段式: redact 路径专用 helper + 生成器 ──────────────────────────

/// FWD-1 半段式断言 (OpenAI / Anthropic 共享): 同协议 + redact 路径下,
/// secret-guard 对 wire 的唯一合法修改是 real→mock.
///
/// 步骤 (与生产 `proxy/same_proto.rs::same_proto_forward` 完全一致):
/// 1. `reader.read_request(wire)` → IR
/// 2. `redact_ir(&mut IR, [secret])` → 替换 IR 字符串叶子 real→mock
/// 3. `writer.write_request(IR)` → wire_out
/// 4. 期望: `normalize(wire_out) == normalize(wire.replace_leaf(real, mock))`
///
/// `replace_leaf` = 遍历 wire JSON 的所有字符串叶子, 做 `s.replace(real, mock)`.
/// 与生产 redact 路径的 [`crate::redact::StringLeafOps`] 在 IR 字符串叶子上的替换等价.
fn assert_fwd1_half_segment(
    reader: &dyn Reader,
    writer: &dyn Writer,
    wire: Value,
    secret_value: &str,
) {
    let secrets = vec![make_secret_entry(secret_value)];

    let mut ir = reader.read_request(&wire).unwrap();
    let (map, _seed) = redact_ir(&mut ir, &secrets);
    let out = writer.write_request(&ir);

    // 期望: wire_out 等于把原 wire 中所有 real secret 字符串叶子替换为对应的 mock.
    let mock = map.mock_for(secret_value).expect("secret 应被 redact 命中");
    let mut expected = wire.clone();
    expected.for_each_str_leaf_mut(&mut |s| *s = s.replace(secret_value, mock));

    assert_eq!(
        normalize_json(&expected),
        normalize_json(&out),
        "FWD-1 半段式违反: redact 路径除了 real→mock 之外修改了 wire \
         (字段丢失 / 形态变化 / 未知信息损失)"
    );
}

/// 构造一个 SecretEntry (Auto mock 模式, 空 global_prefix), 与生产 redact 路径一致.
fn make_secret_entry(value: &str) -> SecretEntry {
    let mut e = SecretEntry {
        id: format!("id-{value}"),
        name: None,
        category: SecretCategory::ApiKey,
        value: value.into(),
        value_file: None,
        mock_strategy: crate::mock::MockStrategy::default(),
    };
    // 模拟生产: resolve_against 让 Auto 模式 infer gen spec.
    e.mock_strategy.resolve_against(&e.value, "");
    e
}

/// FWD-1 生成器: OpenAI wire + 注入的 secret (跨字段出现).
///
/// 契约 FWD-1 `prop_proptest_generator_covers_edge_cases` 要求覆盖:
/// - secret 跨字段重复 (content + user + system + tool_use input)
/// - 多个并行 tool_call (≥2, 验证 9712c52 修复的 index 分配)
///
/// 返回 (wire, secret_value). wire 中至少 1 处含 secret_value.
fn arb_openai_request_with_embedded_secret() -> impl Strategy<Value = (Value, String)> {
    ("[a-z]{8,16}", arb_openai_request_value()).prop_map(|(secret, mut req)| {
        let obj = req.as_object_mut().unwrap();

        // 1. system prompt 注入 (若存在 messages[0].role=system)
        if let Some(Value::Array(arr)) = obj.get_mut("messages") {
            for msg in arr.iter_mut() {
                if msg.get("role").and_then(Value::as_str) == Some("system") {
                    if let Some(Value::String(s)) = msg.get_mut("content") {
                        s.push_str(&format!(" sys:{secret}"));
                    }
                    break;
                }
            }

            // 2. messages[0].content 注入 (string / array 双形态)
            if let Some(Value::Object(first)) = arr.first_mut() {
                match first.get_mut("content") {
                    Some(Value::String(s)) => s.push_str(&format!(" token:{secret}")),
                    Some(Value::Array(parts)) => {
                        if let Some(Value::Object(part)) = parts.first_mut()
                            && let Some(Value::String(t)) = part.get_mut("text")
                        {
                            t.push_str(&format!(" token:{secret}"));
                        }
                    }
                    _ => {}
                }
            }

            // 3. assistant tool_calls: 注入合法 JSON secret 到 arguments
            //    (OpenAI arguments 是 JSON 字符串, 必须保持合法; redact 扫描字符串叶子命中)
            for msg in arr.iter_mut() {
                if let Some(Value::Array(tcs)) = msg.get_mut("tool_calls") {
                    for tc in tcs.iter_mut() {
                        if let Some(Value::String(args)) =
                            tc.get_mut("function").and_then(|f| f.get_mut("arguments"))
                        {
                            // 构造合法 JSON: {"secret_field":"<secret>"}
                            *args = format!(r#"{{"secret_field":"{secret}"}}"#);
                        }
                    }
                }
            }
        }

        // 4. user 字段注入 (OpenAI 顶层 user)
        obj.insert("user".to_string(), Value::String(format!("user-{secret}")));

        (req, secret)
    })
}

/// FWD-1 生成器: Anthropic wire + 注入的 secret.
fn arb_anthropic_request_with_embedded_secret() -> impl Strategy<Value = (Value, String)> {
    ("[a-z]{8,16}", arb_anthropic_request_value()).prop_map(|(secret, mut req)| {
        let obj = req.as_object_mut().unwrap();

        // 1. 顶层 system (Anthropic 风格)
        obj.insert("system".to_string(), Value::String(format!("sys-{secret}")));

        // 2. messages[*].content (string / array 双形态)
        if let Some(Value::Array(arr)) = obj.get_mut("messages") {
            for msg in arr.iter_mut() {
                if let Some(m) = msg.as_object_mut() {
                    match m.get_mut("content") {
                        Some(Value::String(s)) => s.push_str(&format!(" token:{secret}")),
                        Some(Value::Array(parts)) => {
                            for part in parts.iter_mut() {
                                if let Some(p) = part.as_object_mut() {
                                    // text block
                                    if let Some(Value::String(t)) = p.get_mut("text") {
                                        t.push_str(&format!(" token:{secret}"));
                                    }
                                    // tool_use block — 注入到 input
                                    if p.get("type").and_then(Value::as_str) == Some("tool_use")
                                        && let Some(Value::Object(input)) = p.get_mut("input")
                                    {
                                        input.insert(
                                            "secret_field".to_string(),
                                            Value::String(secret.clone()),
                                        );
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // 3. metadata.user_id (Anthropic user 字段位置)
        obj.insert(
            "metadata".to_string(),
            json!({"user_id": format!("user-{secret}")}),
        );

        (req, secret)
    })
}

// ─── 公共小工具生成器 ──────────────────────────────────────────────────────

fn arb_model_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("gpt-4o".to_string()),
        Just("gpt-4o-mini".to_string()),
        Just("gpt-5".to_string()),
        "[a-z]{3,8}-[a-z0-9]{2,5}".prop_map(|s| s),
    ]
}

fn arb_max_tokens_opt() -> impl Strategy<Value = Option<u32>> {
    prop::option::of(1u32..8000)
}

/// OpenAI 的 max_tokens 双读别名字段名 (#283): 二选一 (normalize 不做键名改写,
/// FWD-2 round-trip 必须按原字段名回写才相等). Anthropic 单字段, 不用此轴.
fn arb_openai_max_tokens_field() -> impl Strategy<Value = Option<(&'static str, u32)>> {
    prop::option::of((
        prop_oneof![Just("max_tokens"), Just("max_completion_tokens")],
        1u32..8000,
    ))
}

fn arb_temperature_opt() -> impl Strategy<Value = Option<f64>> {
    prop::option::of(0.0..2.0)
}

/// L7: stop 可能是 string / array / 空 string / 空 array.
fn arb_stop_opt() -> impl Strategy<Value = Option<Value>> {
    prop::option::of(prop_oneof![
        "[a-z]{2,8}".prop_map(Value::String),
        prop::collection::vec("[a-z]{2,8}", 1..3)
            .prop_map(|v| Value::Array(v.into_iter().map(Value::String).collect())),
        // L7 边界: 空字符串 / 空数组
        Just(Value::String(String::new())),
        Just(Value::Array(vec![])),
    ])
}

fn arb_tools_opt(count: std::ops::Range<usize>) -> impl Strategy<Value = Option<Vec<Value>>> {
    prop::option::of(prop::collection::vec(arb_tool_def(), count))
}

fn arb_tool_def() -> impl Strategy<Value = Value> {
    ("[a-z]{3,10}".prop_map(|s| s),).prop_map(|(name,)| {
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
    // 浅嵌套 JSON value (1-2 层) for tool_use input
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        "[a-z]{1,15}".prop_map(Value::String),
        (0i64..1000).prop_map(|n| json!(n)),
        prop::collection::vec("[a-z]{1,8}", 1..3)
            .prop_map(|v| { Value::Array(v.into_iter().map(Value::String).collect()) }),
        ("[a-z]{3,8}", "[a-z]{1,10}").prop_map(|(k, v)| {
            let mut m = serde_json::Map::new();
            m.insert(k, Value::String(v));
            Value::Object(m)
        }),
    ]
}
