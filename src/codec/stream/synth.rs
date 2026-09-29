//! 伪流式上游的形态适配: [`IrResponse`] → 完整 SSE 生命周期 (T5, 审计维度 9 前半).
//!
//! # 职责边界
//!
//! 当客户端显式声明 `stream=true` 而上游 (伪流式中转 / 不支持流式的网关) 对 2xx 响应
//! 返回单块 JSON 时, 转发链经 buffered 翻译产出完整 [`IrResponse`] — 本模块把它
//! **重放 (synthesize)** 为 ingress 协议的完整 SSE 事件流, 让 SDK 流式解析器拿到
//! 期望的 wire 形态 (事件序列 shape), 而非大概率报错的单块 JSON.
//!
//! 实现是纯胶水: `IrResponse` → [`IrStreamEvent`] 序列 (协议无关) → 各协议既有的
//! [`Writer::write_response_event`] (与流式翻译共享的同一序列化路径) → SSE 帧.
//! 不新增任何协议形态知识 — 事件生命周期 (start → block start/delta/stop 配对 →
//! delta → stop) 的合法性由 writer 既有实现保证.
//!
//! # 事件生命周期契约 (与各协议流式 reader 的解码状态机严格对齐)
//!
//! ```text
//! MessageStart{id, created, model, usage}
//! 对每个可承载 block (index 按 content 位置 0,1,2,...):
//!   BlockStart{index} → BlockDelta{index, 全量内容} → BlockStop{index}
//! MessageDelta{stop_reason, stop_sequence, usage, usage_present}
//! MessageStop
//! ```
//!
//! 单块整体 emit (一次 delta 事件带全量内容, 不模拟切块) — SDK 解析器关心事件序列
//! shape 不关心 chunk 粒度; 但**配对/生命周期必须完整**, 否则客户端解析器报错.
//!
//! # 与 StreamTranslate 的机制对齐
//!
//! - **跳过 block 配对过滤**: writer 对 `BlockStart` 返回空 Vec 的 index (如 Anthropic
//!   writer 对 o-origin 的 `IrBlockMeta::ReasoningContent` — o 协议无 opaque 容器,
//!   T7 裁决不为 o 发明 wire 形态), 其
//!   `BlockStop` 一并跳过, 否则产出未配对 `content_block_stop` (协议违例, #282 同型).
//!   与 `StreamTranslate` 跨协议模式的 `skipped_block_starts` 机制语义一致 (探测调用
//!   的幂等性由 writer 的幂等契约保证, 见 [`crate::codec::ir::ResponsesEncodeState`]).
//! - **终止符**: `emits_sse_done_terminator()` 为真的协议 (OpenAI) 在末尾追加
//!   `data: [DONE]`, 与 `StreamTranslate::finish` 同源.
//!
//! # 不可承载 block 的丢弃 与 thinking 族 origin 分派 (假设声明)
//!
//! 响应侧 [`crate::codec::IrBlock`] 的流式 emit 分派 (T7 后按 origin):
//! - Text / ToolUse: 各协议均有事件对应物, 全量单块 emit.
//! - `ReasoningContent{opaque: Some(Signature)}` (**a-origin** thinking): Thinking
//!   meta + 正文 ReasoningDelta + `SignatureDelta` — a writer verbatim 回写 signature
//!   (M1 修复的保真不因 synth 路径破坏), o writer 丢 signature + WARN, r writer 经
//!   envelope 搬进 encrypted_content (T7 origin 机制分派, 本模块零协议知识).
//! - `ReasoningContent{opaque: Some(RedactedData)}`: `RedactedThinking{data}` meta
//!   携全量数据, **无 delta** (与 Anthropic 真实流同型); o writer 跳过 (配对过滤
//!   兜住), r writer 经 envelope.
//! - `ReasoningContent{opaque: None}` (**o-origin**): 维持 T5 形态 (ReasoningContent
//!   meta + ReasoningDelta); a writer 不承载 (o 无容器, 配对过滤跳过整块).
//! - `Reasoning{summary, opaque}` (**r-origin** reasoning item): T5 曾整块跳过;
//!   T7 后 r/a 流式 writer 均可承载 — Thinking meta + summary 正文 delta +
//!   `ReasoningOpaqueDelta`(ec) (r writer verbatim 写回 done 帧; a writer 在 stop
//!   合成 envelope signature)。零信息 (空 summary + 无 ec) 跳过。
//! - ToolResult (属于下一轮 user 消息) / Image (assistant 一般不发) 不 emit 任何
//!   事件 — 与各 writer 非流式 `write_response` 的跳过行为对齐 (lossy-by-target).
//!
//! 调用方: `proxy::cross_proto` (buffered 翻译成功臂) 与 `proxy::fan_out` 的
//! `fan_out_buffered_ir` (same-proto + redact + 判型降级臂), 触发条件均为
//! "客户端请求 stream=true + 上游 2xx + codec 成功 parse"; 失败路径回落 buffered
//! JSON 现状 (best-effort 永不让请求失败, ROB-*).

use super::{SSE_DONE_FRAME, reframe_sse};
use crate::codec::Protocol;
use crate::codec::ir::{
    IrBlock, IrBlockMeta, IrDelta, IrResponse, IrStreamEvent, StreamEncodeState, ThinkingOpaque,
};

/// MessageStart 携带的 id/created 处理策略 (wire 形态合法性).
///
/// - [`Self::Keep`]: 保留 `IrResponse` 携带的 id/created — same-proto 路径, id 本就是
///   ingress 协议格式 (reader 读进来的), 回放保持 round-trip 一致.
/// - [`Self::Synthesize`]: 剥离 id/created, 由 ingress writer 合成本地格式 id —
///   cross-proto 路径, IrResponse 的 id 是 egress 格式 (如 Anthropic 的 `msg_...`),
///   直接出现在 OpenAI wire 上违反协议 id 格式约定 (与 `StreamTranslate` 的
///   "跨协议身份剥离" 同一裁决).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynthIdentity {
    Keep,
    Synthesize,
}

/// 把完整 [`IrResponse`] 重放为 `proto` 协议的完整 SSE 生命周期字节流.
///
/// 总函数 (total function): 序列化路径全部是既有 writer 的 `Value` 构造, 无失败分支;
/// 事件序列恒以 MessageStop (+ OpenAI 族 `[DONE]`) 终止.
pub fn synthesize_sse(proto: Protocol, resp: &IrResponse, identity: SynthIdentity) -> Vec<u8> {
    let writer = proto.writer();
    let mut encode = StreamEncodeState::default();
    // 跳过 block 配对过滤 (见模块文档): writer 对 BlockStart 返回空 Vec 的 index 集合.
    let mut skipped: std::collections::HashSet<usize> = std::collections::HashSet::new();

    let mut out = Vec::new();
    for ev in response_to_events(resp, identity) {
        // 探测 BlockStart: 空 Vec = writer 语义性跳过该 block (登记 index, 帧丢弃).
        // Responses writer 对 BlockStart 的重复调用幂等 (item_id 确定性合成),
        // 非 skipped 的 BlockStart 在下方再次调用 writer 正常 emit.
        if let IrStreamEvent::BlockStart { index, .. } = &ev
            && writer.write_response_event(&ev, &mut encode).is_empty()
        {
            skipped.insert(*index);
            continue;
        }
        // 配对过滤: 跳过 BlockStart 的 index 其 BlockStop 不 emit (未配对的
        // content_block_stop 是协议违例). OpenAI/Responses writer 对 BlockStop 恒不
        // 产未配对帧, 该过滤对它们是 no-op.
        if let IrStreamEvent::BlockStop { index } = &ev
            && skipped.contains(index)
        {
            continue;
        }
        for (event_type, data) in writer.write_response_event(&ev, &mut encode) {
            out.extend_from_slice(&reframe_sse(&event_type, &data));
        }
    }
    if writer.emits_sse_done_terminator() {
        out.extend_from_slice(SSE_DONE_FRAME);
    }
    out
}

/// IrResponse → 完整生命周期事件序列 (协议无关; 生命周期契约见模块文档).
fn response_to_events(resp: &IrResponse, identity: SynthIdentity) -> Vec<IrStreamEvent> {
    let (id, created) = match identity {
        SynthIdentity::Keep => (resp.id.clone(), resp.created),
        SynthIdentity::Synthesize => (None, None),
    };
    let mut events = Vec::with_capacity(2 + 3 * resp.content.len());
    // MessageStart 的 usage: Anthropic message_start 承载 input 侧 usage (真实流形态);
    // 仅在 wire 曾显式携带 (usage_present) 或数字非零时传 Some, 保持 round-trip 的
    // usage_present 语义 (StreamScan 把 Some(usage) 记为 usage_seen). OpenAI /
    // Responses writer 不读 MessageStart 的 usage, 多传无害.
    let start_usage = (resp.usage_present || !resp.usage.is_zero()).then(|| resp.usage.clone());
    events.push(IrStreamEvent::MessageStart {
        usage: start_usage,
        id,
        created,
        model: resp.model.clone(),
    });
    for (index, block) in resp.content.iter().enumerate() {
        // 可承载 block → (meta, deltas); 不可承载 (ToolResult / Image) 不 emit
        // 任何事件。deltas 数量可变: redacted 零 delta (数据在 start meta), a-origin
        // thinking 两个 (正文 + signature) — thinking 族按 origin 分派, 见模块文档
        // "不可承载 block 的丢弃 与 thinking 族 origin 分派"。
        let (block, deltas): (IrBlockMeta, Vec<IrDelta>) = match block {
            IrBlock::Text { text, .. } => {
                (IrBlockMeta::Text, vec![IrDelta::TextDelta(text.clone())])
            }
            IrBlock::ToolUse {
                id, name, input, ..
            } => (
                IrBlockMeta::ToolUse {
                    id: id.clone(),
                    name: name.clone(),
                },
                // 全量 arguments 一次性流出 (单块 emit, 见模块文档); input_to_string
                // 与非流式 writer 的 function.arguments 序列化同源 (JSON 字符串形态).
                vec![IrDelta::InputJsonDelta(crate::codec::input_to_string(
                    input,
                ))],
            ),
            IrBlock::ReasoningContent { text, opaque, .. } => match opaque {
                // a-origin thinking: Thinking meta (有合法 opaque 容器) + 正文 +
                // signature — writer 侧 verbatim / envelope 分派由 T7 origin 机制
                // 处理, 本模块只按 origin 选 meta/delta 形态。
                Some(ThinkingOpaque::Signature(sig)) => (
                    IrBlockMeta::Thinking,
                    vec![
                        IrDelta::ReasoningDelta(text.clone()),
                        IrDelta::SignatureDelta(sig.clone()),
                    ],
                ),
                // redacted_thinking: 纯密文, data 在 start 事件整体携带, 无 delta
                // (与 Anthropic 真实流的该 block 形态同型)。
                Some(ThinkingOpaque::RedactedData(data)) => (
                    IrBlockMeta::RedactedThinking { data: data.clone() },
                    Vec::new(),
                ),
                // o-origin: 维持 T5 形态 (a writer 不承载 o-origin, 配对过滤跳过)。
                None => (
                    IrBlockMeta::ReasoningContent,
                    vec![IrDelta::ReasoningDelta(text.clone())],
                ),
            },
            IrBlock::Reasoning {
                summary, opaque, ..
            } => {
                // r-origin reasoning item: T5 曾整块跳过; T7 后可承载 (r 原生 /
                // a envelope)。零信息 (空 summary + 无 ec) 跳过 — 与 T7 的退化
                // 丢弃规则 (thinking.rs::unpack) 一致。
                if summary.is_empty() && opaque.is_none() {
                    continue;
                }
                let text = summary.join("\n");
                let mut deltas = Vec::new();
                if !text.is_empty() {
                    deltas.push(IrDelta::ReasoningDelta(text));
                }
                if let Some(ec) = opaque {
                    deltas.push(IrDelta::ReasoningOpaqueDelta(ec.clone()));
                }
                (IrBlockMeta::Thinking, deltas)
            }
            IrBlock::ToolResult { .. } | IrBlock::Image { .. } => {
                continue;
            }
        };
        events.push(IrStreamEvent::BlockStart { index, block });
        for delta in deltas {
            events.push(IrStreamEvent::BlockDelta { index, delta });
        }
        events.push(IrStreamEvent::BlockStop { index });
    }
    events.push(IrStreamEvent::MessageDelta {
        stop_reason: resp.stop_reason,
        stop_sequence: resp.stop_sequence.clone(),
        usage: resp.usage.clone(),
        usage_present: resp.usage_present,
    });
    events.push(IrStreamEvent::MessageStop);
    events
}

#[cfg(test)]
mod tests {
    //! 合成 SSE 的两类守卫:
    //! 1. round-trip: 合成字节经对应协议 StreamScan 累积回的 IrResponse 与源语义等价
    //!    (message 内容 / stop_reason / usage — 消费方 SDK 拿到的是合法可解析的流).
    //! 2. wire 合法性: 生命周期配对完整 (start/stop 顺序, block 配对, [DONE] 终止符).

    use super::*;
    use crate::codec::stream::StreamScan;
    use crate::codec::{IrStopReason, IrUsage};
    use serde_json::json;

    /// 多 block fixture: 文本 + tool_use (行为边界自省: 多 content block 必须都 emit).
    fn sample_response() -> IrResponse {
        IrResponse {
            content: vec![
                IrBlock::Text {
                    text: "让我查一下天气".into(),
                    extra: Default::default(),
                },
                IrBlock::ToolUse {
                    id: "call_1".into(),
                    name: "get_weather".into(),
                    input: json!({"city": "北京"}),
                    extra: Default::default(),
                },
            ],
            stop_reason: Some(IrStopReason::ToolUse),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 12,
                output_tokens: 34,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            usage_present: true,
            model: Some("test-model".into()),
            id: Some("id-src".into()),
            created: Some(1700000000),
        }
    }

    /// round-trip 等价断言: content blocks / stop_reason / usage / model / id / created.
    /// (Keep 模式下 id/created 一并 round-trip; block extra 不参与 — scan 折叠的
    /// block 恒 Default extra, 与 reader 从 wire 读入的形态一致.)
    fn assert_round_trip(proto: Protocol, source: &IrResponse, identity: SynthIdentity) {
        let sse = synthesize_sse(proto, source, identity);
        let mut scan = StreamScan::new(proto);
        scan.feed(&sse);
        let back = scan.snapshot();
        assert_eq!(back.content.len(), source.content.len(), "block count");
        for (b, s) in back.content.iter().zip(source.content.iter()) {
            match (b, s) {
                (IrBlock::Text { text: bt, .. }, IrBlock::Text { text: st, .. }) => {
                    assert_eq!(bt, st, "text content");
                }
                (
                    IrBlock::ToolUse {
                        id: bid,
                        name: bname,
                        input: binput,
                        ..
                    },
                    IrBlock::ToolUse {
                        id: sid,
                        name: sname,
                        input: sinput,
                        ..
                    },
                ) => {
                    assert_eq!(bid, sid, "tool id");
                    assert_eq!(bname, sname, "tool name");
                    assert_eq!(binput, sinput, "tool input JSON");
                }
                (other_b, other_s) => panic!("block kind mismatch: {other_b:?} vs {other_s:?}"),
            }
        }
        assert_eq!(back.stop_reason, source.stop_reason, "stop_reason");
        assert_eq!(back.usage, source.usage, "usage");
        assert_eq!(back.usage_present, source.usage_present, "usage_present");
        assert_eq!(back.model, source.model, "model");
        if identity == SynthIdentity::Keep {
            assert_eq!(back.id, source.id, "id (Keep)");
            // created: Anthropic wire 不携带该字段 (message_start 无 created, 非流式
            // write_response 亦不写) — 跳过断言是协议能力边界而非合成缺陷.
            if proto != Protocol::Anthropic {
                assert_eq!(back.created, source.created, "created (Keep)");
            }
        }
    }

    #[test]
    fn synth_round_trip_openai() {
        assert_round_trip(Protocol::OpenAI, &sample_response(), SynthIdentity::Keep);
        assert_round_trip(
            Protocol::OpenAI,
            &sample_response(),
            SynthIdentity::Synthesize,
        );
    }

    #[test]
    fn synth_round_trip_anthropic() {
        assert_round_trip(Protocol::Anthropic, &sample_response(), SynthIdentity::Keep);
        assert_round_trip(
            Protocol::Anthropic,
            &sample_response(),
            SynthIdentity::Synthesize,
        );
    }

    #[test]
    fn synth_round_trip_responses() {
        assert_round_trip(
            Protocol::OpenAIResponses,
            &sample_response(),
            SynthIdentity::Keep,
        );
        assert_round_trip(
            Protocol::OpenAIResponses,
            &sample_response(),
            SynthIdentity::Synthesize,
        );
    }

    /// 空内容响应 (无 block): 生命周期仍完整 (start → delta → stop), 不捏造 block.
    #[test]
    fn synth_empty_content_yields_valid_lifecycle() {
        let resp = IrResponse {
            content: vec![],
            stop_reason: Some(IrStopReason::EndTurn),
            usage: IrUsage {
                input_tokens: 5,
                output_tokens: 0,
                ..Default::default()
            },
            usage_present: true,
            ..Default::default()
        };
        for proto in [
            Protocol::OpenAI,
            Protocol::Anthropic,
            Protocol::OpenAIResponses,
        ] {
            let sse = synthesize_sse(proto, &resp, SynthIdentity::Keep);
            assert!(!sse.is_empty(), "{proto:?}: lifecycle must emit bytes");
            let mut scan = StreamScan::new(proto);
            scan.feed(&sse);
            let back = scan.snapshot();
            assert!(back.content.is_empty(), "{proto:?}: {back:?}");
            assert_eq!(back.stop_reason, Some(IrStopReason::EndTurn));
            assert_eq!(back.usage.input_tokens, 5);
        }
    }

    /// ReasoningContent (思考原文) 在 OpenAI / Responses ingress 的合成覆盖:
    /// o ingress 合成 `delta.reasoning_content` chunk 流, r ingress 合成 reasoning
    /// item (`rs_*`) 的 added/delta/done 完整族 — 两方向 round-trip 内容保真, 且
    /// Synthesize 模式下 foreign id 不上 wire (身份剥离对三协议一致).
    /// (Anthropic 方向的跳过 + 配对过滤由上方 pairing 测试覆盖.)
    #[test]
    fn synth_reasoning_content_round_trip_openai_and_responses() {
        let resp = IrResponse {
            content: vec![
                IrBlock::ReasoningContent {
                    text: "chain of thought".into(),
                    // o-origin (opaque=None): 本测试的 T5 覆盖面; a-origin 分派由
                    // synth_anthropic_thinking_signature_preserved 锁定。
                    opaque: None,
                    extra: Default::default(),
                },
                IrBlock::Text {
                    text: "final answer".into(),
                    extra: Default::default(),
                },
            ],
            stop_reason: Some(IrStopReason::EndTurn),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 7,
                output_tokens: 11,
                ..Default::default()
            },
            usage_present: true,
            model: Some("deepseek-r".into()),
            id: Some("foreign-id-xyz".into()),
            created: Some(1700000000),
        };
        for proto in [Protocol::OpenAI, Protocol::OpenAIResponses] {
            for identity in [SynthIdentity::Keep, SynthIdentity::Synthesize] {
                let sse = synthesize_sse(proto, &resp, identity);
                let client = String::from_utf8_lossy(&sse);
                if identity == SynthIdentity::Synthesize {
                    assert!(
                        !client.contains("foreign-id-xyz"),
                        "{proto:?}: foreign id must not reach wire: {client}"
                    );
                }
                let mut scan = StreamScan::new(proto);
                scan.feed(&sse);
                let back = scan.snapshot();
                assert_eq!(
                    back.content.len(),
                    2,
                    "{proto:?}/{identity:?}: reasoning + text both delivered: {back:?}"
                );
                match (&back.content[0], &back.content[1]) {
                    (
                        IrBlock::ReasoningContent { text: rt, .. },
                        IrBlock::Text { text: tt, .. },
                    ) => {
                        assert_eq!(rt, "chain of thought", "{proto:?}");
                        assert_eq!(tt, "final answer", "{proto:?}");
                    }
                    other => panic!("{proto:?}: unexpected block kinds {other:?}"),
                }
                assert_eq!(back.stop_reason, Some(IrStopReason::EndTurn));
                assert_eq!(back.usage.output_tokens, 11, "{proto:?}");
            }
        }
    }

    /// Anthropic 跨协议身份剥离 + 不可承载 block 的配对过滤: ReasoningContent 在
    /// Anthropic writer 被跳过 (thinking 无法合成), 其 BlockStop 不得产出孤儿帧;
    /// message_start 必须是首帧, message_stop 是末帧.
    #[test]
    fn synth_anthropic_event_pairing_and_lifecycle_order() {
        let resp = IrResponse {
            content: vec![
                IrBlock::ReasoningContent {
                    text: "thinking...".into(),
                    // o-origin: a writer 不承载 (无 opaque 容器), 配对过滤跳过整块
                    // — 本测试的 T5 覆盖面 (reasoning 不泄漏断言)。
                    opaque: None,
                    extra: Default::default(),
                },
                IrBlock::Text {
                    text: "answer".into(),
                    extra: Default::default(),
                },
            ],
            stop_reason: Some(IrStopReason::EndTurn),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 3,
                output_tokens: 7,
                ..Default::default()
            },
            usage_present: true,
            model: Some("m".into()),
            id: Some("msg_foreign".into()),
            created: None,
        };
        let sse = synthesize_sse(Protocol::Anthropic, &resp, SynthIdentity::Synthesize);
        let client = String::from_utf8_lossy(&sse);
        let frames = super::super::iter_sse_frames(sse.as_slice());
        assert!(!frames.is_empty());

        // 生命周期顺序: message_start 首 / message_stop 末 / 恰一个.
        assert_eq!(
            frames.first().map(|(et, _)| et.as_str()),
            Some("message_start")
        );
        assert_eq!(
            frames.last().map(|(et, _)| et.as_str()),
            Some("message_stop")
        );
        assert_eq!(
            frames.iter().filter(|(et, _)| et == "message_stop").count(),
            1
        );

        // block 配对: 每个 content_block_stop 有同 index 前置 start; delta 同理.
        let mut open = std::collections::BTreeSet::new();
        for (et, data) in &frames {
            let index = data.get("index").and_then(serde_json::Value::as_u64);
            match et.as_str() {
                "content_block_start" => {
                    assert!(open.insert(index.unwrap()), "dup start: {client}");
                }
                "content_block_delta" => {
                    assert!(open.contains(&index.unwrap()), "orphan delta: {client}");
                }
                "content_block_stop" => {
                    assert!(open.remove(&index.unwrap()), "orphan stop: {client}");
                }
                _ => {}
            }
        }
        assert!(open.is_empty(), "unclosed block: {client}");

        // 身份剥离: foreign id 不得上 wire (writer 合成 msg_... 本地格式).
        assert!(
            !client.contains("msg_foreign"),
            "foreign id leaked: {client}"
        );
        // reasoning 内容被 Anthropic writer 丢弃 (已知损失 #176), 文本保留.
        assert!(
            !client.contains("thinking..."),
            "reasoning leaked: {client}"
        );
        assert!(client.contains("answer"), "text lost: {client}");
    }

    /// OpenAI / Responses 终止符契约: OpenAI 追加 `data: [DONE]`, Responses 不追加
    /// (response.completed 终止). 多 block (文本 + tool_use) 都到达客户端.
    #[test]
    fn synth_openai_done_terminator_and_multi_block_delivery() {
        let oai = synthesize_sse(Protocol::OpenAI, &sample_response(), SynthIdentity::Keep);
        let oai_text = String::from_utf8_lossy(&oai);
        assert!(
            oai_text.ends_with("data: [DONE]\n\n"),
            "OpenAI must end with [DONE]: {oai_text}"
        );
        assert!(
            oai_text.contains("\"content\":\"让我查一下天气\""),
            "{oai_text}"
        );
        assert!(oai_text.contains("\"name\":\"get_weather\""), "{oai_text}");
        assert!(
            oai_text.contains("\"finish_reason\":\"tool_calls\""),
            "{oai_text}"
        );
        // usage 到达 (finish chunk 携带合并 usage).
        assert!(oai_text.contains("\"prompt_tokens\":12"), "{oai_text}");

        let r = synthesize_sse(
            Protocol::OpenAIResponses,
            &sample_response(),
            SynthIdentity::Keep,
        );
        let r_text = String::from_utf8_lossy(&r);
        assert!(
            !r_text.contains("[DONE]"),
            "Responses has no [DONE]: {r_text}"
        );
        assert!(r_text.contains("event: response.completed"), "{r_text}");
        assert!(
            r_text.contains("event: response.output_item.added"),
            "{r_text}"
        );
    }
    /// T5×T7 语义交互 ①: a-origin thinking 块 (含 signature) 经 synth 的同协议
    /// (Anthropic) round-trip 不丢 signature — 修复前 synth 无条件用
    /// ReasoningContent meta (o-origin 路径), a writer 跳过整块或丢 signature,
    /// M1 修复的保真被 synth 路径破坏。修复后: Thinking meta + ReasoningDelta +
    /// SignatureDelta → a writer verbatim 回写; StreamScan 折叠回带 signature 的块。
    #[test]
    fn synth_anthropic_thinking_signature_preserved() {
        let resp = IrResponse {
            content: vec![
                IrBlock::ReasoningContent {
                    text: "internal deliberation".into(),
                    opaque: Some(ThinkingOpaque::Signature("SIGsynth01".into())),
                    extra: Default::default(),
                },
                IrBlock::Text {
                    text: "answer".into(),
                    extra: Default::default(),
                },
            ],
            stop_reason: Some(IrStopReason::EndTurn),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 3,
                output_tokens: 7,
                ..Default::default()
            },
            usage_present: true,
            model: Some("claude-x".into()),
            id: Some("msg_1".into()),
            created: None,
        };
        let sse = synthesize_sse(Protocol::Anthropic, &resp, SynthIdentity::Keep);
        let client = String::from_utf8_lossy(&sse);
        // wire: thinking block 完整生命周期, signature verbatim 到达。
        assert!(
            client.contains("\"type\":\"thinking\""),
            "thinking start frame missing: {client}"
        );
        assert!(
            client.contains("\"thinking\":\"internal deliberation\""),
            "thinking text missing: {client}"
        );
        assert!(
            client.contains("\"signature\":\"SIGsynth01\""),
            "signature lost in synth path: {client}"
        );
        // StreamScan round-trip: 折叠回 ReasoningContent{text, Signature}。
        let mut scan = StreamScan::new(Protocol::Anthropic);
        scan.feed(&sse);
        let back = scan.snapshot();
        assert!(
            matches!(
                &back.content[0],
                IrBlock::ReasoningContent {
                    text,
                    opaque: Some(ThinkingOpaque::Signature(sig)),
                    ..
                } if text == "internal deliberation" && sig == "SIGsynth01"
            ),
            "scan fold must carry text + signature: {:?}",
            back.content
        );
        // redacted_thinking: data 在 start 事件整体携带, 无 delta, wire 上原样到达。
        let redacted = IrResponse {
            content: vec![IrBlock::ReasoningContent {
                text: String::new(),
                opaque: Some(ThinkingOpaque::RedactedData("RDEXTRACT9".into())),
                extra: Default::default(),
            }],
            ..resp.clone()
        };
        let sse2 = synthesize_sse(Protocol::Anthropic, &redacted, SynthIdentity::Keep);
        let client2 = String::from_utf8_lossy(&sse2);
        assert!(
            client2.contains("\"type\":\"redacted_thinking\"")
                && client2.contains("\"data\":\"RDEXTRACT9\""),
            "redacted_thinking data missing: {client2}"
        );
        // 配对完整 (redacted 无 delta 也必须有 stop)。
        let frames = super::super::iter_sse_frames(sse2.as_slice());
        assert!(
            frames
                .iter()
                .any(|(et, d)| et == "content_block_stop" && d["index"].as_u64() == Some(0)),
            "redacted block must close: {client2}"
        );
    }

    /// T5×T7 语义交互 ②: r-origin reasoning 块 (含 ec) 经 synth 不再整块消失 —
    /// 同协议 (Responses) round-trip ec verbatim; 跨协议 (Anthropic ingress) 经
    /// a writer 的 stop-time envelope 打包 (stateless tool loop 闭合到 synth 路径)。
    #[test]
    fn synth_responses_reasoning_ec_preserved() {
        let resp = IrResponse {
            content: vec![IrBlock::Reasoning {
                summary: vec!["summary text".into()],
                opaque: Some("ECsynth02".into()),
                extra: Default::default(),
            }],
            stop_reason: Some(IrStopReason::EndTurn),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 5,
                output_tokens: 9,
                ..Default::default()
            },
            usage_present: true,
            model: Some("gpt-5".into()),
            id: Some("resp_1".into()),
            created: Some(1700000000),
        };

        // 同协议 r: done 族帧携带 ec verbatim (T5 曾整块跳过)。
        let sse = synthesize_sse(Protocol::OpenAIResponses, &resp, SynthIdentity::Keep);
        let client = String::from_utf8_lossy(&sse);
        assert!(
            client.contains("\"delta\":\"summary text\""),
            "summary delta missing: {client}"
        );
        assert!(
            client.contains("\"encrypted_content\":\"ECsynth02\""),
            "ec must be written verbatim into done frames: {client}"
        );
        // StreamScan 折叠: opaque 存活。
        let mut scan = StreamScan::new(Protocol::OpenAIResponses);
        scan.feed(&sse);
        let back = scan.snapshot();
        assert!(
            matches!(
                &back.content[0],
                IrBlock::ReasoningContent { text, opaque, .. }
                    if text == "summary text"
                        && matches!(opaque, Some(ThinkingOpaque::Signature(ec)) if ec == "ECsynth02")
            ),
            "scan fold must carry summary + ec: {:?}",
            back.content
        );

        // 跨协议 a ingress: thinking 块 + envelope signature (解包还原原生 r 块)。
        let sse_a = synthesize_sse(Protocol::Anthropic, &resp, SynthIdentity::Synthesize);
        let client_a = String::from_utf8_lossy(&sse_a);
        assert!(
            client_a.contains("\"thinking\":\"summary text\""),
            "thinking text (from summary) missing: {client_a}"
        );
        let frames_a = super::super::iter_sse_frames(sse_a.as_slice());
        let sig = frames_a
            .iter()
            .find(|(et, d)| et == "content_block_delta" && d["delta"]["type"] == "signature_delta")
            .map(|(_, d)| d["delta"]["signature"].as_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("envelope signature_delta missing: {client_a}"));
        assert!(
            crate::codec::thinking::unpack(&sig).is_some_and(|b| matches!(
                &b,
                IrBlock::Reasoning { summary, opaque, .. }
                    if summary == &vec!["summary text".to_string()]
                        && opaque.as_deref() == Some("ECsynth02")
            )),
            "envelope must unpack to native Reasoning block: {sig}"
        );
    }
}
