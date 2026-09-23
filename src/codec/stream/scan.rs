//! 流式 parsed view 累积器 [`StreamScan`].
//!
//! 与 [`super::StreamTranslate`] 的关注点正交:
//!   - StreamTranslate: egress SSE → ingress SSE (实时转换, 不保留完整内容).
//!   - StreamScan:      egress SSE → IrResponse  (不转换协议, 只累积语义内容).
//!
//! 用法: fan_out task 在 chunk 循环里 feed 每个 raw chunk, 节流地把 snapshot() 写入
//! DAG node 的 parsed 字段. 流结束时 snapshot() 即最终完整 IrResponse.
//! 对输入的要求: fan_out task 喂的是**原始上游字节** (LLM 视角, 含 mock 或未 redact).
//! snapshot() 产出的 IrResponse 直接序列化给前端 parsed view, 不经 restore (与当前
//! record 语义一致: record 存 LLM 视角).

use super::reassembler::SseReassembler;
use crate::codec::{
    Protocol, Reader,
    ir::{IrBlockMeta, IrStreamEvent, StreamDecodeState},
};

/// 单个 block 的累积状态 (流过程中用于暂存增量, finish 时折叠为 IrBlock).
#[derive(Debug, Default)]
struct ScanBlock {
    /// TextDelta 累积.
    text: String,
    /// InputJsonDelta 累积 (tool_use only).
    json_input: String,
    /// ReasoningDelta 累积 (reasoning block only, #176).
    reasoning: String,
    /// block 元信息 (BlockStart 时记录, 用于 finish 时构造 IrBlock).
    meta: Option<IrBlockMeta>,
}

/// 流式 SSE → IrResponse 累积器.
///
/// 内部维护 reassembly buffer (跨 chunk 不完整帧) + reader 的 `StreamDecodeState`
/// (OpenAI flat stream 的 block 边界合成). 调用者 feed 原始 SSE 字节, 累积器增量更新
/// 内部 `IrResponse`; 通过 [`snapshot`](Self::snapshot) 读取当前累积结果 (O(1) clone).
pub struct StreamScan {
    reader: Box<dyn Reader>,
    decode: StreamDecodeState,
    /// 累积的响应元数据 (model/id/created/usage/stop_reason 等).
    meta: IrResponseMeta,
    /// block index → 累积状态. 流过程中按 index 暂存, finish 时折叠为 `Vec<IrBlock>`.
    blocks: std::collections::BTreeMap<usize, ScanBlock>,
    /// 块的最终顺序 (finish 时按此顺序折叠, 与到达顺序一致).
    block_order: Vec<usize>,
    /// SSE 帧 reassembly 骨架.
    /// snapshot() 返回已累积的部分内容 (abort 不影响转发, 仅 WebUI 可见).
    pub(super) reassembler: SseReassembler,
}

/// IrResponse 的元数据部分 (从 MessageStart / MessageDelta 提取).
#[derive(Debug, Default, Clone)]
struct IrResponseMeta {
    model: Option<String>,
    id: Option<String>,
    created: Option<u64>,
    usage: crate::codec::IrUsage,
    /// 是否观测到过 usage 承载事件 (IrResponse.usage_present 的流式来源).
    ///
    /// 语义: MessageStart 携带 `usage: Some(_)` (Anthropic message_start), 或
    /// MessageDelta 的 `usage_present` 位为真 (wire 显式携带 usage 对象, 含全零).
    /// 与非流式 reader 的 presence 判定精确一致 (STR-2: scan ≡ 非流式 parse).
    usage_seen: bool,
    stop_reason: Option<crate::codec::IrStopReason>,
    stop_sequence: Option<String>,
}

impl StreamScan {
    pub fn new(proto: Protocol) -> Self {
        Self {
            reader: proto.reader(),
            decode: StreamDecodeState::default(),
            meta: IrResponseMeta::default(),
            blocks: std::collections::BTreeMap::new(),
            block_order: Vec::new(),
            reassembler: SseReassembler::new(),
        }
    }

    /// 喂入一段 raw SSE 字节 (可能跨帧 / 含不完整尾帧).
    /// 内部按帧边界解析, 把每个完整帧的 IR 事件增量累积.
    /// 不完整尾帧留在 buffer 等下次 feed 补全.
    ///
    /// 与 StreamTranslate 不同: StreamScan **不** 应用 post-stop guard, 因为
    /// OpenAI `stream_options.include_usage` 的 usage chunk 出现在 finish_reason
    /// chunk (MessageStop) 之后, StreamScan 需要收集它.
    ///
    /// 帧 reassembly (de-frame + parse + JSON + MAX_BUF abort) 委托给共享骨架
    /// `SseReassembler`, 本方法只负责把每个完整帧的 IR 事件累积到 meta / blocks.
    pub fn feed(&mut self, chunk: &[u8]) {
        let mut frames: Vec<(String, serde_json::Value)> = Vec::new();
        self.reassembler.feed(chunk, |event_type, data| {
            frames.push((event_type, data));
        });

        for (event_type, data) in &frames {
            let events = self
                .reader
                .read_response_events(event_type, data, &mut self.decode);
            for ev in events {
                self.apply_event(&ev);
            }
        }
    }

    /// 把单个 IR 事件累积到 meta / blocks.
    fn apply_event(&mut self, ev: &IrStreamEvent) {
        match ev {
            IrStreamEvent::MessageStart {
                id,
                created,
                model,
                usage,
            } => {
                if let Some(u) = usage {
                    self.meta.usage_seen = true;
                    self.meta.usage.input_tokens = u.input_tokens;
                    self.meta.usage.cache_creation_input_tokens = u.cache_creation_input_tokens;
                    self.meta.usage.cache_read_input_tokens = u.cache_read_input_tokens;
                }
                self.meta.id = id.clone().or(self.meta.id.take());
                self.meta.created = created.or(self.meta.created);
                self.meta.model = model.clone().or(self.meta.model.take());
            }
            IrStreamEvent::BlockStart { index, block } => {
                if !self.blocks.contains_key(index) {
                    self.block_order.push(*index);
                }
                let entry = self.blocks.entry(*index).or_default();
                entry.meta = Some(block.clone());
            }
            IrStreamEvent::BlockDelta { index, delta } => {
                let entry = self.blocks.entry(*index).or_default();
                match delta {
                    crate::codec::ir::IrDelta::TextDelta(s) => entry.text.push_str(s),
                    crate::codec::ir::IrDelta::InputJsonDelta(s) => entry.json_input.push_str(s),
                    crate::codec::ir::IrDelta::ReasoningDelta(s) => entry.reasoning.push_str(s),
                }
            }
            IrStreamEvent::BlockStop { index: _ } => {
                // 不删除 entry: finish 时按 block_order 折叠.
                // 这里不删除是为了让 snapshot() 在流过程中也能产出已 Stop 的块.
            }
            IrStreamEvent::MessageDelta {
                stop_reason,
                stop_sequence,
                usage,
                usage_present,
            } => {
                if let Some(sr) = stop_reason {
                    self.meta.stop_reason = Some(*sr);
                }
                if let Some(ss) = stop_sequence {
                    self.meta.stop_sequence = Some(ss.clone());
                }
                if *usage_present {
                    self.meta.usage_seen = true;
                }
                if usage.output_tokens > 0 {
                    self.meta.usage.output_tokens = usage.output_tokens;
                }
                // input usage (backfill): 若 terminal delta 携带了 input, 更新.
                if usage.input_tokens > 0 {
                    self.meta.usage.input_tokens = usage.input_tokens;
                }
                if usage.cache_read_input_tokens.is_some() {
                    self.meta.usage.cache_read_input_tokens = usage.cache_read_input_tokens;
                }
                if usage.cache_creation_input_tokens.is_some() {
                    self.meta.usage.cache_creation_input_tokens = usage.cache_creation_input_tokens;
                }
            }
            IrStreamEvent::MessageStop => {
                // 不应用 post-stop guard: StreamScan 需要收集 MessageStop 之后的
                // usage chunk (OpenAI stream_options.include_usage 格式).
            }
            IrStreamEvent::Error(_) => {}
        }
    }

    /// 当前累积的 IrResponse 快照 (O(blocks 总长) clone).
    /// 流过程中调用 → 到目前为止的累积结果; 流结束后调用 → 最终完整结果.
    pub fn snapshot(&self) -> crate::codec::IrResponse {
        let content: Vec<crate::codec::IrBlock> = self
            .block_order
            .iter()
            .filter_map(|idx| {
                let b = self.blocks.get(idx)?;
                fold_scan_block(b)
            })
            .collect();
        crate::codec::IrResponse {
            content,
            stop_reason: self.meta.stop_reason,
            stop_sequence: self.meta.stop_sequence.clone(),
            usage: self.meta.usage.clone(),
            usage_present: self.meta.usage_seen,
            model: self.meta.model.clone(),
            id: self.meta.id.clone(),
            created: self.meta.created,
        }
    }
}

/// 把 ScanBlock (累积状态) 折叠为最终 IrBlock.
/// - meta=ToolUse → ToolUse block (input JSON parse, 失败则用空 object)
/// - meta=ReasoningContent → ReasoningContent block (思考原文, 空内容不产出)
/// - meta=Text 或缺失 (上游漏发 BlockStart) → Text block
/// - 空内容 (text+json_input+reasoning 均空) → None (不产出空气泡)
fn fold_scan_block(b: &ScanBlock) -> Option<crate::codec::IrBlock> {
    match &b.meta {
        Some(IrBlockMeta::ToolUse { id, name }) => {
            let input = serde_json::from_str(&b.json_input).unwrap_or_default();
            Some(crate::codec::IrBlock::ToolUse {
                id: id.clone(),
                name: name.clone(),
                input,
                extra: Default::default(),
            })
        }
        Some(IrBlockMeta::ReasoningContent) => {
            if b.reasoning.is_empty() {
                None
            } else {
                Some(crate::codec::IrBlock::ReasoningContent {
                    text: b.reasoning.clone(),
                })
            }
        }
        // Text block 或 meta 缺失 (上游漏发 BlockStart, 退化为 Text).
        Some(IrBlockMeta::Text) | None => {
            if b.text.is_empty() && b.json_input.is_empty() {
                None
            } else {
                Some(crate::codec::IrBlock::Text {
                    text: b.text.clone(),
                    extra: Default::default(),
                })
            }
        }
    }
}
