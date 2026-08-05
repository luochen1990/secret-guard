//! 跨协议 SSE 翻译器 [`StreamTranslate`].
//!
//! 把 egress 协议的 SSE 字节流实时翻译为 ingress 协议的 SSE 字节流. 核心 pipeline:
//! ```text
//! egress SSE bytes
//!   → de-frame (按空行切分, 处理跨 chunk 不完整帧)
//!   → parse JSON
//!   → egress.reader.read_response_events() → Vec<IrStreamEvent>
//!   → (跨协议身份剥离 + usage backfill + post-stop guard)
//!   → ingress.writer.write_response_event() → (event_type, JSON)
//!   → re-frame (重新封装为 ingress SSE 字节)
//! → ingress SSE bytes
//! ```
//!
//! 同协议 + restore 模式下, BlockDelta 经 [`StreamingRestorer`] 处理跨 chunk mock 边界.
//!
//! # chunk-boundary
//!
//! 一个 SSE 帧 (`event: foo\n\ndata: {...}\n\n`) 可能被 TCP 切成多个 chunk,
//! 也会出现一个 chunk 包含多个帧的情况. 帧重组由共享骨架
//! [`super::SseReassembler`] 负责 (本类型持有一个实例, 通过 `feed` 委托). 扫描位置
//! (`scanned`) 持续推进以保持 O(n) 性能 (避免每次 feed 都重新扫描已搜索过的前缀).
//!
//! # 终止符
//!
//! OpenAI 流以 `data: [DONE]\n\n` 结尾; Anthropic 用 `event: message_stop` 终止.
//! StreamTranslate 在 [`StreamTranslate::finish`] 时根据 ingress writer 决定是否追加 `[DONE]`.

use super::reassembler::SseReassembler;
use super::{SSE_DONE_FRAME, reframe_sse};
use crate::codec::{
    Protocol, Reader, Writer,
    ir::{IrStreamEvent, StreamDecodeState},
};
use crate::redact::{DeltaKind, RedactionMap, StreamingRestorer, restore_str_inplace};
use std::collections::HashMap;

/// 跨协议 SSE 翻译器. 由 [`feed`](Self::feed) 喂入 egress 字节,
/// 由 [`finish`](Self::finish) 闭合流.
///
/// # 两种模式
///
/// - **跨协议翻译** ([`Self::new`]): ingress != egress, 把 egress SSE 翻译为 ingress SSE.
///   不做 redact restore (跨协议时 redact 在请求侧, response 直接翻译).
/// - **同协议 restore** ([`Self::new_same_proto_restore`]): ingress == egress, SSE 字节
///   解析为 IR 事件, 经 [`StreamingRestorer`] 还原 mock→real (sliding window, 跨 chunk 安全),
///   再序列化回 SSE. 用于同协议 + redact + 流式场景.
pub struct StreamTranslate {
    ingress_writer: Box<dyn Writer>,
    egress_reader: Box<dyn Reader>,
    decode: StreamDecodeState,
    /// SSE 帧 reassembly 骨架.
    reassembler: SseReassembler,
    /// 是否需要在 finish() 时追加 `[DONE]` (ingress 是 OpenAI 风格时为 true).
    emit_done: bool,
    /// 锁定的 message_start usage (Anthropic input_tokens; OpenAI None).
    /// 用于 terminal delta 的 input_tokens=0 时 backfill.
    start_usage: Option<crate::codec::IrUsage>,
    /// MessageStop 后是否再发 MessageDelta (post-stop guard).
    message_stopped: bool,
    /// 同协议 restore 模式: per-block sliding window restorer.
    /// 跨协议模式: `restorers` 空 + `redaction_map` None (不做 restore).
    redaction_map: Option<RedactionMap>,
    /// 每个 block index 对应一个独立 restorer (block 间 mock 边界互不干扰).
    restorers: HashMap<usize, StreamingRestorer>,
}

impl StreamTranslate {
    /// 构造跨协议翻译器. `None` 表示 `ingress == egress` (caller 应走字节透传或 restore 模式).
    pub fn new(ingress: Protocol, egress: Protocol) -> Option<Self> {
        if ingress == egress {
            return None;
        }
        Some(Self {
            ingress_writer: ingress.writer(),
            egress_reader: egress.reader(),
            decode: StreamDecodeState::default(),
            reassembler: SseReassembler::new(),
            emit_done: ingress.writer().emits_sse_done_terminator(),
            start_usage: None,
            message_stopped: false,
            redaction_map: None,
            restorers: HashMap::new(),
        })
    }

    /// 构造同协议 + restore 模式翻译器. 用于同协议 + redact + 流式响应场景.
    ///
    /// 工作流: egress SSE → parse IR events → [`StreamingRestorer`] (跨 chunk restore)
    /// → 序列化回 SSE. 失去 byte-exact (因为 IR re-serialize), 但语义等价,
    /// 同时保留流式 UX + 跨 chunk mock restore.
    pub fn new_same_proto_restore(proto: Protocol, map: RedactionMap) -> Self {
        Self {
            ingress_writer: proto.writer(),
            egress_reader: proto.reader(),
            decode: StreamDecodeState::default(),
            reassembler: SseReassembler::new(),
            emit_done: proto.writer().emits_sse_done_terminator(),
            start_usage: None,
            message_stopped: false,
            redaction_map: if map.is_empty() { None } else { Some(map) },
            restorers: HashMap::new(),
        }
    }

    /// 喂入一段 egress SSE 字节, 返回翻译后的 ingress SSE 字节
    /// (可能为空, 表示当前 chunk 还不足以构成完整帧).
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        // 共享 SSE 帧 reassembly (de-frame + parse + JSON), 把完整帧收集到局部 Vec,
        // 再循环调用 translate_event 处理. 借用隔离: 回调内不能拿 &mut self (reassembler
        // 已占用 &mut self), 所以采用"先收集后处理"模式.
        let mut frames: Vec<(String, serde_json::Value)> = Vec::new();
        self.reassembler.feed(chunk, |event_type, data| {
            frames.push((event_type.to_string(), data.clone()));
        });

        let mut out = Vec::new();
        for (event_type, data) in &frames {
            self.translate_event(event_type, data, &mut out);
        }
        out
    }

    /// 流终止. 返回末尾应追加的字节 (如 OpenAI ingress 的 `[DONE]`).
    ///
    /// 同时 flush 所有残留 restorers (上游异常未发 BlockStop 时, 某些 block 的 mock 尾部
    /// 可能还在 buffer 中). flush 出来的内容包装为对应 kind 的 BlockDelta emit.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.flush_all_restorers(&mut out);
        if self.reassembler.is_aborted() {
            // 流被异常中止: 发 ingress 协议的原生 error frame.
            let err = IrStreamEvent::Error("stream aborted: buffer overflow".into());
            self.emit_ir_event(&err, &mut out);
        }
        if self.emit_done {
            out.extend_from_slice(SSE_DONE_FRAME);
        }
        out
    }

    /// 翻译单个 egress SSE 事件 → 多个 IR 事件 → 多个 ingress SSE 帧.
    fn translate_event(&mut self, event_type: &str, data: &serde_json::Value, out: &mut Vec<u8>) {
        let events = self
            .egress_reader
            .read_response_events(event_type, data, &mut self.decode);
        for mut ev in events {
            // 跨协议身份剥离: 清掉 foreign id/created, 让 ingress writer 合成本地格式.
            // model 保留 (用于合成骨架, 且格式中立).
            if let IrStreamEvent::MessageStart {
                id, created, usage, ..
            } = &mut ev
            {
                if let Some(u) = usage {
                    self.start_usage = Some(u.clone()); // 锁定 input_tokens 用于 backfill
                }
                *id = None;
                *created = None;
            }

            // terminal usage backfill: 若 terminal delta 的 input_tokens==0, 用 start_usage 填回.
            if let IrStreamEvent::MessageDelta { usage, .. } = &mut ev
                && let Some(start) = &self.start_usage.clone()
            {
                if usage.input_tokens == 0 {
                    usage.input_tokens = start.input_tokens;
                }
                if usage.cache_read_input_tokens.is_none() {
                    usage.cache_read_input_tokens = start.cache_read_input_tokens;
                }
                if usage.cache_creation_input_tokens.is_none() {
                    usage.cache_creation_input_tokens = start.cache_creation_input_tokens;
                }
            }

            // post-stop guard: MessageStop 后若再来 MessageDelta, 仅当携带 usage 时放行
            // (OpenAI `stream_options.include_usage: true` 的末尾 usage chunk 就出现在
            // finish_reason chunk 之后, 我们在 reader 里把它解析为 MessageStop 之后的
            // MessageDelta; 丢弃它会让客户端拿不到 token 统计).
            // 无 usage 的 post-stop delta 是无意义的, 仍然丢弃.
            //
            // TODO(cross-proto-streaming): 当前 dispatch 对跨协议 + 流式返回 501, 所以
            // 此 guard 只影响 OpenAI egress. 未来接入跨协议流式 (OpenAI → Anthropic) 时,
            // Anthropic writer 会在 message_stop 之后收到 MessageDelta{usage} 并产生
            // 非法的 wire 顺序. 届时需要把 OpenAI 末尾 usage chunk 折叠到 message_stop
            // 之前的 message_delta, 或让 cross-proto 模式忽略此 guard.
            if self.message_stopped {
                if let IrStreamEvent::MessageDelta { usage, .. } = &ev {
                    if usage.is_zero() {
                        continue;
                    }
                } else if matches!(ev, IrStreamEvent::MessageStop) {
                    // 重复的 MessageStop, 丢弃.
                    continue;
                }
            }
            if matches!(ev, IrStreamEvent::MessageStop) {
                self.message_stopped = true;
            }

            // 同协议 restore 模式 (redaction_map = Some):
            //   - BlockStop: 先 flush 该 block 的尾部 buffer, emit 一个同 kind 的 BlockDelta.
            //   - MessageStop: flush 所有残留 restorers (上游异常漏发 BlockStop 时的兜底).
            //   - 其它: 走 restore_event_inplace (BlockDelta 内部走 sliding window).
            // 跨协议模式 (redaction_map = None): 不做 restore, 直接 emit.
            if self.redaction_map.is_some() {
                if let IrStreamEvent::BlockStop { index } = &ev
                    && let Some(tail_ev) = self.flush_block_as_event(*index)
                {
                    self.emit_ir_event(&tail_ev, out);
                }
                if matches!(ev, IrStreamEvent::MessageStop) {
                    // 上游异常漏发 BlockStop 时, 所有 restorers 残留 mock tail.
                    self.flush_all_restorers(out);
                }
                self.restore_event_inplace(&mut ev);
            }

            // BlockDelta 经 restorer.push 后内容可能为空 (全部 hold 在 buffer), 跳过 emit.
            if let IrStreamEvent::BlockDelta {
                delta:
                    crate::codec::ir::IrDelta::TextDelta(s)
                    | crate::codec::ir::IrDelta::InputJsonDelta(s),
                ..
            } = &ev
                && s.is_empty()
            {
                continue;
            }

            self.emit_ir_event(&ev, out);
        }
    }

    /// 对单个 event 应用 restore 逻辑 (in-place, 不改变 event 类型).
    /// BlockDelta 内容走 per-index sliding-window restorer.
    fn restore_event_inplace(&mut self, ev: &mut IrStreamEvent) {
        let Some(map) = &self.redaction_map else {
            return;
        };
        match ev {
            IrStreamEvent::BlockDelta { index, delta } => {
                let (kind, s) = match delta {
                    crate::codec::ir::IrDelta::TextDelta(s) => (DeltaKind::Text, s),
                    crate::codec::ir::IrDelta::InputJsonDelta(s) => (DeltaKind::InputJson, s),
                };
                let restorer = self
                    .restorers
                    .entry(*index)
                    .or_insert_with(|| StreamingRestorer::new(map.clone()));
                restorer.set_kind(kind);
                *s = restorer.push(std::mem::take(s));
            }
            IrStreamEvent::MessageDelta {
                stop_sequence: Some(s),
                ..
            } => restore_str_inplace(s, map),
            IrStreamEvent::Error(msg) => restore_str_inplace(msg, map),
            _ => {}
        }
    }

    /// BlockStop 时取出该 block 的 restorer 并 flush, 包装成一个 BlockDelta event.
    /// 若 buffer 为空则返回 None.
    fn flush_block_as_event(&mut self, index: usize) -> Option<IrStreamEvent> {
        let mut restorer = self.restorers.remove(&index)?;
        let (kind, tail) = restorer.flush();
        if tail.is_empty() {
            return None;
        }
        Some(IrStreamEvent::BlockDelta {
            index,
            delta: kind.to_ir_delta(tail),
        })
    }

    /// flush 所有残留 restorers (MessageStop / finish 兜底).
    ///
    /// 按 block index 升序 emit, 避免违反客户端对 delta 时序的隐含假设
    /// (eg OpenAI tool_call arguments partial JSON parser 假设按 index 顺序到达).
    /// 触发场景: 上游异常漏发 BlockStop 时, 多个 block 同时残留 mock tail.
    ///
    /// **注意**: 此路径产生的 BlockDelta 在 Anthropic ingress 下可能缺少配对的
    /// content_block_start/stop (上游异常时). 客户端通常宽容处理, 但严格来说是协议违例.
    fn flush_all_restorers(&mut self, out: &mut Vec<u8>) {
        let mut indices: Vec<_> = self.restorers.keys().copied().collect();
        indices.sort_unstable();
        for index in indices {
            if let Some(tail_ev) = self.flush_block_as_event(index) {
                self.emit_ir_event(&tail_ev, out);
            }
        }
    }

    /// 把单个 IR 事件通过 ingress writer 序列化为 SSE 帧并追加到 out.
    fn emit_ir_event(&self, ev: &IrStreamEvent, out: &mut Vec<u8>) {
        let Some((event_type, data)) = self.ingress_writer.write_response_event(ev) else {
            return; // writer 跳过此事件
        };
        out.extend_from_slice(&reframe_sse(&event_type, &data));
    }
}
