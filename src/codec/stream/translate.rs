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
//! 同协议 + restore 模式下, BlockDelta 经调用方注入的 [`StreamRestoreHook`] 处理跨
//! chunk mock 边界 (hook 由 proxy 层注入, 让本模块不依赖 redact — 解除 codec ⇄ redact
//! 模块级循环, 见 #145 偏差 2).
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
    ir::{IrDelta, IrStreamEvent, StreamDecodeState},
};

// ─── StreamRestoreHook: restore 能力的接口倒置 (codec 不依赖 redact) ──────────
//
// 历史上 StreamTranslate 直接 `use crate::redact::{StreamingRestorer, ...}`, 与
// redact.rs `use crate::codec::ir::...` 构成模块级循环. Rust crate 内模块环合法,
// 但 AGENTS.md 规划 "新增协议只需实现 Reader + Writer trait" — codec 是独立可复用件,
// 这个环会让任何 codec 抽离都要把 StreamingRestorer 一起拖走. 这里把 restore 能力
// 倒置为 trait, 由调用方 (proxy/fan_out.rs, 唯一生产调用点) 注入实现, codec::stream
// 不再 import redact (ir.rs 本就零依赖, 是两者共同的纯类型下层).
//
// hook 自持 per-block 状态: index → 独立滑动窗口 (block 间 mock 边界互不干扰).
// StreamTranslate 只负责时序编排 (BlockStop flush / MessageStop / finish 兜底).

/// 流式 restore hook: 把流中 mock 片段还原为真实值, 由 proxy 层注入.
///
/// 契约 (由 `redact::StreamingRestorer` 实现, 行为对齐):
/// - [`Self::restore_delta`]: 还原一段 block delta 内容. 实现持有 per-index 跨 chunk
///   滑动窗口, 末尾 hold 字节直到能安全 emit. 返回空串表示当前内容全部 hold 在窗口内.
/// - [`Self::flush_delta`]: block 终止时冲刷该 index 的窗口残余, 返回 `(kind, tail)`.
///   `kind` 用于把 tail 包装回正确的 delta variant; 空串表示无残余.
/// - [`Self::flush_all`]: 流终止 / MessageStop 兜底: 冲刷**所有** index 的残余,
///   按 index 升序返回 (客户端假设 delta 按 index 顺序到达).
/// - [`Self::restore_inline`]: 就地还原完整出现在单个 event 内的字符串
///   (MessageDelta.stop_sequence / Error message; 无跨 chunk 边界问题).
pub trait StreamRestoreHook: Send {
    /// 还原一段 delta 内容 (跨 chunk 安全), 返回可安全 emit 的部分.
    fn restore_delta(&mut self, index: usize, kind: DeltaKind, s: String) -> String;
    /// 冲刷单个 block 的窗口残余 (BlockStop 时).
    fn flush_delta(&mut self, index: usize) -> (DeltaKind, String);
    /// 冲刷所有 block 的窗口残余 (MessageStop / finish 兜底), 按 index 升序.
    fn flush_all(&mut self) -> Vec<(usize, DeltaKind, String)>;
    /// 就地还原单 event 内的完整字符串 (无边界问题).
    fn restore_inline(&mut self, s: &mut String);
}

/// block delta 的类型标识 (Text / InputJson / Reasoning), flush 时恢复正确的 IrDelta variant.
///
/// 历史上定义在 `redact::DeltaKind` 并由 codec 消费; 接口倒置后归属 codec 侧
/// (hook 契约的一部分, 因 [`StreamRestoreHook::flush_delta`] 需要它包装返回值),
/// redact 侧 re-export 保持既有路径兼容.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaKind {
    Text,
    InputJson,
    /// 思考原文增量 (`delta.reasoning_content`, #176). 与 Text 同样是纯文本流,
    /// secret 可能泄漏进思考输出, 必须走同一 restore 滑窗路径.
    Reasoning,
}

impl DeltaKind {
    pub fn to_ir_delta(self, s: String) -> IrDelta {
        match self {
            DeltaKind::Text => IrDelta::TextDelta(s),
            DeltaKind::InputJson => IrDelta::InputJsonDelta(s),
            DeltaKind::Reasoning => IrDelta::ReasoningDelta(s),
        }
    }
}

/// 跨协议 SSE 翻译器. 由 [`feed`](Self::feed) 喂入 egress 字节,
/// 由 [`finish`](Self::finish) 闭合流.
///
/// # 两种模式
///
/// - **跨协议翻译** ([`Self::new`]): ingress != egress, 把 egress SSE 翻译为 ingress SSE.
///   不做 redact restore (跨协议时 redact 在请求侧, response 直接翻译).
/// - **同协议 restore** ([`Self::new_same_proto_restore`]): ingress == egress, SSE 字节
///   解析为 IR 事件, 经注入的 [`StreamRestoreHook`] 还原 mock→real (sliding window,
///   跨 chunk 安全), 再序列化回 SSE. 用于同协议 + redact + 流式场景.
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
    /// 同协议 restore 模式: 调用方注入的 restore hook (自持 per-block 状态).
    /// 跨协议模式: None (不做 restore).
    restore: Option<Box<dyn StreamRestoreHook>>,
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
            restore: None,
        })
    }

    /// 构造同协议 + restore 模式翻译器. 用于同协议 + redact + 流式响应场景.
    ///
    /// 工作流: egress SSE → parse IR events → `restore` hook (跨 chunk restore,
    /// 由调用方注入, 生产路径是 `redact::StreamingRestorerSet`) → 序列化回 SSE.
    /// 失去 byte-exact (因为 IR re-serialize), 但语义等价, 同时保留流式 UX +
    /// 跨 chunk mock restore.
    pub fn new_same_proto_restore(proto: Protocol, restore: Box<dyn StreamRestoreHook>) -> Self {
        Self {
            ingress_writer: proto.writer(),
            egress_reader: proto.reader(),
            decode: StreamDecodeState::default(),
            reassembler: SseReassembler::new(),
            emit_done: proto.writer().emits_sse_done_terminator(),
            start_usage: None,
            message_stopped: false,
            restore: Some(restore),
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
        self.emit_flush_all(&mut out);
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

            // 同协议 restore 模式 (restore hook 存在):
            //   - BlockStop: 先 flush 该 block 的尾部 buffer, emit 一个同 kind 的 BlockDelta.
            //   - MessageStop: flush 所有残留 restorers (上游异常漏发 BlockStop 时的兜底).
            //   - 其它: 走 restore_event_inplace (BlockDelta 内部走 sliding window).
            // 跨协议模式 (hook 不存在): 不做 restore, 直接 emit.
            if let Some(hook) = self.restore.as_mut() {
                let hook = hook.as_mut();
                // 借用隔离: hook 持 &mut self.restore 期间不能走 &self.emit_ir_event,
                // 故先收集本事件的全部 flush 产物, 释放借用后统一 emit.
                let mut flushes: Vec<IrStreamEvent> = Vec::new();
                if let IrStreamEvent::BlockStop { index } = &ev {
                    let (kind, tail) = hook.flush_delta(*index);
                    if !tail.is_empty() {
                        flushes.push(IrStreamEvent::BlockDelta {
                            index: *index,
                            delta: kind.to_ir_delta(tail),
                        });
                    }
                }
                if matches!(ev, IrStreamEvent::MessageStop) {
                    // 上游异常漏发 BlockStop 时, 所有 restorers 残留 mock tail.
                    flushes.extend(tail_events(hook.flush_all()));
                }
                restore_event_inplace(hook, &mut ev);
                for f in &flushes {
                    self.emit_ir_event(f, out);
                }
            }

            // BlockDelta 经 restorer.push 后内容可能为空 (全部 hold 在 buffer), 跳过 emit.
            if let IrStreamEvent::BlockDelta {
                delta:
                    IrDelta::TextDelta(s) | IrDelta::InputJsonDelta(s) | IrDelta::ReasoningDelta(s),
                ..
            } = &ev
                && s.is_empty()
            {
                continue;
            }

            self.emit_ir_event(&ev, out);
        }
    }

    /// finish() 的 flush 入口: 冲刷所有 block 的窗口残余, 包装为 BlockDelta emit.
    ///
    /// 借用隔离: 先从 hook 收集 flush 结果 (hook 持 &mut self.restore), 释放借用后
    /// 再走不可变的 emit_ir_event.
    ///
    /// 按 block index 升序 emit (由 hook 的 flush_all 保证), 避免违反客户端对 delta
    /// 时序的隐含假设 (eg OpenAI tool_call arguments partial JSON parser 假设按 index
    /// 顺序到达). 触发场景: 上游异常漏发 BlockStop 时, 多个 block 同时残留 mock tail.
    ///
    /// **注意**: 此路径产生的 BlockDelta 在 Anthropic ingress 下可能缺少配对的
    /// content_block_start/stop (上游异常时). 客户端通常宽容处理, 但严格来说是协议违例.
    fn emit_flush_all(&mut self, out: &mut Vec<u8>) {
        let flushed = self
            .restore
            .as_mut()
            .map(|hook| hook.flush_all())
            .unwrap_or_default();
        for ev in tail_events(flushed) {
            self.emit_ir_event(&ev, out);
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

/// hook `flush_all` 元组流 → BlockDelta 事件迭代器 (过滤空 tail).
///
/// MessageStop 分支 (translate_event 内收集) 与 finish 兜底 (emit_flush_all) 两处
/// 共用的转换 SSOT; 空 tail 过滤集中在此 (hook 实现不再预滤, 见 StreamingRestorerSet).
fn tail_events(flushed: Vec<(usize, DeltaKind, String)>) -> impl Iterator<Item = IrStreamEvent> {
    flushed
        .into_iter()
        .filter(|(_, _, tail)| !tail.is_empty())
        .map(|(index, kind, tail)| IrStreamEvent::BlockDelta {
            index,
            delta: kind.to_ir_delta(tail),
        })
}

/// 对单个 event 应用 restore 逻辑 (in-place, 不改变 event 类型).
/// BlockDelta 内容走 hook 的 per-index sliding-window.
fn restore_event_inplace(hook: &mut dyn StreamRestoreHook, ev: &mut IrStreamEvent) {
    match ev {
        IrStreamEvent::BlockDelta { index, delta } => {
            let (kind, s) = match delta {
                IrDelta::TextDelta(s) => (DeltaKind::Text, s),
                IrDelta::InputJsonDelta(s) => (DeltaKind::InputJson, s),
                IrDelta::ReasoningDelta(s) => (DeltaKind::Reasoning, s),
            };
            *s = hook.restore_delta(*index, kind, std::mem::take(s));
        }
        IrStreamEvent::MessageDelta {
            stop_sequence: Some(s),
            ..
        } => hook.restore_inline(s),
        IrStreamEvent::Error(msg) => hook.restore_inline(msg),
        _ => {}
    }
}
