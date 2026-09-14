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
//! 同协议 restore 模式与跨协议 + redact 模式下, BlockDelta 经调用方注入的
//! [`StreamRestoreHook`] 处理跨 chunk mock 边界 (hook 由 proxy 层注入, 让本模块
//! 不依赖 redact — 解除 codec ⇄ redact 模块级循环, 见 #145 偏差 2).
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
/// # 三种模式
///
/// - **跨协议翻译** ([`Self::new_cross_proto`], 兼容入口 [`Self::new`]): ingress != egress,
///   把 egress SSE 翻译为 ingress SSE. 可选注入 [`StreamRestoreHook`] 做响应侧
///   mock→real 还原 (跨协议 + redact 场景; 无 redact 传 `None`).
///   跨协议模式额外启用两个 wire 合法性机制 (同协议模式**不启用**, 行为由现有
///   property 测试锁定):
///   - **跳过 block 的配对过滤**: ingress writer 对 `BlockStart` 返回 None 的 index
///     (如 Anthropic writer 对 `IrBlockMeta::ReasoningContent` — thinking block 需
///     signature 无法合成) 记入集合, 同 index 的 `BlockStop` 一并跳过 — 否则会 emit
///     未配对的 `content_block_stop` (协议违例). `BlockDelta` 不在过滤范围: OpenAI
///     writer 对 Text/Reasoning 的 `BlockStart` 返回 None 是**结构性隐式** (delta 仍
///     是内容, 必须照常 emit), 语义性整体跳过只发生在 Anthropic writer 对
///     ReasoningContent (其 `ReasoningDelta` 本就被 writer 跳过).
///   - **deferred message_stop**: OpenAI egress 开 `include_usage` 时末尾 usage chunk
///     在 finish_reason 之后 → IR 时序 MessageStop 之后跟 MessageDelta{usage}. 但
///     Anthropic ingress 若在 message_stop 后再 emit message_delta 是非法 wire 顺序
///     (Anthropic 规范 message_delta 在 message_stop 之前). 故 MessageStop 先缓存,
///     post-stop usage delta 到达则先 emit delta 再 flush 缓存的 stop; `finish()`
///     时 flush 残留.
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
    /// 跨协议模式: MessageStop 已缓存未 emit (deferred stop, 见结构体文档).
    pending_stop: bool,
    /// 跨协议模式标志 (deferred stop + 配对过滤 仅跨协议启用; 同协议行为锁定).
    cross_proto: bool,
    /// ingress writer 对 BlockStart 返回 None 的 block index 集合 (配对过滤, 见
    /// 结构体文档). 同协议模式恒空 (不启用过滤).
    skipped_block_starts: std::collections::HashSet<usize>,
    /// 同协议 restore 模式: 调用方注入的 restore hook (自持 per-block 状态).
    /// 跨协议模式: redact 场景注入 (响应侧 mock→real), 无 redact 为 None.
    restore: Option<Box<dyn StreamRestoreHook>>,
}

impl StreamTranslate {
    /// 构造跨协议翻译器 (兼容入口, 无 restore). `None` 表示 `ingress == egress`
    /// (caller 应走字节透传或 restore 模式). 返回的实例以跨协议模式运行
    /// (deferred stop + 配对过滤启用, 见结构体文档).
    pub fn new(ingress: Protocol, egress: Protocol) -> Option<Self> {
        Self::new_cross_proto(ingress, egress, None)
    }

    /// 构造跨协议翻译器 (完整入口).
    ///
    /// - `ingress == egress` 时返回 `None` (caller 应走字节透传或同协议 restore 模式).
    /// - `restore`: 跨协议 + redact 场景注入响应侧 mock→real 还原 hook (生产实现
    ///   `redact::StreamingRestorerSet`, 由 proxy 注入 — codec 不依赖 redact, 解环
    ///   #145); 无 redact 传 `None`.
    pub fn new_cross_proto(
        ingress: Protocol,
        egress: Protocol,
        restore: Option<Box<dyn StreamRestoreHook>>,
    ) -> Option<Self> {
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
            pending_stop: false,
            cross_proto: true,
            skipped_block_starts: std::collections::HashSet::new(),
            restore,
        })
    }

    /// 构造同协议 + restore 模式翻译器. 用于同协议 + redact + 流式响应场景.
    ///
    /// 工作流: egress SSE → parse IR events → `restore` hook (跨 chunk restore,
    /// 由调用方注入, 生产路径是 `redact::StreamingRestorerSet`) → 序列化回 SSE.
    /// 失去 byte-exact (因为 IR re-serialize), 但语义等价, 同时保留流式 UX +
    /// 跨 chunk mock restore.
    ///
    /// 同协议模式**不启用** deferred stop 与配对过滤 (OpenAI 原生顺序
    /// finish→usage 合法, 行为由 `fwd_streaming_property.rs` 的 property 测试锁定).
    pub fn new_same_proto_restore(proto: Protocol, restore: Box<dyn StreamRestoreHook>) -> Self {
        Self {
            ingress_writer: proto.writer(),
            egress_reader: proto.reader(),
            decode: StreamDecodeState::default(),
            reassembler: SseReassembler::new(),
            emit_done: proto.writer().emits_sse_done_terminator(),
            start_usage: None,
            message_stopped: false,
            pending_stop: false,
            cross_proto: false,
            skipped_block_starts: std::collections::HashSet::new(),
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
            frames.push((event_type, data));
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
    /// 跨协议模式下 deferred MessageStop 的残留也在此 flush (上游未发 post-stop
    /// usage delta 的常态路径).
    ///
    /// **顺序边界 (病态上游)**: 若 pending_stop 已被 post-stop usage delta 提前 flush,
    /// 此处 `emit_flush_all` 的残余 block 尾部会落在已发出的 message_stop **之后**.
    /// 该形态仅当 "block 未闭合 + MessageStop + post-stop 非零 usage delta" 三者同时
    /// 成立时可达 — OpenAI reader 在 finish_reason 无条件 close_open_blocks,
    /// Anthropic egress 无 post-stop usage 形态, 两个真实 reader 都产不出该组合,
    /// 仅手工构造的病态 wire 可达 (同协议模式无此不对称: MessageStop 处先 flush_all).
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.emit_flush_all(&mut out);
        if self.reassembler.is_aborted() {
            // 流被异常中止: 发 ingress 协议的原生 error frame.
            let err = IrStreamEvent::Error("stream aborted: buffer overflow".into());
            self.emit_ir_event(&err, &mut out);
        }
        // deferred stop flush (跨协议模式; 同协议 pending_stop 恒 false, 零开销).
        // 顺序: 在 [DONE] 之前 — message_stop 是 Anthropic ingress 的流终止 event,
        // [DONE] 是 OpenAI ingress 的流终止符, 两者互斥但都应最后发出.
        if self.pending_stop {
            self.pending_stop = false;
            self.emit_ir_event(&IrStreamEvent::MessageStop, &mut out);
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

            // post-stop guard + deferred MessageStop. 两模式共用 message_stopped
            // 标志, 但 post-stop 放行策略不同 (同协议行为锁定, 跨协议为 wire
            // 合法性收紧):
            //
            // - 同协议模式 (既有行为, property 测试锁定): MessageStop 后若再来
            //   MessageDelta, 仅当携带非零 usage 时放行 (OpenAI
            //   `stream_options.include_usage: true` 的末尾 usage chunk 就出现在
            //   finish_reason chunk 之后, 丢弃它会让客户端拿不到 token 统计);
            //   重复 MessageStop 丢弃; 其余事件类型放行 (OpenAI 原生顺序
            //   finish→usage 合法, 无 wire 顺序问题).
            // - 跨协议模式 (deferred stop): MessageStop 不立即 emit 而是缓存
            //   (pending_stop). post-stop 只放行带非零 usage 的 MessageDelta —
            //   Anthropic ingress 在 message_stop 之后再 emit message_delta 是非法
            //   wire 顺序 (Anthropic 规范 message_delta 在 message_stop 之前), 故
            //   usage delta 先 emit、缓存的 stop 随后 flush (见循环尾); 其他
            //   post-stop 事件类型 (block 事件等) 在真实 reader 产出中不存在,
            //   保守丢弃 (比同协议 guard 更严, 防止 stop 后再出 block 帧的违例).
            if self.cross_proto {
                if matches!(ev, IrStreamEvent::MessageStop) {
                    if !self.message_stopped {
                        self.message_stopped = true;
                        self.pending_stop = true; // 缓存, 待 post-stop usage delta 或 finish() flush
                    }
                    continue; // 首个与重复的 MessageStop 都不立即 emit
                }
                if self.message_stopped {
                    // 只放行 "首个带非零 usage 的 post-stop MessageDelta" (pending_stop
                    // 仍缓存 = 尚未 flush) — 它触发 delta→stop 的有序 flush. 后续
                    // post-stop 事件 (含第二个 usage delta, 病态上游) 一律丢弃:
                    // stop 已 flush 后再 emit 任何事件都违反 Anthropic wire 顺序.
                    let usage_bearing_trigger = matches!(&ev,
                        IrStreamEvent::MessageDelta { usage, .. } if !usage.is_zero())
                        && self.pending_stop;
                    if !usage_bearing_trigger {
                        continue;
                    }
                }
            } else {
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
            }

            // 跨协议模式的跳过 block 配对过滤 (仅对 writer 主动跳过 BlockStart 的
            // index 生效; 见结构体文档 "配对过滤" 段). BlockDelta 不在过滤范围:
            // OpenAI writer 对 Text BlockStart 返回 None 是结构性隐式, delta 仍是
            // 内容 (由 writer 自行决定 emit); 语义性整体跳过 (Anthropic 对
            // ReasoningContent) 的 ReasoningDelta 本就被 writer 跳过.
            // 同协议模式不启用 (skipped_block_starts 恒空).
            if self.cross_proto {
                if let IrStreamEvent::BlockStart { index, .. } = &ev
                    && self.ingress_writer.write_response_event(&ev).is_none()
                {
                    self.skipped_block_starts.insert(*index);
                    continue;
                }
                if let IrStreamEvent::BlockStop { index } = &ev
                    && self.skipped_block_starts.contains(index)
                {
                    // 未配对的 content_block_stop 是协议违例, 跳过其 emit. 但 restore
                    // hook 的 per-block 窗口残余仍须在此冲刷 — 空跳过会让 OpenAI
                    // ingress 的 text 尾部 (hold 窗口字节) 延迟到 finish() 才发出,
                    // 落在 finish_reason 之后 (wire 顺序违例 + 严格客户端丢尾部).
                    // tail 包装回同 kind BlockDelta emit: Anthropic ingress 的
                    // Reasoning tail 被 writer 丢弃 (无害), OpenAI ingress 的 text
                    // tail 在 BlockStop 的正确时机到达.
                    let flushed = self
                        .restore
                        .as_mut()
                        .map(|hook| hook.flush_delta(*index))
                        .filter(|(_, tail)| !tail.is_empty());
                    if let Some((kind, tail)) = flushed {
                        let flush_ev = IrStreamEvent::BlockDelta {
                            index: *index,
                            delta: kind.to_ir_delta(tail),
                        };
                        self.emit_ir_event(&flush_ev, out);
                    }
                    continue;
                }
            }

            // deferred stop flush 时机: pending_stop 为 true 时唯一能走到这里的事件
            // 是 post-stop usage delta (上方 guard 保证), emit delta 后立即补 stop.
            let flush_stop_after = self.cross_proto && self.pending_stop;

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

            // deferred stop flush: 跨协议模式下 post-stop usage delta 已 emit,
            // 现在补发缓存的 MessageStop (message_delta 在 message_stop 之前,
            // Anthropic wire 合法顺序).
            if flush_stop_after {
                self.pending_stop = false;
                self.emit_ir_event(&IrStreamEvent::MessageStop, out);
            }
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

#[cfg(test)]
mod tests {
    //! 跨协议模式的 wire 合法性确定性单测 (配对过滤 + deferred stop).
    //!
    //! property 测试 (fwd_streaming_property.rs) 守卫内容保真, 但不断言 wire 帧顺序
    //! 合法性 — 这里的两个测试补上: 构造最小事件序列, 在 Anthropic writer 层断言
    //! 输出的 SSE 帧序列满足协议约束.

    use super::*;

    /// 把完整 SSE 字节解析为 (event_type, data JSON) 帧序列 (测试辅助).
    /// 假设: 输入是已 reassembled 的完整 SSE, LF 行尾, 帧以空行分隔.
    fn parse_frames(sse: &str) -> Vec<(String, serde_json::Value)> {
        sse.split("\n\n")
            .filter_map(|frame| {
                let mut padded = frame.as_bytes().to_vec();
                padded.extend_from_slice(b"\n\n");
                let (et, data) = super::super::parse_sse_frame(&padded)?;
                if data.is_empty() || data == "[DONE]" {
                    return None;
                }
                serde_json::from_str::<serde_json::Value>(&data)
                    .ok()
                    .map(|v| (et, v))
            })
            .collect()
    }

    /// OpenAI egress 的 reasoning 流 fixture: 思考 chunk → 文本 chunk → finish →
    /// include_usage → [DONE] (思考型模型的典型流形态, #176).
    fn openai_reasoning_stream() -> String {
        [
            r#"data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"thinking..."},"finish_reason":null}]}"#,
            r#"data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"answer"},"finish_reason":null}]}"#,
            r#"data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            r#"data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#,
            "data: [DONE]",
        ]
        .map(|f| f.to_string() + "\n\n")
        .concat()
    }

    /// 1a 配对过滤: Anthropic ingress 下, writer 跳过的 ReasoningContent BlockStart
    /// 不得产生未配对的 content_block_stop (修复前: BlockStop 无状态恒 emit).
    ///
    /// 不变式: 每个 content_block_stop 都有同 index 的前置 content_block_start;
    /// 每个 content_block_delta 同理. 同时守卫 text 内容保真 (reasoning 被显式
    /// 丢弃是 STR-6 裁决的预期行为, 不在断言范围).
    #[test]
    fn cross_proto_reasoning_block_yields_no_unpaired_block_stop() {
        let mut t = StreamTranslate::new_cross_proto(
            Protocol::Anthropic, // ingress
            Protocol::OpenAI,    // egress
            None,
        )
        .expect("ingress != egress");
        let out = t.feed(openai_reasoning_stream().as_bytes());
        let finish = t.finish();
        let combined = [out, finish].concat();
        let client = String::from_utf8_lossy(&combined);

        let frames = parse_frames(&client);
        assert!(!frames.is_empty(), "client should receive frames: {client}");

        // 配对追踪: open 集合内的 index 才允许 delta / stop.
        let mut open: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for (et, data) in &frames {
            let index = data.get("index").and_then(serde_json::Value::as_u64);
            match et.as_str() {
                "content_block_start" => {
                    assert!(
                        open.insert(index.expect("content_block_start has index")),
                        "duplicate content_block_start for open index: {client}"
                    );
                }
                "content_block_delta" => {
                    assert!(
                        open.contains(&index.expect("content_block_delta has index")),
                        "content_block_delta without matching content_block_start: {client}"
                    );
                }
                "content_block_stop" => {
                    let idx = index.expect("content_block_stop has index");
                    assert!(
                        open.remove(&idx),
                        "unpaired content_block_stop (index={idx}) — \
                         skipped BlockStart must also skip BlockStop: {client}"
                    );
                }
                _ => {}
            }
        }
        assert!(open.is_empty(), "unclosed content_block_start: {client}");

        // text 内容保真: reasoning 丢弃, 但 answer 必须到达客户端.
        assert!(
            client.contains("\"text\":\"answer\""),
            "text lost: {client}"
        );
        // reasoning 增量不得到达 (Anthropic 无法承载 thinking block).
        assert!(
            !client.contains("thinking..."),
            "reasoning leaked: {client}"
        );
    }

    /// 1b deferred stop: OpenAI egress 开 include_usage 时, 末尾 usage chunk 在
    /// finish_reason 之后 (IR 时序 MessageStop 之后跟 MessageDelta{usage}). Anthropic
    /// ingress 必须先 emit message_delta(usage) 再 emit message_stop — 修复前
    /// message_stop 之后的 message_delta 是非法 wire 顺序.
    #[test]
    fn cross_proto_defers_message_stop_until_post_stop_usage() {
        let mut t = StreamTranslate::new_cross_proto(
            Protocol::Anthropic, // ingress
            Protocol::OpenAI,    // egress
            None,
        )
        .expect("ingress != egress");
        let out = t.feed(openai_reasoning_stream().as_bytes());
        let finish = t.finish();
        let combined = [out, finish].concat();
        let client = String::from_utf8_lossy(&combined);

        let frames = parse_frames(&client);
        let pos = |name: &str| frames.iter().position(|(et, _)| et == name);

        let stop = pos("message_stop").expect("message_stop must be emitted");
        // 最后一个 message_delta (含 usage) 必须在 message_stop 之前.
        let last_delta = frames
            .iter()
            .rposition(|(et, _)| et == "message_delta")
            .expect("message_delta must be emitted");
        assert!(
            last_delta < stop,
            "message_delta after message_stop is illegal Anthropic wire order: {client}"
        );
        // usage 必须透传 (deferred stop 不能吞掉 include_usage 数据).
        assert!(
            client.contains("\"input_tokens\":10"),
            "usage must pass through: {client}"
        );
        // message_stop 恰好一个 (含 stop_reason 的 delta 与 usage delta 分开 emit, 但 stop 只一次).
        assert_eq!(
            frames.iter().filter(|(et, _)| et == "message_stop").count(),
            1,
            "exactly one message_stop: {client}"
        );
    }

    /// 1b 兜底: 上游不发 post-stop usage chunk (无 include_usage) 时, 缓存的
    /// MessageStop 在 finish() flush — message_stop 仍恰好一次且是最后的事件帧.
    #[test]
    fn cross_proto_flushes_pending_stop_at_finish_without_usage_chunk() {
        let mut t = StreamTranslate::new_cross_proto(
            Protocol::Anthropic, // ingress
            Protocol::OpenAI,    // egress
            None,
        )
        .expect("ingress != egress");
        // 只到 finish_reason, 无 include_usage chunk.
        let sse = [
            r#"data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}"#,
            r#"data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            "data: [DONE]",
        ]
        .map(|f| f.to_string() + "\n\n")
        .concat();
        let out = t.feed(sse.as_bytes());
        // feed 期间 message_stop 不 emit (deferred) — 输出里没有 message_stop 帧.
        assert!(
            !String::from_utf8_lossy(&out).contains("event: message_stop"),
            "MessageStop must be deferred during feed: {}",
            String::from_utf8_lossy(&out)
        );
        let finish = t.finish();
        let combined = [out, finish].concat();
        let client = String::from_utf8_lossy(&combined);
        let frames = parse_frames(&client);
        assert_eq!(
            frames.iter().filter(|(et, _)| et == "message_stop").count(),
            1,
            "pending stop flushed exactly once at finish: {client}"
        );
        // message_stop 是最后一个事件帧.
        assert_eq!(
            frames.last().map(|(et, _)| et.as_str()),
            Some("message_stop"),
            "message_stop must be the final event frame: {client}"
        );
    }

    /// H-1 回归 (OpenAI ingress + restore 方向): 配对过滤不得延迟 restore 的
    /// per-block 尾部 — text block 的 BlockStop 虽被跳过 (OpenAI writer 对
    /// BlockStart{Text} 返回 None 是结构性隐式, index 在 skipped 集合内), hook
    /// 持有的尾部字节仍必须在 finish_reason chunk **之前**发出. 修复前: 尾部
    /// 延迟到 finish() 的 flush_all, 落在 finish_reason 之后 (wire 顺序违例,
    /// 在 finish_reason 处停止读取的客户端丢尾部).
    #[test]
    fn cross_proto_openai_ingress_flushes_skipped_block_tail_before_finish_reason() {
        use crate::redact::RedactionMap;

        // real + mock: mock 出现在 text 中段, 其后还有尾部文本 (会被 restorer 的
        // hold 窗口扣住, 直到 BlockStop flush).
        let real = "sk-real-tailtest-99";
        let mock = "MOCKtailtest";
        let mut map = RedactionMap::default();
        map.insert(real.to_string(), mock.to_string(), "id-tail")
            .expect("single mock no conflict");

        let mut t = StreamTranslate::new_cross_proto(
            Protocol::OpenAI,    // ingress
            Protocol::Anthropic, // egress
            Some(Box::new(crate::redact::StreamingRestorerSet::new(map))),
        )
        .expect("ingress != egress");
        // Anthropic egress 流: text block (含 mock + 尾部) → message_delta(stop) →
        // message_stop.
        let frame = |event: &str, data: &str| format!("event: {event}\ndata: {data}\n\n");
        let sse = [
            frame(
                "message_start",
                r#"{"type":"message_start","message":{"id":"msg_01t","type":"message","role":"assistant","content":[],"model":"claude-3","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":5,"output_tokens":1}}}"#,
            ),
            frame(
                "content_block_start",
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            ),
            frame(
                "content_block_delta",
                &format!(
                    r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"head {mock} tail-end-words"}}}}"#
                ),
            ),
            frame("content_block_stop", r#"{"type":"content_block_stop","index":0}"#),
            frame(
                "message_delta",
                r#"{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":3}}"#,
            ),
            frame("message_stop", r#"{"type":"message_stop"}"#),
        ]
        .concat();
        let out = t.feed(sse.as_bytes());
        let finish = t.finish();
        let combined = [out, finish].concat();
        let client = String::from_utf8_lossy(&combined);

        // 内容保真: real 到达, mock 绝不泄漏 (tail flush 产物已 restore). 内容用
        // 拼接断言 — restorer 的 hold 窗口会把文本切到多个 chunk (chunk 划分不是
        // 契约, 拼接才是).
        assert!(
            client.contains(real),
            "real secret must be restored: {client}"
        );
        assert!(!client.contains(mock), "mock must not leak: {client}");
        let frames = parse_frames(&client);
        let content_all: String = frames
            .iter()
            .filter_map(|(_, d)| {
                d.get("choices")?
                    .get(0)?
                    .get("delta")?
                    .get("content")?
                    .as_str()
                    .map(str::to_string)
            })
            .collect();
        assert!(
            content_all.ends_with("tail-end-words"),
            "tail content must be delivered (joined={content_all:?})"
        );
        // wire 顺序: 最后一个 content chunk 必须在 finish_reason chunk 之前.
        let last_content = client
            .rfind("\"content\":")
            .expect("content chunks must exist");
        let finish_reason = client
            .find("\"finish_reason\":\"stop\"")
            .expect("finish_reason chunk must exist");
        assert!(
            last_content < finish_reason,
            "content chunk after finish_reason is illegal OpenAI wire order \
             (skipped-block tail must flush at BlockStop, not at finish): {client}"
        );
    }
}
