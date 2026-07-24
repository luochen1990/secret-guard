//! SSE 流式响应的 chunk-boundary 处理与跨协议翻译.
//!
//! # 设计
//!
//! [`StreamTranslate`] 把 egress 协议的 SSE 字节流实时翻译为 ingress 协议的 SSE 字节流.
//! 核心 pipeline:
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
//! 也会出现一个 chunk 包含多个帧的情况. [`StreamTranslate::feed`] 维护 reassembly 缓冲,
//! 在内存中按帧边界分割. 扫描位置 (`scanned`) 持续推进以保持 O(n) 性能
//! (避免每次 feed 都重新扫描已搜索过的前缀).
//!
//! # 终止符
//!
//! OpenAI 流以 `data: [DONE]\n\n` 结尾; Anthropic 用 `event: message_stop` 终止.
//! StreamTranslate 在 [`StreamTranslate::finish`] 时根据 ingress writer 决定是否追加 `[DONE]`.

use crate::codec::{
    Protocol, Reader, Writer,
    ir::{IrBlockMeta, IrStreamEvent, StreamDecodeState},
};
use crate::redact::{DeltaKind, RedactionMap, StreamingRestorer, restore_str_inplace};
use std::collections::HashMap;

/// SSE 流终止符 sentinel (OpenAI 约定).
pub const SSE_DONE_SENTINEL: &str = "[DONE]";

/// OpenAI 流的末尾完整帧.
pub const SSE_DONE_FRAME: &[u8] = b"data: [DONE]\n\n";

/// reassembly 缓冲上限. 防止恶意上游用无终止符的字节流耗尽内存.
/// 16 MiB 远大于任何合法的 chat completion SSE 帧.
pub const MAX_BUF: usize = 16 * 1024 * 1024;

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
    /// 帧字节 reassembly 缓冲.
    buf: Vec<u8>,
    /// 已扫描位置 (避免每次 feed 重新扫描整个前缀).
    scanned: usize,
    /// 缓冲溢出 / 异常终止标记. 一旦置位, 后续 feed 直接返回空.
    aborted: bool,
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
            buf: Vec::new(),
            scanned: 0,
            aborted: false,
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
            buf: Vec::new(),
            scanned: 0,
            aborted: false,
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
        if self.aborted {
            return Vec::new();
        }
        self.buf.extend_from_slice(chunk);
        let mut out: Vec<u8> = Vec::new();
        let mut consumed = 0usize;

        loop {
            // 从 scanned (回退 3 字节防 CRLF 跨 chunk 边界) 开始找下一个帧终止符.
            let search_from = self
                .scanned
                .saturating_sub(3)
                .max(consumed)
                .min(self.buf.len());

            let Some((rel, term_len)) = find_frame_terminator(&self.buf[search_from..]) else {
                self.scanned = self.buf.len();
                break;
            };
            let end = search_from + rel + term_len;
            let frame = &self.buf[consumed..end];
            consumed = end;
            self.scanned = end;

            let Some((event_type, data_str)) = parse_sse_frame(frame) else {
                continue; // 没有 data: 行 (eg. event-only, 注释)
            };
            if data_str.is_empty() || data_str == SSE_DONE_SENTINEL {
                continue; // keepalive / [DONE] 不携带 IR
            }
            let Ok(data) = serde_json::from_str::<serde_json::Value>(&data_str) else {
                continue; // 非 JSON, 跳过 (恶意 / 损坏)
            };

            self.translate_event(&event_type, &data, &mut out);
        }

        // 回收已消费前缀 (单次 shift, 线性而非 O(n^2)).
        if consumed > 0 {
            self.buf.drain(..consumed);
            self.scanned = self.buf.len();
        }
        if self.buf.len() > MAX_BUF {
            self.abort();
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
        if self.aborted {
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

    /// 标记流为 aborted, 释放缓冲. 后续 feed 直接返回空.
    fn abort(&mut self) {
        self.aborted = true;
        self.buf.clear();
        self.buf.shrink_to_fit();
        self.scanned = 0;
    }
}

// ─── StreamScan: 流式 parsed view 累积器 ────────────────────────────────────
//
// 与 StreamTranslate 的关注点正交:
//   StreamTranslate: egress SSE → ingress SSE (实时转换, 不保留完整内容)
//   StreamScan:      egress SSE → IrResponse  (不转换协议, 只累积语义内容)
//
// 用法: fan_out task 在 chunk 循环里 feed 每个 raw chunk, 节流地把 snapshot() 写入
// DAG node 的 parsed 字段. 流结束时 snapshot() 即最终完整 IrResponse.
// 对输入的要求: fan_out task 喂的是**原始上游字节** (LLM 视角, 含 mock 或未 redact).
// snapshot() 产出的 IrResponse 直接序列化给前端 parsed view, 不经 restore (与当前
// record 语义一致: record 存 LLM 视角).

/// 单个 block 的累积状态 (流过程中用于暂存增量, finish 时折叠为 IrBlock).
#[derive(Debug, Default)]
struct ScanBlock {
    /// TextDelta 累积.
    text: String,
    /// InputJsonDelta 累积 (tool_use only).
    json_input: String,
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
    /// block index → 累积状态. 流过程中按 index 暂存, finish 时折叠为 Vec<IrBlock>.
    blocks: std::collections::BTreeMap<usize, ScanBlock>,
    /// 块的最终顺序 (finish 时按此顺序折叠, 与到达顺序一致).
    block_order: Vec<usize>,
    /// SSE 帧 reassembly buffer (跨 chunk 不完整帧).
    buf: Vec<u8>,
    /// 已扫描位置 (O(n) 扫描, 避免重复搜前缀).
    scanned: usize,
    /// reassembly buffer 溢出标记. 达到 MAX_BUF 后置位, 停止累积 (防 OOM).
    /// snapshot() 返回已累积的部分内容 (不发给客户端, 只给 WebUI, abort 不影响转发).
    aborted: bool,
}

/// IrResponse 的元数据部分 (从 MessageStart / MessageDelta 提取).
#[derive(Debug, Default, Clone)]
struct IrResponseMeta {
    model: Option<String>,
    id: Option<String>,
    created: Option<u64>,
    usage: crate::codec::IrUsage,
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
            buf: Vec::new(),
            scanned: 0,
            aborted: false,
        }
    }

    /// 喂入一段 raw SSE 字节 (可能跨帧 / 含不完整尾帧).
    /// 内部按帧边界解析, 把每个完整帧的 IR 事件增量累积.
    /// 不完整尾帧留在 buffer 等下次 feed 补全.
    ///
    /// 与 StreamTranslate 不同: StreamScan **不** 应用 post-stop guard, 因为
    /// OpenAI `stream_options.include_usage` 的 usage chunk 出现在 finish_reason
    /// chunk (MessageStop) 之后, StreamScan 需要收集它.
    pub fn feed(&mut self, chunk: &[u8]) {
        if self.aborted {
            return;
        }
        self.buf.extend_from_slice(chunk);
        let mut consumed = 0usize;
        loop {
            let search_from = self
                .scanned
                .saturating_sub(3)
                .max(consumed)
                .min(self.buf.len());
            let Some((rel, term_len)) = find_frame_terminator(&self.buf[search_from..]) else {
                self.scanned = self.buf.len();
                break;
            };
            let end = search_from + rel + term_len;
            let frame = &self.buf[consumed..end];
            consumed = end;
            self.scanned = end;

            let Some((event_type, data_str)) = parse_sse_frame(frame) else {
                continue;
            };
            if data_str.is_empty() || data_str == SSE_DONE_SENTINEL {
                continue;
            }
            let Ok(data) = serde_json::from_str::<serde_json::Value>(&data_str) else {
                continue;
            };
            let events = self
                .reader
                .read_response_events(&event_type, &data, &mut self.decode);
            for ev in events {
                self.apply_event(&ev);
            }
        }
        if consumed > 0 {
            self.buf.drain(..consumed);
            self.scanned = self.buf.len();
        }
        // reassembly buffer 溢出保护 (与 StreamTranslate::feed 一致).
        // 恶意/异常上游发永不闭合的帧时, 防止 buf 无界增长 OOM.
        if self.buf.len() > MAX_BUF {
            self.aborted = true;
            self.buf.clear();
            self.buf.shrink_to_fit();
            self.scanned = 0;
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
            } => {
                if let Some(sr) = stop_reason {
                    self.meta.stop_reason = Some(*sr);
                }
                if let Some(ss) = stop_sequence {
                    self.meta.stop_sequence = Some(ss.clone());
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
            model: self.meta.model.clone(),
            id: self.meta.id.clone(),
            created: self.meta.created,
        }
    }
}

/// 把 ScanBlock (累积状态) 折叠为最终 IrBlock.
/// - meta=ToolUse → ToolUse block (input JSON parse, 失败则用空 object)
/// - meta=Text 或缺失 (上游漏发 BlockStart) → Text block
/// - 空内容 (text+json_input 均空) → None (不产出空气泡)
fn fold_scan_block(b: &ScanBlock) -> Option<crate::codec::IrBlock> {
    match &b.meta {
        Some(IrBlockMeta::ToolUse { id, name }) => {
            let input = serde_json::from_str(&b.json_input).unwrap_or_default();
            Some(crate::codec::IrBlock::ToolUse {
                id: id.clone(),
                name: name.clone(),
                input,
            })
        }
        // Text block 或 meta 缺失 (上游漏发 BlockStart, 退化为 Text).
        Some(IrBlockMeta::Text) | None => {
            if b.text.is_empty() && b.json_input.is_empty() {
                None
            } else {
                Some(crate::codec::IrBlock::Text {
                    text: b.text.clone(),
                })
            }
        }
    }
}

// ─── SSE 解析工具函数 ──────────────────────────────────────────────────────

/// 在 buffer 中找出第一个 SSE 帧终止符 (空行) 的位置和长度.
///
/// 支持两种终止符:
/// - LF-LF: `\n\n` (2 bytes)
/// - CRLF-CRLF: `\r\n\r\n` (4 bytes, WHATWG SSE 标准允许)
///
/// 返回 `(相对 offset, 终止符长度)`.
pub fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            // LF-LF
            if buf.get(i + 1) == Some(&b'\n') {
                return Some((i, 2));
            }
            // CRLF-CRLF (锚定在前一行结尾的 \n 上)
            if i >= 1
                && buf[i - 1] == b'\r'
                && buf.get(i + 1) == Some(&b'\r')
                && buf.get(i + 2) == Some(&b'\n')
            {
                return Some((i - 1, 4));
            }
        }
        i += 1;
    }
    None
}

/// 解析一个完整 SSE 帧为 `(event_type, data_payload)`.
///
/// - `event_type=""` 表示没有 `event:` 行 (OpenAI 风格, bare `data:`).
/// - 多行 `data:` 用 `\n` 连接 (WHATWG SSE §9.2.6 规范).
/// - 没有 `data:` 行返回 `None`.
/// - 非 UTF-8 字节返回 `None`.
pub fn parse_sse_frame(frame: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(frame).ok()?;
    let mut event_type = String::new();
    let mut data_lines: Vec<&str> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            event_type = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            // 仅剥一个前导空格 (SSE 规范); 多个空格保留.
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    if data_lines.is_empty() {
        return None;
    }
    Some((event_type, data_lines.join("\n")))
}

/// 把 `(event_type, data)` 重新封装为 SSE 字节.
///
/// - `event_type=""` → OpenAI 风格 `data: {...}\n\n`
/// - `event_type` 非空 → Anthropic 风格 `event: foo\ndata: {...}\n\n`
pub fn reframe_sse(event_type: &str, data: &serde_json::Value) -> Vec<u8> {
    if event_type.is_empty() {
        format!("data: {data}\n\n").into_bytes()
    } else {
        format!("event: {event_type}\ndata: {data}\n\n").into_bytes()
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Protocol, anthropic::AnthropicReader, openai::OpenAiReader};
    use proptest::prelude::*;

    // ─── find_frame_terminator ─────────────────────────────────────────

    #[test]
    fn find_terminator_lf_lf() {
        let buf = b"data: x\n\ndata: y\n\n";
        let (off, len) = find_frame_terminator(buf).unwrap();
        assert_eq!(off, 7);
        assert_eq!(len, 2);
    }

    #[test]
    fn find_terminator_crlf_crlf() {
        let buf = b"data: x\r\n\r\ndata: y\r\n\r\n";
        let (off, len) = find_frame_terminator(buf).unwrap();
        assert_eq!(off, 7);
        assert_eq!(len, 4);
    }

    #[test]
    fn find_terminator_returns_none_when_no_blank_line() {
        let buf = b"data: x";
        assert!(find_frame_terminator(buf).is_none());
    }

    #[test]
    fn find_terminator_crlf_straddles_chunk_boundary() {
        // 前半段 "\r", 后半段 "\n\r\n"
        let buf = b"data: x\r";
        assert!(find_frame_terminator(buf).is_none());
        let buf = b"data: x\r\n\r\n";
        let (off, len) = find_frame_terminator(buf).unwrap();
        assert_eq!(off, 7);
        assert_eq!(len, 4);
    }

    // ─── parse_sse_frame ───────────────────────────────────────────────

    #[test]
    fn parse_frame_bare_data_openai_style() {
        let frame = b"data: {\"a\":1}\n\n";
        let (et, d) = parse_sse_frame(frame).unwrap();
        assert_eq!(et, "");
        assert_eq!(d, r#"{"a":1}"#);
    }

    #[test]
    fn parse_frame_event_data_anthropic_style() {
        let frame = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let (et, d) = parse_sse_frame(frame).unwrap();
        assert_eq!(et, "message_stop");
        assert_eq!(d, r#"{"type":"message_stop"}"#);
    }

    #[test]
    fn parse_frame_concatenates_multiple_data_lines() {
        let frame = b"data: line1\ndata: line2\n\n";
        let (_, d) = parse_sse_frame(frame).unwrap();
        assert_eq!(d, "line1\nline2");
    }

    #[test]
    fn parse_frame_done_sentinel() {
        let frame = b"data: [DONE]\n\n";
        let (_, d) = parse_sse_frame(frame).unwrap();
        assert_eq!(d, "[DONE]");
    }

    #[test]
    fn parse_frame_event_only_no_data_returns_none() {
        let frame = b"event: foo\n\n";
        assert!(parse_sse_frame(frame).is_none());
    }

    #[test]
    fn parse_frame_invalid_utf8_returns_none() {
        let frame = &[b'd', b'a', b't', b'a', b':', b' ', 0xFF, b'\n', b'\n'];
        assert!(parse_sse_frame(frame).is_none());
    }

    // ─── reframe ───────────────────────────────────────────────────────

    #[test]
    fn reframe_openai_bare_data() {
        let v = serde_json::json!({"a":1});
        let bytes = reframe_sse("", &v);
        assert_eq!(String::from_utf8_lossy(&bytes), "data: {\"a\":1}\n\n");
    }

    #[test]
    fn reframe_anthropic_event_data() {
        let v = serde_json::json!({"x":1});
        let bytes = reframe_sse("foo", &v);
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "event: foo\ndata: {\"x\":1}\n\n"
        );
    }

    // ─── StreamTranslate end-to-end ────────────────────────────────────

    #[test]
    fn translate_openai_egress_to_anthropic_ingress_simple_text() {
        // OpenAI 上游的简化 SSE 流, 翻译为 Anthropic ingress.
        let mut t = StreamTranslate::new(Protocol::Anthropic, Protocol::OpenAI).unwrap();
        let input = b"data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n";
        let out = t.feed(input);
        let s = String::from_utf8_lossy(&out);
        // 应该看到 Anthropic 风格 event: message_start + event: content_block_start + content_block_delta.
        assert!(s.contains("event: message_start"), "got: {s}");
        assert!(s.contains("event: content_block_start"), "got: {s}");
        assert!(s.contains("\"type\":\"text_delta\""), "got: {s}");
        assert!(s.contains("\"text\":\"Hi\""), "got: {s}");
    }

    #[test]
    fn translate_finish_emits_done_for_openai_ingress() {
        // Anthropic egress → OpenAI ingress, finish() 应追加 [DONE].
        let mut t = StreamTranslate::new(Protocol::OpenAI, Protocol::Anthropic).unwrap();
        let finish = t.finish();
        let s = String::from_utf8_lossy(&finish);
        assert!(s.contains("data: [DONE]"), "got: {s}");
    }

    #[test]
    fn translate_anthropic_egress_to_openai_ingress_includes_done_in_finish() {
        // Anthropic 流的 message_stop 不应被翻译为 [DONE], 而 finish() 加.
        let mut t = StreamTranslate::new(Protocol::OpenAI, Protocol::Anthropic).unwrap();
        let input = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let out = t.feed(input);
        let s_out = String::from_utf8_lossy(&out);
        // OpenAI writer 在 IrStreamEvent::MessageStop 时返回 None, 所以 out 应为空.
        assert!(
            s_out.is_empty(),
            "MessageStop should produce no output, got: {s_out}"
        );
        // finish() 不应加 [DONE] 因为还没收到 MessageStart (合成 id 没基础), 但 emit_done=true.
        let finish = t.finish();
        let s_finish = String::from_utf8_lossy(&finish);
        assert!(s_finish.contains("data: [DONE]"), "got: {s_finish}");
    }

    #[test]
    fn feed_handles_split_frame_across_chunks() {
        let mut t = StreamTranslate::new(Protocol::Anthropic, Protocol::OpenAI).unwrap();
        let full = b"data: {\"id\":\"x\",\"created\":0,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"},\"finish_reason\":null}]}\n\n";
        // 切成两半, 第二半才有完整帧.
        let out1 = t.feed(&full[..30]);
        assert!(out1.is_empty(), "no complete frame yet");
        let out2 = t.feed(&full[30..]);
        assert!(!out2.is_empty(), "should have complete frame now");
        let s = String::from_utf8_lossy(&out2);
        assert!(s.contains("text_delta"), "got: {s}");
    }

    #[test]
    fn feed_handles_many_frames_in_one_chunk() {
        let mut t = StreamTranslate::new(Protocol::Anthropic, Protocol::OpenAI).unwrap();
        // 一个 chunk 包含两个帧.
        let input = b"data: {\"id\":\"x\",\"created\":0,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"x\",\"created\":0,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"b\"},\"finish_reason\":null}]}\n\n";
        let out = t.feed(input);
        let s = String::from_utf8_lossy(&out);
        // 应该有 2 个 text_delta.
        let count = s.matches("text_delta").count();
        assert_eq!(count, 2, "got: {s}");
    }

    #[test]
    fn feed_aborts_on_unbounded_buffer() {
        let mut t = StreamTranslate::new(Protocol::Anthropic, Protocol::OpenAI).unwrap();
        // 喂入 MAX_BUF + 1 字节无终止符的数据.
        let huge = vec![b'a'; MAX_BUF + 1];
        let _out = t.feed(&huge);
        // 下一次 feed 应该是 no-op (aborted).
        let out2 = t.feed(b"data: x\n\n");
        assert!(out2.is_empty(), "aborted translator should return empty");
        // finish() 应该发出 error event (因为 aborted).
        let finish = t.finish();
        let s = String::from_utf8_lossy(&finish);
        assert!(s.contains("stream aborted"), "got: {s}");
    }

    #[test]
    fn translate_handles_crlf_sse_frames() {
        // CRLF 风格的 SSE (部分 CDN 用).
        let mut t = StreamTranslate::new(Protocol::Anthropic, Protocol::OpenAI).unwrap();
        let input = b"data: {\"id\":\"x\",\"created\":0,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\r\n\r\n";
        let out = t.feed(input);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("text_delta"), "got: {s}");
    }

    #[test]
    fn same_protocol_returns_none() {
        // 同协议应返回 None (caller 走字节透传).
        assert!(StreamTranslate::new(Protocol::OpenAI, Protocol::OpenAI).is_none());
        assert!(StreamTranslate::new(Protocol::Anthropic, Protocol::Anthropic).is_none());
    }

    // ─── 验证 fan-out: 一个 OpenAI chunk → 多个 IR events ──────────────

    #[test]
    fn openai_fan_out_first_chunk_yields_message_start_and_block_start() {
        use crate::codec::Reader;
        use crate::codec::ir::StreamDecodeState;
        let reader = OpenAiReader;
        let chunk = serde_json::json!({
            "id": "x", "created": 0, "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"content": "Hi"}, "finish_reason": null}]
        });
        let mut state = StreamDecodeState::default();
        let events = reader.read_response_events("", &chunk, &mut state);
        assert!(
            events.len() >= 2,
            "should have at least MessageStart + BlockStart + BlockDelta"
        );
    }

    #[test]
    fn anthropic_reader_message_start_1to1() {
        use crate::codec::Reader;
        use crate::codec::ir::StreamDecodeState;
        let reader = AnthropicReader;
        let data = serde_json::json!({
            "type": "message_start",
            "message": {
                "id": "msg_x", "type": "message", "role": "assistant",
                "content": [], "model": "claude",
                "stop_reason": serde_json::Value::Null,
                "stop_sequence": serde_json::Value::Null,
                "usage": {"input_tokens": 5, "output_tokens": 1}
            }
        });
        let mut state = StreamDecodeState::default();
        let events = reader.read_response_events("message_start", &data, &mut state);
        assert_eq!(events.len(), 1);
    }
    // ─── post-stop guard: usage 透传 / 重复 stop 抑制 ──────────────────

    #[test]
    fn post_stop_guard_passes_usage_only_message_delta_after_stop_openai_ingress() {
        // OpenAI egress + OpenAI ingress (same-proto restore 模式).
        // 模拟 OpenAI `stream_options.include_usage: true` 末尾 chunk:
        // 1. finish_reason chunk (无 usage) → reader 产出 MessageDelta{stop, zero} + MessageStop
        // 2. usage chunk (choices=[], usage 非零) → reader 产出 MessageDelta{None, usage}
        // 客户端应该看到: 一个 finish_reason chunk + 一个 usage chunk (含 prompt_tokens 等).
        use crate::redact::RedactionMap;

        let proto = Protocol::OpenAI;
        let mut t = StreamTranslate::new_same_proto_restore(proto, RedactionMap::default());

        let finish_chunk = serde_json::json!({
            "id": "x", "created": 0, "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        });
        let usage_chunk = serde_json::json!({
            "id": "x", "created": 0, "model": "gpt-4o",
            "choices": [],
            "usage": {"prompt_tokens": 42, "completion_tokens": 7, "total_tokens": 49}
        });

        // 用单个 SSE payload 同时喂两个帧, 模拟真实上游 (TCP 切片无关键影响).
        let sse = format!("data: {finish_chunk}\n\ndata: {usage_chunk}\n\n");
        let out = t.feed(sse.as_bytes());
        let s = String::from_utf8_lossy(&out);
        // 关键: usage 必须透传给客户端 (修复前会被 post-stop guard 丢弃).
        assert!(
            s.contains("\"prompt_tokens\":42"),
            "client must see usage; got: {s}"
        );
        assert!(
            s.contains("\"finish_reason\":\"stop\""),
            "finish_reason must also be emitted; got: {s}"
        );
    }

    #[test]
    fn post_stop_guard_drops_duplicate_message_stop() {
        // 同协议 restore 模式: 上游异常发了两个 message_stop (eg. keepalive 帧错误解析),
        // 应该只产生一份 [DONE] 终止符 (finish() 时 emit_done=true).
        use crate::redact::RedactionMap;
        let proto = Protocol::Anthropic; // message_stop 在 Anthropic 是显式 event
        let mut t = StreamTranslate::new_same_proto_restore(proto, RedactionMap::default());
        let sse = concat!(
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        );
        let out = t.feed(sse.as_bytes());
        let s = String::from_utf8_lossy(&out);
        // 客户端应该只看到一个 message_stop frame.
        let count = s.matches("event: message_stop").count();
        assert_eq!(count, 1, "duplicate message_stop must be dropped; got: {s}");
    }

    // ─── sliding window restore end-to-end ──────────────────────────────

    #[test]
    fn same_proto_restore_handles_mock_split_across_chunks() {
        // 完整 mock 被切到两个 SSE chunk, sliding window 应正确 restore.
        // 场景: LLM 在响应里 echo 了 mock, 但 mock 字符串恰好跨 TCP chunk 边界.
        let real = "sk-real-test-12345";
        // 手造一个 mock 字符串 (测试 restore 的 chunk 边界处理, 与 prefix 无关).
        let mock = "MOCKABCDEFGHIJ";
        // mock 在 content 中是连续的, 但被 chunk 边界切到中间.
        // chunk1: "X" + mock 前半; chunk2: mock 后半 + "Y".
        let mock_split = mock.len() / 2;
        let chunk1_content = format!("X{}", &mock[..mock_split]);
        let chunk2_content = format!("{}Y", &mock[mock_split..]);

        let mut map = crate::redact::RedactionMap::default();
        map.insert(real.to_string(), mock.to_string());
        let mut t = StreamTranslate::new_same_proto_restore(Protocol::OpenAI, map);

        let sse1 = format!(
            r#"data: {{"id":"x","created":0,"model":"gpt-4o","choices":[{{"index":0,"delta":{{"content":"{chunk1_content}"}},"finish_reason":null}}]}}

"#,
        );
        let sse2 = format!(
            r#"data: {{"id":"x","created":0,"model":"gpt-4o","choices":[{{"index":0,"delta":{{"content":"{chunk2_content}"}},"finish_reason":null}}]}}

"#,
        );
        let sse_done = b"data: {\"id\":\"x\",\"created\":0,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n";
        let done = b"data: [DONE]\n\n";

        let out1 = t.feed(sse1.as_bytes());
        let out2 = t.feed(sse2.as_bytes());
        let _ = t.feed(sse_done);
        let _ = t.feed(done);
        let finish = t.finish();

        let combined_bytes = [out1, out2, finish].concat();
        let combined = String::from_utf8_lossy(&combined_bytes);
        eprintln!("mock = {mock:?} (len {})", mock.len());
        eprintln!("combined client output:\n{combined}");
        assert!(
            combined.contains(real),
            "client should see real_secret restored: got {combined:?}"
        );
        assert!(
            !combined.contains(mock),
            "client should NOT see mock {mock}: got {combined:?}"
        );
    }

    // ─── StreamScan ────────────────────────────────────────────────────

    fn openai_text_chunk(content: &str, finish: Option<&str>) -> String {
        let finish_json = match finish {
            Some(fr) => format!(",\"finish_reason\":\"{fr}\""),
            None => ",\"finish_reason\":null".to_string(),
        };
        format!(
            r#"data: {{"id":"cmpl-1","created":100,"model":"gpt-4","choices":[{{"index":0,"delta":{{"content":"{content}"}}{finish_json}}}]}}"#,
        )
    }

    #[test]
    fn stream_scan_openai_text_accumulates_across_chunks() {
        // 三个 OpenAI 文本 delta chunk, 按多次 feed 喂入 (模拟跨 chunk 到达).
        // 每个 chunk 是一个完整的 SSE 帧 (data: ...\n\n).
        let mut scan = StreamScan::new(Protocol::OpenAI);
        let frame = |content: &str, finish: Option<&str>| -> String {
            openai_text_chunk(content, finish) + "\n\n"
        };
        scan.feed(frame("两者", None).as_bytes());
        scan.feed(frame("都可以", None).as_bytes());
        // snapshot 在流中途应该只有前两个 delta.
        let mid = scan.snapshot();
        assert_eq!(mid.content.len(), 1);
        match &mid.content[0] {
            crate::codec::IrBlock::Text { text } => assert_eq!(text, "两者都可以"),
            other => panic!("expected Text block, got {other:?}"),
        }
        // 流末尾: finish_reason + [DONE].
        scan.feed(frame("工作", Some("stop")).as_bytes());
        scan.feed(b"data: [DONE]\n\n");
        let final_ir = scan.snapshot();
        match &final_ir.content[0] {
            crate::codec::IrBlock::Text { text } => assert_eq!(text, "两者都可以工作"),
            other => panic!("expected Text block, got {other:?}"),
        }
        assert_eq!(final_ir.model.as_deref(), Some("gpt-4"));
        assert_eq!(final_ir.id.as_deref(), Some("cmpl-1"));
        assert_eq!(final_ir.created, Some(100));
        assert_eq!(
            final_ir.stop_reason,
            Some(crate::codec::IrStopReason::EndTurn)
        );
    }

    #[test]
    fn stream_scan_openai_cross_chunk_frame_reassembly() {
        // 一个 SSE 帧被 TCP 切成两半, 第二半补全后才能解析.
        let mut scan = StreamScan::new(Protocol::OpenAI);
        scan.feed(b"data: {\"id\":\"x\",\"created\":0,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel");
        // 不完整, snapshot 应该是空 content (帧没终止).
        let mid = scan.snapshot();
        assert!(
            mid.content.is_empty(),
            "partial frame should not yield content"
        );
        // 补全.
        scan.feed(b"lo\"}}]}\n\n");
        let ir = scan.snapshot();
        match &ir.content[0] {
            crate::codec::IrBlock::Text { text } => assert_eq!(text, "hello"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn stream_scan_openai_tool_use_accumulates_partial_json() {
        // 模拟 OpenAI 流式 tool_calls: 多个 chunk 累积 arguments JSON.
        // 每个 chunk 是完整 SSE 帧 (以 \n\n 结尾).
        let chunks = [
            r#"data: {"id":"x","created":0,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}"#,
            r#"data: {"id":"x","created":0,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]}}]}"#,
            r#"data: {"id":"x","created":0,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"北京\"}"}}]}}]}"#,
            r#"data: {"id":"x","created":0,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
            "data: [DONE]",
        ];
        let mut scan = StreamScan::new(Protocol::OpenAI);
        for c in &chunks {
            scan.feed(((*c).to_string() + "\n\n").as_bytes());
        }
        let ir = scan.snapshot();
        assert_eq!(ir.content.len(), 1, "should have one tool_use block");
        match &ir.content[0] {
            crate::codec::IrBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "get_weather");
                assert_eq!(input.get("city").and_then(|v| v.as_str()), Some("北京"));
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
        assert_eq!(ir.stop_reason, Some(crate::codec::IrStopReason::ToolUse));
    }

    #[test]
    fn stream_scan_anthropic_text_accumulates() {
        // Anthropic 流: message_start → content_block_start → deltas → stop → message_delta → message_stop.
        let mut scan = StreamScan::new(Protocol::Anthropic);
        let frame =
            |event: &str, data: &str| -> String { format!("event: {event}\ndata: {data}\n\n") };
        scan.feed(frame("message_start", r#"{"type":"message_start","message":{"id":"msg_1","model":"claude-3","usage":{"input_tokens":10,"output_tokens":0}}}"#).as_bytes());
        scan.feed(frame("content_block_start", r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#).as_bytes());
        let mid = scan.snapshot();
        // 只发了 BlockStart, 没 delta, snapshot 应该折叠为空 Text block 或无 block.
        // 我们的实现: meta=Text 且 text 为空 → fold_scan_block 返回 None → content 空.
        assert!(mid.content.is_empty(), "empty text block should not appear");
        scan.feed(frame("content_block_delta", r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"你好"}}"#).as_bytes());
        scan.feed(frame("content_block_delta", r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"世界"}}"#).as_bytes());
        scan.feed(
            frame(
                "content_block_stop",
                r#"{"type":"content_block_stop","index":0}"#,
            )
            .as_bytes(),
        );
        scan.feed(frame("message_delta", r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}"#).as_bytes());
        scan.feed(frame("message_stop", r#"{"type":"message_stop"}"#).as_bytes());
        let ir = scan.snapshot();
        assert_eq!(ir.content.len(), 1);
        match &ir.content[0] {
            crate::codec::IrBlock::Text { text } => assert_eq!(text, "你好世界"),
            other => panic!("expected Text, got {other:?}"),
        }
        assert_eq!(ir.model.as_deref(), Some("claude-3"));
        assert_eq!(ir.id.as_deref(), Some("msg_1"));
        assert_eq!(ir.usage.input_tokens, 10);
        assert_eq!(ir.usage.output_tokens, 5);
        assert_eq!(ir.stop_reason, Some(crate::codec::IrStopReason::EndTurn));
    }

    #[test]
    fn stream_scan_ignores_post_stop_noise() {
        // 与 StreamTranslate 不同: StreamScan 不应用 post-stop guard.
        // OpenAI include_usage chunk 在 finish_reason (MessageStop) 之后到达,
        // StreamScan 必须收集它. 这里验证 MessageStop 后的 usage 被正确累积.
        let mut scan = StreamScan::new(Protocol::OpenAI);
        let frame = |content: &str, finish: Option<&str>| -> String {
            openai_text_chunk(content, finish) + "\n\n"
        };
        scan.feed(frame("done", Some("stop")).as_bytes());
        // MessageStop 已到达 (finish_reason=stop), 但 include_usage 还没到.
        let ir1 = scan.snapshot();
        assert_eq!(ir1.stop_reason, Some(crate::codec::IrStopReason::EndTurn));
        assert_eq!(ir1.usage.output_tokens, 0, "no usage yet");
        // post-stop include_usage chunk (OpenAI stream_options.include_usage 末尾格式).
        let usage_chunk = r#"data: {"id":"x","created":0,"model":"gpt-4","choices":[],"usage":{"prompt_tokens":15,"completion_tokens":3,"total_tokens":18}}"#;
        scan.feed((usage_chunk.to_string() + "\n\n").as_bytes());
        scan.feed(b"data: [DONE]\n\n");
        let ir2 = scan.snapshot();
        assert_eq!(
            ir2.usage.input_tokens, 15,
            "post-stop usage should be collected"
        );
        assert_eq!(ir2.usage.output_tokens, 3);
        // stop_reason 不应被 post-stop chunk 覆盖 (usage chunk 的 stop_reason=None).
        assert_eq!(ir2.stop_reason, Some(crate::codec::IrStopReason::EndTurn));
    }

    #[test]
    fn stream_scan_include_usage_chunk_updates_usage() {
        // 更直接的测试: 单独发 include_usage chunk, 验证 input/output tokens 更新.
        let usage_chunk = r#"data: {"id":"x","created":0,"model":"gpt-4","choices":[],"usage":{"prompt_tokens":15,"completion_tokens":3,"total_tokens":18}}"#;
        let mut scan = StreamScan::new(Protocol::OpenAI);
        scan.feed((usage_chunk.to_string() + "\n\n").as_bytes());
        let ir = scan.snapshot();
        assert_eq!(ir.usage.input_tokens, 15);
        assert_eq!(ir.usage.output_tokens, 3);
    }

    // ─── proptest: 任意切分点序列的 chunk-boundary 等价性 ──────────────────
    //
    // 契约反复强调 "一个 SSE 帧可能被 TCP 切成多个 chunk", 之前只覆盖切两半的固定案例.
    // 这里用 proptest 穷举任意切分点序列, 验证核心不变式:
    //
    //   对任意合法 SSE 字节流做任意切分, 多次 feed 的累积 snapshot()
    //     == 一次性 feed 整段的 snapshot()
    //
    // 守护 StreamScan 的 reassembly buffer 逻辑 (drain/scan_from/consumed) 对任意
    // chunk 边界都正确, 不依赖特定的切分位置.

    /// 构造一个覆盖多种事件类型的 OpenAI SSE 字节流 (含 text delta / tool_use /
    /// finish_reason / include_usage / DONE), 用来做任意切分等价性测试.
    fn sample_openai_sse_stream() -> Vec<u8> {
        let chunks = [
            // 帧 1: text delta "Hello" (fan-out 为 MessageStart + BlockStart + BlockDelta).
            r#"data: {"id":"cmpl-x","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}"#,
            // 帧 2: text delta " world".
            r#"data: {"id":"cmpl-x","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":" world"},"finish_reason":null}]}"#,
            // 帧 3: tool_call 开始 (tool_calls 数组里 tool_call index=0, id+name).
            r#"data: {"id":"cmpl-x","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}"#,
            // 帧 4: tool_call 参数 delta (partial JSON).
            r#"data: {"id":"cmpl-x","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"SF\"}"}}]},"finish_reason":null}]}"#,
            // 帧 5: finish_reason=tool_calls (关闭 block + MessageDelta + MessageStop).
            r#"data: {"id":"cmpl-x","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
            // 帧 6: include_usage 末尾 chunk (choices=[], usage).
            r#"data: {"id":"cmpl-x","created":1700000000,"model":"gpt-4o","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#,
            // 帧 7: [DONE] 终止符.
            "data: [DONE]",
        ];
        let mut s = String::new();
        for c in &chunks {
            s.push_str(c);
            s.push_str("\n\n");
        }
        s.into_bytes()
    }

    /// 把字节流按给定的切分点序列切成多个 chunk 喂入 StreamScan, 返回最终 snapshot().
    /// 切分点序列语义: split_points 把 [0, len) 区间切成 |splits|+1 段.
    fn scan_chunked(splits: &[usize], full: &[u8]) -> crate::codec::IrResponse {
        let mut scan = StreamScan::new(Protocol::OpenAI);
        let mut prev = 0usize;
        for &sp in splits {
            // clamp 到合法范围并保证单调不减 (防 proptest 生成乱序/越界值).
            let sp = sp.min(full.len()).max(prev);
            if sp > prev {
                scan.feed(&full[prev..sp]);
            }
            prev = sp;
        }
        if prev < full.len() {
            scan.feed(&full[prev..]);
        }
        scan.snapshot()
    }

    proptest! {
        /// 核心不变式: 任意切分点序列 feed 的 snapshot == 一次性 feed 的 snapshot.
        ///
        /// proptest 生成任意数量的切分点 (1..=16 个, 位置范围覆盖整个流长度).
        /// 无论 TCP 把流切成什么样的 chunk 序列, reassembly buffer 必须重组出相同语义.
        /// scan_chunked 内部对切分点做 clamp + 单调化, 容忍 proptest 生成的乱序/越界值.
        #[test]
        fn prop_arbitrary_chunk_split_equivalence(
            // 1..=16 个切分点, 位置范围 [0, 2048) 覆盖整个流长度 (~998 字节).
            splits in proptest::collection::vec(0usize..2048, 1..=16)
        ) {
            let full = sample_openai_sse_stream();
            // 一次性 feed 的 baseline.
            let mut whole = StreamScan::new(Protocol::OpenAI);
            whole.feed(&full);
            let baseline = whole.snapshot();
            // 任意切分点 feed.
            let chunked = scan_chunked(&splits, &full);
            // IrResponse 是确定性的 (id/model 来自上游 chatcmpl-x / gpt-4o, 无合成随机),
            // 所以可以用 assert_eq 严格比较.
            prop_assert_eq!(
                baseline, chunked,
                "chunk-boundary violation: baseline != chunked for splits {:?}",
                splits
            );
        }

        /// StreamTranslate (同协议 restore 模式) 的 chunk-boundary 等价性.
        ///
        /// 与 StreamScan 走的是两份独立的 reassembly buffer 实现 (feed 方法各自维护),
        /// 这里专门守护 StreamTranslate 的路径: 任意切分 feed 的累积 SSE 输出
        ///   == 一次性 feed 的 SSE 输出.
        ///
        /// 使用空 RedactionMap 的 same_proto_restore 模式 (redaction_map=None 短路 restore,
        /// 仅运行 reassembly + re-serialize 路径). StreamTranslate 的 translate_event 会
        /// 把 MessageStart.id 剥离 (跨协议身份剥离), 由 ingress writer 合成新的
        /// chatcmpl-<random> id, 因此输出含随机 id. 比较前用 normalize_id 把
        /// `"id":"chatcmpl-..."` 统一替换为 `"id":"<normalized>"`, 消除随机性后做字节比较.
        #[test]
        fn prop_stream_translate_chunk_split_equivalence(
            splits in proptest::collection::vec(0usize..2048, 1..=16)
        ) {
            use crate::redact::RedactionMap;
            let full = sample_openai_sse_stream();

            // 一次性 feed baseline.
            let mut whole = StreamTranslate::new_same_proto_restore(
                Protocol::OpenAI,
                RedactionMap::default(),
            );
            let baseline: Vec<u8> = whole.feed(&full);

            // 任意切分点 feed.
            let mut chunked_t = StreamTranslate::new_same_proto_restore(
                Protocol::OpenAI,
                RedactionMap::default(),
            );
            let mut chunked: Vec<u8> = Vec::new();
            let mut prev = 0usize;
            for &sp in &splits {
                let sp = sp.min(full.len()).max(prev);
                if sp > prev {
                    chunked.extend_from_slice(&chunked_t.feed(&full[prev..sp]));
                }
                prev = sp;
            }
            if prev < full.len() {
                chunked.extend_from_slice(&chunked_t.feed(&full[prev..]));
            }
            // 两者都未调用 finish (baseline 也没调用), 仅比较 feed 期间的累积输出.
            // 消除随机 id 后字节级比较.
            let baseline_str = String::from_utf8_lossy(&baseline);
            let chunked_str = String::from_utf8_lossy(&chunked);
            let baseline_norm = normalize_sse_id(&baseline_str);
            let chunked_norm = normalize_sse_id(&chunked_str);
            prop_assert_eq!(
                &baseline_norm, &chunked_norm,
                "StreamTranslate chunk-boundary violation for splits {:?}\n\
                 baseline(norm): {}\n\
                 chunked(norm):  {}",
                splits, baseline_norm, chunked_norm,
            );
        }
    }

    /// 极端切分: 每个字节单独成一个 chunk (1-byte splits).
    /// 覆盖 StreamScan reassembly buffer 的退化情形 (每个 feed 只推进 1 字节).
    ///
    /// 输入是确定性的 byte-by-byte 切分 (不依赖 proptest 生成), 作为独立 #[test] 放在
    /// proptest! 块外, 避免引入无用 strategy 参数.
    #[test]
    fn stream_scan_byte_by_byte_split_equivalence() {
        let full = sample_openai_sse_stream();
        let mut whole = StreamScan::new(Protocol::OpenAI);
        whole.feed(&full);
        let baseline = whole.snapshot();
        // 构造每 1 字节一个切分点 (0,1,2,...,len-1).
        let splits: Vec<usize> = (0..full.len()).collect();
        let chunked = scan_chunked(&splits, &full);
        assert_eq!(baseline, chunked);
    }

    /// 把 SSE 输出里的 `"id":"chatcmpl-<base62>"` 统一替换为 `"id":"<n>"`,
    /// 消除 StreamTranslate translate_event 合成的随机 id, 使输出可做字节级比较.
    ///
    /// 仅替换 chatcmpl- 前缀的 id (OpenAI writer 合成路径); 其他字段 (含可能的 UTF-8
    /// content) 原样保留. 用 str::find + 切片操作, 避免逐字节 as char 破坏 UTF-8.
    fn normalize_sse_id(input: &str) -> String {
        const PREFIX: &str = "\"id\":\"chatcmpl-";
        let mut out = String::with_capacity(input.len());
        let mut rest = input;
        while let Some(start) = rest.find(PREFIX) {
            // 推入 PREFIX 之前的部分 + 归一化的前缀.
            out.push_str(&rest[..start]);
            out.push_str("\"id\":\"<n>");
            // 跳过 PREFIX, 跳过 base62 部分直到下一个 '"'.
            let after_prefix = &rest[start + PREFIX.len()..];
            match after_prefix.find('"') {
                Some(end) => {
                    // end 是闭合 '"' 的位置, 保留它 (下一轮循环处理).
                    rest = &after_prefix[end..];
                }
                None => {
                    // 异常: 没有闭合 '"' (截断的 JSON), 直接追加剩余.
                    out.push_str(after_prefix);
                    rest = "";
                    break;
                }
            }
        }
        out.push_str(rest);
        out
    }
}
