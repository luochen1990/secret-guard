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
    ir::{IrStreamEvent, StreamDecodeState},
    Protocol, Reader, Writer,
};
use crate::redact::{restore_ir_stream_event, RedactionMap};

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
///   解析为 IR 事件, restore mock→real, 再序列化回 SSE. 用于同协议 + redact + 流式场景.
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
    /// 同协议 restore 模式: per-event 调用 restore_ir_stream_event.
    /// 跨协议模式: None (不做 restore).
    redaction_map: Option<RedactionMap>,
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
        })
    }

    /// 构造同协议 + restore 模式翻译器. 用于同协议 + redact + 流式响应场景.
    ///
    /// 工作流: egress SSE → parse IR events → restore_ir_stream_event → 序列化回 SSE.
    /// 失去 byte-exact (因为 IR re-serialize), 但语义等价, 同时保留流式 UX.
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
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
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
            if let IrStreamEvent::MessageDelta { usage, .. } = &mut ev {
                if let Some(start) = &self.start_usage.clone() {
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
            }

            // post-stop guard: MessageStop 后任何 MessageDelta 都丢弃
            // (避免 message_delta 在 message_stop 之后的非法 frame 顺序).
            if self.message_stopped && matches!(ev, IrStreamEvent::MessageDelta { .. }) {
                continue;
            }
            if matches!(ev, IrStreamEvent::MessageStop) {
                self.message_stopped = true;
            }

            // 同协议 restore 模式: per-event 把 mock 替换为 real.
            // 跨协议模式 redaction_map 为 None, 不做 restore.
            if let Some(map) = &self.redaction_map {
                restore_ir_stream_event(&mut ev, map);
            }

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

    /// 标记流为 aborted, 释放缓冲. 后续 feed 直接返回空.
    fn abort(&mut self) {
        self.aborted = true;
        self.buf.clear();
        self.buf.shrink_to_fit();
        self.scanned = 0;
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
    use crate::codec::{anthropic::AnthropicReader, openai::OpenAiReader, Protocol};

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
        use crate::codec::ir::StreamDecodeState;
        use crate::codec::Reader;
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
        use crate::codec::ir::StreamDecodeState;
        use crate::codec::Reader;
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
}
