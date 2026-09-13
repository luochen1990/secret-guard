//! SSE 流式响应的 chunk-boundary 处理与跨协议翻译.
//!
//! # 模块结构
//!
//! - [`StreamTranslate`]: 跨协议 SSE 翻译器 + 同协议 restore 模式 (实现在 `translate` 子模块).
//! - [`StreamScan`]:      流式 parsed view 累积器 (egress SSE → IrResponse, 实现在 `scan` 子模块).
//! - `SseReassembler`:    StreamTranslate / StreamScan 共享的帧重组骨架 (实现在 `reassembler` 子模块, 私有不导出).
//! - 本模块 (根):         共享 SSE 工具函数 + 上述类型的 re-export + 集中测试.
//!
//! # 设计概览
//!
//! [`StreamTranslate`] 把 egress 协议的 SSE 字节流实时翻译为 ingress 协议的 SSE 字节流.
//! [`StreamScan`] 把 egress SSE 累积为 [`crate::codec::IrResponse`] (供 WebUI parsed view).
//! 两者关注点正交: 翻译器不保留完整内容, 扫描器不转换协议. 详见各子模块头部文档.
//!
//! # chunk-boundary
//!
//! 一个 SSE 帧 (`event: foo\n\ndata: {...}\n\n`) 可能被 TCP 切成多个 chunk,
//! 也会出现一个 chunk 包含多个帧的情况. 帧重组由共享骨架 `SseReassembler` 负责
//! (StreamTranslate / StreamScan 各持有一个实例, 通过 `feed` 委托). 扫描位置
//! (`scanned`) 持续推进以保持 O(n) 性能 (避免每次 feed 都重新扫描已搜索过的前缀).
//!
//! # 终止符
//!
//! OpenAI 流以 `data: [DONE]\n\n` 结尾; Anthropic 用 `event: message_stop` 终止.
//! StreamTranslate 在 [`StreamTranslate::finish`] 时根据 ingress writer 决定是否追加 `[DONE]`.

mod reassembler;
mod scan;
mod translate;

// 私有引入 SseReassembler 供本模块的 tests 访问 (reassembler.rs 用 pub(super) 暴露).
#[cfg(test)]
use reassembler::SseReassembler;

pub use scan::StreamScan;
pub use translate::{DeltaKind, StreamRestoreHook, StreamTranslate};

/// SSE 流终止符 sentinel (OpenAI 约定).
pub const SSE_DONE_SENTINEL: &str = "[DONE]";

/// OpenAI 流的末尾完整帧.
pub const SSE_DONE_FRAME: &[u8] = b"data: [DONE]\n\n";

/// reassembly 缓冲上限. 防止恶意上游用无终止符的字节流耗尽内存.
/// 16 MiB 远大于任何合法的 chat completion SSE 帧.
pub const MAX_BUF: usize = 16 * 1024 * 1024;

// ─── SSE 解析工具函数 (translate / scan / reassembler 共享) ─────────────────

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
    use crate::codec::{
        Protocol, anthropic::AnthropicReader, openai::OpenAiReader, openai::OpenAiWriter,
    };
    use proptest::prelude::*;
    use serde_json::Value;
    use serde_json::json;

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
    fn feed_skips_frames_without_data_line() {
        // SSE 帧无 data: 行 (event-only / 注释) → parse_sse_frame 返回 None → continue.
        // 覆盖 152-153 分支. 混入一个有效帧确认 continue 后仍正常处理后续帧.
        let mut t = StreamTranslate::new(Protocol::Anthropic, Protocol::OpenAI).unwrap();
        let input = b"event: ping\n\ndata: {\"id\":\"x\",\"created\":0,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"},\"finish_reason\":null}]}\n\n";
        let out = t.feed(input);
        let s = String::from_utf8_lossy(&out);
        // event-only 帧被跳过, 有效帧产出 text_delta.
        assert!(
            s.contains("text_delta"),
            "valid frame after skipped frame: {s}"
        );
    }

    #[test]
    fn feed_skips_done_sentinel_and_empty_data() {
        // data: [DONE] 和空 data → continue (不携带 IR).
        // 覆盖 155-156 分支.
        let mut t = StreamTranslate::new(Protocol::Anthropic, Protocol::OpenAI).unwrap();
        let valid = b"data: {\"id\":\"x\",\"created\":0,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"},\"finish_reason\":null}]}\n\n";
        let input = b"data: [DONE]\n\ndata: \n\n";
        // 先喂有效帧建立 translator 状态, 再喂 [DONE] + 空 data (应被跳过, 不报错).
        let _ = t.feed(valid);
        let out = t.feed(input);
        // [DONE] 和空 data 不产出任何 SSE (跳过), out 应为空.
        let s = String::from_utf8_lossy(&out);
        assert!(
            !s.contains("text_delta") && !s.contains("error"),
            "[DONE] / empty data should be silently skipped: {s}"
        );
    }

    #[test]
    fn feed_skips_non_json_data() {
        // data: 非 JSON 内容 → serde_json::from_str 失败 → continue.
        // 覆盖 158-159 分支 (恶意/损坏 SSE).
        let mut t = StreamTranslate::new(Protocol::Anthropic, Protocol::OpenAI).unwrap();
        let input = b"data: this is not json\n\ndata: {also not json}\n\n";
        let out = t.feed(input);
        // 非 JSON 被跳过, 不产出 SSE, 不 panic.
        assert!(out.is_empty(), "non-JSON data should be skipped: {:?}", out);
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

    // ─── SseReassembler: 共享骨架的单元测试 ────────────────────────────

    #[test]
    fn sse_reassembler_abort_sets_flag_and_releases_buf() {
        // 喂入大 chunk 触发 MAX_BUF 溢出 → abort. 验证 aborted 标志 + buf capacity 收缩.
        let mut r = SseReassembler::new();
        assert!(!r.is_aborted(), "fresh reassembler must not be aborted");
        let huge = vec![b'a'; MAX_BUF + 1];
        let mut seen: Vec<(String, Value)> = Vec::new();
        r.feed(&huge, |et, d| seen.push((et, d)));
        assert!(r.is_aborted(), "should abort after >MAX_BUF unparsable buf");
        // 无帧终止符 → 不应误触发任何 on_frame 回调.
        assert!(seen.is_empty(), "no frame terminator, no callbacks");
        // shrink_to_fit 后 capacity 为 0.
        assert_eq!(
            r.buf.capacity(),
            0,
            "abort should shrink_tofit buf to 0 capacity, got {}",
            r.buf.capacity()
        );
        // 后续 feed 应是 no-op (aborted).
        let mut count = 0;
        r.feed(b"data: {\"x\":1}\n\n", |_et, _d| count += 1);
        assert_eq!(count, 0, "aborted reassembler should drop subsequent feed");
    }

    #[test]
    fn sse_reassembler_abort_explicit_marks_aborted() {
        // 直接调用 abort (非溢出路径), 验证 aborted 标志 + 后续 feed no-op.
        let mut r = SseReassembler::new();
        r.abort();
        assert!(r.is_aborted());
        let mut count = 0;
        r.feed(b"data: {\"x\":1}\n\n", |_et, _d| count += 1);
        assert_eq!(count, 0, "aborted reassembler should drop feed");
    }

    #[test]
    fn sse_reassembler_invokes_callback_for_each_complete_frame() {
        // 一个 chunk 含两个完整帧 + 一个不完整尾帧.
        let mut r = SseReassembler::new();
        let chunk = b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\ndata: {\"c\":";
        let mut got: Vec<Value> = Vec::new();
        r.feed(chunk, |_et, d| got.push(d));
        // 两个完整帧触发回调, 不完整尾帧留在 buffer.
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], json!({"a":1}));
        assert_eq!(got[1], json!({"b":2}));
        // 补全尾帧, 应触发第三个回调.
        got.clear();
        r.feed(b"3}\n\n", |_et, d| got.push(d));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], json!({"c":3}));
    }

    #[test]
    fn sse_reassembler_skips_keepalive_and_done_and_nonjson() {
        // keepalive (空 data) / [DONE] / 非 JSON 都应被跳过, 只回调有效 JSON 帧.
        let mut r = SseReassembler::new();
        let chunk = b"data: \n\ndata: [DONE]\n\ndata: not json\n\ndata: {\"ok\":true}\n\n";
        let mut got: Vec<Value> = Vec::new();
        r.feed(chunk, |_et, d| got.push(d));
        assert_eq!(
            got.len(),
            1,
            "only the valid JSON frame should be delivered"
        );
        assert_eq!(got[0], json!({"ok":true}));
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

    /// 回归测试: OpenAI 同协议 reader→writer 端到端, 多个并行 tool_call 的 oai
    /// index 必须保持唯一 (历史 bug: writer 硬编码 index=0 导致 N 个 tool_call
    /// 被客户端聚合成 1 个).
    #[test]
    fn openai_same_proto_multi_tool_call_preserves_distinct_indices() {
        use crate::codec::Reader;
        use crate::codec::Writer;
        use crate::codec::ir::StreamDecodeState;

        let reader = OpenAiReader;
        let writer = OpenAiWriter;
        let mut state = StreamDecodeState::default();

        // chunk 1: 开始两个 tool_call (index 0 和 1)
        let chunk1 = serde_json::json!({
            "id": "chatcmpl-x", "created": 0, "model": "glm-5.2",
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [
                        {"index": 0, "id": "call_a", "type": "function",
                         "function": {"name": "get_weather", "arguments": ""}},
                        {"index": 1, "id": "call_b", "type": "function",
                         "function": {"name": "get_time", "arguments": ""}}
                    ]
                },
                "finish_reason": null
            }]
        });
        // chunk 2: 两个 tool_call 各自的 arguments delta
        let chunk2 = serde_json::json!({
            "id": "chatcmpl-x", "created": 0, "model": "glm-5.2",
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [
                        {"index": 0, "function": {"arguments": "{\"city\":\"SF\"}"}},
                        {"index": 1, "function": {"arguments": "{}"}}
                    ]
                },
                "finish_reason": null
            }]
        });

        // reader → events → writer → chunks
        let mut seen_oai_indices = std::collections::BTreeSet::new();
        for chunk in [&chunk1, &chunk2] {
            let events = reader.read_response_events("", chunk, &mut state);
            for ev in &events {
                if let Some((_, out)) = writer.write_response_event(ev)
                    && let Some(choices) = out.get("choices").and_then(Value::as_array)
                {
                    for ch in choices {
                        if let Some(tcs) = ch
                            .get("delta")
                            .and_then(|d| d.get("tool_calls"))
                            .and_then(Value::as_array)
                        {
                            for tc in tcs {
                                if let Some(idx) = tc.get("index").and_then(Value::as_u64) {
                                    seen_oai_indices.insert(idx);
                                }
                            }
                        }
                    }
                }
            }
        }

        assert!(
            seen_oai_indices.len() >= 2,
            "端到端: 两个并行 tool_call 经 reader→writer 后必须有 ≥2 个不同的 oai index, 实际: {seen_oai_indices:?}"
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
        let mut t = StreamTranslate::new_same_proto_restore(
            proto,
            Box::new(crate::redact::StreamingRestorerSet::new(
                RedactionMap::default(),
            )),
        );

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
        let mut t = StreamTranslate::new_same_proto_restore(
            proto,
            Box::new(crate::redact::StreamingRestorerSet::new(
                RedactionMap::default(),
            )),
        );
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
        map.insert(real.to_string(), mock.to_string(), "id-test")
            .unwrap();
        let mut t = StreamTranslate::new_same_proto_restore(
            Protocol::OpenAI,
            Box::new(crate::redact::StreamingRestorerSet::new(map)),
        );

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

    #[test]
    fn stream_scan_aborts_on_unbounded_buffer() {
        // 喂入 MAX_BUF+1 字节无终止符数据 → aborted, 后续 feed no-op,
        // snapshot 返回已累积的空内容.
        let mut scan = StreamScan::new(Protocol::OpenAI);
        let huge = vec![b'a'; MAX_BUF + 1];
        scan.feed(&huge);
        // 下一次 feed 应该是 no-op (aborted).
        scan.feed(b"data: {\"id\":\"x\",\"created\":0,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"late\"}}]}\n\n");
        let ir = scan.snapshot();
        assert!(
            ir.content.is_empty(),
            "aborted scan should drop post-overflow feed, got content len {}",
            ir.content.len()
        );
        assert!(
            scan.reassembler.is_aborted(),
            "StreamScan should mark reassembler aborted on buffer overflow"
        );
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
        /// 守卫 STR-1: StreamScan chunk 边界透明 (任意切分 == 一次性 feed).
        ///
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

        /// 守卫 STR-1: StreamTranslate (同协议 restore) chunk 边界透明.
        ///
        /// StreamTranslate (同协议 restore 模式) 的 chunk-boundary 等价性.
        ///
        /// 与 StreamScan 走的是两份独立的 reassembly buffer 实现 (feed 方法各自维护),
        /// 这里专门守护 StreamTranslate 的路径: 任意切分 feed 的累积 SSE 输出
        ///   == 一次性 feed 的 SSE 输出.
        ///
        /// 使用空 RedactionMap 的 same_proto_restore 模式 (redaction_map=None 短路 restore,
        /// 仅运行 reassembly + re-serialize 路径). StreamTranslate 的 translate_event 会
        /// 把 MessageStart.id/created 剥离 (跨协议身份剥离), 由 ingress writer 合成新的
        /// chatcmpl-<random> id 和当前 epoch (current_epoch, 取自 SystemTime::now()).
        /// 因此输出含随机 id 和时敏 created. 比较前用 normalize_sse_volatile_fields 把
        /// 这两类字段归一化 (详见函数注释), 消除差异后做字节比较.
        #[test]
        fn prop_stream_translate_chunk_split_equivalence(
            splits in proptest::collection::vec(0usize..2048, 1..=16)
        ) {
            use crate::redact::RedactionMap;
            let full = sample_openai_sse_stream();

            // 一次性 feed baseline.
            let mut whole = StreamTranslate::new_same_proto_restore(
                Protocol::OpenAI,
                Box::new(crate::redact::StreamingRestorerSet::new(RedactionMap::default())),
            );
            let baseline: Vec<u8> = whole.feed(&full);

            // 任意切分点 feed.
            let mut chunked_t = StreamTranslate::new_same_proto_restore(
                Protocol::OpenAI,
                Box::new(crate::redact::StreamingRestorerSet::new(RedactionMap::default())),
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
            // 消除随机 id 和时敏 created 后字节级比较.
            let baseline_str = String::from_utf8_lossy(&baseline);
            let chunked_str = String::from_utf8_lossy(&chunked);
            let baseline_norm = normalize_sse_volatile_fields(&baseline_str);
            let chunked_norm = normalize_sse_volatile_fields(&chunked_str);
            prop_assert_eq!(
                &baseline_norm, &chunked_norm,
                "StreamTranslate chunk-boundary violation for splits {:?}\n\
                 baseline(norm): {}\n\
                 chunked(norm):  {}",
                splits, baseline_norm, chunked_norm,
            );
        }
    }

    // ─── STR-2 StreamScan 累积正确 (契约 §3 STR-2) ───────────────────────────
    //
    // 契约: docs/design/contracts.md L298-307.
    // 流式 SSE 经 StreamScan 累积的 IrResponse 必须与"等价非流式语义"一致.
    // StreamScan 是 WebUI resp_parsed 字段的真相来源 (DTO-3), 累积错位 → parsed view
    // 与实际响应不一致.
    //
    // 策略 (按 §0.3 Property 设计原则):
    // - 生成任意合法 OpenAI SSE 流 (text delta / tool_use input JSON 片段 / include_usage
    //   chunk / post-stop noise), 参数化各段内容与是否存在.
    // - snapshot 与预期 IrResponse 比较: content 文本拼接 / tool_use input JSON 拼接 /
    //   stop_reason / usage / model / id / created 都由生成器确定 → 可严格 assert_eq.
    // - 这避开了"StreamScan == reader.read_response(累积字节)"的字面形式 (SSE 字节本身
    //   不是合法非流式 JSON), 而是验证两者的**语义等价** (都描述同一个 assistant 回复),
    //   即契约陈述的"StreamScan 累积的 IrResponse 必须与非流式路径语义等价".

    /// 生成器: 任意合法 OpenAI SSE 流.
    ///
    /// 返回 (sse_bytes, expected): expected 是与该 SSE 语义等价的 IrResponse (确定性,
    /// 由生成器同步构造). 各段参数化: text content / tool name / tool_call id / partial JSON
    /// 片段 / 是否有 include_usage chunk / post-stop noise 内容.
    ///
    /// 流形态覆盖 (契约 STR-2 生成器覆盖要求):
    /// - text delta (可多 chunk, 拼接成完整文本)
    /// - tool_use 开始 (BlockStart) + InputJsonDelta 片段 (partial JSON, 跨 chunk 拼接)
    /// - finish_reason chunk (MessageStop 前置)
    /// - include_usage chunk (terminal usage, choices=[]) — **可选**, 由 has_usage 控制
    /// - [DONE] 终止符
    /// - post-stop noise (finish 后的噪声 chunk) — **可选**, 由 noise 控制
    fn arb_openai_sse_with_expected() -> impl Strategy<Value = (Vec<u8>, crate::codec::IrResponse)>
    {
        use crate::codec::ir::{IrBlock, IrStopReason, IrUsage};
        (
            "[a-z]{2,8}",                // text segment 1
            "[a-z]{2,8}",                // text segment 2 (跨 chunk 累积)
            "[a-z]{3,8}",                // tool name
            "call_[a-z0-9]{3,8}",        // tool_call id
            "[a-z]{2,6}",                // partial JSON 字段名
            "[a-z0-9]{2,8}",             // partial JSON 字段值
            any::<bool>(),               // 是否有 include_usage chunk
            any::<bool>(),               // 是否在 finish 后追加噪声 chunk
            "[a-z ]{2,12}",              // reasoning segment 1 (#176)
            "[a-z ]{2,12}",              // reasoning segment 2 (跨 chunk 累积, #176)
            any::<bool>(),               // 是否有思考阶段 chunk (#176)
        )
            .prop_map(
                |(
                    t1,
                    t2,
                    tool_name,
                    tc_id,
                    field,
                    value,
                    has_usage,
                    has_noise,
                    r1,
                    r2,
                    has_reasoning,
                )| {
                    let id = "chatcmpl-test".to_string();
                    let created: u64 = 1700000000;
                    let model = "gpt-4o".to_string();
                    let full_text = format!("{t1} {t2}");

                    let mut frames: Vec<String> = Vec::new();
                    // 预期 blocks (首个元素按 has_reasoning 条件插入 ReasoningContent).
                    let mut expected_blocks = Vec::new();

                    // 帧 0 (可选, #176): 思考阶段. reasoning delta 两段 (跨 chunk 累积),
                    // 在 text 之前 — 思考型模型的流形态 (reasoning chunks → content chunks).
                    // has_reasoning=true 时 reasoning 拿 IR index 1, text 顺延为 2, tool 3.
                    if has_reasoning {
                        frames.push(oai_chunk(&json!({
                            "id":id,"object":"chat.completion.chunk","created":created,"model":model,
                            "choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":r1},"finish_reason":Value::Null}]
                        })));
                        frames.push(oai_chunk(&json!({
                            "id":id,"object":"chat.completion.chunk","created":created,"model":model,
                            "choices":[{"index":0,"delta":{"reasoning_content":format!(" {r2}")},"finish_reason":Value::Null}]
                        })));
                        expected_blocks.push(IrBlock::ReasoningContent {
                            text: format!("{r1} {r2}"),
                        });
                    }

                    // 帧 1: 首个 text delta (fan-out: MessageStart + BlockStart{Text} + BlockDelta).
                    frames.push(oai_chunk(&json!({
                        "id":id,"object":"chat.completion.chunk","created":created,"model":model,
                        "choices":[{"index":0,"delta":{"role":"assistant","content":t1},"finish_reason":Value::Null}]
                    })));
                    // 帧 2: 第二个 text delta (跨 chunk 累积).
                    frames.push(oai_chunk(&json!({
                        "id":id,"object":"chat.completion.chunk","created":created,"model":model,
                        "choices":[{"index":0,"delta":{"content":format!(" {t2}")},"finish_reason":Value::Null}]
                    })));
                    expected_blocks.push(IrBlock::Text { text: full_text });
                    // 帧 3: tool_call 开始 (index=0, id+name, BlockStart{ToolUse}).
                    // 用 oai tool_calls[].index=0 (与 text 的 IR index 不同: text index 由
                    // next_free_block_index 分配, 无思考阶段时 text=1 tool=2; 有思考阶段
                    // reasoning=1, text=2, tool=3).
                    frames.push(oai_chunk(&json!({
                        "id":id,"object":"chat.completion.chunk","created":created,"model":model,
                        "choices":[{"index":0,"delta":{
                            "role":"assistant","content":Value::Null,
                            "tool_calls":[{"index":0,"id":tc_id,"type":"function",
                                "function":{"name":tool_name,"arguments":""}}]
                        },"finish_reason":Value::Null}]
                    })));
                    // 帧 4: tool_call arguments delta (partial JSON 片段, 跨 chunk 累积).
                    let partial = format!(r#"{{"{field}":"{value}"}}"#);
                    frames.push(oai_chunk(&json!({
                        "id":id,"object":"chat.completion.chunk","created":created,"model":model,
                        "choices":[{"index":0,"delta":{
                            "tool_calls":[{"index":0,"function":{"arguments":partial}}]
                        },"finish_reason":Value::Null}]
                    })));
                    // 帧 5: finish_reason chunk (MessageDelta{stop} + MessageStop).
                    frames.push(oai_chunk(&json!({
                        "id":id,"object":"chat.completion.chunk","created":created,"model":model,
                        "choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]
                    })));

                    // 预期 usage: include_usage chunk 携带的值 (若无则全 0).
                    let usage_input: u64 = if has_usage { 15 } else { 0 };
                    let usage_output: u64 = if has_usage { 7 } else { 0 };

                    // 帧 6 (可选): include_usage chunk (terminal usage, choices=[]).
                    if has_usage {
                        frames.push(oai_chunk(&json!({
                            "id":id,"object":"chat.completion.chunk","created":created,"model":model,
                            "choices":[],
                            "usage":{"prompt_tokens":usage_input,"completion_tokens":usage_output,
                                     "total_tokens":usage_input+usage_output}
                        })));
                    }

                    // 帧 7: [DONE] 终止符.
                    frames.push("data: [DONE]\n\n".to_string());

                    // 帧 8 (可选): post-stop noise.
                    // 噪声 = [DONE] 之后到达的、不携带有效 IR 事件的帧 (空 delta / 无 choices).
                    // StreamScan 应忽略此类帧 (reader 产 0 events). 注意: 带实际 content
                    // delta 的帧不是"噪声"——StreamScan 刻意不 guard post-stop content
                    // (apply_event 的 MessageStop 分支注释: 为支持 include_usage chunk).
                    // 因此契约 STR-2 "stop 后噪声被忽略" 的精确语义是: 无效/空帧被忽略,
                    // 而非"任何 stop 后的帧都被 guard".
                    if has_noise {
                        frames.push(oai_chunk(&json!({
                            "id":id,"object":"chat.completion.chunk","created":created,"model":model,
                            "choices":[{"index":0,"delta":{},"finish_reason":Value::Null}]
                        })));
                    }

                    // 构造预期 IrResponse (确定性, 与 SSE 语义等价).
                    let tool_input: Value = serde_json::from_str(&partial)
                        .unwrap_or_else(|_| json!({}));
                    expected_blocks.push(IrBlock::ToolUse {
                        id: tc_id,
                        name: tool_name,
                        input: tool_input,
                    });
                    let expected = crate::codec::IrResponse {
                        content: expected_blocks,
                        stop_reason: Some(IrStopReason::ToolUse),
                        stop_sequence: None,
                        usage: IrUsage {
                            input_tokens: usage_input,
                            output_tokens: usage_output,
                            ..Default::default()
                        },
                        // presence = 流中实际出现 usage 帧 (has_usage=false 时整个帧不发).
                        usage_present: has_usage,
                        model: Some(model),
                        id: Some(id),
                        created: Some(created),
                    };

                    let sse: String = frames.concat();
                    (sse.into_bytes(), expected)
                },
            )
    }

    /// OpenAI SSE chunk 帧 helper: `data: {json}\n\n`.
    fn oai_chunk(data: &Value) -> String {
        format!("data: {data}\n\n")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// STR-2 `prop_stream_scan_equals_non_streaming_parse`:
        /// 对任意合法 OpenAI SSE 流 (text + tool_use + include_usage + post-stop noise),
        /// StreamScan 累积的 snapshot == 预期 IrResponse (语义等价).
        ///
        /// 生成器覆盖 (契约 §0.3 第 3 条): text 跨 chunk 累积 / tool_use input JSON 片段 /
        /// include_usage chunk / post-stop noise. 单协议 OpenAI (StreamScan 目前仅 OpenAI
        /// 风格 chunk 解析路径完整, Anthropic 由 reader read_response_events 同样支持但
        /// snapshot 路径以 OpenAI flat stream 为主战场).
        #[test]
        fn prop_stream_scan_equals_non_streaming_parse(
            case in arb_openai_sse_with_expected()
        ) {
            let (sse, expected) = case;
            let mut scan = StreamScan::new(Protocol::OpenAI);
            scan.feed(&sse);
            let got = scan.snapshot();
            prop_assert_eq!(
                &got, &expected,
                "STR-2: StreamScan snapshot != 预期 IrResponse (语义等价违反)"
            );
        }

        /// STR-2 `prop_stream_scan_accumulates_text`:
        /// text token 跨多 chunk 累积正确 (snapshot 的 Text block == 全部 text delta 拼接).
        /// 按 variant 查找 Text block (has_reasoning=true 时首块是 ReasoningContent,
        /// 位置索引会空转).
        #[test]
        fn prop_stream_scan_accumulates_text(
            case in arb_openai_sse_with_expected()
        ) {
            let (sse, expected) = case;
            let mut scan = StreamScan::new(Protocol::OpenAI);
            scan.feed(&sse);
            let got = scan.snapshot();
            let find_text = |blocks: &[crate::codec::IrBlock]| {
                blocks.iter().find_map(|b| match b {
                    crate::codec::IrBlock::Text { text } => Some(text.clone()),
                    _ => None,
                })
            };
            prop_assert_eq!(
                find_text(&got.content),
                find_text(&expected.content),
                "STR-2 text accumulation 违反"
            );
        }

        /// STR-2 `prop_stream_scan_accumulates_tool_use`:
        /// tool_use input JSON 部分片段跨 chunk 累积正确 (snapshot 的 ToolUse block.input
        /// == 全部 InputJsonDelta 拼接后 parse 的 JSON).
        /// 按 variant 查找 ToolUse block (has_reasoning=true 时 index 1 是 Text 而非 ToolUse).
        #[test]
        fn prop_stream_scan_accumulates_tool_use(
            case in arb_openai_sse_with_expected()
        ) {
            let (sse, expected) = case;
            let mut scan = StreamScan::new(Protocol::OpenAI);
            scan.feed(&sse);
            let got = scan.snapshot();
            let find_tool = |blocks: &[crate::codec::IrBlock]| {
                blocks.iter().find_map(|b| match b {
                    crate::codec::IrBlock::ToolUse { id, name, input } => {
                        Some((id.clone(), name.clone(), input.clone()))
                    }
                    _ => None,
                })
            };
            prop_assert_eq!(
                find_tool(&got.content),
                find_tool(&expected.content),
                "STR-2 tool_use accumulation 违反"
            );
        }

        /// STR-2 `prop_stream_scan_include_usage_chunk`:
        /// include_usage chunk (choices=[], terminal usage) 正确更新 usage.
        /// has_usage=true 时 snapshot.usage 必须含 input/output; has_usage=false 时全 0.
        #[test]
        fn prop_stream_scan_include_usage_chunk(
            case in arb_openai_sse_with_expected()
        ) {
            let (sse, expected) = case;
            let mut scan = StreamScan::new(Protocol::OpenAI);
            scan.feed(&sse);
            let got = scan.snapshot();
            prop_assert_eq!(
                got.usage, expected.usage,
                "STR-2 include_usage chunk accumulation 违反"
            );
        }

        /// STR-2 `prop_stream_scan_ignores_post_stop_noise`:
        /// [DONE] 之后的噪声帧 (不携带有效 IR 事件的帧) 不影响 snapshot.
        ///
        /// "噪声"的精确语义 (见生成器注释): 空 delta / 无 choices 的帧, reader 产 0 events,
        /// StreamScan 不累积. 注意 StreamScan 刻意不 guard 带实际 content 的 post-stop
        /// 帧 (为支持 include_usage chunk), 因此本 property 只守卫"无效/空帧被忽略".
        /// 断言: snapshot == 预期 (无论 has_noise 是否追加空帧).
        #[test]
        fn prop_stream_scan_ignores_post_stop_noise(
            case in arb_openai_sse_with_expected()
        ) {
            let (sse, expected) = case;
            let mut scan = StreamScan::new(Protocol::OpenAI);
            scan.feed(&sse);
            let got = scan.snapshot();
            prop_assert_eq!(
                &got, &expected,
                "STR-2 post-stop noise (空帧) 被错误累积进 snapshot"
            );
        }

        /// STR-6 `prop_stream_scan_accumulates_reasoning` (#176):
        /// 思考阶段 reasoning_content delta 跨 chunk 累积为 ReasoningContent block.
        /// has_reasoning=true 时 snapshot 首个 block 必须是 ReasoningContent 且内容
        /// == 两段 delta 拼接; has_reasoning=false 时不得凭空出现.
        #[test]
        fn prop_stream_scan_accumulates_reasoning(
            case in arb_openai_sse_with_expected()
        ) {
            let (sse, expected) = case;
            let mut scan = StreamScan::new(Protocol::OpenAI);
            scan.feed(&sse);
            let got = scan.snapshot();
            let got_first = got.content.first().and_then(|b| match b {
                crate::codec::IrBlock::ReasoningContent { text } => Some(text.clone()),
                _ => None,
            });
            let want_first = expected.content.first().and_then(|b| match b {
                crate::codec::IrBlock::ReasoningContent { text } => Some(text.clone()),
                _ => None,
            });
            prop_assert_eq!(
                got_first, want_first,
                "STR-6 reasoning accumulation 违反 (首个 block 应为 ReasoningContent)"
            );
        }
    }

    // ─── STR-5 流式 reader 多 tool_call 索引分配 (契约 §3 STR-5) ──────────────
    //
    // 契约: docs/design/contracts.md L327-335.
    // OpenAI 流式响应中 N (≥2) 个并行 tool_call 经 reader 解析后, 每个在 IR 中有独立
    // block index (用于 writer 透传到 wire 的 tool_calls[].index, 保证客户端按 index
    // 聚合时不合并).
    //
    // 历史 bug 9712c52: writer 硬编码 index=0 → N 个 tool_call 被聚合成 1 个.
    // 当前固定测试只测 N=2, 这里用 proptest 覆盖 N=2..=5, 守护 reader 侧 index 分配
    // (next_free_block_index + tool_ir_index 持久化).

    /// 收集一组 IR 事件中所有 BlockStart{ToolUse} 的 IR block index.
    /// 用于断言 N 个 tool_call 各自拿到独立 index.
    fn collect_tool_use_block_indices(
        events: &[crate::codec::ir::IrStreamEvent],
    ) -> Vec<(usize, String)> {
        use crate::codec::ir::IrStreamEvent;
        let mut out = Vec::new();
        for ev in events {
            if let IrStreamEvent::BlockStart {
                index,
                block: crate::codec::ir::IrBlockMeta::ToolUse { id, .. },
            } = ev
            {
                out.push((*index, id.clone()));
            }
        }
        out
    }

    /// 构造一个含 N 个并行 tool_call 的首个 chunk (delta.tool_calls 数组长度 = N).
    /// 每个 tool_call 有不同 oai index (0..N) 与不同 id, 模拟 OpenAI 并行 tool_call 流.
    fn openai_multi_tool_call_start_chunk(n: usize, ids: &[String], names: &[String]) -> Value {
        let tool_calls: Vec<Value> = (0..n)
            .map(|i| {
                json!({
                    "index": i,
                    "id": ids[i],
                    "type": "function",
                    "function": {"name": names[i], "arguments": ""}
                })
            })
            .collect();
        json!({
            "id":"chatcmpl-multi","object":"chat.completion.chunk","created":1700000000,
            "model":"gpt-4o",
            "choices":[{"index":0,"delta":{
                "role":"assistant","content":Value::Null,
                "tool_calls":tool_calls
            },"finish_reason":Value::Null}]
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// STR-5 `prop_stream_reader_assigns_distinct_block_index`:
        /// N (≥2) 个并行 tool_call 经 OpenAI reader 解析后, 每个在 IR 中有独立 block index.
        ///
        /// 生成器: N ∈ [2, 5], 每个 tool_call 有独立 id + name. reader 一次 feed 首个 chunk,
        /// 收集所有 BlockStart{ToolUse} 的 IR index, 断言:
        /// 1. 数量 == N (每个 tool_call 都开了 BlockStart)
        /// 2. IR index 互不相同 (distinct)
        #[test]
        fn prop_stream_reader_assigns_distinct_block_index(
            n in 2usize..=5,
        ) {
            use crate::codec::Reader;
            use crate::codec::ir::StreamDecodeState;
            let reader = OpenAiReader;
            let mut state = StreamDecodeState::default();

            let ids: Vec<String> = (0..n).map(|i| format!("call_{i}")).collect();
            let names: Vec<String> = (0..n).map(|i| format!("tool_{i}")).collect();
            let chunk = openai_multi_tool_call_start_chunk(n, &ids, &names);

            let events = reader.read_response_events("", &chunk, &mut state);
            let indices = collect_tool_use_block_indices(&events);

            prop_assert_eq!(
                indices.len(), n,
                "STR-5: 应有 N 个 BlockStart{{ToolUse}}, 实际 {}",
                indices.len(),
            );
            let ir_idxs: Vec<usize> = indices.iter().map(|(i, _)| *i).collect();
            let unique: std::collections::BTreeSet<usize> = ir_idxs.iter().copied().collect();
            prop_assert_eq!(
                unique.len(), n,
                "STR-5: N 个 tool_call 的 IR index 必须互不相同, 实际 {:?}",
                ir_idxs,
            );
            // id 也必须对应 (每个 BlockStart 的 id 与 wire tool_calls[i].id 一致).
            let got_ids: std::collections::BTreeSet<String> =
                indices.iter().map(|(_, id)| id.clone()).collect();
            let want_ids: std::collections::BTreeSet<String> = ids.iter().cloned().collect();
            prop_assert_eq!(got_ids, want_ids, "STR-5: tool_call id 丢失或不匹配");
        }

        /// STR-5 `prop_stream_reader_mixed_text_and_tool_call_indices_correct`:
        /// 文本 + 多 tool_call 混合流的 IR block index 不冲突.
        ///
        /// 构造: chunk1 含 text delta (开 Text block); chunk2 含 N 个 tool_call (开 N 个
        /// ToolUse block). 断言 text index 不与任何 tool index 相同.
        /// 覆盖历史 bug 模式: text 先到 → text=1, tools=2..N+1 (next_free_block_index).
        #[test]
        fn prop_stream_reader_mixed_text_and_tool_call_indices_correct(
            text in "[a-z]{1,10}",
            n in 2usize..=4,
        ) {
            use crate::codec::Reader;
            use crate::codec::ir::StreamDecodeState;
            let reader = OpenAiReader;
            let mut state = StreamDecodeState::default();

            // chunk1: text delta (开 Text block).
            let chunk1 = json!({
                "id":"chatcmpl-mix","object":"chat.completion.chunk","created":1700000000,
                "model":"gpt-4o",
                "choices":[{"index":0,"delta":{"role":"assistant","content":text},"finish_reason":Value::Null}]
            });
            let _ = reader.read_response_events("", &chunk1, &mut state);

            // chunk2: N 个并行 tool_call.
            let ids: Vec<String> = (0..n).map(|i| format!("call_mix_{i}")).collect();
            let names: Vec<String> = (0..n).map(|i| format!("mix_tool_{i}")).collect();
            let chunk2 = openai_multi_tool_call_start_chunk(n, &ids, &names);
            let events2 = reader.read_response_events("", &chunk2, &mut state);

            // text index (首次 text delta 时分配).
            let text_idx = state.text_index;
            // tool IR indices.
            let tool_indices = collect_tool_use_block_indices(&events2);
            prop_assert_eq!(tool_indices.len(), n, "STR-5 混合: N 个 tool_call BlockStart");
            let tool_ir_idxs: Vec<usize> = tool_indices.iter().map(|(i, _)| *i).collect();

            // text index 与所有 tool index 互不相同.
            if let Some(tidx) = text_idx {
                prop_assert!(
                    !tool_ir_idxs.contains(&tidx),
                    "STR-5 混合: text index {tidx} 与 tool index {:?} 冲突",
                    tool_ir_idxs,
                );
            }
            // tool index 之间也互不相同 (与 distinct property 一致, 这里在混合场景再守卫一次).
            let unique: std::collections::BTreeSet<usize> = tool_ir_idxs.iter().copied().collect();
            prop_assert_eq!(
                unique.len(), n,
                "STR-5 混合: N 个 tool_call IR index 互不相同, 实际 {:?}",
                tool_ir_idxs,
            );
        }

        /// STR-6 `prop_stream_reader_reasoning_text_tool_indices_correct` (#176):
        /// 思考 + 文本 + 多 tool_call 混合流的 IR block index 三类互不冲突.
        ///
        /// 构造: reasoning delta (先到) → text delta → N 个 tool_call. 断言三类
        /// block index 两两不同 (next_free_block_index 的三状态覆盖).
        #[test]
        fn prop_stream_reader_reasoning_text_tool_indices_correct(
            reasoning in "[a-z]{1,10}",
            text in "[a-z]{1,10}",
            n in 2usize..=4,
        ) {
            use crate::codec::Reader;
            use crate::codec::ir::StreamDecodeState;
            let reader = OpenAiReader;
            let mut state = StreamDecodeState::default();

            let base = json!({
                "id":"chatcmpl-rmix","object":"chat.completion.chunk","created":1700000000,
                "model":"gpt-4o",
                "choices":[{"index":0,"delta":{},"finish_reason":Value::Null}]
            });
            let mut with_reasoning = base.clone();
            with_reasoning["choices"][0]["delta"]["reasoning_content"] = json!(reasoning);
            let _ = reader.read_response_events("", &with_reasoning, &mut state);

            let mut with_text = base.clone();
            with_text["choices"][0]["delta"]["content"] = json!(text);
            let _ = reader.read_response_events("", &with_text, &mut state);

            let ids: Vec<String> = (0..n).map(|i| format!("call_rmix_{i}")).collect();
            let names: Vec<String> = (0..n).map(|i| format!("rmix_tool_{i}")).collect();
            let tool_chunk = openai_multi_tool_call_start_chunk(n, &ids, &names);
            let tool_events = reader.read_response_events("", &tool_chunk, &mut state);

            let r_idx = state.reasoning_index.expect("reasoning index allocated");
            let t_idx = state.text_index.expect("text index allocated");
            let tool_idxs: Vec<usize> =
                collect_tool_use_block_indices(&tool_events).into_iter().map(|(i, _)| i).collect();

            let mut all = vec![r_idx, t_idx];
            all.extend(tool_idxs.iter().copied());
            let unique: std::collections::BTreeSet<usize> = all.iter().copied().collect();
            prop_assert_eq!(
                unique.len(),
                all.len(),
                "STR-6: reasoning/text/tool block index 冲突, 实际 r={:?} t={:?} tools={:?}",
                r_idx,
                t_idx,
                tool_idxs,
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

    /// 把 SSE 输出里两类 writer 合成的时敏/随机字段归一化, 使输出可做字节级比较:
    ///
    /// - `"id":"chatcmpl-<base62>"` → `"id":"<n>`  (OpenAI writer `synth_id` 每次随机)
    /// - `"created":<digits>`       → `"created":<n>` (writer `current_epoch` 取自
    ///   `SystemTime::now()`, baseline 与 chunked 两次 `.feed()` 间可能跨整秒边界)
    ///
    /// 两个前缀互不为子串, 不会在同一偏移同时命中, 因此分两趟独立 find-replace 语义等价且更清晰.
    /// 仅替换 writer 合成路径产出的字段: chatcmpl- 前缀用于识别合成 id, 区分上游透传的业务 id
    /// (如 fixture 的 `cmpl-x`); 其他字段 (含可能的 UTF-8 content) 原样保留.
    /// 用 str::find + 切片, 避免逐字节 as char 破坏 UTF-8.
    fn normalize_sse_volatile_fields(input: &str) -> String {
        // Pass 1: `"id":"chatcmpl-<base62>"` → `"id":"<n>`.
        // 假设: writer 用 synth_id 合成, base62 payload 不含 `"`.
        // 不成立时 (截断 JSON 无闭合 `"`) 直接追加剩余, 不报错.
        const ID_PREFIX: &str = "\"id\":\"chatcmpl-";
        let mut out = String::with_capacity(input.len());
        let mut rest = input;
        while let Some(start) = rest.find(ID_PREFIX) {
            out.push_str(&rest[..start]);
            out.push_str("\"id\":\"<n>");
            let after = &rest[start + ID_PREFIX.len()..];
            match after.find('"') {
                // end 是闭合 '"' 的位置, 保留它交由下一轮处理.
                Some(end) => rest = &after[end..],
                None => {
                    out.push_str(after);
                    rest = "";
                    break;
                }
            }
        }
        out.push_str(rest);

        // Pass 2: `"created":<digits>` → `"created":<n>`.
        // 假设: writer 序列化为 compact ASCII 数字 (json!(u64)), 不带空格.
        // writer 契约保证 created 后必有 ≥1 数字, 此处 position 返回 Some(0) 不会发生;
        // 即便发生, end=0 会让 rest 不推进 → 死循环. unwrap_or 兜底到 after.len() 避免之.
        const CREATED_PREFIX: &str = "\"created\":";
        let mut out2 = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(start) = rest.find(CREATED_PREFIX) {
            out2.push_str(&rest[..start]);
            out2.push_str("\"created\":<n>");
            let after = &rest[start + CREATED_PREFIX.len()..];
            let end = after
                .bytes()
                .position(|b| !b.is_ascii_digit())
                .unwrap_or(after.len());
            rest = &after[end..];
        }
        out2.push_str(rest);
        out2
    }
}
