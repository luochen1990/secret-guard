//! SSE 帧重组骨架 [`SseReassembler`].
//!
//! StreamTranslate / StreamScan 两个上层关注点正交 (一个跨协议翻译, 一个累积 parsed
//! view), 但它们的 chunk-boundary 处理 (de-frame + parse + JSON 反序列化 + keepalive
//! / [DONE] / 非 JSON 噪声过滤 + MAX_BUF 溢出 abort) 完全一致, 故抽出此共享骨架.
//!
//! # 用法
//!
//! 调用者持有一个 `SseReassembler` 字段, 通过 [`SseReassembler::feed`] 喂入 chunk,
//! 传入 `on_frame` 回调处理每个完整帧 (回调签名 `FnMut(&str event_type, &Value)`).
//!
//! # 借用隔离
//!
//! `feed` 已占用 `&mut self`, 调用者不应在 `on_frame` 内再拿 `&mut self` (无法编译).
//! 标准模式是"先收集后处理": 回调把 frame 累积到局部 `Vec<(String, Value)>`, feed
//! 返回后再循环调用上层逻辑 (见 `translate::StreamTranslate::feed` / `scan::StreamScan::feed`).

use super::{MAX_BUF, SSE_DONE_SENTINEL, find_frame_terminator, parse_sse_frame};

/// SSE 帧重组骨架. 把任意 chunk 边界切割的字节流切成完整的 SSE frame.
///
/// 持有 reassembly buffer (`buf`) + 扫描游标 (`scanned`) + 溢出标记 (`aborted`).
/// 调用者通过 [`feed`](Self::feed) 喂入 chunk, 传入 `on_frame` 回调处理每个完整帧;
/// abort / MAX_BUF 溢出保护由骨架统一负责.
pub(super) struct SseReassembler {
    pub(super) buf: Vec<u8>,
    scanned: usize,
    aborted: bool,
}

impl SseReassembler {
    pub(super) fn new() -> Self {
        Self {
            buf: Vec::new(),
            scanned: 0,
            aborted: false,
        }
    }

    /// 喂入一个 chunk. 对每个完整 SSE 帧 (parse + JSON 反序列化成功后) 调用 `on_frame(event_name, data)`.
    ///
    /// 回调约束: 调用者不应在 `on_frame` 内拿 `&mut self` (骨架已占用), 应把 frame
    /// 累积到外部集合再循环处理.
    pub(super) fn feed<F: FnMut(&str, &serde_json::Value)>(
        &mut self,
        chunk: &[u8],
        mut on_frame: F,
    ) {
        if self.aborted {
            return;
        }
        self.buf.extend_from_slice(chunk);
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

            on_frame(&event_type, &data);
        }

        // 回收已消费前缀 (单次 shift, 线性而非 O(n^2)).
        if consumed > 0 {
            self.buf.drain(..consumed);
            self.scanned = self.buf.len();
        }
        if self.buf.len() > MAX_BUF {
            self.abort();
        }
    }

    /// 标记 aborted 并释放 reassembly buffer. 后续 [`feed`](Self::feed) 直接返回.
    pub(super) fn abort(&mut self) {
        self.aborted = true;
        self.buf.clear();
        self.buf.shrink_to_fit();
        self.scanned = 0;
    }

    pub(super) fn is_aborted(&self) -> bool {
        self.aborted
    }
}
