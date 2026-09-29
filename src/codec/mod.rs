//! 跨协议 codec: 在 OpenAI Chat Completions / Anthropic Messages / OpenAI Responses 之间双向翻译.
//!
//! # 设计哲学
//!
//! 借鉴 Busbar (`GetBusbar/busbar` Apache-2.0) 的 superset IR + Reader/Writer trait 设计,
//! 但大幅精简以匹配 secret-guard 的 MVP 范围:
//! - 覆盖 **OpenAI ⇄ Anthropic** 双向流式/非流式 (StreamTranslate).
//! - 覆盖 **Responses ⇄ Chat Completions / Anthropic** 流式与非流式 (流式经
//!   StreamTranslate 的事件级翻译, 非流式经通用 IR 路径).
//! - 不覆盖 embeddings/moderation/rerank.
//! - **不做** prompt caching / citations / logprobs.
//! - **不做** Bedrock eventstream 二进制流.
//!
//! # 路由策略
//!
//! - **同协议** (`ingress == egress`): 字节透传, 完全不进入 codec 模块.
//!   这保留 secret-guard 现有的字节级 redact 与流式 UX.
//! - **跨协议** (`ingress != egress`): 在 `proxy::dispatch` 中调用本模块,
//!   ingress bytes → IR → egress bytes; egress response → IR → ingress response.
//!
//! # 模块概览
//!
//! - [`ir`]         —— 协议无关 IR 类型 (IrRequest / IrResponse / IrStreamEvent 等)
//! - [`openai`]     —— OpenAI Chat Completions 的 Reader / Writer
//! - [`anthropic`]  —— Anthropic Messages 的 Reader / Writer
//! - [`responses`]  —— OpenAI Responses API 的 Reader / Writer
//! - [`stream`]     —— SSE 流式响应的 chunk-boundary 处理 (StreamTranslate /
//!   StreamScan / 伪流式形态适配 synthesize_sse)

pub mod anthropic;
pub mod ir;
pub mod normalize;
pub mod openai;
pub mod responses;
pub mod stream;
pub mod thinking;

#[cfg(test)]
mod fwd_cross_proto_property;
#[cfg(test)]
mod fwd_property;
#[cfg(test)]
mod fwd_responses_property;
#[cfg(test)]
mod fwd_streaming_property;

use serde_json::Value;

use crate::provider::Protocol as NativeProtocol;

pub use ir::{
    IrBlock, IrBlockMeta, IrDelta, IrError, IrImageSource, IrMessage, IrReasoning,
    IrReasoningEffort, IrRequest, IrResponse, IrRole, IrStopReason, IrStreamEvent, IrTool,
    IrToolChoice, IrUsage, ThinkingOpaque,
};

/// codec 层使用的 protocol 标识.
///
/// 与 [`crate::provider::Protocol`] 的区别: 后者是 secret-guard 全协议枚举 (含 Gemini/Ollama),
/// 本枚举只列出 codec **当前支持**的协议. 这样后续扩展时, `Protocol::from_native` 是单一接入点,
/// 不支持的协议返回 `None` 由 caller 决策 (通常是 501).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    OpenAI,
    Anthropic,
    /// OpenAI Responses API. 与 [`Self::OpenAI`] (Chat Completions) 字段结构差异显著.
    OpenAIResponses,
}

impl Protocol {
    /// 从 secret-guard 的全局 [`NativeProtocol`] 映射到 codec 支持的子集.
    /// 未支持的 protocol (Gemini/Ollama) 返回 `None`.
    pub fn from_native(p: NativeProtocol) -> Option<Self> {
        match p {
            NativeProtocol::OpenAI => Some(Self::OpenAI),
            NativeProtocol::Anthropic => Some(Self::Anthropic),
            NativeProtocol::OpenAIResponses => Some(Self::OpenAIResponses),
            _ => None,
        }
    }

    /// 该协议的 reader 实现.
    pub fn reader(self) -> Box<dyn Reader> {
        match self {
            Self::OpenAI => Box::new(openai::OpenAiReader),
            Self::Anthropic => Box::new(anthropic::AnthropicReader),
            Self::OpenAIResponses => Box::new(responses::ResponsesReader),
        }
    }

    /// 该协议的 writer 实现.
    pub fn writer(self) -> Box<dyn Writer> {
        match self {
            Self::OpenAI => Box::new(openai::OpenAiWriter),
            Self::Anthropic => Box::new(anthropic::AnthropicWriter),
            Self::OpenAIResponses => Box::new(responses::ResponsesWriter),
        }
    }
}

/// wire bytes / JSON → IR 的协议特定解析器.
///
/// 所有方法都是无状态 / pure function (除了流式 fan-out 用到的 [`ir::StreamDecodeState`],
/// 该 state 由 caller 持有, reader 仅借用).
pub trait Reader: Send + Sync {
    /// 协议名 (用于日志与错误消息).
    fn name(&self) -> &'static str;

    /// 解析请求 body (JSON) → [`IrRequest`].
    ///
    /// 失败返回 [`IrError`], 由 caller 转换为 400 响应给客户端.
    fn read_request(&self, body: &Value) -> Result<IrRequest, IrError>;

    /// 解析非流式响应 body (JSON) → [`IrResponse`].
    fn read_response(&self, body: &Value) -> Result<IrResponse, IrError>;

    /// 解析流式响应的单个 SSE 事件 → 多个 IR 事件 (fan-out).
    ///
    /// OpenAI 的 flat stream 一个 chunk 可能产生 0..n 个 IR 事件 (block 边界需要 state 合成);
    /// Anthropic 1:1 映射. [`ir::StreamDecodeState`] 由 caller 持有, 跨事件复用.
    fn read_response_events(
        &self,
        event_type: &str,
        data: &Value,
        state: &mut ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent>;
}

/// IR → wire bytes / JSON 的协议特定序列化器.
pub trait Writer: Send + Sync {
    /// 协议名 (用于日志与错误消息).
    fn name(&self) -> &'static str;

    /// 上游 request_uri (三段式 `base_url + common_uri + request_uri` 的尾段,
    /// 不含版本前缀: OpenAI `/chat/completions`, Anthropic `/messages`,
    /// Responses `/responses`) — 版本前缀由端点布局决定 (端点的
    /// `effective_common_uri` 推导, 见 `provider::Endpoint`, #260).
    fn upstream_path(&self) -> &'static str;

    /// [`IrRequest`] → 请求 body (JSON).
    fn write_request(&self, req: &IrRequest) -> Value;

    /// [`IrResponse`] → 非流式响应 body (JSON).
    fn write_response(&self, resp: &IrResponse) -> Value;

    /// 单个 IR 事件 → SSE 事件序列 `Vec<(event_type, data)>`; 空 Vec 表示该协议跳过此事件.
    ///
    /// 返回 Vec 是因为一个 IR 事件可能合成多个 SSE 帧 — Responses 的 `BlockStart{Text}`
    /// 产出 `output_item.added` + `content_part.added` 两帧 (done 类事件需要累积状态,
    /// 由 `state` 承载; OpenAI / Anthropic writer 不读 state).
    ///
    /// 例如 OpenAI writer 看到 `IrStreamEvent::MessageStop` 时不发对应 chunk
    /// (OpenAI 流的终止符 `data: [DONE]` 由 caller 在 finish 时追加),
    /// 返回空 Vec 让 StreamTranslate 跳过.
    fn write_response_event(
        &self,
        ev: &IrStreamEvent,
        state: &mut ir::StreamEncodeState,
    ) -> Vec<(String, Value)>;

    /// 该协议的请求是否要求 `max_tokens` 字段.
    /// OpenAI 可选, Anthropic 必填. 跨协议翻译时若 IR 缺 `max_tokens` 且目标必填,
    /// forward 层注入 [`DEFAULT_MAX_TOKENS`].
    fn requires_max_tokens(&self) -> bool {
        false
    }

    /// 该协议的 SSE 流是否以 `data: [DONE]\n\n` 终止.
    /// OpenAI=true, Anthropic=false (用 `message_stop` event 终止).
    fn emits_sse_done_terminator(&self) -> bool {
        false
    }

    /// 把上游错误 (HTTP 4xx/5xx) 翻译为 ingress 协议的原生错误 envelope.
    /// 让客户端 SDK 拿到的错误结构与直连时一致, 不暴露 codec 内部细节.
    fn write_error(&self, status: u16, kind: &str, message: &str) -> Value;
}

/// 跨协议时若目标协议要求 max_tokens 而 IR 缺失, 注入的默认值.
/// 4096 是所有主流 chat 模型都能接受的输出上限 (Anthropic 文档示例值).
pub const DEFAULT_MAX_TOKENS: u32 = 4096;

// ─── 内部共享 helpers (供 OpenAI / Anthropic reader/writer 复用) ────────────

/// 收集未在 first-class 字段处理的 key 到 extra.
/// 同协议时透传 (跨协议翻译前 caller 应清空 extra).
pub(super) fn collect_extra(
    obj: &serde_json::Map<String, Value>,
    known: &[&str],
) -> serde_json::Map<String, Value> {
    obj.iter()
        .filter(|(k, _)| !known.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// 生成 n 字符的 base62 随机串 (LCG, 非密码学安全).
/// 仅用于合成 id (chatcmpl-... / msg_01... / resp_...), 不需要密码学强度.
pub(super) fn random_base62(n: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    const CHARS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut buf = String::with_capacity(n);
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    for _ in 0..n {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        buf.push(CHARS[((seed >> 32) % 62) as usize] as char);
    }
    buf
}

/// 当前 Unix epoch seconds (用于 OpenAI/Responses wire 的 created / created_at 字段).
/// 共享 helper, 避免 openai.rs / responses.rs 各定义一份.
pub(super) fn current_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 把 blocks 中的 Text 块用 '\n' join 成单个字符串 (用于 system prompt 折叠).
/// 共享 helper, 避免 openai.rs / responses.rs 各定义一份.
pub(super) fn blocks_to_text(blocks: &[ir::IrBlock]) -> String {
    blocks
        .iter()
        .filter_map(|b| match b {
            ir::IrBlock::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 请求级聚合: `req.messages` 中全部 ToolResult content 内将被文本折叠丢弃的
/// 非 Text 块 (T8).
///
/// 返回 `(count, kinds)` — kinds 如 `"image:2,reasoning:1"` (BTreeMap 字母序稳定,
/// 类型名用 wire 词形 snake_case); 无丢弃 → `None`. WARN 消费点是 proxy 的
/// **egress 写出路径** (`proxy/helpers.rs::warn_tool_result_media_drop`,
/// cross_proto / same_proto 共享).
///
/// # 为什么是纯函数 (不在 codec 内打日志)
///
/// codec 的 `write_request` 还被多个非 egress 消费面复用 (生产面 ≥3 处):
/// ① cross_proto 的 ingress 视图序列化 (record body 构造, egress 可能是
/// Anthropic — 实际无损); ② DAG timeline 派生 (`derive.rs`, WebUI 3s 轮询
/// 反复触发); ③ records parsed view (`web/api/records.rs`). WARN 内嵌 codec
/// 会在这些路径误报/放大 (M1/M2), 可观测化必须在真正发生丢弃的 egress 调用点.
///
/// # 口径假设
///
/// ToolResult 只出现在 messages (system 不含 — 三协议 reader 均不产出到 system);
/// 嵌套 ToolResult 整体记 1 (`tool_result` kind, 与块级统计口径一致).
pub(crate) fn dropped_tool_result_media(req: &ir::IrRequest) -> Option<(usize, String)> {
    let mut dropped = std::collections::BTreeMap::new();
    for msg in &req.messages {
        for b in &msg.content {
            if let ir::IrBlock::ToolResult { content, .. } = b {
                for (kind, n) in count_dropped_tool_result_blocks(content) {
                    *dropped.entry(kind).or_insert(0) += n;
                }
            }
        }
    }
    if dropped.is_empty() {
        return None;
    }
    let count: usize = dropped.values().sum();
    let kinds = dropped
        .iter()
        .map(|(kind, n)| format!("{kind}:{n}"))
        .collect::<Vec<_>>()
        .join(",");
    Some((count, kinds))
}

/// 统计一个 ToolResult content 中将被文本折叠丢弃的非 Text 块 (类型 → 计数).
fn count_dropped_tool_result_blocks(
    blocks: &[ir::IrBlock],
) -> std::collections::BTreeMap<&'static str, usize> {
    let mut dropped = std::collections::BTreeMap::new();
    for b in blocks {
        let kind = match b {
            ir::IrBlock::Text { .. } => continue,
            ir::IrBlock::Image { .. } => "image",
            ir::IrBlock::ToolUse { .. } => "tool_use",
            ir::IrBlock::ToolResult { .. } => "tool_result",
            ir::IrBlock::Reasoning { .. } => "reasoning",
            ir::IrBlock::ReasoningContent { .. } => "reasoning_content",
        };
        *dropped.entry(kind).or_insert(0) += 1;
    }
    dropped
}

/// IR 图片来源 → URL 字符串 (Url 直通; Base64 → `data:<mime>;base64,<payload>`).
///
/// 共享 helper, 避免 openai.rs / responses.rs 各定义一份 — Responses writer 曾因
/// 独立演化只支持 Url source (Base64 静默丢弃, 审计 T8 附带 bug), 提取共享后
/// data URL 格式由构造保证对称. data URL 是两家协议图片字段的合法值.
pub(super) fn image_source_to_url(source: &ir::IrImageSource) -> String {
    match source {
        ir::IrImageSource::Url(u) => u.clone(),
        ir::IrImageSource::Base64 { media_type, data } => {
            format!("data:{media_type};base64,{data}")
        }
    }
}

/// IR ToolUse 的 input Value → function.arguments 字符串.
///
/// OpenAI Chat 与 Responses 的 arguments 字段都是 **JSON 字符串** (而非裸 JSON 值),
/// writer 必须序列化:
/// - `Value::Null` → `"null"` (历史 bug: 返回空字符串, 破坏 round-trip)
/// - `Value::String(s)` → JSON string literal `"\"s\""` (含引号 + 转义)
///
/// 注: 这与 reader 不对称 — reader 把 arguments 当 JSON 字符串 parse 为 Value,
///     writer 反向把 Value 序列化为 JSON 字符串. 之前的 `String(s.clone())` 是 bug
///     (假设 input 已是去引号字符串). 见 commit ccb8769 (IR wire fidelity).
pub(super) fn input_to_string(input: &Value) -> String {
    serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::{count_dropped_tool_result_blocks, dropped_tool_result_media};
    use crate::codec::ir::{IrBlock, IrImageSource, IrMessage, IrRequest, IrRole};

    fn text(s: &str) -> IrBlock {
        IrBlock::Text {
            text: s.to_string(),
            extra: Default::default(),
        }
    }

    fn image() -> IrBlock {
        IrBlock::Image {
            source: IrImageSource::Url("https://example.com/cat.png".into()),
            extra: Default::default(),
        }
    }

    fn tool_result(content: Vec<IrBlock>) -> IrBlock {
        IrBlock::ToolResult {
            tool_use_id: "call_1".into(),
            content,
            is_error: None,
            content_form: None,
            extra: Default::default(),
        }
    }

    /// T8 块级统计: 非 Text 块按类型计数 (WARN count/kinds 的数据源), Text 不计.
    #[test]
    fn count_dropped_tool_result_blocks_classifies_by_kind() {
        let blocks = vec![
            text("screenshot saved"),
            image(),
            IrBlock::Image {
                source: IrImageSource::Base64 {
                    media_type: "image/png".into(),
                    data: "iVBORw0KGgo=".into(),
                },
                extra: Default::default(),
            },
            IrBlock::ReasoningContent {
                text: "thinking...".into(),
                opaque: None,
                extra: Default::default(),
            },
            text("done"),
        ];
        let dropped = count_dropped_tool_result_blocks(&blocks);
        assert_eq!(dropped.len(), 2);
        assert_eq!(dropped.get("image"), Some(&2));
        assert_eq!(dropped.get("reasoning_content"), Some(&1));
        // 纯 Text / 空输入 → 无丢弃.
        assert!(count_dropped_tool_result_blocks(&[text("a"), text("b")]).is_empty());
        assert!(count_dropped_tool_result_blocks(&[]).is_empty());
    }

    /// T8 请求级聚合: 跨 message 的 ToolResult 统计合并为 (count, kinds),
    /// kinds 字母序稳定; 无 ToolResult / 纯 Text → None.
    #[test]
    fn dropped_tool_result_media_aggregates_across_messages() {
        let ir = IrRequest {
            messages: vec![
                IrMessage {
                    role: IrRole::User,
                    content: vec![text("weather?")],
                    ..Default::default()
                },
                IrMessage {
                    role: IrRole::User,
                    content: vec![tool_result(vec![text("screenshot saved"), image()])],
                    ..Default::default()
                },
                IrMessage {
                    role: IrRole::User,
                    content: vec![tool_result(vec![image()])],
                    ..Default::default()
                },
            ],
            model: "gpt-4o".into(),
            ..Default::default()
        };
        assert_eq!(
            dropped_tool_result_media(&ir),
            Some((2, "image:2".to_string()))
        );
        // system 内的 Image 不参与 (口径假设: ToolResult 只在 messages).
        let ir_system_image = IrRequest {
            system: vec![image()],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![text("hi")],
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            ..Default::default()
        };
        assert_eq!(dropped_tool_result_media(&ir_system_image), None);
        // 无丢弃 → None.
        let ir_plain = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![text("hi")],
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            ..Default::default()
        };
        assert_eq!(dropped_tool_result_media(&ir_plain), None);
    }

    /// M1/M2 回归守卫: codec writer 是纯序列化 — write_request 被非 egress 消费面
    /// (cross_proto 的 ingress 视图 / derive.rs 的 timeline 派生) 复用时**不得**发出
    /// 任何 tracing 事件 (首轮实现的 codec 内 WARN 在 ingress=Anthropic 方向事实性
    /// 误报、在 3s 轮询的视图路径日志放大). 丢弃可观测化在 proxy egress 写出点
    /// (`proxy/helpers.rs::warn_tool_result_media_drop`).
    ///
    /// 捕获方式仿 `redact.rs::CapturingMakeWriter` 先例: 线程局部 fmt subscriber
    /// 写入 Mutex sink, 不引入新 dev-dependency.
    #[test]
    fn write_request_with_media_tool_result_emits_no_log() {
        use crate::codec::Writer;
        use crate::codec::openai::OpenAiWriter;
        use crate::codec::responses::ResponsesWriter;

        struct CapturingMakeWriter {
            sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingMakeWriter {
            type Writer = CapturingWriter;
            fn make_writer(&'a self) -> Self::Writer {
                CapturingWriter {
                    sink: self.sink.clone(),
                }
            }
        }
        struct CapturingWriter {
            sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        }
        impl std::io::Write for CapturingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.sink.lock().expect("sink poisoned").write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![tool_result(vec![text("screenshot saved"), image()])],
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            ..Default::default()
        };

        let sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        tracing::dispatcher::with_default(
            &tracing::dispatcher::Dispatch::new(
                tracing_subscriber::fmt()
                    .with_env_filter(tracing_subscriber::EnvFilter::new("trace"))
                    .with_writer(CapturingMakeWriter { sink: sink.clone() })
                    .with_ansi(false)
                    .finish(),
            ),
            || {
                let _ = OpenAiWriter.write_request(&ir);
                let _ = ResponsesWriter.write_request(&ir);
                // 无损 writer (Anthropic 原样写回 blocks) 同样零日志 (M1 的
                // ingress=Anthropic 误报方向).
                let _ = crate::codec::anthropic::AnthropicWriter.write_request(&ir);
            },
        );
        let buf = sink.lock().expect("sink poisoned").clone();
        assert!(
            buf.is_empty(),
            "codec writer 必须零 tracing 输出 (M1/M2), 实际捕获: {}",
            String::from_utf8_lossy(&buf)
        );
    }
}
