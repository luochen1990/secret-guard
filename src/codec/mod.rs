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
//! - [`stream`]     —— SSE 流式响应的 chunk-boundary 处理 (StreamTranslate)

pub mod anthropic;
pub mod ir;
pub mod normalize;
pub mod openai;
pub mod responses;
pub mod stream;

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
    IrBlock, IrBlockMeta, IrDelta, IrError, IrImageSource, IrMessage, IrRequest, IrResponse,
    IrRole, IrStopReason, IrStreamEvent, IrTool, IrToolChoice, IrUsage,
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
