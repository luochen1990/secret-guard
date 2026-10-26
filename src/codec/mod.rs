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
/// 在正交预算模型 (T6 裁决②, 2026-09-30) 中语义细化为 "**非思考**输出的默认
/// 长度" — 注入 thinking 预算时缺省 max_tokens = thinking_budget + 本值
/// (见 [`apply_thinking_linkage`]).
pub const DEFAULT_MAX_TOKENS: u32 = 4096;

/// 跨协议 seam 的 thinking 注入联动 (T6 两项用户裁决, 2026-09-30; 竞品先例
/// cc-switch `transform_codex_anthropic.rs:369-376` / LiteLLM 2025 同款修复).
///
/// 仅 egress = Anthropic 时生效 (其他协议 no-op); 由 `proxy/cross_proto.rs`
/// seam 在 extra 清空**之后**调用 (依赖 "extra 不含 thinking" 的后置条件 —
/// first-class 注入必然发生, 与 anthropic writer 的注入判定一致); 同协议路径
/// (same_proto redact) **不经此函数**, 采样参数经 first-class round-trip
/// 原样保真 (FWD-1 同协议零触碰).
///
/// # 裁决① 采样参数联动
///
/// 网关**注入** thinking (IrReasoning 以 Effort/Budget/Adaptive 形态写出到
/// Anthropic) 时: `temperature` / `top_p` / `top_k` 不写入 egress 请求 —
/// Anthropic 对 "thinking × 非默认采样参数" 历史上执行 400 (模型版本松紧不同,
/// 现状证据见 known-limitations codec 节采样联动条目). 不做值域判断 (如
/// top_p ≥ 0.95 放行) — 缺省形态恒合法且前缀缓存等价, 分支逻辑无收益.
/// forced tool_choice (`Required` / `Tool` — 客户端显式意图, 且 tools 非空
/// 才会上 egress wire) **优先于** thinking (网关增值注入): 冲突时跳过注入
/// (`reasoning` 置 None) + WARN, 且采样参数随 thinking 关闭恢复翻译 —
/// 宁可关思考, 保 tool 语义.
/// (边界注记: 官方文档 adaptive × forced tool use 兼容, 仅 enabled 形态冲突 —
/// 本函数对 Adaptive 同样保守跳过, 不依赖模型版本差异的兼容面; 该分支当前
/// **生产不可达** (o/r reader 只产 Effort, Adaptive 仅 a reader 产生且 a→a
/// same-proto 不经本函数), 现实影响为零; 若未来 reader 读出跨协议可达的
/// adaptive 形态, 再评估收窄到 Effort/Budget.)
///
/// # 裁决② max_tokens 正交预算合成
///
/// 思考预算 ⊥ 输出长度预算, `max_tokens = 两者之和`; 4096 (非思考输出的默认
/// 长度) = [`DEFAULT_MAX_TOKENS`]. 缺省注入值 = `thinking_budget + 4096`
/// (Effort 查表值 / Budget 原值; `saturating_add` 吸收 `Budget(u32::MAX)`
/// 病态值); 无 thinking 预算 (Disabled / 缺省 / Adaptive — adaptive 自管预算
/// 无 budget_tokens 字段, 不受 budget < max 约束) 时维持 4096 不变.
/// 显式 max_tokens 不在此路径 — anthropic writer 的 `clamp_thinking_budget`
/// 硬校验 (budget = min(budget, max-1)) 保留不动: 用户显式约束了总和,
/// 思考预算装不下就夹紧 (病态透传 400 的既有语义).
///
/// # 职责分工 (seam vs writer)
///
/// 合成规则 + 联动清理是**翻译语义** → 本函数 (seam 调用, 供 property test
/// 复用同一 SSOT); anthropic writer 只做硬校验 clamp. 本函数对 `ir` 的修改
/// (reasoning/采样参数置 None, max_tokens 合成) 会随后的 ingress 视图序列化
/// 一并反映 — record 是 "LLM 看到的版本" (egress 真实语义), 与此一致.
pub fn apply_thinking_linkage(ir: &mut IrRequest, egress: Protocol) {
    if egress != Protocol::Anthropic {
        return;
    }
    // thinking 会被注入为 Anthropic thinking 字段的形态 (Disabled 只写显式关闭,
    // 不构成 "注入" — 与采样参数无冲突).
    let injects_thinking = matches!(
        ir.reasoning,
        Some(IrReasoning::Effort(_)) | Some(IrReasoning::Budget(_)) | Some(IrReasoning::Adaptive)
    );
    // ① forced tool_choice 优先: tools 非空才会上 egress wire (writer gate 同型),
    // 空 tools 请求的 tool_choice 本就被丢弃, 不构成冲突.
    let forced_tool_choice = !ir.tools.is_empty()
        && matches!(
            ir.tool_choice,
            Some(IrToolChoice::Required) | Some(IrToolChoice::Tool { .. })
        );
    if injects_thinking && forced_tool_choice {
        tracing::warn!(
            tool_choice = ?ir.tool_choice,
            "forced tool_choice conflicts with cross-protocol thinking injection; \
             skipping thinking injection to preserve tool semantics \
             (sampling params translate normally with thinking off)"
        );
        ir.reasoning = None;
    } else if injects_thinking {
        // ② 注入 thinking → 采样参数不翻译 (Anthropic "thinking × 非默认采样" 400).
        // 日志级别取舍: 这是联动后的**常态行为** (非异常信号, 缺省形态是上游最稳
        // 形态且前缀缓存等价), 用 debug! 避免 per-request 噪音; 排障另有 record
        // (ingress 视图与 egress 语义一致, 采样参数消失如实可见)。此处早于
        // record push, 无 record_id 可关联 — 与 writer 侧 clamp WARN 同型的取舍.
        if ir.temperature.is_some() || ir.top_p.is_some() || ir.top_k.is_some() {
            tracing::debug!(
                "dropping sampling params (temperature/top_p/top_k) alongside \
                 injected thinking for Anthropic egress (T6 裁决①)"
            );
        }
        ir.temperature = None;
        ir.top_p = None;
        ir.top_k = None;
    }
    // ③ 缺省 max_tokens 正交预算合成 (显式值不动, writer clamp 兜底).
    if ir.max_tokens.is_none() {
        let thinking_budget = match ir.reasoning {
            Some(IrReasoning::Effort(e)) => e.budget_tokens(),
            Some(IrReasoning::Budget(n)) => n,
            _ => 0,
        };
        ir.max_tokens = Some(thinking_budget.saturating_add(DEFAULT_MAX_TOKENS));
    }
}

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

/// 把 `extra` 的键值合并进目标 Map (同名覆盖 — 回写优先级契约的唯一定义点;
/// L4/L5/工具级 extra 的回写共用, 跨协议路径已被 `clear_wire_fidelity` 清空).
pub(super) fn merge_extra_into(
    target: &mut serde_json::Map<String, Value>,
    extra: &serde_json::Map<String, Value>,
) {
    for (k, v) in extra {
        target.insert(k.clone(), v.clone());
    }
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

/// #403: OpenAI Chat 的 `role:"tool"` 消息 content 官方仅支持 text part
/// (`ChatCompletionToolMessageParam.content: string | array of text parts`,
/// image part 被 API 拒收 — "Image URLs are only allowed for messages with
/// role 'user'"), 媒体块搬到紧随 tool 批次的合成 user 消息, 原位置留此标记行
/// (维持 tool 消息 content 非空, cc-switch `TOOL_RESULT_MEDIA_MOVED_MARKER` 同型).
pub(crate) const TOOL_RESULT_MEDIA_MOVED_MARKER: &str =
    "[sg: tool result media moved to the following user message]";

/// #403: 合成 user 消息内的 per-call 媒体标签前缀 (拼 call_id + `]`;
/// cc-switch `queue_chat_tool_output_media` 同型 — label text part + 媒体 parts,
/// 模型可将图片与其 tool call 对应).
pub(crate) const TOOL_RESULT_MEDIA_LABEL_PREFIX: &str = "[sg: media output of tool call ";

/// ToolResult content 非 Text 块在 egress 写出点的处置统计 (#403, 纯函数).
///
/// 命运判定 (与 writer 实际行为对齐, 是 WARN 文案的 SSOT):
/// - **o egress**: User 消息内 ToolResult 的 Image → `moved` (OpenAI writer 搬运到
///   合成 user 消息); 其余非 Text 块 (tool_use / 嵌套 tool_result / reasoning 族 /
///   raw) 及**非 User 消息内**的一切非 Text 块 → `dropped` (退化臂无消息列表上下文,
///   媒体无处可去; 三协议 reader 均不产出该形态, 防御性如实统计).
/// - **r egress**: `function_call_output.output` 官方支持
///   `string | array of (input_text|input_image|input_file)` (2025-09 起,
///   openai-python v2 breaking change) — User 消息内 ToolResult 的 Image / Raw →
///   原位保真 (无条目); 其余非 Text 块 → `dropped`. 例外: ToolResult 自带
///   `content_form=Some(String|Null)` 时 output 按 string 形态回写 (writer 的
///   `Some(_) => false` 对两者同臂), 全部非 Text 块 → `dropped` (该形态经 reader
///   不可达 — string/null output 携带不了媒体; 仅内部构造 IR 可能出现, 统计如实).
/// - **a egress**: writer 原样写回 blocks, 无命运变化 — 本函数返回空 (gate 的
///   SSOT 在此单一化, WARN 消费点依赖空返回).
///
/// ToolResult 只出现在 messages (system 不含 — 三协议 reader 均不产出到 system);
/// 嵌套 ToolResult 整体记 1 (`tool_result` kind, 与块级统计口径一致).
///
/// # 为什么是纯函数 (不在 codec writer 内打日志)
///
/// codec 的 `write_request` 还被多个非 egress 消费面复用 (生产面 ≥3 处):
/// ① cross_proto 的 ingress 视图序列化 (record body 构造, egress 可能是
/// Anthropic — 实际无损); ② DAG timeline 派生 (`derive.rs`, WebUI 3s 轮询
/// 反复触发); ③ records parsed view (`web/api/records.rs`). WARN 内嵌 codec
/// 会在这些路径误报/放大 (M1/M2), 可观测化必须在真正发生丢弃的 egress 调用点.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ToolResultMediaFate {
    /// 搬运到合成 user 消息的块 (kind → count)
    moved: std::collections::BTreeMap<&'static str, usize>,
    /// 文本折叠丢弃的块 (kind → count)
    dropped: std::collections::BTreeMap<&'static str, usize>,
}

impl ToolResultMediaFate {
    /// 非空 bucket 的 (count, kinds) 汇总 (kinds 字母序稳定).
    fn summary(map: &std::collections::BTreeMap<&'static str, usize>) -> Option<(usize, String)> {
        let count: usize = map.values().sum();
        (count > 0).then(|| {
            let kinds = map
                .iter()
                .map(|(kind, n)| format!("{kind}:{n}"))
                .collect::<Vec<_>>()
                .join(",");
            (count, kinds)
        })
    }

    /// moved 非空时的 (count, kinds) 汇总 (kinds 字母序稳定).
    pub(crate) fn moved_summary(&self) -> Option<(usize, String)> {
        Self::summary(&self.moved)
    }

    /// dropped 非空时的 (count, kinds) 汇总 (kinds 字母序稳定).
    pub(crate) fn dropped_summary(&self) -> Option<(usize, String)> {
        Self::summary(&self.dropped)
    }
}

pub(crate) fn tool_result_media_fate(egress: Protocol, req: &ir::IrRequest) -> ToolResultMediaFate {
    // gate SSOT: 非 o/r egress (a 原样写回; 未来新增 codec 协议默认无统计直至
    // 显式判定) — WARN 消费点 (`proxy/helpers.rs`) 直接依赖此空返回.
    if !matches!(egress, Protocol::OpenAI | Protocol::OpenAIResponses) {
        return ToolResultMediaFate::default();
    }
    let mut fate = ToolResultMediaFate::default();
    for msg in &req.messages {
        // 搬运 / 原位保真只发生在 writer 的 User 主路径臂; 非 User 消息内的
        // ToolResult 走退化臂 (无消息列表上下文), 媒体一律 dropped.
        let in_user = msg.role == ir::IrRole::User;
        for b in &msg.content {
            if let ir::IrBlock::ToolResult {
                content,
                content_form,
                ..
            } = b
            {
                // r egress 的 string 形态例外: output 按原形态回写, 媒体无处承载
                // (Null 与 String 同臂 — writer 的 `Some(_) => false` 把两者都按
                // string 形态折叠, 统计口径须一致).
                let string_form = egress == Protocol::OpenAIResponses
                    && matches!(
                        content_form,
                        Some(ir::ContentForm::String | ir::ContentForm::Null)
                    );
                for cb in content {
                    let Some(kind) = nontext_block_kind(cb) else {
                        continue;
                    };
                    let bucket = match (egress, cb, in_user) {
                        // o: User 臂的媒体搬运, 其余丢弃
                        (Protocol::OpenAI, ir::IrBlock::Image { .. }, true) => &mut fate.moved,
                        // r: User 臂媒体/未知 part 原位保真 (array output), 其余丢弃
                        (
                            Protocol::OpenAIResponses,
                            ir::IrBlock::Image { .. } | ir::IrBlock::Raw { .. },
                            true,
                        ) if !string_form => continue,
                        _ => &mut fate.dropped,
                    };
                    *bucket.entry(kind).or_insert(0) += 1;
                }
            }
        }
    }
    fate
}

/// 非 Text 块的类型标签 (Text → None, 不参与统计).
fn nontext_block_kind(b: &ir::IrBlock) -> Option<&'static str> {
    match b {
        ir::IrBlock::Text { .. } => None,
        ir::IrBlock::Image { .. } => Some("image"),
        ir::IrBlock::ToolUse { .. } => Some("tool_use"),
        ir::IrBlock::ToolResult { .. } => Some("tool_result"),
        ir::IrBlock::Reasoning { .. } => Some("reasoning"),
        ir::IrBlock::ReasoningContent { .. } => Some("reasoning_content"),
        ir::IrBlock::Raw { .. } => Some("raw"),
    }
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
    use super::{Protocol, nontext_block_kind, tool_result_media_fate};
    use crate::codec::ir::{ContentForm, IrBlock, IrImageSource, IrMessage, IrRequest, IrRole};

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

    /// #363: 未知 content part / block 三协议同协议 round-trip verbatim —
    /// 修复前 reader 静默 drop 整个 part (FWD-1/FWD-2 违约). 畸形已知 type
    /// (text 缺 text 字段 / image 缺 source) 同为 Raw 原文透传.
    #[test]
    fn raw_content_parts_round_trip_verbatim() {
        use crate::codec::anthropic::{AnthropicReader, AnthropicWriter};
        use crate::codec::normalize::normalize_json;
        use crate::codec::openai::{OpenAiReader, OpenAiWriter};
        use crate::codec::responses::{ResponsesReader, ResponsesWriter};
        use crate::codec::{Reader, Writer};

        let cases: Vec<(&str, serde_json::Value)> = vec![
            (
                "openai",
                serde_json::json!({
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": [
                        {"type": "text", "text": "hi"},
                        {"type": "audio", "input_audio": {"data": "b64x", "format": "wav"}},
                        {"type": "text", "logprobs": {"content": ["a"]}},
                    ]}]
                }),
            ),
            (
                "responses",
                serde_json::json!({
                    "model": "gpt-5.4",
                    "input": [{"type": "message", "role": "user", "content": [
                        {"type": "input_text", "text": "hi"},
                        {"type": "input_file", "file": {"file_data": "data:text/plain;base64,QQ"}},
                    ]}]
                }),
            ),
            (
                "anthropic",
                serde_json::json!({
                    "model": "claude-sonnet-5", "max_tokens": 8,
                    "messages": [{"role": "user", "content": [
                        {"type": "text", "text": "hi"},
                        {"type": "document", "source": {"type": "url", "url": "https://x/d.pdf"}},
                        {"type": "image"},
                    ]}]
                }),
            ),
        ];
        for (name, body) in cases {
            let out = match name {
                "openai" => {
                    let ir = OpenAiReader.read_request(&body).unwrap();
                    OpenAiWriter.write_request(&ir)
                }
                "responses" => {
                    let ir = ResponsesReader.read_request(&body).unwrap();
                    ResponsesWriter.write_request(&ir)
                }
                _ => {
                    let ir = AnthropicReader.read_request(&body).unwrap();
                    AnthropicWriter.write_request(&ir)
                }
            };
            assert_eq!(
                normalize_json(&out),
                normalize_json(&body),
                "#363 {name}: 未知/畸形 part 必须 verbatim round-trip"
            );
        }
    }

    /// #363 响应侧变体: OpenAI Chat 响应 message.content 数组的单个未知 part
    /// round-trip 后必须保持 array 形态 — 裸对象不是合法 content 值
    /// (string | array), `single_or_array` 的单元素解包只对 string 语义无损.
    #[test]
    fn raw_content_part_response_single_part_keeps_array_form() {
        use crate::codec::normalize::normalize_json;
        use crate::codec::openai::{OpenAiReader, OpenAiWriter};
        use crate::codec::{Reader, Writer};

        let body = serde_json::json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": [{"type": "audio", "input_audio": {"data": "b64x", "format": "wav"}}]
                },
                // null → "stop" 是 reader 既有归一化 (与本测试无关), fixture 直接写终态.
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        });
        let ir = OpenAiReader.read_response(&body).unwrap();
        let out = OpenAiWriter.write_response(&ir);
        assert_eq!(
            normalize_json(&out),
            normalize_json(&body),
            "#363: 单 Raw part 响应必须保持 array 形态 round-trip"
        );
    }

    /// #403 块级统计: 非 Text 块按类型计数 (fate 的数据源), Text 不计.
    #[test]
    fn nontext_block_kind_classifies() {
        let blocks = [
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
        let kinds: Vec<&'static str> = blocks.iter().filter_map(nontext_block_kind).collect();
        assert_eq!(kinds, vec!["image", "image", "reasoning_content"]);
    }

    /// #403 请求级 fate 聚合: o egress — Image → moved, 其余非 Text → dropped;
    /// r egress — Image/Raw 原位保真 (无条目), 其余 → dropped; a egress 不适用
    /// (调用方 gate, 但纯函数对 a 返回空也是契约的一部分).
    #[test]
    fn tool_result_media_fate_per_egress() {
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
        // o egress: 两个 image 都搬运.
        let fate = tool_result_media_fate(Protocol::OpenAI, &ir);
        assert_eq!(fate.moved_summary(), Some((2, "image:2".to_string())));
        assert_eq!(fate.dropped_summary(), None);

        // r egress: image 原位保真 (array output) — 无 moved 无 dropped.
        let fate = tool_result_media_fate(Protocol::OpenAIResponses, &ir);
        assert_eq!(fate, Default::default());

        // a egress: writer 原样写回 — 恒空.
        let fate = tool_result_media_fate(Protocol::Anthropic, &ir);
        assert_eq!(fate, Default::default());
    }

    /// #403 fate 的 dropped 面: o egress 的非 Image 块 (reasoning_content) 仍丢弃;
    /// r egress 的 string 形态例外 (content_form=Some(String|Null), reader 不可达
    /// 的内部构造防御面 — writer 的 `Some(_) => false` 对两者同按 string 折叠)
    /// 全部非 Text 丢弃.
    #[test]
    fn tool_result_media_fate_dropped_and_string_form_exception() {
        let tr = |content: Vec<IrBlock>, content_form: Option<ContentForm>| IrBlock::ToolResult {
            tool_use_id: "call_1".into(),
            content,
            is_error: None,
            content_form,
            extra: Default::default(),
        };
        let reasoning = IrBlock::ReasoningContent {
            text: "thinking...".into(),
            opaque: None,
            extra: Default::default(),
        };
        let raw = IrBlock::Raw {
            entry: serde_json::json!({"type": "input_file", "file_id": "f_1"}),
        };
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![
                    tr(vec![image(), reasoning.clone()], None),
                    // r egress 的 string 形态 (reader 不可达, 内部构造防御面):
                    tr(vec![image()], Some(ContentForm::String)),
                    // Null 与 String 同臂 (writer `Some(_) => false`): 媒体同样
                    // 被折叠丢弃, 统计不得记为保真.
                    tr(vec![image()], Some(ContentForm::Null)),
                    // r egress 非 string 形态: raw 原位保真
                    tr(vec![raw], Some(ContentForm::Array)),
                ],
                ..Default::default()
            }],
            model: "m".into(),
            ..Default::default()
        };
        // o egress: image×3 moved; reasoning_content dropped (raw 在 o 跨协议
        // 路径已被 clear_wire_fidelity 丢弃, 同协议 o→o 会到折叠点 — dropped).
        let fate = tool_result_media_fate(Protocol::OpenAI, &ir);
        assert_eq!(fate.moved_summary(), Some((3, "image:3".to_string())));
        assert_eq!(
            fate.dropped_summary(),
            Some((2, "raw:1,reasoning_content:1".to_string()))
        );

        // r egress: 第一个 tr 的 image 保真 + reasoning dropped; string/Null 形态
        // tr 的 image dropped (Null 与 String 同臂); array 形态 tr 的 raw 保真.
        let fate = tool_result_media_fate(Protocol::OpenAIResponses, &ir);
        assert_eq!(fate.moved_summary(), None);
        assert_eq!(
            fate.dropped_summary(),
            Some((3, "image:2,reasoning_content:1".to_string()))
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
        assert_eq!(
            tool_result_media_fate(Protocol::OpenAI, &ir_system_image),
            Default::default()
        );
        // 无 ToolResult / 纯 Text → 恒空.
        let ir_plain = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![text("hi")],
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            ..Default::default()
        };
        assert_eq!(
            tool_result_media_fate(Protocol::OpenAI, &ir_plain),
            Default::default()
        );
    }

    /// M1/M2 回归守卫: codec writer 是纯序列化 — write_request 被非 egress 消费面
    /// (cross_proto 的 ingress 视图 / derive.rs 的 timeline 派生) 复用时**不得**发出
    /// 任何 tracing 事件 (首轮实现的 codec 内 WARN 在 ingress=Anthropic 方向事实性
    /// 误报、在 3s 轮询的视图路径日志放大). 丢弃可观测化在 proxy egress 写出点
    /// (`proxy/helpers.rs::warn_tool_result_media_fate`).
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
