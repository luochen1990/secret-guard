//! 协议无关 IR 类型: 请求 / 响应 / 流事件.
//!
//! # 设计原则
//!
//! - **Superset IR**: 承载 OpenAI 和 Anthropic 都能表达的字段;
//!   单 protocol 独有的字段 (如 Anthropic `top_k`) 也在 IR 中, 但对端 writer 直接 drop.
//! - **first-class 字段优先于 `extra`**: 任何**需要跨协议保留**的字段都必须是 IR first-class 字段,
//!   而不是放在 `extra` (extra 在跨协议翻译时会被清空, 防止源协议独有的字段泄漏到对端).
//! - **同协议 round-trip 语义等价**: 同协议的 reader→writer 链应该让 body **语义等价**
//!   (字段顺序可能不同; 空文本块 / 空 content 等价性可能轻微变化, 但对 LLM 而言无差异).
//!   不追求严格 byte-exact (字段顺序 / 空字符串归一化可能让 wire 字节略变).

use serde_json::{Value, json};

// ─── 请求侧 ────────────────────────────────────────────────────────────────

/// 协议无关的 chat completion 请求.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrRequest {
    /// system / developer 角色的消息 (OpenAI: `messages[].role=="system"` 提升;
    /// Anthropic: 顶层 `system` 字段). 跨协议时这些块要折叠到顶层 system 或反之.
    pub system: Vec<IrBlock>,
    /// 主体对话消息 (不含 system 角色).
    pub messages: Vec<IrMessage>,
    /// 工具定义.
    pub tools: Vec<IrTool>,
    /// wire 形态元数据: 原始 wire 是否含 tools 字段 (即便为空数组).
    /// 同协议 round-trip 时填充, 跨协议翻译前清空.
    /// 区分 "tools: []" (显式空) 与缺失 tools 字段.
    pub tools_present: bool,
    /// 最大输出 token 数. OpenAI 可选, Anthropic 必填.
    pub max_tokens: Option<u32>,
    /// 采样温度. JSON 数字是 f64, 用 f64 避免 0.7→0.699999988 的精度损失.
    pub temperature: Option<f64>,
    /// nucleus sampling 截止. 两个协议都有.
    pub top_p: Option<f64>,
    /// top-k sampling 截止. **仅 Anthropic 有**; OpenAI writer drop.
    pub top_k: Option<u32>,
    /// 停止序列 (归一化为 `Vec<String>`). 空数组表示无 stop 序列 (但仍可能原始 wire 显式存在).
    pub stop: Vec<String>,
    /// wire 形态元数据: 原始 wire 中 `stop` 字段是否存在及其形态.
    /// - `None`: 缺失 / 跨协议路径 (writer 不输出 stop 字段)
    /// - `Some(StopForm::String)`: 原始是单字符串 (writer 输出 `"stop":"..."`)
    /// - `Some(StopForm::Array)`: 原始是数组 (writer 输出 `"stop":[...]`, 即便空数组也输出)
    ///
    /// 仅同协议 round-trip 时填充, 用于 wire 形态保真 (L7).
    /// 跨协议翻译前由 caller 清空.
    pub stop_form: Option<StopForm>,
    /// 工具选择策略.
    pub tool_choice: Option<IrToolChoice>,
    /// 终端用户标识. OpenAI: 顶层 `user`; Anthropic: `metadata.user_id`.
    pub user: Option<String>,
    /// 是否允许并行工具调用.
    /// OpenAI: 顶层 `parallel_tool_calls` (默认 true);
    /// Anthropic: `tool_choice.disable_parallel_tool_use` (默认 false, 注意取反).
    pub parallel_tool_calls: Option<bool>,
    /// 是否流式响应.
    pub stream: bool,
    /// 模型 id (从原始请求透传, 写入 egress 请求).
    pub model: String,
    /// 未建模字段的逃生舱. 同协议 round-trip 时透传; 跨协议时清空 (防泄漏).
    pub extra: serde_json::Map<String, Value>,
}

impl IrRequest {
    /// 清空所有 wire_fidelity 元数据 (跨协议翻译前调用, SSOT).
    ///
    /// wire_fidelity 字段记录的是 **ingress 协议的 wire 形态** (如字段是 string 还是 array),
    /// 跨协议翻译时 ingress 形态对 egress 协议无意义, 必须清空, 否则会污染 egress wire.
    /// 集中在此避免新增字段时漏清.
    pub fn clear_wire_fidelity(&mut self) {
        self.stop_form = None;
        self.tools_present = false;
        for m in &mut self.messages {
            m.content_form = None;
            for b in &mut m.content {
                if let IrBlock::ToolResult { content_form, .. } = b {
                    *content_form = None;
                }
            }
        }
    }
}

/// 单条对话消息.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrMessage {
    pub role: IrRole,
    pub content: Vec<IrBlock>,
    /// wire 形态元数据: 原始 wire 中 `content` 是 string 还是 array 还是 null.
    /// - `None`: 跨协议路径 / 内部构造 (writer 用协议默认形态)
    /// - `Some(ContentForm::String)`: 原始是裸 string (Anthropic 单文本消息常见)
    /// - `Some(ContentForm::Array)`: 原始是 array of blocks
    /// - `Some(ContentForm::Null)`: 原始是 null (assistant 调用工具时)
    ///
    /// 仅同协议 round-trip 时填充, 用于 wire 形态保真 (L1).
    /// 跨协议翻译前由 caller 清空.
    pub content_form: Option<ContentForm>,
    /// 这条消息是否代表用户的**主动文本输入** (而非工具结果的隐式 user 角色).
    ///
    /// 背景: IR 把 OpenAI `role:"tool"` 和 Anthropic `role:"user"+tool_result` 都归一化
    /// 为 `IrRole::User`, 导致无法从 `role` 单一维度区分 "用户真在说话" vs "工具结果
    /// 借 user 角色承载". 此字段补充丢失的维度, 由 reader 入口 (同时看到原始 wire role
    /// 和解析后的 content blocks) 集中判定:
    ///   - `role == User` 且 content 含非空 Text block → true
    ///   - 其他 (tool_result-only user / assistant / system) → false
    ///
    /// 用途: DAG 的 round_role 判定 (sidebar 分组: 用户轮 vs 工具轮).
    /// 不参与 wire 序列化 (writer 忽略此字段).
    ///
    /// 注意: 此字段在 `MessageRef`/`resolve_message` 中**不保留** (MessageRef 只存 role +
    /// block hash). round_role 在 push_messages 时一次性消耗原始 msgs 的此字段, 之后
    /// resolve_message 重建的 IrMessage 此字段会 reset 为 false (Default).
    pub contains_user_text: bool,
}

/// content blocks 是否含非空 Text block.
/// 用于 reader 入口判定 `contains_user_text`.
pub fn blocks_has_text(blocks: &[IrBlock]) -> bool {
    blocks
        .iter()
        .any(|b| matches!(b, IrBlock::Text { text } if !text.is_empty()))
}

/// wire 中 message content 的原始形态. 用于同协议 round-trip 时保留 wire 形态.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentForm {
    /// 裸字符串: `"content": "hello"`
    String,
    /// 数组: `"content": [{"type":"text","text":"hello"}]`
    Array,
    /// null: `"content": null (assistant 调用工具时)
    Null,
}

impl ContentForm {
    /// 从 wire 字段值推断 content 形态. 缺失 / 非预期类型 → None (writer 用协议默认).
    /// 用于 reader 在解析 message content / tool_result content 时记录原始形态 (L1 保真).
    pub fn classify(value: Option<&Value>) -> Option<Self> {
        match value {
            Some(Value::String(_)) => Some(Self::String),
            Some(Value::Array(_)) => Some(Self::Array),
            Some(Value::Null) => Some(Self::Null),
            _ => None,
        }
    }
}

/// wire 中 stop 字段的原始形态. 用于同协议 round-trip 时保留 wire 形态.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopForm {
    /// 单字符串: `"stop": "abc"`
    String,
    /// 数组: `"stop": ["abc"]`
    Array,
}

impl StopForm {
    /// 从 wire `stop` 字段值推断形态. 缺失 / 非预期类型 → None.
    pub fn classify(value: Option<&Value>) -> Option<Self> {
        match value {
            Some(Value::String(_)) => Some(Self::String),
            Some(Value::Array(_)) => Some(Self::Array),
            _ => None,
        }
    }
}

/// 消息角色. 注意: `System` 角色的消息虽然出现在 [`IrMessage`] 里时,
/// reader 会**提升**到 [`IrRequest::system`], 但 IrMessage 仍可承载 (内部一致性).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum IrRole {
    System,
    #[default]
    User,
    Assistant,
    Tool,
}

/// 消息内容块 (chat completion 中所有协议都支持 block-based content).
#[derive(Debug, Clone, PartialEq)]
pub enum IrBlock {
    /// 文本块.
    Text { text: String },
    /// 工具调用 (assistant 发起).
    /// `id` 必须 verbatim 透传, 否则下一轮 tool_result 引用断裂.
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    /// 工具结果 (user 回复 assistant 的 ToolUse).
    /// OpenAI 用独立 `role:"tool"` 消息承载; Anthropic 用 user 消息内的 tool_result 块.
    ToolResult {
        tool_use_id: String,
        content: Vec<IrBlock>,
        is_error: bool,
        /// wire 形态元数据: Anthropic tool_result.content 可能是 string 或 array.
        /// OpenAI 的 tool message content 永远是 string, 此字段 None.
        /// 同协议 round-trip 时填充, 跨协议翻译前清空.
        content_form: Option<ContentForm>,
    },
    /// 图片块. 跨协议唯一无歧义形式是 Base64; URL 引用也保留.
    Image { source: IrImageSource },
    /// 推理块 (Responses API 的 `reasoning` output item).
    ///
    /// 仅承载 `summary` 文本数组 (可被 Redact 扫描是否有 secret 子串).
    /// `encrypted_content` 是 provider-specific opaque blob, **当前实现不保留**
    /// (同协议 round-trip 也会丢失); 这会破坏依赖 reasoning chain 的链式调用
    /// (如 `previous_response_id` + reasoning context compression). 这是已知限制.
    Reasoning { summary: Vec<String> },
}

/// 图片来源 (跨协议中立的图片表达).
#[derive(Debug, Clone, PartialEq)]
pub enum IrImageSource {
    /// 内联 base64 字节 + 真实 MIME type ("image/png" 等).
    Base64 { media_type: String, data: String },
    /// 远程图片 URL (OpenAI `image_url.url` https://...; Anthropic `source.url`).
    Url(String),
}

/// 工具定义.
#[derive(Debug, Clone, PartialEq)]
pub struct IrTool {
    pub name: String,
    pub description: Option<String>,
    /// JSON Schema 描述工具参数.
    pub input_schema: Value,
}

/// 工具选择策略. 取并集: 每个协议都能表达这 4 种.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrToolChoice {
    /// 模型自主决定是否调用工具 (默认).
    Auto,
    /// 模型必须不调用工具 (仅生成文本).
    None,
    /// 模型必须调用某个工具 (任意).
    /// OpenAI `"required"`; Anthropic `{type:"any"}`.
    Required,
    /// 模型必须调用指定名称的工具.
    /// OpenAI `{type:"function",function:{name}}`; Anthropic `{type:"tool",name}`.
    Tool { name: String },
}

// ─── 响应侧 (非流式) ───────────────────────────────────────────────────────

/// 协议无关的非流式 chat completion 响应.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrResponse {
    /// assistant 回复的内容块.
    pub content: Vec<IrBlock>,
    /// 终止原因. 同协议时 verbatim 透传; 跨协议时 enum→enum 映射.
    pub stop_reason: Option<IrStopReason>,
    /// 命中的停止序列 (若有). 跨协议保留.
    pub stop_sequence: Option<String>,
    /// token 用量统计.
    pub usage: IrUsage,
    /// 上游实际服务的模型名 (响应里携带).
    pub model: Option<String>,
    /// 响应 id (OpenAI `chatcmpl-...`; Anthropic `msg_...`).
    /// 同协议时透传; 跨协议时置 None, 由 ingress writer 合成本地格式 id.
    pub id: Option<String>,
    /// Unix epoch seconds (OpenAI 携带; Anthropic 不带, OpenAI writer 合成).
    pub created: Option<u64>,
}

/// 协议无关的终止原因. typed enum (无 String payload), 防止 foreign token 跨协议泄漏.
///
/// reader 把无法识别的 native token 映射到 [`Self::Other`]; writer 的 match 是穷举的,
/// 编译器强制新协议覆盖每个 variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrStopReason {
    /// 自然结束 (OpenAI `"stop"`; Anthropic `"end_turn"`).
    EndTurn,
    /// 命中 stop sequence (OpenAI `"stop"` + stop_sequence; Anthropic `"stop_sequence"`).
    StopSequence,
    /// 达到 max_tokens (两协议都 `"max_tokens"`).
    MaxTokens,
    /// 模型调用工具 (OpenAI `"tool_calls"`; Anthropic `"tool_use"`).
    ToolUse,
    /// 内容审核拦截 (OpenAI `"content_filter"`; Anthropic 无直接对应, 通过 error 表达).
    Safety,
    /// 模型拒绝 (Anthropic `"refusal"`; OpenAI 无直接对应).
    Refusal,
    /// 兜底: 任何无法识别的 native token. 防止 foreign 字符串泄漏.
    Other,
}

/// token 用量统计. 归一化为 "未缓存 input + 加性 cache 字段".
///
/// # 归一化约定
///
/// - `input_tokens`: **未缓存** input (OpenAI 的 `prompt_tokens` 含 cached 总和, reader
///   必须 `saturating_sub(cached_tokens)`)
/// - `cache_read_input_tokens`: 命中缓存读取的 input (加性, 不重复计入 input_tokens)
/// - `cache_creation_input_tokens`: 写入缓存的 input (加性)
/// - `output_tokens`: 输出 token 数
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: Option<u64>,
    pub cache_read_input_tokens: Option<u64>,
}

impl IrUsage {
    /// 全零的零值, 用于流式累积的初始值.
    pub fn zero() -> Self {
        Self::default()
    }

    /// 是否所有字段都为零. 用于判断 usage 是否携带有效统计.
    ///
    /// 单一事实来源: 新增字段时只需要更新此方法, 所有 caller 自动生效.
    /// (eg. OpenAI writer 决定是否在 chunk 中附 `usage` 字段;
    /// StreamTranslate post-stop guard 决定是否放行 MessageDelta.)
    pub fn is_zero(&self) -> bool {
        self.input_tokens == 0
            && self.output_tokens == 0
            && self.cache_creation_input_tokens.unwrap_or(0) == 0
            && self.cache_read_input_tokens.unwrap_or(0) == 0
    }

    /// OpenAI 风格的 `prompt_tokens`: 未缓存 input + 命中缓存 + 写入缓存 (饱和加).
    ///
    /// 单一事实来源: IR 归一化约定中 `input_tokens` 仅含未缓存部分, 但 OpenAI wire
    /// 格式的 `prompt_tokens` 含 cached 总和, writer 必须加回.
    /// 集中在此避免多处手算.
    pub fn openai_prompt_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.cache_read_input_tokens.unwrap_or(0))
            .saturating_add(self.cache_creation_input_tokens.unwrap_or(0))
    }

    /// 序列化为 OpenAI wire 格式的 `usage` 对象 (`{prompt_tokens, completion_tokens, total_tokens}`).
    ///
    /// 单一事实来源: 非流式响应与流式 MessageDelta 都用同一个 wire 形态,
    /// 集中在此避免两处手写 JSON shape (新增字段如 `prompt_tokens_details` 时只改一处).
    pub fn openai_usage_json(&self) -> Value {
        let prompt_tokens = self.openai_prompt_tokens();
        json!({
            "prompt_tokens": prompt_tokens,
            "completion_tokens": self.output_tokens,
            "total_tokens": prompt_tokens.saturating_add(self.output_tokens),
        })
    }
}

// ─── 流式侧 ────────────────────────────────────────────────────────────────

/// 协议无关的流式事件. 取 OpenAI 与 Anthropic 流事件类型的并集.
///
/// reader 把 native SSE 事件解析为 [`IrStreamEvent`]; writer 把 [`IrStreamEvent`] 序列化回 native SSE.
/// [`super::stream::StreamTranslate`] 负责 egress reader ⨯ ingress writer 的组合.
#[derive(Debug, Clone, PartialEq)]
pub enum IrStreamEvent {
    /// 流开始. usage 在 Anthropic 流的 `message_start` 携带 input_tokens;
    /// OpenAI 流的 start chunk 总是 `None` (input 在末尾 include_usage chunk).
    MessageStart {
        usage: Option<IrUsage>,
        id: Option<String>,
        created: Option<u64>,
        model: Option<String>,
    },
    /// 内容块开始.
    BlockStart { index: usize, block: IrBlockMeta },
    /// 内容块增量.
    BlockDelta { index: usize, delta: IrDelta },
    /// 内容块结束.
    BlockStop { index: usize },
    /// 流终止前的元数据 (stop_reason + 最终 usage).
    MessageDelta {
        stop_reason: Option<IrStopReason>,
        stop_sequence: Option<String>,
        usage: IrUsage,
    },
    /// 流终止.
    MessageStop,
    /// 流中错误 (上游 SSE `event: error` 或 OpenAI 流内联 `{"error":...}`).
    Error(String),
}

/// 内容块元信息 (BlockStart 携带).
#[derive(Debug, Clone, PartialEq)]
pub enum IrBlockMeta {
    Text,
    ToolUse { id: String, name: String },
}

/// 内容块增量 (BlockDelta 携带).
#[derive(Debug, Clone, PartialEq)]
pub enum IrDelta {
    /// 文本增量.
    TextDelta(String),
    /// 工具调用参数的 JSON 片段 (流式 partial JSON).
    InputJsonDelta(String),
}

/// reader 端的流式解码状态. 用于 OpenAI flat stream 的 block 边界合成.
///
/// Anthropic 流是 1:1 的 (事件自带 block index), 此 state 在 Anthropic reader 中不使用.
#[derive(Debug, Clone, Default)]
pub struct StreamDecodeState {
    /// 是否已发 MessageStart.
    pub started: bool,
    /// 文本块是否已开. OpenAI flat stream 需要合成 `BlockStart{Text}`.
    pub text_block_open: bool,
    /// 文本块在 IR 中的 index (OpenAI 流里 text 与 tool_call 的相对顺序不固定,
    /// 由首次出现位置决定 index).
    pub text_index: Option<usize>,
    /// 已开启的 OpenAI tool_call 索引集合 (OpenAI `tool_calls[].index`).
    pub open_tools: std::collections::BTreeSet<usize>,
    /// 每个 OpenAI tool_call index 在 IR 中对应的 block index.
    /// 必须持久化记录, 不能在 finish 时 recompute — 否则 text 后到会导致 index 偏移.
    pub tool_ir_index: std::collections::BTreeMap<usize, usize>,
}

// ─── IrError ───────────────────────────────────────────────────────────────

/// codec 解析失败时返回的错误. 当前仅承载人类可读消息,
/// 由 caller 决定如何转换为 HTTP 响应.
#[derive(Debug, Clone)]
pub struct IrError {
    pub message: String,
}

impl IrError {
    pub fn new<M: Into<String>>(msg: M) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for IrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IrError {}

// ─── Helper: stop sequences 归一化 ─────────────────────────────────────────

/// 把 native stop 字段 (可能是 string 或 array) 归一化为 `Vec<String>`.
///
/// - 空字符串元素丢弃 (无意义的 stop).
/// - 缺失 / null / 其他类型返回空 Vec (== 省略).
pub fn read_stop_sequences(val: Option<&Value>) -> Vec<String> {
    match val {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_stop_sequences_handles_string_array_empty() {
        assert_eq!(read_stop_sequences(None), Vec::<String>::new());
        assert_eq!(
            read_stop_sequences(Some(&Value::Null)),
            Vec::<String>::new()
        );
        assert_eq!(
            read_stop_sequences(Some(&serde_json::json!("stop1"))),
            vec!["stop1".to_string()]
        );
        assert_eq!(
            read_stop_sequences(Some(&serde_json::json!(["a", "b"]))),
            vec!["a".to_string(), "b".to_string()]
        );
        // 空字符串元素丢弃.
        assert_eq!(
            read_stop_sequences(Some(&serde_json::json!(["", "x", ""]))),
            vec!["x".to_string()]
        );
        // 单个空字符串视为省略.
        assert_eq!(
            read_stop_sequences(Some(&serde_json::json!(""))),
            Vec::<String>::new()
        );
    }

    #[test]
    fn ir_tool_choice_eq() {
        assert_eq!(IrToolChoice::Auto, IrToolChoice::Auto);
        assert_ne!(
            IrToolChoice::Tool { name: "x".into() },
            IrToolChoice::Tool { name: "y".into() }
        );
    }

    // ─── IrUsage::is_zero ──────────────────────────────────────────────
    //
    // is_zero 是多个决策点的 SSOT (openai_writer 决定是否附 usage、StreamTranslate
    // post-stop guard 决定是否放行 MessageDelta). 任何字段非零都应返回 false.
    // 新增字段时只需更新 is_zero 方法本身, 这些测试自动覆盖回归.

    #[test]
    fn ir_usage_is_zero_when_all_fields_zero() {
        // 全零 (含 None cache 字段) → true.
        assert!(IrUsage::zero().is_zero());
        assert!(IrUsage::default().is_zero());
    }

    #[test]
    fn ir_usage_is_zero_when_cache_fields_are_none() {
        // 显式 None 的 cache 字段也算零.
        assert!(
            IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            }
            .is_zero()
        );
    }

    #[test]
    fn ir_usage_is_nonzero_when_input_tokens_nonzero() {
        let u = IrUsage {
            input_tokens: 1,
            ..Default::default()
        };
        assert!(!u.is_zero());
    }

    #[test]
    fn ir_usage_is_nonzero_when_output_tokens_nonzero() {
        let u = IrUsage {
            output_tokens: 1,
            ..Default::default()
        };
        assert!(!u.is_zero());
    }

    #[test]
    fn ir_usage_is_nonzero_when_cache_read_input_tokens_nonzero() {
        let u = IrUsage {
            cache_read_input_tokens: Some(1),
            ..Default::default()
        };
        assert!(!u.is_zero());
    }

    #[test]
    fn ir_usage_is_nonzero_when_cache_creation_input_tokens_nonzero() {
        let u = IrUsage {
            cache_creation_input_tokens: Some(1),
            ..Default::default()
        };
        assert!(!u.is_zero());
    }
}
