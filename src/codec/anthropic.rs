//! Anthropic Messages 的 Reader / Writer.
//!
//! # wire format 参考
//!
//! - 请求: <https://docs.anthropic.com/en/api/messages>
//! - 响应: <https://docs.anthropic.com/en/api/messages>
//! - 流式: <https://docs.anthropic.com/en/api/messages-streaming>
//!
//! # 字段映射要点
//!
//! - `system` 是**顶层字段** (string 或 array of blocks), 不在 `messages[]` 中.
//! - `content` 永远是 array of blocks: text / thinking / tool_use / tool_result / image.
//! - `max_tokens` **必填** (writer 侧若缺失需注入 [`super::DEFAULT_MAX_TOKENS`]).
//! - `temperature` 必须 clamp 到 [0, 1] (writer 侧若超出, log warn 并 clamp).
//! - 流式 1:1 映射到 IR 事件 (`message_start` / `content_block_*` / `message_delta` / `message_stop`).

use serde_json::{Map, Value, json};

use super::{
    DEFAULT_MAX_TOKENS, IrBlock, IrBlockMeta, IrDelta, IrError, IrImageSource, IrMessage,
    IrRequest, IrResponse, IrRole, IrStopReason, IrStreamEvent, IrTool, IrToolChoice, IrUsage,
    Reader, Writer, collect_extra, ir::StreamDecodeState, random_base62,
};

// ─── Reader ────────────────────────────────────────────────────────────────

pub struct AnthropicReader;

impl Reader for AnthropicReader {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn read_request(&self, body: &Value) -> Result<IrRequest, IrError> {
        let obj = body
            .as_object()
            .ok_or_else(|| IrError::new("Anthropic request body must be a JSON object"))?;

        let model = obj
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        // system 顶层 (string 或 array of blocks).
        let system = read_system_field(obj.get("system"));

        let raw_messages = obj
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| IrError::new("Anthropic request must have 'messages' array"))?;

        let messages: Vec<IrMessage> = raw_messages.iter().filter_map(read_message).collect();

        let tools = obj
            .get("tools")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(read_tool_def).collect())
            .unwrap_or_default();

        let max_tokens = obj
            .get("max_tokens")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|&n| n > 0);
        let temperature = obj.get("temperature").and_then(Value::as_f64);
        let top_p = obj.get("top_p").and_then(Value::as_f64);
        let top_k = obj
            .get("top_k")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        let stop = super::ir::read_stop_sequences(obj.get("stop_sequences"));
        let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
        let user = obj
            .get("metadata")
            .and_then(|m| m.get("user_id"))
            .and_then(Value::as_str)
            .map(String::from);

        // tool_choice: object {type, name?, disable_parallel_tool_use?}.
        let (tool_choice, parallel_tool_calls) = obj
            .get("tool_choice")
            .and_then(Value::as_object)
            .map(read_tool_choice)
            .unwrap_or((None, None));

        let extra = collect_extra(
            obj,
            &[
                "model",
                "messages",
                "system",
                "tools",
                "max_tokens",
                "temperature",
                "top_p",
                "top_k",
                "stop_sequences",
                "tool_choice",
                "metadata",
                "stream",
            ],
        );

        Ok(IrRequest {
            system,
            messages,
            tools,
            max_tokens,
            temperature,
            top_p,
            top_k,
            stop,
            tool_choice,
            user,
            parallel_tool_calls,
            stream,
            model,
            extra,
        })
    }

    fn read_response(&self, body: &Value) -> Result<IrResponse, IrError> {
        let obj = body
            .as_object()
            .ok_or_else(|| IrError::new("Anthropic response body must be a JSON object"))?;

        let id = obj.get("id").and_then(Value::as_str).map(String::from);
        let model = obj
            .get("model")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from);
        // Anthropic 响应没有 created 字段.
        let stop_reason = obj
            .get("stop_reason")
            .and_then(Value::as_str)
            .map(read_stop_reason);
        let stop_sequence = obj
            .get("stop_sequence")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from);

        let content = obj
            .get("content")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(read_block).collect())
            .unwrap_or_default();

        let usage = obj
            .get("usage")
            .filter(|v| v.is_object())
            .map(read_usage)
            .unwrap_or_default();

        Ok(IrResponse {
            content,
            stop_reason,
            stop_sequence,
            usage,
            model,
            id,
            created: None,
        })
    }

    fn read_response_events(
        &self,
        event_type: &str,
        data: &Value,
        _state: &mut StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        // Anthropic 流 1:1, 不需要 state (state 由 caller 持有但 ignored).
        match event_type {
            "message_start" => {
                let message = data.get("message");
                let usage = message
                    .and_then(|m| m.get("usage"))
                    .filter(|v| v.is_object())
                    .map(read_usage);
                let id = message
                    .and_then(|m| m.get("id"))
                    .and_then(Value::as_str)
                    .map(String::from);
                let model = message
                    .and_then(|m| m.get("model"))
                    .and_then(Value::as_str)
                    .map(String::from);
                vec![IrStreamEvent::MessageStart {
                    usage,
                    id,
                    created: None, // Anthropic 流不带 created
                    model,
                }]
            }
            "content_block_start" => {
                let index = data
                    .get("index")
                    .and_then(Value::as_u64)
                    .map(|n| (n as usize).min(1023))
                    .unwrap_or(0);
                let block_meta = data
                    .get("content_block")
                    .and_then(Value::as_object)
                    .and_then(|cb| {
                        let ty = cb.get("type").and_then(Value::as_str).unwrap_or("");
                        match ty {
                            "text" => Some(IrBlockMeta::Text),
                            "tool_use" => {
                                let id = cb.get("id").and_then(Value::as_str).unwrap_or("");
                                let name = cb.get("name").and_then(Value::as_str).unwrap_or("");
                                Some(IrBlockMeta::ToolUse {
                                    id: id.to_string(),
                                    name: name.to_string(),
                                })
                            }
                            _ => None, // thinking / image 等不在 MVP
                        }
                    });
                if let Some(block) = block_meta {
                    vec![IrStreamEvent::BlockStart { index, block }]
                } else {
                    Vec::new()
                }
            }
            "content_block_delta" => {
                let index = data
                    .get("index")
                    .and_then(Value::as_u64)
                    .map(|n| (n as usize).min(1023))
                    .unwrap_or(0);
                let delta = data.get("delta").and_then(Value::as_object).and_then(|d| {
                    let ty = d.get("type").and_then(Value::as_str).unwrap_or("");
                    match ty {
                        "text_delta" => d
                            .get("text")
                            .and_then(Value::as_str)
                            .map(|s| IrDelta::TextDelta(s.to_string())),
                        "input_json_delta" => d
                            .get("partial_json")
                            .and_then(Value::as_str)
                            .map(|s| IrDelta::InputJsonDelta(s.to_string())),
                        _ => None, // thinking_delta / signature_delta 不在 MVP
                    }
                });
                if let Some(delta) = delta {
                    vec![IrStreamEvent::BlockDelta { index, delta }]
                } else {
                    Vec::new()
                }
            }
            "content_block_stop" => {
                let index = data
                    .get("index")
                    .and_then(Value::as_u64)
                    .map(|n| (n as usize).min(1023))
                    .unwrap_or(0);
                vec![IrStreamEvent::BlockStop { index }]
            }
            "message_delta" => {
                let delta = data.get("delta");
                let stop_reason = delta
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(Value::as_str)
                    .map(read_stop_reason);
                let stop_sequence = delta
                    .and_then(|d| d.get("stop_sequence"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                // usage 可能缺失 (message_delta 不带 usage 时不能 ?, 否则会丢失 stop_reason).
                let usage = data
                    .get("usage")
                    .filter(|v| v.is_object())
                    .map(read_usage)
                    .unwrap_or_default();
                vec![IrStreamEvent::MessageDelta {
                    stop_reason,
                    stop_sequence,
                    usage,
                }]
            }
            "message_stop" => vec![IrStreamEvent::MessageStop],
            "error" => {
                let msg = data
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("upstream stream error")
                    .to_string();
                vec![IrStreamEvent::Error(msg)]
            }
            _ => Vec::new(), // ping / unknown 事件忽略
        }
    }
}

// ─── Writer ────────────────────────────────────────────────────────────────

pub struct AnthropicWriter;

impl Writer for AnthropicWriter {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn upstream_path(&self) -> &'static str {
        "/v1/messages"
    }

    fn write_request(&self, req: &IrRequest) -> Value {
        let mut out = Map::new();
        out.insert("model".to_string(), Value::String(req.model.clone()));

        // system 字段 (顶层 string 或 array of blocks).
        if !req.system.is_empty() {
            let blocks: Vec<Value> = req
                .system
                .iter()
                .filter_map(|b| match b {
                    IrBlock::Text { text } => Some(json!({"type": "text", "text": text})),
                    _ => None, // 跨协议来源: 非文本 system block 静默 drop
                })
                .collect();
            // 单一 text block 用 string 形式 (更原生).
            if blocks.len() == 1 {
                if let Some(text) = blocks[0].get("text").cloned() {
                    out.insert("system".to_string(), text);
                }
            } else if !blocks.is_empty() {
                out.insert("system".to_string(), Value::Array(blocks));
            }
        }

        // messages: 过滤掉 system 角色 (已在顶层 system 中), 转换其他角色.
        let messages: Vec<Value> = req
            .messages
            .iter()
            .filter(|m| m.role != IrRole::System)
            .map(write_message)
            .collect();
        out.insert("messages".to_string(), Value::Array(messages));

        // max_tokens: Anthropic 必填, 缺失时注入默认值.
        out.insert(
            "max_tokens".to_string(),
            json!(req.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS)),
        );

        if let Some(t) = req.temperature {
            // Anthropic temperature 必须 [0, 1].
            let (clamped, was_clamped) = clamp_temperature(t);
            if was_clamped {
                tracing::warn!(
                    original = t,
                    clamped,
                    "temperature clamped to [0, 1] for Anthropic target"
                );
            }
            out.insert("temperature".to_string(), json!(clamped));
        }
        if let Some(p) = req.top_p {
            out.insert("top_p".to_string(), json!(p));
        }
        if let Some(k) = req.top_k {
            out.insert("top_k".to_string(), json!(k));
        }
        if !req.stop.is_empty() {
            out.insert(
                "stop_sequences".to_string(),
                Value::Array(req.stop.iter().map(|s| Value::String(s.clone())).collect()),
            );
        }
        if req.stream {
            out.insert("stream".to_string(), Value::Bool(true));
        }
        if let Some(u) = &req.user {
            out.insert("metadata".to_string(), json!({"user_id": u}));
        }
        if !req.tools.is_empty() {
            out.insert(
                "tools".to_string(),
                Value::Array(req.tools.iter().map(write_tool_def).collect()),
            );
        }

        // tool_choice (含 disable_parallel_tool_use). Anthropic 在 tools 为空时收到 tool_choice 会 400, 必须gate.
        if !req.tools.is_empty() {
            if let Some(tc) = &req.tool_choice {
                let mut tc_obj = write_tool_choice(tc);
                if let Some(parallel) = req.parallel_tool_calls
                    && let Some(obj) = tc_obj.as_object_mut()
                {
                    obj.insert(
                        "disable_parallel_tool_use".to_string(),
                        json!(!parallel), // 注意取反
                    );
                }
                out.insert("tool_choice".to_string(), tc_obj);
            } else if let Some(parallel) = req.parallel_tool_calls {
                // 没显式 tool_choice 但有 parallel_tool_calls: 用 auto 作为载体.
                let mut tc_obj = json!({"type": "auto"});
                if let Some(obj) = tc_obj.as_object_mut() {
                    obj.insert("disable_parallel_tool_use".to_string(), json!(!parallel));
                }
                out.insert("tool_choice".to_string(), tc_obj);
            }
        }

        // extra: 同协议时透传.
        for (k, v) in &req.extra {
            out.insert(k.clone(), v.clone());
        }
        Value::Object(out)
    }

    fn write_response(&self, resp: &IrResponse) -> Value {
        let content: Vec<Value> = resp.content.iter().filter_map(write_block).collect();

        let mut out = Map::new();
        out.insert(
            "id".to_string(),
            Value::String(resp.id.clone().unwrap_or_else(synth_id)),
        );
        out.insert("type".to_string(), json!("message"));
        out.insert("role".to_string(), json!("assistant"));
        out.insert("content".to_string(), Value::Array(content));
        if let Some(model) = &resp.model {
            out.insert("model".to_string(), Value::String(model.clone()));
        }
        out.insert(
            "stop_reason".to_string(),
            json!(write_stop_reason(resp.stop_reason)),
        );
        // stop_sequence: None → null (Anthropic 总是携带此字段).
        out.insert(
            "stop_sequence".to_string(),
            resp.stop_sequence
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        out.insert("usage".to_string(), write_usage(&resp.usage));
        Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, Value)> {
        match ev {
            IrStreamEvent::MessageStart {
                id, model, usage, ..
            } => {
                let msg_id = id.clone().unwrap_or_else(synth_id);
                let model_str = model.clone().unwrap_or_default();
                let mut message = Map::new();
                message.insert("id".to_string(), Value::String(msg_id));
                message.insert("type".to_string(), json!("message"));
                message.insert("role".to_string(), json!("assistant"));
                message.insert("content".to_string(), json!([]));
                message.insert("model".to_string(), Value::String(model_str));
                message.insert("stop_reason".to_string(), Value::Null);
                message.insert("stop_sequence".to_string(), Value::Null);
                message.insert(
                    "usage".to_string(),
                    write_usage(usage.as_ref().unwrap_or(&IrUsage::zero())),
                );
                Some((
                    "message_start".to_string(),
                    json!({"type": "message_start", "message": Value::Object(message)}),
                ))
            }
            IrStreamEvent::BlockStart { index, block } => match block {
                IrBlockMeta::Text => Some((
                    "content_block_start".to_string(),
                    json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {"type": "text", "text": ""}
                    }),
                )),
                IrBlockMeta::ToolUse { id, name } => Some((
                    "content_block_start".to_string(),
                    json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "tool_use",
                            "id": id,
                            "name": name,
                            "input": {},
                        }
                    }),
                )),
            },
            IrStreamEvent::BlockDelta { index, delta } => match delta {
                IrDelta::TextDelta(text) => Some((
                    "content_block_delta".to_string(),
                    json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "text_delta", "text": text}
                    }),
                )),
                IrDelta::InputJsonDelta(partial) => Some((
                    "content_block_delta".to_string(),
                    json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "input_json_delta", "partial_json": partial}
                    }),
                )),
            },
            IrStreamEvent::BlockStop { index } => Some((
                "content_block_stop".to_string(),
                json!({"type": "content_block_stop", "index": index}),
            )),
            IrStreamEvent::MessageDelta {
                stop_reason,
                stop_sequence,
                usage,
            } => {
                let mut delta = Map::new();
                delta.insert(
                    "stop_reason".to_string(),
                    json!(write_stop_reason(*stop_reason)),
                );
                delta.insert(
                    "stop_sequence".to_string(),
                    stop_sequence
                        .clone()
                        .map(Value::String)
                        .unwrap_or(Value::Null),
                );
                Some((
                    "message_delta".to_string(),
                    json!({
                        "type": "message_delta",
                        "delta": Value::Object(delta),
                        "usage": write_usage(usage),
                    }),
                ))
            }
            IrStreamEvent::MessageStop => {
                Some(("message_stop".to_string(), json!({"type": "message_stop"})))
            }
            IrStreamEvent::Error(msg) => Some((
                "error".to_string(),
                json!({
                    "type": "error",
                    "error": {"type": "upstream_error", "message": msg}
                }),
            )),
        }
    }

    fn requires_max_tokens(&self) -> bool {
        true
    }

    fn write_error(&self, _status: u16, kind: &str, message: &str) -> Value {
        // Anthropic 错误 envelope: {type:"error", error:{type, message}}.
        json!({
            "type": "error",
            "error": {"type": kind, "message": message}
        })
    }
}

// ─── Helpers: read ─────────────────────────────────────────────────────────

/// 解析 Anthropic 顶层 system 字段 (string 或 array of blocks).
fn read_system_field(val: Option<&Value>) -> Vec<IrBlock> {
    let Some(val) = val else {
        return Vec::new();
    };
    match val {
        Value::String(s) => {
            if s.is_empty() {
                Vec::new()
            } else {
                vec![IrBlock::Text { text: s.clone() }]
            }
        }
        Value::Array(arr) => arr.iter().filter_map(read_block).collect(),
        _ => Vec::new(),
    }
}

/// 解析 Anthropic 单个消息.
fn read_message(msg: &Value) -> Option<IrMessage> {
    let obj = msg.as_object()?;
    let role_str = obj.get("role").and_then(Value::as_str).unwrap_or("user");
    let role = match role_str {
        "system" => IrRole::System,
        "assistant" => IrRole::Assistant,
        _ => IrRole::User, // "user" 或未知
    };
    let content = match obj.get("content") {
        Some(Value::String(s)) => {
            if s.is_empty() {
                Vec::new()
            } else {
                vec![IrBlock::Text { text: s.clone() }]
            }
        }
        Some(Value::Array(arr)) => arr.iter().filter_map(read_block).collect(),
        _ => Vec::new(),
    };
    Some(IrMessage { role, content })
}

/// 解析 Anthropic content block → [`IrBlock`].
fn read_block(b: &Value) -> Option<IrBlock> {
    let obj = b.as_object()?;
    let ty = obj.get("type").and_then(Value::as_str)?;
    match ty {
        "text" => {
            let text = obj.get("text").and_then(Value::as_str).unwrap_or("");
            if text.is_empty() {
                None
            } else {
                Some(IrBlock::Text {
                    text: text.to_string(),
                })
            }
        }
        "tool_use" => {
            let id = obj
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let name = obj
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let input = obj
                .get("input")
                .cloned()
                .unwrap_or(Value::Object(Map::new()));
            if name.is_empty() {
                None
            } else {
                Some(IrBlock::ToolUse { id, name, input })
            }
        }
        "tool_result" => {
            let tool_use_id = obj
                .get("tool_use_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let is_error = obj
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            // content 可能是 string 或 array of blocks.
            let content = match obj.get("content") {
                Some(Value::String(s)) => {
                    if s.is_empty() {
                        Vec::new()
                    } else {
                        vec![IrBlock::Text { text: s.clone() }]
                    }
                }
                Some(Value::Array(arr)) => arr.iter().filter_map(read_block).collect(),
                _ => Vec::new(),
            };
            Some(IrBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            })
        }
        "image" => {
            let source = obj.get("source").and_then(Value::as_object)?;
            let src_type = source.get("type").and_then(Value::as_str).unwrap_or("");
            let image_source = match src_type {
                "base64" => {
                    let media_type = source
                        .get("media_type")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let data = source
                        .get("data")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    IrImageSource::Base64 { media_type, data }
                }
                "url" => {
                    let url = source
                        .get("url")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    IrImageSource::Url(url)
                }
                _ => return None,
            };
            Some(IrBlock::Image {
                source: image_source,
            })
        }
        _ => None, // thinking / redacted_thinking 等不在 MVP
    }
}

/// 解析 Anthropic tool 定义 (顶层 name/description/input_schema).
fn read_tool_def(tool: &Value) -> Option<IrTool> {
    let name = tool
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return None;
    }
    let description = tool
        .get("description")
        .and_then(Value::as_str)
        .map(String::from);
    let input_schema = tool
        .get("input_schema")
        .cloned()
        .unwrap_or(Value::Object(Map::new()));
    Some(IrTool {
        name,
        description,
        input_schema,
    })
}

/// 解析 Anthropic tool_choice → (IrToolChoice, Option<bool> parallel_tool_calls).
/// 注意 disable_parallel_tool_use 的取反.
fn read_tool_choice(obj: &Map<String, Value>) -> (Option<IrToolChoice>, Option<bool>) {
    let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
    let tc = match ty {
        "auto" => Some(IrToolChoice::Auto),
        "none" => Some(IrToolChoice::None),
        "any" => Some(IrToolChoice::Required),
        "tool" => {
            let name = obj
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                Some(IrToolChoice::Required)
            } else {
                Some(IrToolChoice::Tool { name })
            }
        }
        _ => Some(IrToolChoice::Auto),
    };
    let parallel = obj
        .get("disable_parallel_tool_use")
        .and_then(Value::as_bool)
        .map(|disabled| !disabled); // 取反
    (tc, parallel)
}

/// Anthropic `stop_reason` → [`IrStopReason`].
fn read_stop_reason(s: &str) -> IrStopReason {
    match s {
        "end_turn" => IrStopReason::EndTurn,
        "max_tokens" => IrStopReason::MaxTokens,
        "stop_sequence" => IrStopReason::StopSequence,
        "tool_use" => IrStopReason::ToolUse,
        "refusal" => IrStopReason::Refusal,
        _ => IrStopReason::Other,
    }
}

/// Anthropic usage 对象 → [`IrUsage`]. Anthropic 的 input_tokens 本来就是未缓存.
fn read_usage(usage: &Value) -> IrUsage {
    IrUsage {
        input_tokens: usage
            .get("input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens: usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_creation_input_tokens: usage
            .get("cache_creation_input_tokens")
            .and_then(Value::as_u64),
        cache_read_input_tokens: usage.get("cache_read_input_tokens").and_then(Value::as_u64),
    }
}

// ─── Helpers: write ────────────────────────────────────────────────────────

/// IR message → Anthropic wire message.
fn write_message(msg: &IrMessage) -> Value {
    let role_str = match msg.role {
        IrRole::System => "user", // 防御性: 理论上 system 已在顶层, 不应走到这里
        IrRole::Assistant => "assistant",
        IrRole::User => "user",
        IrRole::Tool => "user", // tool 消息在 Anthropic 中也是 user
    };
    let blocks: Vec<Value> = msg.content.iter().filter_map(write_block).collect();
    json!({"role": role_str, "content": blocks})
}

/// IR block → Anthropic content block (用于 message 数组内).
fn write_block(b: &IrBlock) -> Option<Value> {
    match b {
        IrBlock::Text { text } => Some(json!({"type": "text", "text": text})),
        IrBlock::ToolUse { id, name, input } => Some(json!({
            "type": "tool_use",
            "id": id,
            "name": name,
            "input": input,
        })),
        IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => {
            // tool_result 内的 content 是 array of blocks.
            let inner: Vec<Value> = content.iter().filter_map(write_block).collect();
            let mut obj = Map::new();
            obj.insert("type".to_string(), json!("tool_result"));
            obj.insert(
                "tool_use_id".to_string(),
                Value::String(tool_use_id.clone()),
            );
            if !inner.is_empty() {
                obj.insert("content".to_string(), Value::Array(inner));
            }
            if *is_error {
                obj.insert("is_error".to_string(), json!(true));
            }
            Some(Value::Object(obj))
        }
        IrBlock::Image { source } => {
            let src = match source {
                IrImageSource::Base64 { media_type, data } => json!({
                    "type": "base64",
                    "media_type": media_type,
                    "data": data,
                }),
                IrImageSource::Url(url) => json!({
                    "type": "url",
                    "url": url,
                }),
            };
            Some(json!({"type": "image", "source": src}))
        }
    }
}

/// 写 tool 定义 (Anthropic 顶层 name/description/input_schema).
fn write_tool_def(tool: &IrTool) -> Value {
    let mut obj = Map::new();
    obj.insert("name".to_string(), Value::String(tool.name.clone()));
    if let Some(desc) = &tool.description {
        obj.insert("description".to_string(), Value::String(desc.clone()));
    }
    obj.insert("input_schema".to_string(), tool.input_schema.clone());
    Value::Object(obj)
}

/// 写 tool_choice (Anthropic 风格 object).
fn write_tool_choice(tc: &IrToolChoice) -> Value {
    match tc {
        IrToolChoice::Auto => json!({"type": "auto"}),
        IrToolChoice::None => json!({"type": "none"}),
        IrToolChoice::Required => json!({"type": "any"}),
        IrToolChoice::Tool { name } => json!({"type": "tool", "name": name}),
    }
}

/// [`IrStopReason`] → Anthropic `stop_reason` 字符串.
fn write_stop_reason(reason: Option<IrStopReason>) -> String {
    match reason {
        Some(IrStopReason::EndTurn) => "end_turn".to_string(),
        Some(IrStopReason::StopSequence) => "stop_sequence".to_string(),
        Some(IrStopReason::MaxTokens) => "max_tokens".to_string(),
        Some(IrStopReason::ToolUse) => "tool_use".to_string(),
        Some(IrStopReason::Safety) => "end_turn".to_string(), // Anthropic 无 safety, 用 end_turn
        Some(IrStopReason::Refusal) => "refusal".to_string(),
        Some(IrStopReason::Other) | None => "end_turn".to_string(),
    }
}

/// 写 usage 对象.
fn write_usage(u: &IrUsage) -> Value {
    let mut obj = Map::new();
    obj.insert("input_tokens".to_string(), json!(u.input_tokens));
    obj.insert("output_tokens".to_string(), json!(u.output_tokens));
    if let Some(c) = u.cache_creation_input_tokens {
        obj.insert("cache_creation_input_tokens".to_string(), json!(c));
    }
    if let Some(c) = u.cache_read_input_tokens {
        obj.insert("cache_read_input_tokens".to_string(), json!(c));
    }
    Value::Object(obj)
}

/// Clamp temperature 到 [0, 1], 返回 (clamped, was_clamped).
fn clamp_temperature(t: f64) -> (f64, bool) {
    if !t.is_finite() {
        return (t, false);
    }
    let c = t.clamp(0.0, 1.0);
    (c, c != t)
}

/// 合成 Anthropic 格式的 id.
fn synth_id() -> String {
    format!("msg_01{}", random_base62(22))
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn reader() -> AnthropicReader {
        AnthropicReader
    }
    fn writer() -> AnthropicWriter {
        AnthropicWriter
    }

    // ─── read_request ──────────────────────────────────────────────────

    #[test]
    fn read_request_basic() {
        let body = json!({
            "model": "claude-3-5-sonnet-20241022",
            "system": "You are helpful.",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 100,
            "temperature": 0.5,
            "top_k": 40,
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.model, "claude-3-5-sonnet-20241022");
        assert_eq!(ir.system.len(), 1);
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(ir.max_tokens, Some(100));
        assert_eq!(ir.temperature, Some(0.5));
        assert_eq!(ir.top_k, Some(40));
    }

    #[test]
    fn read_request_system_array_of_blocks() {
        let body = json!({
            "model": "claude",
            "messages": [{"role": "user", "content": "hi"}],
            "system": [
                {"type": "text", "text": "rule 1"},
                {"type": "text", "text": "rule 2"},
            ],
            "max_tokens": 10
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.system.len(), 2);
    }

    #[test]
    fn read_request_tool_use_block() {
        let body = json!({
            "model": "claude",
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "id": "toolu_abc",
                    "name": "search",
                    "input": {"q": "rust"}
                }]
            }],
            "max_tokens": 100,
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.messages[0].content.len(), 1);
        match &ir.messages[0].content[0] {
            IrBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_abc");
                assert_eq!(name, "search");
                assert_eq!(input, &json!({"q": "rust"}));
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn read_request_tool_result_block() {
        let body = json!({
            "model": "claude",
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": "toolu_abc",
                    "content": [{"type": "text", "text": "result"}]
                }]
            }],
            "max_tokens": 10
        });
        let ir = reader().read_request(&body).unwrap();
        match &ir.messages[0].content[0] {
            IrBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => {
                assert_eq!(tool_use_id, "toolu_abc");
                assert_eq!(*is_error, false);
                assert_eq!(content.len(), 1);
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    #[test]
    fn read_request_tool_choice_disable_parallel_extraction() {
        let body = json!({
            "model": "claude",
            "messages": [{"role": "user", "content": "x"}],
            "max_tokens": 10,
            "tool_choice": {"type": "auto", "disable_parallel_tool_use": true}
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.tool_choice, Some(IrToolChoice::Auto));
        // disable_parallel_tool_use=true → parallel_tool_calls=false (取反).
        assert_eq!(ir.parallel_tool_calls, Some(false));
    }

    // ─── read_response ─────────────────────────────────────────────────

    #[test]
    fn read_response_basic() {
        let body = json!({
            "id": "msg_01abc",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hi there!"}],
            "model": "claude",
            "stop_reason": "end_turn",
            "stop_sequence": Value::Null,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        });
        let ir = reader().read_response(&body).unwrap();
        assert_eq!(ir.id.as_deref(), Some("msg_01abc"));
        assert_eq!(ir.stop_reason, Some(IrStopReason::EndTurn));
        assert_eq!(ir.usage.input_tokens, 10);
        assert_eq!(ir.usage.output_tokens, 5);
        match &ir.content[0] {
            IrBlock::Text { text } => assert_eq!(text, "Hi there!"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn read_response_stop_reason_variants() {
        let cases = [
            ("end_turn", IrStopReason::EndTurn),
            ("max_tokens", IrStopReason::MaxTokens),
            ("stop_sequence", IrStopReason::StopSequence),
            ("tool_use", IrStopReason::ToolUse),
            ("refusal", IrStopReason::Refusal),
            ("weird_token", IrStopReason::Other),
        ];
        for (s, expected) in cases {
            let body = json!({
                "id": "x", "model": "claude",
                "content": [], "stop_reason": s,
                "usage": {"input_tokens": 0, "output_tokens": 0}
            });
            let ir = reader().read_response(&body).unwrap();
            assert_eq!(ir.stop_reason, Some(expected), "for stop_reason={s}");
        }
    }

    // ─── write_request ─────────────────────────────────────────────────

    #[test]
    fn write_request_system_at_top_level() {
        let ir = IrRequest {
            system: vec![IrBlock::Text {
                text: "Be helpful".into(),
            }],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text { text: "Hi".into() }],
            }],
            model: "claude".into(),
            max_tokens: Some(50),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        // 单一 text block system 用 string 形式.
        assert_eq!(v.get("system").unwrap(), "Be helpful");
        let messages = v.get("messages").unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].get("role").unwrap(), "user");
    }

    #[test]
    fn write_request_injects_max_tokens_when_missing() {
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text { text: "x".into() }],
            }],
            model: "claude".into(),
            max_tokens: None,
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        assert_eq!(v.get("max_tokens").unwrap(), DEFAULT_MAX_TOKENS);
    }

    #[test]
    fn write_request_temperature_clamped() {
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text { text: "x".into() }],
            }],
            model: "claude".into(),
            temperature: Some(1.5),
            max_tokens: Some(50),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        assert_eq!(v.get("temperature").unwrap(), 1.0);
    }

    #[test]
    fn write_request_parallel_tool_calls_translates_to_disable_flag() {
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text { text: "x".into() }],
            }],
            model: "claude".into(),
            max_tokens: Some(50),
            parallel_tool_calls: Some(false),
            tool_choice: Some(IrToolChoice::Auto),
            tools: vec![IrTool {
                name: "w".into(),
                description: None,
                input_schema: json!({"type": "object"}),
            }],
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        let tc = v.get("tool_choice").unwrap();
        // parallel_tool_calls=false → disable_parallel_tool_use=true.
        assert_eq!(tc.get("disable_parallel_tool_use").unwrap(), true);
    }

    #[test]
    fn write_request_parallel_tool_calls_omitted_when_tools_empty() {
        // 修复 M2: tools 为空时 tool_choice 不应被写入 (Anthropic 会 400).
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text { text: "x".into() }],
            }],
            model: "claude".into(),
            max_tokens: Some(50),
            parallel_tool_calls: Some(true), // 即使客户端发了
            tool_choice: Some(IrToolChoice::Auto),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        assert!(
            v.get("tool_choice").is_none(),
            "must omit tool_choice when tools is empty (Anthropic would 400)"
        );
    }

    // ─── write_response ────────────────────────────────────────────────

    #[test]
    fn write_response_envelope_shape() {
        let ir = IrResponse {
            content: vec![IrBlock::Text { text: "Hi".into() }],
            stop_reason: Some(IrStopReason::EndTurn),
            usage: IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            },
            model: Some("claude".into()),
            id: Some("msg_01x".into()),
            created: None,
            stop_sequence: None,
        };
        let v = writer().write_response(&ir);
        assert_eq!(v.get("type").unwrap(), "message");
        assert_eq!(v.get("role").unwrap(), "assistant");
        assert_eq!(v.get("stop_reason").unwrap(), "end_turn");
        assert_eq!(v.get("id").unwrap(), "msg_01x");
        let usage = v.get("usage").unwrap();
        assert_eq!(usage.get("input_tokens").unwrap(), 10);
    }

    #[test]
    fn write_response_synthesizes_id_when_missing() {
        let ir = IrResponse {
            content: vec![IrBlock::Text { text: "Hi".into() }],
            stop_reason: Some(IrStopReason::EndTurn),
            usage: IrUsage::default(),
            model: Some("claude".into()),
            id: None,
            created: None,
            stop_sequence: None,
        };
        let v = writer().write_response(&ir);
        let id = v.get("id").unwrap().as_str().unwrap();
        assert!(
            id.starts_with("msg_01"),
            "synth id must start with msg_01, got {id}"
        );
    }

    // ─── round-trip ────────────────────────────────────────────────────

    #[test]
    fn round_trip_request_with_tools_and_tool_use() {
        let original = json!({
            "model": "claude",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "weather?"}]},
                {"role": "assistant", "content": [{
                    "type": "tool_use", "id": "toolu_1",
                    "name": "get_weather", "input": {"city": "SF"}
                }]},
                {"role": "user", "content": [{
                    "type": "tool_result", "tool_use_id": "toolu_1",
                    "content": [{"type": "text", "text": "Sunny"}]
                }]},
            ],
            "tools": [{
                "name": "get_weather",
                "description": "Get weather",
                "input_schema": {"type": "object", "properties": {}}
            }],
            "tool_choice": {"type": "auto"},
            "max_tokens": 100,
        });
        let ir = reader().read_request(&original).unwrap();
        let rewritten = writer().write_request(&ir);
        let ir2 = reader().read_request(&rewritten).unwrap();
        // round-trip 应等价 (除字段顺序).
        assert_eq!(ir, ir2);
    }

    #[test]
    fn round_trip_response_with_tool_use() {
        let original = json!({
            "id": "msg_01x",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Let me check."},
                {"type": "tool_use", "id": "toolu_1", "name": "w", "input": {"q": "sf"}},
            ],
            "model": "claude",
            "stop_reason": "tool_use",
            "stop_sequence": Value::Null,
            "usage": {"input_tokens": 10, "output_tokens": 20},
        });
        let ir = reader().read_response(&original).unwrap();
        let rewritten = writer().write_response(&ir);
        let ir2 = reader().read_response(&rewritten).unwrap();
        assert_eq!(ir, ir2);
    }

    // ─── stream 1:1 mapping ────────────────────────────────────────────

    #[test]
    fn stream_message_start_1to1() {
        let data = json!({
            "type": "message_start",
            "message": {
                "id": "msg_01x",
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": "claude",
                "stop_reason": Value::Null,
                "stop_sequence": Value::Null,
                "usage": {"input_tokens": 10, "output_tokens": 1}
            }
        });
        let mut state = StreamDecodeState::default();
        let events = reader().read_response_events("message_start", &data, &mut state);
        assert_eq!(events.len(), 1);
        match &events[0] {
            IrStreamEvent::MessageStart {
                id, model, usage, ..
            } => {
                assert_eq!(id.as_deref(), Some("msg_01x"));
                assert_eq!(model.as_deref(), Some("claude"));
                assert_eq!(usage.as_ref().unwrap().input_tokens, 10);
            }
            other => panic!("expected MessageStart, got {other:?}"),
        }
    }

    #[test]
    fn stream_content_block_start_tool_use_1to1() {
        let data = json!({
            "type": "content_block_start",
            "index": 1,
            "content_block": {"type": "tool_use", "id": "toolu_x", "name": "w", "input": {}}
        });
        let mut state = StreamDecodeState::default();
        let events = reader().read_response_events("content_block_start", &data, &mut state);
        assert_eq!(events.len(), 1);
        match &events[0] {
            IrStreamEvent::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { id, name },
            } => {
                assert_eq!(*index, 1);
                assert_eq!(id, "toolu_x");
                assert_eq!(name, "w");
            }
            other => panic!("expected BlockStart ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn stream_message_delta_usage_missing_does_not_lose_stop_reason() {
        let data = json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": Value::Null}
            // 故意没有 usage
        });
        let mut state = StreamDecodeState::default();
        let events = reader().read_response_events("message_delta", &data, &mut state);
        assert_eq!(events.len(), 1);
        match &events[0] {
            IrStreamEvent::MessageDelta {
                stop_reason, usage, ..
            } => {
                assert_eq!(*stop_reason, Some(IrStopReason::EndTurn));
                assert_eq!(usage.input_tokens, 0); // zero default
            }
            other => panic!("expected MessageDelta, got {other:?}"),
        }
    }

    #[test]
    fn stream_ping_ignored() {
        let data = json!({"type": "ping"});
        let mut state = StreamDecodeState::default();
        let events = reader().read_response_events("ping", &data, &mut state);
        assert!(events.is_empty());
    }
}
