//! OpenAI Chat Completions 的 Reader / Writer.
//!
//! # wire format 参考
//!
//! - 请求: <https://platform.openai.com/docs/api-reference/chat/create>
//! - 响应: <https://platform.openai.com/docs/api-reference/chat/object>
//! - 流式: <https://platform.openai.com/docs/api-reference/chat/streaming>
//!
//! # 字段映射要点
//!
//! - `system` 消息在 `messages[].role=="system"` 中, 可出现在任意位置 (reader 提升到 [`IrRequest::system`]).
//! - assistant 的工具调用在 `tool_calls[]` 顶层字段 (不在 content 里); tool 结果在独立 `role:"tool"` 消息中.
//! - `max_tokens` 和 `max_completion_tokens` 都映射到 [`IrRequest::max_tokens`] (后者是 o1/o3 reasoning 模型用).
//! - 流式 chunk `choices[0].delta` 是 flat 的 (text / tool_calls / reasoning_content 同时可能出现), 需要 [`StreamDecodeState`] 合成 block 边界.

use serde_json::{json, Map, Value};

use super::{
    collect_extra, ir::StreamDecodeState, random_base62, IrBlock, IrBlockMeta, IrDelta, IrError,
    IrImageSource, IrMessage, IrRequest, IrResponse, IrRole, IrStopReason, IrStreamEvent, IrTool,
    IrToolChoice, IrUsage, Reader, Writer,
};

// ─── Reader ────────────────────────────────────────────────────────────────

pub struct OpenAiReader;

impl Reader for OpenAiReader {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn read_request(&self, body: &Value) -> Result<IrRequest, IrError> {
        let obj = body
            .as_object()
            .ok_or_else(|| IrError::new("OpenAI request body must be a JSON object"))?;

        let model = obj
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let messages = obj
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| IrError::new("OpenAI request must have 'messages' array"))?;

        let mut system: Vec<IrBlock> = Vec::new();
        let mut ir_messages: Vec<IrMessage> = Vec::new();

        for msg in messages {
            let role_str = msg.get("role").and_then(Value::as_str).unwrap_or("user");
            let role = match role_str {
                "system" | "developer" => IrRole::System, // reasoning 模型用 "developer"
                "assistant" => IrRole::Assistant,
                "tool" => IrRole::Tool,
                _ => IrRole::User, // 默认 user, 防御性兜底
            };

            // 先把 content 解析成 blocks (content 可能是 string 或 array).
            let content_blocks = read_openai_content(msg.get("content"));

            // assistant 消息可能有 tool_calls (顶层字段, 不在 content 里).
            let mut blocks = content_blocks;
            if let Some(tool_calls) = msg.get("tool_calls").and_then(Value::as_array) {
                for tc in tool_calls {
                    if let Some(block) = read_tool_call(tc) {
                        blocks.push(block);
                    }
                }
            }

            // role=="tool" 的消息: tool_call_id (顶层) + content → ToolResult 块.
            if role == IrRole::Tool {
                let tool_use_id = msg
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                // 把 content blocks 包成 ToolResult.
                if !blocks.is_empty() {
                    ir_messages.push(IrMessage {
                        role: IrRole::User, // OpenAI 的 tool 消息在 Anthropic 中是 user 的 tool_result 块
                        content: vec![IrBlock::ToolResult {
                            tool_use_id,
                            content: blocks,
                            is_error: false,
                        }],
                    });
                }
                continue;
            }

            let message = IrMessage {
                role,
                content: blocks,
            };
            if role == IrRole::System {
                // 提升到 system.
                system.extend(message.content);
            } else {
                ir_messages.push(message);
            }
        }

        // sampling 参数.
        let temperature = obj.get("temperature").and_then(Value::as_f64);
        let top_p = obj.get("top_p").and_then(Value::as_f64);
        let max_tokens = obj
            .get("max_tokens")
            .or_else(|| obj.get("max_completion_tokens"))
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|&n| n > 0);
        let stop = super::ir::read_stop_sequences(obj.get("stop"));
        let user = obj.get("user").and_then(Value::as_str).map(String::from);
        let parallel_tool_calls = obj.get("parallel_tool_calls").and_then(Value::as_bool);
        let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
        let tool_choice = obj.get("tool_choice").and_then(read_tool_choice);

        let tools = obj
            .get("tools")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(read_tool_def).collect())
            .unwrap_or_default();

        // extra: 透传未建模字段 (同协议有效, 跨协议会清空).
        let extra = collect_extra(
            obj,
            &[
                "model",
                "messages",
                "tools",
                "max_tokens",
                "max_completion_tokens",
                "temperature",
                "top_p",
                "top_k",
                "stop",
                "tool_choice",
                "user",
                "parallel_tool_calls",
                "stream",
            ],
        );

        Ok(IrRequest {
            system,
            messages: ir_messages,
            tools,
            max_tokens,
            temperature,
            top_p,
            top_k: None, // OpenAI 没有 top_k
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
            .ok_or_else(|| IrError::new("OpenAI response body must be a JSON object"))?;

        let id = obj.get("id").and_then(Value::as_str).map(String::from);
        let model = obj.get("model").and_then(Value::as_str).map(String::from);
        let created = obj.get("created").and_then(Value::as_u64);

        let choice0 = obj
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .ok_or_else(|| IrError::new("OpenAI response must have at least one choice"))?;

        let message = choice0.get("message");
        let mut blocks = Vec::new();
        if let Some(message) = message {
            // 文本内容: content 可能是 string 或 array of parts.
            blocks.extend(read_openai_content(message.get("content")));
            // 工具调用: tool_calls[].
            if let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array) {
                for tc in tool_calls {
                    if let Some(block) = read_tool_call(tc) {
                        blocks.push(block);
                    }
                }
            }
        }

        let stop_reason = choice0
            .get("finish_reason")
            .and_then(Value::as_str)
            .map(read_stop_reason);

        let usage = obj
            .get("usage")
            .filter(|v| v.is_object())
            .map(read_usage)
            .unwrap_or_default();

        Ok(IrResponse {
            content: blocks,
            stop_reason,
            stop_sequence: None, // OpenAI 非流式响应不显式返回 stop_sequence
            usage,
            model,
            id,
            created,
        })
    }

    fn read_response_events(
        &self,
        _event_type: &str,
        data: &Value,
        state: &mut StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        // OpenAI 流的 event_type 总是 "" (bare `data:`), 忽略.
        read_openai_stream_chunk(data, state)
    }
}

// ─── Writer ────────────────────────────────────────────────────────────────

pub struct OpenAiWriter;

impl Writer for OpenAiWriter {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn upstream_path(&self) -> &'static str {
        "/v1/chat/completions"
    }

    fn write_request(&self, req: &IrRequest) -> Value {
        let mut messages: Vec<Value> = Vec::new();

        // system → messages[0] (若有).
        if !req.system.is_empty() {
            let text = blocks_to_text(&req.system);
            if !text.is_empty() {
                messages.push(json!({"role": "system", "content": text}));
            }
        }

        for msg in &req.messages {
            // OpenAI 把 tool 结果放在独立的 role:"tool" 消息中 (一个 tool_use_id 一条).
            // 当 IR User 消息含 ToolResult 块时 (跨协议从 Anthropic 来, 或混合 Text + ToolResult),
            // 必须拆分: ToolResult 块 → N 个独立 tool 消息; 剩余 Text/Image 块保留为原 user 消息.
            // 否则 ToolUse ↔ ToolResult 的关联会断裂, 上游无法识别工具结果.
            if msg.role == IrRole::User
                && msg
                    .content
                    .iter()
                    .any(|b| matches!(b, IrBlock::ToolResult { .. }))
            {
                let (non_tool, tool_results): (Vec<&IrBlock>, Vec<&IrBlock>) = msg
                    .content
                    .iter()
                    .partition(|b| !matches!(b, IrBlock::ToolResult { .. }));
                if !non_tool.is_empty() {
                    messages.push(write_message(&IrMessage {
                        role: IrRole::User,
                        content: non_tool.into_iter().cloned().collect(),
                    }));
                }
                for b in tool_results {
                    if let IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                    } = b
                    {
                        let text = if *is_error {
                            format!("[error] {}", blocks_to_text(content))
                        } else {
                            blocks_to_text(content)
                        };
                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": tool_use_id,
                            "content": text,
                        }));
                    }
                }
            } else {
                messages.push(write_message(msg));
            }
        }

        let mut out = Map::new();
        out.insert("model".to_string(), Value::String(req.model.clone()));
        out.insert("messages".to_string(), Value::Array(messages));

        if let Some(t) = req.max_tokens {
            out.insert("max_tokens".to_string(), json!(t));
        }
        if let Some(t) = req.temperature {
            out.insert("temperature".to_string(), json!(t));
        }
        if let Some(p) = req.top_p {
            out.insert("top_p".to_string(), json!(p));
        }
        if !req.stop.is_empty() {
            out.insert(
                "stop".to_string(),
                Value::Array(req.stop.iter().map(|s| Value::String(s.clone())).collect()),
            );
        }
        if req.stream {
            out.insert("stream".to_string(), Value::Bool(true));
        }
        if let Some(u) = &req.user {
            out.insert("user".to_string(), Value::String(u.clone()));
        }
        // OpenAI 在 tools 为空时, parallel_tool_calls 会触发 400, 必须 gate.
        if !req.tools.is_empty() {
            out.insert(
                "tools".to_string(),
                Value::Array(req.tools.iter().map(write_tool_def).collect()),
            );
            if let Some(p) = req.parallel_tool_calls {
                out.insert("parallel_tool_calls".to_string(), json!(p));
            }
            if let Some(tc) = &req.tool_choice {
                out.insert("tool_choice".to_string(), write_tool_choice(tc));
            }
        }
        // top_k OpenAI 不支持, 静默 drop (lossy-by-target).
        // extra 同协议时透传 (跨协议在调用前清空).
        for (k, v) in &req.extra {
            out.insert(k.clone(), v.clone());
        }
        Value::Object(out)
    }

    fn write_response(&self, resp: &IrResponse) -> Value {
        let mut message = Map::new();
        message.insert("role".to_string(), json!("assistant"));

        // content 和 tool_calls 分开 (OpenAI assistant 消息结构).
        let mut content_parts: Vec<Value> = Vec::new();
        let mut tool_calls: Vec<Value> = Vec::new();
        for block in &resp.content {
            match block {
                IrBlock::Text { text } => {
                    content_parts.push(Value::String(text.clone()));
                }
                IrBlock::ToolUse { id, name, input } => {
                    tool_calls.push(json!({
                        "id": id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": input_to_string(input),
                        }
                    }));
                }
                IrBlock::ToolResult { .. } => {
                    // 非流式响应里通常不会有 ToolResult (它属于下一轮 user 消息), 跳过.
                }
                IrBlock::Image { .. } => {
                    // assistant 一般不发图片, 跳过 (lossy-by-target).
                }
            }
        }
        // OpenAI content: 若只有文本, 用 string; 否则用 array.
        let content = match content_parts.len() {
            0 => Value::Null,
            1 => content_parts.into_iter().next().unwrap(),
            _ => Value::Array(content_parts),
        };
        message.insert("content".to_string(), content);
        if !tool_calls.is_empty() {
            message.insert("tool_calls".to_string(), Value::Array(tool_calls));
        }

        let mut out = Map::new();
        out.insert(
            "id".to_string(),
            Value::String(resp.id.clone().unwrap_or_else(synth_id)),
        );
        out.insert("object".to_string(), json!("chat.completion"));
        out.insert(
            "created".to_string(),
            json!(resp.created.unwrap_or_else(current_epoch)),
        );
        out.insert(
            "model".to_string(),
            Value::String(resp.model.clone().unwrap_or_default()),
        );
        out.insert(
            "choices".to_string(),
            json!([{
                "index": 0,
                "message": Value::Object(message),
                "finish_reason": write_stop_reason(resp.stop_reason),
            }]),
        );
        // usage 反向归一化: OpenAI prompt_tokens 含 cached, 由 IrUsage 统一序列化 (SSOT).
        out.insert("usage".to_string(), resp.usage.openai_usage_json());
        Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, Value)> {
        let event_type = String::new(); // OpenAI 流用 bare `data:` (无 event: 行).
        let chunk = match ev {
            IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                // 第一个 chunk: role + 元信息.
                json!({
                    "id": id.clone().unwrap_or_else(synth_id),
                    "object": "chat.completion.chunk",
                    "created": created.unwrap_or_else(current_epoch),
                    "model": model.clone().unwrap_or_default(),
                    "choices": [{
                        "index": 0,
                        "delta": {"role": "assistant"},
                        "finish_reason": Value::Null,
                    }],
                })
            }
            IrStreamEvent::BlockStart { block, .. } => match block {
                IrBlockMeta::Text => {
                    // OpenAI 流的 text block start 是隐式的: 第一个 text delta chunk 自带 content.
                    // 这里返回 None 避免发出空 chunk (与 BlockStop 同样跳过).
                    return None;
                }
                IrBlockMeta::ToolUse { id, name } => json!({
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "tool_calls": [{
                                "index": 0,
                                "id": id,
                                "type": "function",
                                "function": {"name": name, "arguments": ""},
                            }]
                        },
                        "finish_reason": Value::Null,
                    }]
                }),
            },
            IrStreamEvent::BlockDelta { delta, .. } => match delta {
                IrDelta::TextDelta(text) => json!({
                    "choices": [{
                        "index": 0,
                        "delta": {"content": text},
                        "finish_reason": Value::Null,
                    }]
                }),
                IrDelta::InputJsonDelta(args) => json!({
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "tool_calls": [{
                                "index": 0,
                                "function": {"arguments": args},
                            }]
                        },
                        "finish_reason": Value::Null,
                    }]
                }),
            },
            IrStreamEvent::BlockStop { .. } => {
                // OpenAI 没有 content_block_stop 的对应 event, 跳过.
                return None;
            }
            IrStreamEvent::MessageDelta {
                stop_reason, usage, ..
            } => {
                // MessageDelta 在 OpenAI wire 上有两种合法形态:
                // 1. 带 stop_reason (finish_reason chunk): `choices:[{delta:{},finish_reason}]`,
                //    若 usage 非零也附在顶层 (合并 chunk 形态, 上游可能这样合并).
                // 2. 仅 usage (OpenAI `stream_options.include_usage` 末尾独立 chunk):
                //    `choices:[]` + 顶层 `usage`. 这是规范格式 (见 OpenAI streaming 文档).
                // 必须把 usage 写回, 否则客户端 (如 opencode) 拿不到 token 统计.
                //
                // 空 delta + 无 usage: 无意义, 跳过.
                let has_usage = !usage.is_zero();
                if stop_reason.is_none() && !has_usage {
                    return None;
                }

                let mut chunk = match stop_reason {
                    Some(_) => json!({
                        "choices": [{
                            "index": 0,
                            "delta": {},
                            "finish_reason": write_stop_reason(*stop_reason),
                        }]
                    }),
                    None => json!({ "choices": [] }),
                };
                if has_usage {
                    chunk["usage"] = usage.openai_usage_json();
                }
                chunk
            }
            IrStreamEvent::MessageStop => {
                // OpenAI 的 message_stop 由 emit_done_terminator 在 finish() 中追加.
                return None;
            }
            IrStreamEvent::Error(msg) => json!({
                "error": {"message": msg, "type": "upstream_error"}
            }),
        };
        Some((event_type, chunk))
    }

    fn emits_sse_done_terminator(&self) -> bool {
        true
    }

    fn write_error(&self, _status: u16, kind: &str, message: &str) -> Value {
        // status 不嵌入 body; 由 HTTP status code 承载.
        json!({
            "error": {
                "message": message,
                "type": kind,
                "code": null,
            }
        })
    }
}

// ─── Helpers: read ─────────────────────────────────────────────────────────

/// 解析 OpenAI 消息的 `content` 字段 (string 或 array of parts).
fn read_openai_content(content: Option<&Value>) -> Vec<IrBlock> {
    let Some(content) = content else {
        return Vec::new();
    };
    match content {
        Value::String(s) => {
            if s.is_empty() {
                Vec::new()
            } else {
                vec![IrBlock::Text { text: s.clone() }]
            }
        }
        Value::Array(arr) => arr.iter().filter_map(read_content_part).collect(),
        // 包括 Value::Null (assistant 调用工具时 content 为 null).
        _ => Vec::new(),
    }
}

/// 解析 content array 中的一个 part (`{type:"text"|"image_url", ...}`).
fn read_content_part(part: &Value) -> Option<IrBlock> {
    let part = part.as_object()?;
    let ty = part.get("type").and_then(Value::as_str)?;
    match ty {
        "text" => {
            let text = part.get("text").and_then(Value::as_str)?;
            if text.is_empty() {
                None
            } else {
                Some(IrBlock::Text {
                    text: text.to_string(),
                })
            }
        }
        "image_url" => {
            let url = part
                .get("image_url")
                .and_then(|v| v.get("url"))
                .and_then(Value::as_str)?;
            Some(IrBlock::Image {
                source: parse_image_url(url),
            })
        }
        _ => None, // 未知类型 (audio 等), 静默 drop.
    }
}

/// 解析 OpenAI 的 tool_call 对象 → ToolUse 块.
fn read_tool_call(tc: &Value) -> Option<IrBlock> {
    let id = tc
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let function = tc.get("function")?;
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let input = function
        .get("arguments")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or(Value::Null);
    if name.is_empty() {
        None
    } else {
        Some(IrBlock::ToolUse { id, name, input })
    }
}

/// 解析 tool_choice (string 或 object).
fn read_tool_choice(val: &Value) -> Option<IrToolChoice> {
    match val {
        Value::String(s) => match s.as_str() {
            "auto" => Some(IrToolChoice::Auto),
            "none" => Some(IrToolChoice::None),
            "required" => Some(IrToolChoice::Required),
            _ => Some(IrToolChoice::Auto), // 未知 string 默认 Auto
        },
        Value::Object(obj) => {
            let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
            match ty {
                "function" => {
                    let name = obj
                        .get("function")
                        .and_then(|f| f.get("name"))
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
            }
        }
        _ => None,
    }
}

/// 解析 tools 数组中的一个 tool 定义.
fn read_tool_def(tool: &Value) -> Option<IrTool> {
    let function = tool.get("function")?;
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return None;
    }
    let description = function
        .get("description")
        .and_then(Value::as_str)
        .map(String::from);
    let input_schema = function
        .get("parameters")
        .cloned()
        .unwrap_or(Value::Object(Map::new()));
    Some(IrTool {
        name,
        description,
        input_schema,
    })
}

/// OpenAI `image_url` 字符串 → [`IrImageSource`].
/// 支持 `data:<mime>;base64,<payload>` URI 和 https:// URL.
fn parse_image_url(url: &str) -> IrImageSource {
    if let Some(rest) = url.strip_prefix("data:") {
        if let Some((meta, payload)) = rest.split_once(',') {
            let media_type = meta.split(';').next().unwrap_or("").to_string();
            if meta.contains("base64") && !media_type.is_empty() {
                return IrImageSource::Base64 {
                    media_type,
                    data: payload.to_string(),
                };
            }
        }
    }
    IrImageSource::Url(url.to_string())
}

/// OpenAI `finish_reason` string → [`IrStopReason`].
fn read_stop_reason(s: &str) -> IrStopReason {
    match s {
        "stop" => IrStopReason::EndTurn,
        "length" => IrStopReason::MaxTokens,
        "tool_calls" | "function_call" => IrStopReason::ToolUse,
        "content_filter" => IrStopReason::Safety,
        _ => IrStopReason::Other,
    }
}

/// OpenAI usage 对象 → [`IrUsage`] (含 cached 归一化).
///
/// OpenAI 的 `prompt_tokens` 是包含 cached 的总和, reader 减去 cached 得到未缓存 input.
fn read_usage(usage: &Value) -> IrUsage {
    let prompt_tokens = usage
        .get("prompt_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cached = usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(Value::as_u64);
    let input_tokens = cached
        .and_then(|c| prompt_tokens.checked_sub(c))
        .unwrap_or(prompt_tokens);
    let output_tokens = usage
        .get("completion_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    IrUsage {
        input_tokens,
        output_tokens,
        cache_read_input_tokens: cached,
        cache_creation_input_tokens: None, // OpenAI 不区分 creation/read
    }
}

/// 分配下一个空闲的 IR block index.
///
/// OpenAI flat stream 允许 text 与 tool_calls 以任意顺序到达. 为了避免 text 与 tool 占用
/// 同一个 index (导致 Anthropic 端 `content_block_start` index 冲突), 每次开新 block
/// 都查询当前已用的最大 index + 1.
fn next_free_block_index(state: &StreamDecodeState) -> usize {
    let mut max = 0;
    if let Some(i) = state.text_index {
        max = max.max(i);
    }
    for &i in state.tool_ir_index.values() {
        max = max.max(i);
    }
    max + 1
}

/// OpenAI 流 chunk → 多个 IR 事件 (fan-out).
///
/// OpenAI flat stream: 一个 chunk 的 `choices[0].delta` 可能同时含 role+content+tool_calls.
/// 需要 state 合成 block 边界 (BlockStart / BlockDelta / BlockStop).
fn read_openai_stream_chunk(data: &Value, state: &mut StreamDecodeState) -> Vec<IrStreamEvent> {
    let mut events = Vec::new();

    let id = data.get("id").and_then(Value::as_str).map(String::from);
    let created = data.get("created").and_then(Value::as_u64);
    let model = data.get("model").and_then(Value::as_str).map(String::from);

    // 1) 首次发 MessageStart.
    if !state.started {
        events.push(IrStreamEvent::MessageStart {
            usage: None, // OpenAI 流的 input usage 在末尾 include_usage chunk
            id,
            created,
            model,
        });
        state.started = true;
    }

    let choices = data.get("choices").and_then(Value::as_array);
    // 末尾的 include_usage chunk: choices 缺失或为空数组 (`choices: []`), 但带 usage.
    // OpenAI `stream_options.include_usage: true` 的末尾 chunk 规范格式是 `choices: []`
    // (空数组而非字段缺失), 二者语义等价, 统一处理: 发出 MessageDelta(usage),
    // 否则 IR writer 不会把 usage 写回客户端 (opencode 等客户端会显示 0 tokens).
    let chunk_usage = data.get("usage").filter(|v| v.is_object()).map(read_usage);
    let choice0 = match choices.and_then(|c| c.first()) {
        None => {
            // choices 缺失或为空数组.
            if let Some(u) = chunk_usage {
                events.push(IrStreamEvent::MessageDelta {
                    stop_reason: None,
                    stop_sequence: None,
                    usage: u,
                });
            }
            return events;
        }
        Some(c) => c,
    };
    let delta = choice0.get("delta");
    let finish_reason = choice0.get("finish_reason").and_then(Value::as_str);

    // 2) 处理 delta 内容.
    if let Some(delta) = delta {
        // 文本 delta.
        if let Some(content) = delta.get("content").and_then(Value::as_str) {
            if !content.is_empty() {
                // 用 next_free_index 分配 (避免与已开 tool 的 index 冲突, 无论顺序).
                let index = if !state.text_block_open {
                    let new_idx = next_free_block_index(state);
                    events.push(IrStreamEvent::BlockStart {
                        index: new_idx,
                        block: IrBlockMeta::Text,
                    });
                    state.text_block_open = true;
                    state.text_index = Some(new_idx);
                    new_idx
                } else {
                    state.text_index.unwrap_or(0)
                };
                events.push(IrStreamEvent::BlockDelta {
                    index,
                    delta: IrDelta::TextDelta(content.to_string()),
                });
            }
        }
        // 工具调用 delta (可能有多个并发).
        if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for tc in tool_calls {
                process_tool_call_delta(tc, state, &mut events);
            }
        }
    }

    // 3) 处理 finish_reason: 关闭所有开着的 block + MessageDelta + MessageStop.
    if let Some(reason) = finish_reason {
        let stop_reason = read_stop_reason(reason);
        // 关闭 text block.
        if state.text_block_open {
            if let Some(idx) = state.text_index {
                events.push(IrStreamEvent::BlockStop { index: idx });
            }
            state.text_block_open = false;
        }
        // 关闭所有 open tools.
        let open_indices: Vec<usize> = state.open_tools.iter().copied().collect();
        for oai_idx in open_indices {
            if let Some(&ir_idx) = state.tool_ir_index.get(&oai_idx) {
                events.push(IrStreamEvent::BlockStop { index: ir_idx });
            }
        }
        state.open_tools.clear();
        state.tool_ir_index.clear();

        events.push(IrStreamEvent::MessageDelta {
            stop_reason: Some(stop_reason),
            stop_sequence: None,
            usage: chunk_usage.unwrap_or_default(),
        });
        events.push(IrStreamEvent::MessageStop);
    } else if let Some(u) = chunk_usage {
        // 中间的 usage chunk (理论上 OpenAI 不会有, 防御性处理).
        events.push(IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: u,
        });
    }

    events
}

/// 处理 OpenAI 流 chunk 的单个 `tool_calls[i]` delta.
fn process_tool_call_delta(
    tc: &Value,
    state: &mut StreamDecodeState,
    events: &mut Vec<IrStreamEvent>,
) {
    let oai_idx = tc
        .get("index")
        .and_then(Value::as_u64)
        .map(|n| (n as usize).min(127)) // clamp 防 u64::MAX panic
        .unwrap_or(0);

    let function = tc.get("function");

    // 首次见到此 tool_call: 发 BlockStart.
    if !state.open_tools.contains(&oai_idx) {
        let id = tc
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let name = function
            .and_then(|f| f.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !name.is_empty() {
            // 用 next_free_index 分配 (避免与已开 text block 的 index 冲突, 无论顺序).
            let ir_idx = next_free_block_index(state);
            events.push(IrStreamEvent::BlockStart {
                index: ir_idx,
                block: IrBlockMeta::ToolUse {
                    id: id.clone(),
                    name: name.clone(),
                },
            });
            state.open_tools.insert(oai_idx);
            state.tool_ir_index.insert(oai_idx, ir_idx);
        }
    }

    // arguments delta.
    if let Some(args) = function
        .and_then(|f| f.get("arguments"))
        .and_then(Value::as_str)
    {
        if !args.is_empty() {
            if let Some(&ir_idx) = state.tool_ir_index.get(&oai_idx) {
                events.push(IrStreamEvent::BlockDelta {
                    index: ir_idx,
                    delta: IrDelta::InputJsonDelta(args.to_string()),
                });
            }
        }
    }
}

// ─── Helpers: write ────────────────────────────────────────────────────────

/// 把 blocks 折叠成单个文本 string (用于 system 消息, OpenAI 不支持 array 形式的 system).
fn blocks_to_text(blocks: &[IrBlock]) -> String {
    let mut s = String::new();
    for b in blocks {
        if let IrBlock::Text { text } = b {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(text);
        }
    }
    s
}

/// IR 消息 → OpenAI wire 消息 (含 tool 消息的特殊处理).
fn write_message(msg: &IrMessage) -> Value {
    match msg.role {
        IrRole::System => {
            let text = blocks_to_text(&msg.content);
            json!({"role": "system", "content": text})
        }
        IrRole::User => {
            // OpenAI 约定: 单文本 content 用裸 string; 多模态 / 多块用 array.
            // 这里检测是否只有单一 Text block, 用 string 形式 (更原生).
            if msg.content.len() == 1 {
                if let IrBlock::Text { text } = &msg.content[0] {
                    return json!({"role": "user", "content": text});
                }
            }
            let parts: Vec<Value> = msg.content.iter().filter_map(write_user_block).collect();
            let content = match parts.len() {
                0 => Value::String(String::new()),
                _ => Value::Array(parts),
            };
            json!({"role": "user", "content": content})
        }
        IrRole::Assistant => {
            let mut content_parts: Vec<Value> = Vec::new();
            let mut tool_calls: Vec<Value> = Vec::new();
            for b in &msg.content {
                match b {
                    IrBlock::Text { text } => {
                        if !text.is_empty() {
                            content_parts.push(Value::String(text.clone()));
                        }
                    }
                    IrBlock::ToolUse { id, name, input } => {
                        tool_calls.push(json!({
                            "id": id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": input_to_string(input),
                            }
                        }));
                    }
                    _ => {}
                }
            }
            let content = match content_parts.len() {
                0 => Value::Null,
                1 => content_parts.into_iter().next().unwrap(),
                _ => Value::Array(content_parts),
            };
            let mut obj = Map::new();
            obj.insert("role".to_string(), json!("assistant"));
            obj.insert("content".to_string(), content);
            if !tool_calls.is_empty() {
                obj.insert("tool_calls".to_string(), Value::Array(tool_calls));
            }
            Value::Object(obj)
        }
        IrRole::Tool => {
            // 单个 ToolResult 块 → 独立 role:"tool" 消息.
            // (这条分支只有当 IR 直接含 Tool 角色时命中; 一般 ToolResult 在 user 消息内.)
            for b in &msg.content {
                if let IrBlock::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } = b
                {
                    let text = blocks_to_text(content);
                    return json!({
                        "role": "tool",
                        "tool_call_id": tool_use_id,
                        "content": text,
                    });
                }
            }
            json!({"role": "tool", "content": ""})
        }
    }
}

/// 写 user 消息的 block (text / image / tool_result).
fn write_user_block(b: &IrBlock) -> Option<Value> {
    match b {
        IrBlock::Text { text } => {
            if text.is_empty() {
                None
            } else {
                Some(json!({"type": "text", "text": text}))
            }
        }
        IrBlock::Image { source } => {
            let url = match source {
                IrImageSource::Url(u) => u.clone(),
                IrImageSource::Base64 { media_type, data } => {
                    format!("data:{media_type};base64,{data}")
                }
            };
            Some(json!({
                "type": "image_url",
                "image_url": {"url": url}
            }))
        }
        IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => {
            // OpenAI 的 tool 消息必须独立成一条, 但 caller 可能把它放在 user 消息内
            // (跨协议从 Anthropic 来的). 这里退化为 text 内容, 配合 write_message 的 Tool 分支
            // 通常不会走到这里.
            let text = if *is_error {
                format!("[error] {}", blocks_to_text(content))
            } else {
                blocks_to_text(content)
            };
            Some(json!({
                "type": "text",
                "text": format!("[tool_result for {}: {}]", tool_use_id, text),
            }))
        }
        IrBlock::ToolUse { .. } => None, // user 消息里通常没有 ToolUse
    }
}

/// IR ToolUse 的 input Value → OpenAI function.arguments 字符串.
fn input_to_string(input: &Value) -> String {
    match input {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        _ => serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string()),
    }
}

/// 写 tool 定义.
fn write_tool_def(tool: &IrTool) -> Value {
    let mut function = Map::new();
    function.insert("name".to_string(), Value::String(tool.name.clone()));
    if let Some(desc) = &tool.description {
        function.insert("description".to_string(), Value::String(desc.clone()));
    }
    function.insert("parameters".to_string(), tool.input_schema.clone());
    json!({"type": "function", "function": Value::Object(function)})
}

/// 写 tool_choice.
fn write_tool_choice(tc: &IrToolChoice) -> Value {
    match tc {
        IrToolChoice::Auto => json!("auto"),
        IrToolChoice::None => json!("none"),
        IrToolChoice::Required => json!("required"),
        IrToolChoice::Tool { name } => json!({
            "type": "function",
            "function": {"name": name}
        }),
    }
}

/// [`IrStopReason`] → OpenAI `finish_reason` 字符串.
fn write_stop_reason(reason: Option<IrStopReason>) -> Value {
    let s = match reason {
        Some(IrStopReason::EndTurn) | Some(IrStopReason::StopSequence) => "stop",
        Some(IrStopReason::MaxTokens) => "length",
        Some(IrStopReason::ToolUse) => "tool_calls",
        Some(IrStopReason::Safety) => "content_filter",
        Some(IrStopReason::Refusal) => "stop", // OpenAI 没有 refusal, 映射到 stop
        Some(IrStopReason::Other) | None => "stop",
    };
    Value::String(s.to_string())
}

/// 合成 OpenAI 格式的 id (若上游没有携带).
fn synth_id() -> String {
    format!("chatcmpl-{}", random_base62(24))
}

/// 当前 Unix epoch seconds.
fn current_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn reader() -> OpenAiReader {
        OpenAiReader
    }
    fn writer() -> OpenAiWriter {
        OpenAiWriter
    }

    // ─── read_request: 基础映射 ──────────────────────────────────────────

    #[test]
    fn read_request_basic_chat() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello"},
            ],
            "max_tokens": 100,
            "temperature": 0.7,
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.model, "gpt-4o");
        assert_eq!(ir.system.len(), 1);
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(ir.max_tokens, Some(100));
        assert_eq!(ir.temperature, Some(0.7));
        assert_eq!(ir.top_p, None);
    }

    #[test]
    fn read_request_system_promotion_from_any_position() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Hi"},
                {"role": "system", "content": "Be nice"},
                {"role": "user", "content": "Bye"},
            ]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.system.len(), 1);
        assert_eq!(ir.messages.len(), 2);
        assert_eq!(ir.messages[0].role, IrRole::User);
        assert_eq!(ir.messages[1].role, IrRole::User);
    }

    #[test]
    fn read_request_max_completion_tokens_recognized() {
        // o1/o3 reasoning 模型用 max_completion_tokens.
        let body = json!({
            "model": "o1",
            "messages": [{"role": "user", "content": "Hi"}],
            "max_completion_tokens": 1000,
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.max_tokens, Some(1000));
    }

    #[test]
    fn read_request_tool_calls_in_assistant_message() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [{
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_abc",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\": \"SF\"}"}
                }]
            }]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(ir.messages[0].content.len(), 1);
        match &ir.messages[0].content[0] {
            IrBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_abc");
                assert_eq!(name, "get_weather");
                assert_eq!(input, &json!({"city": "SF"}));
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn read_request_tool_result_message() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": {"name": "w", "arguments": "{}"}
                }]},
                {"role": "tool", "tool_call_id": "call_1", "content": "Sunny"},
            ]
        });
        let ir = reader().read_request(&body).unwrap();
        // system: 0, user: 1, assistant: 1, tool promoted to user: 1
        assert_eq!(ir.messages.len(), 3);
        // 最后一条是 ToolResult (在 user 消息内).
        let last = &ir.messages[2];
        assert_eq!(last.role, IrRole::User);
        match &last.content[0] {
            IrBlock::ToolResult { tool_use_id, .. } => assert_eq!(tool_use_id, "call_1"),
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    // ─── read_response: 基础映射 ─────────────────────────────────────────

    #[test]
    fn read_response_basic() {
        let body = json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello!"},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            }
        });
        let ir = reader().read_response(&body).unwrap();
        assert_eq!(ir.id.as_deref(), Some("chatcmpl-1"));
        assert_eq!(ir.model.as_deref(), Some("gpt-4o"));
        assert_eq!(ir.created, Some(1700000000));
        assert_eq!(ir.stop_reason, Some(IrStopReason::EndTurn));
        assert_eq!(ir.usage.input_tokens, 10);
        assert_eq!(ir.usage.output_tokens, 5);
        assert_eq!(ir.usage.cache_read_input_tokens, None);
        match &ir.content[0] {
            IrBlock::Text { text } => assert_eq!(text, "Hello!"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn read_response_cached_tokens_normalization() {
        // OpenAI prompt_tokens 含 cached 总和; reader 应减去 cached.
        let body = json!({
            "id": "x", "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 10,
                "prompt_tokens_details": {"cached_tokens": 30},
            }
        });
        let ir = reader().read_response(&body).unwrap();
        assert_eq!(ir.usage.input_tokens, 70, "uncached input = 100 - 30");
        assert_eq!(ir.usage.cache_read_input_tokens, Some(30));
    }

    // ─── write_request: 基础映射 ────────────────────────────────────────

    #[test]
    fn write_request_system_becomes_first_message() {
        let ir = IrRequest {
            system: vec![IrBlock::Text {
                text: "Be nice".into(),
            }],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text { text: "Hi".into() }],
            }],
            model: "gpt-4o".into(),
            max_tokens: Some(50),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        let messages = v.get("messages").unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].get("role").unwrap(), "system");
        assert_eq!(messages[1].get("role").unwrap(), "user");
        assert_eq!(v.get("max_tokens").unwrap(), 50);
    }

    #[test]
    fn write_request_no_parallel_tool_calls_when_tools_empty() {
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text { text: "x".into() }],
            }],
            model: "gpt-4o".into(),
            parallel_tool_calls: Some(true),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        assert!(
            v.get("parallel_tool_calls").is_none(),
            "must omit parallel_tool_calls when tools is empty (OpenAI would 400)"
        );
    }

    // ─── write_response: usage 反向归一化 ───────────────────────────────

    #[test]
    fn write_response_prompt_tokens_adds_cached_back() {
        let ir = IrResponse {
            content: vec![IrBlock::Text { text: "hi".into() }],
            stop_reason: Some(IrStopReason::EndTurn),
            usage: IrUsage {
                input_tokens: 70,
                output_tokens: 10,
                cache_read_input_tokens: Some(30),
                ..Default::default()
            },
            model: Some("gpt-4o".into()),
            id: None,
            created: None,
            stop_sequence: None,
        };
        let v = writer().write_response(&ir);
        let usage = v.get("usage").unwrap();
        assert_eq!(usage.get("prompt_tokens").unwrap(), 100); // 70 + 30
        assert_eq!(usage.get("completion_tokens").unwrap(), 10);
        assert_eq!(usage.get("total_tokens").unwrap(), 110);
    }

    // ─── round-trip: read → write → read (应等价) ───────────────────────

    #[test]
    fn round_trip_request_with_tools() {
        let original = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}
                }]},
                {"role": "tool", "tool_call_id": "call_1", "content": "Sunny"},
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get weather",
                    "parameters": {"type": "object", "properties": {}}
                }
            }],
            "tool_choice": "auto",
            "max_tokens": 100,
        });
        let ir = reader().read_request(&original).unwrap();
        let rewritten = writer().write_request(&ir);
        // round-trip: 重新解析应该等价 (除字段顺序).
        let ir2 = reader().read_request(&rewritten).unwrap();
        assert_eq!(ir, ir2);
    }

    // ─── stop sequences 归一化 ───────────────────────────────────────────

    #[test]
    fn read_request_stop_can_be_string_or_array() {
        let ir1 = reader()
            .read_request(&json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "x"}],
                "stop": "END",
            }))
            .unwrap();
        let ir2 = reader()
            .read_request(&json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "x"}],
                "stop": ["END"],
            }))
            .unwrap();
        assert_eq!(ir1.stop, ir2.stop);
        assert_eq!(ir1.stop, vec!["END".to_string()]);
    }

    // ─── stream fan-out ────────────────────────────────────────────────

    #[test]
    fn stream_chunk_first_emits_message_start_then_text_delta() {
        let chunk = json!({
            "id": "chatcmpl-x",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {"content": "Hello"},
                "finish_reason": Value::Null,
            }]
        });
        let mut state = StreamDecodeState::default();
        let events = reader().read_response_events("", &chunk, &mut state);
        // MessageStart + BlockStart(Text) + BlockDelta(TextDelta)
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], IrStreamEvent::MessageStart { .. }));
        assert!(matches!(
            events[1],
            IrStreamEvent::BlockStart {
                block: IrBlockMeta::Text,
                ..
            }
        ));
        assert!(matches!(
            events[2],
            IrStreamEvent::BlockDelta {
                delta: IrDelta::TextDelta(_),
                ..
            }
        ));
    }

    #[test]
    fn stream_chunk_finish_closes_blocks_and_emits_stop() {
        let chunk = json!({
            "id": "x", "created": 0, "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        });
        let mut state = StreamDecodeState {
            started: true,
            text_block_open: true,
            text_index: Some(0),
            ..Default::default()
        };
        let events = reader().read_response_events("", &chunk, &mut state);
        // BlockStop + MessageDelta + MessageStop
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], IrStreamEvent::BlockStop { index: 0 }));
        assert!(matches!(
            events[1],
            IrStreamEvent::MessageDelta {
                stop_reason: Some(IrStopReason::EndTurn),
                ..
            }
        ));
        assert!(matches!(events[2], IrStreamEvent::MessageStop));
    }

    // ─── include_usage (stream_options.include_usage: true) ────────────
    //
    // OpenAI 当客户端传 `stream_options.include_usage: true` 时, 流末尾会发一个
    // 独立的 usage chunk: `choices: []` (空数组) + 顶层 `usage`. 这是规范明确的
    // 格式 (见 OpenAI API reference chat/streaming).
    //
    // 我们必须识别这个 chunk 并以 MessageDelta 形式向上广播 usage, 否则 IR writer
    // 不会把 usage 写回客户端, 导致 opencode 等客户端拿不到 token 统计.

    #[test]
    fn stream_chunk_include_usage_empty_choices_emits_message_delta() {
        // 场景: finish_reason 已经在前一 chunk 发出, 然后单独一个 chunk 携带 usage,
        // choices 是空数组 (不是缺失).
        let chunk = json!({
            "id": "x", "created": 0, "model": "gpt-4o",
            "choices": [],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        });
        let mut state = StreamDecodeState::default();
        let events = reader().read_response_events("", &chunk, &mut state);
        // MessageStart (首次) + MessageDelta(usage).
        // 关键: usage 必须以 MessageDelta 形式发出.
        assert!(
            events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::MessageDelta { usage, .. }
                    if usage.input_tokens == 10 && usage.output_tokens == 5)),
            "expected MessageDelta with usage; got: {events:?}"
        );
    }

    #[test]
    fn writer_message_delta_with_only_usage_emits_empty_choices_plus_usage() {
        // 独立 usage chunk (OpenAI stream_options.include_usage 末尾 chunk 格式):
        // writer 必须输出 `choices: []` + `usage`, 而不是 `choices:[{delta:{}}]`.
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            },
        };
        let (_, chunk) = writer()
            .write_response_event(&ev)
            .expect("should emit chunk");
        let choices = chunk.get("choices").and_then(Value::as_array).unwrap();
        assert!(
            choices.is_empty(),
            "choices must be empty array; got: {chunk}"
        );
        let usage = chunk.get("usage").expect("usage must be present");
        assert_eq!(usage.get("prompt_tokens").unwrap(), 10);
        assert_eq!(usage.get("completion_tokens").unwrap(), 5);
        assert_eq!(usage.get("total_tokens").unwrap(), 15);
    }

    #[test]
    fn writer_message_delta_with_finish_reason_and_usage_emits_both() {
        // finish_reason chunk 也带 usage (非 include_usage 模式, 或上游合并了):
        // writer 应输出 choices[0]+finish_reason + 顶层 usage.
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some(IrStopReason::EndTurn),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 7,
                output_tokens: 3,
                ..Default::default()
            },
        };
        let (_, chunk) = writer()
            .write_response_event(&ev)
            .expect("should emit chunk");
        let choices = chunk.get("choices").and_then(Value::as_array).unwrap();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].get("finish_reason").unwrap(), "stop");
        let usage = chunk.get("usage").expect("usage must be present");
        assert_eq!(usage.get("prompt_tokens").unwrap(), 7);
    }

    #[test]
    fn writer_message_delta_with_no_usage_no_stop_reason_is_skipped() {
        // 空 delta + 无 usage: writer 跳过 (返回 None).
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage::default(),
        };
        assert!(writer().write_response_event(&ev).is_none());
    }
}
