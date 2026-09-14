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

use serde_json::{Map, Value, json};

use super::ir::{ContentForm, ReasoningContentForm, StopForm};
use super::{
    IrBlock, IrBlockMeta, IrDelta, IrError, IrImageSource, IrMessage, IrRequest, IrResponse,
    IrRole, IrStopReason, IrStreamEvent, IrTool, IrToolChoice, IrUsage, Reader, Writer,
    blocks_to_text, collect_extra, current_epoch, input_to_string, ir::StreamDecodeState,
    random_base62,
};

/// OpenAI Chat Completions stream 的 `tool_calls[].index` 字段实际上界.
///
/// OpenAI flat stream 把多个并行 tool_call 平铺到 `delta.tool_calls[]`, 用 `index` 字段
/// 区分 (与 Anthropic 的 `content_block_start.index` 同义). reader 用 [`StreamDecodeState`]
/// 跨 chunk 跟踪每个 oai_idx → ir_idx 的映射, oai_idx 作为 `BTreeSet<usize>` / `BTreeMap`
/// 的 key 必须有上界, 防御 u64::MAX 等 wire 异常值导致内存爆炸.
///
/// 取值依据: 实测上界 (OpenAI 官方文档未明示 index 上限, 但 wire 历史上从未观测到 > 127;
/// 远超此值几乎肯定是上游/中间件 bug). 超过此值的 index 被 clamp 到此值, 行为上是
/// "合并到同一个 tool_call", 优于 panic.
const MAX_OPENAI_TOOL_INDEX: usize = 127;

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
            let mut blocks = read_openai_content(msg.get("content"));

            // 思考型模型的 assistant 历史可能带 reasoning_content (客户端回传,
            // 如 Chatbox / opencode 会把上一轮思考原文发回). FWD-1: 同协议
            // redact 路径对 wire 的唯一合法修改是 real↔mock, 此字段必须建模,
            // 否则历史 reasoning 静默丢失. 空串跳过 (无信息量; wire 形态由
            // reasoning_content_form 保留, writer 据此写回).
            // 假设: reasoning_content 是 string; 非 string 形态静默 drop (ROB-1).
            // blocks 首位 (思考先于正文, 与 read_response / 流式累积顺序一致).
            let rc_field = msg.get("reasoning_content");
            if role == IrRole::Assistant
                && let Some(rc) = rc_field.and_then(Value::as_str)
                && !rc.is_empty()
            {
                blocks.insert(
                    0,
                    IrBlock::ReasoningContent {
                        text: rc.to_string(),
                    },
                );
            }

            // assistant 消息可能有 tool_calls (顶层字段, 不在 content 里).
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
                            content_form: None, // OpenAI tool message content 总是 string
                        }],
                        ..Default::default()
                    });
                }
                continue;
            }

            // L1 保真: 记录 content 原始形态 (string / array / null).
            let content_form = ContentForm::classify(msg.get("content"));
            // L1 保真 (#176): 记录 reasoning_content 的 "显式存在但无信息量" 形态
            // (空串 / null) — 区分与字段缺席, writer 据此写回 (FWD-1).
            let reasoning_content_form = if role == IrRole::Assistant {
                ReasoningContentForm::classify(rc_field)
            } else {
                None
            };
            let message = IrMessage {
                // role==User 且 content 含非空 Text block (排除纯 tool_result user / assistant tool_call).
                contains_user_text: role == IrRole::User && super::ir::blocks_has_text(&blocks),
                role,
                content: blocks,
                content_form,
                reasoning_content_form,
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
        // L7 保真: 记录 stop 原始形态 (string / array). 区分 "stop":"" / "stop":[] 与缺失.
        let stop_form = StopForm::classify(obj.get("stop"));
        let user = obj.get("user").and_then(Value::as_str).map(String::from);
        let parallel_tool_calls = obj.get("parallel_tool_calls").and_then(Value::as_bool);
        let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
        let tool_choice = obj.get("tool_choice").and_then(read_tool_choice);

        let tools = obj
            .get("tools")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(read_tool_def).collect())
            .unwrap_or_default();
        // wire 保真: 仅当 tools 是数组时才算"显式存在" (区分 "tools":[] 与缺失 / null).
        let tools_present = obj.get("tools").and_then(Value::as_array).is_some();

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
            tools_present,
            max_tokens,
            temperature,
            top_p,
            top_k: None, // OpenAI 没有 top_k
            stop,
            stop_form,
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
            // 思考原文 (reasoning model 非流式响应): blocks 首位 (思考在 content 之前).
            if let Some(rc) = message.get("reasoning_content").and_then(Value::as_str)
                && !rc.is_empty()
            {
                blocks.push(IrBlock::ReasoningContent {
                    text: rc.to_string(),
                });
            }
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

        let usage = obj.get("usage").filter(|v| v.is_object()).map(read_usage);
        let usage_present = usage.is_some();
        let usage = usage.unwrap_or_default();

        Ok(IrResponse {
            content: blocks,
            stop_reason,
            stop_sequence: None, // OpenAI 非流式响应不显式返回 stop_sequence
            usage,
            usage_present,
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
                        ..Default::default()
                    }));
                }
                for b in tool_results {
                    if let IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                        content_form: _,
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
        // L7 保真: stop_form.is_some() 时即便 stop 为空也输出 (区分 "stop":"" / "stop":[] 与缺失).
        if !req.stop.is_empty() || req.stop_form.is_some() {
            let stop_value = match req.stop_form {
                Some(StopForm::String) if req.stop.len() == 1 => Value::String(req.stop[0].clone()),
                Some(StopForm::String) => Value::String(String::new()), // 空 string 形态
                _ => Value::Array(req.stop.iter().map(|s| Value::String(s.clone())).collect()),
            };
            out.insert("stop".to_string(), stop_value);
        }
        if req.stream {
            out.insert("stream".to_string(), Value::Bool(true));
        }
        if let Some(u) = &req.user {
            out.insert("user".to_string(), Value::String(u.clone()));
        }
        // OpenAI 在 tools 为空时, parallel_tool_calls 会触发 400, 必须 gate.
        // 但若 wire 原始含 "tools":[] (显式空), 保真输出空数组.
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
        } else if req.tools_present {
            // wire 保真: 原始 wire 显式含 "tools":[], 即便 IR tools 为空也输出.
            out.insert("tools".to_string(), Value::Array(vec![]));
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
                IrBlock::Reasoning { .. } => {
                    // OpenAI Chat 协议无 reasoning item 的标准对应 (有非标 reasoning_content, 但结构不同).
                    // 跨协议翻译时静默丢弃 (lossy-by-target); 同协议路径不会到达 Chat writer.
                }
                IrBlock::ReasoningContent { text } => {
                    // 思考型模型的非标 reasoning_content 字段 (#176). 同协议 redact
                    // 路径 round-trip 用; 跨协议来源不会出现 (Anthropic thinking /
                    // Responses reasoning 不映射到本 block).
                    message.insert("reasoning_content".to_string(), Value::String(text.clone()));
                }
            }
        }
        // OpenAI content: 若只有文本, 用 string; 否则用 array.
        let content = single_or_array(content_parts);
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
            IrStreamEvent::BlockStart { index, block } => match block {
                IrBlockMeta::Text => {
                    // OpenAI 流的 text block start 是隐式的: 第一个 text delta chunk 自带 content.
                    // 这里返回 None 避免发出空 chunk (与 BlockStop 同样跳过).
                    return None;
                }
                IrBlockMeta::ReasoningContent => {
                    // reasoning block start 同样隐式: 第一个 reasoning_content delta
                    // chunk 自带内容. 跳过空 chunk (与 Text 对称).
                    return None;
                }
                IrBlockMeta::ToolUse { id, name } => json!({
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "tool_calls": [{
                                // 用 IR block index 作为 oai tool_call index (非硬编码 0, 否则并行 call 会被客户端聚合).
                                "index": index,
                                "id": id,
                                "type": "function",
                                "function": {"name": name, "arguments": ""},
                            }]
                        },
                        "finish_reason": Value::Null,
                    }]
                }),
            },
            IrStreamEvent::BlockDelta { index, delta } => match delta {
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
                                "index": index,
                                "function": {"arguments": args},
                            }]
                        },
                        "finish_reason": Value::Null,
                    }]
                }),
                IrDelta::ReasoningDelta(rc) => json!({
                    "choices": [{
                        "index": 0,
                        "delta": {"reasoning_content": rc},
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

/// 解析 content array 中的一个 part.
///
/// OpenAI 协议中 content array 元素可能是:
/// - `{type:"text",text:"..."}` 对象 (user 消息的标准形态)
/// - `{type:"image_url",...}` 对象 (多模态)
/// - 裸 string `"..."` (assistant 消息的多段文本, 非标准但 OpenAI 接受)
///
/// 未知类型 (audio 等) 静默 drop (L5 待修: 应保留为 IrBlock::Unknown).
fn read_content_part(part: &Value) -> Option<IrBlock> {
    // 裸 string 元素 (assistant content array 的非标准形态)
    if let Some(s) = part.as_str() {
        if s.is_empty() {
            return None;
        }
        return Some(IrBlock::Text {
            text: s.to_string(),
        });
    }
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
    if let Some(rest) = url.strip_prefix("data:")
        && let Some((meta, payload)) = rest.split_once(',')
    {
        let media_type = meta.split(';').next().unwrap_or("").to_string();
        if meta.contains("base64") && !media_type.is_empty() {
            return IrImageSource::Base64 {
                media_type,
                data: payload.to_string(),
            };
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
/// OpenAI flat stream 允许 text / reasoning / tool_calls 以任意顺序到达. 为了避免
/// 多类 block 占用同一个 index (导致 Anthropic 端 `content_block_start` index 冲突),
/// 每次开新 block 都查询当前已用的最大 index + 1.
fn next_free_block_index(state: &StreamDecodeState) -> usize {
    let mut max = 0;
    if let Some(i) = state.text_index {
        max = max.max(i);
    }
    if let Some(i) = state.reasoning_index {
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
                    usage_present: true,
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
        // 思考原文 delta (reasoning_content, #176). 先于 content 处理:
        // 思考阶段的流形态是 reasoning chunks → content chunks, 同 chunk 同时
        // 携带两者的场景未观测, 但保持 reader 顺序与 wire 字段出现顺序
        // (reasoning_content 在 content 之前) 一致.
        if let Some(rc) = delta.get("reasoning_content").and_then(Value::as_str)
            && !rc.is_empty()
        {
            let index = if !state.reasoning_block_open {
                let new_idx = next_free_block_index(state);
                events.push(IrStreamEvent::BlockStart {
                    index: new_idx,
                    block: IrBlockMeta::ReasoningContent,
                });
                state.reasoning_block_open = true;
                state.reasoning_index = Some(new_idx);
                new_idx
            } else {
                state.reasoning_index.unwrap_or(0)
            };
            events.push(IrStreamEvent::BlockDelta {
                index,
                delta: IrDelta::ReasoningDelta(rc.to_string()),
            });
        }
        // 文本 delta.
        if let Some(content) = delta.get("content").and_then(Value::as_str)
            && !content.is_empty()
        {
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
        // 工具调用 delta (可能有多个并发).
        if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for tc in tool_calls {
                process_tool_call_delta(tc, state, &mut events);
            }
        }
    }

    // 3) 处理 finish_reason: 关闭所有开着的 block + MessageDelta + MessageStop;
    //    否则若有中间 usage chunk, 防御性 emit MessageDelta(usage).
    if let Some(reason) = finish_reason {
        finish_stream(state, &mut events, read_stop_reason(reason), chunk_usage);
    } else if let Some(u) = chunk_usage {
        // 中间的 usage chunk (理论上 OpenAI 不会有, 防御性处理).
        events.push(IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: u,
            usage_present: true,
        });
    }

    events
}

/// 流末尾的"关闭一切"操作: 依次关闭所有开着的 block (reasoning + text + 全部 open tool),
/// 然后 emit `MessageDelta(stop_reason, usage)` 与 `MessageStop`.
///
/// **顺序契约**: 先关 reasoning block (若开着), 再关 text block (若开着), 再按 oai_idx
/// 升序关所有 open tool (`open_tools` 是 `BTreeSet`, 升序迭代), 最后 MessageDelta /
/// MessageStop. 此顺序与单测 + STR-5/STR-6 proptest 锁定的 wire 顺序一致, 不得调整
/// (Anthropic writer 把 BlockStop 翻译为 `content_block_stop`, 顺序错位会破坏客户端的
/// block 聚合). reasoning 在最前: 思考先于正文, 与模型输出顺序一致.
fn finish_stream(
    state: &mut StreamDecodeState,
    events: &mut Vec<IrStreamEvent>,
    stop_reason: IrStopReason,
    usage: Option<IrUsage>,
) {
    close_open_blocks(state, events);
    events.push(IrStreamEvent::MessageDelta {
        stop_reason: Some(stop_reason),
        stop_sequence: None,
        usage: usage.clone().unwrap_or_default(),
        usage_present: usage.is_some(),
    });
    events.push(IrStreamEvent::MessageStop);
}

/// 关闭所有当前开着的 block: 先 reasoning block, 再 text block, 再所有 open tool.
///
/// 关闭后清空 `reasoning_block_open` / `text_block_open` / `open_tools` / `tool_ir_index`.
/// "关 reasoning + text + 全部 tool" 是三个状态机的统一收尾动作, 集中此处避免散落.
///
/// **行为等价**: `open_tools` (BTreeSet, 升序) 作为"哪些 oai_idx 开着"的真相源,
/// `tool_ir_index` 仅查 ir_idx (不假设两集合 key 同步).
fn close_open_blocks(state: &mut StreamDecodeState, events: &mut Vec<IrStreamEvent>) {
    // 关闭 reasoning block.
    if state.reasoning_block_open {
        if let Some(idx) = state.reasoning_index {
            events.push(IrStreamEvent::BlockStop { index: idx });
        }
        state.reasoning_block_open = false;
    }
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
        .map(|n| (n as usize).min(MAX_OPENAI_TOOL_INDEX)) // clamp 防 u64::MAX panic
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
        && !args.is_empty()
        && let Some(&ir_idx) = state.tool_ir_index.get(&oai_idx)
    {
        events.push(IrStreamEvent::BlockDelta {
            index: ir_idx,
            delta: IrDelta::InputJsonDelta(args.to_string()),
        });
    }
}

// ─── Helpers: write ────────────────────────────────────────────────────────

/// 单元素 Vec 收敛为该元素, 多元素保持数组, 空归 null
/// (OpenAI assistant content 的 wire 形态收敛: string | array | null).
fn single_or_array(parts: Vec<Value>) -> Value {
    match parts.len() {
        0 => Value::Null,
        1 => parts.into_iter().next().unwrap(),
        _ => Value::Array(parts),
    }
}

/// IR 消息 → OpenAI wire 消息 (含 tool 消息的特殊处理).
fn write_message(msg: &IrMessage) -> Value {
    match msg.role {
        IrRole::System => {
            let text = blocks_to_text(&msg.content);
            json!({"role": "system", "content": text})
        }
        IrRole::User => {
            // L1 保真: 按 wire 原始形态输出 content.
            //   - String + 单 Text block → 裸 string (OpenAI 约定)
            //   - Null + 空 content       → null
            //   - Array / 其他            → array
            //   - None (内部构造 / 跨协议) → 按默认约定 (单文本 string, 多块 array)
            let single_text: Option<&String> = match msg.content.as_slice() {
                [IrBlock::Text { text }] => Some(text),
                _ => None,
            };

            // use_string_form: 当形态要求 string 或默认走 string 约定时, 且确实只有单个 Text.
            let want_string = !matches!(
                msg.content_form,
                Some(ContentForm::Array) | Some(ContentForm::Null)
            );
            if want_string && let Some(text) = single_text {
                return json!({"role": "user", "content": text});
            }
            if matches!(msg.content_form, Some(ContentForm::Null)) && msg.content.is_empty() {
                return json!({"role": "user", "content": Value::Null});
            }

            let parts: Vec<Value> = msg.content.iter().filter_map(write_user_block).collect();
            // 空数组: 按 wire 形态决定 (Array → [], 默认 → "").
            let content = match (msg.content_form, parts.is_empty()) {
                (Some(ContentForm::Array), _) => Value::Array(parts),
                (Some(ContentForm::Null), true) => Value::Null,
                (_, false) => Value::Array(parts),
                (_, true) => Value::String(String::new()), // 默认 / String + 空 → ""
            };
            json!({"role": "user", "content": content})
        }
        IrRole::Assistant => {
            let mut content_parts: Vec<Value> = Vec::new();
            let mut tool_calls: Vec<Value> = Vec::new();
            // 思考原文 (reasoning model 的 assistant 历史回传, #176). FWD-1: 同协议
            // redact 路径必须保留. 空 text 跳过 (与 wire 缺席等价, reader 侧对称).
            let mut reasoning_content: Option<String> = None;
            for b in &msg.content {
                match b {
                    IrBlock::Text { text } => {
                        if !text.is_empty() {
                            content_parts.push(Value::String(text.clone()));
                        }
                    }
                    IrBlock::ReasoningContent { text } => {
                        if !text.is_empty() {
                            reasoning_content = Some(text.clone());
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
            // L1 保真: content_form 决定 wire 形态 (Array / Null 强制; 其余按默认约定).
            let content = match (msg.content_form, content_parts.len()) {
                (Some(ContentForm::Array), _) => Value::Array(content_parts),
                (Some(ContentForm::Null), 0) => Value::Null,
                _ => single_or_array(content_parts),
            };
            let mut obj = Map::new();
            obj.insert("role".to_string(), json!("assistant"));
            obj.insert("content".to_string(), content);
            // reasoning_content 写回: 非空 block 优先; 否则按 wire 形态元数据恢复
            // "显式空 / null" (L1 保真, 区分缺席; FWD-1). 跨协议来源 form=None +
            // 无 block → 不输出 (缺席), 与原行为一致.
            if let Some(rc) = reasoning_content.map(Value::String).or_else(|| {
                msg.reasoning_content_form
                    .map(ReasoningContentForm::to_value)
            }) {
                obj.insert("reasoning_content".to_string(), rc);
            }
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
            content_form: _,
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
        IrBlock::Reasoning { .. } => None, // user 消息里通常没有 Reasoning
        IrBlock::ReasoningContent { .. } => None, // 同上 (思考原文属 assistant 消息)
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

    // ─── read_tool_choice: 纯函数全分支覆盖 ─────────────────────────────────
    //
    // read_tool_choice 把 OpenAI wire 的 tool_choice 字段映射为 IR 枚举.
    // 现有 read_request 测试不传 tool_choice, 4 个 string 分支 + 2 个 object 分支 +
    // fallthrough 均未覆盖. 这里构造 JSON Value 直接调用, 覆盖全部分支.

    #[test]
    fn read_tool_choice_covers_all_branches() {
        use crate::codec::ir::IrToolChoice;

        // String 分支.
        assert_eq!(read_tool_choice(&json!("auto")), Some(IrToolChoice::Auto));
        assert_eq!(read_tool_choice(&json!("none")), Some(IrToolChoice::None));
        assert_eq!(
            read_tool_choice(&json!("required")),
            Some(IrToolChoice::Required)
        );
        // 未知 string → 默认 Auto.
        assert_eq!(
            read_tool_choice(&json!("weird-value")),
            Some(IrToolChoice::Auto)
        );

        // Object 分支: type=function + 有 name.
        assert_eq!(
            read_tool_choice(&json!({"type":"function","function":{"name":"ls"}})),
            Some(IrToolChoice::Tool {
                name: "ls".to_string()
            })
        );
        // Object 分支: type=function 但 name 空/缺失 → Required.
        assert_eq!(
            read_tool_choice(&json!({"type":"function","function":{}})),
            Some(IrToolChoice::Required)
        );
        // Object 分支: type 非 function → Auto.
        assert_eq!(
            read_tool_choice(&json!({"type":"other"})),
            Some(IrToolChoice::Auto)
        );

        // 非 string 非 object → None.
        assert_eq!(read_tool_choice(&json!(42)), None);
        assert_eq!(read_tool_choice(&json!(null)), None);
    }

    // ─── read_tool_def: 纯函数边界覆盖 ───────────────────────────────────────

    #[test]
    fn read_tool_def_returns_none_for_missing_name() {
        // name 缺失/空 → None (覆盖 689-690 的早退).
        assert_eq!(read_tool_def(&json!({"function":{}})), None);
        assert_eq!(read_tool_def(&json!({"function":{"name":""}})), None);
        // 无 function key → None (683 行 ? 早退).
        assert_eq!(read_tool_def(&json!({"not_function":{}})), None);
    }

    #[test]
    fn read_tool_def_parses_full_definition() {
        let tool = read_tool_def(&json!({
            "function": {
                "name": "search",
                "description": "Search the web",
                "parameters": {"type": "object", "properties": {}}
            }
        }));
        let tool = tool.expect("valid tool def");
        assert_eq!(tool.name, "search");
        assert_eq!(tool.description.as_deref(), Some("Search the web"));
    }

    #[test]
    fn reader_name_is_openai() {
        // 覆盖 name() 纯函数 (30-32), 守卫 protocol 标识符稳定.
        assert_eq!(reader().name(), "openai");
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

    // ─── usage_present (USAGE-2: presence 语义, usage-stats 采集) ─────────
    //

    /// 最小合法 OpenAI 响应 body (read_response 的可复用 fixture).
    fn oai_resp_body_with_extra(extra: &str) -> String {
        format!(
            r#"{{"id":"chatcmpl-1","model":"gpt-4o","choices":[{{"index":0,
                "message":{{"role":"assistant","content":"hi"}},"finish_reason":"stop"}}]{extra}}}"#
        )
    }

    #[test]
    fn read_response_usage_present_true_when_usage_object_in_wire() {
        // wire 显式携带 usage 对象 (即便全零) → usage_present = true (P-3: 缺失显式).
        let body: Value = serde_json::from_str(&oai_resp_body_with_extra(
            r#","usage":{"prompt_tokens":0,"completion_tokens":0}"#,
        ))
        .unwrap();
        let ir = reader().read_response(&body).unwrap();
        assert!(
            ir.usage_present,
            "explicit zero usage object must set presence"
        );
    }

    #[test]
    fn read_response_usage_present_false_when_usage_absent() {
        // wire 无 usage 字段 → usage_present = false (与全零回显区分).
        let body: Value = serde_json::from_str(&oai_resp_body_with_extra("")).unwrap();
        let ir = reader().read_response(&body).unwrap();
        assert!(!ir.usage_present, "absent usage must not set presence");
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

    // ─── single_or_array: 纯函数全分支覆盖 ────────────────────────────────

    #[test]
    fn single_or_array_forms() {
        assert_eq!(single_or_array(vec![]), Value::Null);
        assert_eq!(single_or_array(vec![json!("hi")]), json!("hi"));
        assert_eq!(
            single_or_array(vec![json!("a"), json!("b")]),
            json!(["a", "b"])
        );
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
                ..Default::default()
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
                ..Default::default()
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
            usage_present: true,
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

    // ─── 跨协议 round-trip: OpenAI → IR → Anthropic → IR → OpenAI ───────
    //
    // 背景: AGENTS.md 把 OpenAI ⇄ Anthropic 双向翻译列为核心职责, 但之前只有同协议
    // round-trip. 这里补 `openai_reader → anthropic_writer → anthropic_reader → openai_writer`
    // 的全链路 round-trip, 验证语义关键字段 (role/text/tool name+input/tool_result) 保真.
    //
    // 跨协议不可能 byte-exact (字段语义差异), 我们断言**语义关键字段**相等, 并用注释说明
    // 哪些字段在跨协议中会丢失/转换:
    //   - OpenAI `max_tokens` 可选 / Anthropic 必填 (writer 缺失时注入 DEFAULT_MAX_TOKENS).
    //   - OpenAI temperature 无上限 / Anthropic 必须 [0,1] (writer clamp).
    //   - OpenAI tool 消息是独立 role:"tool" / Anthropic 是 user 消息内的 tool_result 块.
    //   - OpenAI `extra` 字段在跨协议时被清空 (防源协议独有字段泄漏).

    /// 跨协议 round-trip 辅助: 提取语义关键字段做相等断言 (不比较 max_tokens/temperature
    /// 等协议特定归一化字段, 也不比较 extra).
    fn assert_cross_proto_semantic_eq(a: &IrRequest, b: &IrRequest, ctx: &str) {
        assert_eq!(a.messages.len(), b.messages.len(), "{ctx}: message count");
        for (i, (am, bm)) in a.messages.iter().zip(b.messages.iter()).enumerate() {
            assert_eq!(am.role, bm.role, "{ctx}: msg[{i}].role");
            assert_eq!(
                am.content.len(),
                bm.content.len(),
                "{ctx}: msg[{i}].content.len()"
            );
            for (j, (ab, bb)) in am.content.iter().zip(bm.content.iter()).enumerate() {
                match (ab, bb) {
                    (IrBlock::Text { text: at }, IrBlock::Text { text: bt }) => {
                        assert_eq!(at, bt, "{ctx}: msg[{i}].block[{j}] text");
                    }
                    (
                        IrBlock::ToolUse {
                            id: aid,
                            name: an,
                            input: ain,
                        },
                        IrBlock::ToolUse {
                            id: bid,
                            name: bn,
                            input: bin,
                        },
                    ) => {
                        assert_eq!(aid, bid, "{ctx}: msg[{i}].block[{j}] tool id");
                        assert_eq!(an, bn, "{ctx}: msg[{i}].block[{j}] tool name");
                        assert_eq!(ain, bin, "{ctx}: msg[{i}].block[{j}] tool input");
                    }
                    (
                        IrBlock::ToolResult {
                            tool_use_id: aid,
                            content: ac,
                            is_error: ae,
                            ..
                        },
                        IrBlock::ToolResult {
                            tool_use_id: bid,
                            content: bc,
                            is_error: be,
                            ..
                        },
                    ) => {
                        assert_eq!(aid, bid, "{ctx}: msg[{i}].block[{j}] tool_use_id");
                        assert_eq!(ae, be, "{ctx}: msg[{i}].block[{j}] is_error");
                        assert_eq!(
                            ac.len(),
                            bc.len(),
                            "{ctx}: msg[{i}].block[{j}] tool_result content.len()"
                        );
                    }
                    (left, right) => {
                        panic!(
                            "{ctx}: msg[{i}].block[{j}] block type mismatch: {left:?} vs {right:?}"
                        );
                    }
                }
            }
        }
        // system 内容 (纯文本) 跨协议保真.
        assert_eq!(a.system.len(), b.system.len(), "{ctx}: system.len()");
    }

    #[test]
    fn cross_proto_round_trip_text_only_messages() {
        // 纯文本 user/assistant 消息往返: OpenAI → Anthropic → OpenAI.
        use crate::codec::anthropic::{AnthropicReader, AnthropicWriter};
        let original = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there!"},
                {"role": "user", "content": "Bye"},
            ],
        });
        // 1. OpenAI → IR.
        let ir1 = reader().read_request(&original).unwrap();
        // 2. IR → Anthropic wire.
        let anth_wire = AnthropicWriter.write_request(&ir1);
        // 3. Anthropic wire → IR.
        let ir2 = AnthropicReader.read_request(&anth_wire).unwrap();
        // 4. IR → OpenAI wire.
        let oai_wire = writer().write_request(&ir2);
        // 5. OpenAI wire → IR.
        let ir3 = reader().read_request(&oai_wire).unwrap();
        // 关键语义字段 (role + text content) 跨协议保真.
        assert_cross_proto_semantic_eq(&ir1, &ir2, "OpenAI→Anthropic");
        assert_cross_proto_semantic_eq(&ir2, &ir3, "Anthropic→OpenAI");
    }

    #[test]
    fn cross_proto_round_trip_system_prompt() {
        // system message 的跨协议转换:
        //   OpenAI messages[0]=system → IR.system → Anthropic 顶层 system 字段 → IR.system.
        use crate::codec::anthropic::{AnthropicReader, AnthropicWriter};
        let original = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hi"},
            ],
        });
        let ir1 = reader().read_request(&original).unwrap();
        // 关键: OpenAI reader 把 system message 提升到 ir.system, messages 里只剩 user.
        assert_eq!(ir1.system.len(), 1, "OpenAI reader should promote system");
        assert_eq!(ir1.messages.len(), 1);
        let anth_wire = AnthropicWriter.write_request(&ir1);
        // 关键: Anthropic writer 把 ir.system 写成顶层 system 字段 (string 形式).
        assert_eq!(
            anth_wire["system"], "You are a helpful assistant.",
            "system should be top-level string in Anthropic wire"
        );
        let ir2 = AnthropicReader.read_request(&anth_wire).unwrap();
        // Anthropic reader 把顶层 system 读回 ir.system.
        assert_eq!(ir2.system.len(), 1);
        assert_eq!(ir2.messages.len(), 1);
        // 写回 OpenAI: system 又变回 messages[0].
        let oai_wire = writer().write_request(&ir2);
        let messages = oai_wire["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "You are a helpful assistant.");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages.len(), 2, "system + 1 user message");
        // 语义等价 (system text 保真).
        assert_cross_proto_semantic_eq(&ir1, &ir2, "system: OpenAI→Anthropic");
    }

    #[test]
    fn cross_proto_round_trip_tool_use_and_tool_result() {
        // 工具调用往返: assistant 的 ToolUse + user 的 ToolResult 跨协议保真.
        //
        // 关键差异 (语义等价但 wire 不同):
        //   OpenAI: assistant.tool_calls[] + 独立 role:"tool" 消息
        //   Anthropic: assistant 的 tool_use 块 + user 消息内的 tool_result 块
        use crate::codec::anthropic::{AnthropicReader, AnthropicWriter};
        let original = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "call_42", "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}
                }]},
                {"role": "tool", "tool_call_id": "call_42", "content": "Sunny, 20C"},
            ],
        });
        // OpenAI → IR.
        let ir1 = reader().read_request(&original).unwrap();
        // IR 里 assistant 消息含 ToolUse 块, tool 消息变成 user 角色的 ToolResult 块.
        assert_eq!(
            ir1.messages.len(),
            3,
            "user, assistant(tool_use), user(tool_result)"
        );
        // 第 3 条是 user + ToolResult (OpenAI tool → Anthropic user 角色).
        assert_eq!(ir1.messages[2].role, IrRole::User);
        // contains_user_text: 第 1 条 (真用户输入) = true; 第 3 条 (tool_result 借 user
        // 角色) = false. 此字段是 round_role 判定的依据 (sidebar 折叠工具循环为 sub-dot).
        assert!(ir1.messages[0].contains_user_text, "真 user 文本");
        assert!(
            !ir1.messages[2].contains_user_text,
            "tool_result 借 user 角色"
        );

        // IR → Anthropic wire → IR → OpenAI wire → IR.
        let anth_wire = AnthropicWriter.write_request(&ir1);
        let ir2 = AnthropicReader.read_request(&anth_wire).unwrap();
        let oai_wire = writer().write_request(&ir2);
        let ir3 = reader().read_request(&oai_wire).unwrap();

        // 语义关键字段保真: tool id / name / input / tool_result content.
        assert_cross_proto_semantic_eq(&ir1, &ir2, "tool: OpenAI→Anthropic");
        assert_cross_proto_semantic_eq(&ir2, &ir3, "tool: Anthropic→OpenAI");
        // 专门验证 ToolUse id 透传 (断裂会导致 tool_result 关联失败).
        let asst_ir3 = &ir3.messages[1];
        match &asst_ir3.content[0] {
            IrBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_42", "tool_use id must be verbatim preserved");
                assert_eq!(name, "get_weather");
                assert_eq!(input, &json!({"city": "SF"}));
            }
            other => panic!("expected ToolUse after round-trip, got {other:?}"),
        }
        // tool_result content text 保真 (作为 ToolResult 块内的 Text 块).
        match &ir3.messages[2].content[0] {
            IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                assert_eq!(tool_use_id, "call_42");
                assert_eq!(content.len(), 1);
                match &content[0] {
                    IrBlock::Text { text } => assert_eq!(text, "Sunny, 20C"),
                    other => panic!("expected Text in tool_result content, got {other:?}"),
                }
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
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
            usage_present: true,
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
            usage_present: true,
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
            usage_present: false,
        };
        assert!(writer().write_response_event(&ev).is_none());
    }

    // ─── 多 tool_call 流式: index 唯一性 (回归测试) ──────────────────────
    //
    // 历史 bug: writer 硬编码 tool_calls[].index=0, 多个并行 tool_call 的 delta
    // 被客户端按 index 聚合成 1 个. 修复后用 IR block index 区分.

    #[test]
    fn stream_two_tool_calls_must_have_distinct_oai_indices() {
        // 构造 IR 事件序列: 两个独立的 ToolUse block (ir_idx 1 和 2),
        // 模拟 reader 解析上游 "并行 2 个 tool_call" 的场景.
        let events = vec![
            IrStreamEvent::MessageStart {
                usage: None,
                id: Some("chatcmpl-x".into()),
                created: Some(1),
                model: Some("gpt-test".into()),
            },
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: "call_a".into(),
                    name: "get_weather".into(),
                },
            },
            IrStreamEvent::BlockStart {
                index: 2,
                block: IrBlockMeta::ToolUse {
                    id: "call_b".into(),
                    name: "get_time".into(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("{\"city\":\"SF\"}".into()),
            },
            IrStreamEvent::BlockDelta {
                index: 2,
                delta: IrDelta::InputJsonDelta("{}".into()),
            },
        ];

        // 收集所有 chunk 里 tool_calls[].index (直接用 BTreeSet 去重).
        let mut seen_indices = std::collections::BTreeSet::new();
        for ev in &events {
            if let Some((_, chunk)) = writer().write_response_event(ev)
                && let Some(choices) = chunk.get("choices").and_then(Value::as_array)
            {
                for ch in choices {
                    if let Some(tcs) = ch
                        .get("delta")
                        .and_then(|d| d.get("tool_calls"))
                        .and_then(Value::as_array)
                    {
                        for tc in tcs {
                            if let Some(idx) = tc.get("index").and_then(Value::as_u64) {
                                seen_indices.insert(idx);
                            }
                        }
                    }
                }
            }
        }

        assert!(
            seen_indices.len() >= 2,
            "multiple tool_calls must have distinct oai indices, got: {seen_indices:?}"
        );
    }

    #[test]
    fn stream_text_plus_two_tool_calls_ir_idx_not_starting_from_zero() {
        // 混合场景: 先 text block (ir_idx=1) 再两个 tool blocks (ir_idx=2,3).
        // 验证: 即使 oai tool_call index 不从 0 起始 (这里是 2 和 3),
        // 客户端仍能按 index 正确关联 BlockStart 与 BlockDelta.
        // (OpenAI 协议未规定 index 必须从 0 起始或连续, index 是关联 key 而非位置序号.)
        let events = vec![
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::Text,
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::TextDelta("thinking...".into()),
            },
            IrStreamEvent::BlockStart {
                index: 2,
                block: IrBlockMeta::ToolUse {
                    id: "call_a".into(),
                    name: "task".into(),
                },
            },
            IrStreamEvent::BlockStart {
                index: 3,
                block: IrBlockMeta::ToolUse {
                    id: "call_b".into(),
                    name: "task".into(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 2,
                delta: IrDelta::InputJsonDelta("{\"d\":\"A\"}".into()),
            },
            IrStreamEvent::BlockDelta {
                index: 3,
                delta: IrDelta::InputJsonDelta("{\"d\":\"B\"}".into()),
            },
        ];

        // 按 oai index 收集每个 tool_call 的 arguments delta, 验证 index→args 映射正确.
        let mut args_by_index: std::collections::BTreeMap<u64, String> = Default::default();
        for ev in &events {
            if let Some((_, chunk)) = writer().write_response_event(ev)
                && let Some(choices) = chunk.get("choices").and_then(Value::as_array)
            {
                for ch in choices {
                    if let Some(tcs) = ch
                        .get("delta")
                        .and_then(|d| d.get("tool_calls"))
                        .and_then(Value::as_array)
                    {
                        for tc in tcs {
                            let idx = tc.get("index").and_then(Value::as_u64).unwrap_or(0);
                            if let Some(args) = tc
                                .get("function")
                                .and_then(|f| f.get("arguments"))
                                .and_then(Value::as_str)
                            {
                                args_by_index.entry(idx).or_default().push_str(args);
                            }
                        }
                    }
                }
            }
        }

        // 两个不同的 tool index, 且各自 arguments 正确归属.
        assert_eq!(
            args_by_index.len(),
            2,
            "expected 2 distinct tool_call indices, got: {args_by_index:?}"
        );
        // ir_idx=2 → args A; ir_idx=3 → args B (证明 index 关联正确, 未被混到一起).
        let (idx_a, idx_b) = {
            let mut keys: Vec<_> = args_by_index.keys().copied().collect();
            keys.sort();
            (keys[0], keys[1])
        };
        assert!(
            args_by_index[&idx_a].contains('A'),
            "idx {idx_a} should have args A"
        );
        assert!(
            args_by_index[&idx_b].contains('B'),
            "idx {idx_b} should have args B"
        );
        assert!(idx_a != idx_b);
    }

    // ─── Image block: 多模态唯一通路 (read + write) ─────────────────────
    //
    // 两个协议的 read+write Image block 全无测试, 这里覆盖 base64 data URI 和 https URL
    // 两种 source. OpenAI 用 `image_url.url` 字段统一承载两种 source.

    #[test]
    fn read_content_part_image_url_https() {
        // OpenAI image_url (https URL 形式) → IR Image{Url}.
        let body = json!({
            "model": "gpt-4o",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "what is this?"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}},
                ],
            }],
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.messages[0].content.len(), 2);
        match &ir.messages[0].content[1] {
            IrBlock::Image { source } => {
                assert_eq!(
                    source,
                    &IrImageSource::Url("https://example.com/cat.png".into())
                );
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn read_content_part_image_url_base64_data_uri() {
        // OpenAI image_url (data:<mime>;base64,<payload> URI) → IR Image{Base64}.
        let body = json!({
            "model": "gpt-4o",
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "image_url",
                    "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="},
                }],
            }],
        });
        let ir = reader().read_request(&body).unwrap();
        match &ir.messages[0].content[0] {
            IrBlock::Image { source } => match source {
                IrImageSource::Base64 { media_type, data } => {
                    assert_eq!(media_type, "image/png");
                    assert_eq!(data, "iVBORw0KGgo=");
                }
                other => panic!("expected Base64, got {other:?}"),
            },
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn write_user_block_image_url_https() {
        // IR Image{Url} → OpenAI image_url.url = https://...
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![
                    IrBlock::Text {
                        text: "what is this?".into(),
                    },
                    IrBlock::Image {
                        source: IrImageSource::Url("https://example.com/cat.png".into()),
                    },
                ],
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        let msg = &v["messages"][0];
        assert_eq!(msg["role"], "user");
        let content = msg["content"].as_array().unwrap();
        // 文本 + 图片 = 2 parts.
        assert_eq!(content.len(), 2);
        assert_eq!(content[1]["type"], "image_url");
        assert_eq!(
            content[1]["image_url"]["url"],
            "https://example.com/cat.png"
        );
    }

    #[test]
    fn write_user_block_image_base64_data_uri() {
        // IR Image{Base64} → OpenAI image_url.url = "data:<mime>;base64,<payload>"
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Image {
                    source: IrImageSource::Base64 {
                        media_type: "image/jpeg".into(),
                        data: "abc123".into(),
                    },
                }],
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        let msg = &v["messages"][0];
        // 单 image block → array content (因为非单一 Text block).
        let url = msg["content"][0]["image_url"]["url"].as_str().unwrap();
        assert_eq!(url, "data:image/jpeg;base64,abc123");
    }

    // ─── reasoning_content (#176): reader 解码 + writer 写回 ─────────────
    //
    // 思考型模型 (glm / deepseek-r1 等 OpenAI 兼容 provider) 在响应与流式 delta 中
    // 携带非标 `reasoning_content` 字段. 历史 bug: codec 未建模 → redact 流式路径
    // (IR 重建) 思考期零字节, 客户端空闲看门狗超时断连 (Chatbox 30s, 生产 499).

    #[test]
    fn read_response_reasoning_content_becomes_block() {
        // 非流式响应: message.reasoning_content → IrBlock::ReasoningContent (首位).
        let body = json!({
            "id": "chatcmpl-r1",
            "model": "glm-5.3",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "reasoning_content": "let me think...",
                    "content": "the answer is 3",
                },
                "finish_reason": "stop",
            }],
        });
        let ir = reader().read_response(&body).unwrap();
        assert_eq!(ir.content.len(), 2);
        assert!(matches!(
            &ir.content[0],
            IrBlock::ReasoningContent { text } if text == "let me think..."
        ));
        assert!(matches!(
            &ir.content[1],
            IrBlock::Text { text } if text == "the answer is 3"
        ));
    }

    #[test]
    fn write_response_reasoning_content_round_trip() {
        // writer: ReasoningContent block → message.reasoning_content 字段.
        let ir = IrResponse {
            content: vec![
                IrBlock::ReasoningContent {
                    text: "thinking...".into(),
                },
                IrBlock::Text {
                    text: "answer".into(),
                },
            ],
            stop_reason: Some(IrStopReason::EndTurn),
            usage: IrUsage::default(),
            usage_present: false,
            model: Some("glm-5.3".into()),
            id: Some("chatcmpl-r1".into()),
            created: Some(1),
            stop_sequence: None,
        };
        let v = writer().write_response(&ir);
        let msg = &v["choices"][0]["message"];
        assert_eq!(msg["reasoning_content"], "thinking...");
        assert_eq!(msg["content"], "answer");
        // round-trip: writer 输出重新被 reader 解析, blocks 保序保真.
        let ir2 = reader().read_response(&v).unwrap();
        assert_eq!(ir2.content, ir.content);
    }

    #[test]
    fn read_request_assistant_history_reasoning_content_round_trip() {
        // 客户端把上一轮思考原文回传进 assistant 历史 (Chatbox 等客户端行为).
        // FWD-1: 同协议 redact 路径除 real↔mock 外不得改 wire → 必须建模 + 写回.
        let body = json!({
            "model": "glm-5.3",
            "messages": [
                {"role": "user", "content": "1+1?"},
                {"role": "assistant", "reasoning_content": "trivial arithmetic",
                 "content": "2"},
                {"role": "user", "content": "and 2+2?"},
            ],
        });
        let ir = reader().read_request(&body).unwrap();
        assert!(matches!(
            &ir.messages[1].content[0],
            IrBlock::ReasoningContent { text } if text == "trivial arithmetic"
        ));
        let out = writer().write_request(&ir);
        let msg = &out["messages"][1];
        assert_eq!(msg["role"], "assistant");
        assert_eq!(msg["reasoning_content"], "trivial arithmetic");
        assert_eq!(msg["content"], "2");
    }

    // ─── reasoning_content 流式: reader 状态机 + writer 写回 (#176) ────────

    #[test]
    fn stream_reasoning_delta_emits_block_start_then_reasoning_delta() {
        // 思考阶段首 chunk: MessageStart + BlockStart{ReasoningContent} + BlockDelta{ReasoningDelta}.
        let chunk = json!({
            "id": "chatcmpl-r",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "glm-5.3",
            "choices": [{
                "index": 0,
                "delta": {"reasoning_content": "step 1"},
                "finish_reason": Value::Null,
            }]
        });
        let mut state = StreamDecodeState::default();
        let events = reader().read_response_events("", &chunk, &mut state);
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], IrStreamEvent::MessageStart { .. }));
        assert!(matches!(
            events[1],
            IrStreamEvent::BlockStart {
                block: IrBlockMeta::ReasoningContent,
                ..
            }
        ));
        assert!(matches!(
            &events[2],
            IrStreamEvent::BlockDelta {
                delta: IrDelta::ReasoningDelta(s),
                ..
            } if s == "step 1"
        ));
    }

    #[test]
    fn stream_reasoning_then_text_distinct_indices() {
        // 思考块与文本块必须是两个独立 block (独立 index), writer 各写各的 wire 字段.
        let reasoning_chunk = json!({
            "id": "chatcmpl-r", "object": "chat.completion.chunk", "created": 1700000000,
            "model": "glm-5.3",
            "choices": [{"index": 0, "delta": {"reasoning_content": "thinking"}, "finish_reason": Value::Null}]
        });
        let text_chunk = json!({
            "id": "chatcmpl-r", "object": "chat.completion.chunk", "created": 1700000000,
            "model": "glm-5.3",
            "choices": [{"index": 0, "delta": {"content": "answer"}, "finish_reason": Value::Null}]
        });
        let finish_chunk = json!({
            "id": "chatcmpl-r", "object": "chat.completion.chunk", "created": 1700000000,
            "model": "glm-5.3",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        });
        let mut state = StreamDecodeState::default();
        let mut all = Vec::new();
        for chunk in [&reasoning_chunk, &text_chunk, &finish_chunk] {
            all.extend(reader().read_response_events("", chunk, &mut state));
        }

        // reasoning 拿 index 1 (next_free_block_index 首个), text 拿 index 2 — 互不相同.
        let reasoning_idx = all
            .iter()
            .find_map(|ev| match ev {
                IrStreamEvent::BlockStart {
                    index,
                    block: IrBlockMeta::ReasoningContent,
                } => Some(*index),
                _ => None,
            })
            .expect("reasoning BlockStart");
        let text_idx = all
            .iter()
            .find_map(|ev| match ev {
                IrStreamEvent::BlockStart {
                    index,
                    block: IrBlockMeta::Text,
                } => Some(*index),
                _ => None,
            })
            .expect("text BlockStart");
        assert_ne!(reasoning_idx, text_idx);

        // finish: reasoning 先关 (BlockStop 顺序: reasoning → text), 再 text.
        let stops: Vec<usize> = all
            .iter()
            .filter_map(|ev| match ev {
                IrStreamEvent::BlockStop { index } => Some(*index),
                _ => None,
            })
            .collect();
        assert_eq!(stops, vec![reasoning_idx, text_idx], "close order");

        // writer: ReasoningDelta 写回 delta.reasoning_content, TextDelta 写 delta.content.
        let mut saw_reasoning = false;
        let mut saw_content = false;
        for ev in &all {
            if let Some((_, chunk)) = writer().write_response_event(ev)
                && let Some(delta) = chunk
                    .get("choices")
                    .and_then(Value::as_array)
                    .and_then(|c| c.first())
                    .and_then(|c| c.get("delta"))
            {
                if delta.get("reasoning_content").is_some() {
                    saw_reasoning = true;
                }
                if delta.get("content").is_some() {
                    saw_content = true;
                }
            }
        }
        assert!(saw_reasoning, "writer must emit reasoning_content delta");
        assert!(saw_content, "writer must emit content delta");
    }

    #[test]
    fn stream_reasoning_writer_block_start_is_implicit() {
        // OpenAI writer 对 BlockStart{ReasoningContent} 返回 None (start 隐式在首个 delta 内),
        // 与 Text 对称 — 不发空 chunk.
        let ev = IrStreamEvent::BlockStart {
            index: 1,
            block: IrBlockMeta::ReasoningContent,
        };
        assert!(writer().write_response_event(&ev).is_none());
    }

    // ─── ReasoningContent 跨协议丢弃 (FWD-3 范围外显式丢弃, #176) ──────────
    //
    // Anthropic thinking block 需 signature / Responses reasoning item 依赖
    // encrypted_content, 均无法从思考原文合法合成 → writer 跳过 (lossy-by-target).
    // 这里锁定该裁决: 防未来 "好心" 合成非法 wire 形态 (伪造 signature 会被
    // Anthropic API 拒收). rationale SSOT 见 src/codec/AGENTS.md 支持矩阵注记.

    #[test]
    fn reasoning_content_block_dropped_by_anthropic_writer() {
        use crate::codec::anthropic::{AnthropicReader, AnthropicWriter};
        // 请求侧: assistant 历史含 ReasoningContent block → Anthropic wire 无 thinking.
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::Assistant,
                content: vec![IrBlock::ReasoningContent {
                    text: "hidden chain of thought".into(),
                }],
                ..Default::default()
            }],
            model: "claude-x".into(),
            ..Default::default()
        };
        let wire = AnthropicWriter.write_request(&ir);
        let wire_str = serde_json::to_string(&wire).unwrap();
        assert!(
            !wire_str.contains("thinking") && !wire_str.contains("hidden chain"),
            "Anthropic egress must not contain synthesized thinking block: {wire_str}"
        );
        // 响应侧: write_block / BlockStart meta / ReasoningDelta 全部跳过.
        let resp = IrResponse {
            content: vec![IrBlock::ReasoningContent { text: "cot".into() }],
            ..Default::default()
        };
        let resp_wire = serde_json::to_string(&AnthropicWriter.write_response(&resp)).unwrap();
        assert!(
            !resp_wire.contains("thinking") && !resp_wire.contains("cot"),
            "Anthropic response must not contain reasoning text: {resp_wire}"
        );
        assert!(
            AnthropicWriter
                .write_response_event(&IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::ReasoningContent,
                })
                .is_none()
        );
        assert!(
            AnthropicWriter
                .write_response_event(&IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: IrDelta::ReasoningDelta("cot".into()),
                })
                .is_none()
        );
        // 丢弃后重读: Anthropic reader 不产出 ReasoningContent (round-trip 丢弃确认).
        let ir2 = AnthropicReader.read_request(&wire).unwrap();
        assert!(
            !ir2.messages.iter().any(|m| m
                .content
                .iter()
                .any(|b| matches!(b, IrBlock::ReasoningContent { .. }))),
            "ReasoningContent must not survive cross-proto round-trip"
        );
    }

    #[test]
    fn reasoning_content_block_dropped_by_responses_writer() {
        use crate::codec::responses::ResponsesWriter;
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::Assistant,
                content: vec![IrBlock::ReasoningContent {
                    text: "hidden chain of thought".into(),
                }],
                ..Default::default()
            }],
            model: "o1".into(),
            ..Default::default()
        };
        let wire = ResponsesWriter.write_request(&ir);
        let wire_str = serde_json::to_string(&wire).unwrap();
        assert!(
            !wire_str.contains("encrypted_content") && !wire_str.contains("hidden chain"),
            "Responses egress must not synthesize reasoning item: {wire_str}"
        );
        let resp = IrResponse {
            content: vec![IrBlock::ReasoningContent { text: "cot".into() }],
            ..Default::default()
        };
        let resp_wire = serde_json::to_string(&ResponsesWriter.write_response(&resp)).unwrap();
        assert!(
            !resp_wire.contains("\"reasoning\"") && !resp_wire.contains("cot"),
            "Responses output must not contain reasoning item: {resp_wire}"
        );
    }
}
