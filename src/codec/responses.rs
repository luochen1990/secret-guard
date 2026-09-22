//! OpenAI Responses API 的 Reader / Writer.
//!
//! # wire format 参考
//!
//! - 请求: <https://platform.openai.com/docs/api-reference/responses/create>
//! - 响应: <https://platform.openai.com/docs/api-reference/responses/object>
//! - 流式: <https://platform.openai.com/docs/api-reference/responses-streaming>
//!
//! # 与 Chat Completions 的核心差异
//!
//! Responses API 用 `input` (string 或 items 数组) + `instructions` (system prompt)
//! 替代 Chat 的 `messages`; 响应用 `output[]` items 数组替代 `choices[].message`;
//! usage 字段名为 `input_tokens`/`output_tokens` (而非 prompt_tokens/completion_tokens);
//! 流式是 typed semantic events (`response.created` / `response.output_text.delta` / ...).
//!
//! # MVP 范围 (FWD-3 建模范围内语义保留, 范围外显式丢弃)
//!
//! **覆盖**:
//! - `input: string` → 单条 user message; `input: array` → items list
//! - items: `message` (含 input_text/output_text/input_image content parts) /
//!   `function_call` / `function_call_output` / `reasoning` (仅 summary 文本)
//! - `instructions` → system 消息
//! - tools: `function` 类型 (平铺 `{name, parameters, description}` ↔ Chat 嵌套
//!   `{type:"function", function:{...}}`); 其他 type 静默丢弃
//! - usage 双向映射
//! - 非流式响应: `output[]` 中的 `message` (output_text) + `function_call` items
//!
//! **不覆盖** (reader 读取时丢弃 — 仅 function 工具进入 IR, 同协议 IR 重建路径
//! 与跨协议翻译同受影响; 纯字节透传路径不受影响; 丢弃点打 WARN):
//! - hosted tools (web_search / file_search / computer_use / mcp / image_generation)
//! - namespace tools flattening (留作后续)
//! - reasoning 的 `encrypted_content` (provider-specific opaque, 不可跨协议)
//! - `previous_response_id` 服务端状态 (secret-guard 是 stateless 代理)
//!
//! 流式: reader + writer 双侧已实现 — 事件→IR 映射表见 `read_responses_stream_event`,
//! IR→事件合成规格见 `write_responses_stream_event` (done 族帧需要累积状态, 由
//! `ResponsesEncodeState` 承载). proxy 层流式接线: same_proto restore 路径
//! (`proxy/same_proto.rs`) + 跨协议翻译路径 (`proxy/cross_proto.rs`), 端到端行为由
//! 集成测试锁定 (`cross_protocol_streaming_translates_*` /
//! `responses_streaming_with_secret_hit_restores_mock`, tests/integration.rs).
//!
//! # 同协议 round-trip (FWD-2)
//!
//! Responses 同协议 + Redact 路径走 reader → redact_ir → writer, 与 OpenAI/Anthropic
//! 同协议路径一致. wire 形态元数据 (input_form / instructions_form) 保留 round-trip 保真.

use serde_json::{Map, Value, json};

use super::ir::{
    IrBlock, IrImageSource, IrMessage, IrRequest, IrResponse, IrRole, ResponsesDecodeState,
    ResponsesEncodeState, ResponsesItemAccum, ResponsesItemKind, StreamItemState, blocks_has_text,
};
use super::{
    IrBlockMeta, IrDelta, IrError, IrStopReason, IrStreamEvent, IrTool, IrToolChoice, IrUsage,
    Reader, Writer, blocks_to_text, collect_extra, current_epoch, input_to_string, random_base62,
};

// ─── Reader ────────────────────────────────────────────────────────────────

pub struct ResponsesReader;

impl Reader for ResponsesReader {
    fn name(&self) -> &'static str {
        "responses"
    }

    fn read_request(&self, body: &Value) -> Result<IrRequest, IrError> {
        let obj = body
            .as_object()
            .ok_or_else(|| IrError::new("Responses request body must be a JSON object"))?;

        let model = obj
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // system / instructions: instructions (string 或 items) → system blocks.
        // 注意: instructions 不随 previous_response_id 延续 (OpenAI 设计意图), 这里直接
        // 当 system prompt 处理, 与 Chat 的 system 消息等价.
        let mut system: Vec<IrBlock> = Vec::new();
        if let Some(instr) = obj.get("instructions") {
            system.extend(read_instructions(instr));
        }

        // input: string | array of items.
        let mut ir_messages: Vec<IrMessage> = Vec::new();
        if let Some(input) = obj.get("input") {
            match input {
                Value::String(s) => {
                    if !s.is_empty() {
                        ir_messages.push(IrMessage {
                            role: IrRole::User,
                            content: vec![IrBlock::Text { text: s.clone() }],
                            contains_user_text: true,
                            ..Default::default()
                        });
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        // system/developer message 提升到 system blocks (与 instructions 同等).
                        // 这样 writer 能通过 instructions 还原, 避免丢失 (FWD-2).
                        if is_system_input_item(item) {
                            system.extend(read_message_content(item.get("content")));
                            continue;
                        }
                        if let Some(msgs) = read_input_item(item) {
                            ir_messages.extend(msgs);
                        }
                    }
                }
                _ => {} // null / 其他类型: 忽略
            }
        }

        // sampling 参数. Responses 用 max_output_tokens (而非 max_tokens).
        let max_tokens = obj
            .get("max_output_tokens")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|&n| n > 0);
        let temperature = obj.get("temperature").and_then(Value::as_f64);
        let top_p = obj.get("top_p").and_then(Value::as_f64);
        let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
        let tool_choice = obj.get("tool_choice").and_then(read_tool_choice);
        let parallel_tool_calls = obj.get("parallel_tool_calls").and_then(Value::as_bool);

        // tools: Responses 的 tools 是平铺数组, 每个有 type.
        // function 类型: {type:"function", name, parameters, description, strict?}
        // 其他类型 (web_search/file_search/computer/mcp/namespace/custom/...): 丢弃.
        // 丢弃点就在这里 (reader 层, 同协议 IR 重建与跨协议翻译共用此 choke point —
        // hosted tools 不进 IR.tools, 也不进 extra: collect_extra 的 known 列表含
        // "tools")。只记计数不记内容 (SEC 纪律)。
        let (tools, tools_present) = if let Some(arr) = obj.get("tools").and_then(Value::as_array) {
            let tools: Vec<IrTool> = arr.iter().filter_map(read_tool_def).collect();
            let hosted = arr.len().saturating_sub(tools.len());
            if hosted > 0 {
                tracing::warn!(
                    count = hosted,
                    "dropping tool definition(s) not representable in IR \
                     (hosted tools: web_search/file_search/computer/mcp/..., or \
                     malformed function entries); only well-formed function tools \
                     round-trip through the codec"
                );
            }
            (tools, true)
        } else {
            (Vec::new(), false)
        };

        // extra: 透传顶层未建模字段 (previous_response_id 等; 跨协议前 caller 清空).
        // 注意: tools 是 modeled 字段, 不进 extra; 嵌套字段 (如 input[].encrypted_content)
        // 不被 collect_extra 捕获, 会丢失.
        let extra = collect_extra(
            obj,
            &[
                "model",
                "input",
                "instructions",
                "tools",
                "max_output_tokens",
                "temperature",
                "top_p",
                "tool_choice",
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
            top_k: None, // Responses 无 top_k
            stop: Vec::new(),
            stop_form: None,
            tool_choice,
            user: None, // Responses 无 user 字段
            parallel_tool_calls,
            stream,
            model,
            extra,
        })
    }

    fn read_response(&self, body: &Value) -> Result<IrResponse, IrError> {
        let obj = body
            .as_object()
            .ok_or_else(|| IrError::new("Responses response body must be a JSON object"))?;

        let id = obj.get("id").and_then(Value::as_str).map(String::from);
        let model = obj.get("model").and_then(Value::as_str).map(String::from);
        let created = obj.get("created_at").and_then(Value::as_u64);

        // output[]: items 数组. 每个 item 有 type.
        //   message → output_text content blocks (→ IrBlock::Text)
        //   function_call → IrBlock::ToolUse
        //   reasoning → IrBlock::Reasoning (仅 summary)
        //   其他 (computer_call/file_search_call/web_search_call/...): 静默丢弃
        let mut blocks: Vec<IrBlock> = Vec::new();
        if let Some(outputs) = obj.get("output").and_then(Value::as_array) {
            for item in outputs {
                if let Some(b) = read_output_item(item) {
                    blocks.push(b);
                }
            }
        }

        // status → stop_reason. Responses 的顶层 status 是 completed/incomplete/failed.
        // incomplete_details.reason 给更精确的 stop reason.
        let stop_reason = read_response_status(obj);

        // usage: Responses 用 input_tokens/output_tokens (而非 prompt_tokens/completion_tokens).
        let usage = obj.get("usage").filter(|v| v.is_object()).map(read_usage);
        let usage_present = usage.is_some();
        let usage = usage.unwrap_or_default();
        Ok(IrResponse {
            content: blocks,
            stop_reason,
            stop_sequence: None,
            usage,
            usage_present,
            model,
            id,
            created,
        })
    }

    fn read_response_events(
        &self,
        event_type: &str,
        data: &Value,
        state: &mut super::ir::StreamDecodeState,
    ) -> Vec<super::IrStreamEvent> {
        read_responses_stream_event(event_type, data, &mut state.responses)
    }
}

// ─── Writer ────────────────────────────────────────────────────────────────

pub struct ResponsesWriter;

impl Writer for ResponsesWriter {
    fn name(&self) -> &'static str {
        "responses"
    }

    fn upstream_path(&self) -> &'static str {
        "/v1/responses"
    }

    fn write_request(&self, req: &IrRequest) -> Value {
        let mut out = Map::new();
        out.insert("model".to_string(), Value::String(req.model.clone()));

        // instructions ← system blocks (折叠为 string; Responses 接受 string 或 items).
        if !req.system.is_empty() {
            let text = blocks_to_text(&req.system);
            if !text.is_empty() {
                out.insert("instructions".to_string(), Value::String(text));
            }
        }

        // input ← messages. Responses 的 input 是 items 数组.
        // IR messages → Responses items (message / function_call / function_call_output).
        let items: Vec<Value> = req.messages.iter().flat_map(write_input_items).collect();
        out.insert("input".to_string(), Value::Array(items));

        if let Some(t) = req.max_tokens {
            out.insert("max_output_tokens".to_string(), json!(t));
        }
        if let Some(t) = req.temperature {
            out.insert("temperature".to_string(), json!(t));
        }
        if let Some(p) = req.top_p {
            out.insert("top_p".to_string(), json!(p));
        }
        if req.stream {
            out.insert("stream".to_string(), Value::Bool(true));
        }
        // tools: 仅 function 类型. Responses 平铺形态 (name/parameters 在 top-level).
        if !req.tools.is_empty() {
            let tools: Vec<Value> = req.tools.iter().map(write_tool_def).collect();
            out.insert("tools".to_string(), Value::Array(tools));
            if let Some(p) = req.parallel_tool_calls {
                out.insert("parallel_tool_calls".to_string(), json!(p));
            }
            if let Some(tc) = &req.tool_choice {
                out.insert("tool_choice".to_string(), write_tool_choice(tc));
            }
        } else if req.tools_present {
            out.insert("tools".to_string(), Value::Array(vec![]));
        }
        // extra 同协议时透传 (跨协议在调用前清空).
        for (k, v) in &req.extra {
            out.insert(k.clone(), v.clone());
        }
        Value::Object(out)
    }

    fn write_response(&self, resp: &IrResponse) -> Value {
        // output[]: IR blocks → Responses items.
        // Text → message item (output_text content)
        // ToolUse → function_call item
        // Reasoning → reasoning item (仅 summary)
        // ToolResult / Image → 跳过 (响应里通常不出现)
        let mut output: Vec<Value> = Vec::new();
        let mut text_acc = String::new();
        // flush 累积文本为 message item (用 mem::take 避免无谓 clone, 与 write_input_items 一致).
        let flush_text = |acc: &mut String, out: &mut Vec<Value>| {
            if !acc.is_empty() {
                out.push(json!({
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": std::mem::take(acc)}],
                }));
            }
        };
        for block in &resp.content {
            match block {
                IrBlock::Text { text } => {
                    if !text.is_empty() {
                        text_acc.push_str(text);
                    }
                }
                IrBlock::ToolUse { id, name, input } => {
                    flush_text(&mut text_acc, &mut output);
                    output.push(json!({
                        "type": "function_call",
                        "id": id,
                        "call_id": id,
                        "name": name,
                        "arguments": input_to_string(input),
                        "status": "completed",
                    }));
                }
                IrBlock::Reasoning { summary } => {
                    flush_text(&mut text_acc, &mut output);
                    let summary_items: Vec<Value> = summary
                        .iter()
                        .map(|s| json!({"type": "summary_text", "text": s}))
                        .collect();
                    output.push(json!({
                        "type": "reasoning",
                        "summary": summary_items,
                    }));
                }
                IrBlock::ReasoningContent { .. } => {
                    // Responses reasoning item 依赖 encrypted_content (provider-opaque),
                    // 无法从思考原文合法合成 — 跳过不产出 (lossy-by-target, FWD-3 已知
                    // 损失, 见 codec/AGENTS.md; 与 Reasoning{summary} 的降级同族).
                }
                IrBlock::ToolResult { .. } | IrBlock::Image { .. } => {
                    // 响应里通常不出现, 跳过.
                }
            }
        }
        flush_text(&mut text_acc, &mut output);

        let mut out = Map::new();
        out.insert(
            "id".to_string(),
            Value::String(resp.id.clone().unwrap_or_else(synth_response_id)),
        );
        out.insert("object".to_string(), json!("response"));
        out.insert(
            "created_at".to_string(),
            json!(resp.created.unwrap_or_else(current_epoch)),
        );
        out.insert(
            "model".to_string(),
            Value::String(resp.model.clone().unwrap_or_default()),
        );
        out.insert("status".to_string(), write_status(resp.stop_reason));
        out.insert("output".to_string(), Value::Array(output));
        // usage: IR → Responses 风格 (input_tokens/output_tokens).
        out.insert("usage".to_string(), responses_usage_json(&resp.usage));
        Value::Object(out)
    }

    fn write_response_event(
        &self,
        ev: &super::IrStreamEvent,
        state: &mut super::ir::StreamEncodeState,
    ) -> Vec<(String, Value)> {
        write_responses_stream_event(ev, &mut state.responses)
    }

    fn emits_sse_done_terminator(&self) -> bool {
        // Responses 流以 response.completed / response.failed 事件终止, 不用 [DONE].
        false
    }

    fn write_error(&self, _status: u16, kind: &str, message: &str) -> Value {
        json!({
            "error": {
                "code": kind,
                "message": message,
            }
        })
    }
}

// ─── Helpers: read ─────────────────────────────────────────────────────────

/// 解析 `instructions` 字段 (string 或 items 数组) → system blocks.
/// 假设: instructions 主要是文本; 复杂形态降级为 Text 块.
fn read_instructions(instr: &Value) -> Vec<IrBlock> {
    match instr {
        Value::String(s) if !s.is_empty() => vec![IrBlock::Text { text: s.clone() }],
        Value::Array(arr) => arr
            .iter()
            .filter_map(|item| {
                // instructions items 形如 {"type":"message", "role":"...", "content":[...]}
                // 简化: 取 content 里的文本.
                item.get("content")
                    .and_then(Value::as_array)
                    .and_then(|parts| {
                        let texts: Vec<&str> = parts
                            .iter()
                            .filter_map(|p| {
                                if p.get("type").and_then(Value::as_str) == Some("input_text") {
                                    p.get("text").and_then(Value::as_str)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if texts.is_empty() {
                            None
                        } else {
                            Some(IrBlock::Text {
                                text: texts.join("\n"),
                            })
                        }
                    })
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// 判断 input item 是否是 system/developer message (需提升到 system blocks).
fn is_system_input_item(item: &Value) -> bool {
    item.get("type").and_then(Value::as_str) == Some("message")
        && matches!(
            item.get("role").and_then(Value::as_str),
            Some("system") | Some("developer")
        )
}

/// 解析 input array 中的一个 item → 0..n 条 IR messages.
///
/// 假设: item 是对象且有 type 字段. 未知 type 返回 None (静默丢弃).
/// 降级: reasoning item 的 encrypted_content 忽略, 仅保留 summary 文本.
/// 注意: system/developer message 由 caller (read_request) 提前提升到 system blocks,
///       不会进入本函数.
fn read_input_item(item: &Value) -> Option<Vec<IrMessage>> {
    let obj = item.as_object()?;
    let ty = obj.get("type").and_then(Value::as_str)?;
    match ty {
        "message" => {
            let role_str = obj.get("role").and_then(Value::as_str).unwrap_or("user");
            let role = match role_str {
                "assistant" => IrRole::Assistant,
                "user" => IrRole::User,
                _ => IrRole::User, // system/developer 已被 caller 提前拦截, 这里兜底
            };
            let blocks = read_message_content(obj.get("content"));
            if blocks.is_empty() {
                return None;
            }
            let contains_user_text = role == IrRole::User && blocks_has_text(&blocks);
            Some(vec![IrMessage {
                role,
                content: blocks,
                contains_user_text,
                ..Default::default()
            }])
        }
        "function_call" => {
            let block = read_function_call_block(obj);
            Some(vec![IrMessage {
                role: IrRole::Assistant,
                content: vec![block],
                ..Default::default()
            }])
        }
        "function_call_output" => {
            // 工具结果 → user message 含 ToolResult block.
            let tool_use_id = obj
                .get("call_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            // function_call_output 的 output 字段与 message content 共享同一套 wire 形态.
            let content = read_message_content(obj.get("output"));
            Some(vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error: false,
                    content_form: None,
                }],
                ..Default::default()
            }])
        }
        "reasoning" => {
            // reasoning item: 仅取 summary 文本, 忽略 encrypted_content.
            read_reasoning_block(obj).map(|b| {
                vec![IrMessage {
                    role: IrRole::Assistant,
                    content: vec![b],
                    ..Default::default()
                }]
            })
        }
        // hosted tools / computer_call / file_search_call / ... → 静默丢弃 (降级).
        _ => None,
    }
}

/// 解析 message item 的 content array → IrBlocks.
/// content parts: input_text / output_text / input_image / image_url / refusal.
fn read_message_content(content: Option<&Value>) -> Vec<IrBlock> {
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
        _ => Vec::new(),
    }
}

/// 解析 content array 中的一个 part.
fn read_content_part(part: &Value) -> Option<IrBlock> {
    let part = part.as_object()?;
    let ty = part.get("type").and_then(Value::as_str)?;
    match ty {
        "input_text" | "output_text" | "text" => {
            let text = part.get("text").and_then(Value::as_str).unwrap_or("");
            if text.is_empty() {
                None
            } else {
                Some(IrBlock::Text {
                    text: text.to_string(),
                })
            }
        }
        "input_image" => part
            .get("image_url")
            .and_then(Value::as_str)
            .map(|url| IrBlock::Image {
                source: IrImageSource::Url(url.to_string()),
            }),
        "image_url" => {
            // OpenAI 风格 image_url (object {url: ...}).
            part.get("image_url")
                .and_then(|v| v.get("url"))
                .and_then(Value::as_str)
                .map(|url| IrBlock::Image {
                    source: IrImageSource::Url(url.to_string()),
                })
        }
        "refusal" => {
            // refusal text → Text block (语义降级, 但保留信息).
            let text = part.get("refusal").and_then(Value::as_str).unwrap_or("");
            if text.is_empty() {
                None
            } else {
                Some(IrBlock::Text {
                    text: text.to_string(),
                })
            }
        }
        _ => None, // 未知类型静默丢弃 (ROB-1)
    }
}

/// 解析 reasoning item 的 summary → Vec<String> (仅 summary_text).
fn read_reasoning_summary(summary: Option<&Value>) -> Vec<String> {
    let Some(arr) = summary.and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| {
            if s.get("type").and_then(Value::as_str) == Some("summary_text") {
                s.get("text").and_then(Value::as_str).map(String::from)
            } else {
                None
            }
        })
        .collect()
}

/// 解析 Responses tool 定义 → IrTool.
/// Responses function tool: {type:"function", name, parameters, description, strict?}
/// (注意: Responses 是平铺的, Chat 是嵌套在 function 子对象里).
fn read_tool_def(tool: &Value) -> Option<IrTool> {
    let obj = tool.as_object()?;
    let ty = obj.get("type").and_then(Value::as_str)?;
    if ty != "function" {
        return None; // 非 function 类型静默丢弃 (web_search/file_search/computer/mcp/...)
    }
    let name = obj.get("name").and_then(Value::as_str)?.to_string();
    let description = obj
        .get("description")
        .and_then(Value::as_str)
        .map(String::from);
    let input_schema = obj
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| json!({"type": "object"}));
    Some(IrTool {
        name,
        description,
        input_schema,
    })
}

/// 解析 tool_choice.
/// Responses 的 tool_choice 形态: "auto"|"none"|"required"|{type:"function", name}.
fn read_tool_choice(val: &Value) -> Option<IrToolChoice> {
    match val {
        Value::String(s) => match s.as_str() {
            "auto" => Some(IrToolChoice::Auto),
            "none" => Some(IrToolChoice::None),
            "required" => Some(IrToolChoice::Required),
            _ => None,
        },
        Value::Object(obj) => {
            let ty = obj.get("type").and_then(Value::as_str)?;
            match ty {
                "function" => obj
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|n| IrToolChoice::Tool {
                        name: n.to_string(),
                    }),
                _ => None,
            }
        }
        _ => None,
    }
}

/// 解析 Responses usage 对象 → IrUsage.
/// Responses: {input_tokens, output_tokens, total_tokens, input_tokens_details:{cached_tokens}, output_tokens_details:{reasoning_tokens}}.
fn read_usage(usage: &Value) -> IrUsage {
    let input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cached = usage
        .get("input_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(Value::as_u64);
    // Responses 的 input_tokens 含 cached (与 OpenAI prompt_tokens 同语义),
    // IR 归一化要求 input_tokens 仅含未缓存部分, 这里减去 cached.
    let input_tokens = cached
        .and_then(|c| input_tokens.checked_sub(c))
        .unwrap_or(input_tokens);
    IrUsage {
        input_tokens,
        output_tokens,
        cache_read_input_tokens: cached,
        cache_creation_input_tokens: None, // Responses 不区分 creation/read
    }
}

/// 解析 Responses response 的 status → IrStopReason.
fn read_response_status(obj: &Map<String, Value>) -> Option<IrStopReason> {
    let status = obj.get("status").and_then(Value::as_str)?;
    match status {
        "completed" => Some(IrStopReason::EndTurn),
        "incomplete" => {
            // incomplete_details.reason 给精确原因.
            let reason = obj
                .get("incomplete_details")
                .and_then(|d| d.get("reason"))
                .and_then(Value::as_str);
            match reason {
                Some("max_output_tokens") => Some(IrStopReason::MaxTokens),
                Some("content_filter") => Some(IrStopReason::Safety),
                // 未知 reason: 归到 Other (避免误报为 token 限制).
                _ => Some(IrStopReason::Other),
            }
        }
        "failed" | "cancelled" | "expired" => Some(IrStopReason::Other),
        // in_progress / queued 等中间态: 不映射 stop_reason.
        _ => None,
    }
}

/// 解析 output 数组中的一个 item → IrBlock (或 None 表示跳过).
fn read_output_item(item: &Value) -> Option<IrBlock> {
    let obj = item.as_object()?;
    let ty = obj.get("type").and_then(Value::as_str)?;
    match ty {
        "message" => {
            // 取 content 里的 output_text, 合并为单个 Text block.
            let blocks = read_message_content(obj.get("content"));
            // 多个 Text block 合并为一个 (响应侧通常只一个).
            let text: String = blocks
                .iter()
                .filter_map(|b| {
                    if let IrBlock::Text { text } = b {
                        Some(text.as_str())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("");
            if text.is_empty() {
                None
            } else {
                Some(IrBlock::Text { text })
            }
        }
        "function_call" => Some(read_function_call_block(obj)),
        "reasoning" => read_reasoning_block(obj),
        // computer_call / file_search_call / web_search_call / image_generation_call / ... → 丢弃.
        _ => None,
    }
}

// ─── Helpers: read (streaming) ─────────────────────────────────────────────

/// Responses 流式 SSE 事件 → IR 事件 (fan-out, 0..n), 实现规格 = Responses 流式
/// 支持方案的 D2 映射表.
///
/// 核心映射决策 (rationale 见方案文档; 与非流式 `read_output_item` 的先例对称):
/// - ir_index 全局递增, 按 BlockStart 发出顺序分配, 记录在 state (不可重算);
/// - message item 的 BlockStart 延迟到 `content_part.added` (每 part 一个 IR Text
///   block), BlockStop 在 `content_part.done` 对称配对; `output_item.done(message)`
///   仅兜底关闭未关 part;
/// - function_call / reasoning 的 BlockStart 在 `output_item.added` 即发, BlockStop
///   在 `output_item.done`;
/// - done 族事件 (output_text.done 等) 携带的全量内容不重放 (已由 delta 流入 IR),
///   function_call 例外: 从未流式过 arguments 时用 done item 的全量兜底补发一条.
///
/// 输入假设: `event_type` 是 SSE 帧 `event:` 行的完整名 (`"response.output_text.delta"`
/// 等), 是唯一的 dispatch 依据 — data JSON 里的冗余 `type` 字段不参与判定 (缺失或与
/// event_type 不一致均不影响). Responses SSE 帧恒带 `event:` 行; event_type 为空
/// (OpenAI 风格 bare data 帧) 或未知 → 忽略该事件 (ROB-1, 永不 panic).
fn read_responses_stream_event(
    event_type: &str,
    data: &Value,
    state: &mut ResponsesDecodeState,
) -> Vec<IrStreamEvent> {
    match event_type {
        "response.created" => stream_message_start(data, state),
        "response.output_item.added" => stream_item_added(data, state),
        "response.content_part.added" => stream_part_added(data, state),
        "response.content_part.done" => stream_part_done(data, state),
        "response.output_text.delta" => stream_text_delta(data, state),
        "response.function_call_arguments.delta" => stream_args_delta(data, state),
        "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
            stream_reasoning_delta(data, state)
        }
        "response.output_item.done" => stream_item_done(data, state),
        "response.completed" => {
            let stop = if state.saw_function_call {
                IrStopReason::ToolUse
            } else {
                IrStopReason::EndTurn
            };
            stream_finished(data, stop)
        }
        "response.incomplete" => {
            let resp = data.get("response").unwrap_or(data);
            let stop = resp
                .as_object()
                .and_then(read_response_status)
                .unwrap_or(IrStopReason::Other);
            stream_finished(data, stop)
        }
        "response.failed" => vec![stream_failed(data)],
        "error" => vec![stream_bare_error(data)],
        // 其余全部忽略: 进度噪音 (queued/in_progress) / done 族 (内容已由 delta 流入
        // IR, 含 output_text.done·content_part.done 的全量文本·arguments.done·
        // reasoning 族 done / reasoning_summary_part.added|done) / refusal (无 IR
        // 建模, 与非流式丢弃对称 — 见下方 refusal.delta 的 warn) / hosted tool 各自
        // 的 delta 族 (item 已标 Dropped) / 未知事件.
        "response.refusal.delta" => {
            tracing::warn!(
                count = 1,
                "dropping stream refusal delta not representable in IR"
            );
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// 分配下一个全局 IR block index (按 BlockStart 发出顺序递增, 持久记录不可重算).
fn alloc_ir_index(state: &mut ResponsesDecodeState) -> usize {
    let index = state.next_ir_index;
    state.next_ir_index += 1;
    index
}

/// 提取 message part 的 `(output_index, content_index)` 定位键; 缺任一 → None
/// (该事件忽略, ROB-1).
fn part_key(data: &Value) -> Option<(u64, u64)> {
    Some((
        data.get("output_index").and_then(Value::as_u64)?,
        data.get("content_index").and_then(Value::as_u64)?,
    ))
}

/// `response.created` → `MessageStart` (仅首个 — 后续重复/乱序忽略).
///
/// 假设: data 形如 `{"type":..., "response":{...}}`; response 对象缺失或字段类型
/// 不符时对应字段降级 None, MessageStart 仍发出 (后续 block 事件需要流的头部).
/// usage 恒 None: Responses 的完整 usage 只在 completed/incomplete 事件携带.
fn stream_message_start(data: &Value, state: &mut ResponsesDecodeState) -> Vec<IrStreamEvent> {
    if state.started {
        return Vec::new();
    }
    state.started = true;
    let resp = data.get("response").unwrap_or(data);
    vec![IrStreamEvent::MessageStart {
        usage: None,
        id: resp.get("id").and_then(Value::as_str).map(String::from),
        created: resp.get("created_at").and_then(Value::as_u64),
        model: resp.get("model").and_then(Value::as_str).map(String::from),
    }]
}

/// `response.output_item.added`: 按 item.type 分派.
/// - message → 仅登记归属, 不发事件 (BlockStart 延迟到 content_part.added);
/// - function_call → `BlockStart{ToolUse}` (id 取 call_id 优先, 无则 item.id —
///   客户端以 call_id 关联 function_call_output, 与非流式 `read_function_call_block`
///   一致);
/// - reasoning → `BlockStart{ReasoningContent}`;
/// - hosted tool / 未知 / item 畸形 → Dropped + warn (SEC: 只记计数不记内容,
///   与非流式 read_tool_def / read_output_item 的丢弃点对称).
///
/// 假设: `output_index` 缺失或 added 重复 (病态) → 忽略, 首个登记为准.
fn stream_item_added(data: &Value, state: &mut ResponsesDecodeState) -> Vec<IrStreamEvent> {
    let Some(output_index) = data.get("output_index").and_then(Value::as_u64) else {
        return Vec::new();
    };
    if state.items.contains_key(&output_index) {
        return Vec::new();
    }
    let item = data.get("item");
    let ty = item.and_then(|i| i.get("type")).and_then(Value::as_str);
    match ty {
        Some("message") => {
            state.items.insert(output_index, StreamItemState::Message);
            Vec::new()
        }
        Some("function_call") => {
            let ir_index = alloc_ir_index(state);
            let obj = item.and_then(Value::as_object);
            let field = |k: &str| obj.and_then(|o| o.get(k)).and_then(Value::as_str);
            // call_id 优先于 id (两者都可能出现).
            let id = field("call_id").or_else(|| field("id")).unwrap_or_default();
            let name = field("name").unwrap_or_default();
            state.saw_function_call = true;
            state.items.insert(
                output_index,
                StreamItemState::FunctionCall {
                    ir_index,
                    args_delta_seen: false,
                },
            );
            vec![IrStreamEvent::BlockStart {
                index: ir_index,
                block: IrBlockMeta::ToolUse {
                    id: id.to_string(),
                    name: name.to_string(),
                },
            }]
        }
        Some("reasoning") => {
            let ir_index = alloc_ir_index(state);
            state
                .items
                .insert(output_index, StreamItemState::Reasoning { ir_index });
            vec![IrStreamEvent::BlockStart {
                index: ir_index,
                block: IrBlockMeta::ReasoningContent,
            }]
        }
        _ => {
            state.items.insert(output_index, StreamItemState::Dropped);
            tracing::warn!(
                count = 1,
                "dropping stream output item not representable in IR \
                 (hosted tools: web_search/file_search/computer/mcp/..., or unknown type)"
            );
            Vec::new()
        }
    }
}

/// `response.content_part.added`: output_text part → `BlockStart{Text}`;
/// refusal / 未知 part 类型 / 父 item 非 message 的游离 part → 不登记 + warn
/// (后续 delta/done 查不到映射自然忽略, ROB 降级 — content_part.done 对被跳过的
/// part 也不发 BlockStop).
/// 假设: 定位键缺失或重复 added (病态) → 忽略.
fn stream_part_added(data: &Value, state: &mut ResponsesDecodeState) -> Vec<IrStreamEvent> {
    let Some(key) = part_key(data) else {
        return Vec::new();
    };
    // 仅当父 item 已登记为 message 时受理 (part 事件语义上隶属于 message item);
    // 病态游离 part (父 item 缺席 / 归属 function_call 等) 忽略, 防止产出游离
    // Text block 且条目滞留 part_ir_index (output_item.done 的兜底清扫只覆盖
    // message arm).
    if !matches!(state.items.get(&key.0), Some(StreamItemState::Message)) {
        tracing::warn!(
            count = 1,
            "dropping stream content part not representable in IR (orphan part without message item)"
        );
        return Vec::new();
    }
    let is_text = data
        .get("part")
        .and_then(|p| p.get("type"))
        .and_then(Value::as_str)
        == Some("output_text");
    if !is_text {
        tracing::warn!(
            count = 1,
            "dropping stream content part not representable in IR (refusal or unknown part type)"
        );
        return Vec::new();
    }
    if state.part_ir_index.contains_key(&key) {
        return Vec::new();
    }
    let ir_index = alloc_ir_index(state);
    state.part_ir_index.insert(key, ir_index);
    vec![IrStreamEvent::BlockStart {
        index: ir_index,
        block: IrBlockMeta::Text,
    }]
}

/// `response.content_part.done`: 与 content_part.added 对称配对的 `BlockStop`.
/// part 被跳过 (refusal 等) 或重复 done (病态) → 查不到映射, 不发.
fn stream_part_done(data: &Value, state: &mut ResponsesDecodeState) -> Vec<IrStreamEvent> {
    let Some(key) = part_key(data) else {
        return Vec::new();
    };
    match state.part_ir_index.remove(&key) {
        Some(ir_index) => vec![IrStreamEvent::BlockStop { index: ir_index }],
        None => Vec::new(),
    }
}

/// `response.output_text.delta` → `BlockDelta{TextDelta}`.
/// 病态流 (未见 content_part.added / delta 缺失或空) → 忽略, 不 panic.
fn stream_text_delta(data: &Value, state: &ResponsesDecodeState) -> Vec<IrStreamEvent> {
    let Some(key) = part_key(data) else {
        return Vec::new();
    };
    match (
        state.part_ir_index.get(&key),
        data.get("delta").and_then(Value::as_str),
    ) {
        (Some(&ir_index), Some(d)) if !d.is_empty() => vec![IrStreamEvent::BlockDelta {
            index: ir_index,
            delta: IrDelta::TextDelta(d.to_string()),
        }],
        _ => Vec::new(),
    }
}

/// `response.function_call_arguments.delta` → `BlockDelta{InputJsonDelta}` + 标记
/// args_delta_seen. 仅**非空** delta 标记 seen (空 delta 不构成"已流式"证据 —
/// done 兜底补全量更安全). 病态 (未见 item.added / delta 缺失或空) → 忽略.
fn stream_args_delta(data: &Value, state: &mut ResponsesDecodeState) -> Vec<IrStreamEvent> {
    let Some(output_index) = data.get("output_index").and_then(Value::as_u64) else {
        return Vec::new();
    };
    match (
        state.items.get_mut(&output_index),
        data.get("delta").and_then(Value::as_str),
    ) {
        (
            Some(StreamItemState::FunctionCall {
                ir_index,
                args_delta_seen,
            }),
            Some(d),
        ) if !d.is_empty() => {
            *args_delta_seen = true;
            vec![IrStreamEvent::BlockDelta {
                index: *ir_index,
                delta: IrDelta::InputJsonDelta(d.to_string()),
            }]
        }
        _ => Vec::new(),
    }
}

/// `response.reasoning_summary_text.delta` / `response.reasoning_text.delta` →
/// `BlockDelta{ReasoningDelta}` (summary 与思考原文两种形态归一, IR 无区分维度 —
/// 已知损失, 重合成侧事件类型可能变化但内容保留).
/// 定位键是 output_index (item 级). 病态 (未见 item.added / delta 缺失或空) → 忽略.
fn stream_reasoning_delta(data: &Value, state: &ResponsesDecodeState) -> Vec<IrStreamEvent> {
    let Some(output_index) = data.get("output_index").and_then(Value::as_u64) else {
        return Vec::new();
    };
    match (
        state.items.get(&output_index),
        data.get("delta").and_then(Value::as_str),
    ) {
        (Some(StreamItemState::Reasoning { ir_index }), Some(d)) if !d.is_empty() => {
            vec![IrStreamEvent::BlockDelta {
                index: *ir_index,
                delta: IrDelta::ReasoningDelta(d.to_string()),
            }]
        }
        _ => Vec::new(),
    }
}

/// `response.output_item.done`: 按 item 状态收尾.
/// - function_call → 兜底补发 (从未收到非空 args delta 且 done item 的 arguments
///   非空 → 补一条全量 `InputJsonDelta`) + `BlockStop`;
/// - reasoning → `BlockStop` (reasoning 无 part 级事件);
/// - message → 兜底关闭仍未关闭的 part (正常路径已由 content_part.done 关闭, 无事件);
/// - Dropped / 未见 added (病态) → 忽略.
fn stream_item_done(data: &Value, state: &mut ResponsesDecodeState) -> Vec<IrStreamEvent> {
    let Some(output_index) = data.get("output_index").and_then(Value::as_u64) else {
        return Vec::new();
    };
    match state.items.remove(&output_index) {
        Some(StreamItemState::FunctionCall {
            ir_index,
            args_delta_seen,
        }) => {
            let mut events = Vec::new();
            let args = data
                .get("item")
                .and_then(|i| i.get("arguments"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if !args_delta_seen && !args.is_empty() {
                events.push(IrStreamEvent::BlockDelta {
                    index: ir_index,
                    delta: IrDelta::InputJsonDelta(args.to_string()),
                });
            }
            events.push(IrStreamEvent::BlockStop { index: ir_index });
            events
        }
        Some(StreamItemState::Reasoning { ir_index }) => {
            vec![IrStreamEvent::BlockStop { index: ir_index }]
        }
        Some(StreamItemState::Message) => {
            let mut events = Vec::new();
            let stale: Vec<(u64, u64)> = state
                .part_ir_index
                .range((output_index, u64::MIN)..=(output_index, u64::MAX))
                .map(|(k, _)| *k)
                .collect();
            for key in stale {
                if let Some(ir_index) = state.part_ir_index.remove(&key) {
                    events.push(IrStreamEvent::BlockStop { index: ir_index });
                }
            }
            events
        }
        Some(StreamItemState::Dropped) | None => Vec::new(),
    }
}

/// `response.completed` / `response.incomplete` 的公共尾部:
/// `MessageDelta{stop_reason, usage, usage_present}` + `MessageStop`.
/// stop_reason 由调用方推断 (completed: 已见 function_call → ToolUse, 否则 EndTurn;
/// incomplete: 复用非流式 `read_response_status` 的映射). usage 提取与非流式一致.
fn stream_finished(data: &Value, stop_reason: IrStopReason) -> Vec<IrStreamEvent> {
    let resp = data.get("response").unwrap_or(data);
    let usage = resp.get("usage").filter(|v| v.is_object()).map(read_usage);
    let usage_present = usage.is_some();
    vec![
        IrStreamEvent::MessageDelta {
            stop_reason: Some(stop_reason),
            stop_sequence: None,
            usage: usage.unwrap_or_default(),
            usage_present,
        },
        IrStreamEvent::MessageStop,
    ]
}

/// `response.failed` 的错误消息: `response.error` 的 message 优先, 缺省 code, 再
/// 缺省固定文案 (上游错误透传, 不含 secret-guard 侧内容).
fn stream_failed(data: &Value) -> IrStreamEvent {
    let error = data.get("response").and_then(|r| r.get("error"));
    let msg = error
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .or_else(|| error.and_then(|e| e.get("code")).and_then(Value::as_str))
        .unwrap_or("upstream response failed");
    IrStreamEvent::Error(msg.to_string())
}

/// 裸 `error` 事件 (非标形态, 非 `response.` 前缀): `data.error.message` 优先,
/// 缺省顶层 message (与 anthropic reader 的 error 事件处理同型).
fn stream_bare_error(data: &Value) -> IrStreamEvent {
    let msg = data
        .get("error")
        .and_then(|e| e.get("message"))
        .or_else(|| data.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("upstream stream error");
    IrStreamEvent::Error(msg.to_string())
}

// ─── Helpers: write ────────────────────────────────────────────────────────

/// 解析 Responses function_call item 的公共字段 → IrBlock::ToolUse.
///
/// request input items 和 response output items 都用此 helper (字段名一致).
/// `call_id` 优先于 `id` (Responses 响应里两者都可能出现).
/// arguments 是 JSON 字符串, parse 失败降级为 Null (ROB-1).
fn read_function_call_block(obj: &Map<String, Value>) -> IrBlock {
    let id = obj
        .get("call_id")
        .or_else(|| obj.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let input = obj
        .get("arguments")
        .and_then(|v| serde_json::from_str::<Value>(v.as_str().unwrap_or("null")).ok())
        .unwrap_or(Value::Null);
    IrBlock::ToolUse { id, name, input }
}

/// 解析 reasoning item 的 summary → IrBlock::Reasoning (空 summary 返回 None).
///
/// request input items 和 response output items 都用此 helper.
/// `encrypted_content` 不保留 (见 ir.rs IrBlock::Reasoning 注释).
fn read_reasoning_block(obj: &Map<String, Value>) -> Option<IrBlock> {
    let summary = read_reasoning_summary(obj.get("summary"));
    if summary.is_empty() {
        None
    } else {
        Some(IrBlock::Reasoning { summary })
    }
}

/// IR message → Responses input items (一条 IR message 可能产出多个 items).
///
/// 关键: OpenAI Chat 的 assistant tool_calls 数组在 Responses 里是独立的 function_call items.
fn write_input_items(msg: &IrMessage) -> Vec<Value> {
    match msg.role {
        IrRole::System => {
            // system 已在 instructions 输出, 这里跳过 (避免重复).
            Vec::new()
        }
        IrRole::User => {
            // user 消息可能含 Text / Image / ToolResult 块.
            // ToolResult → function_call_output item; 其余 → message item.
            let mut items = Vec::new();
            let mut content_parts: Vec<Value> = Vec::new();
            for b in &msg.content {
                match b {
                    IrBlock::Text { text } => {
                        if !text.is_empty() {
                            content_parts.push(json!({"type": "input_text", "text": text}));
                        }
                    }
                    IrBlock::Image { source } => {
                        if let IrImageSource::Url(u) = source {
                            content_parts.push(json!({"type": "input_image", "image_url": u}));
                        }
                    }
                    IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                        ..
                    } => {
                        // 先 flush 累积的 content parts 为 message item.
                        if !content_parts.is_empty() {
                            items.push(json!({
                                "type": "message",
                                "role": "user",
                                "content": content_parts.clone(),
                            }));
                            content_parts.clear();
                        }
                        let text = blocks_to_text(content);
                        let output_val = if *is_error {
                            json!(format!("[error] {text}"))
                        } else {
                            Value::String(text)
                        };
                        items.push(json!({
                            "type": "function_call_output",
                            "call_id": tool_use_id,
                            "output": output_val,
                        }));
                    }
                    IrBlock::ToolUse { .. } | IrBlock::Reasoning { .. } => {
                        // user 消息里通常不出现, 跳过.
                    }
                    IrBlock::ReasoningContent { .. } => {
                        // user 消息里通常不出现 (思考原文属 assistant), 跳过.
                    }
                }
            }
            if !content_parts.is_empty() {
                items.push(json!({
                    "type": "message",
                    "role": "user",
                    "content": content_parts,
                }));
            }
            items
        }
        IrRole::Assistant => {
            // assistant 消息: Text/Reasoning + ToolUse 块.
            // ToolUse → function_call item; Text → message item; Reasoning → reasoning item.
            // 连续的 Text 块累积到一个 message item 的 content parts 里 (保留 part 边界).
            let mut items = Vec::new();
            let mut text_parts: Vec<Value> = Vec::new();
            let flush_text = |parts: &mut Vec<Value>, items: &mut Vec<Value>| {
                if !parts.is_empty() {
                    items.push(json!({
                        "type": "message",
                        "role": "assistant",
                        "content": std::mem::take(parts),
                    }));
                }
            };
            for b in &msg.content {
                match b {
                    IrBlock::Text { text } => {
                        if !text.is_empty() {
                            text_parts.push(json!({"type": "output_text", "text": text}));
                        }
                    }
                    IrBlock::ToolUse { id, name, input } => {
                        flush_text(&mut text_parts, &mut items);
                        items.push(json!({
                            "type": "function_call",
                            "call_id": id,
                            "name": name,
                            "arguments": input_to_string(input),
                        }));
                    }
                    IrBlock::Reasoning { summary } => {
                        flush_text(&mut text_parts, &mut items);
                        let summary_items: Vec<Value> = summary
                            .iter()
                            .map(|s| json!({"type": "summary_text", "text": s}))
                            .collect();
                        items.push(json!({"type": "reasoning", "summary": summary_items}));
                    }
                    IrBlock::ReasoningContent { .. } => {
                        // 跳过: Responses reasoning item 依赖 encrypted_content, 无法从
                        // 思考原文合法合成 (见 write_response 同款分支).
                    }
                    IrBlock::ToolResult { .. } | IrBlock::Image { .. } => {
                        // assistant 消息里通常不出现, 跳过.
                    }
                }
            }
            flush_text(&mut text_parts, &mut items);
            items
        }
        IrRole::Tool => {
            // IR 的 Tool role 在 Responses 里没有直接对应; 视为 user 的 function_call_output.
            // (正常路径 reader 已把 tool result 归一化为 User + ToolResult block, 不会出现 Tool role.)
            Vec::new()
        }
    }
}

/// IR Tool → Responses tool 定义 (平铺形态).
fn write_tool_def(tool: &IrTool) -> Value {
    let mut obj = Map::new();
    obj.insert("type".to_string(), json!("function"));
    obj.insert("name".to_string(), Value::String(tool.name.clone()));
    if let Some(desc) = &tool.description {
        obj.insert("description".to_string(), Value::String(desc.clone()));
    }
    obj.insert("parameters".to_string(), tool.input_schema.clone());
    Value::Object(obj)
}

/// IR tool_choice → Responses tool_choice wire.
fn write_tool_choice(tc: &IrToolChoice) -> Value {
    match tc {
        IrToolChoice::Auto => json!("auto"),
        IrToolChoice::None => json!("none"),
        IrToolChoice::Required => json!("required"),
        IrToolChoice::Tool { name } => json!({"type": "function", "name": name}),
    }
}

/// IrStopReason → Responses status 字符串 (str 形态 SSOT — 非流式 `write_response`
/// 与流式 `response.completed` 骨架共用, 集中避免两处映射漂移).
fn write_status_str(reason: Option<IrStopReason>) -> &'static str {
    match reason {
        None | Some(IrStopReason::EndTurn) | Some(IrStopReason::StopSequence) => "completed",
        Some(IrStopReason::MaxTokens) => "incomplete",
        Some(IrStopReason::ToolUse) => "completed", // 工具调用也算 completed
        Some(IrStopReason::Safety) | Some(IrStopReason::Refusal) => "incomplete",
        Some(IrStopReason::Other) => "failed",
    }
}

/// IrStopReason → Responses status 字符串 (Value 形态, 非流式 `write_response` 用).
fn write_status(reason: Option<IrStopReason>) -> Value {
    json!(write_status_str(reason))
}

/// IR usage → Responses 风格 usage JSON ({input_tokens, output_tokens, total_tokens}).
fn responses_usage_json(u: &IrUsage) -> Value {
    let input_total = u.input_tokens + u.cache_read_input_tokens.unwrap_or(0);
    json!({
        "input_tokens": input_total,
        "output_tokens": u.output_tokens,
        "total_tokens": input_total + u.output_tokens,
    })
}

/// 合成 response id (resp_ 前缀 + base62).
fn synth_response_id() -> String {
    format!("resp_{}", random_base62(24))
}

// ─── Helpers: write (streaming) ─────────────────────────────────────────────

/// IR 事件 → Responses SSE 帧序列 (fan-out, 0..n), 实现规格 = Responses 流式
/// 支持方案的 D3 合成表 (与 reader 侧 `read_responses_stream_event` 对称的逆映射).
///
/// 核心合成决策 (rationale 见方案文档):
/// - **有状态累积**: done 族帧 (`output_item.done` / 终止事件) 携带全量
///   item/response, 内容由 `ResponsesEncodeState` 按 IR block index 累积;
/// - **1 IR 事件 → 0..n 帧**: `BlockStart{Text}` 产出 item + part 两帧,
///   `BlockStop` 产出 done 族 2-3 帧, `MessageDelta` 缓存不发帧;
/// - **终止事件 type 按 status 分派**: completed / incomplete / failed 三分
///   (incomplete_details 只随 incomplete 事件携带, 与 reader 侧分支对称);
/// - **item_id 确定性合成**: `msg_{n}` / `fc_{n}` / `rs_{n}` (n = 全局 item 序号),
///   ToolUse 的 `call_id` = IR id (round-trip 关联键);
/// - **output_index = IR block index**, `content_index`/`summary_index` 恒 0
///   (每 part 一个 block 的折叠逆操作), `sequence_number` 省略 (SDK 不依赖).
///
/// 幂等契约 (T1 移交): translate 层对 BlockStart 有探测调用 (非空 → 同一事件再次
/// 调用), 注册点在 [`stream_write_block_start`] 内幂等 (详见 state 字段注释).
/// 病态 IR 流 (BlockStart/Delta/Stop 先于 MessageStart / 孤儿 BlockStop /
/// delta-kind 与 item-kind 错配) 全部宽容降级, 永不 panic (ROB-*).
fn write_responses_stream_event(
    ev: &IrStreamEvent,
    state: &mut ResponsesEncodeState,
) -> Vec<(String, Value)> {
    match ev {
        IrStreamEvent::MessageStart {
            id, created, model, ..
        } => stream_write_message_start(id, created, model, state),
        IrStreamEvent::BlockStart { index, block } => {
            stream_write_block_start(*index, block, state)
        }
        IrStreamEvent::BlockDelta { index, delta } => {
            stream_write_block_delta(*index, delta, state)
        }
        IrStreamEvent::BlockStop { index } => stream_write_block_stop(*index, state),
        IrStreamEvent::MessageDelta {
            stop_reason,
            usage,
            usage_present,
            ..
        } => {
            // 缓存终止信息, 不发帧 (汇总在 MessageStop 的终止事件).
            // "带信息的 delta 获胜": stop_reason 仅 Some 时覆盖; usage 在
            // present=true (显式回显, 即使全零) 或携带非零值时覆盖 — 防护
            // 针对 present=false 的全零 delta (病态) 冲掉真值.
            if stop_reason.is_some() {
                state.stop_reason = *stop_reason;
            }
            if *usage_present || !usage.is_zero() {
                state.usage = usage.clone();
                state.usage_present = *usage_present;
            }
            Vec::new()
        }
        IrStreamEvent::MessageStop => {
            // 终止事件 type = `response.{status}` (官方 wire 语义: incomplete/failed
            // 状态用对应事件承载, 客户端 SDK 按事件 type 分派; 恒发 completed 会让
            // incomplete_details 被 status-completed 处理路径忽略 — reader 侧同理,
            // 只有 `response.incomplete` 分支读 incomplete_details).
            let event_type = format!("response.{}", write_status_str(state.stop_reason));
            vec![(
                event_type.clone(),
                json!({
                    "type": event_type,
                    "response": stream_write_terminal_response(state),
                }),
            )]
        }
        IrStreamEvent::Error(msg) => stream_write_error(msg, state),
    }
}

/// `MessageStart` → `response.created` (response 骨架: status=in_progress,
/// output=[], usage=null), 同时捕获元信息 (首个为准, 不覆盖 — 幂等安全).
/// MessageStart 携带的 usage 忽略: Responses 的完整 usage 只在 completed 携带
/// (translate 层的 terminal backfill 已保证 input_tokens 落到 terminal delta).
fn stream_write_message_start(
    id: &Option<String>,
    created: &Option<u64>,
    model: &Option<String>,
    state: &mut ResponsesEncodeState,
) -> Vec<(String, Value)> {
    if state.id.is_none() {
        state.id = id.clone();
    }
    if state.created.is_none() {
        state.created = *created;
    }
    if state.model.is_none() {
        state.model = model.clone();
    }
    vec![(
        "response.created".to_string(),
        json!({
            "type": "response.created",
            "response": response_skeleton(state, "in_progress"),
        }),
    )]
}

/// `BlockStart` → added 族帧 (message 额外产 part 帧).
///
/// 幂等契约落点: 已注册的 index 不重复注册/不覆盖、`next_item_seq` 不重复递增,
/// 两次调用返回的帧因 item_id 确定性而完全一致 (探测调用的帧被丢弃也无害).
fn stream_write_block_start(
    index: usize,
    block: &IrBlockMeta,
    state: &mut ResponsesEncodeState,
) -> Vec<(String, Value)> {
    if !state.items.contains_key(&index) {
        let seq = state.next_item_seq;
        state.next_item_seq += 1;
        let accum = match block {
            IrBlockMeta::Text => {
                ResponsesItemAccum::simple(ResponsesItemKind::Message, format!("msg_{seq}"))
            }
            IrBlockMeta::ToolUse { id, name } => ResponsesItemAccum {
                kind: ResponsesItemKind::FunctionCall,
                item_id: format!("fc_{seq}"),
                call_id: id.clone(),
                name: name.clone(),
                content: String::new(),
            },
            IrBlockMeta::ReasoningContent => {
                ResponsesItemAccum::simple(ResponsesItemKind::Reasoning, format!("rs_{seq}"))
            }
        };
        state.items.insert(index, accum);
    }
    let accum = state
        .items
        .get(&index)
        .expect("item registered immediately above");
    let item_added = |item: Value| {
        json!({
            "type": "response.output_item.added",
            "output_index": index,
            "item": item,
        })
    };
    match accum.kind {
        ResponsesItemKind::Message => vec![
            (
                "response.output_item.added".to_string(),
                item_added(json!({
                    "id": accum.item_id,
                    "type": "message",
                    "status": "in_progress",
                    "role": "assistant",
                    "content": [],
                })),
            ),
            (
                "response.content_part.added".to_string(),
                json!({
                    "type": "response.content_part.added",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "content_index": 0,
                    "part": {"type": "output_text", "text": "", "annotations": []},
                }),
            ),
        ],
        ResponsesItemKind::FunctionCall => vec![(
            "response.output_item.added".to_string(),
            item_added(json!({
                "id": accum.item_id,
                "type": "function_call",
                "status": "in_progress",
                "call_id": accum.call_id,
                "name": accum.name,
                "arguments": "",
            })),
        )],
        ResponsesItemKind::Reasoning => vec![
            (
                "response.output_item.added".to_string(),
                item_added(json!({
                    "id": accum.item_id,
                    "type": "reasoning",
                    "status": "in_progress",
                    "summary": [],
                })),
            ),
            // summary part 的 added/done 配对帧 (官方 reasoning 序列含此事件,
            // 与 message 的 content_part.added 对称; reader 侧忽略之).
            (
                "response.reasoning_summary_part.added".to_string(),
                json!({
                    "type": "response.reasoning_summary_part.added",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "summary_index": 0,
                    "part": {"type": "summary_text", "text": ""},
                }),
            ),
        ],
    }
}

/// `BlockDelta` → delta 族帧 + 内容累积到 `ItemAccum.content`.
/// delta 类型与 item kind 错配 (病态 IR 流) / 未知 index (Delta 先于 Start) →
/// 丢弃 (纵深防御, 不 panic).
fn stream_write_block_delta(
    index: usize,
    delta: &IrDelta,
    state: &mut ResponsesEncodeState,
) -> Vec<(String, Value)> {
    let Some(accum) = state.items.get_mut(&index) else {
        return Vec::new();
    };
    match (delta, accum.kind) {
        (IrDelta::TextDelta(d), ResponsesItemKind::Message) => {
            accum.content.push_str(d);
            vec![(
                "response.output_text.delta".to_string(),
                json!({
                    "type": "response.output_text.delta",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "content_index": 0,
                    "delta": d,
                }),
            )]
        }
        (IrDelta::InputJsonDelta(d), ResponsesItemKind::FunctionCall) => {
            accum.content.push_str(d);
            vec![(
                "response.function_call_arguments.delta".to_string(),
                json!({
                    "type": "response.function_call_arguments.delta",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "delta": d,
                }),
            )]
        }
        (IrDelta::ReasoningDelta(d), ResponsesItemKind::Reasoning) => {
            accum.content.push_str(d);
            vec![(
                "response.reasoning_summary_text.delta".to_string(),
                json!({
                    "type": "response.reasoning_summary_text.delta",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "summary_index": 0,
                    "delta": d,
                }),
            )]
        }
        _ => Vec::new(),
    }
}

/// `BlockStop` → done 族帧 (全量内容, 从 `ItemAccum` 读取; 不移除条目 —
/// 终止事件的 output 重建仍需要).
/// 孤儿 BlockStop (无 ItemAccum 记录, 即 BlockStop 先于 BlockStart 的病态序列;
/// Responses writer 自身的 BlockStart 恒产帧, 不会进 translate 层的配对过滤
/// 跳过集合) → 空 Vec (纵深防御).
fn stream_write_block_stop(index: usize, state: &mut ResponsesEncodeState) -> Vec<(String, Value)> {
    let Some(accum) = state.items.get(&index) else {
        return Vec::new();
    };
    let item_done = || {
        json!({
            "type": "response.output_item.done",
            "output_index": index,
            "item": completed_item_json(accum),
        })
    };
    match accum.kind {
        ResponsesItemKind::Message => vec![
            (
                "response.output_text.done".to_string(),
                json!({
                    "type": "response.output_text.done",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "content_index": 0,
                    "text": accum.content,
                }),
            ),
            (
                "response.content_part.done".to_string(),
                json!({
                    "type": "response.content_part.done",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "content_index": 0,
                    "part": {"type": "output_text", "text": accum.content, "annotations": []},
                }),
            ),
            ("response.output_item.done".to_string(), item_done()),
        ],
        ResponsesItemKind::FunctionCall => vec![
            (
                "response.function_call_arguments.done".to_string(),
                json!({
                    "type": "response.function_call_arguments.done",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "arguments": accum.content,
                }),
            ),
            ("response.output_item.done".to_string(), item_done()),
        ],
        ResponsesItemKind::Reasoning => vec![
            (
                "response.reasoning_summary_text.done".to_string(),
                json!({
                    "type": "response.reasoning_summary_text.done",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "summary_index": 0,
                    "text": accum.content,
                }),
            ),
            (
                "response.reasoning_summary_part.done".to_string(),
                json!({
                    "type": "response.reasoning_summary_part.done",
                    "item_id": accum.item_id,
                    "output_index": index,
                    "summary_index": 0,
                    "part": {"type": "summary_text", "text": accum.content},
                }),
            ),
            ("response.output_item.done".to_string(), item_done()),
        ],
    }
}

/// `MessageStop` → 终止事件 (`response.completed` / `response.incomplete` /
/// `response.failed`, type 由调用方按 status 分派) 的 response 全量对象:
/// 骨架 + status (`write_status_str` 映射) + output 全量重建 (items 按 index 升序)
/// + usage (cached, 无条件写全量对象 — 与非流式 `write_response` 一致)
/// + incomplete_details (MaxTokens/Safety/Refusal 时给 reason, 其余 null).
///
/// 注意: stop_reason=Other 走 `response.failed` 但**不合成 error 对象** (IR 无
/// 错误信息可编造, 与非流式 status=failed 无 error 的先例一致); reader 侧读到
/// 后经 `stream_failed` 兜底文案转 Error 事件 — Other→Error 的往返漂移是已接受
/// 的语义传达 (无法识别的终止 ≈ 失败).
fn stream_write_terminal_response(state: &mut ResponsesEncodeState) -> Value {
    let mut resp = response_skeleton(state, write_status_str(state.stop_reason));
    let obj = resp.as_object_mut().expect("skeleton is always an object");
    obj.insert(
        "incomplete_details".to_string(),
        match state.stop_reason {
            Some(IrStopReason::MaxTokens) => json!({"reason": "max_output_tokens"}),
            // Refusal 无官方 reason 对应, 归 content_filter (reader 读回 Safety —
            // Refusal→Safety 的往返损失已知, Responses wire 无更精确的表达).
            Some(IrStopReason::Safety) | Some(IrStopReason::Refusal) => {
                json!({"reason": "content_filter"})
            }
            _ => Value::Null,
        },
    );
    obj.insert(
        "output".to_string(),
        Value::Array(
            state
                .items
                .values()
                .map(completed_item_json)
                .collect::<Vec<_>>(),
        ),
    );
    obj.insert("usage".to_string(), responses_usage_json(&state.usage));
    resp
}

/// `Error` → 两帧: 裸 `error` 事件 + `response.failed` (骨架 + status=failed +
/// error 对象). message 截断 (char boundary 安全, 接收端可感知).
fn stream_write_error(msg: &str, state: &mut ResponsesEncodeState) -> Vec<(String, Value)> {
    let truncated = crate::util::truncate_chars_with_ellipsis(msg, 256);
    let mut resp = response_skeleton(state, "failed");
    resp.as_object_mut()
        .expect("skeleton is always an object")
        .insert(
            "error".to_string(),
            json!({"code": "upstream_error", "message": truncated}),
        );
    vec![
        (
            "error".to_string(),
            json!({
                "type": "error",
                "code": "upstream_error",
                "message": truncated,
            }),
        ),
        (
            "response.failed".to_string(),
            json!({
                "type": "response.failed",
                "response": resp,
            }),
        ),
    ]
}

/// response 骨架对象 (created / completed / failed 共用基础形态).
///
/// `id`/`created` 首次需要时隐式初始化 (synth id / now) **并写回 state** — 后续
/// 帧复用同值, 保证整条流内 response 元信息一致 (MessageStart 缺席或字段为 None
/// 的病态流也能闭合). `model` 缺省空串 (格式中立, 无随机量).
fn response_skeleton(state: &mut ResponsesEncodeState, status: &str) -> Value {
    let id = state.id.get_or_insert_with(synth_response_id).clone();
    let created = state.created.get_or_insert_with(current_epoch);
    let model = state.model.get_or_insert_with(String::new).clone();
    json!({
        "id": id,
        "object": "response",
        "created_at": created,
        "status": status,
        "error": null,
        "incomplete_details": null,
        "model": model,
        "output": [],
        "usage": null,
    })
}

/// `ItemAccum` → 全量 item JSON (`output_item.done` 帧与 `response.completed` 的
/// output 重建共用; status=completed, content/summary/arguments 均为累积全量).
fn completed_item_json(accum: &ResponsesItemAccum) -> Value {
    match accum.kind {
        ResponsesItemKind::Message => json!({
            "id": accum.item_id,
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": accum.content, "annotations": []}],
        }),
        ResponsesItemKind::FunctionCall => json!({
            "id": accum.item_id,
            "type": "function_call",
            "status": "completed",
            "call_id": accum.call_id,
            "name": accum.name,
            "arguments": accum.content,
        }),
        ResponsesItemKind::Reasoning => json!({
            "id": accum.item_id,
            "type": "reasoning",
            "status": "completed",
            "summary": [{"type": "summary_text", "text": accum.content}],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn reader() -> ResponsesReader {
        ResponsesReader
    }
    fn writer() -> ResponsesWriter {
        ResponsesWriter
    }

    // ─── read_request: 基础映射 ──────────────────────────────────────────

    // ─── usage_present (USAGE-2: presence 语义, usage-stats 采集) ─────────
    //

    #[test]
    fn read_response_usage_present_semantics() {
        // 显式全零 usage → present; 缺席 → absent.
        let present = reader()
            .read_response(&json!({
                "id": "resp_1", "model": "gpt-4o", "status": "completed",
                "output": [], "usage": {"input_tokens": 0, "output_tokens": 0},
            }))
            .unwrap();
        assert!(present.usage_present);
        let absent = reader()
            .read_response(&json!({
                "id": "resp_1", "model": "gpt-4o", "status": "completed", "output": [],
            }))
            .unwrap();
        assert!(!absent.usage_present);
    }

    #[test]
    fn read_request_basic_chat() {
        let body = json!({
            "model": "gpt-4o",
            "instructions": "You are helpful.",
            "input": [{"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "Hello"}
            ]}],
            "max_output_tokens": 100,
            "temperature": 0.7,
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.model, "gpt-4o");
        assert_eq!(ir.system.len(), 1);
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(ir.max_tokens, Some(100));
        assert_eq!(ir.temperature, Some(0.7));
    }

    #[test]
    fn read_request_string_input() {
        // input 是纯字符串 → 单条 user message.
        let body = json!({
            "model": "gpt-4o",
            "input": "Hello"
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(ir.messages[0].role, IrRole::User);
        match &ir.messages[0].content[0] {
            IrBlock::Text { text } => assert_eq!(text, "Hello"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn read_request_function_call_item() {
        // 历史工具调用 → assistant ToolUse.
        let body = json!({
            "model": "gpt-4o",
            "input": [
                {"type": "message", "role": "user", "content": "weather?"},
                {"type": "function_call", "call_id": "call_1", "name": "get_weather",
                 "arguments": "{\"city\":\"SF\"}"}
            ]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.messages.len(), 2);
        assert_eq!(ir.messages[1].role, IrRole::Assistant);
        match &ir.messages[1].content[0] {
            IrBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "get_weather");
                assert_eq!(input, &json!({"city": "SF"}));
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn read_request_function_call_output_item() {
        // 工具结果 → user ToolResult.
        let body = json!({
            "model": "gpt-4o",
            "input": [
                {"type": "function_call_output", "call_id": "call_1", "output": "Sunny"}
            ]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.messages.len(), 1);
        match &ir.messages[0].content[0] {
            IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                assert_eq!(tool_use_id, "call_1");
                assert_eq!(content.len(), 1);
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    #[test]
    fn read_request_reasoning_item() {
        // reasoning item → IrBlock::Reasoning (仅 summary).
        let body = json!({
            "model": "o1",
            "input": [{
                "type": "reasoning",
                "summary": [{"type": "summary_text", "text": "thinking..."}],
                "encrypted_content": "opaque-bytes"
            }]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.messages.len(), 1);
        match &ir.messages[0].content[0] {
            IrBlock::Reasoning { summary } => {
                assert_eq!(summary, &vec!["thinking...".to_string()]);
            }
            other => panic!("expected Reasoning, got {other:?}"),
        }
    }

    #[test]
    fn read_request_function_tool_flat() {
        // Responses function tool 是平铺的 (name/parameters 在 top-level).
        let body = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{
                "type": "function",
                "name": "search",
                "description": "Search the web",
                "parameters": {"type": "object", "properties": {}}
            }]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.tools.len(), 1);
        assert_eq!(ir.tools[0].name, "search");
        assert_eq!(ir.tools[0].description.as_deref(), Some("Search the web"));
    }

    #[test]
    fn read_request_drops_hosted_tools() {
        // web_search / computer / mcp 等非 function 类型静默丢弃.
        let body = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [
                {"type": "function", "name": "f1", "parameters": {}},
                {"type": "web_search"},
                {"type": "computer_use_preview"},
                {"type": "mcp", "server_label": "x"}
            ]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.tools.len(), 1); // 只剩 function
        assert_eq!(ir.tools[0].name, "f1");
    }

    #[test]
    fn read_request_unknown_input_item_dropped() {
        // 未知 item type 静默丢弃 (ROB-1).
        let body = json!({
            "model": "gpt-4o",
            "input": [
                {"type": "computer_call", "action": {"type": "click"}},
                {"type": "message", "role": "user", "content": "hi"}
            ]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.messages.len(), 1); // 只剩 message
    }

    // ─── read_response ─────────────────────────────────────────────────

    #[test]
    fn read_response_basic() {
        let body = json!({
            "id": "resp_abc",
            "object": "response",
            "created_at": 1700000000,
            "model": "gpt-4o",
            "status": "completed",
            "output": [{
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "Hi there!"}]
            }],
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        });
        let ir = reader().read_response(&body).unwrap();
        assert_eq!(ir.id.as_deref(), Some("resp_abc"));
        assert_eq!(ir.model.as_deref(), Some("gpt-4o"));
        assert_eq!(ir.created, Some(1700000000));
        assert_eq!(ir.stop_reason, Some(IrStopReason::EndTurn));
        assert_eq!(ir.usage.input_tokens, 10);
        assert_eq!(ir.usage.output_tokens, 5);
        match &ir.content[0] {
            IrBlock::Text { text } => assert_eq!(text, "Hi there!"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn read_response_function_call_output_item() {
        let body = json!({
            "id": "resp_1", "model": "gpt-4o", "status": "completed",
            "output": [{
                "type": "function_call",
                "id": "fc_1", "call_id": "call_1",
                "name": "get_weather",
                "arguments": "{\"city\":\"SF\"}"
            }],
            "usage": {"input_tokens": 0, "output_tokens": 0}
        });
        let ir = reader().read_response(&body).unwrap();
        match &ir.content[0] {
            IrBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "get_weather");
                assert_eq!(input, &json!({"city": "SF"}));
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn read_response_status_variants() {
        let cases = [
            ("completed", IrStopReason::EndTurn),
            ("incomplete", IrStopReason::Other), // 无 incomplete_details 时归 Other (m2 修复)
            ("failed", IrStopReason::Other),
        ];
        for (status, expected) in cases {
            let body = json!({
                "id": "x", "model": "m", "status": status,
                "output": [],
                "usage": {"input_tokens": 0, "output_tokens": 0}
            });
            let ir = reader().read_response(&body).unwrap();
            assert_eq!(ir.stop_reason, Some(expected), "for status={status}");
        }
    }

    #[test]
    fn read_response_usage_cached_subtracted() {
        // input_tokens 含 cached, IR 减去 cached 得到未缓存 input.
        let body = json!({
            "id": "x", "model": "m", "status": "completed", "output": [],
            "usage": {
                "input_tokens": 100,
                "output_tokens": 5,
                "input_tokens_details": {"cached_tokens": 30}
            }
        });
        let ir = reader().read_response(&body).unwrap();
        assert_eq!(ir.usage.input_tokens, 70); // 100 - 30
        assert_eq!(ir.usage.cache_read_input_tokens, Some(30));
    }

    // ─── write_request ─────────────────────────────────────────────────

    #[test]
    fn write_request_basic() {
        let ir = IrRequest {
            system: vec![IrBlock::Text {
                text: "Be helpful".into(),
            }],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text { text: "Hi".into() }],
                contains_user_text: true,
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            max_tokens: Some(50),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        assert_eq!(v.get("model").unwrap(), "gpt-4o");
        assert_eq!(v.get("instructions").unwrap(), "Be helpful");
        let input = v.get("input").unwrap().as_array().unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input[0].get("type").unwrap(), "message");
        assert_eq!(input[0].get("role").unwrap(), "user");
        assert_eq!(v.get("max_output_tokens").unwrap(), 50);
    }

    #[test]
    fn write_request_assistant_with_tool_calls() {
        // assistant 含 ToolUse → function_call item.
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::Assistant,
                content: vec![
                    IrBlock::Text {
                        text: "Let me check".into(),
                    },
                    IrBlock::ToolUse {
                        id: "call_1".into(),
                        name: "search".into(),
                        input: json!({"q": "rust"}),
                    },
                ],
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        let input = v.get("input").unwrap().as_array().unwrap();
        // message item (text) + function_call item.
        assert_eq!(input.len(), 2);
        assert_eq!(input[0].get("type").unwrap(), "message");
        assert_eq!(input[1].get("type").unwrap(), "function_call");
        assert_eq!(input[1].get("call_id").unwrap(), "call_1");
        assert_eq!(input[1].get("name").unwrap(), "search");
    }

    #[test]
    fn write_request_tool_result_to_function_call_output() {
        // user ToolResult → function_call_output item.
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::ToolResult {
                    tool_use_id: "call_1".into(),
                    content: vec![IrBlock::Text {
                        text: "Sunny".into(),
                    }],
                    is_error: false,
                    content_form: None,
                }],
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        let input = v.get("input").unwrap().as_array().unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input[0].get("type").unwrap(), "function_call_output");
        assert_eq!(input[0].get("call_id").unwrap(), "call_1");
        assert_eq!(input[0].get("output").unwrap(), "Sunny");
    }

    #[test]
    fn write_request_tools_flat() {
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text { text: "x".into() }],
                contains_user_text: true,
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            tools: vec![IrTool {
                name: "search".into(),
                description: Some("Search".into()),
                input_schema: json!({"type": "object"}),
            }],
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        let tools = v.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].get("type").unwrap(), "function");
        assert_eq!(tools[0].get("name").unwrap(), "search");
        // 平铺: 没有 function 子对象.
        assert!(tools[0].get("function").is_none());
    }

    // ─── write_response ────────────────────────────────────────────────

    #[test]
    fn write_response_basic() {
        let ir = IrResponse {
            content: vec![IrBlock::Text { text: "Hi".into() }],
            stop_reason: Some(IrStopReason::EndTurn),
            usage: IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            },
            usage_present: true,
            model: Some("gpt-4o".into()),
            id: Some("resp_01x".into()),
            created: None,
            stop_sequence: None,
        };
        let v = writer().write_response(&ir);
        assert_eq!(v.get("id").unwrap(), "resp_01x");
        assert_eq!(v.get("object").unwrap(), "response");
        assert_eq!(v.get("status").unwrap(), "completed");
        let output = v.get("output").unwrap().as_array().unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].get("type").unwrap(), "message");
        let content = output[0].get("content").unwrap().as_array().unwrap();
        assert_eq!(content[0].get("type").unwrap(), "output_text");
        assert_eq!(content[0].get("text").unwrap(), "Hi");
        let usage = v.get("usage").unwrap();
        assert_eq!(usage.get("input_tokens").unwrap(), 10);
        assert_eq!(usage.get("output_tokens").unwrap(), 5);
    }

    #[test]
    fn write_response_with_tool_call() {
        let ir = IrResponse {
            content: vec![
                IrBlock::Text {
                    text: "Let me search".into(),
                },
                IrBlock::ToolUse {
                    id: "call_1".into(),
                    name: "search".into(),
                    input: json!({"q": "rust"}),
                },
            ],
            stop_reason: Some(IrStopReason::ToolUse),
            usage: IrUsage::default(),
            usage_present: false,
            model: Some("gpt-4o".into()),
            id: None,
            created: None,
            stop_sequence: None,
        };
        let v = writer().write_response(&ir);
        let output = v.get("output").unwrap().as_array().unwrap();
        // message + function_call.
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].get("type").unwrap(), "message");
        assert_eq!(output[1].get("type").unwrap(), "function_call");
        assert_eq!(output[1].get("call_id").unwrap(), "call_1");
    }

    #[test]
    fn write_response_synthesizes_id_when_missing() {
        let ir = IrResponse {
            content: vec![IrBlock::Text { text: "Hi".into() }],
            stop_reason: Some(IrStopReason::EndTurn),
            usage: IrUsage::default(),
            usage_present: false,
            model: Some("gpt-4o".into()),
            id: None,
            created: None,
            stop_sequence: None,
        };
        let v = writer().write_response(&ir);
        let id = v.get("id").unwrap().as_str().unwrap();
        assert!(
            id.starts_with("resp_"),
            "synth id must start with resp_, got {id}"
        );
    }

    // ─── round-trip: read → write → read (应等价) ───────────────────────

    #[test]
    fn round_trip_request_basic() {
        let original = json!({
            "model": "gpt-4o",
            "instructions": "Be helpful",
            "input": [{"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "Hello"}
            ]}],
            "max_output_tokens": 100,
        });
        let ir = reader().read_request(&original).unwrap();
        let rewritten = writer().write_request(&ir);
        let ir2 = reader().read_request(&rewritten).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn round_trip_request_with_tools_and_tool_calls() {
        let original = json!({
            "model": "gpt-4o",
            "input": [
                {"type": "message", "role": "user", "content": "weather?"},
                {"type": "function_call", "call_id": "c1", "name": "get_weather",
                 "arguments": "{\"city\":\"SF\"}"},
                {"type": "function_call_output", "call_id": "c1", "output": "Sunny"}
            ],
            "tools": [{
                "type": "function",
                "name": "get_weather",
                "description": "Get weather",
                "parameters": {"type": "object", "properties": {}}
            }],
            "tool_choice": "auto",
            "max_output_tokens": 100,
        });
        let ir = reader().read_request(&original).unwrap();
        let rewritten = writer().write_request(&ir);
        let ir2 = reader().read_request(&rewritten).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn round_trip_response_basic() {
        let original = json!({
            "id": "resp_abc",
            "object": "response",
            "created_at": 1700000000,
            "model": "gpt-4o",
            "status": "completed",
            "output": [{
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "Hi there!"}]
            }],
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        });
        let ir = reader().read_response(&original).unwrap();
        let rewritten = writer().write_response(&ir);
        let ir2 = reader().read_response(&rewritten).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn round_trip_response_with_tool_call() {
        let original = json!({
            "id": "resp_1",
            "object": "response",
            "created_at": 1700000000,
            "model": "gpt-4o",
            "status": "completed",
            "output": [{
                "type": "function_call",
                "id": "fc_1", "call_id": "call_1",
                "name": "get_weather",
                "arguments": "{\"city\":\"SF\"}",
                "status": "completed"
            }],
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
        });
        let ir = reader().read_response(&original).unwrap();
        let rewritten = writer().write_response(&ir);
        let ir2 = reader().read_response(&rewritten).unwrap();
        assert_eq!(ir, ir2);
    }

    // ─── 跨协议: Responses → Chat 方向 (验证 IR 中间态) ──────────────────

    #[test]
    fn cross_proto_responses_to_chat_request() {
        // Responses request → IR → Chat request.
        // 验证 IR 是正确的中间态 (能被 Chat writer 消费).
        let responses_body = json!({
            "model": "gpt-4o",
            "instructions": "Be helpful",
            "input": [{"type": "message", "role": "user", "content": "Hello"}],
            "max_output_tokens": 100,
        });
        let ir = reader().read_request(&responses_body).unwrap();
        // 用 OpenAI Chat writer 写出.
        let chat_writer = super::super::openai::OpenAiWriter;
        let chat_body = chat_writer.write_request(&ir);
        // Chat body 应有 messages (含 system + user).
        let messages = chat_body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].get("role").unwrap(), "system");
        assert_eq!(messages[1].get("role").unwrap(), "user");
        assert_eq!(chat_body.get("max_tokens").unwrap(), 100);
    }

    #[test]
    fn cross_proto_chat_to_responses_response() {
        // Chat response → IR → Responses response.
        let chat_body = json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello!"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        });
        let chat_reader = super::super::openai::OpenAiReader;
        let ir = chat_reader.read_response(&chat_body).unwrap();
        let responses_body = writer().write_response(&ir);
        assert_eq!(responses_body.get("object").unwrap(), "response");
        let output = responses_body.get("output").unwrap().as_array().unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].get("type").unwrap(), "message");
        let usage = responses_body.get("usage").unwrap();
        // Chat 的 prompt_tokens → Responses 的 input_tokens.
        assert_eq!(usage.get("input_tokens").unwrap(), 10);
        assert_eq!(usage.get("output_tokens").unwrap(), 5);
    }

    // ─── read_response_events: 流式 SSE 事件 → IR ─────────────────────
    //
    // 场景 fixture 对齐官方 Responses 流式文档的事件序列 (event_type 完整名 +
    // data 冗余 type). 断言用整体 assert_eq (IrStreamEvent: PartialEq) 锁定
    // 事件序列与 index 分配, 避免逐字段 matches! 漏检顺序错位.

    /// 把 (event_type, data) SSE 帧序列逐帧喂入 reader (跨帧共享 state), 收集 IR 事件.
    fn feed_stream(frames: &[(&str, Value)]) -> Vec<IrStreamEvent> {
        let mut state = crate::codec::ir::StreamDecodeState::default();
        let mut out = Vec::new();
        for (ty, data) in frames {
            out.extend(reader().read_response_events(ty, data, &mut state));
        }
        out
    }

    /// 官方 text 场景的 response.created 帧.
    fn created_frame() -> (&'static str, Value) {
        (
            "response.created",
            json!({
                "type": "response.created", "sequence_number": 0,
                "response": {
                    "id": "resp_1", "object": "response", "created_at": 1700000000,
                    "model": "gpt-5", "status": "in_progress", "output": [], "usage": null,
                },
            }),
        )
    }

    /// `created_frame()` 的期望投影 (期望向量的公共前缀, 与输入 fixture 配对).
    fn expected_message_start() -> IrStreamEvent {
        IrStreamEvent::MessageStart {
            usage: None,
            id: Some("resp_1".into()),
            created: Some(1700000000),
            model: Some("gpt-5".into()),
        }
    }

    /// 官方 text 场景的完整输入帧序列 (reader 场景测试 + reader→writer round-trip
    /// 测试共用的 fixture).
    fn official_text_frames() -> Vec<(&'static str, Value)> {
        vec![
            created_frame(),
            (
                "response.in_progress",
                json!({"type": "response.in_progress",
                        "response": {"id": "resp_1", "status": "in_progress"}}),
            ),
            (
                "response.output_item.added",
                json!({"type": "response.output_item.added", "output_index": 0,
                        "item": {"id": "msg_1", "type": "message", "status": "in_progress",
                                  "role": "assistant", "content": []}}),
            ),
            (
                "response.content_part.added",
                json!({"type": "response.content_part.added", "item_id": "msg_1",
                        "output_index": 0, "content_index": 0,
                        "part": {"type": "output_text", "text": "", "annotations": []}}),
            ),
            (
                "response.output_text.delta",
                json!({"type": "response.output_text.delta", "item_id": "msg_1",
                        "output_index": 0, "content_index": 0, "delta": "Hel"}),
            ),
            (
                "response.output_text.delta",
                json!({"type": "response.output_text.delta", "item_id": "msg_1",
                        "output_index": 0, "content_index": 0, "delta": "lo"}),
            ),
            (
                "response.output_text.done",
                json!({"type": "response.output_text.done", "item_id": "msg_1",
                        "output_index": 0, "content_index": 0, "text": "Hello"}),
            ),
            (
                "response.content_part.done",
                json!({"type": "response.content_part.done", "item_id": "msg_1",
                        "output_index": 0, "content_index": 0,
                        "part": {"type": "output_text", "text": "Hello", "annotations": []}}),
            ),
            (
                "response.output_item.done",
                json!({"type": "response.output_item.done", "output_index": 0,
                        "item": {"id": "msg_1", "type": "message", "status": "completed",
                                  "role": "assistant",
                                  "content": [{"type": "output_text", "text": "Hello"}]}}),
            ),
            (
                "response.completed",
                json!({"type": "response.completed",
                        "response": {"id": "resp_1", "status": "completed",
                                      "usage": {"input_tokens": 10, "output_tokens": 5,
                                                 "total_tokens": 15}}}),
            ),
        ]
    }

    /// text 场景 reader 期望的 IR 事件序列 (同时是 writer 镜像测试的输入 fixture).
    fn official_text_ir() -> Vec<IrStreamEvent> {
        vec![
            expected_message_start(),
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text,
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("Hel".into()),
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("lo".into()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(IrStopReason::EndTurn),
                stop_sequence: None,
                usage: IrUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                    ..Default::default()
                },
                usage_present: true,
            },
            IrStreamEvent::MessageStop,
        ]
    }

    #[test]
    fn stream_text_scenario_full_official_sequence() {
        // 官方 text 场景: created → in_progress → item.added → part.added →
        // text.delta×2 → done 族 → item.done → completed.
        assert_eq!(feed_stream(&official_text_frames()), official_text_ir());
    }

    /// function_call 场景输入帧 (call_id 优先 + args 流式; 共用 fixture).
    fn official_function_call_frames() -> Vec<(&'static str, Value)> {
        vec![
            created_frame(),
            (
                "response.output_item.added",
                json!({"output_index": 0, "item": {
                    "id": "fc_1", "call_id": "call_9", "type": "function_call",
                    "name": "get_weather", "arguments": "", "status": "in_progress",
                }}),
            ),
            (
                "response.function_call_arguments.delta",
                json!({"item_id": "fc_1", "output_index": 0, "delta": "{\"city\":"}),
            ),
            (
                "response.function_call_arguments.delta",
                json!({"item_id": "fc_1", "output_index": 0, "delta": "\"SF\"}"}),
            ),
            (
                "response.function_call_arguments.done",
                json!({"item_id": "fc_1", "output_index": 0,
                        "arguments": "{\"city\":\"SF\"}"}),
            ),
            (
                "response.output_item.done",
                json!({"output_index": 0, "item": {
                    "id": "fc_1", "call_id": "call_9", "type": "function_call",
                    "name": "get_weather", "arguments": "{\"city\":\"SF\"}",
                    "status": "completed",
                }}),
            ),
            (
                "response.completed",
                json!({"response": {"id": "resp_1", "status": "completed",
                                     "usage": {"input_tokens": 7, "output_tokens": 3}}}),
            ),
        ]
    }

    /// function_call 场景期望 IR (writer 镜像测试输入 fixture).
    fn official_function_call_ir() -> Vec<IrStreamEvent> {
        vec![
            expected_message_start(),
            // call_id 优先于 id.
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::ToolUse {
                    id: "call_9".into(),
                    name: "get_weather".into(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::InputJsonDelta("{\"city\":".into()),
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::InputJsonDelta("\"SF\"}".into()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            // 出现过 function_call → completed 推断 ToolUse.
            IrStreamEvent::MessageDelta {
                stop_reason: Some(IrStopReason::ToolUse),
                stop_sequence: None,
                usage: IrUsage {
                    input_tokens: 7,
                    output_tokens: 3,
                    ..Default::default()
                },
                usage_present: true,
            },
            IrStreamEvent::MessageStop,
        ]
    }

    #[test]
    fn stream_function_call_scenario_call_id_preferred_and_args_deltas() {
        assert_eq!(
            feed_stream(&official_function_call_frames()),
            official_function_call_ir()
        );
    }

    /// reasoning + message 混合场景输入帧 (共用 fixture).
    fn official_reasoning_mixed_frames() -> Vec<(&'static str, Value)> {
        vec![
            created_frame(),
            (
                "response.output_item.added",
                json!({"output_index": 0, "item": {"id": "rs_1", "type": "reasoning",
                                                     "summary": [], "status": "in_progress"}}),
            ),
            (
                "response.reasoning_summary_part.added",
                json!({"item_id": "rs_1", "output_index": 0, "summary_index": 0}),
            ),
            (
                "response.reasoning_summary_text.delta",
                json!({"item_id": "rs_1", "output_index": 0, "summary_index": 0,
                        "delta": "Think "}),
            ),
            (
                "response.reasoning_summary_text.done",
                json!({"item_id": "rs_1", "output_index": 0, "summary_index": 0,
                        "text": "Think "}),
            ),
            (
                "response.output_item.done",
                json!({"output_index": 0, "item": {"id": "rs_1", "type": "reasoning",
                                                     "status": "completed",
                                                     "summary": [{"type": "summary_text",
                                                                   "text": "Think "}]}}),
            ),
            (
                "response.output_item.added",
                json!({"output_index": 1, "item": {"id": "msg_1", "type": "message",
                                                     "status": "in_progress",
                                                     "role": "assistant", "content": []}}),
            ),
            (
                "response.content_part.added",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 0,
                        "part": {"type": "output_text", "text": ""}}),
            ),
            (
                "response.output_text.delta",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 0,
                        "delta": "Answer"}),
            ),
            (
                "response.content_part.done",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 0,
                        "part": {"type": "output_text", "text": "Answer"}}),
            ),
            (
                "response.output_item.done",
                json!({"output_index": 1, "item": {"id": "msg_1", "type": "message",
                                                     "status": "completed", "role": "assistant",
                                                     "content": [{"type": "output_text",
                                                                   "text": "Answer"}]}}),
            ),
            (
                "response.completed",
                json!({"response": {"status": "completed", "usage": null}}),
            ),
        ]
    }

    /// reasoning + message 混合场景期望 IR (writer 镜像测试输入 fixture):
    /// 两个独立 IR block, index 按 BlockStart 发出顺序 (reasoning 先 → 0, text → 1).
    fn official_reasoning_mixed_ir() -> Vec<IrStreamEvent> {
        vec![
            expected_message_start(),
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::ReasoningContent,
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::ReasoningDelta("Think ".into()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::Text,
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::TextDelta("Answer".into()),
            },
            IrStreamEvent::BlockStop { index: 1 },
            // 无 function_call → EndTurn; usage 缺席 (null) → usage_present false.
            IrStreamEvent::MessageDelta {
                stop_reason: Some(IrStopReason::EndTurn),
                stop_sequence: None,
                usage: IrUsage::default(),
                usage_present: false,
            },
            IrStreamEvent::MessageStop,
        ]
    }

    #[test]
    fn stream_reasoning_then_message_mixed_scenario() {
        assert_eq!(
            feed_stream(&official_reasoning_mixed_frames()),
            official_reasoning_mixed_ir()
        );
    }

    #[test]
    fn stream_hosted_tool_and_refusal_parts_dropped_without_panicking() {
        // hosted tool item (web_search_call) 整族忽略 + refusal part 丢弃;
        // IR 流的其余部分 (message) 完好.
        let frames = vec![
            created_frame(),
            (
                "response.output_item.added",
                json!({"output_index": 0, "item": {"id": "ws_1", "type": "web_search_call",
                                                     "status": "in_progress"}}),
            ),
            (
                "response.web_search_call.in_progress",
                json!({"output_index": 0, "item_id": "ws_1"}),
            ),
            (
                "response.output_item.done",
                json!({"output_index": 0, "item": {"id": "ws_1", "type": "web_search_call",
                                                     "status": "completed"}}),
            ),
            (
                "response.output_item.added",
                json!({"output_index": 1, "item": {"id": "msg_1", "type": "message",
                                                     "status": "in_progress",
                                                     "role": "assistant", "content": []}}),
            ),
            (
                "response.content_part.added",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 0,
                        "part": {"type": "output_text", "text": ""}}),
            ),
            (
                "response.content_part.added",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 1,
                        "part": {"type": "refusal", "refusal": ""}}),
            ),
            (
                "response.refusal.delta",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 1,
                        "delta": "cannot"}),
            ),
            (
                "response.output_text.delta",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 0,
                        "delta": "ok"}),
            ),
            (
                "response.refusal.done",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 1,
                        "refusal": "cannot"}),
            ),
            (
                "response.content_part.done",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 0,
                        "part": {"type": "output_text", "text": "ok"}}),
            ),
            (
                "response.content_part.done",
                json!({"item_id": "msg_1", "output_index": 1, "content_index": 1,
                        "part": {"type": "refusal", "refusal": "cannot"}}),
            ),
            (
                "response.output_item.done",
                json!({"output_index": 1, "item": {"id": "msg_1", "type": "message",
                                                     "status": "completed",
                                                     "role": "assistant", "content": []}}),
            ),
            (
                "response.completed",
                json!({"response": {"status": "completed",
                                     "usage": {"input_tokens": 1, "output_tokens": 1}}}),
            ),
        ];
        assert_eq!(
            feed_stream(&frames),
            vec![
                expected_message_start(),
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Text,
                },
                IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: IrDelta::TextDelta("ok".into()),
                },
                IrStreamEvent::BlockStop { index: 0 },
                IrStreamEvent::MessageDelta {
                    stop_reason: Some(IrStopReason::EndTurn),
                    stop_sequence: None,
                    usage: IrUsage {
                        input_tokens: 1,
                        output_tokens: 1,
                        ..Default::default()
                    },
                    usage_present: true,
                },
                IrStreamEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn stream_failed_emits_error_with_message_preferred() {
        let frames = vec![
            created_frame(),
            (
                "response.failed",
                json!({"response": {"id": "resp_1", "status": "failed",
                                     "error": {"code": "server_error",
                                                "message": "The model is overloaded"}}}),
            ),
        ];
        assert_eq!(
            feed_stream(&frames),
            vec![
                expected_message_start(),
                IrStreamEvent::Error("The model is overloaded".into()),
            ]
        );
        // error.message 缺失 → 兜底 code.
        let frames = vec![(
            "response.failed",
            json!({"response": {"status": "failed",
                                 "error": {"code": "rate_limit_exceeded"}}}),
        )];
        assert_eq!(
            feed_stream(&frames),
            vec![IrStreamEvent::Error("rate_limit_exceeded".into())]
        );
    }

    #[test]
    fn stream_incomplete_maps_max_output_tokens_to_max_tokens_stop() {
        let frames = vec![
            created_frame(),
            (
                "response.incomplete",
                json!({"response": {"id": "resp_1", "status": "incomplete",
                                     "incomplete_details": {"reason": "max_output_tokens"},
                                     "usage": {"input_tokens": 4, "output_tokens": 2}}}),
            ),
        ];
        assert_eq!(
            feed_stream(&frames),
            vec![
                expected_message_start(),
                IrStreamEvent::MessageDelta {
                    stop_reason: Some(IrStopReason::MaxTokens),
                    stop_sequence: None,
                    usage: IrUsage {
                        input_tokens: 4,
                        output_tokens: 2,
                        ..Default::default()
                    },
                    usage_present: true,
                },
                IrStreamEvent::MessageStop,
            ]
        );
        // content_filter → Safety; 未知 reason → Other (复用 read_response_status).
        for (reason, expected) in [
            ("content_filter", IrStopReason::Safety),
            ("max_messages", IrStopReason::Other),
        ] {
            let frames = vec![(
                "response.incomplete",
                json!({"response": {"status": "incomplete",
                                     "incomplete_details": {"reason": reason}}}),
            )];
            let events = feed_stream(&frames);
            assert!(
                matches!(events.as_slice(),
                    [IrStreamEvent::MessageDelta { stop_reason: Some(r), .. }, IrStreamEvent::MessageStop]
                    if *r == expected),
                "for reason={reason}: {events:?}"
            );
        }
    }

    #[test]
    fn stream_function_call_done_only_arguments_backfills_full_input_json_delta() {
        // 病态/兜底路径: 从未发 arguments.delta, done item 带全量 arguments →
        // 补发一条 InputJsonDelta (再 BlockStop). 对照: 已流式过则不补发.
        let frames = vec![
            created_frame(),
            (
                "response.output_item.added",
                json!({"output_index": 0, "item": {"id": "fc_1", "call_id": "call_2",
                                                     "type": "function_call",
                                                     "name": "ping", "arguments": ""}}),
            ),
            (
                "response.output_item.done",
                json!({"output_index": 0, "item": {"id": "fc_1", "call_id": "call_2",
                                                     "type": "function_call", "name": "ping",
                                                     "arguments": "{\"a\":1}",
                                                     "status": "completed"}}),
            ),
            (
                "response.completed",
                json!({"response": {"status": "completed", "usage": null}}),
            ),
        ];
        assert_eq!(
            feed_stream(&frames),
            vec![
                expected_message_start(),
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::ToolUse {
                        id: "call_2".into(),
                        name: "ping".into(),
                    },
                },
                // 兜底补发: 全量 arguments 一条.
                IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: IrDelta::InputJsonDelta("{\"a\":1}".into()),
                },
                IrStreamEvent::BlockStop { index: 0 },
                IrStreamEvent::MessageDelta {
                    stop_reason: Some(IrStopReason::ToolUse),
                    stop_sequence: None,
                    usage: IrUsage::default(),
                    usage_present: false,
                },
                IrStreamEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn stream_duplicate_created_emits_single_message_start() {
        let frames = vec![created_frame(), created_frame()];
        assert_eq!(feed_stream(&frames), vec![expected_message_start()]);
    }

    #[test]
    fn stream_orphan_text_delta_without_part_added_is_ignored() {
        // 病态流: output_text.delta 先于 content_part.added 到达 → 忽略, 不 panic;
        // message 的 output_item.done 兜底也无未关 part 可关 (零事件).
        let frames = vec![
            created_frame(),
            (
                "response.output_text.delta",
                json!({"item_id": "msg_x", "output_index": 0, "content_index": 0,
                        "delta": "orphan"}),
            ),
            (
                "response.output_item.done",
                json!({"output_index": 0, "item": {"id": "msg_x", "type": "message",
                                                     "status": "completed",
                                                     "role": "assistant", "content": []}}),
            ),
            (
                "response.completed",
                json!({"response": {"status": "completed", "usage": null}}),
            ),
        ];
        assert_eq!(
            feed_stream(&frames),
            vec![
                expected_message_start(),
                IrStreamEvent::MessageDelta {
                    stop_reason: Some(IrStopReason::EndTurn),
                    stop_sequence: None,
                    usage: IrUsage::default(),
                    usage_present: false,
                },
                IrStreamEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn stream_message_item_done_backfills_block_stop_for_open_part() {
        // D2 兜底路径: content_part.done 缺席 (病态), output_item.done(message) 补发
        // 未关 part 的 BlockStop.
        let frames = vec![
            created_frame(),
            (
                "response.output_item.added",
                json!({"output_index": 0, "item": {"id": "msg_1", "type": "message",
                                                     "status": "in_progress",
                                                     "role": "assistant", "content": []}}),
            ),
            (
                "response.content_part.added",
                json!({"item_id": "msg_1", "output_index": 0, "content_index": 0,
                        "part": {"type": "output_text", "text": ""}}),
            ),
            (
                "response.output_text.delta",
                json!({"item_id": "msg_1", "output_index": 0, "content_index": 0,
                        "delta": "Hi"}),
            ),
            (
                "response.output_item.done",
                json!({"output_index": 0, "item": {"id": "msg_1", "type": "message",
                                                     "status": "completed",
                                                     "role": "assistant", "content": []}}),
            ),
            (
                "response.completed",
                json!({"response": {"status": "completed", "usage": null}}),
            ),
        ];
        assert_eq!(
            feed_stream(&frames),
            vec![
                expected_message_start(),
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Text,
                },
                IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: IrDelta::TextDelta("Hi".into()),
                },
                // 兜底 BlockStop (正常路径应由 content_part.done 发出, 此处缺席).
                IrStreamEvent::BlockStop { index: 0 },
                IrStreamEvent::MessageDelta {
                    stop_reason: Some(IrStopReason::EndTurn),
                    stop_sequence: None,
                    usage: IrUsage::default(),
                    usage_present: false,
                },
                IrStreamEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn stream_part_added_with_non_message_parent_is_ignored() {
        // 父 item 校验回归锁: content_part.added 只有在父 item 已登记为 message 时
        // 才受理 — 挂在 function_call 父 / 父缺席 (病态) 的 part 一律忽略, 且后续
        // 同 key 的 delta / part.done 查不到映射自然降级 (无游离 Text block).
        let frames = vec![
            created_frame(),
            (
                "response.output_item.added",
                json!({"output_index": 0, "item": {"id": "fc_1", "call_id": "c1",
                                                     "type": "function_call",
                                                     "name": "f", "arguments": ""}}),
            ),
            // part 挂在 function_call 的 output_index 上 → 忽略.
            (
                "response.content_part.added",
                json!({"output_index": 0, "content_index": 0,
                        "part": {"type": "output_text", "text": ""}}),
            ),
            // 父缺席 (output_index 9 从未 added) → 忽略.
            (
                "response.content_part.added",
                json!({"output_index": 9, "content_index": 0,
                        "part": {"type": "output_text", "text": ""}}),
            ),
            // 同 key 后续事件查不到映射 → 零事件.
            (
                "response.output_text.delta",
                json!({"output_index": 0, "content_index": 0, "delta": "x"}),
            ),
            (
                "response.content_part.done",
                json!({"output_index": 0, "content_index": 0, "part": {}}),
            ),
            (
                "response.output_item.done",
                json!({"output_index": 0, "item": {"id": "fc_1", "call_id": "c1",
                                                     "type": "function_call", "name": "f",
                                                     "arguments": "", "status": "completed"}}),
            ),
            (
                "response.completed",
                json!({"response": {"status": "completed", "usage": null}}),
            ),
        ];
        assert_eq!(
            feed_stream(&frames),
            vec![
                expected_message_start(),
                // function_call 的 BlockStart (唯一的内容 block; 无游离 Text BlockStart).
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::ToolUse {
                        id: "c1".into(),
                        name: "f".into(),
                    },
                },
                IrStreamEvent::BlockStop { index: 0 },
                IrStreamEvent::MessageDelta {
                    stop_reason: Some(IrStopReason::ToolUse),
                    stop_sequence: None,
                    usage: IrUsage::default(),
                    usage_present: false,
                },
                IrStreamEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn stream_bare_data_frame_ignores_redundant_type_field() {
        // event_type 为空 (bare data 帧) 时以 event_type 为准: data 里的冗余 type
        // 不参与判定 → 忽略 (Responses 流恒带 event: 行, 此为防御性锁定).
        let frames = vec![(
            "",
            json!({"type": "response.output_text.delta", "output_index": 0,
                    "content_index": 0, "delta": "x"}),
        )];
        assert_eq!(feed_stream(&frames), Vec::<IrStreamEvent>::new());
    }

    // ─── read_response_events: 病态流 property (ROB-1) ─────────────────
    //
    // 全新状态机 reader 的核心风险面是随机病态输入 (事件乱序 / 重复 / 孤儿事件 /
    // 畸形字段). property 断言 (契约 ROB-* / 对齐 openai reader 的流式 property 先例):
    // 1) 永不 panic; 2) BlockStart index 全局唯一; 3) 无悬空 BlockStop (每个 BlockStop
    //    的 index 必有先行的 BlockStart). well-formed 序列的语义等价已由上方场景
    //    测试整体 assert_eq 锁定, 此处不重复.

    #[test]
    fn prop_responses_stream_reader_survives_pathological_event_sequences() {
        use proptest::prelude::*;

        // 事件帧模板: (event_type, data JSON) — 覆盖全部 dispatch 分支.
        fn frame_templates() -> Vec<(&'static str, Value)> {
            vec![
                (
                    "response.created",
                    json!({"response": {"id": "r", "created_at": 1, "model": "m"}}),
                ),
                ("response.in_progress", json!({"response": {}})),
                ("response.queued", json!({})),
                (
                    "response.output_item.added",
                    json!({"output_index": 0, "item": {"type": "message", "id": "msg_1"}}),
                ),
                (
                    "response.output_item.added",
                    json!({"output_index": 1, "item": {"type": "function_call", "id": "fc_1",
                                                         "call_id": "c1", "name": "f"}}),
                ),
                (
                    "response.output_item.added",
                    json!({"output_index": 2, "item": {"type": "reasoning", "id": "rs_1"}}),
                ),
                (
                    "response.output_item.added",
                    json!({"output_index": 3, "item": {"type": "web_search_call", "id": "ws_1"}}),
                ),
                (
                    "response.content_part.added",
                    json!({"output_index": 0, "content_index": 0,
                            "part": {"type": "output_text", "text": ""}}),
                ),
                (
                    "response.content_part.added",
                    json!({"output_index": 0, "content_index": 1,
                            "part": {"type": "refusal", "refusal": ""}}),
                ),
                (
                    "response.content_part.done",
                    json!({"output_index": 0, "content_index": 0, "part": {}}),
                ),
                (
                    "response.output_text.delta",
                    json!({"output_index": 0, "content_index": 0, "delta": "d"}),
                ),
                (
                    "response.output_text.delta",
                    json!({"output_index": 9, "content_index": 9, "delta": "orphan"}),
                ),
                (
                    "response.function_call_arguments.delta",
                    json!({"output_index": 1, "delta": "{\"a\":1}"}),
                ),
                (
                    "response.function_call_arguments.delta",
                    json!({"output_index": 2, "delta": "wrong-item-type"}),
                ),
                (
                    "response.reasoning_summary_text.delta",
                    json!({"output_index": 2, "summary_index": 0, "delta": "th"}),
                ),
                (
                    "response.reasoning_text.delta",
                    json!({"output_index": 2, "content_index": 0, "delta": "ink"}),
                ),
                (
                    "response.output_item.done",
                    json!({"output_index": 1, "item": {"type": "function_call",
                                                         "arguments": "{\"a\":1}"}}),
                ),
                (
                    "response.output_item.done",
                    json!({"output_index": 2, "item": {"type": "reasoning"}}),
                ),
                (
                    "response.output_item.done",
                    json!({"output_index": 3, "item": {"type": "web_search_call"}}),
                ),
                (
                    "response.output_item.done",
                    json!({"output_index": 0, "item": {"type": "message", "content": []}}),
                ),
                (
                    "response.output_item.done",
                    json!({"output_index": 7, "item": {"type": "message"}}),
                ),
                (
                    "response.completed",
                    json!({"response": {"status": "completed", "usage": {"input_tokens": 1, "output_tokens": 1}}}),
                ),
                (
                    "response.incomplete",
                    json!({"response": {"status": "incomplete",
                                         "incomplete_details": {"reason": "max_output_tokens"}}}),
                ),
                (
                    "response.failed",
                    json!({"response": {"error": {"code": "x", "message": "boom"}}}),
                ),
                ("error", json!({"error": {"message": "bare"}})),
                ("response.output_text.done", json!({"text": "full"})),
                ("response.refusal.delta", json!({"delta": "no"})),
                ("response.unknown.event", json!({"whatever": true})),
                // 畸形字段形态: 缺定位键 / 类型突变 / 空值 (只走降级路径, 不产事件).
                (
                    "response.output_item.added",
                    json!({"item": {"type": "message"}}),
                ),
                (
                    "response.content_part.added",
                    json!({"output_index": 0, "content_index": 0, "part": "not-an-object"}),
                ),
                (
                    "response.output_text.delta",
                    json!({"output_index": 0, "content_index": 0, "delta": 42}),
                ),
                (
                    "response.output_text.delta",
                    json!({"output_index": 0, "content_index": 0, "delta": ""}),
                ),
            ]
        }

        proptest!(|(n in 0usize..512)| {
            let templates = frame_templates();
            // 确定性伪随机选择 (避免 proptest strategy 与 Vec<(&str, Value)> 的
            // borrow 纠缠: 用简单 LCG 展开种子).
            let mut seed = n as u64 * 2654435761;
            let mut next = move || {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (seed >> 33) as usize
            };
            let mut state = crate::codec::ir::StreamDecodeState::default();
            let mut started_indices: std::collections::BTreeSet<usize> =
                std::collections::BTreeSet::new();
            for _ in 0..n {
                let (ty, data) = &templates[next() % templates.len()];
                let events = reader().read_response_events(ty, data, &mut state);
                for ev in events {
                    match ev {
                        IrStreamEvent::BlockStart { index, .. } => {
                            prop_assert!(started_indices.insert(index),
                                "BlockStart index {index} must be globally unique");
                        }
                        IrStreamEvent::BlockStop { index } => {
                            prop_assert!(started_indices.contains(&index),
                                "BlockStop {index} without prior BlockStart");
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    // ─── write_response_event: IR → 流式 SSE 帧 (D3 合成表镜像) ────────
    //
    // 镜像测试与 reader 场景 fixture 一一对应 (official_*_frames → reader →
    // official_*_ir → writer → 帧断言); round-trip 测试断言语义等价闭环.

    /// 把 IR 事件序列逐个喂入 writer (跨事件共享 encode state), 收集帧序列.
    fn write_events(events: &[IrStreamEvent]) -> Vec<(String, Value)> {
        let mut state = crate::codec::ir::StreamEncodeState::default();
        let mut out = Vec::new();
        for ev in events {
            out.extend(writer().write_response_event(ev, &mut state));
        }
        out
    }

    /// 帧序列的 event type 投影 (断言可读性辅助).
    fn frame_types(frames: &[(String, Value)]) -> Vec<&str> {
        frames.iter().map(|(t, _)| t.as_str()).collect()
    }

    #[test]
    fn stream_write_text_scenario_mirror() {
        let frames = write_events(&official_text_ir());
        assert_eq!(
            frame_types(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        // created 骨架: 元信息捕获 + in_progress + 空 output + null usage.
        let created = &frames[0].1;
        assert_eq!(created["type"], "response.created");
        assert_eq!(created["response"]["id"], "resp_1");
        assert_eq!(created["response"]["object"], "response");
        assert_eq!(created["response"]["created_at"], 1700000000);
        assert_eq!(created["response"]["model"], "gpt-5");
        assert_eq!(created["response"]["status"], "in_progress");
        assert_eq!(created["response"]["error"], Value::Null);
        assert_eq!(created["response"]["incomplete_details"], Value::Null);
        assert_eq!(created["response"]["output"], json!([]));
        assert_eq!(created["response"]["usage"], Value::Null);
        // item id 确定性合成 (msg_0, 全局序号从 0) + 定位键.
        assert_eq!(frames[1].1["output_index"], 0);
        assert_eq!(frames[1].1["item"]["id"], "msg_0");
        assert_eq!(frames[1].1["item"]["type"], "message");
        assert_eq!(frames[1].1["item"]["status"], "in_progress");
        assert_eq!(frames[1].1["item"]["role"], "assistant");
        assert_eq!(frames[1].1["item"]["content"], json!([]));
        assert_eq!(frames[2].1["item_id"], "msg_0");
        assert_eq!(frames[2].1["output_index"], 0);
        assert_eq!(frames[2].1["content_index"], 0);
        assert_eq!(
            frames[2].1["part"],
            json!({
                "type": "output_text", "text": "", "annotations": []
            })
        );
        // delta 帧带定位键 + 内容透传.
        assert_eq!(frames[3].1["item_id"], "msg_0");
        assert_eq!(frames[3].1["content_index"], 0);
        assert_eq!(frames[3].1["delta"], "Hel");
        assert_eq!(frames[4].1["delta"], "lo");
        // done 族全量断言 (累积内容).
        assert_eq!(frames[5].1["text"], "Hello");
        assert_eq!(frames[6].1["part"]["text"], "Hello");
        assert_eq!(frames[7].1["item"]["status"], "completed");
        assert_eq!(frames[7].1["item"]["content"][0]["text"], "Hello");
        // completed 全量重建: status / output / usage / 无 sequence_number.
        assert_eq!(frames[8].1["type"], "response.completed");
        let resp = &frames[8].1["response"];
        assert_eq!(resp["id"], "resp_1");
        assert_eq!(resp["status"], "completed");
        assert_eq!(resp["incomplete_details"], Value::Null);
        assert_eq!(resp["output"][0]["type"], "message");
        assert_eq!(resp["output"][0]["content"][0]["text"], "Hello");
        assert_eq!(
            resp["usage"],
            json!({"input_tokens": 10, "output_tokens": 5, "total_tokens": 15})
        );
        assert!(frames[8].1.get("sequence_number").is_none());
    }

    #[test]
    fn stream_write_function_call_scenario_mirror() {
        let frames = write_events(&official_function_call_ir());
        assert_eq!(
            frame_types(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.function_call_arguments.delta",
                "response.function_call_arguments.delta",
                "response.function_call_arguments.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        // fc_0 合成 id + call_id = IR id (round-trip 关联键, 必须保真).
        let added = &frames[1].1["item"];
        assert_eq!(added["id"], "fc_0");
        assert_eq!(added["type"], "function_call");
        assert_eq!(added["call_id"], "call_9");
        assert_eq!(added["name"], "get_weather");
        assert_eq!(added["arguments"], "");
        assert_eq!(frames[1].1["output_index"], 0);
        // delta 流式透传.
        assert_eq!(frames[2].1["delta"], "{\"city\":");
        assert_eq!(frames[3].1["delta"], "\"SF\"}");
        // done 族全量.
        assert_eq!(frames[4].1["arguments"], "{\"city\":\"SF\"}");
        let done = &frames[5].1["item"];
        assert_eq!(done["status"], "completed");
        assert_eq!(done["call_id"], "call_9");
        assert_eq!(done["name"], "get_weather");
        assert_eq!(done["arguments"], "{\"city\":\"SF\"}");
        // completed 全量重建含 function_call item; ToolUse stop → status completed.
        let resp = &frames[6].1["response"];
        assert_eq!(resp["status"], "completed");
        assert_eq!(resp["output"][0]["type"], "function_call");
        assert_eq!(resp["output"][0]["call_id"], "call_9");
        assert_eq!(resp["output"][0]["arguments"], "{\"city\":\"SF\"}");
        assert_eq!(
            resp["usage"],
            json!({"input_tokens": 7, "output_tokens": 3, "total_tokens": 10})
        );
    }

    #[test]
    fn stream_write_reasoning_scenario_mirror() {
        let frames = write_events(&official_reasoning_mixed_ir());
        assert_eq!(
            frame_types(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.reasoning_summary_part.added",
                "response.reasoning_summary_text.delta",
                "response.reasoning_summary_text.done",
                "response.reasoning_summary_part.done",
                "response.output_item.done",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        // rs_0 (首个 item) + summary_index 恒 0.
        assert_eq!(frames[1].1["item"]["id"], "rs_0");
        assert_eq!(frames[1].1["item"]["type"], "reasoning");
        assert_eq!(frames[1].1["item"]["summary"], json!([]));
        assert_eq!(
            frames[2].1["part"],
            json!({"type": "summary_text", "text": ""})
        );
        assert_eq!(frames[3].1["summary_index"], 0);
        assert_eq!(frames[3].1["delta"], "Think ");
        // reasoning done 族三帧全量.
        assert_eq!(frames[4].1["text"], "Think ");
        assert_eq!(
            frames[5].1["part"],
            json!({"type": "summary_text", "text": "Think "})
        );
        assert_eq!(frames[6].1["item"]["summary"][0]["text"], "Think ");
        // 第二个 item 序号推进: msg_1 (rs_0 已占 seq 0).
        assert_eq!(frames[7].1["item"]["id"], "msg_1");
        assert_eq!(frames[9].1["delta"], "Answer");
        assert_eq!(frames[10].1["text"], "Answer");
        // 终止事件: output 按 index 升序重建 (reasoning → message).
        let resp = &frames[13].1["response"];
        assert_eq!(resp["output"][0]["type"], "reasoning");
        assert_eq!(resp["output"][0]["summary"][0]["text"], "Think ");
        assert_eq!(resp["output"][1]["type"], "message");
        assert_eq!(resp["output"][1]["content"][0]["text"], "Answer");
        // usage 缺席 (usage_present=false) → 全零 usage 对象 (与非流式 write_response
        // 一致; round-trip 时 reader 侧 present 单向漂移, 见 round-trip 测试注).
        assert_eq!(
            resp["usage"],
            json!({"input_tokens": 0, "output_tokens": 0, "total_tokens": 0})
        );
    }

    #[test]
    fn stream_write_error_emits_error_and_response_failed() {
        let frames = write_events(&[
            expected_message_start(),
            IrStreamEvent::Error("The model is overloaded".into()),
        ]);
        assert_eq!(
            frame_types(&frames),
            vec!["response.created", "error", "response.failed"]
        );
        assert_eq!(frames[1].1["type"], "error");
        assert_eq!(frames[1].1["code"], "upstream_error");
        assert_eq!(frames[1].1["message"], "The model is overloaded");
        let resp = &frames[2].1["response"];
        assert_eq!(frames[2].1["type"], "response.failed");
        assert_eq!(resp["status"], "failed");
        assert_eq!(resp["id"], "resp_1"); // 已捕获的元信息保留
        assert_eq!(resp["error"]["code"], "upstream_error");
        assert_eq!(resp["error"]["message"], "The model is overloaded");
        // 超长 message 截断 (char boundary 安全, 接收端可感知).
        let frames = write_events(&[IrStreamEvent::Error("x".repeat(300))]);
        let msg = frames[0].1["message"].as_str().unwrap();
        assert!(
            msg.chars().count() < 300 && msg.ends_with('…'),
            "truncated: {msg}"
        );
    }

    #[test]
    fn stream_write_message_stop_status_and_incomplete_details() {
        let delta = |reason| IrStreamEvent::MessageDelta {
            stop_reason: Some(reason),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 4,
                output_tokens: 2,
                ..Default::default()
            },
            usage_present: true,
        };
        // MaxTokens → response.incomplete 事件 + max_output_tokens reason
        // (终止事件 type 按 status 分派, 官方 incomplete 语义).
        let frames = write_events(&[
            expected_message_start(),
            delta(IrStopReason::MaxTokens),
            IrStreamEvent::MessageStop,
        ]);
        assert_eq!(
            frame_types(&frames),
            vec!["response.created", "response.incomplete"]
        );
        let resp = &frames[1].1["response"];
        assert_eq!(resp["status"], "incomplete");
        assert_eq!(
            resp["incomplete_details"],
            json!({"reason": "max_output_tokens"})
        );
        assert_eq!(
            resp["usage"],
            json!({"input_tokens": 4, "output_tokens": 2, "total_tokens": 6})
        );
        // Safety/Refusal → content_filter (incomplete 事件); ToolUse/EndTurn →
        // completed 事件无 details; Other → failed 事件.
        for (reason, event, details) in [
            (
                IrStopReason::Safety,
                "response.incomplete",
                json!({"reason": "content_filter"}),
            ),
            (
                IrStopReason::Refusal,
                "response.incomplete",
                json!({"reason": "content_filter"}),
            ),
            (IrStopReason::ToolUse, "response.completed", Value::Null),
            (IrStopReason::EndTurn, "response.completed", Value::Null),
            (IrStopReason::Other, "response.failed", Value::Null),
        ] {
            let frames = write_events(&[delta(reason), IrStreamEvent::MessageStop]);
            assert_eq!(frames[0].0, event, "for reason {reason:?}");
            let resp = &frames[0].1["response"];
            assert_eq!(resp["incomplete_details"], details, "for reason {reason:?}");
        }
    }

    #[test]
    fn stream_write_message_stop_rebuilds_output_in_index_order() {
        // 混合 items (text 在 0, tool_use 在 1) 的全量重建, 按 index 升序.
        let frames = write_events(&[
            expected_message_start(),
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text,
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("Let me check".into()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::BlockStart {
                index: 1,
                block: IrBlockMeta::ToolUse {
                    id: "call_1".into(),
                    name: "search".into(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 1,
                delta: IrDelta::InputJsonDelta("{\"q\":\"rust\"}".into()),
            },
            IrStreamEvent::BlockStop { index: 1 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(IrStopReason::ToolUse),
                stop_sequence: None,
                usage: IrUsage::default(),
                usage_present: false,
            },
            IrStreamEvent::MessageStop,
        ]);
        let output = &frames.last().unwrap().1["response"]["output"];
        assert_eq!(output.as_array().unwrap().len(), 2);
        assert_eq!(output[0]["type"], "message");
        assert_eq!(output[0]["content"][0]["text"], "Let me check");
        assert_eq!(output[1]["type"], "function_call");
        assert_eq!(output[1]["call_id"], "call_1");
        assert_eq!(output[1]["arguments"], "{\"q\":\"rust\"}");
    }

    #[test]
    fn stream_write_block_start_idempotent_under_probe_call() {
        // translate 层配对过滤对 BlockStart 探测调用两次 (非空 → 帧丢弃后重调):
        // 注册必须幂等 — items 不重复注册, next_item_seq 不重复递增, 两次帧一致.
        let mut state = crate::codec::ir::StreamEncodeState::default();
        let ev = IrStreamEvent::BlockStart {
            index: 3,
            block: IrBlockMeta::Text,
        };
        let first = writer().write_response_event(&ev, &mut state);
        let second = writer().write_response_event(&ev, &mut state);
        assert_eq!(first, second, "probe call must return identical frames");
        assert_eq!(state.responses.items.len(), 1, "no re-registration");
        assert_eq!(
            state.responses.next_item_seq, 1,
            "seq advances exactly once"
        );
        // 后续 delta 的 item_id 与 BlockStart 帧一致 (第二次调用不换 id).
        let delta = IrStreamEvent::BlockDelta {
            index: 3,
            delta: IrDelta::TextDelta("x".into()),
        };
        let frames = writer().write_response_event(&delta, &mut state);
        assert_eq!(frames[0].1["item_id"], first[1].1["item_id"]);
        // 下一个不同 index 的 BlockStart 序号正常推进 (探测未消耗序号).
        let ev2 = IrStreamEvent::BlockStart {
            index: 4,
            block: IrBlockMeta::Text,
        };
        let f2 = writer().write_response_event(&ev2, &mut state);
        assert_eq!(f2[0].1["item"]["id"], "msg_1");
    }

    #[test]
    fn stream_write_orphan_block_stop_returns_empty() {
        // 孤儿 BlockStop (无 ItemAccum 记录): 纵深防御, 空帧不 panic.
        let frames = write_events(&[IrStreamEvent::BlockStop { index: 42 }]);
        assert!(frames.is_empty());
    }

    #[test]
    fn stream_write_mismatched_or_unregistered_delta_dropped() {
        // 病态 IR 流的 delta 防御 (ROB-*): delta 类型与 item kind 错配 / delta 先于
        // BlockStart → 丢弃 (空帧), 不 panic, 不污染已注册 item 的内容累积.
        let mut state = crate::codec::ir::StreamEncodeState::default();
        writer().write_response_event(
            &IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::ToolUse {
                    id: "c1".into(),
                    name: "f".into(),
                },
            },
            &mut state,
        );
        // TextDelta 发到 function_call item → 错配丢弃.
        let mismatch = writer().write_response_event(
            &IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("wrong-kind".into()),
            },
            &mut state,
        );
        assert!(mismatch.is_empty());
        // delta 先于 BlockStart (未知 index) → 丢弃.
        let orphan = writer().write_response_event(
            &IrStreamEvent::BlockDelta {
                index: 7,
                delta: IrDelta::InputJsonDelta("{\"a\":1}".into()),
            },
            &mut state,
        );
        assert!(orphan.is_empty());
        // 内容未污染: 后续正确 delta 累积 + done 全量只含正确内容.
        writer().write_response_event(
            &IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::InputJsonDelta("{\"a\":1}".into()),
            },
            &mut state,
        );
        let done =
            writer().write_response_event(&IrStreamEvent::BlockStop { index: 0 }, &mut state);
        assert_eq!(done[0].1["arguments"], "{\"a\":1}");
    }

    #[test]
    fn stream_write_survives_missing_message_start() {
        // 病态 IR 流: block 事件先于 MessageStart / MessageStart 全程缺席 —
        // 不 panic; 元信息缺省在首次合成骨架处隐式初始化 (synth id / now / "").
        let events = vec![
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text,
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("hi".into()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(IrStopReason::EndTurn),
                stop_sequence: None,
                usage: IrUsage::default(),
                usage_present: false,
            },
            IrStreamEvent::MessageStop,
        ];
        let frames = write_events(&events);
        assert_eq!(
            frame_types(&frames),
            vec![
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed"
            ]
        );
        let resp = &frames.last().unwrap().1["response"];
        assert!(resp["id"].as_str().unwrap().starts_with("resp_"));
        assert_eq!(resp["model"], "");
        assert_eq!(resp["status"], "completed");
        assert_eq!(resp["output"][0]["content"][0]["text"], "hi");
    }

    // ─── write_response_event: reader→writer 同协议 round-trip ──────────

    /// 重组帧再次喂 reader (round-trip 第二跳辅助).
    fn read_frames_back(frames: &[(String, Value)]) -> Vec<IrStreamEvent> {
        let input: Vec<(&str, Value)> = frames
            .iter()
            .map(|(t, d)| (t.as_str(), d.clone()))
            .collect();
        feed_stream(&input)
    }

    /// 断言两个 IR 事件流语义等价 (round-trip 保真).
    ///
    /// 逐事件严格 assert_eq, 唯一放宽: MessageDelta 的 `usage_present` 允许
    /// false→true 单向漂移 — writer 无条件写全零 usage 对象 (与非流式一致),
    /// reader 观测到显式 usage 对象即置 present. item_id 变化不出现在此层
    /// (IR 事件不含 item_id; BlockStart 的 ToolUse id 经 call_id 保真).
    fn assert_stream_round_trip(first: &[IrStreamEvent], second: &[IrStreamEvent], ctx: &str) {
        assert_eq!(first.len(), second.len(), "event count drift ({ctx})");
        for (i, (a, b)) in first.iter().zip(second.iter()).enumerate() {
            match (a, b) {
                (
                    IrStreamEvent::MessageDelta {
                        stop_reason: ra,
                        usage: ua,
                        usage_present: pa,
                        ..
                    },
                    IrStreamEvent::MessageDelta {
                        stop_reason: rb,
                        usage: ub,
                        usage_present: pb,
                        ..
                    },
                ) => {
                    assert_eq!(ra, rb, "stop_reason (event {i}, {ctx})");
                    assert_eq!(ua, ub, "usage (event {i}, {ctx})");
                    assert!(
                        !*pa || *pb,
                        "usage_present must not regress true→false (event {i}, {ctx})"
                    );
                }
                _ => assert_eq!(a, b, "event {i} ({ctx})"),
            }
        }
    }

    #[test]
    fn stream_round_trip_text_scenario() {
        let first = feed_stream(&official_text_frames());
        let second = read_frames_back(&write_events(&first));
        assert_stream_round_trip(&first, &second, "text");
    }

    #[test]
    fn stream_round_trip_function_call_scenario() {
        let first = feed_stream(&official_function_call_frames());
        let second = read_frames_back(&write_events(&first));
        assert_stream_round_trip(&first, &second, "function_call");
        // 重点: 工具调用 round-trip 保真 (call_id / name / arguments 全量).
        let tool_blocks: Vec<_> = second
            .iter()
            .filter_map(|ev| match ev {
                IrStreamEvent::BlockStart {
                    block: IrBlockMeta::ToolUse { id, name },
                    ..
                } => Some((id.clone(), name.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            tool_blocks,
            vec![("call_9".to_string(), "get_weather".to_string())]
        );
        let args: String = second
            .iter()
            .filter_map(|ev| match ev {
                IrStreamEvent::BlockDelta {
                    delta: IrDelta::InputJsonDelta(d),
                    ..
                } => Some(d.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(args, "{\"city\":\"SF\"}");
    }

    #[test]
    fn stream_round_trip_reasoning_mixed_scenario() {
        let first = feed_stream(&official_reasoning_mixed_frames());
        let second = read_frames_back(&write_events(&first));
        assert_stream_round_trip(&first, &second, "reasoning_mixed");
        // 重点: 文本与思考内容保真 (事件类型 reasoning_summary_text 是归一形态,
        // 两个方向都如此 — 见 D5 已知损失 4).
        let texts: Vec<&str> = second
            .iter()
            .filter_map(|ev| match ev {
                IrStreamEvent::BlockDelta {
                    delta: IrDelta::TextDelta(d),
                    ..
                } => Some(d.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(texts, vec!["Answer"]);
        let reasoning: Vec<&str> = second
            .iter()
            .filter_map(|ev| match ev {
                IrStreamEvent::BlockDelta {
                    delta: IrDelta::ReasoningDelta(d),
                    ..
                } => Some(d.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(reasoning, vec!["Think "]);
    }

    #[test]
    fn stream_round_trip_incomplete_max_tokens_scenario() {
        // MaxTokens stop_reason 的往返保真: incomplete + details → 读回 MaxTokens.
        let frames = vec![
            created_frame(),
            (
                "response.incomplete",
                json!({"response": {"id": "resp_1", "status": "incomplete",
                                     "incomplete_details": {"reason": "max_output_tokens"},
                                     "usage": {"input_tokens": 4, "output_tokens": 2}}}),
            ),
        ];
        let first = feed_stream(&frames);
        let second = read_frames_back(&write_events(&first));
        assert_stream_round_trip(&first, &second, "incomplete_max_tokens");
    }
}
