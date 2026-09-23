//! OpenAI Responses API 的 Reader / Writer (模块目录).
//!
//! # 目录结构
//!
//! - 本文件 (`mod.rs`): 非流式部分 — `ResponsesReader` / `ResponsesWriter` 的
//!   trait 实现 (流式方法 `read_response_events` / `write_response_event` 委托
//!   `stream` 子模块) + 请求/响应侧的非流式 read/write helpers (流式侧共用) + 非流式测试.
//! - `stream`: 流式部分 — Responses SSE 事件 ↔ IR 事件双向翻译 (`read_responses_stream_event`
//!   / `write_responses_stream_event` 全家 helpers) + 流式测试; 状态机设计要点
//!   (reader 映射表 / writer 合成累积 / 探测双调用幂等契约) 见其文件头.
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
//! 流式: reader + writer 双侧已实现 (实现整体在 `stream.rs`) — proxy 层流式接线:
//! same_proto restore 路径 (`proxy/same_proto.rs`) + 跨协议翻译路径
//! (`proxy/cross_proto.rs`), 端到端行为由集成测试锁定
//! (`cross_protocol_streaming_translates_*` /
//! `responses_streaming_with_secret_hit_restores_mock`, tests/integration.rs).
//!
//! # 同协议 round-trip (FWD-2)
//!
//! Responses 同协议 + Redact 路径走 reader → redact_ir → writer, 与 OpenAI/Anthropic
//! 同协议路径一致. wire 形态元数据 (input_form / instructions_form) 保留 round-trip 保真.

mod stream;

use serde_json::{Map, Value, json};

use super::ir::{
    IrBlock, IrImageSource, IrMessage, IrRequest, IrResponse, IrRole, blocks_has_text,
};
use super::{
    IrError, IrStopReason, IrTool, IrToolChoice, IrUsage, Reader, Writer, blocks_to_text,
    collect_extra, current_epoch, input_to_string, random_base62,
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
            // system_form 是 Anthropic wire 形态元数据, Responses 无此字段 (writer 不消费).
            system_form: None,
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
        stream::read_responses_stream_event(event_type, data, &mut state.responses)
    }
}

// ─── Writer ────────────────────────────────────────────────────────────────

pub struct ResponsesWriter;

impl Writer for ResponsesWriter {
    fn name(&self) -> &'static str {
        "responses"
    }

    fn upstream_path(&self) -> &'static str {
        "/responses"
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
        out.insert(
            "usage".to_string(),
            responses_usage_or_null(&resp.usage, resp.usage_present),
        );
        Value::Object(out)
    }

    fn write_response_event(
        &self,
        ev: &super::IrStreamEvent,
        state: &mut super::ir::StreamEncodeState,
    ) -> Vec<(String, Value)> {
        stream::write_responses_stream_event(ev, &mut state.responses)
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
/// "completed" 按 output 推断 (有 function_call → ToolUse, 否则 EndTurn — 与流式
/// reader 对齐); incomplete 由 incomplete_details.reason 精确化; failed/cancelled/
/// expired 归 Other (IR 无错误信息载体, 读侧保持 — 写侧 Other 已映射 completed).
fn read_response_status(obj: &Map<String, Value>) -> Option<IrStopReason> {
    let status = obj.get("status").and_then(Value::as_str)?;
    match status {
        "completed" => {
            // 按 output 推断 (2026-09-23 统一裁决): 有 function_call item → ToolUse,
            // 否则 EndTurn — 与流式 reader 的 `saw_function_call` 推断对齐, 消除
            // 流式/非流式的粒度分叉 (原恒 EndTurn 是 status 三态表达力不足的
            // 实现阶段折衷).
            let has_function_call =
                obj.get("output")
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        items.iter().any(|it| {
                            it.get("type").and_then(Value::as_str) == Some("function_call")
                        })
                    });
            Some(if has_function_call {
                IrStopReason::ToolUse
            } else {
                IrStopReason::EndTurn
            })
        }
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
            // system 消息按原位输出为 role=system 的 message item (2026-09-23 修正,
            // 与 Anthropic reader 的位置保真对称 — 旧实现跳过, 会静默丢 Anthropic
            // ingress 的中途 system 消息, issue #269)。Text 块 → input_text parts;
            // 其他块类型在 system 消息中不出现, 跳过 (与 user 臂同型)。
            let mut items = Vec::new();
            let mut content_parts: Vec<Value> = Vec::new();
            for b in &msg.content {
                if let IrBlock::Text { text } = b
                    && !text.is_empty()
                {
                    content_parts.push(json!({"type": "input_text", "text": text}));
                }
            }
            // 显式空 system 消息也输出空 content item — 保位比省字节优先.
            items.push(json!({
                "type": "message",
                "role": "system",
                "content": content_parts,
            }));
            items
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
        // Other (未知停止原因) → completed (2026-09-23 裁决): 未知大多是正常结束的
        // 变体, 映射 failed 会触发客户端错误处理路径 (弹错/重试), 误导性强 —
        // "未知不伪装成确定错误". 读侧 "failed"→Other 保持 (read_response_status),
        // round-trip failed→Other→completed 有损, 是该折衷的已知代价.
        Some(IrStopReason::Other) => "completed",
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

/// usage 呈现值 (非流式 `write_response` 与流式终止事件共用 SSOT):
/// present → Responses 风格对象; 缺失 → null (诚实呈现, 2026-09-23 裁决) —
/// 上游没报用量时合成全零对象会伪装成 "网关报了 0", null 保留 "缺失" 语义,
/// reader 读回 usage_present=false (round-trip presence 保真).
fn responses_usage_or_null(u: &IrUsage, present: bool) -> Value {
    if present {
        responses_usage_json(u)
    } else {
        Value::Null
    }
}

/// 合成 response id (resp_ 前缀 + base62).
fn synth_response_id() -> String {
    format!("resp_{}", random_base62(24))
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
        // (status, output items, expected) — completed 按 output 推断 (2026-09-23
        // 统一): 有 function_call → ToolUse, 无 → EndTurn (与流式 reader 对齐).
        let fc_item = json!({
            "type": "function_call", "id": "fc_1", "call_id": "c1",
            "name": "f", "arguments": "{}"
        });
        let cases = [
            ("completed", json!([]), IrStopReason::EndTurn),
            ("completed", json!([fc_item]), IrStopReason::ToolUse),
            ("incomplete", json!([]), IrStopReason::Other), // 无 incomplete_details 时归 Other (m2 修复)
            ("failed", json!([]), IrStopReason::Other),
        ];
        for (status, output, expected) in cases {
            let body = json!({
                "id": "x", "model": "m", "status": status,
                "output": output,
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
        // usage_present=false → null (诚实呈现缺失, 不伪造全零对象).
        assert_eq!(v.get("usage").unwrap(), &Value::Null);
    }

    #[test]
    fn write_response_other_maps_to_completed() {
        // Other (未知停止原因) → "completed" (2026-09-23 裁决): 伪装 failed 会触发
        // 客户端错误处理路径. 读侧 "failed"→Other 保持, round-trip
        // failed→Other→completed 有损 — 已知折衷 (见 write_status_str 注释).
        let ir = IrResponse {
            content: vec![IrBlock::Text {
                text: "done".into(),
            }],
            stop_reason: Some(IrStopReason::Other),
            usage: IrUsage::default(),
            usage_present: false,
            model: Some("gpt-4o".into()),
            id: None,
            created: None,
            stop_sequence: None,
        };
        let v = writer().write_response(&ir);
        assert_eq!(v.get("status").unwrap(), "completed");
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
    fn round_trip_response_usage_absent_stays_absent() {
        // usage 缺席 → usage_present=false → writer 写 null (不伪造全零) →
        // reader 读回 absent — 诚实呈现的非流式 round-trip 保真 (2026-09-23).
        let original = json!({
            "id": "resp_1",
            "object": "response",
            "created_at": 1700000000,
            "model": "gpt-4o",
            "status": "completed",
            "output": [{
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "Hi"}]
            }],
        });
        let ir = reader().read_response(&original).unwrap();
        assert!(!ir.usage_present);
        let rewritten = writer().write_response(&ir);
        assert_eq!(rewritten.get("usage").unwrap(), &Value::Null);
        let ir2 = reader().read_response(&rewritten).unwrap();
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
}
