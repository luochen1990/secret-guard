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
//!   `function_call` / `function_call_output` / `reasoning` (summary + encrypted_content,
//!   T7 passthrough)
//! - `instructions` → system 消息
//! - tools: `function` 类型 (平铺 `{name, parameters, description, strict?}` ↔ Chat
//!   嵌套 `{type:"function", function:{...}}`; strict 等未建模字段经条目级 extra
//!   保真, parameters 缺席不注入默认 schema); **非 function 条目 (hosted tools:
//!   web_search / file_search / computer_use / mcp / tool_search / custom / ...) 收为
//!   [`IrTool::Raw`] 原文保真 (#321)** — 同协议 round-trip verbatim 回写, 字符串
//!   叶子进 redact 扫描面; 跨协议翻译在 `clear_wire_fidelity` 丢弃 + WARN
//! - usage 双向映射
//! - 非流式响应: `output[]` 中的 `message` (output_text) + `function_call` items
//!
//! **不覆盖** (响应侧读取时丢弃 — 请求侧 tools 已全部保真, 见上):
//! - 响应侧 hosted tool call items (web_search_call / computer_call / file_search_call /
//!   mcp_call / ...) — 请求侧 tool_search 机制发现工具后模型按普通 `function_call`
//!   调用 (已建模), 响应侧无新增形态需求 (#321 核实)
//! - namespace tools flattening (留作后续)
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
    ContentForm, IrBlock, IrImageSource, IrMessage, IrReasoning, IrReasoningEffort, IrRequest,
    IrResponse, IrRole, blocks_has_text,
};
use super::{
    IrError, IrStopReason, IrTool, IrToolChoice, IrUsage, Reader, Writer, blocks_to_text,
    collect_extra, current_epoch, image_source_to_url, input_to_string, merge_extra_into,
    random_base62,
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
                            content: vec![IrBlock::Text {
                                text: s.clone(),
                                extra: Default::default(),
                            }],
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
        // reasoning 配置 (A1): reasoning.effort → Effort. reasoning 对象整体留在
        // extra (不进 collect_extra 排除清单) — summary 等未建模子字段靠 extra
        // 同协议保真, 这里只投影 effort 档位; 未知档位 → None (ROB).
        let reasoning = obj
            .get("reasoning")
            .and_then(|r| r.get("effort"))
            .and_then(Value::as_str)
            .and_then(IrReasoningEffort::parse)
            .map(IrReasoning::Effort);

        // tools: Responses 的 tools 是平铺数组, 每个有 type.
        // function 类型: {type:"function", name, parameters, description, strict?}
        // → IrTool::Function (strict 等未建模字段经条目级 extra 保真, #269 同型).
        // 其他类型 (web_search/file_search/computer/mcp/tool_search/custom/...):
        // IrTool::Raw 原文保真 (#321) — 同协议 round-trip verbatim 回写, 不再
        // 在 reader 层丢弃; 跨协议丢弃收口在 clear_wire_fidelity (该处 WARN).
        let (tools, tools_present) = if let Some(arr) = obj.get("tools").and_then(Value::as_array) {
            let tools: Vec<IrTool> = arr.iter().map(read_tool_def).collect();
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
            // max_tokens_form 是 OpenAI Chat 双读别名的 wire 形态元数据, Responses
            // 单字段 (max_output_tokens) 无名可记 (writer 不消费).
            max_tokens_form: None,
            temperature,
            top_p,
            top_k: None, // Responses 无 top_k
            stop: Vec::new(),
            stop_form: None,
            tool_choice,
            user: None, // Responses 无 user 字段
            parallel_tool_calls,
            stream,
            reasoning,
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
            // #402: extra 是 a 协议 wire 形态容器, o/r reader 不收集 (typed-only).
            extra: Default::default(),
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
        // reasoning 配置 (A1): 跨协议注入 reasoning {effort} (to_effort 投影,
        // Disabled → 无对应字段不写). same-proto 时 extra 携带原始 reasoning
        // 对象 (含 summary 等子字段), 跳过注入由 extra 原样回写 (无双写 / 无损失).
        if let Some(effort) = req.reasoning.and_then(IrReasoning::to_effort)
            && !req.extra.contains_key("reasoning")
        {
            out.insert("reasoning".to_string(), json!({"effort": effort.as_str()}));
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
                IrBlock::Text { text, .. } => {
                    if !text.is_empty() {
                        text_acc.push_str(text);
                    }
                }
                IrBlock::ToolUse {
                    id, name, input, ..
                } => {
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
                IrBlock::Reasoning {
                    summary,
                    opaque,
                    extra,
                } => {
                    // provider opaque 原样写回 (T7: 同协议 fidelity / a-origin
                    // envelope 由 reader 侧解包, 这里只会是 r 原生 blob)。
                    flush_text(&mut text_acc, &mut output);
                    output.push(reasoning_item_json(
                        summary
                            .iter()
                            .map(|s| json!({"type": "summary_text", "text": s}))
                            .collect(),
                        opaque.clone(),
                        extra,
                    ));
                }
                IrBlock::ReasoningContent {
                    text,
                    opaque,
                    extra,
                } => {
                    // T7: a-origin thinking 族正文以 summary 形态承载 (语义降档,
                    // 与流式保留裁决同型), opaque 经 sg-envelope 搬进 encrypted_content
                    // — stateless tool loop 回传时 reader 侧解包还原 (codec/thinking.rs)。
                    // o-origin (opaque=None) 保留正文、**不**发 envelope (零信息增益
                    // 且外来 ec 有上游拒收风险 — o→r→o 的身份回传本就因 r→o 丢弃
                    // 不可达); 消除 "流式保留/非流式丢弃" 分叉 (契约演进原则的精确化)。
                    flush_text(&mut text_acc, &mut output);
                    if text.is_empty() && opaque.is_none() {
                        continue; // 零信息块 (与 unpack 的退化丢弃规则对称)。
                    }
                    let summary_items = if text.is_empty() {
                        Vec::new()
                    } else {
                        vec![json!({"type": "summary_text", "text": text})]
                    };
                    let ec = opaque
                        .as_ref()
                        .map(|op| super::thinking::pack_reasoning_content(text, &Some(op.clone())));
                    output.push(reasoning_item_json(summary_items, ec, extra));
                }
                IrBlock::ToolResult { .. } | IrBlock::Image { .. } => {
                    // 响应里通常不出现, 跳过.
                }
                // Raw 原文 verbatim 回写 (#363): 响应侧 output message content 的
                // 未知 part 同协议 round-trip 保真 — flush 累积文本后以独立
                // message item 原样携带 (不折叠进 text_acc, 折叠会改写形态).
                IrBlock::Raw { entry } => {
                    flush_text(&mut text_acc, &mut output);
                    output.push(json!({
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [entry.clone()],
                    }));
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
        let (status, incomplete_reason) = write_status_and_reason(resp.stop_reason);
        out.insert("status".to_string(), json!(status));
        // incomplete 时写 reason, reader 才能精确化读回 (round-trip 保真, #285);
        // completed 不写该键 (最小 wire 差异).
        if let Some(reason) = incomplete_reason {
            out.insert("incomplete_details".to_string(), json!({"reason": reason}));
        }
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
        Value::String(s) if !s.is_empty() => vec![IrBlock::Text {
            text: s.clone(),
            extra: Default::default(),
        }],
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
                                extra: Default::default(),
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
/// 降级: reasoning item 的 summary 空且无 encrypted_content 时丢弃
/// (T7 起 encrypted_content 已保留, 见 read_reasoning_block).
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
            // L1 保真 (#403): 记录 output 原始形态 (string / array) — writer 按原形态
            // 回写; array 形态承载 input_image 等媒体 part (官方 2025-09 起支持),
            // r→r round-trip 媒体原位保真的依据.
            let content_form = ContentForm::classify(obj.get("output"));
            Some(vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error: None, // Responses 协议无 is_error 概念
                    content_form,
                    extra: Default::default(),
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
                vec![IrBlock::Text {
                    text: s.clone(),
                    extra: Default::default(),
                }]
            }
        }
        Value::Array(arr) => arr.iter().filter_map(read_content_part).collect(),
        _ => Vec::new(),
    }
}

/// 解析 content array 中的一个 part.
///
/// 无法建模的元素 (未知 type (input_file 等) / 结构畸形的已知 type / 非对象
/// 元素) 收为 [`IrBlock::Raw`] 原文保真 (#363, 与 IrTool::Raw #321 同型) —
/// 同协议 verbatim round-trip, 上游自会拒绝畸形形态; 唯一例外是空文本形态
/// (`text:""` 等) 按既有约定视为缺席丢弃 (writer 对称跳过, FWD-2 生成器不
/// 生成该形态).
fn read_content_part(part: &Value) -> Option<IrBlock> {
    let raw = || {
        Some(IrBlock::Raw {
            entry: part.clone(),
        })
    };
    let Some(obj) = part.as_object() else {
        // 非对象元素: 原文保真透传, 上游自会拒绝.
        return raw();
    };
    let Some(ty) = obj.get("type").and_then(Value::as_str) else {
        // 无 type 字段 / type 非 string: 畸形 → Raw 原文透传.
        return raw();
    };
    match ty {
        "input_text" | "output_text" | "text" => match obj.get("text") {
            Some(Value::String(text)) if text.is_empty() => None,
            Some(Value::String(text)) => Some(IrBlock::Text {
                text: text.clone(),
                extra: Default::default(),
            }),
            // text 缺席/类型不符: 畸形已知 type → Raw 原文透传.
            _ => raw(),
        },
        "input_image" => match obj.get("image_url").and_then(Value::as_str) {
            Some(url) => Some(IrBlock::Image {
                source: IrImageSource::Url(url.to_string()),
                extra: Default::default(),
            }),
            // image_url 缺席: 畸形已知 type → Raw 原文透传.
            None => raw(),
        },
        "image_url" => {
            // OpenAI 风格 image_url (object {url: ...}).
            match obj
                .get("image_url")
                .and_then(|v| v.get("url"))
                .and_then(Value::as_str)
            {
                Some(url) => Some(IrBlock::Image {
                    source: IrImageSource::Url(url.to_string()),
                    extra: Default::default(),
                }),
                // url 缺席: 畸形已知 type → Raw 原文透传.
                None => raw(),
            }
        }
        "refusal" => {
            // refusal text → Text block (语义降级, 但保留信息).
            match obj.get("refusal").and_then(Value::as_str) {
                Some("") => None,
                Some(text) => Some(IrBlock::Text {
                    text: text.to_string(),
                    extra: Default::default(),
                }),
                // refusal 缺席/类型不符: 畸形已知 type → Raw 原文透传.
                _ => raw(),
            }
        }
        // 未知类型 → Raw 原文保真 (#363, 修复前静默 drop 是 FWD-1 违约; ROB-1
        // 依旧成立 — Raw 是纯数据容器, 不做任何解析假设).
        _ => raw(),
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

/// 解析 Responses tool 定义 → IrTool (#321: 永不返回 None / 永不丢弃条目).
/// Responses function tool: {type:"function", name, parameters?, description?, strict?, ...}
/// (注意: Responses 是平铺的, Chat 是嵌套在 function 子对象里).
/// - 合法 function 条目 → [`IrTool::Function`]; `parameters` 缺席存 Null 哨兵
///   (writer 跳过, 不注入默认 schema — 加字段同属 FWD-1 违约); strict 等其余
///   未建模字段经条目级 extra 保真回写.
/// - 其余一切 (hosted tools: web_search/file_search/computer/mcp/tool_search/
///   image_generation / custom / 未知 type / 非 function 或缺 name 的畸形条目 /
///   非对象元素) → [`IrTool::Raw`] 原文保真: 同协议 verbatim round-trip,
///   跨协议由 `clear_wire_fidelity` 丢弃 + WARN.
fn read_tool_def(tool: &Value) -> IrTool {
    let parse_function = (|| {
        let obj = tool.as_object()?;
        if obj.get("type").and_then(Value::as_str) != Some("function") {
            return None;
        }
        let name = obj.get("name").and_then(Value::as_str)?;
        if name.is_empty() {
            return None;
        }
        let description = obj
            .get("description")
            .and_then(Value::as_str)
            .map(String::from);
        Some(IrTool::Function {
            name: name.to_string(),
            description,
            // parameters 缺席 → Null 哨兵 (不注入默认 {"type":"object"}).
            input_schema: obj.get("parameters").cloned().unwrap_or(Value::Null),
            extra: collect_extra(obj, &["type", "name", "description", "parameters"]),
        })
    })();
    parse_function.unwrap_or(IrTool::Raw {
        entry: tool.clone(),
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
        // #402: extra 是 a 协议 wire 形态容器, o/r reader 不收集 (typed-only).
        extra: Default::default(),
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
                    if let IrBlock::Text { text, .. } = b {
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
                Some(IrBlock::Text {
                    text,
                    extra: Default::default(),
                })
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
    IrBlock::ToolUse {
        id,
        name,
        input,
        extra: Default::default(),
    }
}

/// 构造 reasoning item 的 wire JSON (T7 SSOT — `write_response` 与
/// `write_input_items` 共用, summary items + 可选 `encrypted_content` + L5 extra
/// 原样回写; 同名覆盖优先级: modeled 字段 > extra, 与 merge_extra_into 契约一致)。
fn reasoning_item_json(
    summary_items: Vec<Value>,
    encrypted: Option<String>,
    extra: &Map<String, Value>,
) -> Value {
    let mut item = Map::new();
    item.insert("type".to_string(), json!("reasoning"));
    item.insert("summary".to_string(), Value::Array(summary_items));
    if let Some(ec) = encrypted {
        item.insert("encrypted_content".to_string(), json!(ec));
    }
    for (k, v) in extra {
        item.insert(k.clone(), v.clone());
    }
    Value::Object(item)
}

/// 解析 reasoning item → [`IrBlock`] (T7: 含 encrypted_content opaque 搬运).
///
/// request input items 和 response output items 都用此 helper.
/// - `encrypted_content` 带 `sg-thinking-v1:` 前缀 → envelope 解包 (reader 侧
///   pre-redact 位置 — 解包文本成为叶子, 必然流经扫描; envelope 块为权威源,
///   wire 上的 summary 丢弃, 见 codec/thinking.rs 安全链注记)。
/// - 无前缀 → 视为 r 原生 provider opaque, 原样保留 (同协议 round-trip 不丢,
///   修复 reasoning chain 断裂已知限制)。
/// - 空 summary 且无 opaque → None (无信息量, 与既有退化规则一致)。
fn read_reasoning_block(obj: &Map<String, Value>) -> Option<IrBlock> {
    let summary = read_reasoning_summary(obj.get("summary"));
    let opaque = obj
        .get("encrypted_content")
        .and_then(Value::as_str)
        .map(str::to_string);
    // L5 (T7 修复轮): 未建模字段 (item id 等) 收集 — envelope 载荷不携带 extra,
    // 解包后与本跳 wire 现收值合并 (同 anthropic.rs::merge_wire_extra 语义)。
    let extra: Map<String, Value> = obj
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "type" | "summary" | "encrypted_content"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(env) = &opaque
        && let Some(mut block) = super::thinking::unpack(env)
    {
        // sg-envelope: 权威源 (我们上一跳自己打包的块), wire summary 是其投影;
        // extra 以本跳 wire 为准 (envelope 不携带)。
        match &mut block {
            IrBlock::Reasoning { extra: dst, .. }
            | IrBlock::ReasoningContent { extra: dst, .. } => *dst = extra,
            _ => {}
        }
        return Some(block);
    }
    if summary.is_empty() && opaque.is_none() {
        None
    } else {
        Some(IrBlock::Reasoning {
            summary,
            opaque,
            extra,
        })
    }
}

/// IR block → Responses content part (Text → input_text, Image → input_image
/// (Base64 → data URL), Raw → verbatim (#363 同型)). 空 Text 跳过 (与 reader
/// `read_content_part` 的 "空文本视为缺席" 对称); ToolUse / reasoning 族 → None
/// (user/system 消息通常不出现, 出现即不可表示). message content 与
/// `function_call_output.output` array 共享同一套 part 形态 (reader 侧
/// `read_message_content` 的同一对称, #403).
fn block_to_input_part(b: &IrBlock) -> Option<Value> {
    match b {
        IrBlock::Text { text, .. } if !text.is_empty() => {
            Some(json!({"type": "input_text", "text": text}))
        }
        IrBlock::Image { source, .. } => Some(json!({
            "type": "input_image",
            "image_url": image_source_to_url(source)
        })),
        // Raw 原文 verbatim 回写 (#363): input_file 等未建模 part 原位保真
        // (跨协议路径已被 clear_wire_fidelity 丢弃, 不会走到这里).
        IrBlock::Raw { entry } => Some(entry.clone()),
        _ => None,
    }
}

/// #403: ToolResult content → `function_call_output.output` array 形态的 parts
/// (官方 2025-09 起支持 `string | array of (input_text|input_image|input_file)`).
/// part 映射共享 [`block_to_input_part`]; is_error → `[error]` 前缀: 拼进首个
/// **Text 派生** part (Raw 条目即使 type 形似 input_text 也不可改写 — verbatim
/// 契约), 无 text part 时独立成 part (与 string 形态的 `"[error] {text}"` 对齐).
fn tool_result_output_parts(content: &[IrBlock], is_error: Option<bool>) -> Vec<Value> {
    let mut parts: Vec<Value> = Vec::new();
    let mut first_text_idx: Option<usize> = None;
    for b in content {
        if matches!(b, IrBlock::Text { text, .. } if !text.is_empty()) && first_text_idx.is_none() {
            first_text_idx = Some(parts.len());
        }
        parts.extend(block_to_input_part(b));
    }
    if is_error.unwrap_or(false) {
        match first_text_idx.and_then(|i| parts.get_mut(i)) {
            Some(Value::Object(first)) => {
                let prefixed = format!("[error] {}", first["text"].as_str().unwrap_or_default());
                first.insert("text".to_string(), Value::String(prefixed));
            }
            _ => parts.insert(0, json!({"type": "input_text", "text": "[error]"})),
        }
    }
    parts
}

/// IR message → Responses input items (一条 IR message 可能产出多个 items).
///
/// 关键: OpenAI Chat 的 assistant tool_calls 数组在 Responses 里是独立的 function_call items.
fn write_input_items(msg: &IrMessage) -> Vec<Value> {
    match msg.role {
        IrRole::System => {
            // system 消息按原位输出为 role=system 的 message item (2026-09-23 修正,
            // 与 Anthropic reader 的位置保真对称 — 旧实现跳过, 会静默丢 Anthropic
            // ingress 的中途 system 消息, issue #269)。part 映射共享
            // `block_to_input_part` (#403: Image 亦回写 — IrRole::System 消息只来自
            // a reader (原位保留的 role=system, content 可含 image block), 这是
            // **a→r 跨协议**的保真改进; r→r 同协议的 system item 媒体仍经
            // instructions 折叠丢弃 (reader 提升到顶层 system, L2 搁置项)).
            let mut items = Vec::new();
            let content_parts: Vec<Value> =
                msg.content.iter().filter_map(block_to_input_part).collect();
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
                    IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                        content_form,
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
                        // #403 媒体原位保真: `function_call_output.output` 官方支持
                        // `string | array of (input_text|input_image|input_file)`
                        // (2025-09 起, openai-python v2 breaking change) — 无需搬运,
                        // 非 Text 块以原生 part 形态留在 output 内:
                        //   - Some(Array) → array 形态 (r→r round-trip 形态保真)
                        //   - Some(String)/Some(Null) → string 形态 (String 原形态
                        //     回写; Null 归一为 string — 既有行为, 非"原形态";
                        //     两者都携带不了媒体, reader 不可达防御面)
                        //   - None (跨协议 / 内部构造) → 含非 Text 块时 array (媒体
                        //     原位), 否则 string (与既有行为兼容)
                        // 不可表示块 (reasoning 族 / 嵌套) 折叠丢弃, fate 统计在
                        // proxy egress 写出点.
                        let has_nontext =
                            content.iter().any(|b| !matches!(b, IrBlock::Text { .. }));
                        let use_array = match content_form {
                            Some(ContentForm::Array) => true,
                            Some(_) => false,
                            None => has_nontext,
                        };
                        let output_val = if use_array {
                            Value::Array(tool_result_output_parts(content, *is_error))
                        } else {
                            let text = blocks_to_text(content);
                            if is_error.unwrap_or(false) {
                                json!(format!("[error] {text}"))
                            } else {
                                Value::String(text)
                            }
                        };
                        items.push(json!({
                            "type": "function_call_output",
                            "call_id": tool_use_id,
                            "output": output_val,
                        }));
                    }
                    // Text (非空) / Image / Raw → 原生 part (共享 `block_to_input_part`,
                    // #403 收敛); 其余 (ToolUse / reasoning 族 / 空 Text — user 消息
                    // 通常不出现) 跳过.
                    _ => {
                        if let Some(part) = block_to_input_part(b) {
                            content_parts.push(part);
                        }
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
                    IrBlock::Text { text, .. } => {
                        if !text.is_empty() {
                            text_parts.push(json!({"type": "output_text", "text": text}));
                        }
                    }
                    IrBlock::ToolUse {
                        id, name, input, ..
                    } => {
                        flush_text(&mut text_parts, &mut items);
                        items.push(json!({
                            "type": "function_call",
                            "call_id": id,
                            "name": name,
                            "arguments": input_to_string(input),
                        }));
                    }
                    IrBlock::Reasoning {
                        summary,
                        opaque,
                        extra,
                    } => {
                        flush_text(&mut text_parts, &mut items);
                        items.push(reasoning_item_json(
                            summary
                                .iter()
                                .map(|s| json!({"type": "summary_text", "text": s}))
                                .collect(),
                            opaque.clone(),
                            extra,
                        ));
                    }
                    IrBlock::ReasoningContent {
                        text,
                        opaque,
                        extra,
                    } => {
                        // T7: 请求侧 assistant 历史 (a-origin thinking 回传) 同样以
                        // summary + envelope 搬运 (与 write_response 同型; o-origin
                        // 正文保留、不发 envelope)。回传方向 reader 解包 → a writer
                        // 原生写回。
                        flush_text(&mut text_parts, &mut items);
                        if text.is_empty() && opaque.is_none() {
                            continue; // 零信息块 (与 unpack 的退化丢弃规则对称)。
                        }
                        let summary_items = if text.is_empty() {
                            Vec::new()
                        } else {
                            vec![json!({"type": "summary_text", "text": text})]
                        };
                        let ec = opaque.as_ref().map(|op| {
                            super::thinking::pack_reasoning_content(text, &Some(op.clone()))
                        });
                        items.push(reasoning_item_json(summary_items, ec, extra));
                    }
                    IrBlock::ToolResult { .. } | IrBlock::Image { .. } => {
                        // assistant 消息里通常不出现, 跳过.
                    }
                    // Raw 原文 verbatim 回写 (#363): assistant 历史 content 的
                    // 未知 part 同协议 round-trip 保真 (跨协议路径已被
                    // clear_wire_fidelity 丢弃, 不会走到这里).
                    IrBlock::Raw { entry } => {
                        text_parts.push(entry.clone());
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
    match tool {
        // Raw 原文 verbatim 回写 (#321): reader 收的是本协议 wire 的原始条目,
        // 同协议 round-trip 必须字节保真 (跨协议路径已被 clear_wire_fidelity
        // 丢弃, 不会走到这里 — 与 extra 的 seam 契约同型).
        IrTool::Raw { entry } => entry.clone(),
        IrTool::Function {
            name,
            description,
            input_schema,
            extra,
        } => {
            let mut obj = Map::new();
            obj.insert("type".to_string(), json!("function"));
            obj.insert("name".to_string(), Value::String(name.clone()));
            if let Some(desc) = description {
                obj.insert("description".to_string(), Value::String(desc.clone()));
            }
            // Null 哨兵 = 原始 wire 缺 parameters 字段, 跳过 (不注入默认 schema).
            if !input_schema.is_null() {
                obj.insert("parameters".to_string(), input_schema.clone());
            }
            merge_extra_into(&mut obj, extra);
            Value::Object(obj)
        }
    }
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

/// IrStopReason → (Responses status 字符串, incomplete_details.reason 值) 一体产出.
///
/// status 与 reason 的 IrStopReason 映射收敛为单一 SSOT — 非流式 `write_response`
/// 与流式终止事件 `stream_write_terminal_response` **整块**共享 (#285: 此前 status
/// 共用而 reason 仅流式手写, 半截 SSOT 分叉致非流式 incomplete 轮次丢 reason,
/// MaxTokens round-trip 降级 Other). reason 仅 incomplete 变体为 Some:
/// MaxTokens→max_output_tokens; Safety/Refusal→content_filter (Refusal 无官方
/// reason 对应, 归 content_filter — reader 读回 Safety, Refusal→Safety 的往返
/// 损失已知, Responses wire 无更精确的表达).
fn write_status_and_reason(reason: Option<IrStopReason>) -> (&'static str, Option<&'static str>) {
    match reason {
        None | Some(IrStopReason::EndTurn) | Some(IrStopReason::StopSequence) => {
            ("completed", None)
        }
        Some(IrStopReason::MaxTokens) => ("incomplete", Some("max_output_tokens")),
        Some(IrStopReason::ToolUse) => ("completed", None), // 工具调用也算 completed
        Some(IrStopReason::Safety) | Some(IrStopReason::Refusal) => {
            ("incomplete", Some("content_filter"))
        }
        // Other (未知停止原因) → completed (2026-09-23 裁决): 未知大多是正常结束的
        // 变体, 映射 failed 会触发客户端错误处理路径 (弹错/重试), 误导性强 —
        // "未知不伪装成确定错误". 读侧 "failed"→Other 保持 (read_response_status),
        // round-trip failed→Other→completed 有损, 是该折衷的已知代价.
        // #388: Anthropic 专属官方值 (PauseTurn / ContextWindowExceeded) 同走
        // completed — r 侧无对应概念, 跨协议投影与 Other 一致.
        Some(IrStopReason::PauseTurn)
        | Some(IrStopReason::ContextWindowExceeded)
        | Some(IrStopReason::Other) => ("completed", None),
    }
}

/// IrStopReason → Responses status 字符串 (str 形态 — 流式事件名用,
/// `write_status_and_reason` 的 status 投影; 需要伴随 reason 的消费面一律走
/// `write_status_and_reason`, 避免半截消费 #285 反模式复发).
fn write_status_str(reason: Option<IrStopReason>) -> &'static str {
    write_status_and_reason(reason).0
}

/// IR usage → Responses 风格 usage JSON ({input_tokens, output_tokens, total_tokens}).
///
/// `input_tokens` 与 OpenAI `prompt_tokens` 同语义 (含 cached 总和), 总和复用
/// [`IrUsage::openai_prompt_tokens`] SSOT (#284 修复前手算漏加 cache_creation);
/// `cache_read` 经 `input_tokens_details.cached_tokens` 写回 — 条件写判据与
/// Anthropic writer 的双 cache 字段一致 (`Some` 即写); `cache_creation` 无
/// Responses 对应字段, 只计入总和.
fn responses_usage_json(u: &IrUsage) -> Value {
    let input_total = u.openai_prompt_tokens();
    let mut obj = Map::new();
    obj.insert("input_tokens".to_string(), json!(input_total));
    obj.insert("output_tokens".to_string(), json!(u.output_tokens));
    obj.insert(
        "total_tokens".to_string(),
        json!(input_total.saturating_add(u.output_tokens)),
    );
    if let Some(cached) = u.cache_read_input_tokens {
        obj.insert(
            "input_tokens_details".to_string(),
            json!({ "cached_tokens": cached }),
        );
    }
    Value::Object(obj)
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

    // ─── IR block 构造 helper (#403 测试族共用) ──────────────────────────

    fn text(s: &str) -> IrBlock {
        IrBlock::Text {
            text: s.into(),
            extra: Default::default(),
        }
    }
    fn img(url: &str) -> IrBlock {
        IrBlock::Image {
            source: IrImageSource::Url(url.into()),
            extra: Default::default(),
        }
    }
    fn tr(
        content: Vec<IrBlock>,
        content_form: Option<ContentForm>,
        is_error: Option<bool>,
    ) -> IrBlock {
        IrBlock::ToolResult {
            tool_use_id: "call_1".into(),
            content,
            is_error,
            content_form,
            extra: Default::default(),
        }
    }
    fn user_req(content: Vec<IrBlock>) -> IrRequest {
        IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content,
                ..Default::default()
            }],
            model: "gpt-5.4".into(),
            ..Default::default()
        }
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
            IrBlock::Text { text, .. } => assert_eq!(text, "Hello"),
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
            IrBlock::ToolUse {
                id, name, input, ..
            } => {
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
            IrBlock::Reasoning { summary, .. } => {
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
        assert!(matches!(
            ir.tools[0],
            IrTool::Function { ref name, ref description, .. }
                if name == "search" && description.as_deref() == Some("Search the web")
        ));
    }

    #[test]
    fn read_request_raw_tools_kept_verbatim() {
        // web_search / computer / mcp / tool_search 等非 function 类型收为 Raw
        // 原文保真 (#321), 不再丢弃; 混合数组的顺序与位置保留.
        let body = json!({
            "model": "gpt-5.4",
            "input": "hi",
            "tools": [
                {"type": "function", "name": "f1", "parameters": {}},
                {"type": "tool_search", "defer_loading": true, "namespace": "search"},
                {"type": "web_search"},
                {"type": "mcp", "server_label": "x"}
            ]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.tools.len(), 4);
        assert!(matches!(ir.tools[0], IrTool::Function { ref name, .. } if name == "f1"));
        // Raw 条目 = 原始 JSON 原样 (含 tool_search 的 defer_loading / namespace).
        assert!(matches!(ir.tools[1], IrTool::Raw { .. }));
        // 同协议 round-trip verbatim: normalize 相等 (hosted 条目一个字节不丢).
        let out = writer().write_request(&ir);
        // 只比 tools 子字段: input 的 string→数组展开是既有规范化, 与本断言正交.
        assert_eq!(
            crate::codec::normalize::normalize_json(&body["tools"]),
            crate::codec::normalize::normalize_json(&out["tools"])
        );
    }

    #[test]
    fn read_request_malformed_function_entry_is_raw() {
        // 畸形 function 条目 (缺 name / name 空 / 非 function type / 非对象):
        // 不丢弃, 收为 Raw 让上游自己拒绝 (FWD-1: 网关不代客户端改写).
        let body = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [
                {"type": "function", "parameters": {}},
                {"type": "function", "name": ""},
                "not-even-an-object",
                {"type": "custom", "name": "apply_patch", "format": {"type": "grammar"}}
            ]
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.tools.len(), 4);
        assert!(ir.tools.iter().all(|t| matches!(t, IrTool::Raw { .. })));
        let out = writer().write_request(&ir);
        // 只比 tools 子字段: input 的 string→数组展开是既有规范化, 与本断言正交.
        assert_eq!(
            crate::codec::normalize::normalize_json(&body["tools"]),
            crate::codec::normalize::normalize_json(&out["tools"])
        );
    }

    #[test]
    fn read_request_function_tool_unmodeled_fields_via_extra() {
        // function 条目上的未建模字段 (strict 等) 经条目级 extra 保真回写;
        // parameters 缺席 → writer 不注入默认 schema (Null 哨兵).
        let body = json!({
            "model": "gpt-5.4",
            "input": "hi",
            "tools": [
                {"type": "function", "name": "strict_tool", "strict": true},
                {"type": "function", "name": "no_params"}
            ]
        });
        let ir = reader().read_request(&body).unwrap();
        assert!(matches!(
            ir.tools[0],
            IrTool::Function { ref input_schema, ref extra, .. }
                if input_schema.is_null() && extra.get("strict") == Some(&json!(true))
        ));
        let out = writer().write_request(&ir);
        // 只比 tools 子字段: input 的 string→数组展开是既有规范化, 与本断言正交.
        assert_eq!(
            crate::codec::normalize::normalize_json(&body["tools"]),
            crate::codec::normalize::normalize_json(&out["tools"])
        );
    }

    // ─── reasoning 配置 (A1) ────────────────────────────────────────────

    #[test]
    fn read_request_reasoning_effort_and_summary_in_extra() {
        use crate::codec::ir::{IrReasoning, IrReasoningEffort};
        // reasoning.effort → first-class Effort; summary 等子字段靠 extra
        // (reasoning 对象不进 collect_extra 排除清单) same-proto 保真.
        let body = json!({
            "model": "gpt-5",
            "input": "hi",
            "reasoning": {"effort": "low", "summary": "auto"},
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(
            ir.reasoning,
            Some(IrReasoning::Effort(IrReasoningEffort::Low))
        );
        assert_eq!(
            ir.extra.get("reasoning"),
            Some(&json!({"effort": "low", "summary": "auto"}))
        );
        // 未知档位 → None (ROB), extra 兜底.
        let body = json!({
            "model": "gpt-5",
            "input": "hi",
            "reasoning": {"effort": "banana"},
        });
        let ir = reader().read_request(&body).unwrap();
        assert_eq!(ir.reasoning, None);
        assert_eq!(
            ir.extra.get("reasoning"),
            Some(&json!({"effort": "banana"}))
        );
    }

    #[test]
    fn write_request_reasoning_effort_and_extra_priority() {
        use crate::codec::ir::{IrReasoning, IrReasoningEffort};
        let mk = |reasoning| IrRequest {
            model: "m".into(),
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text {
                    text: "hi".into(),
                    extra: Default::default(),
                }],
                ..Default::default()
            }],
            reasoning,
            ..Default::default()
        };
        // 跨协议 (extra 空): Effort 直写; Budget → nearest; Disabled → 不写.
        let v = writer().write_request(&mk(Some(IrReasoning::Effort(IrReasoningEffort::Medium))));
        assert_eq!(v.get("reasoning"), Some(&json!({"effort": "medium"})));
        let v = writer().write_request(&mk(Some(IrReasoning::Budget(2000))));
        // 2000 → nearest Low (2048).
        assert_eq!(v.get("reasoning"), Some(&json!({"effort": "low"})));
        let v = writer().write_request(&mk(Some(IrReasoning::Disabled)));
        assert!(v.get("reasoning").is_none());

        // same-proto (extra 有 reasoning): extra 优先回写 (summary 不丢).
        let mut ir = mk(Some(IrReasoning::Effort(IrReasoningEffort::Low)));
        ir.extra.insert(
            "reasoning".into(),
            json!({"effort": "low", "summary": "detailed"}),
        );
        let v = writer().write_request(&ir);
        assert_eq!(
            v.get("reasoning"),
            Some(&json!({"effort": "low", "summary": "detailed"}))
        );
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
            IrBlock::Text { text, .. } => assert_eq!(text, "Hi there!"),
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
            IrBlock::ToolUse {
                id, name, input, ..
            } => {
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

    // ─── responses_usage_json: cache 归类 (#284) ────────────────────────
    //
    // B3a 回归: input 总和含 cache_creation (SSOT = IrUsage::openai_prompt_tokens,
    // 手算漂移正是根因) + cache_read 经 input_tokens_details.cached_tokens 上 wire.

    #[test]
    fn responses_usage_input_total_includes_cache_creation() {
        let u = IrUsage {
            input_tokens: 100,
            output_tokens: 10,
            cache_read_input_tokens: Some(50),
            cache_creation_input_tokens: Some(30),
            extra: Default::default(),
        };
        let v = responses_usage_json(&u);
        assert_eq!(
            v.get("input_tokens"),
            Some(&json!(180)),
            "input_tokens 漏加 cache_creation (期望 100+50+30=180)"
        );
        assert_eq!(
            v.get("input_tokens_details")
                .and_then(|d| d.get("cached_tokens")),
            Some(&json!(50)),
            "缺 input_tokens_details.cached_tokens (cache_read 不上 wire)"
        );
    }

    // 一致性守卫 (#284 长期避免机制): 两个 usage 序列化函数对同一 IrUsage 的
    // input 总和与 details.cached_tokens 必须一致 — writer 手算 cache 加法被禁止,
    // 总和口径只能经 openai_prompt_tokens SSOT.
    #[test]
    fn usage_json_serializations_agree_on_input_total_and_cached_details() {
        let u = IrUsage {
            input_tokens: 100,
            output_tokens: 10,
            cache_read_input_tokens: Some(50),
            cache_creation_input_tokens: Some(30),
            extra: Default::default(),
        };
        let openai = u.openai_usage_json();
        let responses = responses_usage_json(&u);
        assert_eq!(
            openai.get("prompt_tokens"),
            responses.get("input_tokens"),
            "OpenAI prompt_tokens 与 Responses input_tokens 总和口径漂移"
        );
        assert_eq!(
            openai
                .get("prompt_tokens_details")
                .and_then(|d| d.get("cached_tokens")),
            responses
                .get("input_tokens_details")
                .and_then(|d| d.get("cached_tokens")),
            "两协议 details.cached_tokens 漂移"
        );
    }

    // ─── write_request ─────────────────────────────────────────────────

    #[test]
    fn write_request_basic() {
        let ir = IrRequest {
            system: vec![IrBlock::Text {
                text: "Be helpful".into(),
                extra: Default::default(),
            }],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text {
                    text: "Hi".into(),
                    extra: Default::default(),
                }],
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
                        extra: Default::default(),
                    },
                    IrBlock::ToolUse {
                        id: "call_1".into(),
                        name: "search".into(),
                        input: json!({"q": "rust"}),
                        extra: Default::default(),
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
                        extra: Default::default(),
                    }],
                    is_error: None,
                    content_form: None,
                    extra: Default::default(),
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
    fn write_request_tool_result_media_native_output_array() {
        // #403: `function_call_output.output` 官方支持 array of (input_text|
        // input_image|input_file) (2025-09 起) — 媒体原位保真, 无搬运无占位标记.
        let image = img("https://example.com/cat.png");
        // content_form=None (跨协议 a→r / 内部构造): 含非 Text 块 → array 原位.
        let v = writer().write_request(&user_req(vec![tr(
            vec![text("screenshot saved"), image.clone(), text("done")],
            None,
            None,
        )]));
        let input = v.get("input").unwrap().as_array().unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input[0].get("type").unwrap(), "function_call_output");
        assert_eq!(
            input[0].get("output").unwrap(),
            &json!([
                {"type": "input_text", "text": "screenshot saved"},
                {"type": "input_image", "image_url": "https://example.com/cat.png"},
                {"type": "input_text", "text": "done"},
            ])
        );

        // content_form=Some(Array) (r→r 同协议): array 形态保真回写.
        let v = writer().write_request(&user_req(vec![tr(
            vec![text("sunny"), image],
            Some(ContentForm::Array),
            None,
        )]));
        let output = v["input"][0]["output"].as_array().unwrap();
        assert_eq!(output.len(), 2);
        assert_eq!(output[1]["type"], "input_image");

        // content_form=Some(String) (r→r 同协议, string 形态): 保持 string —
        // 媒体在该形态下不可达 (reader 不会产出, 内部构造防御面如实回写).
        let v = writer().write_request(&user_req(vec![tr(
            vec![text("sunny")],
            Some(ContentForm::String),
            None,
        )]));
        assert_eq!(v["input"][0]["output"], "sunny");

        // 纯 Text + content_form=None: 沿用 string 形态 (与既有行为兼容).
        let v = writer().write_request(&user_req(vec![tr(vec![text("sunny")], None, None)]));
        assert_eq!(v["input"][0]["output"], "sunny");

        // 纯图片 tool_result: array 单 part (非空, 结构合法).
        let v = writer().write_request(&user_req(vec![tr(
            vec![IrBlock::Image {
                source: IrImageSource::Base64 {
                    media_type: "image/png".into(),
                    data: "iVBORw0KGgo=".into(),
                },
                extra: Default::default(),
            }],
            None,
            None,
        )]));
        assert_eq!(
            v["input"][0]["output"],
            json!([{"type": "input_image", "image_url": "data:image/png;base64,iVBORw0KGgo="}])
        );
    }

    /// #403: Raw part (input_file 等) 在 array 形态 output 内 verbatim 保真;
    /// is_error 的 `[error]` 前缀拼进首个 **Text 派生** part (Raw 即使 type 形似
    /// input_text 也不可改写 — verbatim 契约), 无 text part 时独立成 part.
    #[test]
    fn write_request_tool_result_output_array_raw_and_error() {
        let raw = IrBlock::Raw {
            entry: json!({"type": "input_file", "file_id": "file_1", "filename": "a.pdf"}),
        };
        let v = writer().write_request(&user_req(vec![tr(vec![text("doc"), raw], None, None)]));
        assert_eq!(
            v["input"][0]["output"],
            json!([
                {"type": "input_text", "text": "doc"},
                {"type": "input_file", "file_id": "file_1", "filename": "a.pdf"},
            ])
        );

        let v = writer().write_request(&user_req(vec![tr(
            vec![text("boom"), img("https://e.com/x.png")],
            None,
            Some(true),
        )]));
        assert_eq!(
            v["input"][0]["output"],
            json!([
                {"type": "input_text", "text": "[error] boom"},
                {"type": "input_image", "image_url": "https://e.com/x.png"},
            ])
        );

        // 无 text part 的 is_error: 独立 [error] part.
        let v = writer().write_request(&user_req(vec![tr(
            vec![img("https://e.com/x.png")],
            None,
            Some(true),
        )]));
        assert_eq!(v["input"][0]["output"][0]["text"], "[error]");

        // Raw 前置 + is_error: 首个 part 是 Raw (type 形似 input_text 也不可改写),
        // [error] 前缀落不到 Raw 上 — 拼进其后首个 Text 派生 part.
        let raw_like_text = IrBlock::Raw {
            entry: json!({"type": "input_text", "text": 123}),
        };
        let v = writer().write_request(&user_req(vec![tr(
            vec![raw_like_text, text("boom")],
            None,
            Some(true),
        )]));
        assert_eq!(
            v["input"][0]["output"],
            json!([
                {"type": "input_text", "text": 123},
                {"type": "input_text", "text": "[error] boom"},
            ])
        );
    }

    /// #403: `IrRole::System` 消息 (a reader 原位保留的 role=system, 跨协议 a→r)
    /// 的 Image 经共享 `block_to_input_part` 回写为 input_image part — 修复前
    /// 该臂跳过非 Text 块 (a→r 保真损失)。r→r 同协议的 system 媒体不经此臂
    /// (reader 提升到顶层 instructions 折叠, L2 搁置项)。
    #[test]
    fn write_request_system_message_media_part_written() {
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::System,
                content: vec![
                    text("policy: verify screenshots"),
                    img("https://e.com/s.png"),
                ],
                ..Default::default()
            }],
            model: "m".into(),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        let input = v["input"].as_array().unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input[0]["type"], "message");
        assert_eq!(input[0]["role"], "system");
        assert_eq!(
            input[0]["content"],
            json!([
                {"type": "input_text", "text": "policy: verify screenshots"},
                {"type": "input_image", "image_url": "https://e.com/s.png"},
            ])
        );
    }

    /// #403 r→r round-trip: function_call_output 的 string / array 双形态 +
    /// array 内媒体 part 经 reader→writer 原位保真 (FWD-2 normalize 相等).
    #[test]
    fn read_request_function_call_output_form_and_media_round_trip() {
        let body = json!({
            "model": "gpt-5",
            "input": [
                {"type": "function_call_output", "call_id": "call_1",
                 "output": [
                     {"type": "input_text", "text": "screenshot saved"},
                     {"type": "input_image", "image_url": "data:image/png;base64,iVBORw0KGgo="},
                 ]},
                {"type": "function_call_output", "call_id": "call_2", "output": "plain text"},
            ],
        });
        let ir = reader().read_request(&body).unwrap();
        // reader: array → Image block + content_form=Some(Array).
        let tr1 = match &ir.messages[0].content[0] {
            IrBlock::ToolResult {
                content,
                content_form,
                ..
            } => (content.clone(), *content_form),
            other => panic!("expected ToolResult, got {other:?}"),
        };
        assert_eq!(tr1.1, Some(ContentForm::Array));
        assert_eq!(tr1.0.len(), 2);
        assert!(matches!(tr1.0[1], IrBlock::Image { .. }));
        // string → 单 Text + content_form=Some(String).
        match &ir.messages[1].content[0] {
            IrBlock::ToolResult {
                content,
                content_form,
                ..
            } => {
                assert_eq!(*content_form, Some(ContentForm::String));
                assert_eq!(content.len(), 1);
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
        // writer 回写: 形态 + part 字节保真.
        let v = writer().write_request(&ir);
        assert_eq!(
            v["input"][0],
            json!({
                "type": "function_call_output", "call_id": "call_1",
                "output": [
                    {"type": "input_text", "text": "screenshot saved"},
                    {"type": "input_image", "image_url": "data:image/png;base64,iVBORw0KGgo="},
                ]
            })
        );
        assert_eq!(v["input"][1]["output"], "plain text");
    }

    #[test]
    fn write_request_tools_flat() {
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text {
                    text: "x".into(),
                    extra: Default::default(),
                }],
                contains_user_text: true,
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            tools: vec![IrTool::Function {
                name: "search".into(),
                description: Some("Search".into()),
                input_schema: json!({"type": "object"}),
                extra: Default::default(),
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
            content: vec![IrBlock::Text {
                text: "Hi".into(),
                extra: Default::default(),
            }],
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
            extra: Default::default(),
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
                    extra: Default::default(),
                },
                IrBlock::ToolUse {
                    id: "call_1".into(),
                    name: "search".into(),
                    input: json!({"q": "rust"}),
                    extra: Default::default(),
                },
            ],
            stop_reason: Some(IrStopReason::ToolUse),
            usage: IrUsage::default(),
            usage_present: false,
            model: Some("gpt-4o".into()),
            id: None,
            created: None,
            stop_sequence: None,
            extra: Default::default(),
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
        // failed→Other→completed 有损 — 已知折衷 (见 write_status_and_reason 注释).
        let ir = IrResponse {
            content: vec![IrBlock::Text {
                text: "done".into(),
                extra: Default::default(),
            }],
            stop_reason: Some(IrStopReason::Other),
            usage: IrUsage::default(),
            usage_present: false,
            model: Some("gpt-4o".into()),
            id: None,
            created: None,
            stop_sequence: None,
            extra: Default::default(),
        };
        let v = writer().write_response(&ir);
        assert_eq!(v.get("status").unwrap(), "completed");
    }

    #[test]
    fn write_response_synthesizes_id_when_missing() {
        let ir = IrResponse {
            content: vec![IrBlock::Text {
                text: "Hi".into(),
                extra: Default::default(),
            }],
            stop_reason: Some(IrStopReason::EndTurn),
            usage: IrUsage::default(),
            usage_present: false,
            model: Some("gpt-4o".into()),
            id: None,
            created: None,
            stop_sequence: None,
            extra: Default::default(),
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

    #[test]
    fn max_tokens_round_trip_via_responses_nonstream() {
        // #285: 非流式 writer 必须写 incomplete_details.reason — MaxTokens 经
        // write→read round-trip 保真 (此前只写 status=incomplete, 读回归 Other).
        let ir = IrResponse {
            content: vec![IrBlock::Text {
                text: "partial".into(),
                extra: Default::default(),
            }],
            stop_reason: Some(IrStopReason::MaxTokens),
            model: Some("gpt-4o".into()),
            ..Default::default()
        };
        let wire = writer().write_response(&ir);
        assert_eq!(wire.get("status").unwrap(), "incomplete");
        let back = reader().read_response(&wire).unwrap();
        assert_eq!(
            back.stop_reason,
            Some(IrStopReason::MaxTokens),
            "#285: MaxTokens round-trip 降级为 {:?} (incomplete 无 reason → Other)",
            back.stop_reason
        );
    }

    #[test]
    fn round_trip_response_incomplete_max_tokens_scenario() {
        // 照流式 stream_round_trip_incomplete_max_tokens_scenario 对齐非流式维度:
        // 上游 wire 带 incomplete_details.reason → IR MaxTokens → 写回保真.
        let original = json!({
            "id": "resp_1",
            "object": "response",
            "created_at": 1700000000,
            "model": "gpt-4o",
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
            "output": [{
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "partial"}]
            }],
        });
        let ir = reader().read_response(&original).unwrap();
        assert_eq!(ir.stop_reason, Some(IrStopReason::MaxTokens));
        let rewritten = writer().write_response(&ir);
        let ir2 = reader().read_response(&rewritten).unwrap();
        assert_eq!(ir, ir2);
    }

    // ─── write_status_and_reason SSOT 映射表 (#285 review 中等问题补钉) ───
    // property 生成器不生成 incomplete 族 finish_reason (fwd_responses_property
    // 的 arb_chat_response_value 只有 stop/tool_calls), SSOT 映射表此前无钉死
    // 测试 — 本表驱动单测把 8 个臂 (None + 7 变体) 逐臂锁定, 防止未来重构
    // 悄悄改映射 (流式/非流式两消费面共享此表, 一处锁定双向守护).
    #[test]
    fn write_status_and_reason_maps_every_variant() {
        let cases: &[(Option<IrStopReason>, &str, Option<&str>)] = &[
            (None, "completed", None),
            (Some(IrStopReason::EndTurn), "completed", None),
            (Some(IrStopReason::StopSequence), "completed", None),
            (Some(IrStopReason::ToolUse), "completed", None),
            (Some(IrStopReason::Other), "completed", None),
            // #388: Anthropic 专属官方值 — 跨协议投影与 Other 一致 (r 无对应概念).
            (Some(IrStopReason::PauseTurn), "completed", None),
            (Some(IrStopReason::ContextWindowExceeded), "completed", None),
            (
                Some(IrStopReason::MaxTokens),
                "incomplete",
                Some("max_output_tokens"),
            ),
            (
                Some(IrStopReason::Safety),
                "incomplete",
                Some("content_filter"),
            ),
            (
                Some(IrStopReason::Refusal),
                "incomplete",
                Some("content_filter"),
            ),
        ];
        for (input, status, reason) in cases {
            assert_eq!(
                write_status_and_reason(*input),
                (*status, *reason),
                "SSOT 映射分叉: {input:?} 期望 ({status}, {reason:?})"
            );
        }
        // 结构性不变式: incomplete 必带 reason — helper 无法产出 ("incomplete", None),
        // 自家 round-trip 不依赖 reader 的病态 wire 容错 (无 reason → Other).
        for (input, ..) in cases {
            let (status, reason) = write_status_and_reason(*input);
            assert_ne!((status, reason), ("incomplete", None), "{input:?}");
        }
    }

    #[test]
    fn round_trip_response_incomplete_content_filter_scenario() {
        // Safety 变体: content_filter reason 经写回保真 (读回归 Safety).
        let original = json!({
            "id": "resp_1",
            "object": "response",
            "created_at": 1700000000,
            "model": "gpt-4o",
            "status": "incomplete",
            "incomplete_details": {"reason": "content_filter"},
            "output": [{
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "blocked"}]
            }],
        });
        let ir = reader().read_response(&original).unwrap();
        assert_eq!(ir.stop_reason, Some(IrStopReason::Safety));
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
    fn write_request_user_image_base64_data_url() {
        // IR Image{Base64} → Responses input_image.image_url = "data:<mime>;base64,<payload>".
        // 修复前 writer 只支持 Url source, Base64 被静默丢弃 (与 OpenAI writer 不对称);
        // data URL 是 Responses input_image 的合法值 (官方 API 接受 URL 或 data URL).
        let ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Image {
                    source: IrImageSource::Base64 {
                        media_type: "image/png".into(),
                        data: "iVBORw0KGgo=".into(),
                    },
                    extra: Default::default(),
                }],
                ..Default::default()
            }],
            model: "gpt-4o".into(),
            ..Default::default()
        };
        let v = writer().write_request(&ir);
        let items = v["input"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["type"], "message");
        let content = items[0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 1, "Base64 image 不得被丢弃");
        let part = &content[0];
        assert_eq!(part["type"], "input_image");
        assert_eq!(
            part["image_url"].as_str().unwrap(),
            "data:image/png;base64,iVBORw0KGgo="
        );
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
