//! 从 chat request body 字节流派生轻量字段的逻辑 (域 B 派生链).
//!
//! # 职责边界
//!
//! 本模块提供协议无关的派生函数, 从 request body 提取 sidebar 标题 preview + model 名 +
//! message 文本片段. 这些派生属于 **域 B (派生链)**: 从原始字节 (域 A 透明中继产出的
//! `req_body_raw`) 或已解析的 IR 派生 WebUI 需要的轻量视图.
//!
//! # 为什么不在 `web::api`
//!
//! 历史上这些函数定义在 `web::api` (展示层), 但消费者跨三层:
//! - 转发链 [`crate::proxy`] (push 时一次性提取 preview/model, 缓存进 [`crate::dag::CallEvent`]).
//! - 派生链 [`crate::dag`] (timeline delta 切片时用 `extract_text_blocks` 提取 system 文本;
//!   测试构造 CallEvent 时用 `extract_preview_and_model`).
//! - 展示层 `crate::web::api` (parsed view 不直接调用, 但语义同源).
//!
//! 让 `proxy` / `dag` (域 A/B) 反向依赖 `web::api` (域 C 展示层) 违反单向承诺
//! (域 A → 域 B → 域 C, 禁止反向). 故下沉到本独立模块, 让三层各自从 `crate::derive` 取用.
//!
//! # 两个入口 (IR + 字符串)
//!
//! - `extract_preview_and_model_from_ir`: codec 路径 (same_proto + redact / cross_proto)
//!   已 parse 出 IR, 直接从 IR 提取, **零重复 JSON parse**.
//! - `extract_preview_and_model`: passthrough 路径 (无 redact) 不 parse IR (保持 byte-exact),
//!   从原始 body 字符串提取. 此路径不限制 body 大小 (opencode 的 system prompt + MCP 工具
//!   schema 常超 1 MiB; 旧版 PREVIEW_BODY_MAX=1MiB 导致全部 round preview=None 是历史 bug).
//!
//! # 鲁棒性 (best-effort, 永不 panic) → ROB-1 契约
//!
//! 这些函数接收用户可控的 HTTP body (任意字节), 任何 panic 都能让单个恶意请求崩溃整个进程
//! (DoS). 故对非 JSON / 字段缺失 / 类型不符 / 空数组 / 越界一律返回 `None`/空, 由调用方走
//! fallback (preview fallback 到 method+path). 形式化契约 ROB-1 (永不 panic) 由本模块测试中
//! 的两个 proptest 守卫 (覆盖任意字节 + 合法 JSON 扰动两路径), 详见 `docs/design/contracts.md` §8.

/// preview 截断上限 (char count). 后端唯一截断点, 前端直接渲染.
///
/// 决策依据: sidebar 单条目宽度约 ~20em, 48 个 char (含中英文混合) 在单行省略号下
/// 既保留足够辨识度 (用户问题前半句), 又不撑爆紧凑布局. 调小 → 同质性升高难辨识;
/// 调大 → 多条目挤压. 48 是实测权衡值.
const PREVIEW_MAX: usize = 48;

/// opencode 压缩会话注入的固定 user message (opencode 源码:
/// packages/opencode/src/session/message-v2.ts:231). 命中时优先取最后一条 assistant 摘要.
/// 精确匹配依赖 opencode 内部实现; 若 opencode 改变 marker, 匹配失败会优雅降级到
/// 正常的 "最后一条有文本的 message" 路径 (有测试覆盖该降级).
const COMPRESSED_MARKER: &str = "What did we do so far?";

// ─── preview 核心逻辑 (协议无关, 输入候选文本列表) ──────────────────────────

/// preview 选择 + 归一化 + 截断 (纯函数, 不依赖 JSON / IR).
///
/// 输入: 按 messages 数组顺序 (oldest-first) 排列的 (role, 文本) 候选对.
/// 选择策略 (issue #27):
/// 1. 最后一条 role=user 的文本 (人类可读, 反映本轮问题)
/// 2. 无 user → 最后一条有文本的 message (不限 role, 覆盖纯 tool-call 轮次)
/// 3. 压缩 marker 命中时 → 最后一条 assistant 摘要
fn select_and_truncate_preview(candidates: &[(&str, &str)]) -> Option<String> {
    // 最后一条 role=user 的文本.
    let last_user = candidates
        .iter()
        .rev()
        .find_map(|(role, text)| (*role == "user").then_some(*text));
    // 最后一条有文本的 message (不限 role).
    let last_any = candidates.last().map(|(_, text)| *text);
    // 最后一条 role=assistant 的文本 (压缩 marker fallback 用).
    let last_assistant = candidates
        .iter()
        .rev()
        .find_map(|(role, text)| (*role == "assistant").then_some(*text));

    let raw = match last_user {
        Some(COMPRESSED_MARKER) => last_assistant.or(last_user),
        Some(_) => last_user,
        None => last_any,
    };
    raw.map(truncate_preview)
}

/// 归一化空白 + 截断到 PREVIEW_MAX chars (SSOT, 前后端一致).
fn truncate_preview(s: &str) -> String {
    let normalized = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.chars().count() > PREVIEW_MAX {
        let end = normalized
            .char_indices()
            .nth(PREVIEW_MAX)
            .map(|(i, _)| i)
            .unwrap_or(normalized.len());
        format!("{}…", &normalized[..end])
    } else {
        normalized
    }
}

// ─── IR 入口 (codec 路径, 零重复 parse) ─────────────────────────────────────

/// 从已解析的 IR 提取 (sidebar 标题 preview, model 名).
///
/// codec 路径 (same_proto + redact / cross_proto) 已将请求 body parse 成 IR, 此函数
/// 直接从 IR 的 messages 提取, **零额外 JSON parse**. 替代旧的从 `req_body_raw` 字符串
/// 重新 parse 的方式 (重复 parse 浪费, 且大 body 时 preview 被 PREVIEW_BODY_MAX 跳过).
///
/// model 直接取 `ir.model` (顶层字段, reader 已解析).
/// preview 选择策略与 `extract_preview_and_model` 完全一致 (共用 `select_and_truncate_preview`).
pub(crate) fn extract_preview_and_model_from_ir(
    ir: &crate::codec::ir::IrRequest,
) -> (Option<String>, Option<String>) {
    // model: IR 的 model 字段 (reader 已解析顶层 model, 永远非空).
    let model = if ir.model.is_empty() {
        None
    } else {
        Some(ir.model.clone())
    };

    // 收集候选: 遍历 messages, 提取每条的 (role, 首个文本块文本).
    // IrMessage.content 是 Vec<IrBlock>, 文本块是 IrBlock::Text { text }.
    let candidates: Vec<(&str, &str)> = ir
        .messages
        .iter()
        .filter_map(|m| {
            let text = m.content.iter().find_map(|b| match b {
                crate::codec::ir::IrBlock::Text { text } if !text.is_empty() => Some(text.as_str()),
                _ => None,
            })?;
            // IrRole → 字符串 (与 wire JSON 的 role 值一致: lowercase).
            let role = match m.role {
                crate::codec::ir::IrRole::System => "system",
                crate::codec::ir::IrRole::User => "user",
                crate::codec::ir::IrRole::Assistant => "assistant",
                crate::codec::ir::IrRole::Tool => "tool",
            };
            Some((role, text))
        })
        .collect();

    let preview = select_and_truncate_preview(&candidates);
    (preview, model)
}

// ─── 字符串入口 (passthrough 路径) ──────────────────────────────────────────

/// 从 chat request body 字符串提取 (sidebar 标题 preview, model 名).
///
/// passthrough 路径 (无 redact) 不 parse IR (保持 byte-exact), 从原始 body 字符串提取.
/// codec 路径应优先用 `extract_preview_and_model_from_ir` (零重复 parse).
///
/// **不限制 body 大小**: opencode (含大量 MCP 工具 schema 的 system prompt) 请求 body 常超
/// 1 MiB, 旧版 PREVIEW_BODY_MAX=1MiB 导致全部 round preview=None (sidebar "no preview").
/// push 路径每请求只调一次, serde_json parse 5 MiB ≈ 50ms (LLM 请求本身要数秒), 开销可接受.
/// 仅保留非空 + 非 `{` 开头的快速路径 guard (过滤 GET/DELETE 等无 body 场景).
///
/// 失败容错: 非 JSON / 字段缺失 / 类型不匹配一律返回 (None, None), 不影响 list 响应.
/// 前端按 None fallback 到 method+path (与旧行为一致).
pub(crate) fn extract_preview_and_model(req_body: &str) -> (Option<String>, Option<String>) {
    // 快速路径: 空 body 或明显非 JSON (不以 '{' 开头 = GET/DELETE 等无 body 场景).
    if req_body.is_empty() || !req_body.starts_with('{') {
        return (None, None);
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(req_body) else {
        return (None, None);
    };
    let model = v
        .get("model")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty()) // 空 model 名 = None (与 IR 入口语义一致).
        .map(|s| s.to_string());

    let messages = v.get("messages").and_then(|m| m.as_array());
    // 收集候选 (role, 文本), 复用 IR 路径的 select_and_truncate_preview.
    let candidates: Vec<(&str, String)> = match messages {
        Some(msgs) => msgs
            .iter()
            .filter_map(|m| {
                let role = m.get("role").and_then(|r| r.as_str())?;
                let text = message_text(m)?;
                Some((role, text))
            })
            .collect(),
        None => Vec::new(),
    };
    let candidates_ref: Vec<(&str, &str)> =
        candidates.iter().map(|(r, t)| (*r, t.as_str())).collect();
    let preview = select_and_truncate_preview(&candidates_ref);
    (preview, model)
}

/// 从单条 wire message 中提取可展示文本 (content string 或 array of text blocks).
/// 跳过无文本的 message (tool_call only / null content / 空串).
/// 仅 passthrough 路径 (字符串入口) 使用; codec 路径直接从 IR 的 IrBlock::Text 提取.
fn message_text(m: &serde_json::Value) -> Option<String> {
    let content = m.get("content")?;
    // string content: 直接取 (空串视为无文本).
    if let Some(s) = content.as_str() {
        return if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        };
    }
    // array content: 拼接所有 type=text 的 text 字段.
    if let Some(arr) = content.as_array() {
        return extract_text_blocks(arr).map(|t| t.join(" "));
    }
    None
}

/// 从 content blocks 数组中收集所有 text 块的文本.
/// 用于 message.content (array 形态) 和 Anthropic system (array 形态).
/// 返回原始文本片段 (未 join), 调用方决定分隔符 (message 用 space, system 用 newline).
pub(crate) fn extract_text_blocks(arr: &[serde_json::Value]) -> Option<Vec<String>> {
    let texts: Vec<String> = arr
        .iter()
        .filter_map(|b| {
            if b.get("type").and_then(|t| t.as_str()) != Some("text") {
                return None;
            }
            b.get("text")
                .and_then(|t| t.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        .collect();
    if texts.is_empty() { None } else { Some(texts) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn extract_preview_model_openai_string_content() {
        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}]}"#;
        let (preview, model) = extract_preview_and_model(body);
        assert_eq!(model.as_deref(), Some("gpt-4o"));
        assert_eq!(preview.as_deref(), Some("hello world"));
    }

    #[test]
    fn extract_preview_model_anthropic_array_content() {
        let body = r#"{"model":"claude-3","messages":[{"role":"user","content":[{"type":"text","text":"hi there"}]}]}"#;
        let (preview, model) = extract_preview_and_model(body);
        assert_eq!(model.as_deref(), Some("claude-3"));
        assert_eq!(preview.as_deref(), Some("hi there"));
    }

    #[test]
    fn extract_preview_picks_last_user_message() {
        // 累积数组: 多条 user message → 取最后一条 (本轮问题, issue #25).
        let body = r#"{"model":"x","messages":[{"role":"user","content":"first user"},{"role":"assistant","content":"noop"},{"role":"user","content":"second user"}]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("second user"));
    }

    #[test]
    fn extract_preview_accumulated_history_each_round_unique() {
        // 模拟同一会话的 3 轮累积请求 (OpenAI 风格 messages 数组逐轮增长):
        // 三轮的 preview 应分别为 Q1/Q2/Q3 (而非全都是 Q1).
        let r1 = r#"{"model":"x","messages":[{"role":"user","content":"Q1"}]}"#;
        let r2 = r#"{"model":"x","messages":[{"role":"user","content":"Q1"},{"role":"assistant","content":"A1"},{"role":"user","content":"Q2"}]}"#;
        let r3 = r#"{"model":"x","messages":[{"role":"user","content":"Q1"},{"role":"assistant","content":"A1"},{"role":"user","content":"Q2"},{"role":"assistant","content":"A2"},{"role":"user","content":"Q3"}]}"#;
        assert_eq!(extract_preview_and_model(r1).0.as_deref(), Some("Q1"));
        assert_eq!(extract_preview_and_model(r2).0.as_deref(), Some("Q2"));
        assert_eq!(extract_preview_and_model(r3).0.as_deref(), Some("Q3"));
    }

    // ─── PR26 bug #1 修复验证: tool-call 循环 preview 策略 ──────────────────
    //
    // agent tool-call 循环: 用户问一次, agent 多轮 tool_call + tool_result.
    // preview 优先取最后一条 user (可读性好); 无 user 时回退到最后一条有文本的 message.
    // tool-call 循环中 user 不变 (都是初始问题), 但二级菜单靠轮次序号 + 时间戳区分.
    #[test]
    fn extract_preview_tool_call_cycle_prefers_user() {
        // 轮1: 用户问 "list files"
        let r1 = r#"{"model":"x","messages":[
            {"role":"system","content":"sys"},
            {"role":"user","content":"list files"}
        ]}"#;
        // 轮2: agent 调 tool, tool 返回结果.
        let r2 = r#"{"model":"x","messages":[
            {"role":"system","content":"sys"},
            {"role":"user","content":"list files"},
            {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"ls","arguments":"{}"}}]},
            {"role":"tool","tool_call_id":"c1","content":"file1\nfile2"}
        ]}"#;
        let p1 = extract_preview_and_model(r1).0;
        let p2 = extract_preview_and_model(r2).0;
        // 优先取 user message (可读性好, 不暴露 tool_result 结构化数据).
        assert_eq!(p1.as_deref(), Some("list files"));
        assert_eq!(
            p2.as_deref(),
            Some("list files"),
            "优先取 user 而非 tool_result"
        );
    }

    #[test]
    fn extract_preview_no_user_falls_back_to_tool_result() {
        // 无 user message 时, 回退到最后一条有文本的 message (tool_result / assistant).
        let body = r#"{"model":"x","messages":[
            {"role":"system","content":"sys"},
            {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"ls","arguments":"{}"}}]},
            {"role":"tool","tool_call_id":"c1","content":"result data"}
        ]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(
            preview.as_deref(),
            Some("result data"),
            "无 user → 回退到 tool_result"
        );
    }

    #[test]
    fn extract_preview_compressed_session_falls_back_to_last_assistant() {
        // opencode 压缩会话: 最后一条 user = "What did we do so far?" → 改取最后一条 assistant 摘要.
        let body = r###"{"model":"x","messages":[
            {"role":"user","content":"earlier question"},
            {"role":"assistant","content":"earlier answer"},
            {"role":"user","content":"What did we do so far?"},
            {"role":"assistant","content":"## 目标\n实现 secret-guard WebUI 标题优化"}
        ]}"###;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(
            preview.as_deref(),
            Some("## 目标 实现 secret-guard WebUI 标题优化")
        );
    }

    #[test]
    fn extract_preview_compressed_session_array_content_assistant() {
        // 同上但 assistant 用 array content (Anthropic 风格).
        let body = r###"{"model":"claude-3","messages":[
            {"role":"user","content":"What did we do so far?"},
            {"role":"assistant","content":[{"type":"text","text":"## 目标 重构 preview 提取"}]}
        ]}"###;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("## 目标 重构 preview 提取"));
    }

    #[test]
    fn extract_preview_compressed_marker_not_normalized_still_normal_path() {
        // marker 比对用原始文本 (未归一化空白). 非精确匹配 (如本例多一个单词) 走正常路径,
        // 不触发 assistant fallback.
        let body = r#"{"model":"x","messages":[
            {"role":"user","content":"What did we do so far? extra"}
        ]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("What did we do so far? extra"));
    }

    #[test]
    fn extract_preview_compressed_session_no_assistant_falls_back_to_marker() {
        // 压缩 marker 命中但无 assistant 消息 → last_assistant 返回 None.
        // marker 本身作为 preview (总比 None 强).
        let body = r#"{"model":"x","messages":[
            {"role":"user","content":"What did we do so far?"}
        ]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("What did we do so far?"));
    }

    #[test]
    fn extract_preview_truncates_long_text() {
        let long = "a".repeat(100);
        let body = format!(r#"{{"model":"x","messages":[{{"role":"user","content":"{long}"}}]}}"#);
        let (preview, _) = extract_preview_and_model(&body);
        let p = preview.expect("preview should be set");
        assert_eq!(p.chars().count(), PREVIEW_MAX + 1); // 48 chars + '…'
        assert!(p.ends_with('…'));
    }

    #[test]
    fn extract_preview_normalizes_whitespace() {
        let body = r#"{"model":"x","messages":[{"role":"user","content":"  hello\n\n  world  "}]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("hello world"));
    }

    #[test]
    fn extract_preview_system_only_returns_system_text() {
        // 只有 system message (无 user): 修复后取最后一条有文本的 message = system.
        // (旧行为: 只找 user → 返回 None; 新行为: 不限 role → 返回 system 文本)
        let body = r#"{"model":"x","messages":[{"role":"system","content":"sys text"}]}"#;
        let (preview, model) = extract_preview_and_model(body);
        assert_eq!(model.as_deref(), Some("x"));
        assert_eq!(preview.as_deref(), Some("sys text"));
    }

    #[test]
    fn extract_preview_non_json_returns_none() {
        let (preview, model) = extract_preview_and_model("not json{");
        assert!(preview.is_none());
        assert!(model.is_none());
    }

    #[test]
    fn extract_preview_empty_body_returns_none() {
        let (preview, model) = extract_preview_and_model("");
        assert!(preview.is_none());
        assert!(model.is_none());
    }

    #[test]
    fn extract_preview_large_body_over_1mib_still_extracted() {
        // Bug 1 根因修复: opencode 的 system prompt + MCP 工具定义常超 1 MiB,
        // 旧版 PREVIEW_BODY_MAX=1MiB 导致全部 round preview=None (sidebar "no preview").
        // 移除大小限制后, 大 body 也应正常提取 preview + model.
        // 构造: 1.2 MiB system prompt + 短 user message (模拟 opencode 典型请求).
        let big_system = "x".repeat(1_200_000);
        let body = format!(
            r#"{{"model":"claude-sonnet-4","system":"{big_system}","messages":[{{"role":"user","content":"How do I fix this bug?"}}]}}"#
        );
        assert!(body.len() > 1_048_576, "body 应超过 1 MiB");
        let (preview, model) = extract_preview_and_model(&body);
        assert_eq!(model.as_deref(), Some("claude-sonnet-4"));
        assert_eq!(
            preview.as_deref(),
            Some("How do I fix this bug?"),
            "大 body 也应提取 preview (Bug 1 修复)"
        );
    }

    // ─── IR 入口测试 (codec 路径, 零重复 parse) ──────────────────────────────

    /// 辅助: 用 OpenAI reader 把 wire JSON 解析成 IR (测试 extract_preview_and_model_from_ir).
    fn parse_ir(body: &str) -> crate::codec::ir::IrRequest {
        let proto = crate::codec::Protocol::OpenAI;
        let reader = proto.reader();
        let v: serde_json::Value = serde_json::from_str(body).expect("parse json");
        reader
            .read_request(&v)
            .expect("read_request should succeed")
    }

    #[test]
    fn ir_entry_extracts_preview_and_model() {
        // IR 入口: 从已 parse 的 IR 提取, 结果应与字符串入口一致.
        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}]}"#;
        let ir = parse_ir(body);
        let (preview_ir, model_ir) = extract_preview_and_model_from_ir(&ir);
        let (preview_str, model_str) = extract_preview_and_model(body);
        assert_eq!(model_ir.as_deref(), model_str.as_deref());
        assert_eq!(preview_ir.as_deref(), preview_str.as_deref());
        assert_eq!(model_ir.as_deref(), Some("gpt-4o"));
        assert_eq!(preview_ir.as_deref(), Some("hello world"));
    }

    #[test]
    fn ir_entry_and_string_entry_consistent_for_tool_call_cycle() {
        // tool-call 循环: IR 入口和字符串入口应给出相同 preview (压缩 marker 降级也覆盖).
        let body = r#"{"model":"x","messages":[
            {"role":"user","content":"list files"},
            {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"ls","arguments":"{}"}}]},
            {"role":"tool","tool_call_id":"c1","content":"file1\nfile2"}
        ]}"#;
        let ir = parse_ir(body);
        let (preview_ir, _) = extract_preview_and_model_from_ir(&ir);
        let (preview_str, _) = extract_preview_and_model(body);
        // 优先取 user message ("list files"), 两入口一致.
        assert_eq!(preview_ir.as_deref(), Some("list files"));
        assert_eq!(preview_ir.as_deref(), preview_str.as_deref());
    }

    #[test]
    fn ir_entry_large_body_zero_reparse() {
        // Bug 1 核心: codec 路径从 IR 提取, 零重复 JSON parse.
        // 大 body (1.2 MiB system prompt) 经 reader parse 成 IR 后, IR 入口直接提取 preview.
        // 对比: 字符串入口需重新 parse 整个 body (但也能提取, 见上测试).
        let big_system = "x".repeat(1_200_000);
        let body = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"system","content":"{big_system}"}},{{"role":"user","content":"Fix the bug"}}]}}"#
        );
        let ir = parse_ir(&body);
        let (preview, model) = extract_preview_and_model_from_ir(&ir);
        assert_eq!(model.as_deref(), Some("gpt-4o"));
        assert_eq!(preview.as_deref(), Some("Fix the bug"));
    }

    #[test]
    fn ir_entry_covers_system_role_branch() {
        // extract_preview_and_model_from_ir 的 match m.role 的 System 分支 (126 行).
        // OpenAI reader 把 role=system 提升到 IrRequest.system (不在 ir.messages), 故从
        // wire parse 的 IR 走不到 System role 分支. 手工构造 IR 直接覆盖.
        //
        // 单独构造只有 System+Text 的 IR (无 user/tool), preview 回退到最后一条有文本的
        // message = System, 从而独立守卫 System 候选的收集 + 字符串映射.
        use crate::codec::ir::{IrBlock, IrMessage, IrRequest, IrRole};
        let ir = IrRequest {
            model: "m".to_string(),
            messages: vec![IrMessage {
                role: IrRole::System,
                content: vec![IrBlock::Text {
                    text: "sys-only-msg".to_string(),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let (preview, _) = extract_preview_and_model_from_ir(&ir);
        assert_eq!(preview.as_deref(), Some("sys-only-msg"));
    }

    #[test]
    fn ir_entry_covers_tool_role_branch() {
        // Tool role 分支 (129 行). 同理手工构造 IR (wire parse 的 tool content 变成
        // ToolResult block 非 Text). 单独构造 Tool+Text, 守卫 Tool 候选收集.
        use crate::codec::ir::{IrBlock, IrMessage, IrRequest, IrRole};
        let ir = IrRequest {
            model: "m".to_string(),
            messages: vec![IrMessage {
                role: IrRole::Tool,
                content: vec![IrBlock::Text {
                    text: "tool-only-msg".to_string(),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let (preview, _) = extract_preview_and_model_from_ir(&ir);
        assert_eq!(preview.as_deref(), Some("tool-only-msg"));
    }

    #[test]
    fn extract_preview_not_starting_with_brace_returns_none() {
        // 快速路径: 不以 { 开头直接跳过 (catches GET / DELETE 等无 body 场景).
        let (preview, model) = extract_preview_and_model("plain text");
        assert!(preview.is_none());
        assert!(model.is_none());
    }

    #[test]
    fn extract_preview_multibyte_truncation_safe() {
        // 截断在 UTF-8 char boundary 安全 (用 char_indices).
        let body = r#"{"model":"x","messages":[{"role":"user","content":"你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界"}]}"#;
        let (preview, _) = extract_preview_and_model(body);
        let p = preview.unwrap();
        // 截断点在 48 chars 处, 末尾加 '…', UTF-8 不应 panic.
        assert!(p.ends_with('…'));
        assert_eq!(p.chars().count(), PREVIEW_MAX + 1);
    }

    // ─── property-based (ROB-1 永不 panic) ──────────────────────────────────
    //
    // 契约: docs/design/contracts.md §8 ROB-1 — extract_preview_and_model 对任意字节
    // 输入 (含非 JSON / 空 / 损坏 / 超长 / UTF-8 边界) 必须不 panic, 返回 (None, None)
    // 或合法的 (preview, model). 这是 best-effort 永不 panic 原则的直接 property:
    // 该函数接收用户可控的 HTTP body (任意字节), 任何 panic 都能让单个恶意请求崩溃
    // 整个进程 (DoS).
    //
    // 用 catch_unwind 跨 panic 边界守卫, 而非依赖 proptest 的 panic-as-fail 语义 —
    // 这样在 release build (无 panic = abort) 之外也能定位是哪个输入触发的.

    /// 辅助: 在 catch_unwind 内运行 extract_preview_and_model(body), 返回是否 panic.
    /// ROB-1 只关心是否 panic, 不关心返回值 (返回值由其他 example 测试覆盖).
    fn preview_panicked(body: &str) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            extract_preview_and_model(body)
        }))
        .is_err()
    }

    /// 生成任意字节流 (大部分不是合法 JSON, 覆盖 guard 早退与 serde parse 失败路径).
    fn arb_arbitrary_bytes() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<u8>(), 0..4096)
            .prop_map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// 生成合法 chat-request JSON body, 再随机扰动以触发 serde parse 成功后的下游
    /// 分支 (messages 数组访问 / content string-or-array 处理 / 类型不符等).
    ///
    /// **必要性**: 纯 arb_arbitrary_bytes 几乎不会触达 `serde_json::from_str` 的 Ok
    /// 分支 (随机字节构成合法 JSON 的概率≈0), 仅覆盖 guard 早退路径. 本生成器补合法
    /// JSON 路径, 让 messages[start..] 切片、role/content 类型检查等真正进入测试视野.
    fn arb_perturbed_chat_json() -> impl Strategy<Value = String> {
        // messages: 0..8 条; 每条 role + content 都随机 (string / array / 非法类型混搭).
        // 用 serde_json::json! 宏构造 content 片段, 保证拼出的 messages 数组永远是合法 JSON.
        let msg = (
            "[a-z]{1,10}", // role
            prop::sample::select(vec![
                // 各种 content 形态 — 覆盖 message_text 的所有返回路径.
                serde_json::json!({"content": "text"}), // string → Some
                serde_json::json!({"content": [{"type": "text", "text": "hi"}]}), // array → Some
                serde_json::json!({"content": serde_json::Value::Null}), // null → None
                serde_json::json!({"content": 42}),     // numeric → None
                serde_json::json!({"content": true}),   // bool → None
                serde_json::json!({}),                  // 无 content 字段 → None
            ]),
        );
        let body = prop::collection::vec(msg, 0..8).prop_map(|msgs| {
            let arr: Vec<serde_json::Value> = msgs
                .into_iter()
                .map(|(role, mut extra)| {
                    // 把 role 注入 extra (extra 是 {content:...} 或 {}, 加 role 字段).
                    if let Some(obj) = extra.as_object_mut() {
                        obj.insert("role".to_string(), serde_json::json!(role));
                    }
                    extra
                })
                .collect();
            serde_json::json!({"model": "m", "messages": arr}).to_string()
        });
        // 一半概率原样用 (合法 JSON → 触达下游分支), 一半概率随机截断 (模拟 wire 损坏 →
        // 走 parse 失败路径, 与变体 A 覆盖互补).
        prop_oneof![
            body.clone(),
            (body, 0usize..200).prop_map(|(b, cut)| {
                let cut = cut.min(b.len());
                let mut bytes = b.into_bytes();
                bytes.truncate(cut);
                String::from_utf8_lossy(&bytes).into_owned()
            }),
        ]
    }

    proptest! {
        /// ROB-1 (变体 A): 任意字节输入 (含非 JSON / 空 / 超长 / UTF-8 损坏) 永不 panic.
        /// 主要覆盖函数入口 guard (`is_empty / len > MAX / !starts_with('{')`) 与
        /// serde_json::from_str 失败路径 — 这些是恶意输入最常触达的分支.
        #[test]
        fn prop_preview_never_panics_arbitrary_bytes(body in arb_arbitrary_bytes()) {
            let panicked = preview_panicked(&body);
            prop_assert!(
                !panicked,
                "ROB-1 violation: extract_preview_and_model panicked on arbitrary bytes (len={})",
                body.len()
            );
        }

        /// ROB-1 (变体 B): 合法 chat JSON + 随机扰动 永不 panic.
        /// 覆盖 serde_json parse 成功后的下游分支 (messages 数组 / content 各种形态 /
        /// 截断损坏). 与变体 A 互补, 确保 parse 成功后的逻辑也不 panic.
        #[test]
        fn prop_preview_never_panics_perturbed_json(body in arb_perturbed_chat_json()) {
            let panicked = preview_panicked(&body);
            prop_assert!(
                !panicked,
                "ROB-1 violation: extract_preview_and_model panicked on perturbed chat json (len={})",
                body.len()
            );
        }
    }
}
