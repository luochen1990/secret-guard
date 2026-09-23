//! 从 chat request body 字节流派生轻量字段的逻辑 (域 B 派生链).
//!
//! # 职责边界
//!
//! 本模块提供协议无关的派生函数, 从 request body / DAG 结构化存储提取:
//! - sidebar 标题 preview + model 名 + message 文本片段 (`extract_preview_and_model` /
//!   `extract_preview_and_model_from_ir` / `extract_text_blocks`).
//! - 工具轮次 preview = tool name (`extract_tool_use_name`): DAG push_messages 在
//!   `round_role = Tool` 时调用, 覆盖 `extract_preview` 的 fallback 结果.
//! - timeline delta messages (B1 数据源: `extract_delta_messages_from_blocks`):
//!   从 BlockPool 结构化派生 (resolve → real→mock 投影替换 → ingress writer 序列化
//!   以及根节点 system 注入); 旧 raw 切片实现 (`extract_delta_messages_from_raw`)
//!   保留为 consistency-check shadow 对照 + 等价性 oracle.
//! - timeline tail parsed (B1: `response_parsed_from_parts`): response.message +
//!   元字段 → ingress writer 序列化 (finalize 后 stored parsed 已清除的渲染派生).
//!
//! 这些派生属于 **域 B (派生链)**: 从原始字节 (域 A 透明中继产出的 `req_body_raw`)
//! 或 DAG 内容寻址存储 (`req_delta` / `response.message`, real 视角) 派生 WebUI
//! 需要的轻量视图. 视角纪律: 出 web 层的派生结果一律为 **LLM 视角** (含 mock,
//! real→mock 替换经 redactions 投影重建, 不经 seed 重放 — 见
//! `redact::rebuild_real_to_mock_pairs` 文档的论证).
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
//! fallback (preview 返回 None, 前端降级到占位文本). 形式化契约 ROB-1 (永不 panic) 由本模块测试中
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
    crate::util::truncate_chars_with_ellipsis(&normalized, PREVIEW_MAX)
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

    // 收集候选: 遍历 messages, 提取每条的 (role, 全部文本块 join).
    // IrMessage.content 是 Vec<IrBlock>, 文本块是 IrBlock::Text { text }.
    // 多 Text block 用 " " join + preview_head 截断 — 与字符串入口 `message_text`
    // 的 join 语义逐字对齐 (consistency-check 的 assert_preview_model_match_source
    // 以字符串提取为 SSOT 断言两入口一致; 2026-09-23 前本入口只取首个 block,
    // 多 block user message (claude code 的 system-reminder + 问题) 下两入口漂移,
    // 被新集成测试在 consistency-check 下首次踩中).
    let joined: Vec<(String, String)> = ir
        .messages
        .iter()
        .filter_map(|m| {
            let texts: Vec<&str> = m
                .content
                .iter()
                .filter_map(|b| match b {
                    crate::codec::ir::IrBlock::Text { text, .. } if !text.is_empty() => {
                        Some(text.as_str())
                    }
                    _ => None,
                })
                .collect();
            if texts.is_empty() {
                return None;
            }
            // IrRole → 字符串 (与 wire JSON 的 role 值一致: lowercase).
            let role = match m.role {
                crate::codec::ir::IrRole::System => "system".to_string(),
                crate::codec::ir::IrRole::User => "user".to_string(),
                crate::codec::ir::IrRole::Assistant => "assistant".to_string(),
                crate::codec::ir::IrRole::Tool => "tool".to_string(),
            };
            Some((role, preview_head(&texts.join(" "))))
        })
        .collect();
    let candidates: Vec<(&str, &str)> = joined
        .iter()
        .map(|(r, t)| (r.as_str(), t.as_str()))
        .collect();

    let preview = select_and_truncate_preview(&candidates);
    (preview, model)
}

/// 从 messages 中提取首个 ToolUse 的 tool name (归一化 + 截断).
///
/// 用于 `round_role = Tool` 的轮次 (工具循环, sidebar 三级小圆点):
/// 此类轮次的 preview 应是 tool name (前端 `index.html` 的 sub-dot tooltip +
/// `providerColor` 哈希源都依赖 tool name, 详尽契约见 `dag::push_messages` 3.5 步).
///
/// `select_and_truncate_preview` (sidebar 主标题) 在无 user 时 fallback 到 "最后一条
/// 有文本的 message" (可能是 tool_result 片段 / assistant thinking), 与 tool name 契约
/// 不一致, 故工具轮次需要本函数单独覆盖 preview.
///
/// 找不到 ToolUse → None (调用方保留原 preview). 多个 ToolUse → 取首个 (oldest-first,
/// 反映本轮首个工具调用, 多并发工具调用时首个最具代表性).
///
/// 截断复用 `truncate_preview` (SSOT, 48 chars), 保持与 user round preview 一致的视觉长度.
pub(crate) fn extract_tool_use_name(msgs: &[crate::codec::ir::IrMessage]) -> Option<String> {
    msgs.iter().find_map(|m| {
        m.content.iter().find_map(|b| match b {
            crate::codec::ir::IrBlock::ToolUse { name, .. } => Some(truncate_preview(name)),
            _ => None,
        })
    })
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
/// 前端按 None 降级到占位文本 (round/session 两级占位不同, 详见 `src/web/AGENTS.md`).
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
///
/// **收集时截断**: 只保留 [`preview_head`] 的头部 chars. select_and_truncate_preview
/// 的消费方式只依赖候选文本头部 (COMPRESSED_MARKER 精确相等 + 归一化后首 PREVIEW_MAX
/// chars), 多轮大对话 (100+ messages) 无需把每条 message 的完整文本 clone 进 candidates
/// (PERF: 多轮场景曾有 MiB 级全量克隆, 只为最终选 48 char preview). 已知边界: array
/// content 分支仍先 `join` 完整文本再截断 (瞬时单次分配, 随即丢弃; 常驻 candidates
/// 已缩到 ≤49 chars — 主路径 OpenAI string content 无此开销), 不再进一步优化.
fn message_text(m: &serde_json::Value) -> Option<String> {
    let content = m.get("content")?;
    // string content: 直接取 (空串视为无文本).
    if let Some(s) = content.as_str() {
        return if s.is_empty() {
            None
        } else {
            Some(preview_head(s))
        };
    }
    // array content: 拼接所有 type=text 的 text 字段.
    if let Some(arr) = content.as_array() {
        return extract_text_blocks(arr).map(|t| preview_head(&t.join(" ")));
    }
    None
}

/// 收集时截断的头部上限: [`PREVIEW_MAX`] + 1 (char count, char-boundary 安全).
///
/// +1 保留 "超长" 信号: `truncate_preview` 只对归一化后超过 PREVIEW_MAX chars 的
/// 文本追加 '…'; 恰好截到 PREVIEW_MAX 会让所有长文本归一化后 ≤ 48, 省略号永不
/// 出现. COMPRESSED_MARKER (23 chars) 精确相等比较不受影响: 更长的文本截断后是
/// 49 chars, 恒不等于 23 chars 的 marker.
///
/// 已知可接受差异: 截断发生在空白归一化**之前**, 极端空白 (前 49 chars 是长空白 run,
/// 后续才有内容) 时归一化结果与全量文本不同. preview 是 best-effort 展示字段
/// (域 B, ROB-1 只约束不 panic, 无 byte-exact 契约), 差异仅影响该极端场景的展示.
fn preview_head(s: &str) -> String {
    s.chars().take(PREVIEW_MAX + 1).collect()
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

/// (legacy oracle) 从 node.req_body_raw 末尾截取 req_delta.len() 条 messages (wire JSON).
///
/// **B1 后生产路径已切换到 [`extract_delta_messages_from_blocks`]** (BlockPool 结构化
/// 派生); 本函数保留作两用途: ① consistency-check feature 的 shadow 对照 (VIEW-2
/// 守卫 [`assert_delta_view_matches_raw`]); ② 等价性 proptest 的 oracle. 两者之外
/// 禁止新增生产调用点.
///
/// # system 处理
///
/// OpenAI reader 把 role=system 提升到 IrRequest.system (不在 messages 里),
/// writer 再写回 messages[0]. DAG 的 req_delta 不含 system (基于 IR messages).
/// 因此根节点 (parent=None) 时, 从 req_body_raw 顶层提取 system 字段 (Anthropic 风格)
/// 或 messages[0] (OpenAI 风格 role=system), 作为 delta 的首条 synthetic message.
///
/// # 已知限制
///
/// OpenAI writer 的 ToolResult 拆分场景下尾部对齐使 delta 可能丢失本轮展开的头部
/// (不混入前序轮消息; 同协议不受影响). 详见 AGENTS.md "已知限制" + src/web/AGENTS.md.
///
/// # 鲁棒性 (ROB-1 契约)
///
/// 接收 HTTP body 派生数据, 任何 panic 都能让单个恶意请求崩溃进程. 对非 JSON /
/// 字段缺失 / count 与 messages 数不匹配一律返回空 Vec, 不 panic.
#[cfg_attr(not(any(test, feature = "consistency-check")), allow(dead_code))]
pub(crate) fn extract_delta_messages_from_raw(node: &crate::dag::Node) -> Vec<serde_json::Value> {
    let count = node.req_delta.len();
    if count == 0 {
        return Vec::new();
    }
    let Ok(req_body) = serde_json::from_str::<serde_json::Value>(&node.event.req_body_raw) else {
        return Vec::new();
    };
    let Some(messages) = req_body.get("messages").and_then(|m| m.as_array()) else {
        return Vec::new();
    };
    if messages.len() < count {
        return Vec::new();
    }
    let start = messages.len() - count;
    let mut result: Vec<serde_json::Value> = messages[start..].to_vec();

    // 根节点: 若有顶层 system (Anthropic 风格) 或 messages[0] 是 system (OpenAI),
    // 且未被 req_delta 覆盖 (start > 0 说明 system 在 messages[start] 之前),
    // 则把 system 作为 delta 的首条 synthetic message 注入.
    // 这让根节点的 system prompt 在 timeline 可见 (issue #27 bug 3).
    if node.parent.is_none() && start > 0 {
        // Anthropic 风格: 顶层 system 字段 (string 或 array).
        if let Some(sys) = req_body.get("system") {
            let sys_text = if let Some(s) = sys.as_str() {
                (!s.is_empty()).then(|| s.to_string())
            } else if let Some(arr) = sys.as_array() {
                extract_text_blocks(arr).map(|t| t.join("\n"))
            } else {
                None
            };
            if let Some(text) = sys_text {
                result.insert(0, serde_json::json!({"role": "system", "content": text}));
            }
        }
        // OpenAI 风格: messages[0] 是 role=system (writer 写回).
        // 若 start > 0 且 messages[0].role == system, 注入到 delta 首位
        // (额外 guard result.first 非 system, 防御 messages 含多条 system 的畸形输入).
        else if messages
            .first()
            .and_then(|m| m.get("role").and_then(|r| r.as_str()))
            == Some("system")
            && result
                .first()
                .and_then(|m| m.get("role").and_then(|r| r.as_str()))
                != Some("system")
        {
            result.insert(0, messages[0].clone());
        }
    }

    result
}

/// 从 BlockPool 结构化派生 timeline 的 req_delta_messages (B1 数据源).
///
/// 数据流: `req_delta` (MessageRef, **real 视角含真 secret**) → resolve →
/// real→mock 替换 (投影重建的映射, 见 [`crate::redact::rebuild_real_to_mock_pairs`])
/// → ingress writer 序列化 → 取尾 `count` 条 wire messages (+ 根节点 system 注入).
/// 输出与 legacy [`extract_delta_messages_from_raw`] (req_body_raw 切片) **逐字节
/// 等价**, 由 `prop_blocks_derivation_matches_raw` (常驻) +
/// [`assert_delta_view_matches_raw`] (consistency-check shadow) 双重守卫.
///
/// # 等价性要点 (为什么字节级成立)
///
/// - 推送的 real messages 与产出 req_body_raw 的 redact 后 IR 出自同一 reader 解析
///   (clone 快照), block 内容 + wire 形态元数据 (content_form 等, MessageRef 保存)
///   完全一致; 同一 ingress writer 序列化 → 相同字节.
/// - mock 替换: 旧路径的 text 叶子 = redact_ir_inner 逐 secret `replace_in_place`
///   的产物; 新路径用同一 `replace_in_place` 按同一处理序 (见
///   `rebuild_real_to_mock_pairs` 文档) 重放 → 相同字节.
/// - 尾部切片: delta 是 messages 的后缀, writer 的 message 展开是逐消息的
///   (OpenAI 含 ToolResult 拆分), delta 的 wire 展开 = 全量 wire 数组的后缀;
///   取尾 `count` 条与旧路径 `messages[len-count..]` 同元素.
/// - system 注入: 见下方 "system 注入等价".
///
/// # system 注入等价
///
/// 旧路径条件 `parent.is_none() && start > 0` + 形态分支, 在 codec 路径上等价于:
/// **根节点 && OpenAI ingress && system 文本非空** → 注入
/// `{"role":"system","content": <blocks_to_text(system)>}` (与旧路径克隆的
/// messages[0] = OpenAI writer 的 system 输出同形). Anthropic writer 对 messages
/// 1:1 不膨胀 (根节点恒 start==0, 旧路径的 Anthropic 分支在生产不可达 — 顶层
/// system 从不进 messages 数组), Responses wire 无 messages 字段 (下方早退) —
/// 两协议均不注入, 与旧行为一致. 根节点 system blocks 来自 `Node.system_refs`
/// (real 视角), 同样过 real→mock 替换后 join — 与 writer 写入 req_body_raw 的
/// system 文本 (替换后 blocks_to_text) 相同.
///
/// # passthrough / 空协议节点
///
/// `ingress_protocol == None` (字节透传) 或 `req_delta` 空 (count==0) → 空 Vec,
/// 与旧路径行为一致 (passthrough 节点 timeline 本就是 preview-only).
///
/// # 鲁棒性 (ROB-1 契约)
///
/// resolve 失败 = 池状态损坏 (节点自持 refcount, 理论不变式下 block 不会被
/// evict) — 返回空 Vec 而非 panic, 前端降级 preview-only.
pub(crate) fn extract_delta_messages_from_blocks(
    node: &crate::dag::Node,
    pool: &crate::dag::BlockPool,
) -> Vec<serde_json::Value> {
    use crate::codec::ir::{IrBlock, IrMessage, IrRequest};

    let count = node.req_delta.len();
    if count == 0 {
        return Vec::new();
    }
    let Some(protocol) = node.event.ingress_protocol else {
        return Vec::new();
    };
    // Responses ingress: wire 是 input[] 而非 messages[], 旧路径恒返回空
    // (已知限制, DTO-5) — 等价复刻, 不趁机"修复".
    if protocol == crate::codec::Protocol::OpenAIResponses {
        return Vec::new();
    }

    // resolve req_delta → real 视角 IrMessage.
    let mut msgs: Vec<IrMessage> = Vec::with_capacity(count);
    for r in node.req_delta.iter() {
        let Some(m) = pool.resolve_message(r) else {
            return Vec::new();
        };
        msgs.push(m);
    }

    // real → mock (视角对齐: 旧路径 req_body_raw 是 LLM 视角含 mock).
    let pairs = crate::redact::rebuild_real_to_mock_pairs(
        &node.event.redactions,
        &node.event.policy.secrets,
    );
    if !pairs.is_empty() {
        crate::redact::apply_real_to_mock_messages(&mut msgs, &pairs);
    }

    // ingress writer 序列化: 经合成 IrRequest 复用 write_request 的 message 展开
    // 逻辑 (含 OpenAI ToolResult 拆分为 1+N 条 wire 消息), 只取 messages 数组.
    let writer = protocol.writer();
    let wire = writer.write_request(&IrRequest {
        messages: msgs,
        ..Default::default()
    });
    let Some(arr) = wire.get("messages").and_then(|m| m.as_array()) else {
        return Vec::new();
    };
    // 每条 IR message 展开为 ≥1 条 wire 消息, 故 arr.len() ≥ count;
    // saturating_sub 为防御性写法 (池损坏时不 panic).
    // 前提 (不变式): 两个 reader 都把 System 消息提升出 ir.messages — 故
    // Anthropic writer 的 System filter (1:N 收缩) 生产不可达; 若未来 reader
    // 放开 System-in-messages, 此处与旧切片路径 (count > len 早退空 Vec) 将分歧.
    let start = arr.len().saturating_sub(count);
    let mut result: Vec<serde_json::Value> = arr[start..].to_vec();

    // 根节点 system 注入 (等价推导见函数头 "system 注入等价"; 仅 OpenAI 可达).
    if node.parent.is_none() && protocol == crate::codec::Protocol::OpenAI {
        let mut sys_blocks: Vec<IrBlock> = Vec::with_capacity(node.system_refs.len());
        for &h in node.system_refs.iter() {
            let Some(b) = pool.get(h) else {
                return Vec::new();
            };
            sys_blocks.push((*b).clone());
        }
        if !pairs.is_empty() {
            crate::redact::apply_real_to_mock_blocks(&mut sys_blocks, &pairs);
        }
        let text = crate::codec::blocks_to_text(&sys_blocks);
        // 与旧路径等价的 gate: OpenAI writer 仅在 text 非空时写 system message
        // (messages[0] 存在且 role=system), 注入才可能触发.
        if !text.is_empty() {
            result.insert(0, serde_json::json!({"role": "system", "content": text}));
        }
    }

    result
}

/// tail parsed 派生 (B1): response.message (LLM 视角 blocks, MessageRef) +
/// [`ResponseData`] 元字段 → ingress writer 序列化的响应 envelope.
///
/// # 数据源与视角
///
/// `response.message` 存的是 **LLM 原始返回** (含 mock, 未 restore) — 与清除前的
/// stored `parsed` (writer 序列化的同一 IrResponse) 视角一致. 元字段
/// (usage / stop_reason / stop_sequence / id / created / model) 在响应 finalize
/// 时从最终 IrResponse 一并快照进 [`ResponseData`] (此前为空, B1 接通).
///
/// # 等价性与已知非确定点
///
/// 派生 = `writer(IrResponse { content: resolve(message), 元字段 })`, stored =
/// `writer(同一 IrResponse)` — resolve 的 blocks 与元字段逐项相同 → 字节级相等,
/// 例外是 writer 对缺失字段的**合成是非确定的**:
/// - `id == None` → writer 合成随机 id (`chatcmpl-{random}`);
/// - `created == None` → writer 取当前 epoch 秒.
///
/// 上游响应缺这两个字段时 (病态场景), 每次派生的 id/created 值不同 (长度恒定,
/// 不影响前端 length 判定); consistency-check 守卫比对时对这两字段归一化.
///
/// # 返回 None 的条件 (调用方走 stored parsed / raw fallback)
///
/// - `message` 缺失: 流式进行中 (finalize 前) / 错误响应 / 无 codec 协议;
/// - 任一 block resolve 失败 (池损坏, ROB-*);
/// - `usage_present` 等 wire 形态位: writer 不读, 不参与.
pub(crate) fn response_parsed_from_parts(
    protocol: crate::codec::Protocol,
    pool: &crate::dag::BlockPool,
    message: &crate::dag::MessageRef,
    resp: &crate::dag::ResponseData,
) -> Option<serde_json::Value> {
    let content = pool.resolve_message(message)?.content;
    let ir_resp = crate::codec::ir::IrResponse {
        content,
        stop_reason: resp.stop_reason,
        stop_sequence: resp.stop_sequence.clone(),
        usage: resp.usage.clone().unwrap_or_default(),
        // writer 不读此位 (见 IrResponse::usage_present 文档); 语义上与
        // usage 的 Option-ness 对齐即可.
        usage_present: resp.usage.is_some(),
        id: resp.id.clone(),
        created: resp.created,
        model: resp.model.clone(),
    };
    Some(protocol.writer().write_response(&ir_resp))
}

/// B1 双态 parsed 的**单点语义** (四个渲染消费点共享: timeline tail /
/// NodeView.parsed_response / records parsed view / dag 便捷入口):
/// 流式进行中 → stored 节流 parsed (StreamScan 快照, 前端实时进度) 优先;
/// finalize 后 (stored 已清除) → `response.message` + 元字段渲染派生.
pub(crate) fn parsed_view(
    node: &crate::dag::Node,
    pool: &crate::dag::BlockPool,
    resp: &crate::dag::ResponseData,
) -> Option<serde_json::Value> {
    resp.parsed.clone().or_else(|| {
        let message = resp.message.as_ref()?;
        node.event
            .ingress_protocol
            .and_then(|protocol| response_parsed_from_parts(protocol, pool, message, resp))
    })
}

/// 视图正确性守卫 (CI 用, 需 `--features consistency-check`): blocks 派生 (新,
/// 生产路径) 与 req_body_raw 切片 (旧, 保留 oracle) 的输出逐元素相等.
///
/// B1 数据源切换的 shadow 断言 — "先断言后删除" 纪律: req_body_raw 仍是 SSOT
/// 存储 (B2 才引入不存储开关), 在它被任何 timeline 路径放弃前, 每次渲染都
/// 验证两条派生路径等价. 详见 AGENTS.md "视图正确性确保机制" (VIEW-2 表).
///
/// 跳过: `ingress_protocol == None` (passthrough) 节点 — 生产不变式下其
/// req_delta 恒空 (same_proto_passthrough / 无 codec 降级均推 `vec![]`),
/// count>0 + 无协议是 fixture-only 的矛盾态, 两路径对它的输出定义不同
/// (blocks 路径返回空更安全: passthrough raw 是未 redact 的客户端原始字节).
/// 跳过 (B2): `audit_captured == false` 的请求 — req_body_raw 未存储 (空串),
/// oracle 无数据源; on 的请求守卫行为不变.
#[cfg(feature = "consistency-check")]
pub(crate) fn assert_delta_view_matches_raw(node: &crate::dag::Node, pool: &crate::dag::BlockPool) {
    if node.event.ingress_protocol.is_none() || !node.event.audit_captured {
        return;
    }
    let derived = extract_delta_messages_from_blocks(node, pool);
    let oracle = extract_delta_messages_from_raw(node);
    debug_assert_eq!(
        derived,
        oracle,
        "timeline delta drift: blocks-derived view != req_body_raw slice \
         (node={}, proto={:?}, count={})",
        node.id,
        node.event.ingress_protocol,
        node.req_delta.len()
    );
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

    // ─── extract_tool_use_name (工具轮次 preview) ───────────────────────────

    #[test]
    fn extract_tool_use_name_finds_first() {
        let msgs = vec![crate::codec::ir::IrMessage {
            role: crate::codec::ir::IrRole::Assistant,
            content: vec![
                crate::codec::ir::IrBlock::ToolUse {
                    id: "c1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({}),
                    extra: Default::default(),
                },
                crate::codec::ir::IrBlock::ToolUse {
                    id: "c2".into(),
                    name: "write_file".into(),
                    input: serde_json::json!({}),
                    extra: Default::default(),
                },
            ],
            ..Default::default()
        }];
        assert_eq!(
            extract_tool_use_name(&msgs).as_deref(),
            Some("read_file"),
            "首个 ToolUse 的 name"
        );
    }

    #[test]
    fn extract_tool_use_name_empty_returns_none() {
        assert!(extract_tool_use_name(&[]).is_none());
    }

    #[test]
    fn extract_tool_use_name_no_tool_use_returns_none() {
        // 只有 Text block, 无 ToolUse.
        let msgs = vec![crate::codec::ir::IrMessage {
            role: crate::codec::ir::IrRole::User,
            content: vec![crate::codec::ir::IrBlock::Text {
                text: "hello".into(),
                extra: Default::default(),
            }],
            ..Default::default()
        }];
        assert!(extract_tool_use_name(&msgs).is_none());
    }

    #[test]
    fn extract_tool_use_name_truncates_long_name() {
        let long = "x".repeat(100);
        let msgs = vec![crate::codec::ir::IrMessage {
            role: crate::codec::ir::IrRole::Assistant,
            content: vec![crate::codec::ir::IrBlock::ToolUse {
                id: "c1".into(),
                name: long,
                input: serde_json::json!({}),
                extra: Default::default(),
            }],
            ..Default::default()
        }];
        let name = extract_tool_use_name(&msgs).expect("Some");
        assert!(name.ends_with('…'));
        assert_eq!(name.chars().count(), PREVIEW_MAX + 1); // 48 + '…'
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
                    extra: Default::default(),
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
                    extra: Default::default(),
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

    // ─── extract_delta_messages_from_raw (ROB-1 + system 注入) ──────────────
    //
    // 契约: docs/design/contracts.md §8 ROB-1 — extract_delta_messages_from_raw
    // (timeline 的 req_delta 切片 fallback) 对任意 req_body_raw + 任意 req_delta.len()
    // 组合 (含非 JSON / 空 / 损坏 / count 与 messages 数不匹配) 必须不 panic, 返回空 Vec
    // 或合法切片.
    //
    // catch_unwind 守卫: 即便未来有人改函数时引入 panic 路径, 这个 property 也会显式 fail
    // 并报告输入的 (count, body_len), 而非让测试进程崩溃 (release build panic=abort 时
    // proptest 自身的 panic-as-fail 机制无法生效).

    use crate::codec::ir::IrRole;
    use crate::dag::{CallEvent, Node, PolicySnapshot, SessionId};
    use parking_lot::RwLock;
    use std::sync::Arc;
    use uuid::Uuid;

    /// 构造一个最小化 Node, 用作 extract_delta_messages_from_raw 的 fixture.
    /// `count` 决定 `req_delta.len()` (函数内部用此长度做切片); `req_body_raw` 是任意字节.
    fn fixture_node(count: usize, req_body_raw: String) -> Node {
        let event = CallEvent {
            created_at: chrono::Utc::now(),
            method: "POST".to_string(),
            path: "/o/test/v1/chat".to_string(),
            req_headers: vec![],
            ingress_protocol: None,
            redact_seed: 0,
            req_system: vec![],
            policy: Arc::new(PolicySnapshot::default()),
            req_body_raw,
            round_role: IrRole::User,
            round_kind: crate::dag::RoundKind::Normal,
            preview: None,
            model: None,
            upstream_id: Arc::from("test"),
            redactions: Arc::from([]),
            upstream_model: None,
            audit_captured: true,
        };
        // req_delta 用任意 MessageRef 填充到 count 长度 — 内容不重要, 只用 len().
        let dummy_ref = crate::dag::MessageRef {
            role: IrRole::User,
            blocks: Vec::new(),
            content_form: None,
            reasoning_content_form: None,
        };
        let req_delta: Arc<[crate::dag::MessageRef]> = if count == 0 {
            Arc::from([])
        } else {
            Arc::from(vec![dummy_ref; count])
        };
        Node {
            id: Uuid::new_v4(),
            parent: None, // 根节点: 触发 system 注入分支
            session_id: SessionId::new(),
            child_count: 0,
            req_delta,
            system_refs: Arc::from([]),
            own_hash: 0,
            prefix_hash: 0,
            event,
            response: RwLock::new(None),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// ROB-1 (变体 A): 任意字节 body + 任意 count, extract_delta_messages_from_raw 不 panic.
        /// 主要覆盖 serde_json::from_str 失败路径 (messages 不可解析 → 早退返回空 Vec).
        #[test]
        fn prop_delta_never_panics_arbitrary(
            count in 0usize..32,
            bytes in prop::collection::vec(any::<u8>(), 0..2048)
        ) {
            let body = String::from_utf8_lossy(&bytes).into_owned();
            let node = fixture_node(count, body.clone());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                extract_delta_messages_from_raw(&node)
            }));
            prop_assert!(
                result.is_ok(),
                "ROB-1 violation: extract_delta_messages_from_raw panicked \
                 (count={}, body_len={})",
                count,
                body.len()
            );
        }

        /// ROB-1 (变体 B): 合法 chat JSON + count 在 messages.len() 边界附近不 panic.
        ///
        /// `messages[start..]` 切片 (start = messages.len() - count) 是 panic 高危区.
        /// 本 property 构造合法 messages 数组 + 让 count 在 `[0 .. n+2]` 区间随机,
        /// 覆盖 count < n (正常切片) / count == n (全取) / count > n (函数内早退返回空)
        /// 三种语义. 配合 parent=None (根节点) 触发 system 注入分支, 覆盖完整函数路径.
        #[test]
        fn prop_delta_never_panics_chat_json_edge_slice(
            n in 1usize..16,
            count in 0usize..18,  // 故意让 count 能略大于 n, 触发 messages.len() < count 早退分支
            seed in any::<u64>()
        ) {
            // n 条 messages + count 的依赖关系难以纯声明式表达 (count 需引用 n),
            // 这里用确定性 seed 直接构造 body (role/content 随机但 n 固定).
            let body = build_chat_body_with_n_messages(n, seed);
            let node = fixture_node(count, body.clone());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                extract_delta_messages_from_raw(&node)
            }));
            prop_assert!(
                result.is_ok(),
                "ROB-1 violation: extract_delta_messages_from_raw panicked on chat-json \
                 (n={}, count={}, body_len={})",
                n,
                count,
                body.len()
            );
        }
    }

    /// 用确定性 seed 生成含 n 条 messages 的合法 chat JSON.
    /// role/content 从 (seed, i) 经 `crate::util::hash64` 派生 (项目 SSOT, 见 src/util.rs),
    /// 每个 i 独立 hash, 保证可复现, 不依赖 proptest strategy API.
    fn build_chat_body_with_n_messages(n: usize, seed: u64) -> String {
        let msgs: Vec<String> = (0..n)
            .map(|i| {
                let h = crate::util::hash64(&(seed, i));
                let role = match h % 4 {
                    0 => "system",
                    1 => "user",
                    2 => "assistant",
                    _ => "tool",
                };
                let content = format!("msg-{}", h % 1000);
                format!("{{\"role\":\"{role}\",\"content\":\"{content}\"}}")
            })
            .collect();
        format!("{{\"messages\":[{}]}}", msgs.join(","))
    }

    // ─── DTO-5 切片正确性 (契约 §3 DTO-5) ──────────────────────────────────
    //
    // 契约: docs/design/contracts.md §3 DTO-5 — timeline 路径的 req_delta_messages
    // 必须是本轮新增的 messages (同协议路径 = req_body_raw 末尾 count 条). 这是正确性契约,
    // 不同于 ROB-1 (鲁棒性, 不 panic). 用确定性 content 让逐条断言可行.

    /// 构造合法 chat JSON, messages 数 = n, 第 i 条 content = format!("{i}").
    /// 用确定性的 messages (而非 hash 派生) 让 slice 正确性可逐条断言.
    fn build_chat_body_indexed(n: usize) -> String {
        let msgs: Vec<String> = (0..n)
            .map(|i| format!("{{\"role\":\"user\",\"content\":\"msg-{i}\"}}"))
            .collect();
        format!("{{\"messages\":[{}]}}", msgs.join(","))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// DTO-5 `prop_delta_slice_correct_same_proto`:
        /// 同协议路径下, req_delta_messages == req_body_raw 末尾 count 条 messages.
        ///
        /// 构造: n 条 messages (n ∈ [2, 12]), count ∈ [1, n] (保证 messages.len() >= count).
        /// 断言: result.len() == count, 且 result == messages[start..] (start = n - count),
        /// content 逐条相等.
        ///
        /// 注: 根节点 (parent=None) 且 start > 0 时函数会注入 system (若无 system 字段则
        /// OpenAI 风格 messages[0]=system). 这里 messages[0] 是 role=user, start>0 时
        /// messages[0].role != system → 不注入 → result 严格 == messages[start..].
        /// 为隔离 system 注入逻辑 (DTO-5 prop_delta_includes_system_at_root 单独守卫),
        /// 本 property 用 parent=None 且 count == n (start=0, 不触发 system 注入) +
        /// count < n 但 messages[0].role=user 两种 case:
        /// - count == n: start=0, 无 system 注入, result == messages[0..].
        /// - count < n: start>0, messages[0].role=user (非 system) → 不注入, result == messages[start..].
        #[test]
        fn prop_delta_slice_correct_same_proto(
            n in 2usize..=12,
            count in 1usize..=12, // 由 prop_assume 约束 ≤ n
        ) {
            prop_assume!(count <= n, "count must be ≤ n for slice semantics");
            let body = build_chat_body_indexed(n);
            let node = fixture_node(count, body.clone());
            let result = extract_delta_messages_from_raw(&node);

            let start = n - count;
            prop_assert_eq!(
                result.len(),
                count,
                "DTO-5: result.len() 应 == count, 实际 {}",
                result.len(),
            );
            // 逐条比对 content (messages[start..]).
            for (i, got) in result.iter().enumerate() {
                let want_idx = start + i;
                let want_content = format!("msg-{want_idx}");
                let got_content = got
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<missing>");
                prop_assert_eq!(
                    got_content, &want_content,
                    "DTO-5: result[i] content 不匹配 (want messages[want_idx])"
                );
            }
        }

        /// DTO-5 `prop_delta_includes_system_at_root`:
        /// 根节点 (parent=None) 的 delta 在 start > 0 时补回 system prompt.
        ///
        /// 构造: OpenAI 风格 body, messages[0] = role=system, 后续 n-1 条 user.
        /// count < n → start > 0, messages[0].role == system → 注入到 result 首位.
        /// 断言: result[0].role == "system" (注入的 system message).
        #[test]
        fn prop_delta_includes_system_at_root(
            n_sys in 3usize..=8,    // 含 1 条 system + (n_sys-1) 条 user
            count in 1usize..=8,
        ) {
            prop_assume!(count < n_sys, "count < n_sys 才触发 system 注入 (start > 0)");
            // body: messages[0]=system, messages[1..]=user.
            let mut msgs = vec![r#"{"role":"system","content":"SYS-PROMPT"}"#.to_string()];
            for i in 1..n_sys {
                msgs.push(format!("{{\"role\":\"user\",\"content\":\"u-{i}\"}}"));
            }
            let body = format!("{{\"messages\":[{}]}}", msgs.join(","));
            let node = fixture_node(count, body);
            let result = extract_delta_messages_from_raw(&node);

            // 注入的 system 在 result 首位.
            prop_assert!(
                !result.is_empty(),
                "DTO-5 system 注入: result 不应为空 (count={count})"
            );
            let first_role = result[0]
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            prop_assert_eq!(
                first_role, "system",
                "DTO-5 system 注入: result[0].role 应为 system (根节点 start>0 时注入)"
            );
        }

        /// DTO-5 `prop_delta_handles_non_json_body`:
        /// 非 JSON body 时返回空 vec (不 panic).
        ///
        /// 构造: req_body_raw = 任意字节 (非 JSON), count > 0.
        /// 断言: result.is_empty() (serde_json::from_str 失败早退).
        #[test]
        fn prop_delta_handles_non_json_body(
            count in 1usize..=8,
            body in "[^{}\\[\\]]{0,64}", // 非 JSON-ish 字节
        ) {
            // prop_assume: body 不应意外是合法 JSON object/array (生成器已排除 {} []).
            prop_assume!(!body.trim_start().starts_with('{'), "body 非合法 JSON object");
            let node = fixture_node(count, body.clone());
            let result = extract_delta_messages_from_raw(&node);
            prop_assert!(
                result.is_empty(),
                "DTO-5: 非 JSON body 应返回空 vec (body={:?}, count={count})",
                body,
            );
        }

        /// DTO-5 `prop_delta_handles_count_mismatch`:
        /// messages 数 < req_delta_count 时返回空 vec.
        ///
        /// 构造: n 条 messages, count > n (函数内 messages.len() < count 早退).
        /// 断言: result.is_empty().
        #[test]
        fn prop_delta_handles_count_mismatch(
            n in 1usize..=8,
            extra in 1usize..=5, // count = n + extra > n
        ) {
            let count = n + extra;
            let body = build_chat_body_indexed(n);
            let node = fixture_node(count, body.clone());
            let result = extract_delta_messages_from_raw(&node);
            prop_assert!(
                result.is_empty(),
                "DTO-5: messages 数 ({n}) < count ({count}) 应返回空 vec",
            );
        }
    }

    // ─── system 注入 (Anthropic 风格顶层 system / OpenAI 风格 messages[0]) ────
    //
    // 覆盖 extract_delta_messages_from_raw 的根节点 system 注入分支.
    // OpenAI reader 把 role=system 提升到 IrRequest.system (不在 messages 里),
    // writer 再写回 messages[0]. 故根节点 delta 切片可能不含 system, 需注入.
    //
    // Anthropic 风格 (顶层 "system" 字段, string 或 array) 走的是另一个分支,
    // proptest 生成器不产生顶层 system 字段, 故用固定用例补全覆盖.

    /// 构造 Anthropic 风格 body: 顶层 system 字段 + 固定 3 条 messages (u1/a1/u2).
    /// 5 个 system 注入测试共享此骨架, 只变 system 字段值.
    fn body_with_anthropic_system(system_field: &str) -> String {
        format!(
            r#"{{"system":{system_field},"messages":[
                {{"role":"user","content":"u1"}},
                {{"role":"assistant","content":"a1"}},
                {{"role":"user","content":"u2"}}
            ]}}"#
        )
    }

    #[test]
    fn delta_includes_anthropic_top_level_system_string() {
        // Anthropic 风格: 顶层 "system" 是 string. 根节点 + start>0 → 注入 system.
        // count=1 → start=2>0, 注入顶层 system 到 delta 首位.
        let node = fixture_node(1, body_with_anthropic_system(r#""ANTHROPIC-SYS""#));
        let result = extract_delta_messages_from_raw(&node);
        // result[0] 应为注入的 system, result[1] 为切出的 user.
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].get("role").and_then(|v| v.as_str()),
            Some("system")
        );
        assert_eq!(
            result[0].get("content").and_then(|v| v.as_str()),
            Some("ANTHROPIC-SYS")
        );
        assert_eq!(
            result[1].get("content").and_then(|v| v.as_str()),
            Some("u2")
        );
    }

    #[test]
    fn delta_includes_anthropic_top_level_system_array() {
        // Anthropic 风格: 顶层 "system" 是 array of {type:text,text:...}.
        // 覆盖 extract_text_blocks 路径.
        let node = fixture_node(
            1,
            body_with_anthropic_system(
                r#"[{"type":"text","text":"SYS-A"},{"type":"text","text":"SYS-B"}]"#,
            ),
        );
        let result = extract_delta_messages_from_raw(&node);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].get("role").and_then(|v| v.as_str()),
            Some("system")
        );
        // array 的多个 text block 用 \n join.
        assert_eq!(
            result[0].get("content").and_then(|v| v.as_str()),
            Some("SYS-A\nSYS-B")
        );
    }

    #[test]
    fn delta_skips_empty_anthropic_system_string() {
        // 边界: 顶层 system 是空字符串 → (!is_empty).then 为 None → 不注入.
        let node = fixture_node(1, body_with_anthropic_system(r#""""#));
        let result = extract_delta_messages_from_raw(&node);
        // 空 system 不注入, result 只有切出的 user.
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].get("content").and_then(|v| v.as_str()),
            Some("u2")
        );
    }

    #[test]
    fn delta_skips_non_string_non_array_anthropic_system() {
        // 边界: 顶层 system 是 number (非 string 非 array) → None → 不注入.
        let node = fixture_node(1, body_with_anthropic_system("42"));
        let result = extract_delta_messages_from_raw(&node);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].get("content").and_then(|v| v.as_str()),
            Some("u2")
        );
    }

    #[test]
    fn delta_does_not_inject_system_for_non_root_node() {
        // 非根节点 (parent=Some) 即使有顶层 system + start>0 也不注入.
        let mut node = fixture_node(1, body_with_anthropic_system(r#""SYS""#));
        node.parent = Some(Uuid::new_v4()); // 改为非根节点
        let result = extract_delta_messages_from_raw(&node);
        // 非根节点不注入 system, result 只有切出的 user.
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].get("content").and_then(|v| v.as_str()),
            Some("u2")
        );
    }

    // ─── prop_blocks_derivation_matches_raw (B1 等价性质, DTO-5) ──────────
    //
    // 契约: docs/design/contracts.md §5 DTO-5 — timeline 的 req_delta_messages
    // 从 BlockPool 派生 (B1 数据源) 与旧 req_body_raw 尾部切片 (oracle) **逐字节
    // 等价**. 生成器覆盖 matrix (覆盖度是契约要求, 见 §0.4):
    //   × ingress 协议 wire 形态: OpenAI / Anthropic
    //   × system 形态: 无 / 顶层 string / 顶层 array / messages[0] role=system
    //   × delta 规模: 1..=6 条 message (全链最多 8)
    //   × block 种类: Text / 裸 string content / array content / null content /
    //     ToolUse (含嵌套 input JSON) / ToolResult (含 is_error) / Image
    //   × secret 命中: 0 条 (seed=0) / 1..=3 条命中 (seed≠0, 含 tool input /
    //     tool_result 深处命中) / 另加 1 条未命中
    //   × 根 / 非根节点 (prefix 延续 push)
    //
    // 管线 = 生产管线镜像: wire body → ingress reader → clone real 快照 →
    // redact_ir (LLM 视角) → derive_redactions (投影) → ingress writer 序列化
    // → req_body_raw → dag.push_messages (+ 根节点 system_refs).
    // 比对: dag.timeline_view 的 req_delta_messages (新生产路径) vs
    // extract_delta_messages_from_raw (oracle, 经最小 Node shim 喂入同 raw).

    use crate::codec::Protocol as CodecProtocol;
    use crate::dag::ConversationDag;
    use crate::secrets::{SecretCategory, SecretEntry};

    /// 与 redact 测试同型的 secret entry 构造 (Auto 策略经 resolve_against infer,
    /// 与生产 validate_and_resolve 路径一致).
    fn eq_secret_entry(value: &str) -> SecretEntry {
        let mut e = SecretEntry {
            id: format!("sid-{value}"),
            name: None,
            category: SecretCategory::ApiKey,
            value: value.into(),
            value_file: None,
            mock_strategy: crate::mock::MockStrategy::default(),
        };
        e.mock_strategy.resolve_against(&e.value, "");
        e
    }

    /// 可嵌 secret 的文本: `(基串, secret 池索引)`.
    type MaybeSecretText = (String, Option<usize>);

    /// Chat 消息 content array 的 part: 文本 / 图片 (url 可嵌 secret — Image 的
    /// url 是 StringLeafOps 叶子, redact 覆盖, matrix 轴之一).
    #[derive(Clone, Debug)]
    enum EqPart {
        Text(MaybeSecretText),
        Image(MaybeSecretText),
    }

    /// 协议无关的 message 抽象 (渲染层按 proto 输出 wire 形态).
    #[derive(Clone, Debug)]
    enum EqMsg {
        /// user / assistant 的普通消息, content 形态三选一 (L1 保真轴).
        Chat {
            assistant: bool,
            str_form: bool,
            null_form: bool,
            parts: Vec<EqPart>,
        },
        /// assistant 发起工具调用 (arguments 是 JSON object 源码串, 内含文本叶子).
        ToolUse {
            id: String,
            name: String,
            args_text: MaybeSecretText,
        },
        /// 工具结果回传 (OpenAI: role=tool 独立消息; Anthropic: user 内 tool_result).
        ToolResult {
            tool_use_id: String,
            text: MaybeSecretText,
            is_error: bool,
        },
    }

    fn render_text(t: &MaybeSecretText, pool: &[SecretEntry]) -> String {
        // 索引越界 (生成器索引 0..4, 实际 secrets 0..=3) 视为不嵌 — 兼作
        // "0 命中" 轴的来源.
        match t.1.and_then(|i| pool.get(i)) {
            Some(e) => format!("{}{}{}", t.0, e.value, t.0),
            None => t.0.clone(),
        }
    }

    /// Chat 消息的协议共享渲染 (两协议仅 Image part 的 wire 形态分叉):
    /// role + content 三态 (null / 裸 string (仅单 Text part 合法) / array).
    fn render_chat_msg(
        assistant: bool,
        str_form: bool,
        null_form: bool,
        parts: &[EqPart],
        pool: &[SecretEntry],
        render_image: impl Fn(&str) -> serde_json::Value,
    ) -> serde_json::Value {
        let role = if assistant { "assistant" } else { "user" };
        // 裸 string 形态仅对 "单 Text part" 合法 (图片无 string 形态);
        // 生成器的 str_form 对非该形态自动回退 array (两侧 reader 对称归一).
        let single_text = match parts {
            [EqPart::Text(t)] => Some(render_text(t, pool)),
            _ => None,
        };
        let content = if null_form {
            serde_json::Value::Null
        } else if str_form && let Some(t) = single_text {
            // 裸 string content (reader 归一化为单 Text block + String 形态).
            serde_json::Value::String(t)
        } else {
            serde_json::Value::Array(
                parts
                    .iter()
                    .map(|p| match p {
                        EqPart::Text(t) => serde_json::json!({
                            "type": "text", "text": render_text(t, pool)
                        }),
                        EqPart::Image(url) => render_image(&render_text(url, pool)),
                    })
                    .collect(),
            )
        };
        serde_json::json!({"role": role, "content": content})
    }

    /// 把协议无关 message 渲染为 OpenAI wire 形态.
    fn render_msg_openai(m: &EqMsg, pool: &[SecretEntry]) -> serde_json::Value {
        match m {
            EqMsg::Chat {
                assistant,
                str_form,
                null_form,
                parts,
            } => render_chat_msg(
                *assistant,
                *str_form,
                *null_form,
                parts,
                pool,
                |url| serde_json::json!({"type": "image_url", "image_url": {"url": url}}),
            ),
            EqMsg::ToolUse {
                id,
                name,
                args_text,
            } => serde_json::json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": id,
                    "type": "function",
                    "function": {"name": name, "arguments": render_text(args_text, pool)}
                }]
            }),
            EqMsg::ToolResult {
                tool_use_id,
                text,
                is_error,
            } => serde_json::json!({
                "role": "tool",
                "tool_call_id": tool_use_id,
                "content": render_text(text, pool),
                "is_error": is_error,
            }),
        }
    }

    /// 把协议无关 message 渲染为 Anthropic wire 形态.
    fn render_msg_anthropic(m: &EqMsg, pool: &[SecretEntry]) -> serde_json::Value {
        match m {
            EqMsg::Chat {
                assistant,
                str_form,
                null_form,
                parts,
            } => render_chat_msg(
                *assistant,
                *str_form,
                *null_form,
                parts,
                pool,
                |url| serde_json::json!({"type": "image", "source": {"type": "url", "url": url}}),
            ),
            EqMsg::ToolUse {
                id,
                name,
                args_text,
            } => serde_json::json!({
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "id": id,
                    "name": name,
                    // input: JSON object (文本叶子内嵌 secret).
                    "input": {"q": render_text(args_text, pool), "n": 1}
                }]
            }),
            EqMsg::ToolResult {
                tool_use_id,
                text,
                is_error,
            } => {
                let mut tr = serde_json::json!({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": render_text(text, pool)
                });
                if *is_error {
                    tr["is_error"] = serde_json::Value::Bool(true);
                }
                serde_json::json!({"role": "user", "content": [tr]})
            }
        }
    }

    /// system 形态 (matrix 轴).
    #[derive(Clone, Debug)]
    enum EqSystem {
        None,
        /// 顶层 system: string 形态 (OpenAI 渲染为 messages[0]; Anthropic 为 "system": "...").
        TopLevelString(Vec<MaybeSecretText>),
        /// 顶层 system: array-of-text-blocks 形态.
        TopLevelArray(Vec<MaybeSecretText>),
        /// messages[0] role=system (OpenAI 原生形态; Anthropic 非标准但 reader 支持).
        InMessages(Vec<MaybeSecretText>),
    }

    /// 完整等价性测试用例.
    #[derive(Clone, Debug)]
    struct EqCase {
        proto: CodecProtocol,
        system: EqSystem,
        /// 全链 messages (prefix = 前 `prefix_len` 条; delta = 其余, ≥1).
        msgs: Vec<EqMsg>,
        prefix_len: usize,
        secrets: Vec<SecretEntry>,
    }

    /// system 文本块渲染 (InMessages / TopLevelArray 共用).
    fn render_text_blocks(t: &[MaybeSecretText], pool: &[SecretEntry]) -> Vec<serde_json::Value> {
        t.iter()
            .map(|p| serde_json::json!({"type": "text", "text": render_text(p, pool)}))
            .collect()
    }

    /// 渲染完整请求 body (per proto). `msgs` 为消息切片 (prefix 请求 / full 请求).
    fn render_body(c: &EqCase, msgs: &[EqMsg]) -> serde_json::Value {
        let mut wire_msgs: Vec<serde_json::Value> = msgs
            .iter()
            .map(|m| match c.proto {
                CodecProtocol::OpenAI => render_msg_openai(m, &c.secrets),
                _ => render_msg_anthropic(m, &c.secrets),
            })
            .collect();
        match &c.system {
            EqSystem::None => {}
            EqSystem::InMessages(t) => {
                wire_msgs.insert(
                    0,
                    serde_json::json!({
                        "role": "system",
                        "content": render_text_blocks(t, &c.secrets)
                    }),
                );
            }
            EqSystem::TopLevelString(t) if c.proto == CodecProtocol::OpenAI => {
                // OpenAI 无顶层 system 字段 — 生产客户端把它放 messages[0],
                // reader 提升进 ir.system, writer 写回 messages[0].
                let text = render_text(&t[0], &c.secrets);
                wire_msgs.insert(0, serde_json::json!({"role": "system", "content": text}));
            }
            _ => {}
        }
        let mut body = serde_json::Map::new();
        body.insert("model".into(), serde_json::json!("eq-model"));
        if c.proto == CodecProtocol::Anthropic {
            body.insert("max_tokens".into(), serde_json::json!(64));
            match &c.system {
                EqSystem::TopLevelString(t) => {
                    body.insert(
                        "system".into(),
                        serde_json::json!(render_text(&t[0], &c.secrets)),
                    );
                }
                EqSystem::TopLevelArray(t) => {
                    body.insert(
                        "system".into(),
                        serde_json::Value::Array(render_text_blocks(t, &c.secrets)),
                    );
                }
                _ => {}
            }
        }
        body.insert("messages".into(), serde_json::Value::Array(wire_msgs));
        serde_json::Value::Object(body)
    }

    /// 生产管线镜像: parse → redact → 投影 → writer 序列化 → push.
    /// 返回 (node_id, req_body_raw).
    fn eq_push_request(
        dag: &ConversationDag,
        c: &EqCase,
        body: &serde_json::Value,
    ) -> Option<(uuid::Uuid, String)> {
        let reader = c.proto.reader();
        let ir = reader.read_request(body).ok()?;
        let real_system = ir.system.clone();
        let real_messages = ir.messages.clone();
        let mut llm = ir.clone();
        // 生产路径是 redact_ir_checked(FailClosed 默认); 测试用 redact_ir (FailOpen)
        // — 对能通过的生成用例两者产出相同 map.
        let (map, seed) = crate::redact::redact_ir(&mut llm, &c.secrets);
        let redactions = crate::proxy::derive_redactions(&map, &c.secrets);
        let raw = serde_json::to_string(&c.proto.writer().write_request(&llm)).ok()?;
        let event = CallEvent {
            created_at: chrono::Utc::now(),
            method: "POST".to_string(),
            path: "/o/eq/v1/chat".to_string(),
            req_headers: vec![],
            ingress_protocol: Some(c.proto),
            redact_seed: seed,
            req_system: real_system,
            policy: Arc::new(PolicySnapshot {
                secrets: Arc::from(c.secrets.clone()),
            }),
            req_body_raw: raw.clone(),
            round_role: IrRole::User,
            round_kind: crate::dag::RoundKind::Normal,
            preview: None,
            model: None,
            upstream_id: Arc::from("eq"),
            redactions: Arc::from(redactions),
            upstream_model: None,
            audit_captured: true,
        };
        Some((dag.push_messages(real_messages, event), raw))
    }

    /// 运行用例: push (prefix 根 + full 子) → timeline_view 全链比对新派生 vs oracle.
    fn eq_run_case(c: &EqCase) -> Result<(), String> {
        let dag = ConversationDag::new(32, 128, 4);
        let mut raw_of: std::collections::HashMap<uuid::Uuid, String> =
            std::collections::HashMap::new();
        let mut push = |body: &serde_json::Value| -> Result<uuid::Uuid, String> {
            let (id, raw) =
                eq_push_request(&dag, c, body).ok_or_else(|| "reader rejected body".to_string())?;
            raw_of.insert(id, raw);
            Ok(id)
        };

        let sid = if c.prefix_len == 0 {
            // 单根场景: full body 一次 push.
            let id = push(&render_body(c, &c.msgs))?;
            dag.get_node(id).unwrap().session_id
        } else {
            // 两跳场景: 根 = prefix body, 子 = full body (生产: 客户端每轮重发全量).
            let prefix: Vec<EqMsg> = c.msgs[..c.prefix_len].to_vec();
            push(&render_body(c, &prefix))?;
            let cid = push(&render_body(c, &c.msgs))?;
            let nv = dag.get_node(cid).unwrap();
            if nv.parent.is_none() {
                return Err("child unexpectedly became root (prefix mismatch)".into());
            }
            nv.session_id
        };

        // 全链 timeline (新生产路径) vs oracle (旧 raw 切片, 经最小 Node shim).
        let page = dag
            .timeline_view(sid, None, 32)
            .ok_or_else(|| "timeline_view none".to_string())?;
        for round in &page.rounds {
            let nv = dag.get_node(round.id).unwrap();
            let mut shim = fixture_node(nv.req_delta_count, raw_of.get(&round.id).unwrap().clone());
            shim.parent = nv.parent;
            let oracle = extract_delta_messages_from_raw(&shim);
            if round.req_delta_messages != oracle {
                return Err(format!(
                    "node {} (root={}, count={}) mismatch:\n  blocks: {}\n  raw:    {}",
                    round.id,
                    nv.parent.is_none(),
                    nv.req_delta_count,
                    serde_json::to_string(&round.req_delta_messages).unwrap_or_default(),
                    serde_json::to_string(&oracle).unwrap_or_default(),
                ));
            }
        }
        Ok(())
    }

    /// matrix 生成器: 见本段头部注释的轴清单.
    fn arb_eq_case() -> impl proptest::prelude::Strategy<Value = EqCase> {
        use proptest::prelude::*;
        let proto = prop::bool::ANY.prop_map(|b| {
            if b {
                CodecProtocol::Anthropic
            } else {
                CodecProtocol::OpenAI
            }
        });
        // 文本基串: 短字母数字 (与 secret 值字符集重叠, 让替换有区分度).
        let text: proptest::strategy::BoxedStrategy<MaybeSecretText> =
            (any::<u16>(), prop::option::of(0usize..4))
                .prop_map(|(n, idx)| (format!("t{}", n % 977), idx))
                .boxed();
        // Chat parts: 文本为主, 混入 image (url 可嵌 secret — Image 的 url 是
        // StringLeafOps 叶子, matrix 轴之一).
        let part: proptest::strategy::BoxedStrategy<EqPart> = prop_oneof![
            3 => text.clone().prop_map(EqPart::Text),
            1 => text.clone().prop_map(EqPart::Image),
        ]
        .boxed();
        let texts = prop::collection::vec(text.clone(), 1..=3);
        let system = prop::option::of(prop_oneof![
            3 => texts.clone().prop_map(EqSystem::TopLevelString),
            2 => texts.clone().prop_map(EqSystem::TopLevelArray),
            2 => texts.prop_map(EqSystem::InMessages),
        ]);
        let msg = prop_oneof![
            4 => (
                prop::bool::ANY,
                prop::bool::ANY,
                prop::bool::ANY,
                prop::collection::vec(part.clone(), 1..=3),
            )
                .prop_map(|(assistant, str_form, null_form, parts)| EqMsg::Chat {
                    assistant,
                    // null_form 只对 assistant 有意义 (reader 把 user 的 null 读成空 vec,
                    // 同样保留 — 覆盖空 content 消息形态).
                    str_form: str_form && !null_form,
                    null_form: null_form && assistant,
                    parts,
                }),
            2 => (any::<u16>(), text.clone()).prop_map(|(n, t)| EqMsg::ToolUse {
                id: format!("tu-{n}"),
                name: format!("tool_{}", n % 17),
                args_text: t,
            }),
            2 => (any::<u16>(), text.clone(), prop::bool::ANY).prop_map(
                |(n, t, is_error)| EqMsg::ToolResult {
                    tool_use_id: format!("tu-{}", n % 3), // 与 ToolUse id 弱关联
                    text: t,
                    is_error,
                },
            ),
        ];
        (
            proto,
            system,
            prop::collection::vec(msg, 1..8),
            any::<u64>(),
        )
            .prop_flat_map(move |(proto, system, msgs, salt)| {
                // secrets 数量 0..=3 (2/5 概率 0 条 = seed=0 轴); 长度互异覆盖替换序;
                // 偶数 salt 再加一条恒未命中 secret (只进 policy 快照, 不进文本).
                let n_secrets = ((salt % 5) as usize).saturating_sub(1);
                let mut secrets: Vec<SecretEntry> = (0..n_secrets)
                    .map(|i| {
                        let ch = char::from(b'a' + ((salt as usize + i * 7) % 26) as u8);
                        let value: String = std::iter::repeat_n(ch, 8 + i * 5).collect();
                        eq_secret_entry(&format!("{value}-sk{i}"))
                    })
                    .collect();
                if salt % 2 == 0 {
                    secrets.push(eq_secret_entry("zzz-unhit-secret-value"));
                }
                // prefix_len: salt%3==0 → 根场景; 否则 1..=msgs.len()-1 (delta ≥1).
                let max_prefix = msgs.len().saturating_sub(1);
                let prefix_len = if salt % 3 == 0 {
                    0
                } else {
                    (salt as usize) % (max_prefix + 1)
                };
                Just(EqCase {
                    proto,
                    system: system.unwrap_or(EqSystem::None),
                    msgs,
                    prefix_len,
                    secrets,
                })
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// DTO-5 核心: blocks 派生 == raw 切片 (全 matrix, 128 cases).
        ///
        /// skip 策略: 仅 reader 拒绝的形态走 prop_assume (生成器产出无效);
        /// "child unexpectedly became root" 属**结构性意外** (prefix 匹配回归 /
        /// 生成器 bug) — 直接 fail, 不静默降级为 skip (防部分掩盖 prefix 回归).
        #[test]
        fn prop_blocks_derivation_matches_raw(case in arb_eq_case()) {
            match eq_run_case(&case) {
                Ok(()) => {}
                Err(e) if e.starts_with("reader rejected") => {
                    proptest::prop_assume!(false, "skip structurally invalid case: {}", e);
                }
                Err(e) => panic!("equivalence violated: {e}"),
            }
        }
    }

    /// 边界 (固定用例): passthrough 节点 (ingress=None) — 新路径空 Vec
    /// (count==0 早退; 生产 passthrough 恒推空 messages, 见 same_proto_passthrough).
    #[test]
    fn blocks_derivation_passthrough_node_returns_empty() {
        let node = fixture_node(0, r#"{"messages":[{"role":"user","content":"x"}]}"#.into());
        let pool = crate::dag::BlockPool::default();
        assert!(extract_delta_messages_from_blocks(&node, &pool).is_empty());
    }

    /// 边界 (固定用例): Responses ingress — wire 无 messages 字段, 新旧路径恒空
    /// (已知限制的等价复刻, DTO-5).
    #[test]
    fn blocks_derivation_responses_ingress_returns_empty() {
        let node = fixture_node(1, r#"{"model":"m","input":[]}"#.into());
        let pool = crate::dag::BlockPool::default();
        assert!(extract_delta_messages_from_blocks(&node, &pool).is_empty());
        // oracle 同样为空 (无 messages 字段).
        assert!(extract_delta_messages_from_raw(&node).is_empty());
    }
}
