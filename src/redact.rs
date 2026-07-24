//! Secret redaction (请求) 与 restoration (响应) 逻辑, 基于 [`crate::codec::ir`] IR.
//!
//! # 设计哲学
//!
//! redact 是 secret-guard 的核心功能: 在请求里把真 secret 替换为 mock (假 secret),
//! 让 LLM 看不到真值; 响应回来时反向 restore, 让本地 agent 看到真值.
//!
//! 历史上 redact 是字节级 find-and-replace. 现在升级为 **IR 变换** (基于 [`crate::codec::ir`]),
//! 与 codec 模块同层, 两者能自然组合 (跨协议翻译 + redact 在同一层 pipeline).
//!
//! # 形式化契约 (mock 生成 + redact pipeline)
//!
//! mock 生成由 [`crate::mock`] 模块负责 (三维度策略), 本模块负责 IR 扫描 + 替换 + restore.
//! 核心契约:
//!
//! - **C1 非空性**: 每个 mock 非空, 满足其 [`crate::mock::GenSpec`] 的 prefix/charset/length.
//! - **C2 上下文唯一性 (in-context uniqueness)**:
//!   `gen_mock_for_ir(ir, secret, allocated)` 返回的 mock 一定**不在** `ir` 中出现
//!   (traverse IR 检查) 且不在 `allocated` 集合中 (C4 保证).
//! - **C3 前缀缓存友好性**: redact 不应无必要地改变 request body 的字节内容, 避免破坏
//!   LLM Provider 侧的前缀缓存命中. 实现手段: per-request seed (单一标量) 驱动整个
//!   redactMap 的 mock 生成. 同一 policy + 同一 messages 上下文 → 同一 seed → 同一
//!   redactMap → mock 在会话全程稳定 (见 [`redact_ir`] 的 seed 语义).
//!
//!   **权衡**: policy 变动 (添加/删除/编辑任一 secret) 会改变 init_seed → 所有 secret 的
//!   mock 全部变化 → 整个会话的前缀缓存失效. 这是 per-request seed 模型 (vs 旧 per-secret
//!   seed) 的代价, 换取了 lazy redact 重建的极简 (node 只存单标量 seed). secret 编辑是
//!   罕见操作, 不在多轮对话热路径上, 实际影响可忽略.
//! - **C4 单射性**: 在一次 [`redact_ir`] 调用内, 不同 secret 总映射到不同 mock
//!   (因为每次 gen_mock_for_ir 都检查 allocated 集合).
//! - **C5 不含 real_secret 子串** (best-effort):
//!   - Auto 模式: mock 由 hash 驱动, 极大概率不含 real_secret 的 ≥4 字符连续子串.
//!     `gen.prefix` (用户自定义或 `[redact] global_mock_prefix` 注入的) 在
//!     [`crate::mock::MockStrategy::validate_against_real`] 中校验不与 real 重叠
//!     (prefix 不出现在 real 中, 也不含 real 的 ≥4 字符子串).
//!   - Fixed 模式: 由 [`crate::mock::MockStrategy::validate_against_real`] 在 upsert 时检查
//!     (char-level windows, 正确处理 multibyte UTF-8 secret).
//!     前提: `SecretTable::upsert` 通过 `validate_value` 拒绝含 `global_mock_prefix` 的 secret
//!     (见 [`crate::secrets::validate_value`]; prefix 为空时此检查跳过).
//!     `proptest-regressions/redact.txt` 记录历史失败种子 (real 全 base62 字母时风险更高).
//! - **C6 可逆性 (restorability)**: round-trip identity —
//!   `restore_ir_response(&mut <redacted IrResponse>, &redact_ir(&mut <IrRequest>, secrets).0)`
//!   后 IR 语义等价于原 IR. (`redact_ir` 原地变异 IrRequest, 返回 `(RedactionMap, seed)`,
//!   `.0` 取 RedactionMap.)
//! - **C7 流式可逆性 (streaming restorability)**:
//!   [`StreamingRestorer`] 在任意 chunk 切分下保证 round-trip identity —
//!   `concat(push(c_1), push(c_2), ..., push(c_n), flush().1)` 严格等于
//!   `content.replace(mock, real)`. UTF-8 安全 (多字节字符不在 char boundary 中间切).
//!
//! # 扫描覆盖范围
//!
//! [`redact_ir`] 扫描以下字段:
//! - `IrRequest::system` (system prompt blocks)
//! - `IrRequest::messages[].content[]` (所有 block 递归, 含 ToolUse input JSON 字符串叶子)
//! - `IrRequest::tools[].{name, description, input_schema}` (工具元数据)
//! - `IrRequest::stop` (stop sequences)
//! - `IrRequest::user` (user id)
//! - `IrRequest.extra` (未建模字段, JSON 字符串叶子)
//!
//! **不扫描**: `IrRequest::model` (模型名不应该是 secret), `IrRequest.tools[].input_schema` 的非字符串叶子
//! (eg JSON Schema 的 type / properties 结构).
//!
//! # 流式 trade-off
//!
//! - **Text block / Text delta**: 必 redact. 流式响应通过 [`StreamingRestorer`] 做 sliding-window
//!   restore (尾部缓冲 N 字节, N = max mock len - 1), 避免跨 chunk mock 丢失 round-trip.
//! - **InputJsonDelta (流式 tool 参数片段)**: 同样走 [`StreamingRestorer`], 与 text 同算法.
//!   per-block 独立状态, 跨 block 互不干扰.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::codec::ir::{IrBlock, IrDelta, IrRequest, IrResponse, IrTool};
use crate::secrets::SecretEntry;

/// 改写映射: real ↔ mock 双向索引.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionMap {
    /// real_secret → mock_secret.
    pub real_to_mock: HashMap<String, String>,
    /// mock_secret → real_secret.
    pub mock_to_real: HashMap<String, String>,
}

impl RedactionMap {
    pub fn is_empty(&self) -> bool {
        self.real_to_mock.is_empty()
    }

    /// 插入映射. 若 mock 已存在但 real 不同 (碰撞), panic.
    /// C4 保证 collision 实际不可能发生 (probing 挽救); 这里是 defense-in-depth.
    pub fn insert(&mut self, real: String, mock: String) {
        if let Some(existing) = self.mock_to_real.get(&mock) {
            assert!(
                existing == &real,
                "mock collision: mock={mock:?} already maps to {existing:?}, attempted {real:?}"
            );
        }
        self.mock_to_real.insert(mock.clone(), real.clone());
        self.real_to_mock.insert(real, mock);
    }

    pub fn mock_for(&self, real: &str) -> Option<&str> {
        self.real_to_mock.get(real).map(|s| s.as_str())
    }

    pub fn real_for(&self, mock: &str) -> Option<&str> {
        self.mock_to_real.get(mock).map(|s| s.as_str())
    }
}

// ─── 内部算法 ──────────────────────────────────────────────────────────────

/// 计算 policy 的 init seed (per-request seed 链的起点).
///
/// 对同一 policy (相同 secrets 集合 + 策略) 总产生同一 init seed →
/// 同一候选序列起点 (C3 前缀缓存友好性的根基).
pub fn init_seed(secrets: &[SecretEntry]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for s in secrets {
        s.value.hash(&mut h);
        s.mock_strategy.hash(&mut h);
    }
    if h.finish() == 0 {
        // 避免与 passthrough sentinel (0) 冲突.
        1
    } else {
        h.finish()
    }
}

/// 在给定 per-request `seed` 下, 为单个 secret 生成候选 mock (不做唯一性检查).
///
/// counter 是 per-secret 的 probing 计数器: 0 是首选, 冲突时递增.
fn candidate_for(secret: &SecretEntry, seed: u64, counter: u32) -> String {
    crate::mock::gen_candidate(&secret.value, &secret.mock_strategy, seed, counter)
}

/// 生成一个在当前 IR 中**未出现**且**未分配过**的 mock.
///
/// per-request seed 模型: 所有 secret 共享同一 seed. counter 是 per-secret 的 probing.
fn gen_mock_for_ir(
    ir: &IrRequest,
    secret: &SecretEntry,
    seed: u64,
    allocated: &HashSet<String>,
) -> String {
    let mut counter: u32 = 0;
    loop {
        let candidate = candidate_for(secret, seed, counter);
        if !ir_request_contains(ir, &candidate) && !allocated.contains(&candidate) {
            return candidate;
        }
        counter += 1;
        if counter > (1u32 << 20) {
            panic!(
                "mock probing exhausted after 2^20 attempts; \
                 ir likely adversarial (real={:?}, strategy={:?})",
                secret.value, secret.mock_strategy
            );
        }
    }
}

// ─── 公开 API: IR 级 redact / restore ─────────────────────────────────────

/// 在 [`IrRequest`] 中查找所有 secret 并替换为 mock.
///
/// per-request seed 模型: 所有 secret 共享一个 seed (整个 redactMap 的候选序列起点)。
/// counter 是 per-secret 的 probing 计数器。返回 `(RedactionMap, seed)`:
/// - seed = 0 表示无 secret 命中 (passthrough), DAG node 存 0.
/// - seed ≠ 0 = init_seed(secrets), DAG node 存它用于 lazy 重建.
///
/// C2 (in-context uniqueness): gen_mock_for_ir 检查 pre-replace IR.
/// C4 (injectivity): allocated 集合保证 mock 互不冲突.
pub fn redact_ir(ir: &mut IrRequest, secrets: &[SecretEntry]) -> (RedactionMap, u64) {
    let mut map = RedactionMap::default();
    if secrets.is_empty() {
        return (map, 0);
    }

    let mut sorted: Vec<&SecretEntry> = secrets.iter().filter(|e| !e.value.is_empty()).collect();
    sorted.sort_by_key(|e| std::cmp::Reverse(e.value.len()));
    sorted.dedup_by(|a, b| a.value == b.value);

    let mut allocated: HashSet<String> = HashSet::new();
    let seed = init_seed(secrets);
    let mut hit_any = false;

    for secret in sorted {
        if !ir_request_contains(ir, &secret.value) {
            continue;
        }
        hit_any = true;
        let mock = gen_mock_for_ir(ir, secret, seed, &allocated);
        ir_request_replace_all(ir, &secret.value, &mock);
        allocated.insert(mock.clone());
        map.insert(secret.value.clone(), mock);
    }

    let final_seed = if hit_any { seed } else { 0 };
    (map, final_seed)
}

/// 在 [`IrResponse`] 中反向替换 mock 为真实 secret.
///
/// 非流式响应的 restore 路径.
pub fn restore_ir_response(ir: &mut IrResponse, map: &RedactionMap) {
    if map.is_empty() {
        return;
    }
    // stop_sequence 可能含 secret (虽然罕见).
    if let Some(s) = &mut ir.stop_sequence {
        restore_str(s, map);
    }
    for block in &mut ir.content {
        restore_block(block, map);
    }
}

// ─── StreamingRestorer: sliding window restore ──────────────────────────────

/// Block delta 类型标识, 让 [`StreamingRestorer`] 在 flush 时能恢复正确的 IrDelta variant.
///
/// 一个 block 的生命周期内 (BlockStart .. BlockStop) delta 类型固定不变,
/// restorer 每次 push 都更新 last_kind, flush 时按 last_kind 包装返回.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaKind {
    Text,
    InputJson,
}

impl DeltaKind {
    pub fn to_ir_delta(self, s: String) -> IrDelta {
        match self {
            DeltaKind::Text => IrDelta::TextDelta(s),
            DeltaKind::InputJson => IrDelta::InputJsonDelta(s),
        }
    }
}

/// Sliding-window mock→real restorer for streaming [`IrStreamEvent`]s.
///
/// # 为什么需要 sliding window
///
/// 流式响应里 mock (如 `MOCKABC123`) 可能跨多个 chunk:
/// ```text
/// event 1 TextDelta: "the secret is MOCKAB"
/// event 2 TextDelta: "C123 end"
/// ```
/// 单 event 不含完整 mock, 直接 [`restore_str_inplace`] 找不到匹配.
/// [`StreamingRestorer`] 在尾部缓冲一定字节, 凑齐完整 mock 再 emit, 保证 round-trip identity.
///
/// # 算法
///
/// 1. push(content) → 与当前 buffer 拼接.
/// 2. 在 combined 中扫描所有 mock, 取最大 `mock_end_byte_offset`.
/// 3. `safe_end = max(mock_end_max, combined.len().saturating_sub(hold))`,
///    `hold = max_mock_len - 1` (防御 mock 跨 chunk).
/// 4. emit `combined[..safe_end]` (restore 后); 保留 `combined[safe_end..]` 进 buffer.
/// 5. [`Self::flush`] 在流/Block 结束时清空 buffer, 对剩余部分做 best-effort restore.
///
/// # Invariant
///
/// - `buffer.len() ≤ hold + 3` (push 后必然 trim; +3 是 UTF-8 char boundary 回退上限).
/// - `max_mock_len` 在构造时锁定 (proxy.rs 保证 redact snapshot 期间 RedactionMap 不变).
/// - 一个 restorer 对应单个 block index, 期间 delta kind 不变 (text 或 input_json 二选一).
///
/// # Scope / Out of scope
///
/// - 处理 [`IrDelta::TextDelta`] 和 [`IrDelta::InputJsonDelta`] (内容字节流).
/// - 不处理 [`IrStreamEvent::MessageDelta::stop_sequence`] / [`IrStreamEvent::Error`]
///   (单 event 完整, 直接 [`restore_str_inplace`]).
#[derive(Debug)]
pub struct StreamingRestorer {
    map: RedactionMap,
    /// 尾部 hold 字节数 = max_mock_len - 1 (防御跨 chunk mock).
    hold: usize,
    /// 当前未 emit 的尾部 buffer.
    buffer: String,
    /// 最后一次 push 的 delta 类型. flush 时按此类型包装返回.
    /// 默认 Text (一个 block 的第一个 push 之前不会有 flush).
    last_kind: DeltaKind,
}

impl StreamingRestorer {
    /// 构造. `map` 为空时所有 push 直接透传 (zero overhead).
    pub fn new(map: RedactionMap) -> Self {
        let max_mock_len = map.mock_to_real.keys().map(|m| m.len()).max().unwrap_or(0);
        Self {
            map,
            hold: max_mock_len.saturating_sub(1),
            buffer: String::new(),
            last_kind: DeltaKind::Text,
        }
    }

    /// 喂入一段 content delta (TextDelta / InputJsonDelta 的字符串部分).
    ///
    /// 返回可以安全 emit 的部分 (mock 已替换为 real).
    /// 末尾 hold 字节保留在 buffer 等下一个 chunk 凑齐.
    pub fn push(&mut self, content: String) -> String {
        if self.map.is_empty() {
            return content;
        }
        let mut combined = std::mem::take(&mut self.buffer);
        combined.push_str(&content);
        let safe_end = self.find_safe_end(&combined);
        // split_off(safe_end) 把 combined 切成 [...safe_end) + [safe_end...).
        // self.buffer 持有 tail, combined 持有 head; 避免 clone + truncate.
        self.buffer = combined.split_off(safe_end);
        restore_str_inplace(&mut combined, &self.map);
        combined
    }

    /// 设置下次 flush 时使用的 delta kind (text / input_json).
    /// 由 StreamTranslate 在每次 BlockDelta 时同步, 确保 flush 返回正确类型.
    pub fn set_kind(&mut self, kind: DeltaKind) {
        self.last_kind = kind;
    }

    /// Block 结束 (BlockStop) 时调用. 若上游异常未发 BlockStop,
    /// 由 caller (StreamTranslate) 在 MessageStop / finish() 时主动调用以避免 mock 尾部泄漏.
    /// 返回 (delta_kind, restored_content).
    pub fn flush(&mut self) -> (DeltaKind, String) {
        let kind = self.last_kind;
        if self.buffer.is_empty() {
            return (kind, String::new());
        }
        let mut remaining = std::mem::take(&mut self.buffer);
        // buffer 非空蕴含 map 非空 (push 在 map 为空时直接返回 content, 从不写 buffer).
        restore_str_inplace(&mut remaining, &self.map);
        (kind, remaining)
    }

    /// 找出 combined 中可以安全 emit 的末尾 offset.
    ///
    /// 规则: max(最后一个 mock 末尾, len - hold).
    /// 保证 mock 不会跨 emit / buffer 边界.
    ///
    /// 特殊: 当 len ≤ hold 时返回 0 (全部 hold), 避免短 chunk 提前 emit mock 前缀.
    ///
    /// UTF-8 安全: 返回值必然落在 char boundary 上 (回退到最近的 boundary).
    /// buffer 不变式从 `≤ hold` 放宽到 `≤ hold + 3` (UTF-8 char 最多 4 字节).
    fn find_safe_end(&self, combined: &str) -> usize {
        let len = combined.len();
        if self.hold == 0 {
            return len;
        }
        if len <= self.hold {
            return 0;
        }
        let mut max_mock_end = 0usize;
        for mock in self.map.mock_to_real.keys() {
            if mock.len() > len {
                continue;
            }
            let mut start = 0usize;
            while let Some(off) = combined[start..].find(mock) {
                let abs = start + off;
                let end = abs + mock.len();
                if end > max_mock_end {
                    max_mock_end = end;
                }
                start = abs + 1;
            }
        }
        let safe_end_lower_by_hold = len - self.hold;
        let mut safe_end = std::cmp::max(max_mock_end, safe_end_lower_by_hold);
        // 回退到最近的 char boundary (mock 全是 ASCII, mock_end 必然在 boundary 上;
        // len - hold 可能在多字节 char 中间, 回退最多 3 字节).
        while safe_end > 0 && !combined.is_char_boundary(safe_end) {
            safe_end -= 1;
        }
        safe_end
    }
}

/// [`restore_str`] 的纯函数版本 (in-place), 复用同一段 find-and-replace 逻辑.
pub(crate) fn restore_str_inplace(s: &mut String, map: &RedactionMap) {
    if map.is_empty() || s.is_empty() {
        return;
    }
    for (mock, real) in &map.mock_to_real {
        if s.contains(mock) {
            *s = s.replace(mock, real);
        }
    }
}

// ─── IR traverse helpers ───────────────────────────────────────────────────

/// IR 中是否出现 needle (在字符串字段中).
///
/// 扫描范围: system blocks / messages.blocks / tools (name+description+input_schema) /
/// IrBlock::ToolUse.{id, name, input} / IrBlock::ToolResult.content (递归) /
/// stop sequences / user / extra (JSON 字符串叶子).
fn ir_request_contains(ir: &IrRequest, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    for block in &ir.system {
        if block_contains(block, needle) {
            return true;
        }
    }
    for msg in &ir.messages {
        for block in &msg.content {
            if block_contains(block, needle) {
                return true;
            }
        }
    }
    for tool in &ir.tools {
        if tool_contains(tool, needle) {
            return true;
        }
    }
    ir.stop.iter().any(|s| s.contains(needle))
        || ir.user.as_ref().is_some_and(|u| u.contains(needle))
        || value_contains(&serde_json::Value::Object(ir.extra.clone()), needle)
}

/// IR 中所有字符串字段把 `from` 全部替换为 `to`.
fn ir_request_replace_all(ir: &mut IrRequest, from: &str, to: &str) {
    if from.is_empty() {
        return;
    }
    for block in &mut ir.system {
        block_replace_all(block, from, to);
    }
    for msg in &mut ir.messages {
        for block in &mut msg.content {
            block_replace_all(block, from, to);
        }
    }
    for tool in &mut ir.tools {
        tool_replace_all(tool, from, to);
    }
    for s in &mut ir.stop {
        replace_in_place(s, from, to);
    }
    if let Some(u) = &mut ir.user {
        replace_in_place(u, from, to);
    }
    // extra 是 Map<String, Value>, 遍历所有 Value 的字符串叶子.
    for v in ir.extra.values_mut() {
        value_replace_all(v, from, to);
    }
}

/// IrBlock 是否含 needle.
fn block_contains(b: &IrBlock, needle: &str) -> bool {
    match b {
        IrBlock::Text { text } => text.contains(needle),
        IrBlock::ToolUse { id, name, input } => {
            id.contains(needle) || name.contains(needle) || value_contains(input, needle)
        }
        IrBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } => tool_use_id.contains(needle) || content.iter().any(|c| block_contains(c, needle)),
        IrBlock::Image { source } => image_source_contains(source, needle),
    }
}

/// IrBlock 字符串字段替换.
fn block_replace_all(b: &mut IrBlock, from: &str, to: &str) {
    match b {
        IrBlock::Text { text } => replace_in_place(text, from, to),
        IrBlock::ToolUse { id, name, input } => {
            replace_in_place(id, from, to);
            replace_in_place(name, from, to);
            value_replace_all(input, from, to);
        }
        IrBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } => {
            replace_in_place(tool_use_id, from, to);
            for c in content.iter_mut() {
                block_replace_all(c, from, to);
            }
        }
        IrBlock::Image { source } => image_source_replace(source, from, to),
    }
}

/// IrBlock 字符串字段 restore (反向 redact).
fn restore_block(b: &mut IrBlock, map: &RedactionMap) {
    match b {
        IrBlock::Text { text } => restore_str(text, map),
        IrBlock::ToolUse { id, name, input } => {
            restore_str(id, map);
            restore_str(name, map);
            value_restore(input, map);
        }
        IrBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } => {
            restore_str(tool_use_id, map);
            for c in content.iter_mut() {
                restore_block(c, map);
            }
        }
        IrBlock::Image { source } => image_source_restore(source, map),
    }
}

/// IrTool 是否含 needle (name / description / input_schema 字符串叶子).
fn tool_contains(tool: &IrTool, needle: &str) -> bool {
    tool.name.contains(needle)
        || tool
            .description
            .as_ref()
            .is_some_and(|d| d.contains(needle))
        || value_contains(&tool.input_schema, needle)
}

/// IrTool 字符串字段替换.
fn tool_replace_all(tool: &mut IrTool, from: &str, to: &str) {
    replace_in_place(&mut tool.name, from, to);
    if let Some(desc) = &mut tool.description {
        replace_in_place(desc, from, to);
    }
    value_replace_all(&mut tool.input_schema, from, to);
}

/// IrImageSource 是否含 needle (仅 URL 形式可能含 ASCII secret; base64 一般不含).
fn image_source_contains(src: &crate::codec::ir::IrImageSource, needle: &str) -> bool {
    match src {
        crate::codec::ir::IrImageSource::Url(u) => u.contains(needle),
        _ => false,
    }
}

/// IrImageSource 字符串字段替换.
fn image_source_replace(src: &mut crate::codec::ir::IrImageSource, from: &str, to: &str) {
    if let crate::codec::ir::IrImageSource::Url(u) = src {
        replace_in_place(u, from, to);
    }
}

/// IrImageSource 字符串字段 restore.
fn image_source_restore(src: &mut crate::codec::ir::IrImageSource, map: &RedactionMap) {
    if let crate::codec::ir::IrImageSource::Url(u) = src {
        restore_str(u, map);
    }
}

/// JSON Value 是否含 needle (仅检查字符串叶子).
fn value_contains(v: &serde_json::Value, needle: &str) -> bool {
    match v {
        serde_json::Value::String(s) => s.contains(needle),
        serde_json::Value::Array(arr) => arr.iter().any(|e| value_contains(e, needle)),
        serde_json::Value::Object(obj) => obj.values().any(|e| value_contains(e, needle)),
        _ => false,
    }
}

/// JSON Value 字符串叶子替换.
fn value_replace_all(v: &mut serde_json::Value, from: &str, to: &str) {
    match v {
        serde_json::Value::String(s) => replace_in_place(s, from, to),
        serde_json::Value::Array(arr) => {
            for e in arr.iter_mut() {
                value_replace_all(e, from, to);
            }
        }
        serde_json::Value::Object(obj) => {
            for e in obj.values_mut() {
                value_replace_all(e, from, to);
            }
        }
        _ => {}
    }
}

/// JSON Value 字符串叶子 restore.
fn value_restore(v: &mut serde_json::Value, map: &RedactionMap) {
    match v {
        serde_json::Value::String(s) => restore_str(s, map),
        serde_json::Value::Array(arr) => {
            for e in arr.iter_mut() {
                value_restore(e, map);
            }
        }
        serde_json::Value::Object(obj) => {
            for e in obj.values_mut() {
                value_restore(e, map);
            }
        }
        _ => {}
    }
}

/// 在 s 中替换所有 from 出现为 to.
fn replace_in_place(s: &mut String, from: &str, to: &str) {
    if from.is_empty() || !s.contains(from) {
        return;
    }
    *s = s.replace(from, to);
}

/// 在 s 中把所有 mock 替换为 real (反向 redact).
fn restore_str(s: &mut String, map: &RedactionMap) {
    restore_str_inplace(s, map);
}

// ─── 测试工具 ──────────────────────────────────────────────────────────────

#[cfg(test)]
fn sample_ir_with_text(text: &str) -> IrRequest {
    use crate::codec::ir::{IrMessage, IrRole};
    IrRequest {
        system: vec![],
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::Text {
                text: text.to_string(),
            }],
        }],
        tools: vec![],
        max_tokens: Some(100),
        model: "test-model".to_string(),
        ..Default::default()
    }
}

#[cfg(test)]
fn sample_ir_response_with_text(text: &str) -> IrResponse {
    IrResponse {
        content: vec![IrBlock::Text {
            text: text.to_string(),
        }],
        ..Default::default()
    }
}

#[cfg(test)]
use crate::secrets::SecretCategory;

#[cfg(test)]
fn entry(value: &str) -> SecretEntry {
    let mut e = SecretEntry {
        id: format!("id-{value}"),
        name: None,
        category: SecretCategory::ApiKey,
        value: value.into(),
        value_file: None,
        mock_strategy: crate::mock::MockStrategy::default(),
    };
    // 测试 helper 模拟生产路径: validate_and_resolve 会调用 resolve_against,
    // 让 Auto 模式的 gen spec 被 infer 出来 (否则 gen_candidate 会 panic).
    // 测试默认场景: 空 global_prefix (Auto 模式 mock 无前缀).
    e.mock_strategy.resolve_against(&e.value, "");
    e
}

/// 预测 redact 对给定 real_secret 生成的首个 mock (counter=0).
///
/// 复用 entry() helper (空 global_prefix) + init_seed + gen_candidate,
/// 与生产 [`redact_ir`] 路径的首次候选一致. 集中"如何预测 mock"知识, 供多个测试复用.
#[cfg(test)]
fn predict_mock(real: &str) -> String {
    let e = entry(real);
    let seed = init_seed(std::slice::from_ref(&e));
    crate::mock::gen_candidate(real, &e.mock_strategy, seed, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ir::{IrMessage, IrResponse, IrRole};
    use pretty_assertions::assert_eq;

    // ─── 契约单元测试 ──────────────────────────────────────────────────────

    #[test]
    fn c1_non_empty() {
        // Auto 模式 (空 global_prefix) 生成的 mock 非空, 仅含 infer 自 real 的字符集.
        let ir = sample_ir_with_text("ctx");
        let mut ir_mut = ir.clone();
        let _ = redact_ir(&mut ir_mut, &[entry("sk-test-123")]);
        let m = predict_mock("sk-test-123");
        assert!(!m.is_empty());
        // 空 prefix + real "sk-test-123" → mock 与 real 等长 (11 chars), charset 来自 real.
        assert_eq!(m.chars().count(), 11);
    }

    #[test]
    fn c2_in_context_uniqueness() {
        // gen_mock_for_ir 生成的 mock 必须不出现在当前 IR 中.
        // 构造 IR 里含一个占位字符串, gen 出的 mock 应该避开它.
        let ir = sample_ir_with_text("placeholder-string-that-must-be-avoided");
        let allocated = HashSet::new();
        let entry = entry("real-secret");
        let seed = init_seed(std::slice::from_ref(&entry));
        let m = gen_mock_for_ir(&ir, &entry, seed, &allocated);
        assert!(
            !ir_request_contains(&ir, &m),
            "gen mock must avoid existing IR content; got {m}"
        );
        assert_ne!(m, "placeholder-string-that-must-be-avoided");
    }

    #[test]
    fn c3_determinism() {
        // gen_candidate 在同一 (real, strategy, seed, counter) 下确定.
        for secret in ["short", "sk-test-123", "a-much-longer-secret-value-XYZ"] {
            let m1 = predict_mock(secret);
            let m2 = predict_mock(secret);
            assert_eq!(m1, m2, "same input must produce same mock for '{secret}'");
        }
    }

    // C3 端到端幂等性.
    //
    // 现有 c3_determinism 只覆盖纯函数层 (predict_mock = init_seed + gen_candidate),
    // 未覆盖生产入口 redact_ir. C3 的本质是 "同一 policy + 同一 IR 上下文 → 同一
    // RedactionMap" (前缀缓存友好性的根基, 见模块头部 C3 契约). redact_ir 内部走
    // candidate_for → mock::gen_candidate (生产路径, 非 legacy), 还涉及 sorted 排序 +
    // allocated probing, 这些环节任一引入非确定性都会破坏 C3. 本测试用端到端双调用 +
    // 全 map 比对锁死该不变量.
    //
    // 场景: 2 个 secret, 分别命中 system prompt 与 user text block (覆盖多条扫描路径),
    // 断言两次 redact_ir 的 (RedactionMap, seed) 完全相等.
    #[test]
    fn c3_redact_ir_end_to_end_idempotent() {
        use crate::codec::ir::IrRequest;
        // 构造一个含 system + user text 的 IR, 让两个 secret 各命中一条扫描路径.
        let build_ir = || IrRequest {
            system: vec![IrBlock::Text {
                text: "system context mentions sk-sys-secret here".to_string(),
            }],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text {
                    text: "user msg embeds sk-user-secret-xyz".to_string(),
                }],
            }],
            ..sample_ir_with_text("")
        };
        let secrets = vec![entry("sk-sys-secret"), entry("sk-user-secret-xyz")];

        let (map1, seed1) = redact_ir(&mut build_ir(), &secrets);
        let (map2, seed2) = redact_ir(&mut build_ir(), &secrets);

        // seed 必须相等 (per-request seed 链起点稳定, C3 根基).
        assert_eq!(seed1, seed2, "init_seed must be stable for same policy");
        // 整个 RedactionMap 必须相等: real→mock 与 mock→real 双向索引逐条一致.
        // 这要求 sorted 顺序 + probing counter 序列 + gen_candidate 全部可复现.
        assert_eq!(
            map1, map2,
            "redact_ir must produce identical RedactionMap for identical (ir, secrets)"
        );
        // 确保测试确实命中了两个 secret (否则 map 为空会让等式平凡成立).
        assert_eq!(
            map1.real_to_mock.len(),
            2,
            "test setup must hit both secrets; got map {:?}",
            map1.real_to_mock
        );
    }

    #[test]
    fn c4_injectivity_within_redact() {
        // 100 个不同 secret, 在同一 redact_ir 内应映射到 100 个不同 mock.
        let secrets: Vec<SecretEntry> = (0..100)
            .map(|i| entry(&format!("secret-value-{i:03}")))
            .collect();
        let body_text = secrets
            .iter()
            .map(|e| e.value.clone())
            .collect::<Vec<_>>()
            .join(" ");
        let mut ir = sample_ir_with_text(&body_text);
        let (map, _) = redact_ir(&mut ir, &secrets);
        let mocks: HashSet<_> = map.real_to_mock.values().cloned().collect();
        assert_eq!(mocks.len(), 100, "all 100 mocks must be distinct");
    }

    #[test]
    fn c5_no_substring_of_real_secret() {
        // mock 不应含 real_secret 的任何 ≥4 字符连续子串 (概率性契约, 见 mock.rs 注释).
        // 空 global_prefix 下, mock 由 hash 驱动, 极小概率碰撞.
        for real in ["sk-test-123", "super-secret-xyz", "ABCDEFGH", "abcdefgh"] {
            let m = predict_mock(real);
            for window in 4..=real.len() {
                for sub in real.as_bytes().windows(window) {
                    let sub_str = std::str::from_utf8(sub).unwrap();
                    assert!(
                        !m.contains(sub_str),
                        "mock '{m}' contains '{sub_str}' from real '{real}' (window={window})"
                    );
                }
            }
        }
    }

    #[test]
    fn c6_round_trip_identity() {
        let text = "auth=sk-test-123; user=alice; token=ABCDEF-1234567890";
        let secrets = vec![entry("sk-test-123"), entry("ABCDEF-1234567890")];
        let mut ir = sample_ir_with_text(text);
        let (map, _) = redact_ir(&mut ir, &secrets);
        // 验证 redact 确实替换了.
        let redacted_text = match &ir.messages[0].content[0] {
            IrBlock::Text { text } => text.clone(),
            _ => panic!("expected Text"),
        };
        assert!(!redacted_text.contains("sk-test-123"));
        assert!(!redacted_text.contains("ABCDEF-1234567890"));
        // restore_ir_response 端到端验证.
        let mut restored_ir = sample_ir_response_with_text(&redacted_text);
        restore_ir_response(&mut restored_ir, &map);
        let restored_text = match &restored_ir.content[0] {
            IrBlock::Text { text } => text.clone(),
            _ => panic!("expected Text"),
        };
        assert_eq!(restored_text, text, "round-trip must restore original text");
    }

    // ─── 行为测试 ──────────────────────────────────────────────────────────

    #[test]
    fn mock_length_matches_real_when_no_prefix() {
        // 空 global_prefix 下, infer 的 mock 长度 == real 长度 (见 GenSpec::infer_default_for).
        for real in ["abcd", "sk-test", "-leading-dash", "longer-secret-value"] {
            let m = predict_mock(real);
            assert_eq!(
                m.chars().count(),
                real.chars().count(),
                "mock '{m}' length must equal real '{real}' (no global prefix)"
            );
        }
    }

    #[test]
    fn redact_ir_replaces_secret_in_text_block() {
        let mut ir = sample_ir_with_text("my key is sk-test-123 ok");
        let secrets = vec![entry("sk-test-123")];
        let (map, _) = redact_ir(&mut ir, &secrets);
        assert_eq!(map.real_to_mock.len(), 1);
        let mock = map.mock_for("sk-test-123").unwrap();
        let redacted_text = match &ir.messages[0].content[0] {
            IrBlock::Text { text } => text.clone(),
            _ => panic!("expected Text block"),
        };
        assert!(redacted_text.contains(mock));
        assert!(!redacted_text.contains("sk-test-123"));
    }

    #[test]
    fn redact_ir_replaces_secret_in_tool_use_input() {
        use serde_json::json;
        let mut ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "search".to_string(),
                    input: json!({"api_key": "sk-secret-value", "other": "text"}),
                }],
            }],
            ..sample_ir_with_text("")
        };
        let (map, _) = redact_ir(&mut ir, &[entry("sk-secret-value")]);
        assert_eq!(map.real_to_mock.len(), 1);
        // input 里的 secret 应被替换.
        match &ir.messages[0].content[0] {
            IrBlock::ToolUse { input, .. } => {
                let s = serde_json::to_string(input).unwrap();
                assert!(!s.contains("sk-secret-value"));
                assert!(s.contains(map.mock_for("sk-secret-value").unwrap()));
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[test]
    fn redact_ir_replaces_secret_in_tool_result_recursively() {
        let mut ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: vec![IrBlock::Text {
                        text: "result with sk-secret".to_string(),
                    }],
                    is_error: false,
                }],
            }],
            ..sample_ir_with_text("")
        };
        let (map, _) = redact_ir(&mut ir, &[entry("sk-secret")]);
        assert_eq!(map.real_to_mock.len(), 1);
        match &ir.messages[0].content[0] {
            IrBlock::ToolResult { content, .. } => match &content[0] {
                IrBlock::Text { text } => assert!(!text.contains("sk-secret")),
                _ => panic!("expected Text"),
            },
            _ => panic!("expected ToolResult"),
        }
    }

    #[test]
    fn redact_ir_replaces_secret_in_system_prompt() {
        use crate::codec::ir::IrRequest;
        let mut ir = IrRequest {
            system: vec![IrBlock::Text {
                text: "system with sk-secret".to_string(),
            }],
            ..sample_ir_with_text("")
        };
        let _ = redact_ir(&mut ir, &[entry("sk-secret")]);
        match &ir.system[0] {
            IrBlock::Text { text } => assert!(!text.contains("sk-secret")),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn redact_ir_longer_secret_wins_overlapping() {
        // 长度倒序: 先替换 AAAAA, 替换后 IR 中无 AAAAA 残留,
        // AAA 在剩余 IR 中找不到, 不进 map.
        let mut ir = sample_ir_with_text("found AAAAA in body");
        let secrets = vec![entry("AAA"), entry("AAAAA")];
        let (map, _) = redact_ir(&mut ir, &secrets);
        assert!(
            !map.real_to_mock.contains_key("AAA"),
            "AAA should not be in map; map = {:?}",
            map.real_to_mock
        );
        assert!(map.real_to_mock.contains_key("AAAAA"));
    }

    #[test]
    fn redact_ir_skips_secret_not_in_ir() {
        let mut ir = sample_ir_with_text("hello world");
        let secrets = vec![entry("not-present")];
        let (map, _) = redact_ir(&mut ir, &secrets);
        assert!(map.is_empty());
    }

    #[test]
    fn redact_ir_dedupes_identical_values() {
        let mut ir = sample_ir_with_text("token: XYZ123");
        // 两个 entry 共享同一 value "XYZ123" 但 id 不同. redact_ir 按 value 去重,
        // 只生成一个 mock (与 map.real_to_mock 的 key 去重语义一致).
        let mut e1 = entry("XYZ123");
        e1.id = "id-1".into();
        let mut e2 = entry("XYZ123");
        e2.id = "id-2".into();
        let secrets = vec![e1, e2];
        let (map, _) = redact_ir(&mut ir, &secrets);
        assert_eq!(map.real_to_mock.len(), 1);
    }

    #[test]
    fn redact_ir_no_secrets_returns_empty_map() {
        let mut ir = sample_ir_with_text("hello");
        let (map, _) = redact_ir(&mut ir, &[]);
        assert!(map.is_empty());
    }

    // ─── restore_ir_response / restore_ir_stream_event ───────────────────

    #[test]
    fn restore_ir_response_swaps_mock_back_to_real() {
        let mut ir = IrResponse {
            content: vec![IrBlock::Text {
                text: "result MOCKABCDEF12345 end".to_string(),
            }],
            ..Default::default()
        };
        let mut map = RedactionMap::default();
        map.insert("sk-real-secret".to_string(), "MOCKABCDEF12345".to_string());
        restore_ir_response(&mut ir, &map);
        match &ir.content[0] {
            IrBlock::Text { text } => {
                assert!(text.contains("sk-real-secret"));
                assert!(!text.contains("MOCKABCDEF12345"));
            }
            _ => panic!("expected Text"),
        }
    }

    // ─── StreamingRestorer ───────────────────────────────────────────────

    use super::StreamingRestorer;

    fn map_with(real: &str, mock: &str) -> RedactionMap {
        let mut m = RedactionMap::default();
        m.insert(real.to_string(), mock.to_string());
        m
    }

    #[test]
    fn restorer_round_trip_on_single_chunk_with_full_mock() {
        let mut r = StreamingRestorer::new(map_with("real-secret", "MOCKABCDEFGHIJK"));
        let content = "the secret is MOCKABCDEFGHIJK padding-padding-padding".to_string();
        let mut emitted = r.push(content.clone());
        emitted.push_str(&r.flush().1);
        assert_eq!(emitted, "the secret is real-secret padding-padding-padding");
    }

    #[test]
    fn restorer_round_trip_on_mock_split_across_chunks() {
        // 核心 contract 的具体落地 (chunk 边界落在 mock 中间).
        // 详细 byte-offset 推理由 prop_streaming_restorer_round_trip 覆盖所有 chunk_size.
        let mut r = StreamingRestorer::new(map_with("real-secret", "MOCKABCDEFGHIJK"));
        let out1 = r.push("the secret is MOCKAB".to_string());
        let out2 = r.push("CDEFGHIJK done".to_string());
        let (_, tail) = r.flush();
        assert_eq!(out1 + &out2 + &tail, "the secret is real-secret done");
    }

    #[test]
    fn restorer_empty_map_is_passthrough() {
        let mut r = StreamingRestorer::new(RedactionMap::default());
        let out = r.push("anything".to_string());
        assert_eq!(out, "anything");
        let (_, tail) = r.flush();
        assert_eq!(tail, "");
    }

    #[test]
    fn restorer_preserves_delta_kind_on_flush() {
        // input_json delta 也应正确 restore, flush 时保留 InputJson kind.
        use super::DeltaKind;
        let mut r = StreamingRestorer::new(map_with("real-token", "MOCKABCDEFGHIJK"));
        r.set_kind(DeltaKind::InputJson);
        // 喂一段长度 ≤ hold 的不完整 mock, 全部进 buffer, push 返回空.
        let out = r.push("MOCKA".to_string()); // 5 字节 < hold=14
        assert!(
            out.is_empty(),
            "push should return empty when all held: {out}"
        );
        let (kind, tail) = r.flush();
        // kind 正确包装为 InputJsonDelta.
        let delta = kind.to_ir_delta(tail.clone());
        assert!(
            matches!(delta, crate::codec::ir::IrDelta::InputJsonDelta(_)),
            "flush should wrap tail as InputJsonDelta"
        );
        // flush 时 best-effort restore, 因 mock 不完整, tail 仍含原始 mock 残段.
        assert!(
            tail.contains("MOCKA"),
            "tail should contain raw mock remnant, got: {tail}"
        );
    }

    #[test]
    fn restorer_round_trip_on_multiple_mocks_in_one_chunk() {
        let mut map = RedactionMap::default();
        map.insert("r1".to_string(), "MOCK11111111111".to_string());
        map.insert("r2".to_string(), "MOCK22222222222".to_string());
        let mut r = StreamingRestorer::new(map);
        let out = r.push("a MOCK11111111111 b MOCK22222222222 c".to_string());
        let (_, tail) = r.flush();
        assert_eq!(out + &tail, "a r1 b r2 c");
    }

    #[test]
    fn restorer_caps_buffer_at_hold_when_no_mock_in_chunk() {
        // 无 mock 时尾部仍 hold (防下个 chunk 携带 mock 前缀).
        // buffer ≤ hold + 3 (UTF-8 char boundary 回退最多 3 字节, 见 find_safe_end).
        let mut r = StreamingRestorer::new(map_with("r", "MOCKABCDEFGHIJK")); // hold = 14
        let chunk = "hello world, this is a long chunk";
        let out = r.push(chunk.to_string());
        let (_, tail) = r.flush();
        assert_eq!(out + &tail, chunk);
        assert!(tail.len() <= 14 + 3, "buffer ≤ hold+3: got {}", tail.len());
    }

    // ─── property-based 测试 (proptest) ─────────────────────────────────────
    use proptest::prelude::*;

    /// 把 full 切成 chunk_size 字节片喂给 r, 返回 emit + flush 拼接结果.
    /// boundary_align=true 时把 chunk 末尾对齐到 char boundary (UTF-8 测试用).
    fn push_chunked(
        r: &mut StreamingRestorer,
        full: &str,
        chunk_size: usize,
        boundary_align: bool,
    ) -> String {
        let bytes = full.as_bytes();
        let mut emitted = String::new();
        let mut i = 0;
        while i < bytes.len() {
            let mut end = (i + chunk_size).min(bytes.len());
            if boundary_align {
                while end < bytes.len() && !full.is_char_boundary(end) {
                    end += 1;
                }
            }
            let piece = std::str::from_utf8(&bytes[i..end]).unwrap().to_string();
            emitted.push_str(&r.push(piece));
            i = end;
        }
        emitted.push_str(&r.flush().1);
        emitted
    }

    proptest! {
        /// C3 + C4: 不同 secret 总产生不同 mock.
        #[test]
        fn prop_distinct_secrets_distinct_mocks(
            s1 in "[a-z]{4,12}",
            s2 in "[a-z]{4,12}"
        ) {
            prop_assume!(s1 != s2);
            // 在同一个空 IR 上, 两个 secret 应映射到不同 mock.
            let mut ir = sample_ir_with_text(&format!("{s1} {s2}"));
            let (map, _) = redact_ir(&mut ir, &[entry(&s1), entry(&s2)]);
            let m1 = map.mock_for(&s1).unwrap();
            let m2 = map.mock_for(&s2).unwrap();
            prop_assert!(m1 != m2, "mocks for distinct secrets collided: {} == {}", m1, m2);
        }

        /// C2: mock 不在 IR 中 (redact 后的 IR 不含 mock 作为子串 — wait, 它含, 因为替换进去了).
        /// 真正的 C2: gen_mock_for_ir 生成的 mock 在生成那一刻不在 IR 中.
        #[test]
        fn prop_mock_not_in_pre_redact_ir(
            secret in "[a-z0-9]{4,16}",
            filler in "[a-z0-9 ]{0,100}"
        ) {
            let body = format!("{filler} {secret} {filler}");
            let ir = sample_ir_with_text(&body);
            // gen_mock_for_ir 内部: 候选 mock 不在 ir 中.
            let allocated = HashSet::new();
            let entry = entry(&secret);
            let seed = init_seed(std::slice::from_ref(&entry));
            let m = gen_mock_for_ir(&ir, &entry, seed, &allocated);
            prop_assert!(!ir_request_contains(&ir, &m),
                "mock must not appear in pre-redact IR: mock={}", m);
        }

        /// C6: round-trip 是 identity (redact + restore).
        #[test]
        fn prop_round_trip_identity(
            body_prefix in "[a-z0-9 ,.!?'\"\n]{0,100}",
            secret in "[A-Z]{4,12}",
            body_suffix in "[a-z0-9 ,.!?'\"\n]{0,100}"
        ) {
            let body = format!("{body_prefix}{secret}{body_suffix}");
            let mut ir = sample_ir_with_text(&body);
            let original_text = body.clone();
            let (map, _) = redact_ir(&mut ir, &[entry(&secret)]);
            // 取 redact 后的 text.
            let redacted_text = match &ir.messages[0].content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            // restore.
            let mut restored = redacted_text;
            for (mock, real) in &map.mock_to_real {
                if restored.contains(mock) {
                    restored = restored.replace(mock, real);
                }
            }
            prop_assert_eq!(restored, original_text);
        }

        /// C1: mock 非空. 字符集由 infer 自 real (此处含字母数字与连字符).
        #[test]
        fn prop_mock_non_empty(
            secret in "[A-Za-z0-9-]{4,20}"
        ) {
            let m = predict_mock(&secret);
            prop_assert!(!m.is_empty());
        }

        /// C5: mock 不含 real_secret 的 ≥4 字符子串 (概率性契约).
        #[test]
        fn prop_no_real_substring(
            secret in "[A-Za-z0-9]{8,20}"
        ) {
            let m = predict_mock(&secret);
            for window in 4..=secret.len() {
                for sub in secret.as_bytes().windows(window) {
                    let sub_str = std::str::from_utf8(sub).unwrap();
                    prop_assert!(!m.contains(sub_str),
                        "mock contains substring from secret: mock={}, sub={}", m, sub_str);
                }
            }
        }

        /// C6 多 secret round-trip: N 个 secret 同时出现在 IR, restore 后严格等于原 IR.
        #[test]
        fn prop_multi_secret_round_trip(
            n in 1usize..10,
            prefix in "[a-z]{0,30}",
            suffix in "[a-z]{0,30}"
        ) {
            let secrets: Vec<SecretEntry> = (0..n)
                .map(|i| entry(&format!("SECRET_{:03}", i)))
                .collect();
            let body = format!(
                "{prefix}{}{suffix}",
                secrets.iter().map(|s| s.value.as_str()).collect::<Vec<_>>().join(" /// ")
            );
            let mut ir = sample_ir_with_text(&body);
            let original = body.clone();
            let (map, _) = redact_ir(&mut ir, &secrets);
            let mut redacted_text = match &ir.messages[0].content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            for (mock, real) in &map.mock_to_real {
                if redacted_text.contains(mock) {
                    redacted_text = redacted_text.replace(mock, real);
                }
            }
            prop_assert_eq!(redacted_text, original);
        }

        /// C6 同一 secret 多次出现: round-trip 仍为 identity.
        #[test]
        fn prop_repeated_secret_round_trip(
            secret in "[A-Z]{4,8}",
            repeat in 1usize..5,
            filler in "[a-z ]{0,30}"
        ) {
            let body = std::iter::repeat_n(secret.clone(), repeat)
                .collect::<Vec<_>>()
                .join(&filler);
            let mut ir = sample_ir_with_text(&body);
            let original = body.clone();
            let (map, _) = redact_ir(&mut ir, &[entry(&secret)]);
            let mut redacted_text = match &ir.messages[0].content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            for (mock, real) in &map.mock_to_real {
                if redacted_text.contains(mock) {
                    redacted_text = redacted_text.replace(mock, real);
                }
            }
            prop_assert_eq!(redacted_text, original);
        }

        /// C4 加强版: N 个不同 secret → N 个不同 mock.
        #[test]
        fn prop_redact_produces_distinct_mocks(
            n in 2usize..20
        ) {
            let secrets: Vec<SecretEntry> = (0..n)
                .map(|i| entry(&format!("secret-{:03}", i)))
                .collect();
            let body = secrets.iter().map(|e| e.value.clone()).collect::<Vec<_>>().join(" ");
            let mut ir = sample_ir_with_text(&body);
            let (map, _) = redact_ir(&mut ir, &secrets);
            let mocks: HashSet<_> = map.real_to_mock.values().collect();
            prop_assert_eq!(mocks.len(), n);
        }

        /// StreamingRestorer 核心 contract: 把含 mock 的文本切成任意 chunk_size, 拼接
        /// emit + flush 必须严格等于 (prefix + real + suffix).
        #[test]
        fn prop_streaming_restorer_round_trip(
            prefix in "[a-z ]{0,50}",
            suffix in "[a-z ]{0,50}",
            chunk_size in 1usize..30,
        ) {
            let real = "SECRETVALUE";
            let mock = "MOCKABCDEFGHIJK"; // 15 字节, 与 real 等价映射
            let mut map = RedactionMap::default();
            map.insert(real.to_string(), mock.to_string());

            let full = format!("{prefix}{mock}{suffix}");
            let mut r = StreamingRestorer::new(map);
            let emitted = push_chunked(&mut r, &full, chunk_size, false);

            let expected = format!("{prefix}{real}{suffix}");
            prop_assert_eq!(emitted, expected);
        }

        /// UTF-8 safety: 多字节字符 (中文 / emoji) 不应在 char boundary 中间被切.
        /// mock 仍是 ASCII, 但 prefix/suffix 含多字节 UTF-8.
        #[test]
        fn prop_streaming_restorer_round_trip_utf8(
            prefix in "[\\x{4e00}-\\x{9fff}]{0,30}",  // 中文
            suffix in "[\\x{4e00}-\\x{9fff}]{0,30}",
            chunk_size in 1usize..=50,
        ) {
            let real = "SECRETVALUE";
            let mock = "MOCKABCDEFGHIJK";
            let mut map = RedactionMap::default();
            map.insert(real.to_string(), mock.to_string());

            let full = format!("{prefix}{mock}{suffix}");
            let mut r = StreamingRestorer::new(map);
            let emitted = push_chunked(&mut r, &full, chunk_size, true);

            let expected = format!("{prefix}{real}{suffix}");
            prop_assert_eq!(emitted, expected);
        }

        /// Multi-mock 场景: 多个 mock 同时出现在 content 中, 任意 chunk 切分下都正确 round-trip.
        /// 覆盖 mock self-overlap / nested mock 等边缘情况.
        #[test]
        fn prop_streaming_restorer_round_trip_multi_mock(
            filler in "[a-z ]{0,30}",
            chunk_size in 1usize..=50,
        ) {
            let real1 = "R1";
            let real2 = "R2";
            let mock1 = "MOCK11111111111"; // 15 字节
            let mock2 = "MOCK22222222222";
            let mut map = RedactionMap::default();
            map.insert(real1.to_string(), mock1.to_string());
            map.insert(real2.to_string(), mock2.to_string());

            // full 含两个 mock + filler (可能相邻 / 嵌套 / 被 filler 分隔).
            let full = format!("{filler}{mock1}{filler}{mock2}{filler}");
            let mut r = StreamingRestorer::new(map);
            let emitted = push_chunked(&mut r, &full, chunk_size, false);

            let expected = format!("{filler}{real1}{filler}{real2}{filler}");
            prop_assert_eq!(emitted, expected);
        }

        /// C3 端到端幂等性 (property 版): 对任意 (prefix, suffix, secret) 组合,
        /// 同一 IR + 同一 policy 的两次 redact_ir 调用必须产出逐字段相等的
        /// RedactionMap 与相等的 seed. 现有 c3_determinism 只覆盖纯函数层
        /// (predict_mock), prop_distinct_secrets_distinct_mocks 只比对 mock 是否两两
        /// 不同, 两者都未锁死 "整张 map 可复现" 这一 C3 核心不变量.
        #[test]
        fn prop_c3_redact_ir_idempotent(
            secret in "[A-Za-z0-9]{4,16}",
            filler in "[a-z0-9 ]{0,60}",
        ) {
            let body = format!("{filler} {secret} {filler}");
            let secrets = vec![entry(&secret)];
            // 两次独立 redact_ir: 重建 IR 以避免前一次原地变异影响.
            let (map1, seed1) = redact_ir(&mut sample_ir_with_text(&body), &secrets);
            let (map2, seed2) = redact_ir(&mut sample_ir_with_text(&body), &secrets);
            prop_assert_eq!(seed1, seed2, "init_seed must be stable");
            // 防平凡: secret 必须命中进 map (在全 map 比对前检查, 避免 prop_assert_eq! 消费 map1).
            prop_assert!(map1.mock_for(&secret).is_some(), "secret must be redacted");
            prop_assert_eq!(
                map1, map2,
                "redact_ir must produce identical RedactionMap for identical (ir, secrets)"
            );
        }

        /// C5 生产路径 (property 版, 端到端): redact_ir 产出的 mock 不含 real 的任何
        /// ≥4 字符连续子串. 现有 prop_no_real_substring 用 predict_mock (纯函数) 验证,
        /// 但生产路径在 mock 已出现在 IR 时会 probing 到 counter>0 候选, 该路径下的 C5
        /// 行为未被覆盖. 本测试走完整 redact_ir, 覆盖 probing 路径.
        ///
        /// 注: 这是 best-effort 概率性契约 (见模块头部 C5 + mock.rs 头部).
        /// 输入限定为高基数字母表 [A-Za-z0-9] (典型 secret 形态), 实测碰撞率 ≈ 0.
        /// 极低基数 real (如仅 2 个不同字符) 是已知 C5 边界, 不在本测试范围
        /// (历史 regression 见 proptest-regressions/redact.txt).
        #[test]
        fn prop_c5_redact_mock_no_real_substring_end_to_end(
            secret in "[A-Za-z0-9]{8,20}",
            filler in "[a-z0-9 ]{0,40}",
        ) {
            let body = format!("{filler} {secret} {filler}");
            let mut ir = sample_ir_with_text(&body);
            let (map, _) = redact_ir(&mut ir, &[entry(&secret)]);
            let mock = map.mock_for(&secret).expect("secret must be redacted");
            // char-level windows (正确处理 multibyte; 此处虽全 ASCII 仍保持一致风格).
            let needle_chars: Vec<char> = secret.chars().collect();
            for w in needle_chars.windows(4) {
                let sub: String = w.iter().collect();
                prop_assert!(
                    !mock.contains(&sub),
                    "mock {:?} contains real ≥4-char substring {:?} (secret={:?})",
                    mock, sub, secret
                );
            }
        }
    }
}
