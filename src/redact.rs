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
//! # 形式化契约 (mock_with_salt 算法)
//!
//! [`mock_with_salt`] 满足:
//!
//! - **C1 非空性**: 返回的 mock 非空, 长度 = `MOCK_PREFIX.len() + MOCK_BODY_LEN`,
//!   仅含 ASCII 字母数字 + 下划线.
//! - **C2 上下文唯一性 (in-context uniqueness)**:
//!   `gen_mock_for_ir(ir, secret, allocated)` 返回的 mock 一定**不在** `ir` 中出现
//!   (traverse IR 检查) 且不在 `allocated` 集合中 (C4 保证).
//! - **C3 确定性 (determinism)**: 同一 `(real, salt)` 对总返回同一 mock.
//! - **C4 单射性**: 在一次 [`redact_ir`] 调用内, 不同 secret 总映射到不同 mock
//!   (因为每次 gen_mock_for_ir 都检查 allocated 集合).
//! - **C5 不含 real_secret 子串** (best-effort): mock 极大概率不含 real_secret 的 ≥4 字符
//!   连续子串 (取决于 SipHash 输出, 碰撞概率 ≈ 2^-32 per secret).
//!   `proptest-regressions/redact.txt` 记录历史失败种子 (real 全 base62 字母时风险更高).
//!   前提: `SecretTable::upsert` 通过 `validate_value` 拒绝含 `MOCK_PREFIX` ("sgm_") 的 secret.
//! - **C6 可逆性 (restorability)**: round-trip identity —
//!   `restore_ir_response(redact_ir(...).ir, map)` 后 IR 语义等价于原 IR.
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
//! - **Text block / Text delta**: 必 redact.
//! - **InputJsonDelta (流式 tool 参数片段)**: 跳过 (MVP). 跨 chunk 的 secret 会泄漏.
//!   未来用 sliding window 缓冲尾部 N 字节 (N = max secret length) 解决.
//!   TODO(b/secret-guard#redact-streaming): 实现 InputJsonDelta 的 sliding window restore.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

use crate::codec::ir::{IrBlock, IrDelta, IrRequest, IrResponse, IrStreamEvent, IrTool};
use crate::secrets::SecretEntry;

/// mock 的固定 prefix. 与 real_secret 无关, 是 C5 (no-real-substring) 的关键.
pub const MOCK_PREFIX: &str = "sgm_";

/// mock 的 body 长度 (base62 编码 u64 的固定长度, 范围 ~10^19 ≈ 2^63).
pub const MOCK_BODY_LEN: usize = 11;

/// 改写映射: real ↔ mock 双向索引.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

/// 64-bit hash (Rust 默认 SipHash 1-2-3, 同 Rust 版本内确定).
fn hash64(s: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// base62 编码 u64 → 固定长度字符串.
fn base62_fixed(n: u64) -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    debug_assert_eq!(CHARS.len(), 62);
    let mut buf = [b'0'; MOCK_BODY_LEN];
    let mut n = n;
    for i in (0..MOCK_BODY_LEN).rev() {
        buf[i] = CHARS[(n % 62) as usize];
        n /= 62;
    }
    String::from_utf8(buf.to_vec()).expect("base62 output is ASCII")
}

/// 给 real + salt 生成一个 mock 候选 (不做唯一性检查).
/// salt = 0 是默认 hash; salt > 0 用于 collision probing.
///
/// 公开 (`pub`) 让集成测试可以预测预期 mock 值; 生产代码不应直接调用.
pub fn mock_with_salt(real: &str, salt: u64) -> String {
    let hash_input = if salt == 0 {
        real.to_string()
    } else {
        format!("{real}{salt}")
    };
    format!("{MOCK_PREFIX}{}", base62_fixed(hash64(&hash_input)))
}

/// 生成一个在当前 IR 中**未出现**且**未分配过**的 mock.
///
/// C2 (in-context uniqueness): traverse IR 检查候选 mock 是否出现.
/// C4 (injectivity): 检查 `allocated` 集合避免重复分配.
///
/// probing 直到找到合格候选, 几乎总是 1 次 (hash 空间 2^64 远大于 IR 字符串数).
fn gen_mock_for_ir(ir: &IrRequest, real: &str, allocated: &HashSet<String>) -> String {
    let mut salt: u64 = 0;
    loop {
        let candidate = mock_with_salt(real, salt);
        if !ir_request_contains(ir, &candidate) && !allocated.contains(&candidate) {
            return candidate;
        }
        salt += 1;
        if salt > (1u64 << 32) {
            panic!(
                "mock probing exhausted after 2^32 attempts; \
                 ir likely adversarial (real={real:?})"
            );
        }
    }
}

// ─── 公开 API: IR 级 redact / restore ─────────────────────────────────────

/// 在 [`IrRequest`] 中查找所有 secret 并替换为 mock.
///
/// 实现:
/// 1. 按 secret 长度倒序排序, 先替换长的 (避免短的先替换导致长的部分被破坏).
/// 2. 对每个在 IR 中出现的 secret, 生成不冲突的 mock (内部 traverse IR 检查唯一性).
/// 3. 替换 IR 中所有字符串字段里的 secret 出现.
///
/// 返回 [`RedactionMap`] 用于响应 restore.
///
/// 复杂度: O(secrets × ir_size). MVP 阶段 secrets 数量 <100, IR 字符串总量 <1 MiB, 可接受.
pub fn redact_ir(ir: &mut IrRequest, secrets: &[SecretEntry]) -> RedactionMap {
    let mut map = RedactionMap::default();
    if secrets.is_empty() {
        return map;
    }

    // 按 value 长度倒序 + 去重 + 过滤空.
    let mut sorted: Vec<&str> = secrets
        .iter()
        .map(|e| e.value.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));
    sorted.dedup();

    let mut allocated: HashSet<String> = HashSet::new();

    for secret in sorted {
        if !ir_request_contains(ir, secret) {
            continue;
        }
        let mock = gen_mock_for_ir(ir, secret, &allocated);
        ir_request_replace_all(ir, secret, &mock);
        allocated.insert(mock.clone());
        map.insert(secret.to_string(), mock);
    }
    map
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

/// 在单个 [`IrStreamEvent`] 中反向替换 mock 为真实 secret.
///
/// 流式响应的 per-event restore 路径.
///
/// # 处理的事件类型
/// - `BlockDelta { TextDelta(s) }`: 完整 redact (核心场景).
/// - `BlockDelta { InputJsonDelta(s) }`: **跳过 + warn** (MVP). 跨 chunk secret 会泄漏.
///   TODO: 用 sliding window 缓冲尾部 N 字节解决.
/// - `MessageDelta { stop_sequence, .. }`: restore (与 `restore_ir_response` 行为一致).
/// - `MessageStart` / `BlockStart` / `BlockStop` / `MessageStop`:
///   不含 secret-carrying 字段, no-op.
/// - `Error(s)`: error message 一般不含 secret, 但保守起见仍 restore.
pub fn restore_ir_stream_event(ev: &mut IrStreamEvent, map: &RedactionMap) {
    if map.is_empty() {
        return;
    }
    match ev {
        IrStreamEvent::BlockDelta {
            delta: IrDelta::TextDelta(s),
            ..
        } => restore_str(s, map),
        IrStreamEvent::BlockDelta {
            delta: IrDelta::InputJsonDelta(_),
            ..
        } => {
            // MVP: 跳过. 见模块 doc 中的 TODO.
        }
        IrStreamEvent::MessageDelta {
            stop_sequence: Some(s),
            ..
        } => restore_str(s, map),
        IrStreamEvent::Error(msg) => restore_str(msg, map),
        _ => {}
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
    if map.is_empty() || s.is_empty() {
        return;
    }
    for (mock, real) in &map.mock_to_real {
        if s.contains(mock) {
            *s = s.replace(mock, real);
        }
    }
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
    SecretEntry {
        id: format!("id-{value}"),
        name: None,
        category: SecretCategory::ApiKey,
        value: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ir::{IrDelta, IrMessage, IrResponse, IrRole, IrStreamEvent};
    use pretty_assertions::assert_eq;

    // ─── 契约单元测试 ──────────────────────────────────────────────────────

    #[test]
    fn c1_non_empty() {
        let ir = sample_ir_with_text("ctx");
        let mut ir_mut = ir.clone();
        let _ = redact_ir(&mut ir_mut, &[entry("sk-test-123")]);
        // mock 形式由 gen_mock_for_ir 保证; 直接验证 mock_with_salt 的形式.
        let m = mock_with_salt("sk-test-123", 0);
        assert!(!m.is_empty());
        assert!(m.starts_with(MOCK_PREFIX));
        assert!(
            m.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "mock '{m}' must be ASCII alphanumeric + underscore"
        );
        assert_eq!(m.len(), MOCK_PREFIX.len() + MOCK_BODY_LEN);
    }

    #[test]
    fn c2_in_context_uniqueness() {
        // gen_mock_for_ir 生成的 mock 必须不出现在当前 IR 中.
        // 构造 IR 里含一个 mock-shaped 字符串, gen 出的 mock 应该避开它.
        let ir = sample_ir_with_text("sgm_AAAAAAAAAAAAA");
        let allocated = HashSet::new();
        let m = gen_mock_for_ir(&ir, "real-secret", &allocated);
        assert!(
            !ir_request_contains(&ir, &m),
            "gen mock must avoid existing IR content; got {m}"
        );
        assert_ne!(m, "sgm_AAAAAAAAAAAAA");
    }

    #[test]
    fn c3_determinism() {
        for secret in ["short", "sk-test-123", "a-much-longer-secret-value-XYZ"] {
            let m1 = mock_with_salt(secret, 0);
            let m2 = mock_with_salt(secret, 0);
            assert_eq!(m1, m2, "same input must produce same mock for '{secret}'");
        }
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
        let map = redact_ir(&mut ir, &secrets);
        let mocks: HashSet<_> = map.real_to_mock.values().cloned().collect();
        assert_eq!(mocks.len(), 100, "all 100 mocks must be distinct");
    }

    #[test]
    fn c5_no_substring_of_real_secret() {
        // mock 不应含 real_secret 的任何 ≥4 字符连续子串.
        // 前提: real_secret 不含 MOCK_PREFIX (validate_value 已强制).
        for real in ["sk-test-123", "super-secret-xyz", "ABCDEFGH", "abcdefgh"] {
            assert!(
                !real.contains(MOCK_PREFIX),
                "test fixture '{real}' should be rejected by validate_value"
            );
            let m = mock_with_salt(real, 0);
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
        let map = redact_ir(&mut ir, &secrets);
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
    fn mock_has_fixed_prefix_and_length() {
        for real in ["abcd", "sk-test", "-leading-dash", "longer-secret-value"] {
            let m = mock_with_salt(real, 0);
            assert!(
                m.starts_with(MOCK_PREFIX),
                "mock '{m}' must start with '{MOCK_PREFIX}'"
            );
            assert_eq!(
                m.len(),
                MOCK_PREFIX.len() + MOCK_BODY_LEN,
                "mock '{m}' must have fixed length"
            );
        }
    }

    #[test]
    fn redact_ir_replaces_secret_in_text_block() {
        let mut ir = sample_ir_with_text("my key is sk-test-123 ok");
        let secrets = vec![entry("sk-test-123")];
        let map = redact_ir(&mut ir, &secrets);
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
        let map = redact_ir(&mut ir, &[entry("sk-secret-value")]);
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
        let map = redact_ir(&mut ir, &[entry("sk-secret")]);
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
        let map = redact_ir(&mut ir, &secrets);
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
        let map = redact_ir(&mut ir, &secrets);
        assert!(map.is_empty());
    }

    #[test]
    fn redact_ir_dedupes_identical_values() {
        let mut ir = sample_ir_with_text("token: XYZ123");
        let secrets = vec![
            SecretEntry {
                id: "id-1".into(),
                name: None,
                category: SecretCategory::ApiKey,
                value: "XYZ123".into(),
            },
            SecretEntry {
                id: "id-2".into(),
                name: None,
                category: SecretCategory::ApiKey,
                value: "XYZ123".into(),
            },
        ];
        let map = redact_ir(&mut ir, &secrets);
        assert_eq!(map.real_to_mock.len(), 1);
    }

    #[test]
    fn redact_ir_no_secrets_returns_empty_map() {
        let mut ir = sample_ir_with_text("hello");
        let map = redact_ir(&mut ir, &[]);
        assert!(map.is_empty());
    }

    // ─── restore_ir_response / restore_ir_stream_event ───────────────────

    #[test]
    fn restore_ir_response_swaps_mock_back_to_real() {
        let mut ir = IrResponse {
            content: vec![IrBlock::Text {
                text: "result sgm_ABCDEF12345 end".to_string(),
            }],
            ..Default::default()
        };
        let mut map = RedactionMap::default();
        map.insert("sk-real-secret".to_string(), "sgm_ABCDEF12345".to_string());
        restore_ir_response(&mut ir, &map);
        match &ir.content[0] {
            IrBlock::Text { text } => {
                assert!(text.contains("sk-real-secret"));
                assert!(!text.contains("sgm_ABCDEF12345"));
            }
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn restore_ir_stream_event_handles_text_delta() {
        let mut ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::TextDelta("chunk sgm_XYZ987 end".to_string()),
        };
        let mut map = RedactionMap::default();
        map.insert("real-token".to_string(), "sgm_XYZ987".to_string());
        restore_ir_stream_event(&mut ev, &map);
        match ev {
            IrStreamEvent::BlockDelta {
                delta: IrDelta::TextDelta(s),
                ..
            } => {
                assert!(s.contains("real-token"));
                assert!(!s.contains("sgm_XYZ987"));
            }
            _ => panic!("unexpected event"),
        }
    }

    #[test]
    fn restore_ir_stream_event_skips_input_json_delta() {
        // MVP: InputJsonDelta 不 restore (跨 chunk secret 处理留给 sliding window).
        let mut ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::InputJsonDelta(r#"{"key":"sgm_XYZ987"}"#.to_string()),
        };
        let mut map = RedactionMap::default();
        map.insert("real-token".to_string(), "sgm_XYZ987".to_string());
        restore_ir_stream_event(&mut ev, &map);
        match ev {
            IrStreamEvent::BlockDelta {
                delta: IrDelta::InputJsonDelta(s),
                ..
            } => {
                // 没被 restore, 仍含 mock.
                assert!(s.contains("sgm_XYZ987"));
            }
            _ => panic!("unexpected event"),
        }
    }

    #[test]
    fn restore_ir_stream_event_empty_map_is_noop() {
        let mut ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::TextDelta("hello".to_string()),
        };
        let map = RedactionMap::default();
        restore_ir_stream_event(&mut ev, &map);
        match ev {
            IrStreamEvent::BlockDelta {
                delta: IrDelta::TextDelta(s),
                ..
            } => assert_eq!(s, "hello"),
            _ => panic!("unexpected event"),
        }
    }

    // ─── property-based 测试 (proptest) ─────────────────────────────────────

    use proptest::prelude::*;

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
            let map = redact_ir(&mut ir, &[entry(&s1), entry(&s2)]);
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
            let m = gen_mock_for_ir(&ir, &secret, &allocated);
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
            let map = redact_ir(&mut ir, &[entry(&secret)]);
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

        /// C1: mock 非空且仅含 ASCII 字母数字 + 下划线.
        #[test]
        fn prop_mock_alphanumeric(
            secret in "[A-Za-z0-9-]{4,20}"
        ) {
            let m = mock_with_salt(&secret, 0);
            prop_assert!(!m.is_empty());
            prop_assert!(m.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        }

        /// C5: mock 不含 real_secret 的 ≥4 字符子串.
        #[test]
        fn prop_no_real_substring(
            secret in "[A-Za-z0-9]{8,20}"
        ) {
            prop_assume!(!secret.contains(MOCK_PREFIX));
            let m = mock_with_salt(&secret, 0);
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
            let map = redact_ir(&mut ir, &secrets);
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
            let map = redact_ir(&mut ir, &[entry(&secret)]);
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
            let map = redact_ir(&mut ir, &secrets);
            let mocks: HashSet<_> = map.real_to_mock.values().collect();
            prop_assert_eq!(mocks.len(), n);
        }
    }
}
