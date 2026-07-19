//! Secret redaction (请求) 与 restoration (响应) 逻辑.
//!
//! # 第四步实现说明 (naive)
//! - [`mock_secret`] 是基于 `real_secret` 哈希的纯函数, 输出单个 Unicode 私有区字符
//!   (U+E000..=U+F8FF, 6400 个码位). 通过 `full_context` 做线性探测避免与上下文已有字符冲突.
//! - 碰撞风险: 6400 个码位理论上不够大, 不同 real_secret 可能映射到同一 mock.
//!   第五步会用更精细的方案消除碰撞, 并给出契约与正确性证明.
//!
//! # 流式 trade-off
//! 当前实现对**非流式响应**直接做 restore; 对**流式响应**也采用 "完整累积再 restore" 策略
//! (失去流式 UX, 但保证 mock→real 映射正确, 避免 chunk 边界问题).
//! 第五步会引入 chunk boundary 处理恢复流式.

use std::cmp::Reverse;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

use crate::secrets::SecretEntry;

/// Unicode 私有区 (BMP PUA) 范围. 6400 个码位.
const PUA_START: u32 = 0xE000;
const PUA_END: u32 = 0xF8FF; // inclusive
const PUA_LEN: u32 = PUA_END - PUA_START + 1; // 0x1900

/// 生成一个 mock secret.
///
/// 契约 (第四步 naive 版本):
/// 1. **确定性**: 同样的 `(real_secret)` 在同一进程内 (DefaultHasher 是稳定的)
///    产生同样的起始码位.
/// 2. **上下文唯一性**: 若起始码位已出现在 `full_context` 中, 线性探测下一个,
///    保证返回的 mock 在 `full_context` 中**不在场**.
/// 3. **非空性**: 返回的字符串总是单个合法 Unicode 字符 (UTF-8 3 bytes).
///
/// 不变式 (第五步会更强):
/// - 仍有**全局碰撞风险**: 不同 `real_secret` 在同一 `full_context` 下可能产生相同 mock.
///   这是因为 codepoint 空间 (6400) 远小于 secret 空间.
pub fn mock_secret(full_context: &str, real_secret: &str) -> String {
    if real_secret.is_empty() {
        // 空字符串不是合法 secret; 返回 PUA 起始作为兜底.
        return char::from_u32(PUA_START).unwrap().to_string();
    }
    let mut hasher = DefaultHasher::new();
    real_secret.hash(&mut hasher);
    let base = hasher.finish();
    let mut codepoint = PUA_START + ((base % PUA_LEN as u64) as u32);
    // 线性探测: 找一个不在 full_context 中的码位.
    for _ in 0..PUA_LEN {
        if let Some(c) = char::from_u32(codepoint) {
            let s = c.to_string();
            if !full_context.contains(&s) {
                return s;
            }
        }
        codepoint = if codepoint >= PUA_END {
            PUA_START
        } else {
            codepoint + 1
        };
    }
    // 极端情况: 所有码位都被占用 (几乎不可能). 返回起始码位.
    char::from_u32(PUA_START).unwrap().to_string()
}

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

    /// 插入映射. 若 mock 已存在但 real 不同 (碰撞), debug_assert 失败 (开发期捕获).
    pub fn insert(&mut self, real: String, mock: String) {
        debug_assert!(
            !self.mock_to_real.contains_key(&mock) || self.mock_to_real.get(&mock) == Some(&real),
            "mock collision: mock={mock:?} already maps to {:?}, attempted {real:?}",
            self.mock_to_real.get(&mock)
        );
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

/// 在请求 body 中查找所有 secret 并替换为 mock.
///
/// 实现:
/// 1. 按 secret 长度倒序排序, 先替换长的 (避免短的先替换导致长的部分被破坏).
/// 2. 对每个在 body 中出现的 secret, 调用 [`mock_secret`] 生成 mock, 全局 str::replace.
/// 3. 每次替换后, `full_context` 更新为已改写版本, 后续 mock 在更新后的上下文中保持唯一.
///
/// 复杂度: O(secrets × body_size). MVP 阶段 secrets 数量 <100, body <16 MiB, 可接受.
pub fn redact_request(body: &str, secrets: &[SecretEntry]) -> (String, RedactionMap) {
    let mut sorted: Vec<&SecretEntry> = secrets.iter().collect();
    sorted.sort_by_key(|e| Reverse(e.value.len()));
    // 去重: 同一 value 只 redact 一次.
    let mut seen_values = HashSet::new();

    let mut redacted = body.to_string();
    let mut map = RedactionMap::default();

    for entry in sorted {
        if entry.value.is_empty() {
            continue;
        }
        if !seen_values.insert(entry.value.as_str()) {
            continue;
        }
        if !redacted.contains(&entry.value) {
            continue;
        }
        let mock = mock_secret(&redacted, &entry.value);
        // 全局替换: 注意 String::replace 处理 non-overlapping 出现.
        redacted = redacted.replace(&entry.value, &mock);
        map.insert(entry.value.clone(), mock);
    }
    (redacted, map)
}

/// 在响应 body 中反向替换 mock 为真实 secret.
///
/// 仅在 [`RedactionMap`] 非空时调用.
pub fn restore_response(body: &str, map: &RedactionMap) -> String {
    if map.is_empty() {
        return body.to_string();
    }
    let mut restored = body.to_string();
    for (mock, real) in &map.mock_to_real {
        if restored.contains(mock) {
            restored = restored.replace(mock, real);
        }
    }
    restored
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretCategory;

    fn entry(value: &str) -> SecretEntry {
        SecretEntry {
            id: format!("id-{value}"),
            name: None,
            category: SecretCategory::ApiKey,
            value: value.into(),
        }
    }

    #[test]
    fn mock_secret_is_deterministic_for_same_input() {
        let m1 = mock_secret("hello world", "secret-1");
        let m2 = mock_secret("hello world", "secret-1");
        assert_eq!(m1, m2, "same input must produce same mock");
    }

    #[test]
    fn mock_secret_probes_when_in_context() {
        // 先生成 mock, 然后把它放进 context, 再生成一次, 应该得到不同的 mock.
        let first = mock_secret("ctx", "abc");
        let ctx_with_first = format!("ctx{first}");
        let second = mock_secret(&ctx_with_first, "abc");
        assert_ne!(first, second, "must probe to a different codepoint");
    }

    #[test]
    fn mock_secret_is_single_pua_char() {
        let m = mock_secret("any", "any-secret");
        assert_eq!(m.chars().count(), 1);
        let c = m.chars().next().unwrap();
        let cp = c as u32;
        assert!(
            (PUA_START..=PUA_END).contains(&cp),
            "mock must be in PUA range, got U+{cp:04X}"
        );
    }

    #[test]
    fn mock_secret_empty_input_returns_default() {
        let m = mock_secret("ctx", "");
        assert_eq!(m, "\u{E000}");
    }

    #[test]
    fn redact_replaces_secrets_with_mock() {
        let body = "Authorization: Bearer sk-test-123\nHello world";
        let secrets = vec![entry("sk-test-123")];
        let (redacted, map) = redact_request(body, &secrets);
        assert!(!redacted.contains("sk-test-123"));
        assert!(map.real_to_mock.contains_key("sk-test-123"));
        let mock = map.real_to_mock.get("sk-test-123").unwrap();
        assert!(redacted.contains(mock));
    }

    #[test]
    fn redact_handles_multiple_secrets() {
        let body = "key1=AAA key2=BBB key3=CCC";
        let secrets = vec![entry("AAA"), entry("BBB"), entry("CCC")];
        let (redacted, map) = redact_request(body, &secrets);
        assert!(!redacted.contains("AAA"));
        assert!(!redacted.contains("BBB"));
        assert!(!redacted.contains("CCC"));
        assert_eq!(map.real_to_mock.len(), 3);
        // 三个 mock 互不相同.
        let mocks: HashSet<_> = map.real_to_mock.values().cloned().collect();
        assert_eq!(mocks.len(), 3);
    }

    #[test]
    fn redact_longer_secret_wins_overlapping() {
        // AAA 是 AAAAA 的子串. 必须先替换 AAAAA (长的), 否则 AAA 先替换会破坏 AAAAA.
        let body = "found AAAAA in body";
        let secrets = vec![entry("AAA"), entry("AAAAA")];
        let (redacted, map) = redact_request(body, &secrets);
        // AAAAA 应该被作为一个整体 mock 替换.
        assert!(
            !redacted.contains("AAAAA"),
            "longer secret must be replaced, got: {redacted}"
        );
        // AAA 不应该出现 (要么被作为 AAAAA 的一部分替换, 要么单独替换).
        // 但 AAAAA 被替换后, AAA 的 mock 应该不存在.
        // 实际上, AAA 出现在 AAAAA 中, 所以 AAA 本身也存在; 按 sort_by_key 倒序,
        // AAAAA 先替换为 mock, 然后 AAA 在剩余 body 中找不到了 (因为已经被替换为 mock 字符).
        // 所以 map 应该只包含 AAAAA.
        assert!(
            !map.real_to_mock.contains_key("AAA"),
            "AAA should not be in map since it's already covered by AAAAA"
        );
        assert!(map.real_to_mock.contains_key("AAAAA"));
    }

    #[test]
    fn redact_preserves_non_secret_content() {
        let body = "user: alice, password: secret123, role: admin";
        let secrets = vec![entry("secret123")];
        let (redacted, _) = redact_request(body, &secrets);
        assert!(redacted.contains("user: alice"));
        assert!(redacted.contains("role: admin"));
    }

    #[test]
    fn redact_no_secrets_returns_body_unchanged() {
        let body = "hello";
        let (redacted, map) = redact_request(body, &[]);
        assert_eq!(redacted, body);
        assert!(map.is_empty());
    }

    #[test]
    fn restore_reverses_redact() {
        let body = "key=AAA, key2=BBB";
        let secrets = vec![entry("AAA"), entry("BBB")];
        let (redacted, map) = redact_request(body, &secrets);
        assert_ne!(redacted, body);
        let restored = restore_response(&redacted, &map);
        assert_eq!(restored, body, "round-trip must be identity");
    }

    #[test]
    fn restore_with_empty_map_is_identity() {
        let body = "anything";
        let map = RedactionMap::default();
        assert_eq!(restore_response(body, &map), body);
    }

    #[test]
    fn restore_preserves_llm_generated_content() {
        // LLM 在响应中引用了 mock (假设它"理解"了 mock 作为一个 token).
        let body = "user AAA has password BBB";
        let secrets = vec![entry("AAA"), entry("BBB")];
        let (redacted, map) = redact_request(body, &secrets);
        // 模拟 LLM 处理后回写了部分 mock + 新内容.
        let llm_response = format!(
            "I see {mock1} and {mock2} in the input.",
            mock1 = map.real_to_mock.get("AAA").unwrap(),
            mock2 = map.real_to_mock.get("BBB").unwrap()
        );
        let restored = restore_response(&llm_response, &map);
        assert!(restored.contains("AAA"));
        assert!(restored.contains("BBB"));
        // LLM 添加的非 mock 内容保持不变.
        assert!(restored.contains("I see"));
        let _ = redacted; // silence unused warning
    }

    #[test]
    fn redact_skips_secret_not_in_body() {
        let body = "hello world";
        let secrets = vec![entry("not-present")];
        let (redacted, map) = redact_request(body, &secrets);
        assert_eq!(redacted, body);
        assert!(map.is_empty(), "secret not in body must not produce a mock");
    }

    #[test]
    fn redact_dedupes_identical_values() {
        let body = "token: XYZ";
        let secrets = vec![
            SecretEntry {
                id: "id-1".into(),
                name: None,
                category: SecretCategory::ApiKey,
                value: "XYZ".into(),
            },
            SecretEntry {
                id: "id-2".into(),
                name: None,
                category: SecretCategory::ApiKey,
                value: "XYZ".into(),
            },
        ];
        let (redacted, map) = redact_request(body, &secrets);
        // 只有一个 mock (因为同一个 value 只 redact 一次).
        assert_eq!(map.real_to_mock.len(), 1);
        assert!(redacted.contains(map.real_to_mock.get("XYZ").unwrap()));
    }
}
