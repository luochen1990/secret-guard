//! Secret redaction (请求) 与 restoration (响应) 逻辑.
//!
//! # 第五步精化: 契约与正确性
//!
//! [`mock_secret`] 的形式化契约:
//!
//! - **C1 非空性**: 返回的 mock 非空, 长度 = `MOCK_PREFIX.len() + MOCK_BODY_LEN`,
//!   仅含 ASCII 字母数字 + 下划线.
//! - **C2 上下文唯一性 (in-context uniqueness)**:
//!   `mock_secret(ctx, secret)` 返回的 mock 一定**不在** `ctx` 中出现.
//!   这保证 redact 后的 body 中, mock 与所有非 secret 内容可区分.
//! - **C3 确定性 (determinism)**:
//!   同一进程内, 同一 `(ctx, secret)` 对总返回同一 mock (直到 ctx 改变).
//! - **C4 单射性 (injectivity within a redact pass)**:
//!   在 [`redact_request`] 的一次调用内, 不同 secret 总映射到不同 mock
//!   (因为 redact_request 在每次替换后, 把上一次的 mock 加进 ctx 再调 `mock_secret`).
//! - **C5 不含 real_secret 子串 (non-disclosure)**:
//!   mock 中**不含** real_secret 的任何 ≥4 字符连续子串.
//!   通过使用与 real_secret 无关的固定 prefix (`sgm_`) + hash body 实现.
//! - **C6 可逆性 (restorability)**:
//!   对 [`redact_request`] 返回的 `(redacted, map)`,
//!   `restore_response(redacted, map)` 严格恢复原始 body.
//!
//! # 实现思路
//!
//! - **prefix**: 固定 `sgm_` (secret-guard mock). 与 real_secret 无关, 保证 C5.
//! - **body**: 用 SipHash 1-2-3 (Rust `DefaultHasher`) 把 real_secret 映射到 u64,
//!   再 base62 编码为 11 字符. 不同 secret 几乎一定产生不同 body (碰撞概率 ≈ 2^-64).
//! - **collision probing**: 若初始 mock 已在 full_context 中, 用 `hash(secret || salt)`
//!   重新生成 body, 直到不再冲突.
//!
//! # 流式 trade-off
//! 当前对**非流式响应**直接做 restore; 对**流式响应**采用 "完整累积再 restore" 策略
//! (失去流式 UX, 但保证 mock→real 映射正确). 见 [`crate::proxy`] 的 fan_out_buffered.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

use crate::secrets::SecretEntry;

/// mock 的固定 prefix. 与 real_secret 无关, 是 C5 (no-real-substring) 的关键.
pub const MOCK_PREFIX: &str = "sgm_";

/// mock 的 body 长度 (base62 编码 u64 的固定长度, 范围 ~10^19 ≈ 2^63).
pub const MOCK_BODY_LEN: usize = 11;

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

/// 生成一个 mock secret. 形式化契约见模块级 doc.
///
/// 复杂度: 平均 O(|ctx|) (一次 contains); 极端 ctx 下 O(|ctx| × probes).
///
/// **终止性**: hash 空间 2^64, |ctx| 含 mock 子串数远小于 2^64, probing 必然终止.
/// 兜底 `salt > 2^32` 时 panic 而非返回错误结果, 强制暴露逻辑错误.
pub fn mock_secret(full_context: &str, real_secret: &str) -> String {
    let mut salt: u64 = 0;
    loop {
        let hash_input = if salt == 0 {
            real_secret.to_string()
        } else {
            format!("{real_secret}{salt}")
        };
        let body = base62_fixed(hash64(&hash_input));
        let candidate = format!("{MOCK_PREFIX}{body}");
        if !full_context.contains(&candidate) {
            return candidate;
        }
        salt += 1;
        if salt > (1u64 << 32) {
            // 极端情况: ctx 中可能含 hash 空间所有 candidate 的子集 (几乎不可能).
            // panic 而非返回错误结果, 强制暴露逻辑错误或外部攻击.
            panic!(
                "mock_secret probing exhausted after 2^32 attempts; \
                 ctx likely adversarial (size={})",
                full_context.len()
            );
        }
    }
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
    sorted.sort_by_key(|e| std::cmp::Reverse(e.value.len()));
    let mut seen_values: std::collections::HashSet<&str> = std::collections::HashSet::new();

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

    // ─── 契约单元测试 ──────────────────────────────────────────────────────

    #[test]
    fn c1_non_empty() {
        let m = mock_secret("ctx", "sk-test-123");
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
        let m1 = mock_secret("ctx", "abc");
        let ctx_with_m1 = format!("ctx{m1}");
        let m2 = mock_secret(&ctx_with_m1, "abc");
        assert!(
            !ctx_with_m1.contains(&m2),
            "m2={m2} must not appear in ctx_with_m1"
        );
    }

    #[test]
    fn c3_determinism() {
        for secret in ["short", "sk-test-123", "a-much-longer-secret-value-XYZ"] {
            let m1 = mock_secret("fixed-ctx", secret);
            let m2 = mock_secret("fixed-ctx", secret);
            assert_eq!(m1, m2, "same input must produce same mock for '{secret}'");
        }
    }

    #[test]
    fn c4_injectivity_within_redact() {
        // 100 个不同 secret, 在同一 redact_request 内应映射到 100 个不同 mock.
        let secrets: Vec<SecretEntry> = (0..100)
            .map(|i| entry(&format!("secret-value-{i:03}")))
            .collect();
        let body = secrets
            .iter()
            .map(|e| e.value.clone())
            .collect::<Vec<_>>()
            .join(" ");
        let (_, map) = redact_request(&body, &secrets);
        let mocks: std::collections::HashSet<_> = map.real_to_mock.values().cloned().collect();
        assert_eq!(mocks.len(), 100, "all 100 mocks must be distinct");
    }

    #[test]
    fn c5_no_substring_of_real_secret() {
        // mock 不应含 real_secret 的任何 ≥4 字符连续子串.
        // 前提: real_secret 不含 MOCK_PREFIX (validate_value 已强制).
        // 若 real 含 "sgm_", validate_value 会拒绝; 所以测试中所有 real 都通过验证.
        for real in ["sk-test-123", "super-secret-xyz", "ABCDEFGH", "abcdefgh"] {
            // validate_value 在 SecretTable::upsert 时强制, 这里再 sanity check.
            assert!(
                !real.contains(MOCK_PREFIX),
                "test fixture '{real}' should be rejected by validate_value"
            );
            let m = mock_secret("any-ctx", real);
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
        let body = "auth=sk-test-123; user=alice; token=ABCDEF-1234567890";
        let secrets = vec![entry("sk-test-123"), entry("ABCDEF-1234567890")];
        let (redacted, map) = redact_request(body, &secrets);
        assert_ne!(redacted, body);
        let restored = restore_response(&redacted, &map);
        assert_eq!(restored, body, "round-trip must be identity");
    }

    // ─── 行为测试 ──────────────────────────────────────────────────────────

    #[test]
    fn mock_has_fixed_prefix_and_length() {
        for real in ["abcd", "sk-test", "-leading-dash", "longer-secret-value"] {
            let m = mock_secret("ctx", real);
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
    fn redact_replaces_multiple_secrets() {
        let body = "key1=AAA key2=BBB key3=CCC";
        let secrets = vec![entry("AAA"), entry("BBB"), entry("CCC")];
        let (redacted, map) = redact_request(body, &secrets);
        assert!(!redacted.contains("AAA"));
        assert!(!redacted.contains("BBB"));
        assert!(!redacted.contains("CCC"));
        assert_eq!(map.real_to_mock.len(), 3);
    }

    #[test]
    fn redact_longer_secret_wins_overlapping() {
        let body = "found AAAAA in body";
        let secrets = vec![entry("AAA"), entry("AAAAA")];
        let (redacted, map) = redact_request(body, &secrets);
        // AAAAA 被作为一个整体替换为 mock (e.g. "sgm_xxxxxxxxxxxx"), body 中不再含 "AAA".
        // 所以 AAA 在剩余 body 中找不到, 不会被加入 map.
        assert!(!redacted.contains("AAAAA"));
        assert!(
            !map.real_to_mock.contains_key("AAA"),
            "AAA should not be in map; map = {:?}",
            map.real_to_mock
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
    fn restore_with_empty_map_is_identity() {
        let body = "anything";
        let map = RedactionMap::default();
        assert_eq!(restore_response(body, &map), body);
    }

    #[test]
    fn redact_skips_secret_not_in_body() {
        let body = "hello world";
        let secrets = vec![entry("not-present")];
        let (redacted, map) = redact_request(body, &secrets);
        assert_eq!(redacted, body);
        assert!(map.is_empty());
    }

    #[test]
    fn redact_dedupes_identical_values() {
        let body = "token: XYZ123";
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
        let (_, map) = redact_request(body, &secrets);
        assert_eq!(map.real_to_mock.len(), 1);
    }

    // ─── property-based 测试 (proptest) ─────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        /// C3 + C4: 不同 secret 几乎总产生不同 mock (在固定 ctx 下).
        #[test]
        fn prop_distinct_secrets_distinct_mocks(
            s1 in "[a-z]{4,12}",
            s2 in "[a-z]{4,12}"
        ) {
            prop_assume!(s1 != s2);
            let m1 = mock_secret("fixed-context", &s1);
            let m2 = mock_secret("fixed-context", &s2);
            prop_assert!(m1 != m2, "mocks for distinct secrets collided: {} == {}", m1, m2);
        }

        /// C2: mock 不在 full_context 中.
        #[test]
        fn prop_mock_not_in_context(
            secret in "[a-z0-9]{4,16}",
            ctx in "[a-z0-9 ]{0,100}"
        ) {
            let m = mock_secret(&ctx, &secret);
            prop_assert!(!ctx.contains(&m), "mock must not appear in ctx: mock={}", m);
        }

        /// C6: round-trip 是 identity (redact + restore).
        #[test]
        fn prop_round_trip_identity(
            body_prefix in "[a-z0-9 ,.!?'\"\n]{0,100}",
            secret in "[A-Z]{4,12}",
            body_suffix in "[a-z0-9 ,.!?'\"\n]{0,100}"
        ) {
            let body = format!("{body_prefix}{secret}{body_suffix}");
            let secrets = vec![entry(&secret)];
            let (redacted, map) = redact_request(&body, &secrets);
            let restored = restore_response(&redacted, &map);
            prop_assert_eq!(restored, body);
        }

        /// C1: mock 非空且仅含 ASCII 字母数字 + 下划线.
        #[test]
        fn prop_mock_alphanumeric(
            secret in "[A-Za-z0-9-]{4,20}"
        ) {
            let m = mock_secret("ctx", &secret);
            prop_assert!(!m.is_empty());
            prop_assert!(m.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        }

        /// C5: mock 不含 real_secret 的 ≥4 字符子串.
        /// (validate_value 已强制 real 不含 MOCK_PREFIX; proptest 输入空间遵守此前提.)
        #[test]
        fn prop_no_real_substring(
            secret in "[A-Za-z0-9]{8,20}"
        ) {
            prop_assume!(!secret.contains(MOCK_PREFIX));
            let m = mock_secret("ctx", &secret);
            for window in 4..=secret.len() {
                for sub in secret.as_bytes().windows(window) {
                    let sub_str = std::str::from_utf8(sub).unwrap();
                    prop_assert!(!m.contains(sub_str),
                        "mock contains substring from secret: mock={}, sub={}", m, sub_str);
                }
            }
        }

        /// C6 多 secret round-trip: N 个 secret 同时出现在 body, restore 后严格等于原 body.
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
            let (redacted, map) = redact_request(&body, &secrets);
            let restored = restore_response(&redacted, &map);
            prop_assert_eq!(restored, body);
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
            let secrets = vec![entry(&secret)];
            let (redacted, map) = redact_request(&body, &secrets);
            let restored = restore_response(&redacted, &map);
            prop_assert_eq!(restored, body);
        }

        /// C4 加强版: 在单次 redact_request 内, N 个不同 secret → N 个不同 mock.
        #[test]
        fn prop_redact_produces_distinct_mocks(
            n in 2usize..20
        ) {
            let secrets: Vec<SecretEntry> = (0..n)
                .map(|i| entry(&format!("secret-{:03}", i)))
                .collect();
            let body = secrets.iter().map(|e| e.value.clone()).collect::<Vec<_>>().join(" ");
            let (_, map) = redact_request(&body, &secrets);
            let mocks: std::collections::HashSet<_> = map.real_to_mock.values().collect();
            prop_assert_eq!(mocks.len(), n);
        }
    }
}
