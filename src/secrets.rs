//! Secret 类型定义 + 校验 + [`DynamicEntry`] 实现 + effective 视图.
//!
//! # 三层数据模型 (与 [`crate::provider`] 完全对称)
//!
//! [`SecretTable`] (= [`DynamicTable<SecretEntry>`](crate::config::DynamicTable)) 同时持有:
//! - `static_entries`: 来自 `secret-guard.toml` 的只读基线, 启动时加载, 进程内不可变.
//! - `dynamic_entries`: 来自 `secret-guard.state.toml` 的 WebUI 编辑结果, 可 CRUD.
//! - `decisions`: 与 [`crate::provider::ProviderTable`] 共享同一份 [`Decisions`] 实例
//!   (因为两者都写 state.toml).
//!
//! 合并 / CRUD / 持久化等所有通用逻辑都在 [`crate::config::DynamicTable`] 中实现,
//! 本模块只补充 Secret 类型特定的小部分: [`DynamicEntry`] impl + effective 视图
//! 的 masked 映射 ([`compute_effective_secret`]) + secret 校验工具.
//!
//! # 持久化与并发
//!
//! 见 [`crate::config::DynamicTable`] 的文档.

use serde::{Deserialize, Serialize};

use crate::config::{
    classify_source, pick_effective, Decisions, DynamicEntry, DynamicState, DynamicTable,
    EffectiveSource, OverrideMode,
};

/// 单条 secret 注册项.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// 唯一 id (slug). 同一份表 (static 或 dynamic) 中必须唯一.
    /// 通过 [`validate_id`] 校验合法字符集.
    pub id: String,
    /// 可选的人类可读名称 (用于 Web UI 显示).
    #[serde(default)]
    pub name: Option<String>,
    /// 类别: 影响 mock_secret 的生成策略 (第四步细化).
    #[serde(default)]
    pub category: SecretCategory,
    /// 真实 secret 明文 (服务端使用; 永不通过 API 返回).
    pub value: String,
}

/// Secret 类别. 用于第四步选择不同的 mock 生成器.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretCategory {
    /// 密码 (相对短, 任意可打印字符).
    Password,
    /// API key (通常较长, 固定前缀如 sk-/ANTHROPIC-/AKIA).
    #[default]
    ApiKey,
    /// 长 bearer token (JWT 等).
    Token,
    /// Cookie 值.
    Cookie,
    /// 私钥 (PEM 等, 多行).
    PrivateKey,
    /// 兜底.
    Other,
}

impl SecretCategory {
    /// 所有变体及其字符串名 (与 `#[serde(rename_all = "lowercase")]` 同步).
    /// 单一事实来源: `all()` 与 `as_str()` 均从这里派生.
    pub const ALL: [(Self, &'static str); 6] = [
        (Self::Password, "password"),
        (Self::ApiKey, "apikey"),
        (Self::Token, "token"),
        (Self::Cookie, "cookie"),
        (Self::PrivateKey, "privatekey"),
        (Self::Other, "other"),
    ];

    pub fn as_str(self) -> &'static str {
        Self::ALL
            .into_iter()
            .find(|(c, _)| *c == self)
            .map(|(_, s)| s)
            .expect("ALL covers every variant")
    }
}

/// 校验 secret id (slug). 允许: 字母/数字开头, 长度 1-64, 仅含 `[A-Za-z0-9_-]`.
/// 防止 XSS / 路径冲突 / 路由切段问题.
///
/// 同时被 secret 与 provider 的 id 校验复用 (单一事实来源).
pub fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 64 {
        return Err(format!("id length must be 1..=64, got {}", id.len()));
    }
    let mut chars = id.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_alphanumeric() {
        return Err(format!("id must start with [A-Za-z0-9], got '{first}'"));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!(
                "id contains illegal character '{c}' (allowed: alphanumeric, '_', '-')"
            ));
        }
    }
    Ok(())
}

/// 校验 secret value. 防止用户误配短 / 结构性 / 含 PUA / 与 mock prefix 冲突的 secret
/// (避免 redact 时破坏整个请求 body 或 round-trip identity).
///
/// 特别拒绝 [`crate::redact::MOCK_PREFIX`] (`sgm_`): 该 prefix 与 mock_secret 输出
/// 共享, 若 real secret 也含此 prefix, mock 可能与 real 共享 ≥4 字符子串, 违反 C5.
pub fn validate_value(value: &str) -> Result<(), String> {
    if value.len() < 3 {
        return Err(format!(
            "secret value too short (min 3 bytes), got {}",
            value.len()
        ));
    }
    // 含 mock prefix → 与 redact 输出冲突, 拒绝.
    if value.contains(crate::redact::MOCK_PREFIX) {
        return Err(format!(
            "secret value must not contain the mock prefix '{}' (reserved for redaction)",
            crate::redact::MOCK_PREFIX
        ));
    }
    // PUA 字符与 mock 输出冲突, 拒绝.
    if value
        .chars()
        .any(|c| (0xE000..=0xF8FF).contains(&(c as u32)))
    {
        return Err("secret value must not contain Unicode PUA characters (U+E000..U+F8FF)".into());
    }
    Ok(())
}

/// 对 secret / api_key 做最小信息脱敏:
/// - 空 → 空;
/// - 短 (≤8 字符) → 用相同长度的 `*` 填充, 暴露长度但不暴露内容;
/// - 长 (>8 字符) → 保留首尾各 1 字符 + 中间 `*` (长度等于原值).
///
/// `pub(crate)` 让 web::api / provider / secrets 共用同一份实现 (DRY).
pub(crate) fn mask_value(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head = chars[0];
    let tail = chars[chars.len() - 1];
    let stars = "*".repeat(chars.len().saturating_sub(2));
    format!("{head}{stars}{tail}")
}

// ─── DynamicEntry impl: 把 SecretEntry 接入泛型 DynamicTable ──────────────

impl DynamicEntry for SecretEntry {
    fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        validate_value(&self.value)?;
        Ok(())
    }

    fn set_state_field(state: &mut DynamicState, entries: Vec<Self>) {
        state.secrets = entries;
    }

    fn get_decision(d: &Decisions, id: &str) -> OverrideMode {
        d.secret(id)
    }

    fn set_decision(d: &mut Decisions, id: &str, mode: OverrideMode) {
        d.set_secret(id, mode);
    }
}

// ─── SecretTable 别名 + 类型特定 effective 视图 ────────────────────────────

/// Secret 表. 在 ProxyState 中作为共享可变状态.
///
/// 实际类型是 [`DynamicTable<SecretEntry>`](crate::config::DynamicTable),
/// 所有通用方法 (effective_raw / get_effective / upsert_dynamic / ...) 在那里实现;
/// 下面的 `impl DynamicTable<SecretEntry>` 仅补充 Secret 特有的 effective 视图.
pub type SecretTable = DynamicTable<SecretEntry>;

/// Secret 的合并视图项. value 已脱敏 (永不回传真实值).
#[derive(Debug, Clone, Serialize)]
pub struct EffectiveSecret {
    pub id: String,
    pub name: Option<String>,
    pub category: SecretCategory,
    pub value_masked: String,
    pub value_length: usize,

    pub source: EffectiveSource,
    pub decision: OverrideMode,
    pub static_version: Option<SecretMasked>,
    pub dynamic_version: Option<SecretMasked>,
}

/// 对外返回时屏蔽真实 value. 见 [`mask_value`] 的脱敏规则.
#[derive(Debug, Clone, Serialize)]
pub struct SecretMasked {
    pub id: String,
    pub name: Option<String>,
    pub category: SecretCategory,
    pub value_masked: String,
    pub value_length: usize,
}

impl From<SecretEntry> for SecretMasked {
    fn from(e: SecretEntry) -> Self {
        Self {
            value_masked: crate::secrets::mask_value(&e.value),
            value_length: e.value.chars().count(),
            id: e.id,
            name: e.name,
            category: e.category,
        }
    }
}

impl DynamicTable<SecretEntry> {
    /// 返回 effective 视图 (WebUI 列表). value 已脱敏.
    pub fn effective_snapshot(&self) -> Vec<EffectiveSecret> {
        self.effective_triples()
            .into_iter()
            .filter_map(|(s, d, m)| compute_effective_secret(s, d, m))
            .collect()
    }
}

/// 给定 (static_ver, dynamic_ver, mode), 计算 effective secret 的合并视图.
fn compute_effective_secret(
    static_ver: Option<SecretEntry>,
    dynamic_ver: Option<SecretEntry>,
    mode: OverrideMode,
) -> Option<EffectiveSecret> {
    let raw = pick_effective(static_ver.clone(), dynamic_ver.clone(), mode)?;
    let source = classify_source(static_ver.is_some(), dynamic_ver.is_some(), mode)
        .expect("pick_effective Some ⇒ classify_source Some");
    let static_masked = static_ver.map(SecretMasked::from);
    let dynamic_masked = dynamic_ver.map(SecretMasked::from);
    Some(EffectiveSecret {
        value_masked: crate::secrets::mask_value(&raw.value),
        value_length: raw.value.chars().count(),
        id: raw.id,
        name: raw.name,
        category: raw.category,
        source,
        decision: mode,
        static_version: static_masked,
        dynamic_version: dynamic_masked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EffectiveSource, OverrideMode};
    use std::path::PathBuf;
    use std::sync::Arc;

    use parking_lot::RwLock;

    use crate::config::Decisions;

    fn entry(id: &str, value: &str) -> SecretEntry {
        SecretEntry {
            id: id.into(),
            name: Some(format!("name-{id}")),
            category: SecretCategory::ApiKey,
            value: value.into(),
        }
    }

    fn empty_decisions() -> Arc<RwLock<Decisions>> {
        Arc::new(RwLock::new(Decisions::default()))
    }

    fn tempfile_path() -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-secrets-{id}.toml"));
        let _ = std::fs::remove_file(&path);
        path
    }

    // ─── 类型特定的校验函数 ─────────────────────────────────────────────

    #[test]
    fn validate_id_accepts_valid_slugs() {
        assert!(validate_id("a").is_ok());
        assert!(validate_id("abc-123_XYZ").is_ok());
        assert!(validate_id(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn validate_id_rejects_invalid() {
        assert!(validate_id("").is_err());
        assert!(validate_id(&"a".repeat(65)).is_err());
        assert!(validate_id("-abc").is_err());
        assert!(validate_id("_abc").is_err());
        assert!(validate_id("has space").is_err());
        assert!(validate_id("slash/here").is_err());
        assert!(validate_id("quote'here").is_err());
        assert!(validate_id("<html>").is_err());
    }

    #[test]
    fn validate_value_rejects_short_and_mock_prefix() {
        // 太短.
        assert!(validate_value("ab").is_err());
        // 含 mock prefix.
        assert!(validate_value("contains sgm_ in middle").is_err());
        // 含 PUA 字符.
        assert!(validate_value("ok\u{E000}value").is_err());
        // 合法.
        assert!(validate_value("normal-secret-value").is_ok());
    }

    #[test]
    fn mask_value_hides_full_content() {
        assert_eq!(mask_value(""), "");
        assert_eq!(mask_value("short"), "*****"); // ≤8 → 全 *
        assert_eq!(mask_value("12345678"), "********");
        assert_eq!(mask_value("123456789"), "1*******9"); // >8 → 首尾各 1
                                                          // 任意 >8 长度: head + (n-2) stars + tail.
        let secret = "sk-1234567890abcdef";
        let masked = mask_value(secret);
        assert_eq!(masked.len(), secret.chars().count());
        assert!(masked.starts_with('s'));
        assert!(masked.ends_with('f'));
        // 中间应全是 '*'.
        let middle: String = masked
            .chars()
            .skip(1)
            .take(masked.chars().count() - 2)
            .collect();
        assert!(middle.chars().all(|c| c == '*'));
    }

    #[test]
    fn secret_category_roundtrip_str() {
        for (cat, name) in SecretCategory::ALL {
            assert_eq!(cat.as_str(), name);
        }
        // 其他类型转换正确.
        assert_eq!(SecretCategory::default(), SecretCategory::ApiKey);
    }

    // ─── effective_snapshot: 类型特定的 masked 视图 ─────────────────────
    //
    // 通用合并 / CRUD / 持久化 / decision 行为已在 `crate::config::table_tests`
    // 用 SecretEntry 作为 canonical 类型覆盖. 这里只测 EffectiveSecret 特有的
    // masked 字段映射.

    #[test]
    fn effective_snapshot_includes_provenance_and_masks_value() {
        let tmp = tempfile_path();
        let t = SecretTable::new(
            vec![
                entry("static-only", "static-secret-v"),
                entry("override-id", "static-base-v"),
            ],
            vec![
                entry("dynamic-only", "dynamic-secret-v"),
                entry("override-id", "dynamic-over-v"),
            ],
            empty_decisions(),
            tmp,
        );
        let snap = t.effective_snapshot();
        assert_eq!(snap.len(), 3);

        // 序列化结果中真实 value 不应出现.
        let json = serde_json::to_string(&snap).unwrap();
        assert!(!json.contains("static-secret-v"));
        assert!(!json.contains("dynamic-secret-v"));
        assert!(json.contains("value_masked"));

        let by_id: std::collections::HashMap<String, EffectiveSecret> =
            snap.into_iter().map(|e| (e.id.clone(), e)).collect();

        let s = by_id.get("static-only").unwrap();
        assert_eq!(s.source, EffectiveSource::Static);
        assert!(s.static_version.is_some());
        assert!(s.dynamic_version.is_none());

        let d = by_id.get("dynamic-only").unwrap();
        assert_eq!(d.source, EffectiveSource::Dynamic);
        assert!(d.static_version.is_none());
        // dynamic-only 时, dynamic_version 就是自身.
        assert!(d.dynamic_version.is_some());

        let ov = by_id.get("override-id").unwrap();
        assert_eq!(ov.source, EffectiveSource::DynamicOverride);
        assert!(ov.static_version.is_some());
        assert!(ov.dynamic_version.is_some());
    }

    #[test]
    fn prefer_static_marks_source_correctly() {
        let tmp = tempfile_path();
        let t = SecretTable::new(
            vec![entry("a", "static-v")],
            vec![entry("a", "dynamic-v")],
            empty_decisions(),
            tmp,
        );
        t.set_decision("a", OverrideMode::PreferStatic).unwrap();
        let snap = t.effective_snapshot();
        assert_eq!(snap[0].source, EffectiveSource::StaticPreferred);
        // "static-v" 8 字符, ≤ 8 → 全 *; length 8.
        assert_eq!(snap[0].value_masked, "********");
        assert_eq!(snap[0].value_length, 8);
    }
}
