//! Secret 注册表: 类型定义 + 内存存储 + 双层 (static + dynamic) 持久化.
//!
//! # 三层数据模型
//!
//! [`SecretTable`] 同时持有:
//! - `static_entries`: 来自 `secret-guard.toml` 的只读基线, 启动时加载, 进程内不可变.
//! - `dynamic_entries`: 来自 `secret-guard.state.toml` 的 WebUI 编辑结果, 可 CRUD.
//! - `decisions`: 与 [`crate::provider::ProviderTable`] 共享同一份 [`Decisions`] 实例
//!   (因为两者都写 state.toml).
//!
//! # 合并语义 (effective view)
//!
//! 对每个 id, [`SecretTable::effective_snapshot`] 按 [`OverrideMode`] 计算实际生效值,
//! 与 [`crate::provider::ProviderTable`] 完全对称. 见该模块的文档.
//!
//! # 持久化
//!
//! - 任何修改都立即写回 state.toml (atomic rename + fsync).
//! - **先持久化, 再更新内存** — 失败时内存自动回滚.
//! - 共享 `persist_lock` 串行整个 RMW, 避免与 ProviderTable 互相覆盖.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::config::{
    classify_source, pick_effective, Decisions, DynamicState, EffectiveSource, OverrideMode,
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

// ─── Effective view ────────────────────────────────────────────────────────

// EffectiveSource 已抽到 `crate::config`, provider / secret 共用同一份 SSOT.

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
            id: e.id,
            name: e.name,
            category: e.category,
            value_masked: crate::secrets::mask_value(&e.value),
            value_length: e.value.chars().count(),
        }
    }
}

// ─── Upsert / Delete 返回值 ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertKind {
    Inserted,
    Updated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    NotFound,
}

// ─── SecretTable ───────────────────────────────────────────────────────────

/// Secret 表. 在 ProxyState 中作为共享可变状态.
#[derive(Clone)]
pub struct SecretTable {
    static_entries: Arc<RwLock<Vec<SecretEntry>>>,
    dynamic_entries: Arc<RwLock<Vec<SecretEntry>>>,
    /// 与 ProviderTable 共享.
    decisions: Arc<RwLock<Decisions>>,
    persist_lock: Arc<Mutex<()>>,
    state_path: Arc<PathBuf>,
}

impl std::fmt::Debug for SecretTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.static_entries.read();
        let d = self.dynamic_entries.read();
        f.debug_struct("SecretTable")
            .field("static_count", &s.len())
            .field("dynamic_count", &d.len())
            .field("state_path", &self.state_path)
            .finish()
    }
}

impl SecretTable {
    pub fn new(
        static_entries: Vec<SecretEntry>,
        dynamic_entries: Vec<SecretEntry>,
        decisions: Arc<RwLock<Decisions>>,
        state_path: PathBuf,
    ) -> Self {
        Self::with_persist_lock(
            static_entries,
            dynamic_entries,
            decisions,
            state_path,
            Arc::new(Mutex::new(())),
        )
    }

    /// 用外部共享的 `persist_lock` 构造. 与 `ProviderTable::with_persist_lock` 对称:
    /// server 启动时创建一把锁传给两个 table, 保证它们对 state 文件的 RMW 串行化.
    pub fn with_persist_lock(
        static_entries: Vec<SecretEntry>,
        dynamic_entries: Vec<SecretEntry>,
        decisions: Arc<RwLock<Decisions>>,
        state_path: PathBuf,
        persist_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            static_entries: Arc::new(RwLock::new(static_entries)),
            dynamic_entries: Arc::new(RwLock::new(dynamic_entries)),
            decisions,
            persist_lock,
            state_path: Arc::new(state_path),
        }
    }

    /// 返回 effective view 中所有生效 secret 的**原始值** (未脱敏).
    /// 供 redact 流程使用. Disabled 的项被排除.
    pub fn effective_raw(&self) -> Vec<SecretEntry> {
        let statics = self.static_entries.read();
        let dynamics = self.dynamic_entries.read();
        let decisions = self.decisions.read();

        let mut out: Vec<SecretEntry> = Vec::with_capacity(statics.len() + dynamics.len());
        let mut seen: HashSet<String> = HashSet::new();

        for s in statics.iter() {
            seen.insert(s.id.clone());
            let d = dynamics.iter().find(|e| e.id == s.id).cloned();
            let mode = decisions.secret(&s.id);
            if let Some(e) = pick_effective(Some(s.clone()), d, mode) {
                out.push(e);
            }
        }
        for d in dynamics.iter() {
            if seen.contains(&d.id) {
                continue;
            }
            seen.insert(d.id.clone());
            if let Some(e) = pick_effective(None, Some(d.clone()), OverrideMode::Default) {
                out.push(e);
            }
        }
        out
    }

    /// 返回 effective view (供 WebUI 列表). value 已脱敏.
    pub fn effective_snapshot(&self) -> Vec<EffectiveSecret> {
        let statics = self.static_entries.read();
        let dynamics = self.dynamic_entries.read();
        let decisions = self.decisions.read();

        let mut out: Vec<EffectiveSecret> = Vec::with_capacity(statics.len() + dynamics.len());
        let mut seen: HashSet<String> = HashSet::new();

        for s in statics.iter() {
            seen.insert(s.id.clone());
            let d = dynamics.iter().find(|e| e.id == s.id).cloned();
            let mode = decisions.secret(&s.id);
            if let Some(ev) = compute_effective_secret(Some(s.clone()), d, mode) {
                out.push(ev);
            }
        }
        for d in dynamics.iter() {
            if seen.contains(&d.id) {
                continue;
            }
            seen.insert(d.id.clone());
            if let Some(ev) = compute_effective_secret(None, Some(d.clone()), OverrideMode::Default)
            {
                out.push(ev);
            }
        }
        out
    }

    /// 仅 dynamic 层 CRUD —— upsert. 若 id 同时存在于 static, 创建 / 更新 override.
    pub fn upsert_dynamic(&self, entry: SecretEntry) -> anyhow::Result<(SecretEntry, UpsertKind)> {
        validate_id(&entry.id).map_err(anyhow::Error::msg)?;
        validate_value(&entry.value).map_err(anyhow::Error::msg)?;

        let _guard = self.persist_lock.lock();
        let (new_entries, kind) = {
            let g = self.dynamic_entries.read();
            let mut v = g.clone();
            if let Some(e) = v.iter_mut().find(|e| e.id == entry.id) {
                *e = entry.clone();
                (v, UpsertKind::Updated)
            } else {
                v.push(entry.clone());
                (v, UpsertKind::Inserted)
            }
        };
        self.persist_dynamic(&new_entries)?;
        *self.dynamic_entries.write() = new_entries;
        Ok((entry, kind))
    }

    /// 仅 dynamic 层 CRUD —— delete.
    pub fn delete_dynamic(&self, id: &str) -> anyhow::Result<DeleteOutcome> {
        let _guard = self.persist_lock.lock();
        let new_entries = {
            let g = self.dynamic_entries.read();
            let existed = g.iter().any(|e| e.id == id);
            if !existed {
                return Ok(DeleteOutcome::NotFound);
            }
            g.iter().filter(|e| e.id != id).cloned().collect::<Vec<_>>()
        };
        self.persist_dynamic(&new_entries)?;
        *self.dynamic_entries.write() = new_entries;
        Ok(DeleteOutcome::Deleted)
    }

    /// 设置对某 static id 的决策. 持久化到 state.toml.
    ///
    /// 满足"先持久化, 再更新内存"契约: 若 atomic_write 失败, 内存 decisions 保持旧值.
    pub fn set_decision(&self, id: &str, mode: OverrideMode) -> anyhow::Result<()> {
        let _guard = self.persist_lock.lock();
        let new_decisions = {
            let cur = self.decisions.read().clone();
            let mut next = cur;
            next.set_secret(id, mode);
            next
        };
        let mut state = DynamicState::load_or_empty(&self.state_path)?;
        state.decisions = new_decisions.clone();
        let text = state.to_toml()?;
        atomic_write(&self.state_path, &text)?;
        *self.decisions.write() = new_decisions;
        Ok(())
    }

    /// 直接查 static 层. 同 [`crate::provider::ProviderTable::has_static`].
    pub fn has_static(&self, id: &str) -> bool {
        self.static_entries.read().iter().any(|e| e.id == id)
    }

    // ─── 内部持久化 helper ──────────────────────────────────────────────

    fn persist_dynamic(&self, new_dynamic: &[SecretEntry]) -> anyhow::Result<()> {
        let mut state = DynamicState::load_or_empty(&self.state_path)?;
        state.secrets = new_dynamic.to_vec();
        let text = state.to_toml()?;
        atomic_write(&self.state_path, &text)
    }
}

// ─── 合并算法 (薄包装, 事实源在 `crate::config`) ───────────────────────────

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

// ─── atomic_write 共用工具 ─────────────────────────────────────────────────

/// 原子写文件: 先写带 UUID 的 `.tmp`, sync, 再 rename.
///
/// `pub(crate)` 以便 `provider` 复用同一份实现.
pub(crate) fn atomic_write(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid config file name: {}", path.display()))?;
    // tmp 名带 UUID: 防止并发 persist 互相覆盖.
    let tmp_name = format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4().simple());
    let tmp = parent.join(&tmp_name);

    let mut f = std::fs::File::create(&tmp)
        .map_err(|e| anyhow::anyhow!("create tmp {} failed: {e}", tmp.display()))?;
    f.write_all(text.as_bytes())
        .map_err(|e| anyhow::anyhow!("write tmp {} failed: {e}", tmp.display()))?;
    f.sync_all()
        .map_err(|e| anyhow::anyhow!("fsync tmp {} failed: {e}", tmp.display()))?;
    drop(f);

    std::fs::rename(&tmp, path).map_err(|e| {
        // 失败时尝试清理 tmp.
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("rename {} -> {} failed: {e}", tmp.display(), path.display())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn effective_raw_isolated_from_static_only() {
        let t = SecretTable::new(
            vec![entry("a", "value-a"), entry("b", "value-b")],
            vec![],
            empty_decisions(),
            PathBuf::from("/tmp/x.toml"),
        );
        let mut snap = t.effective_raw();
        snap.clear();
        assert_eq!(t.effective_raw().len(), 2, "static_entries unchanged");
    }

    #[test]
    fn dynamic_overrides_static_by_default() {
        let t = SecretTable::new(
            vec![entry("a", "static-value")],
            vec![entry("a", "dynamic-value")],
            empty_decisions(),
            PathBuf::from("/tmp/x.toml"),
        );
        let snap = t.effective_raw();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].value, "dynamic-value");
    }

    #[test]
    fn prefer_static_wins_over_dynamic() {
        let t = SecretTable::new(
            vec![entry("a", "static-value")],
            vec![entry("a", "dynamic-value")],
            empty_decisions(),
            PathBuf::from("/tmp/x.toml"),
        );
        t.set_decision("a", OverrideMode::PreferStatic).unwrap();
        let snap = t.effective_raw();
        assert_eq!(snap[0].value, "static-value");
    }

    #[test]
    fn disabled_drops_secret() {
        let t = SecretTable::new(
            vec![entry("a", "static-value")],
            vec![],
            empty_decisions(),
            PathBuf::from("/tmp/x.toml"),
        );
        t.set_decision("a", OverrideMode::Disabled).unwrap();
        assert!(t.effective_raw().is_empty());
    }

    #[test]
    fn upsert_inserts_then_updates_dynamic() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp.clone());
        let (_, k1) = t.upsert_dynamic(entry("a", "value-1")).unwrap();
        assert_eq!(k1, UpsertKind::Inserted);
        let (_, k2) = t.upsert_dynamic(entry("a", "value-2")).unwrap();
        assert_eq!(k2, UpsertKind::Updated);
        let snap = t.effective_raw();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].value, "value-2");
    }

    #[test]
    fn delete_dynamic_removes_and_persists() {
        let tmp = tempfile_path();
        let t = SecretTable::new(
            vec![],
            vec![entry("a", "value-1"), entry("b", "value-b")],
            empty_decisions(),
            tmp.clone(),
        );
        assert_eq!(t.delete_dynamic("a").unwrap(), DeleteOutcome::Deleted);
        assert_eq!(t.effective_raw().len(), 1);
        let state = DynamicState::load_or_empty(&tmp).unwrap();
        assert_eq!(state.secrets.len(), 1);
        assert_eq!(state.secrets[0].id, "b");
    }

    #[test]
    fn delete_dynamic_keeps_static_baseline() {
        let tmp = tempfile_path();
        let t = SecretTable::new(
            vec![entry("a", "static-value")],
            vec![entry("a", "dynamic-value")],
            empty_decisions(),
            tmp,
        );
        assert_eq!(t.delete_dynamic("a").unwrap(), DeleteOutcome::Deleted);
        let snap = t.effective_raw();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].value, "static-value");
    }

    #[test]
    fn delete_dynamic_missing_returns_not_found() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp);
        assert_eq!(t.delete_dynamic("nope").unwrap(), DeleteOutcome::NotFound);
    }

    #[test]
    fn invalid_id_rejected() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp);
        let bad = SecretEntry {
            id: "has space".into(),
            name: None,
            category: SecretCategory::Other,
            value: "v".into(),
        };
        assert!(t.upsert_dynamic(bad).is_err());
    }

    #[test]
    fn leading_dash_id_rejected() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp);
        let bad = SecretEntry {
            id: "-leading-dash".into(),
            name: None,
            category: SecretCategory::Other,
            value: "v".into(),
        };
        assert!(t.upsert_dynamic(bad).is_err());
    }

    #[test]
    fn concurrent_upserts_no_lost_update() {
        // Smoke test: 两个线程并发 upsert 不同的 id, 两者都应该最终可见.
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp);
        let t1 = t.clone();
        let t2 = t.clone();
        let h1 = std::thread::spawn(move || t1.upsert_dynamic(entry("a", "value-a")));
        let h2 = std::thread::spawn(move || t2.upsert_dynamic(entry("b", "value-b")));
        h1.join().unwrap().unwrap();
        h2.join().unwrap().unwrap();
        let snap = t.effective_raw();
        let ids: Vec<_> = snap.iter().map(|e| e.id.clone()).collect();
        assert!(ids.contains(&"a".to_string()), "lost update: {ids:?}");
        assert!(ids.contains(&"b".to_string()), "lost update: {ids:?}");
    }

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
}
