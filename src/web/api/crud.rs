//! secrets/providers CRUD 的泛型流程 (共享骨架).
//!
//! 从 api.rs 单文件拆出 (见 #146 残留 2). create_secret / create_provider (以及
//! update/delete/decision) 的流程段逐段同构, 仅 entry 类型 / validate 钩子 / 错误消息中
//! 的 "secret"/"provider" 一词不同. 本模块把流程级骨架抽成泛型函数, handler 退化为
//! 薄壳 (类型特定的 entry 构造与校验作闭包参数).
//!
//! # 三层抽象
//!
//! - [`EffectiveItem`]: effective 视图项的 id 访问 (冲突检查 / 查回).
//! - [`EntryItem`]: 写入 entry 的 id 读写 (create 时 "id 空则自动生成").
//! - [`CrudTable`]: 一张 dynamic 表的 CRUD 操作面 (snapshot / upsert / delete /
//!   has_static / set_decision), 由 `DynamicTable<SecretEntry>` /
//!   `DynamicTable<Provider>` 各自实现.
//!
//! 流程函数 (错误消息与原两份实现逐字相同, 仅 kind_label 参数化):
//! - [`create_flow`]: into-entry → id 空则 Uuid (201 响应体以 `generated_id` 明示) →
//!   validate 钩子 → 冲突检查 → upsert (Updated 视为并发冲突) → 查回 effective → 201.
//! - [`update_flow`]: 存在性检查 → build 钩子 → 填 id → validate 钩子 → upsert →
//!   查回 → 200.
//! - [`delete_flow`]: delete → DeleteOutcome 分类 (static-only 409 / 不存在 404) → 204.
//! - [`decision_flow`]: static 检查 → set_decision → ack.

use serde::{Deserialize, Serialize};

use crate::config::{DeleteOutcome, DynamicTable, OverrideMode, UpsertKind};
use crate::provider::{EffectiveProvider, Provider};
use crate::secrets::{EffectiveSecret, SecretEntry};

use super::error::ApiError;

/// EffectiveItem: 让 EffectiveSecret / EffectiveProvider 共享 "按 id 查" 的泛型 helper.
/// 仅需 id 访问器, 不引入 sealed trait 的复杂度.
pub(crate) trait EffectiveItem {
    fn effective_id(&self) -> &str;
}

impl EffectiveItem for EffectiveSecret {
    fn effective_id(&self) -> &str {
        &self.id
    }
}

impl EffectiveItem for EffectiveProvider {
    fn effective_id(&self) -> &str {
        &self.id
    }
}

/// 写入 entry 的 id 读写 (create 时 "id 空则自动生成" 需要).
pub(crate) trait EntryItem {
    fn entry_id(&self) -> &str;
    fn set_entry_id(&mut self, id: String);
}

impl EntryItem for SecretEntry {
    fn entry_id(&self) -> &str {
        &self.id
    }
    fn set_entry_id(&mut self, id: String) {
        self.id = id;
    }
}

impl EntryItem for Provider {
    fn entry_id(&self) -> &str {
        &self.id
    }
    fn set_entry_id(&mut self, id: String) {
        self.id = id;
    }
}

/// 一张 dynamic 表的 CRUD 操作面 (secrets / providers 两张表实现).
///
/// 是 `DynamicTable<T>` 类型特定方法 (effective_snapshot 等) 的薄封装, 让流程函数
/// 与具体表类型解耦.
pub(crate) trait CrudTable {
    type Entry: EntryItem;
    type Effective: EffectiveItem;

    /// effective 视图快照 (static+dynamic+decision 合并后).
    fn snapshot(&self) -> Vec<Self::Effective>;
    fn upsert(&self, entry: Self::Entry) -> anyhow::Result<(Self::Entry, UpsertKind)>;
    fn delete(&self, id: &str) -> anyhow::Result<DeleteOutcome>;
    /// 直接查 static 层, 不受 decision 影响 (decision=Disabled 的 id 也能识别).
    fn has_static(&self, id: &str) -> bool;
    fn set_decision(&self, id: &str, mode: OverrideMode) -> anyhow::Result<()>;
}

impl CrudTable for DynamicTable<SecretEntry> {
    type Entry = SecretEntry;
    type Effective = EffectiveSecret;

    fn snapshot(&self) -> Vec<Self::Effective> {
        self.effective_snapshot()
    }
    fn upsert(&self, entry: Self::Entry) -> anyhow::Result<(Self::Entry, UpsertKind)> {
        DynamicTable::upsert_dynamic(self, entry)
    }
    fn delete(&self, id: &str) -> anyhow::Result<DeleteOutcome> {
        DynamicTable::delete_dynamic(self, id)
    }
    fn has_static(&self, id: &str) -> bool {
        DynamicTable::has_static(self, id)
    }
    fn set_decision(&self, id: &str, mode: OverrideMode) -> anyhow::Result<()> {
        DynamicTable::set_decision(self, id, mode)
    }
}

impl CrudTable for DynamicTable<Provider> {
    type Entry = Provider;
    type Effective = EffectiveProvider;

    fn snapshot(&self) -> Vec<Self::Effective> {
        self.effective_snapshot()
    }
    fn upsert(&self, entry: Self::Entry) -> anyhow::Result<(Self::Entry, UpsertKind)> {
        DynamicTable::upsert_dynamic(self, entry)
    }
    fn delete(&self, id: &str) -> anyhow::Result<DeleteOutcome> {
        DynamicTable::delete_dynamic(self, id)
    }
    fn has_static(&self, id: &str) -> bool {
        DynamicTable::has_static(self, id)
    }
    fn set_decision(&self, id: &str, mode: OverrideMode) -> anyhow::Result<()> {
        DynamicTable::set_decision(self, id, mode)
    }
}

// ─── 泛型叶操作 ─────────────────────────────────────────────────────────────

/// effective 视图中是否存在指定 id.
fn effective_contains_id(items: &[impl EffectiveItem], id: &str) -> bool {
    items.iter().any(|x| x.effective_id() == id)
}

/// upsert 后从 effective 视图按 id 查回最新状态 (upsert_dynamic 不返回 effective 视图,
/// 需重新查一次给前端). 找不到时 panic (刚 upsert, 不应发生).
fn effective_find_by_id<I: EffectiveItem>(items: Vec<I>, id: &str) -> I {
    items
        .into_iter()
        .find(|x| x.effective_id() == id)
        .expect("just upserted; effective view must contain it")
}

/// delete_dynamic 的 DeleteOutcome 分类: Deleted → 204; NotFound → 区分 static-only
/// (409 conflict, 提示用 disabled decision) vs 真不存在 (404).
///
/// `kind_label` = "secret" | "provider", 用于错误消息.
fn classify_delete_outcome(
    outcome: DeleteOutcome,
    has_static: bool,
    kind_label: &str,
    id: &str,
) -> Result<(), ApiError> {
    match outcome {
        DeleteOutcome::Deleted => Ok(()), // 204 No Content.
        DeleteOutcome::NotFound => {
            if has_static {
                Err(ApiError::conflict(format!(
                    "cannot delete a static {kind_label}; use PATCH .../decision with \
                     {{\"mode\":\"disabled\"}} to disable it"
                )))
            } else {
                Err(ApiError::not_found(format!("{kind_label} {id} not found")))
            }
        }
    }
}

// ─── 泛型流程函数 ───────────────────────────────────────────────────────────

/// create 成功的 201 响应体: effective 视图 + `generated_id` 明示位 (#164 子项 6).
///
/// POST 不传 id 时服务端静默生成 UUID, 脚本用户拿到的 id 与预期不符却无提示.
/// 现在在响应体加 `generated_id: true` 明示 (仅生成时出现, 显式传 id 时省略 —
/// 向后兼容的加法, 旧客户端忽略新字段即可). WebUI 前端依赖自动生成逻辑不受影响.
#[derive(Serialize)]
pub(crate) struct Created<T> {
    #[serde(flatten)]
    effective: T,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    generated_id: bool,
}

/// create 通用流程: 构造 entry → id 空则 Uuid → validate 钩子 → effective 冲突检查 →
/// upsert (Updated = 并发创建, 409) → 查回 effective 视图.
///
/// 返回 [`Created`] (effective 视图 + generated_id 明示位), handler 加
/// `(StatusCode::CREATED, NO_STORE, Json)` 包装.
pub(crate) fn create_flow<T: CrudTable>(
    table: &T,
    kind_label: &str,
    build: impl FnOnce() -> Result<T::Entry, ApiError>,
    validate: impl FnOnce(&mut T::Entry) -> Result<(), ApiError>,
) -> Result<Created<T::Effective>, ApiError>
where
    T::Effective: Serialize,
{
    let mut entry = build()?;
    // create 模式: 若没传 id, 自动生成. 记录该事实, 201 响应体明示 (脚本用户可感知).
    let generated_id = entry.entry_id().is_empty();
    if generated_id {
        entry.set_entry_id(uuid::Uuid::new_v4().to_string());
    }
    validate(&mut entry)?;
    // 检查 effective view 中是否已存在 (含 static 来源). 不允许覆盖 static 创建同 id.
    if effective_contains_id(&table.snapshot(), entry.entry_id()) {
        return Err(ApiError::conflict(format!(
            "{kind_label} with id '{}' already exists (in static or dynamic); use PUT to override",
            entry.entry_id()
        )));
    }
    let (saved, kind) = table.upsert(entry).map_err(ApiError::from_any)?;
    if kind == UpsertKind::Updated {
        // 并发写入导致在 check 与 upsert 之间被其他请求创建; 视为 conflict.
        return Err(ApiError::conflict(format!(
            "{kind_label} was concurrently created; please retry"
        )));
    }
    // upsert_dynamic 不返回 effective 视图, 这里再查一次给前端 (低成本, 创建场景罕见).
    Ok(Created {
        effective: effective_find_by_id(table.snapshot(), saved.entry_id()),
        generated_id,
    })
}

/// update 通用流程: 存在性检查 (404) → build 钩子 (构造 entry + 类型特定预处理) →
/// 填 path id → validate 钩子 → upsert → 查回 effective 视图.
///
/// 注: `build` 必须惰性 (FnOnce 闭包, 在存在性检查之后才求值) — 保持
/// "404 先于 payload 校验" 的历史错误顺序.
pub(crate) fn update_flow<T: CrudTable>(
    table: &T,
    kind_label: &str,
    id: &str,
    build: impl FnOnce() -> Result<T::Entry, ApiError>,
    validate: impl FnOnce(&mut T::Entry) -> Result<(), ApiError>,
) -> Result<T::Effective, ApiError> {
    // 允许编辑 static-only id: 服务端自动 fork 出 dynamic override.
    // 但若 id 完全不存在 (effective 中查不到), 返回 404.
    if !effective_contains_id(&table.snapshot(), id) {
        return Err(ApiError::not_found(format!("{kind_label} {id} not found")));
    }
    let mut entry = build()?;
    entry.set_entry_id(id.to_string());
    validate(&mut entry)?;
    let (saved, _kind) = table.upsert(entry).map_err(ApiError::from_any)?;
    Ok(effective_find_by_id(table.snapshot(), saved.entry_id()))
}

/// delete 通用流程: delete → outcome 分类 (static-only 409 / 不存在 404).
/// 成功返回 `()` (handler 包装为 204 空 body).
pub(crate) fn delete_flow<T: CrudTable>(
    table: &T,
    kind_label: &str,
    id: &str,
) -> Result<(), ApiError> {
    // 若 dynamic 有此 id, 删除 (覆盖关系下仅移除 override, static 保留).
    // 若 dynamic 无此 id 但 static 有, 拒绝删除 (static 永不可写; 提示用 disabled decision).
    // 用 has_static 直接查 static 层, 不受 decision 影响 (disabled 的 id 也能正确报 409).
    let outcome = table.delete(id).map_err(ApiError::from_any)?;
    classify_delete_outcome(outcome, table.has_static(id), kind_label, id)
}

/// `PATCH /{id}/decision` 的请求 body (secrets / providers 共享).
#[derive(Debug, Deserialize)]
pub(crate) struct DecisionRequest {
    pub mode: String,
}

impl DecisionRequest {
    pub(crate) fn into_mode(self) -> Result<OverrideMode, ApiError> {
        OverrideMode::parse(&self.mode).ok_or_else(|| {
            ApiError::validation(format!(
                "unknown decision mode '{}' (expected one of: default, prefer_static, disabled)",
                self.mode
            ))
        })
    }
}

/// `PATCH /{id}/decision` 的 ack 响应 (secrets / providers 共享).
#[derive(Serialize)]
pub(crate) struct DecisionAck {
    pub id: String,
    /// "provider" | "secret" — 前端可用于校验是否返回了正确资源类型.
    pub resource: &'static str,
    pub decision: OverrideMode,
    /// 仅 mode=Disabled 且资源是 secret 时非 None (#161): 显式警告
    /// "该 secret 将明文转发到上游". 其他 mode 缺省 (skip_serializing_if,
    /// 向后兼容 — 旧客户端解析不到该字段).
    ///
    /// 仅对 secret 加: provider 的 Disabled 语义是 "禁止经此 provider 转发"
    /// (503 unavailable), 不存在放行敏感数据的问题, 无需警告.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<&'static str>,
}

/// secret decision=Disabled 时返回的警告文案 (SSOT, 前端直接展示 ack.warning).
pub(crate) const SECRET_DISABLED_WARNING: &str = "protection for this secret is disabled: it will be forwarded in plaintext \
     to upstream providers";

/// decision 通用流程: static 检查 (404) → set_decision → ack.
///
/// mode=Disabled + secret 时在 ack 上附 [`SECRET_DISABLED_WARNING`] (#161):
/// Disabled 对 secret 意味着 "明文放行" (与产品核心承诺相反), 必须在响应中显式警示.
pub(crate) fn decision_flow<T: CrudTable>(
    table: &T,
    kind_label: &'static str,
    id: String,
    mode: OverrideMode,
) -> Result<DecisionAck, ApiError> {
    if !table.has_static(&id) {
        return Err(ApiError::not_found(format!(
            "{kind_label} {id} is not a static id; decision does not apply"
        )));
    }
    table.set_decision(&id, mode).map_err(ApiError::from_any)?;
    let warning = if mode == OverrideMode::Disabled && kind_label == "secret" {
        // 服务端日志同步警示 (#161): 让不看 PATCH 响应体的运维也能在 sg 日志中
        // 发现 "该 secret 已被明文放行". 安全: 只记 id, 不记 value.
        tracing::warn!(
            secret_id = %id,
            "secret decision set to disabled: it will be forwarded in plaintext \
             to upstream providers"
        );
        Some(SECRET_DISABLED_WARNING)
    } else {
        None
    };
    Ok(DecisionAck {
        id,
        resource: kind_label,
        decision: mode,
        warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretTable;

    /// 构造含一个 static secret 的表 (决策端到端测试用).
    /// state 路径带 uuid (对齐 tests/integration.rs 惯例, 避免并行测试互踩).
    fn secret_table_with_static() -> SecretTable {
        use crate::secrets::SecretEntry;
        let state_path = std::path::PathBuf::from(format!(
            "/tmp/opencode/tmp/test-decision-ack-{}.toml",
            uuid::Uuid::new_v4()
        ));
        SecretTable::new(
            vec![SecretEntry {
                id: "s1".into(),
                name: None,
                category: crate::secrets::SecretCategory::ApiKey,
                value: "sk-live-qwerty987654".into(),
                value_file: None,
                mock_strategy: crate::mock::MockStrategy::default(),
            }],
            vec![],
            std::sync::Arc::new(parking_lot::RwLock::new(crate::config::Decisions::default())),
            state_path,
        )
    }

    /// #161: secret + disabled → ack.warning 非空 (明文放行警示);
    /// 其他 mode / provider 的 disabled → warning 缺省 (None, 序列化时省略).
    #[test]
    fn decision_ack_warning_only_for_secret_disabled() {
        let t = secret_table_with_static();

        let ack = decision_flow(&t, "secret", "s1".into(), OverrideMode::Disabled).unwrap();
        assert_eq!(ack.decision, OverrideMode::Disabled);
        let warning = ack.warning.expect("secret+disabled must carry warning");
        assert!(warning.contains("plaintext"), "warning wording: {warning}");

        // 切回 default: 无 warning.
        let ack = decision_flow(&t, "secret", "s1".into(), OverrideMode::Default).unwrap();
        assert!(ack.warning.is_none());
        // prefer_static: 无 warning.
        let ack = decision_flow(&t, "secret", "s1".into(), OverrideMode::PreferStatic).unwrap();
        assert!(ack.warning.is_none());

        // provider 的 disabled: 语义是禁转发 (非放行 secret), 无 warning.
        // (providers 表此处借 secret 表验证 flow 逻辑 — kind_label 决定 warning,
        //  与表类型无关; provider 表的同构行为由同一段代码保证.)
        let ack = decision_flow(&t, "provider", "s1".into(), OverrideMode::Disabled).unwrap();
        assert!(ack.warning.is_none());
    }

    /// 序列化向后兼容: 非 disabled 时 JSON 无 warning 字段 (旧客户端 shape 不变);
    /// disabled 时字段出现.
    #[test]
    fn decision_ack_json_warning_field_shape() {
        let t = secret_table_with_static();
        let ack = decision_flow(&t, "secret", "s1".into(), OverrideMode::Default).unwrap();
        let json = serde_json::to_string(&ack).unwrap();
        assert!(!json.contains("warning"), "default mode json: {json}");

        let ack = decision_flow(&t, "secret", "s1".into(), OverrideMode::Disabled).unwrap();
        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("warning"), "disabled mode json: {json}");
        assert!(
            !json.contains("sk-live"),
            "ack must not leak secret value: {json}"
        );
    }
}
