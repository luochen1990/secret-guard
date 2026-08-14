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
//! - [`create_flow`]: into-entry → id 空则 Uuid → validate 钩子 → 冲突检查 →
//!   upsert (Updated 视为并发冲突) → 查回 effective → 201.
//! - [`update_flow`]: 存在性检查 → build 钩子 → 填 id → validate 钩子 → upsert →
//!   查回 → 200.
//! - [`delete_flow`]: delete → DeleteOutcome 分类 (static-only 409 / 不存在 404) → 204.
//! - [`decision_flow`]: static 检查 → set_decision → ack.

use axum::http::StatusCode;

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
) -> Result<&'static str, ApiError> {
    match outcome {
        DeleteOutcome::Deleted => Ok(""), // 204 No Content 的空 body.
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

/// create 通用流程: 构造 entry → id 空则 Uuid → validate 钩子 → effective 冲突检查 →
/// upsert (Updated = 并发创建, 409) → 查回 effective 视图.
///
/// 返回 `(StatusCode::CREATED, effective_view)`, handler 加 NO_STORE + Json 包装.
pub(crate) fn create_flow<T: CrudTable>(
    table: &T,
    kind_label: &str,
    build: impl FnOnce() -> Result<T::Entry, ApiError>,
    validate: impl FnOnce(&mut T::Entry) -> Result<(), ApiError>,
) -> Result<(StatusCode, T::Effective), ApiError> {
    let mut entry = build()?;
    // create 模式: 若没传 id, 自动生成.
    if entry.entry_id().is_empty() {
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
    let ev = effective_find_by_id(table.snapshot(), saved.entry_id());
    Ok((StatusCode::CREATED, ev))
}

/// update 通用流程: 存在性检查 (404) → build 钩子 (构造 entry + 类型特定预处理) →
/// 填 path id → validate 钩子 → upsert → 查回 effective 视图.
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
/// 返回 204 的空 body.
pub(crate) fn delete_flow<T: CrudTable>(
    table: &T,
    kind_label: &str,
    id: &str,
) -> Result<&'static str, ApiError> {
    // 若 dynamic 有此 id, 删除 (覆盖关系下仅移除 override, static 保留).
    // 若 dynamic 无此 id 但 static 有, 拒绝删除 (static 永不可写; 提示用 disabled decision).
    // 用 has_static 直接查 static 层, 不受 decision 影响 (disabled 的 id 也能正确报 409).
    let outcome = table.delete(id).map_err(ApiError::from_any)?;
    classify_delete_outcome(outcome, table.has_static(id), kind_label, id)
}

/// decision 通用流程: static 检查 (404) → set_decision → ack.
pub(crate) fn decision_flow<T: CrudTable>(
    table: &T,
    kind_label: &'static str,
    id: String,
    mode: OverrideMode,
) -> Result<(String, &'static str, OverrideMode), ApiError> {
    if !table.has_static(&id) {
        return Err(ApiError::not_found(format!(
            "{kind_label} {id} is not a static id; decision does not apply"
        )));
    }
    table.set_decision(&id, mode).map_err(ApiError::from_any)?;
    Ok((id, kind_label, mode))
}
