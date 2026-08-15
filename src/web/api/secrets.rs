//! secrets CRUD: `GET/POST/PUT/DELETE /secrets[/{id}]` + `PATCH /{id}/decision`.
//!
//! 从 api.rs 单文件拆出 (见 #146 残留 1). CRUD 流程骨架在 [`super::crud`]
//! (泛型, 与 providers 共享), 本文件只承载 secret 特有的 entry 构造与校验.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::config::OverrideMode;
use crate::secrets::{EffectiveSecret, SecretCategory, SecretEntry};
use crate::state::{AppState, NO_STORE};

use super::crud::{Created, DecisionRequest, create_flow, decision_flow, delete_flow, update_flow};
use super::error::ApiError;

pub async fn list_secrets(State(state): State<AppState>) -> impl IntoResponse {
    let secrets: Vec<EffectiveSecret> = state.secrets.effective_snapshot();
    let categories: Vec<&'static str> = SecretCategory::ALL.iter().map(|(_, s)| *s).collect();
    let decisions: Vec<&'static str> = OverrideMode::ALL.iter().map(|(_, s)| *s).collect();
    (
        NO_STORE,
        Json(ListSecretsResponse {
            secrets,
            categories,
            decisions,
        }),
    )
}

pub async fn create_secret(
    State(state): State<AppState>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let created: Created<EffectiveSecret> = create_flow(
        &state.secrets,
        "secret",
        || payload.into_entry(),
        |entry| {
            // 完整 validate+resolve 序列 (互斥 / 文件可读 / value 内容合法).
            // 必须在 upsert 前跑: 否则内存中 value 为空 (value_file 模式), 当次 redact
            // 不识别此 secret. 也是 WebUI 路径上互斥校验的执行点 (见 into_entry 的注释
            // — 那里只做基础字段校验).
            entry
                .validate_and_resolve(&state.global_mock_prefix)
                .map_err(ApiError::validation)
        },
    )?;
    Ok((StatusCode::CREATED, NO_STORE, Json(created)))
}

pub async fn update_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 完整 validate+resolve 序列, 与 create_secret 一致 (见那里的注释).
    let ev = update_flow(
        &state.secrets,
        "secret",
        &id,
        || payload.into_entry(),
        |entry| {
            entry
                .validate_and_resolve(&state.global_mock_prefix)
                .map_err(ApiError::validation)
        },
    )?;
    Ok((StatusCode::OK, NO_STORE, Json(ev)))
}

pub async fn delete_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    delete_flow(&state.secrets, "secret", &id)?;
    Ok((StatusCode::NO_CONTENT, NO_STORE, ""))
}

/// 切换对 static id 的 per-item 决策. body: `{"mode": "default|prefer_static|disabled"}`.
///
/// 响应体是简短 ack (`{id, decision}`), 不返回 effective view — 因为切换到 `Disabled`
/// 后该 id 会从 effective view 中消失, 前端应在收到 200 后重新调 list 拉新状态.
///
/// 用 [`crate::secrets::SecretTable::has_static`] 直接查 static 层, 这样
/// decision=Disabled 状态下也能切回 Default / PreferStatic.
///
/// 注: `SecretTable` 现为 `DynamicTable<SecretEntry>` 的别名, has_static 是
/// 泛型 [`DynamicTable::has_static`](crate::config::DynamicTable) 提供的方法.
pub async fn set_secret_decision(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<DecisionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mode = payload.into_mode()?;
    let ack = decision_flow(&state.secrets, "secret", id, mode)?;
    Ok((StatusCode::OK, NO_STORE, Json(ack)))
}

#[derive(Serialize)]
pub(crate) struct ListSecretsResponse {
    pub secrets: Vec<EffectiveSecret>,
    pub categories: Vec<&'static str>,
    /// 所有合法的 OverrideMode 字符串名, 供前端渲染 decision 选择器.
    pub decisions: Vec<&'static str>,
}

/// 创建/更新 secret 的请求 body.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateSecretRequest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub category: Option<SecretCategory>,
    /// 直接值. 与 `value_file` 互斥 (同时设置会在 `validate()` 报错).
    /// WebUI 默认用此字段 (用户手填); 留空且提供了 `value_file` 则走文件读取模式.
    #[serde(default)]
    pub value: String,
    /// 可选: 从文件路径读取 secret 明文. 与 `value` 互斥.
    /// 主要用于 static config (sops 注入), WebUI 创建 dynamic-only secret 时一般不用,
    /// 但保留字段以支持 "dynamic secret 引用 sops 解密路径" 的高级用例.
    #[serde(default)]
    pub value_file: Option<String>,
    /// 可选: mock 策略. 省略时后端用 [`crate::mock::MockStrategy::default`]
    /// (Auto + resolve 时 infer gen spec).
    #[serde(default)]
    pub mock_strategy: Option<crate::mock::MockStrategy>,
}

impl CreateSecretRequest {
    fn into_entry(self) -> Result<SecretEntry, ApiError> {
        // 早期字段级反馈: value 与 value_file 至少一个非空. 互斥校验和 value 内容校验
        // 由后续 handler 中的 SecretEntry::validate_and_resolve 统一执行 (SSOT).
        if self.value.is_empty() && self.value_file.is_none() {
            return Err(ApiError::validation(
                "either value or value_file must be set",
            ));
        }
        Ok(SecretEntry {
            id: self.id.unwrap_or_default(),
            name: self.name.filter(|s| !s.trim().is_empty()),
            category: self.category.unwrap_or_default(),
            value: self.value,
            value_file: self.value_file.map(std::path::PathBuf::from),
            mock_strategy: self.mock_strategy.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_validates_empty_value() {
        let req = CreateSecretRequest {
            id: None,
            name: None,
            category: None,
            value: String::new(),
            value_file: None,
            mock_strategy: None,
        };
        assert!(req.into_entry().is_err());
    }

    #[test]
    fn create_request_into_entry_does_not_check_mutex() {
        // into_entry 故意不做互斥校验 (由 SecretEntry::validate_and_resolve 在 handler 层做, SSOT).
        // 这里断言此契约: 同时填 value + value_file 时 into_entry 仍然成功,
        // 把校验责任显式交给后续 validate_and_resolve.
        let req = CreateSecretRequest {
            id: Some("x".into()),
            name: None,
            category: None,
            value: "direct-value".into(),
            value_file: Some("/some/path".into()),
            mock_strategy: None,
        };
        let entry = req.into_entry().expect("into_entry skips mutex check");
        // 但 SecretEntry::validate_and_resolve 必须拒绝此组合.
        let mut entry = entry;
        let err = entry.validate_and_resolve("").unwrap_err();
        assert!(
            err.contains("both value and value_file"),
            "validate_and_resolve should reject mutex violation: {err}"
        );
    }

    #[test]
    fn decision_request_parses_valid_modes() {
        for (_, name) in OverrideMode::ALL {
            let req = DecisionRequest {
                mode: name.to_string(),
            };
            assert!(req.into_mode().is_ok());
        }
    }

    #[test]
    fn decision_request_rejects_unknown_mode() {
        let req = DecisionRequest {
            mode: "bogus".to_string(),
        };
        assert!(req.into_mode().is_err());
    }
}
