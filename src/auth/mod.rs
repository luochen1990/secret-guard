//! 认证骨架: OIDC 登录 (浏览器 WebUI) + 本地 API key (SDK 转发路径).
//!
//! # 静态预设 API key
//!
//! 用户可在 `secret-guard.toml` 中预设 API key (如 CI/CD 场景), 与 WebUI 签发的 key
//! 一起在 WebUI 列出. 静态 key 不可删除, 只能 disable/enable.
//!
//! ```toml
//! [[auth.api_keys]]
//! label = "ci-pipeline"
//! key = "sg_abc123..."        # 或 key_file = "/run/credentials/..."
//! ```

pub mod apikey;
pub mod handlers;
pub mod middleware;
pub mod oidc;
pub mod session;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use apikey::{ApiKeyEntry, ApiKeyStore};
pub use middleware::{AuthenticatedTenant, require_api_key};
pub use oidc::{OidcBackend, OidcCredentials, OidcError, User};
pub use session::build_session_layer;

/// 认证配置 (static config 的 `[auth]` 段).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    /// 静态预设 API key 列表.
    #[serde(default)]
    pub api_keys: Vec<StaticApiKey>,
}

/// 静态预设 API key. 明文由用户直接写在配置文件中, 启动时 hash 后注入 ApiKeyStore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticApiKey {
    pub label: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
}

impl StaticApiKey {
    /// resolve 明文: key 与 key_file 互斥.
    pub fn resolve(&self, config_path: &Path) -> anyhow::Result<String> {
        match (&self.key, &self.key_file) {
            (Some(k), None) => Ok(k.clone()),
            (None, Some(path)) => {
                let abs = config_path.parent().unwrap_or(Path::new(".")).join(path);
                Ok(std::fs::read_to_string(&abs)
                    .map_err(|e| anyhow::anyhow!("read key_file {}: {e}", abs.display()))?
                    .trim()
                    .into())
            }
            (Some(_), Some(_)) => anyhow::bail!(
                "[auth.api_keys] '{}': key and key_file are mutually exclusive",
                self.label
            ),
            (None, None) => anyhow::bail!(
                "[auth.api_keys] '{}': must specify either key or key_file",
                self.label
            ),
        }
    }
}

/// OIDC Provider 配置 (static config 的 `[auth.oidc]` 段).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
}

impl AuthConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled {
            let oidc = self
                .oidc
                .as_ref()
                .ok_or_else(|| "[auth] enabled = true but [auth.oidc] is missing".to_string())?;
            if oidc.issuer_url.trim().is_empty() {
                return Err("[auth.oidc] issuer_url must not be empty".into());
            }
            if oidc.client_id.trim().is_empty() {
                return Err("[auth.oidc] client_id must not be empty".into());
            }
        }
        let mut seen = std::collections::HashSet::new();
        for (i, ak) in self.api_keys.iter().enumerate() {
            if ak.label.trim().is_empty() {
                return Err(format!(
                    "[auth.api_keys] index {i}: label must not be empty"
                ));
            }
            if !seen.insert(ak.label.as_str()) {
                return Err(format!("[auth.api_keys] duplicate label '{}'", ak.label));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_disabled_by_default() {
        assert!(!AuthConfig::default().enabled);
        assert!(AuthConfig::default().validate().is_ok());
    }

    #[test]
    fn enabled_without_oidc_fails() {
        assert!(
            AuthConfig {
                enabled: true,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn duplicate_static_labels_fail() {
        let cfg = AuthConfig {
            api_keys: vec![
                StaticApiKey {
                    label: "ci".into(),
                    key: Some("sg_abc".into()),
                    key_file: None,
                },
                StaticApiKey {
                    label: "ci".into(),
                    key: Some("sg_xyz".into()),
                    key_file: None,
                },
            ],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
