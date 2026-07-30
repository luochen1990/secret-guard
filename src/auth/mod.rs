//! 认证骨架: OIDC 登录 (浏览器 WebUI) + 本地 API key (SDK 转发路径).
//!
//! # "只认证, 不隔离" 哲学
//!
//! ApiKeyStore 在 server.rs 中**无条件构造** (与 `auth.enabled` 无关), 让 WebUI
//! 在单用户模式下也能管理和预配置 key (用户可先配好, 等启用 auth 后即可使用).
//! `/api/api-keys` CRUD 路由无条件挂载 (在 `web::router()`), handler 不做用户隔离 —
//! 所有 (登录的) 用户共享同一份 key 池. 设计理由见 `src/web/api.rs` 中 `/api-keys` 段.
//! `require_api_key` middleware 仅在 auth 启用时挂载到 forwarding 路径.
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
    /// 可选: OIDC 回调 URL (覆盖由 host+port 派生的默认值).
    ///
    /// 需显式配置的场景: 监听地址非浏览器可达时 (如 `0.0.0.0` 或经反向代理以独立域名暴露),
    /// 因为默认回退值含监听地址, IdP 会拒绝.
    ///
    /// **path 必须是 `/__sg/oauth2/callback`** (与内部 axum 路由一致, 见 `server.rs`);
    /// 只能换 scheme/host/port, 换 path 会导致 IdP 回跳后 404.
    ///
    /// 留空 (默认) 时, server.rs 回退为 `http://{host}:{port}/__sg/oauth2/callback`,
    /// 与历史行为一致.
    #[serde(default)]
    pub redirect_url: Option<String>,
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
            // redirect_url 校验前置到启动时 (集中式预处理), 避免错误延迟到 OIDC
            // Discovery 阶段才暴露. 不引入 url crate 作直接依赖, 只做最小校验:
            // 必须是 http/https scheme + path 必须是 /__sg/oauth2/callback (与 axum 路由一致).
            if let Some(ru) = oidc.redirect_url.as_ref() {
                let trimmed = ru.trim();
                if trimmed.is_empty() {
                    return Err("[auth.oidc] redirect_url must not be empty".into());
                }
                if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
                    return Err(format!(
                        "[auth.oidc] redirect_url '{trimmed}' must start with http:// or https://"
                    ));
                }
                if !trimmed.ends_with("/__sg/oauth2/callback") {
                    return Err(format!(
                        "[auth.oidc] redirect_url '{trimmed}' must end with /__sg/oauth2/callback \
                         (axum callback route, only scheme/host/port can vary)"
                    ));
                }
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

    // ─── OidcConfig: redirect_url 字段 serde 行为 ────────────────────────────
    // pin 住 serde 默认行为, 防止未来重构 (改成必填 / 改名) 静默破坏既有配置文件.

    #[test]
    fn oidc_config_redirect_url_defaults_to_none() {
        // 老格式 (无 redirect_url 字段) 必须仍能解析为 None.
        let toml_text = r#"
            issuer_url = "https://idp.example.com"
            client_id = "sg"
        "#;
        let oidc: OidcConfig = toml::from_str(toml_text).expect("toml parse");
        assert_eq!(oidc.issuer_url, "https://idp.example.com");
        assert_eq!(oidc.client_id, "sg");
        assert!(oidc.redirect_url.is_none());
        assert!(oidc.client_secret_file.is_none());
    }

    #[test]
    fn oidc_config_redirect_url_parses_when_set() {
        // 新格式 (显式配置 redirect_url) 必须正确解析.
        let toml_text = r#"
            issuer_url = "https://idp.example.com"
            client_id = "sg"
            redirect_url = "https://sg.example.com/__sg/oauth2/callback"
        "#;
        let oidc: OidcConfig = toml::from_str(toml_text).expect("toml parse");
        assert_eq!(
            oidc.redirect_url.as_deref(),
            Some("https://sg.example.com/__sg/oauth2/callback")
        );
    }

    // ─── validate: redirect_url 前置校验 (仅 enabled=true 时触发) ─────────────
    //
    // 与 issuer_url/client_id 对齐: 把"明显误配"在启动时 fail-fast, 而非延迟到
    // OIDC Discovery 阶段才暴露. 校验两条契约: (1) http/https scheme;
    // (2) path 结尾 /__sg/oauth2/callback (与 axum callback 路由一致).

    /// 辅助: 构造一个 enabled=true 的 AuthConfig, oidc 必填字段已填合法值,
    /// 只留 redirect_url 给调用方覆盖.
    fn auth_enabled_cfg(redirect_url: Option<&str>) -> AuthConfig {
        AuthConfig {
            enabled: true,
            oidc: Some(OidcConfig {
                issuer_url: "https://idp.example.com".into(),
                client_id: "sg".into(),
                client_secret_file: None,
                redirect_url: redirect_url.map(str::to_string),
            }),
            api_keys: vec![],
        }
    }

    #[test]
    fn validate_redirect_url_none_passes() {
        // enabled=true 且 redirect_url 留空: 与历史行为兼容, 必须 ok.
        assert!(auth_enabled_cfg(None).validate().is_ok());
    }

    #[test]
    fn validate_redirect_url_valid_https_passes() {
        // 合法 https + 正确 path: ok.
        assert!(
            auth_enabled_cfg(Some("https://sg.example.com/__sg/oauth2/callback"))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_redirect_url_rejects_empty() {
        let err = auth_enabled_cfg(Some("   ")).validate().unwrap_err();
        assert!(err.contains("redirect_url must not be empty"), "got: {err}");
    }

    #[test]
    fn validate_redirect_url_rejects_non_http_scheme() {
        let err = auth_enabled_cfg(Some("ftp://sg.example.com/__sg/oauth2/callback"))
            .validate()
            .unwrap_err();
        assert!(err.contains("must start with http"), "got: {err}");
    }

    #[test]
    fn validate_redirect_url_rejects_wrong_path() {
        // scheme 对但 path 不是 /__sg/oauth2/callback → 会被 IdP 回跳后 404, 前置拒绝.
        let err = auth_enabled_cfg(Some("https://sg.example.com/oauth2/callback"))
            .validate()
            .unwrap_err();
        assert!(err.contains("/__sg/oauth2/callback"), "got: {err}");
    }

    #[test]
    fn validate_redirect_url_skipped_when_auth_disabled() {
        // enabled=false 时 redirect_url 校验必须跳过 (与 issuer_url/client_id 行为一致).
        let mut cfg = auth_enabled_cfg(Some("not-a-url"));
        cfg.enabled = false;
        assert!(cfg.validate().is_ok());
    }

    // ─── StaticApiKey::resolve: 三条纯逻辑分支 ──────────────────────────────
    //
    // resolve 是启动期 fail-fast 校验的核心: key 与 key_file 互斥, 缺一不可.
    // 守卫: (1) key 直取, (2) key_file 读取+trim, (3) 互斥违反, (4) 都缺失.

    #[test]
    fn resolve_key_directly() {
        let sk = StaticApiKey {
            label: "ci".into(),
            key: Some("sg_direct_123".into()),
            key_file: None,
        };
        assert_eq!(
            sk.resolve(std::path::Path::new(".")).unwrap(),
            "sg_direct_123"
        );
    }

    #[test]
    fn resolve_key_file_trims_whitespace() {
        // key_file 内容会被 trim (防文件末尾换行污染 key). 写临时文件验证.
        // 临时文件放在 /tmp/opencode/ (放行目录); uuid 防并发冲突; 残留依赖 CI tmpfs 周期重置.
        let dir = std::path::PathBuf::from("/tmp/opencode");
        std::fs::create_dir_all(&dir).unwrap();
        let kf = dir.join(format!("sg-resolve-{}.txt", uuid::Uuid::new_v4()));
        std::fs::write(&kf, "  sg_from_file_456  \n").unwrap();
        let sk = StaticApiKey {
            label: "ci".into(),
            key: None,
            key_file: Some(kf),
        };
        assert_eq!(
            sk.resolve(&dir).unwrap(),
            "sg_from_file_456",
            "key_file content must be trimmed"
        );
    }

    #[test]
    fn resolve_rejects_both_key_and_key_file() {
        let dir = std::path::PathBuf::from("/tmp/opencode");
        std::fs::create_dir_all(&dir).unwrap();
        // 文件内容无关紧要 — 仅需文件存在以触发互斥校验.
        let kf = dir.join(format!("sg-both-{}.txt", uuid::Uuid::new_v4()));
        std::fs::write(&kf, "placeholder").unwrap();
        let sk = StaticApiKey {
            label: "ci".into(),
            key: Some("sg_a".into()),
            key_file: Some(kf),
        };
        let err = sk.resolve(std::path::Path::new(".")).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn resolve_rejects_neither_key_nor_key_file() {
        let sk = StaticApiKey {
            label: "ci".into(),
            key: None,
            key_file: None,
        };
        let err = sk.resolve(std::path::Path::new(".")).unwrap_err();
        assert!(
            err.to_string().contains("must specify either"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_rejects_empty_static_label() {
        // validate 的空 label 错误分支 (CRUD 前置校验, 防止空 label key 进 store).
        let cfg = AuthConfig {
            api_keys: vec![StaticApiKey {
                label: "   ".into(),
                key: Some("sg_x".into()),
                key_file: None,
            }],
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("label must not be empty"), "got: {err}");
    }
}
