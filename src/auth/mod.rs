//! 认证骨架: OIDC 登录 (浏览器 WebUI) + 本地 API key (SDK 转发路径).
//!
//! # 双轨认证
//!
//! | 流量 | 路径 | 认证方式 |
//! |---|---|---|---|
//! | 浏览器 WebUI | `/__sg/*` | OIDC Authorization Code + PKCE → cookie session |
//! | SDK 转发 | `/{o\|a\|g\|l}/*` | 本地 API key (`Authorization: Bearer sg_...`) |
//!
//! 浏览器登录后, WebUI 提供 "生成 API key" 入口, secret-guard 本地签发随机 key
//! (存 SHA-256 hash, 明文仅签发时返回一次). SDK 配置 `api_key=<生成的 key>`,
//! 转发路径的 middleware 校验 key → 解析 tenant_id → 注入 request extension.
//!
//! # 安全边界
//!
//! - API key 校验在 middleware 层完成, **不进入 LLM body redact pipeline**.
//!   原因: proxy.rs::apply_provider_auth 会用 provider 的真实 api_key 覆盖
//!   Authorization header, 客户端的 API key 不会到达上游.
//! - PKCE verifier + nonce **必须存服务端 session**, 绝不放 cookie.
//! - API key 明文永不持久化, 只存 hash.
//!
//! # 配置
//!
//! `secret-guard.toml` 的 `[auth]` 段:
//! ```toml
//! [auth]
//! enabled = true
//!
//! [auth.oidc]
//! issuer_url = "https://auth.example.com/application/o/secret-guard/"
//! client_id = "secret-guard"
//! client_secret_file = "/run/credentials/secret-guard.service/oidc_client_secret"
//! ```
//!
//! `enabled = false` (默认) = 单用户模式, 所有路由无认证 (向后兼容).
//!
//! # 模块结构
//!
//! - [`apikey`] — ApiKeyStore + ApiKeyEntry + 签发/校验.
//! - [`oidc`] — OidcBackend (axum-login AuthnBackend) + User + 登录流程 handler.
//! - [`session`] — SessionManagerLayer 装配.
//! - [`middleware`] — require_api_key middleware + AuthenticatedTenant.

pub mod apikey;
pub mod handlers;
pub mod middleware;
pub mod oidc;
pub mod session;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use apikey::{ApiKeyEntry, ApiKeyStore};
pub use middleware::{AuthenticatedTenant, require_api_key};
pub use oidc::{OidcBackend, OidcCredentials, OidcError, User};
pub use session::build_session_layer;

/// 认证配置 (static config 的 `[auth]` 段).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// 是否启用认证. `false` (默认) = 单用户模式, 所有路由无认证.
    #[serde(default)]
    pub enabled: bool,
    /// OIDC 配置. `enabled = true` 时必须存在 (启动时 fail-fast).
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
}

/// OIDC Provider 配置 (static config 的 `[auth.oidc]` 段).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// IdP 的 issuer URL (OIDC Discovery 端点).
    /// 例如: `https://accounts.google.com` 或
    /// `https://auth.example.com/application/o/secret-guard/`.
    pub issuer_url: String,
    /// OIDC client id (在 IdP 注册时分配).
    pub client_id: String,
    /// 可选: 从文件读取 client secret (与 Provider.api_key_file 对称).
    /// 公开客户端 (PKCE-only) 可省略.
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
}

impl AuthConfig {
    /// 启动时校验: enabled = true 时 oidc 配置必须存在且 issuer_url 非空.
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_disabled_by_default() {
        let cfg = AuthConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.validate().is_ok(), "disabled config is always valid");
    }

    #[test]
    fn enabled_without_oidc_fails() {
        let cfg = AuthConfig {
            enabled: true,
            oidc: None,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn enabled_with_empty_issuer_fails() {
        let cfg = AuthConfig {
            enabled: true,
            oidc: Some(OidcConfig {
                issuer_url: "  ".into(),
                client_id: "x".into(),
                client_secret_file: None,
            }),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn enabled_with_valid_oidc_passes() {
        let cfg = AuthConfig {
            enabled: true,
            oidc: Some(OidcConfig {
                issuer_url: "https://auth.example.com".into(),
                client_id: "secret-guard".into(),
                client_secret_file: None,
            }),
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn auth_config_parses_from_toml() {
        let toml_str = r#"
[auth]
enabled = true

[auth.oidc]
issuer_url = "https://auth.example.com"
client_id = "sg"
"#;
        // 模拟顶层 Config 的 auth 字段反序列化.
        #[derive(Deserialize)]
        struct Wrapper {
            auth: AuthConfig,
        }
        let w: Wrapper = toml::from_str(toml_str).unwrap();
        assert!(w.auth.enabled);
        assert_eq!(w.auth.oidc.as_ref().unwrap().client_id, "sg");
    }
}
