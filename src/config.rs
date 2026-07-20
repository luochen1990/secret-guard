//! 配置文件 schema (TOML + serde).
//!
//! 暴露字段集: 监听地址、记录容量、providers 列表、secrets 列表.
//! - `providers` 与运行时 [`crate::provider::ProviderTable`] 共享同一份 `Vec<Provider>`.
//! - `secrets` 与运行时 [`crate::secrets::SecretTable`] 共享同一份 `Vec<SecretEntry>`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::provider::Provider;
use crate::secrets::SecretEntry;

/// 顶层配置.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// 服务监听相关.
    #[serde(default)]
    pub server: ServerConfig,

    /// LLM provider 列表 (替代旧版单一 `upstream`).
    #[serde(default)]
    pub providers: Vec<Provider>,

    /// Secret 注册表.
    #[serde(default)]
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// 内存中保留的转发记录条数上限 (FIFO 淘汰).
    pub records_capacity: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8787,
            records_capacity: 1024,
        }
    }
}

/// Secret 注册表.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretsConfig {
    /// 真实 secret 列表.
    pub entries: Vec<SecretEntry>,
}

impl Config {
    /// 从 TOML 文件加载; 若文件不存在返回默认值并 warn.
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            tracing::warn!(
                path = %path.display(),
                "config file not found; using defaults"
            );
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read config {}: {e}", path.display()))?;
        let cfg: Self = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse config {}: {e}", path.display()))?;
        Ok(cfg)
    }

    /// 序列化回 TOML (供 Web UI 写回).
    pub fn to_toml(&self) -> anyhow::Result<String> {
        toml::to_string_pretty(self).map_err(|e| anyhow::anyhow!("serialize config: {e}"))
    }
}
