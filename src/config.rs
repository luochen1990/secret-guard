//! 配置文件 schema (TOML + serde).
//!
//! MVP 阶段只暴露最小字段集: 监听地址、上游 URL、(为后续步骤预留) secrets 列表.
//! 第三步会扩展 secret table; 此处先建立 SSOT 形状.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// 顶层配置.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// 服务监听相关.
    #[serde(default)]
    pub server: ServerConfig,

    /// 上游 LLM Provider.
    #[serde(default)]
    pub upstream: UpstreamConfig,

    /// (第三步填充) secret 注册表.
    #[serde(default)]
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8787,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamConfig {
    /// LLM Provider base URL, 末尾不带 `/`.
    pub base: String,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            base: "https://api.anthropic.com".to_string(),
        }
    }
}

/// (第三步) secret 注册表, 当前为占位.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretsConfig {
    /// 真实 secret 明文列表 (后续可换为指向 keyring / 文件路径).
    pub entries: Vec<String>,
}

impl Config {
    /// 从 TOML 文件加载; 若文件不存在返回默认值.
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
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
