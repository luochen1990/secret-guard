//! 命令行参数 schema.
//!
//! 当前仅暴露 `run` 子命令,后续可扩展 (例如 `web`, `redact` 等离线模式).

use clap::{Parser, Subcommand};

/// secret-guard: 防止 agent 不经意间把 secret 泄露到 LLM Provider.
#[derive(Parser, Debug)]
#[command(name = "secret-guard", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// 启动 LLM 网关 (默认行为: 不传子命令时也启动).
    Run(RunArgs),
}

/// 网关启动参数.
#[derive(clap::Args, Debug, Clone)]
pub struct RunArgs {
    /// 监听地址.
    #[arg(long, default_value = "127.0.0.1", env = "SG_HOST")]
    pub host: String,

    /// 监听端口.
    #[arg(long, default_value = "8787", env = "SG_PORT")]
    pub port: u16,

    /// 上游 LLM Provider base URL (例如 https://api.anthropic.com).
    #[arg(long, env = "SG_UPSTREAM")]
    pub upstream: Option<String>,

    /// 配置文件路径 (TOML).
    #[arg(
        long,
        short = 'c',
        env = "SG_CONFIG",
        default_value = "secret-guard.toml"
    )]
    pub config: std::path::PathBuf,
}

impl RunArgs {
    /// 若未显式指定 upstream,默认使用 Anthropic API.
    pub fn upstream_or_default(&self) -> String {
        self.upstream
            .clone()
            .unwrap_or_else(|| "https://api.anthropic.com".to_string())
    }
}
