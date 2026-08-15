//! 命令行参数 schema.
//!
//! 当前仅暴露 `run` 子命令, 后续可扩展 (例如 `web`, `redact` 等离线模式).
//! `Option<T>` 表示"是否被显式指定", 用于区分 CLI 显式覆盖 vs 配置文件回退.

use clap::{Args, Parser, Subcommand};

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

/// 网关启动参数. `Option<T>` 字段表示 "CLI 未显式指定时回退到 config".
#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    /// 监听地址 (未指定时回退到 `server.host` 配置, 默认 127.0.0.1).
    #[arg(long, env = "SG_HOST")]
    pub host: Option<String>,

    /// 监听端口 (未指定时回退到 `server.port` 配置, 默认 8787).
    #[arg(long, env = "SG_PORT")]
    pub port: Option<u16>,

    /// **声明式**配置文件路径 (TOML). 进程内只读.
    #[arg(
        long,
        short = 'c',
        env = "SG_CONFIG",
        default_value = "secret-guard.toml"
    )]
    pub config: std::path::PathBuf,

    /// **动态状态**文件路径 (TOML). WebUI 写回. 缺省时由 static config 路径派生
    /// (例如 `secret-guard.toml` → `secret-guard.state.toml`).
    #[arg(long, env = "SG_STATE")]
    pub state: Option<std::path::PathBuf>,
}

impl Default for RunArgs {
    fn default() -> Self {
        Self {
            host: None,
            port: None,
            config: std::path::PathBuf::from("secret-guard.toml"),
            state: None,
        }
    }
}
