//! secret-guard 二进制入口.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use secret_guard::{
    cli::{Cli, Command},
    config::Config,
    server,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let Command::Run(args) = cli.command.unwrap_or(Command::Run(args::default_run()));

    let cfg = Config::load_or_default(&args.config)?;
    let host = if cli_override(&args.host) {
        args.host.clone()
    } else {
        cfg.server.host.clone()
    };
    let port = if args.port != 8787 || env_set("SG_PORT") {
        args.port
    } else {
        cfg.server.port
    };
    let upstream = args
        .upstream
        .clone()
        .unwrap_or_else(|| cfg.upstream.base.clone());

    tracing::info!(
        listen = format!("{host}:{port}"),
        upstream = %upstream,
        config = ?args.config,
        "starting secret-guard"
    );

    server::serve(&host, port, upstream, 1024).await
}

// 检查 args.host 是否被显式指定: 当前实现以 default 值 "127.0.0.1" 为信号.
// (clap 4 的 ArgAction::Set 显式 vs 默认的区分能力有限, MVP 暂用此简化策略.)
mod args {
    use secret_guard::RunArgs;
    pub fn default_run() -> RunArgs {
        RunArgs {
            host: "127.0.0.1".into(),
            port: 8787,
            upstream: None,
            config: "secret-guard.toml".into(),
        }
    }
}

fn cli_override(_v: &str) -> bool {
    env_set("SG_HOST")
}

fn env_set(key: &str) -> bool {
    std::env::var_os(key).is_some()
}
