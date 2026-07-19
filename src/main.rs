//! secret-guard 二进制入口.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use secret_guard::{
    cli::{Cli, Command, RunArgs},
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
    let args = match cli.command {
        Some(Command::Run(args)) => args,
        None => RunArgs::default(),
    };

    let cfg = Config::load_or_default(&args.config)?;
    let host = args.host.unwrap_or(cfg.server.host);
    let port = args.port.unwrap_or(cfg.server.port);
    let upstream = args.upstream.unwrap_or(cfg.upstream.base);
    let records_capacity = cfg.server.records_capacity;

    tracing::info!(
        listen = format!("{host}:{port}"),
        upstream = %upstream,
        config = ?args.config,
        records_capacity,
        "starting secret-guard"
    );

    server::serve(&host, port, upstream, records_capacity).await
}
