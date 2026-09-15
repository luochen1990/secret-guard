//! secret-guard 二进制入口.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use secret_guard::{
    cli::{Cli, Command, RunArgs},
    config::{Config, DynamicState},
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

    // 双层加载: static 来自 secret-guard.toml; dynamic 来自 state.toml.
    let static_cfg = Config::load_or_default(&args.config)?;
    let state_path = args
        .state
        .clone()
        .unwrap_or_else(|| default_state_path(&args.config));
    // dynamic state 的 secret 校验用 static config 的 global_mock_prefix.
    let global_mock_prefix = static_cfg.redact.global_mock_prefix.clone();
    let on_probe_exhausted = static_cfg.redact.on_probe_exhausted;
    let on_unsupported_protocol = static_cfg.redact.on_unsupported_protocol;
    let on_fallback_restore = static_cfg.redact.on_fallback_restore;
    let redacted_headers = static_cfg.redact.redacted_headers;
    let dyn_state = DynamicState::load_or_empty(&state_path, &global_mock_prefix)?;

    let host = args.host.unwrap_or_else(|| static_cfg.server.host.clone());
    let port = args.port.unwrap_or(static_cfg.server.port);
    let records_capacity = static_cfg.server.records_capacity;
    let upstream_timeouts = secret_guard::config::UpstreamTimeouts::from(&static_cfg.server);

    tracing::info!(
        listen = format!("{host}:{port}"),
        static_config = ?args.config,
        state_file = ?state_path,
        records_capacity,
        static_providers = static_cfg.providers.len(),
        static_secrets = static_cfg.secrets.entries.len(),
        dynamic_providers = dyn_state.providers.len(),
        dynamic_secrets = dyn_state.secrets.len(),
        decisions = dyn_state.decisions.providers.len() + dyn_state.decisions.secrets.len(),
        on_probe_exhausted = ?on_probe_exhausted,
        on_unsupported_protocol = ?on_unsupported_protocol,
        on_fallback_restore = ?on_fallback_restore,
        "starting secret-guard"
    );

    server::serve(
        &host,
        port,
        records_capacity,
        static_cfg.providers,
        static_cfg.secrets.entries,
        dyn_state,
        state_path,
        args.config.clone(),
        static_cfg.auth,
        global_mock_prefix,
        on_probe_exhausted,
        on_unsupported_protocol,
        on_fallback_restore,
        redacted_headers,
        upstream_timeouts,
        static_cfg.usage,
        static_cfg.server.allowed_domains,
    )
    .await
}

/// state.toml 的默认路径: 与 static config 同目录, 文件名加 `.state` 后缀.
/// 例如 `secret-guard.toml` → `secret-guard.state.toml`.
fn default_state_path(static_config: &Path) -> PathBuf {
    let file_name = static_config
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("secret-guard.toml");
    let new_name = if let Some(stem) = file_name.strip_suffix(".toml") {
        format!("{stem}.state.toml")
    } else {
        format!("{file_name}.state")
    };
    static_config.with_file_name(new_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_state_path_appends_state_suffix() {
        let p = default_state_path(&PathBuf::from("secret-guard.toml"));
        assert_eq!(p, PathBuf::from("secret-guard.state.toml"));
    }

    #[test]
    fn default_state_path_handles_subdir() {
        let p = default_state_path(&PathBuf::from("/etc/sg/config.toml"));
        assert_eq!(p, PathBuf::from("/etc/sg/config.state.toml"));
    }

    #[test]
    fn default_state_path_fallback_for_non_toml() {
        let p = default_state_path(&PathBuf::from("config.json"));
        assert_eq!(p, PathBuf::from("config.json.state"));
    }
}
