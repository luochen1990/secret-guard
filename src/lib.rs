//! secret-guard — a lightweight LLM gateway that prevents accidental secret leakage.
//!
//! 模块概览:
//! - [`cli`]      —— 命令行参数 schema (clap)
//! - [`config`]   —— TOML 配置文件 schema (serde)
//! - [`proxy`]    —— 透明反向代理 handler (axum + reqwest)
//! - [`record`]   —— 转发记录模型与内存存储 (供 Web UI 消费)
//! - [`server`]   —— axum router 装配与服务启动
//!
//! 设计目标: 全程"协议无关", body 在字节层面流动, 中间件可对 body 做 find-and-replace.
//! 协议无关意味着 OpenAI / Anthropic / Gemini 等任意 LLM API 都能透传, 无需 schema 同步.

pub mod cli;
pub mod config;
pub mod proxy;
pub mod record;
pub mod server;

pub use cli::{Cli, Command, RunArgs};
pub use config::Config;
