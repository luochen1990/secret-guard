//! secret-guard — a lightweight LLM gateway that prevents accidental secret leakage.
//!
//! 模块概览:
//! - [`cli`]      —— 命令行参数 schema (clap)
//! - [`codec`]    —— 跨协议 codec (OpenAI ⇄ Anthropic, 借鉴 Busbar IR 设计)
//! - [`config`]   —— TOML 配置文件 schema (serde)
//! - [`mock`]     —— Per-secret mock 策略 (两维度: 初始值 / 生成策略)
//! - [`provider`] —— Provider 注册表 + Protocol 类型 (ingress / egress 抽象)
//! - [`proxy`]    —— 透明反向代理 handler (axum + reqwest)
//! - [`record`]   —— 转发记录模型与内存存储 (供 Web UI 消费)
//! - [`redact`]   —— Secret 改写 (请求) 与还原 (响应) 逻辑
//! - [`secrets`]  —— Secret 注册表 + 内存状态 + 配置持久化
//! - [`server`]   —— axum router 装配与服务启动
//! - [`web`]      —— `/__sg/*` Web UI 与 JSON API
//!
//! 设计目标: body 在字节层面流动, 中间件可对 body 做 find-and-replace.
//! 路由 `/{proto_short}/{provider_id}/*path` 同时编码 ingress protocol 与 provider.
//! 同协议走字节透传; 跨协议通过 [`codec`] 模块的 IR 翻译.

pub mod cli;
pub mod codec;
pub mod config;
pub mod dag;
pub mod mock;
pub mod provider;
pub mod proxy;
pub mod record;
pub mod redact;
pub mod secrets;
pub mod server;
pub mod web;

pub use cli::{Cli, Command, RunArgs};
pub use config::Config;
