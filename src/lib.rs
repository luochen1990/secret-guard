//! secret-guard — a lightweight LLM gateway that prevents accidental secret leakage.
//!
//! 模块概览:
//! - [`auth`]    —— OIDC 登录 + 本地 API key 鉴权 (WebUI 与 SDK 双通道)
//! - [`cli`]     —— 命令行参数 schema (clap)
//! - [`codec`]   —— 跨协议 codec (OpenAI ⇄ Anthropic, 借鉴 Busbar IR 设计)
//! - [`config`]  —— TOML 配置文件 schema (serde)
//! - [`dag`]     —— 内容寻址的对话 DAG 存储 (BlockPool + Node + Merkle prefix)
//! - [`mod@derive`]  —— 从 request body 字节派生 preview/model/text 的逻辑 (域 B 派生链)
//! - [`dto`]     —— WebUI 响应 DTO 的中立类型层 (域 B → 域 C wire shape, dag 构造 / web 序列化)
//! - [`error`]   —— 统一应用错误类型 (转发链 + 鉴权层共用, 不反向依赖)
//! - [`mock`]    —— Per-secret mock 策略 (两维度: 初始值 / 生成策略)
//! - [`provider`]—— Provider 注册表 + Protocol 类型 (ingress / egress 抽象)
//! - [`proxy`]   —— 透明反向代理 handler (axum + reqwest)
//! - [`record`]  —— 转发记录 DTO (从 DAG Node 派生, 供 Web UI 序列化)
//! - [`redact`]  —— Secret 改写 (请求) 与还原 (响应) 逻辑
//! - [`secrets`] —— Secret 注册表 + 内存状态 + 配置持久化
//! - [`server`]  —— axum router 装配与服务启动
//! - [`state`]   —— 进程级共享状态 AppState + HTTP 共享常量 (NO_STORE)
//! - [`web`]     —— `/__sg/*` Web UI 与 JSON API
//!
//! 设计目标: body 在字节层面流动, 中间件可对 body 做 find-and-replace.
//! 路由 `/{proto_short}/{provider_id}/*path` 同时编码 ingress protocol 与 provider.
//! 同协议走字节透传; 跨协议通过 [`codec`] 模块的 IR 翻译.

pub mod auth;
pub mod cli;
pub mod codec;
pub mod config;
pub mod dag;
pub mod derive;
pub mod dto;
pub mod error;
pub mod mock;
pub mod provider;
pub mod proxy;
pub mod record;
pub mod redact;
pub mod secrets;
pub mod server;
pub mod state;
pub mod util;
pub mod web;

pub use cli::{Cli, Command, RunArgs};
pub use config::Config;
