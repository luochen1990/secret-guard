//! `/api/*` JSON endpoints (模块目录根: 按资源组拆分).
//!
//! 所有响应都带 `Cache-Control: no-store`, 避免浏览器对自动刷新返回缓存内容.
//!
//! # 数据流
//!
//! - `GET /secrets` / `GET /providers` 返回 **effective** (static+dynamic+decision 合并后)
//!   的视图, 每个 item 同时携带 provenance (static/dynamic/override 标签) 与原始 static /
//!   dynamic 版本. UI 基于此渲染只读 / 可编辑 / 可切换状态.
//! - `POST / PUT / DELETE` 操作 **dynamic** 层. static 永远不可写.
//!   编辑 static-only id 时, 服务端自动 fork 一份 dynamic override (符合 git-style 心智模型).
//! - `PATCH /{id}/decision` 切换对 static id 的 per-item 决策
//!   (Default / PreferStatic / Disabled).
//!
//! # 子模块 (按资源组拆分, 837 行单文件 → ~6 文件, 见 #146 残留 1)
//!
//! - `error`: `ApiError` 统一错误类型 (所有 handler 共享).
//! - `crud`: secrets/providers 共享的 CRUD 泛型流程 (`EffectiveItem` + upsert/delete 泛型).
//! - `records`: `GET /records/{id}` 单条 raw + parsed view (WebUI 弹窗按需拉).
//! - `sessions`: `GET /sessions` + `GET /sessions/{sid}/timeline` + `POST /sync`
//!   (session-aware timeline API).
//! - `secrets`: secrets CRUD (5 endpoints).
//! - `providers`: providers CRUD (5 endpoints) + `POST /providers/probe` 协议探测
//!   (薄壳, 算法在 `proxy::models`) + `PUT/DELETE /providers/probe` 存量 "probe"
//!   id 条目的管理薄 wrapper.
//! - `apikeys`: API key CRUD (4 endpoints, 无条件挂载, 见该文件头注释).
//!
//! # 安全姿态
//!
//! - GET 永不返回 secret 的 `value` / provider 的 `api_key` 真实值 (用 [`crate::secrets::mask_value`] 占位).
//! - 写操作通过同源策略 + 本地监听 (默认 127.0.0.1) 保护.
//! - 内部错误细节不通过响应体返回, 仅进 tracing.

pub(crate) mod apikeys;
pub(crate) mod crud;
pub(crate) mod error;
pub(crate) mod providers;
pub(crate) mod records;
pub(crate) mod secrets;
pub(crate) mod sessions;
pub(crate) mod usage;

// handler re-export: 保持 `web::api::<handler>` 路径稳定 (web/mod.rs router 直接引用).
pub use apikeys::{create_api_key, delete_api_key, list_api_keys, toggle_api_key};
pub use providers::{
    create_provider, delete_provider, delete_provider_probe, list_providers, probe_provider,
    set_provider_decision, update_provider, update_provider_probe,
};
pub use records::get_record;
pub use secrets::{create_secret, delete_secret, list_secrets, set_secret_decision, update_secret};
pub use sessions::{list_sessions, session_timeline, sync};
pub use usage::usage_summary;
