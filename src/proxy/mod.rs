//! 透明反向代理 handler (模块目录根).
//!
//! # 契约 / DoD
//! 1. **协议无关**: 任意 HTTP 方法 / 路径透传, body 视为字节流.
//! 2. **零字段损失**: 上游响应的所有 header / 状态码 / body 原样回传 (除 hop-by-hop).
//! 3. **流式友好**: 上游若返回 SSE / chunked, 也以流式方式回传给客户端.
//! 4. **可观测**: 每次请求都生成 DAG node, 包括错误路径下的 incomplete 标记.
//! 5. **可插拔**: 后续 secret 改写只需在 "请求 body 收集后" 与 "响应 chunk 流出前" 两处插入 hook.
//!
//! # 路由策略
//! URL = `/{proto_short}/{provider_id}/*path`, 由 [`ForwardPath`] 解析:
//! - `proto_short` 决定 ingress 协议 (完整映射见 [`Protocol::ALL`], SSOT).
//! - `provider_id` 决定目标 provider (含 egress 协议).
//! - 若 provider 不存在 / 被禁用: 返回 404 / 503.
//!
//! # dispatch 路径选择 (`dispatch`)
//!
//! 根据 ingress == egress 与 SecretTable 是否空, 选择三条路径之一:
//!
//! | 场景 | 函数 | 路径 |
//! |---|---|---|
//! | 同协议 + 无 Redact (SecretTable 空) | `same_proto_passthrough` | 字节透传 (零回归, 最热路径) |
//! | 同协议 + Redact | `same_proto_forward` | IR 路径: reader → `redact_ir` → writer |
//! | 跨协议 | `cross_proto_forward` | IR 路径: reader → `redact_ir` → extra.clear → writer |
//!
//! - **跨协议 + `stream=true`** → 501 (StreamTranslate 跨协议翻译已实现但未接入 dispatch).
//! - **Gemini/Ollama 跨协议** → 501 (codec 未覆盖, `Protocol::from_native` 返回 None).
//!
//! # fan_out 三路径 (响应扇出)
//!
//! - `fan_out_streaming`: 字节流式透传, 用于 same-proto + 无 Redact. 客户端响应 = 上游字节.
//! - `fan_out_streaming_with_restore`: 流式 + IR restore, 用于 same-proto + Redact + 流式响应.
//!   用 StreamTranslate 同协议 restore 模式 (egress SSE → IR event → restore → ingress SSE).
//!   失去 byte-exact (IR re-serialize), 但保留流式 UX.
//! - `fan_out_buffered_ir`: 非流式 + IR restore, 用于 same-proto + Redact + 非流式 / cross-proto.
//!   完整累积响应, restore, 一次性返回.
//! - **客户端响应永远无大小上限**; 只有 record 累积受 `MAX_RESP_BODY_RECORD` (32 MiB) 约束.
//!
//! # 流式响应处理
//! 用 mpsc channel 做扇出: 一个后台 task 读取上游 chunk, 同时写一份给客户端 channel
//! 一份累积给记录. 顺序上**先 send 后 acc**, 让客户端反向压力能尽早传到上游.
//! 流结束 / 客户端断开 / 上游错误 都触发记录更新 (带 incomplete 标记).
//!
//! # Provider 鉴权 (`apply_provider_auth`)
//!
//! 用 `provider.effective_api_key()` 注入对应协议的 auth header:
//! - OpenAI / Ollama → `Authorization: Bearer <key>`
//! - Anthropic → `x-api-key: <key>`
//! - Gemini → `x-goog-api-key: <key>`
//!
//! 同时剥离竞争 header (避免客户端误传的对手协议 auth 干扰上游), provider 配置优先于客户端.
//! api_key 的两种来源 (`api_key` 直接值 / `api_key_file` 运行时读文件) 见 `src/provider.rs` 头部.
//!
//! # 模块拆分
//!
//! 历史上是单文件 `proxy.rs` (prod ~1531 行, 接近 FILE_MAX_PROD_LINES=1600 硬门禁).
//! 按职责拆分为模块目录:
//! - `mod` (本文件): 入口 + dispatch + 共享常量.
//!   (进程级共享状态 `AppState` 在顶层 `crate::state`, 上移见 #145 偏差 3.)
//! - `helpers`: HTTP header / URL / 字符串工具 (无业务语义).
//! - `auth`: Provider 鉴权注入.
//! - `recorder`: DAG record 构造 + 视图守卫 + 响应累积器.
//! - `same_proto`: 同协议转发 (字节透传 / IR redact).
//! - `cross_proto`: 跨协议 codec 翻译.
//! - `fan_out`: 三条响应扇出路径.

mod auth;
mod cross_proto;
mod fan_out;
mod helpers;
mod recorder;
mod same_proto;

use std::time::Instant;

use axum::{
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::Response,
};

use crate::error::AppError;
use crate::provider::Protocol;
use crate::state::AppState;

/// axum 路径参数: `/{proto}/{name}/{*rest}`.
///
/// `rest` 由 axum 的 catch-all 语法 (`{*rest}`) 提供, 含前导 `/`, 例如 `/v1/chat`.
/// 若 URL 只到 `/{proto}/{name}` 则走 [`forward_no_rest`] 单独路由.
#[derive(serde::Deserialize, Debug)]
pub struct ForwardPath {
    pub proto: String,
    pub name: String,
    pub rest: String,
}

/// 请求 body 在内存中收集的上限 (16 MiB).
///
/// 决策依据: 实测覆盖 99% LLM 请求 (system prompt + 多轮对话 + tools schema).
/// 超过此值的请求往往是误传 (如整库代码上传), 失败比 OOM 更可恢复.
/// 客户端错误信息会提示 "request body too large".
pub(super) const MAX_REQ_BODY: usize = 16 * 1024 * 1024;

/// 单条响应 body 累积记录的上限 (32 MiB).
///
/// 决策依据: LLM 长输出 (如 100k token 代码生成) 经 SSE 累积可达 ~10 MiB JSON;
/// 32 MiB 留 3x 余量覆盖极端长输出 + tool_use input 嵌套场景.
/// 注意: 此上限**只影响 DAG 记录**, 客户端响应**不受限** (流式透传, 不全量 buffer).
pub(super) const MAX_RESP_BODY_RECORD: usize = 32 * 1024 * 1024;

/// overflow 时写入 raw_resp_body 的占位 banner (供前端展示).
pub(super) const TRUNCATED_BANNER: &str = "<truncated: exceeded record cap>";

/// 错误响应回放给客户端时的 message 字段截断上限 (字节).
///
/// 决策依据: 上游错误 body 可能含整段 stack trace / HTML 错误页, 全量回放会污染
/// 客户端错误日志. 4 KiB 足以保留 "error.message" 主信息 + 一段上下文.
pub(super) const MAX_ERROR_MSG_LEN: usize = 4096;

// ─── doc-link 稳定性 re-export ─────────────────────────────────────────────
//
// codec 模块的 doc 注释用 intradoc link 引用了两个转发私有函数:
//   - `crate::proxy::cross_proto_forward` (src/codec/fwd_cross_proto_property.rs)
//   - `crate::proxy::fan_out_streaming_with_restore` (src/codec/fwd_streaming_property.rs)
// 拆分后这些函数迁入子模块, 直接路径不再可达, 会触发 `cargo doc -D warnings` 断链.
// 用 `pub(crate) use` 在模块根 re-export, 保持 doc-link 路径稳定 (零行为变更,
// 仅影响 doc 解析, 不扩大 crate 公共 API — pub(crate) 对 crate 外不可见).
// `#[allow(unused)]`: 这些 re-export 仅服务于 doc-link, 代码本身不引用.
#[allow(unused_imports)]
pub(crate) use {cross_proto::cross_proto_forward, fan_out::fan_out_streaming_with_restore};

/// 主 handler: 路径 `/{proto}/{name}/{*rest}`, 解析后透传到对应 provider.
///
/// 路径段语义:
/// - `proto` = ingress 协议的单字母简写 (完整映射见 [`Protocol::ALL`], SSOT).
/// - `name` = 目标 provider id.
/// - `rest` = 上游 path (含前导 `/`), query string 单独从 uri 拼回.
///
/// MVP: 仅支持 ingress == provider.protocol (identity passthrough);
/// 跨协议请求返回 501 Not Implemented.
pub async fn forward(
    State(state): State<AppState>,
    Path(fp): Path<ForwardPath>,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    dispatch(state, fp, req).await
}

/// 路径只到 `/{proto}/{name}` (没有 rest 段) 的薄包装: 等价于 rest = "/".
pub async fn forward_no_rest(
    State(state): State<AppState>,
    Path((proto, name)): Path<(String, String)>,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    let fp = ForwardPath {
        proto,
        name,
        rest: "/".to_string(),
    };
    dispatch(state, fp, req).await
}

async fn dispatch(
    state: AppState,
    fp: ForwardPath,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    let started = Instant::now();
    let (parts, body) = req.into_parts();

    // 1. 解析 ingress 协议.
    let ingress = Protocol::from_short(&fp.proto).ok_or_else(|| {
        AppError::NotFound(format!(
            "unknown protocol '/{}' (expected one of: o/a/g/l/r)",
            fp.proto
        ))
    })?;

    // 2. 查找 effective provider (合并 static + dynamic + decision 后的生效值).
    let provider = state
        .providers
        .get_effective(&fp.name)
        .ok_or_else(|| AppError::NotFound(format!("unknown provider '/{}'", fp.name)))?;
    if !provider.enabled {
        return Err(AppError::Unavailable(format!(
            "provider '{}' is disabled",
            provider.id
        )));
    }

    // 3. 收集请求 body (跨协议和同协议都需要).
    let req_bytes = to_bytes(body, MAX_REQ_BODY)
        .await
        .map_err(|e| AppError::BadBody(e.to_string()))?;

    // 4. 协议匹配: 同协议走 IR / 字节透传; 跨协议走 codec 翻译.
    let secrets_snapshot = state.secrets.effective_raw();
    // disabled secret 明文放行按请求 WARN (#161): 挂 dispatch 层 (raw bytes 扫描) 以
    // 覆盖透传快捷分支, 命中才告警. 挂载层级论证见 warn_disabled_secrets_in_body doc.
    let disabled_secrets = state.secrets.disabled_statics();
    if !disabled_secrets.is_empty() {
        crate::redact::warn_disabled_secrets_in_body(&req_bytes, &disabled_secrets);
    }
    if ingress != provider.protocol {
        return cross_proto_forward(
            state,
            fp,
            parts,
            req_bytes,
            ingress,
            provider,
            started,
            secrets_snapshot,
        )
        .await;
    }
    same_proto::same_proto_forward(
        state,
        fp,
        parts,
        req_bytes,
        ingress,
        provider,
        started,
        secrets_snapshot,
    )
    .await
}
