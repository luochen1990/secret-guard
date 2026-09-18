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
//! 进入三条路径**之前**有一类本地终结分支 (#196, FWD-7): router provider + GET +
//! 模型列表端点 → `models::handle_router_models` 本地合成 (别名 ∪ 过滤后上游清单),
//! 不收集 body / 不做路由解析 / 不记 DAG。Direct provider 不进该分支。
//!
//! - **跨协议 + `stream=true`** (OpenAI ⇄ Anthropic): StreamTranslate 跨协议流式翻译,
//!   经流式扇出回传 (redact 场景响应侧 restore); **Responses 任一侧例外** → 501
//!   (Responses 流式 SSE 事件翻译未实现, 放行会翻译出空流).
//! - **Gemini/Ollama 跨协议** → 501 (codec 未覆盖, `Protocol::from_native` 返回 None).
//!
//! # fan_out 四路径 (响应扇出)
//!
//! - `fan_out_streaming`: 字节流式透传, 用于 same-proto + 无 Redact. 客户端响应 = 上游字节.
//! - `fan_out_streaming_with_restore`: 流式 + IR restore, 用于 same-proto + Redact + 流式响应.
//!   用 StreamTranslate 同协议 restore 模式 (egress SSE → IR event → restore → ingress SSE).
//!   失去 byte-exact (IR re-serialize), 但保留流式 UX.
//! - `fan_out_streaming_cross_proto`: 跨协议流式翻译 (可选 restore), 用于 cross-proto +
//!   stream=true + 2xx SSE. egress SSE → IR event → (restore) → ingress SSE.
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
//! 用 `DirectProvider::effective_api_key(id)` 注入对应协议的 auth header:
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
//! - `helpers`: HTTP header / URL / 字符串工具 + 转发链轻量语义判定点
//!   (stream 档位 / 请求 model 提取 / usage 采集编排, 详见该文件头部).
//! - `auth`: Provider 鉴权注入.
//! - `models`: router GET /models 本地合成 + 上游清单缓存 (#196, FWD-7; 含
//!   `ModelListCache` — AppState 聚合的纯数据 store, 经本模块根 re-export).
//! - `recorder`: DAG record 构造 + 视图守卫 + 响应累积器.
//! - `same_proto`: 同协议转发 (字节透传 / IR redact).
//! - `cross_proto`: 跨协议 codec 翻译.
//! - `fan_out`: 三条响应扇出路径.

mod auth;
mod cross_proto;
mod fan_out;
mod helpers;
mod models;
mod recorder;
mod same_proto;

use std::time::Instant;

use axum::{
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{Method, Response},
};

use crate::error::AppError;
use crate::provider::{Protocol, ProviderKind, ResolvedRoute};
use crate::state::AppState;

// AppState (crate::state) 持有 models::ModelListCache 字段: 类型是纯数据 store
// (无 proxy 行为依赖), 在模块根 re-export 供 state / server / 集成测试命名
// (子模块保持私有, 组合根先例同 state.rs 的 api_keys 字段, #196).
pub use models::ModelListCache;

// probe 端点 (web/api/providers) 复用 models 的上游探测基建: 行为借用
// (probe_provider_upstream 执行出站 HTTP 探测, 非纯数据/纯函数), 依赖方向
// 例外已登记在根 AGENTS.md "已接受的例外".
pub(crate) use models::probe_provider_upstream;

/// axum 路径参数: `/{proto}/{name}/{*rest}`.
///
/// `rest` 由 axum 的 catch-all 语法 (`{*rest}`) 提供. **注意 (2026-08 实测, #196)**:
/// axum 0.8 的 `{*rest}` 捕获**不含前导 `/`** (如 `v1/chat`); 旧注释 "含前导 `/`"
/// 与实测不符 — 转发路径因 `helpers::build_upstream_url` 的双向容错从未暴露.
/// 消费方一律经容错处理 (剥/补前导 `/`), 勿假设单一形态.
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
/// - `rest` = 上游 path (axum 0.8 `{*rest}` 捕获**不含前导 `/`**, 见 [`ForwardPath`]
///   注释; 消费方一律容错处理), query string 单独从 uri 拼回.
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

    // 1. 解析 ingress 协议. 合法简写清单从 Protocol::ALL 派生 (SSOT, 先例:
    //    web/api/providers.rs 同款投影), 新增协议无需同步此文案.
    let ingress = Protocol::from_short(&fp.proto).ok_or_else(|| {
        let shorts = Protocol::ALL
            .iter()
            .map(|(_, _, s)| *s)
            .collect::<Vec<_>>()
            .join("/");
        AppError::NotFound(format!(
            "unknown protocol '/{}' (expected one of: {shorts})",
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

    // 2.5 #196: router provider 的模型列表 GET 请求本地终结 (别名 ∪ 过滤后上游
    // 清单, N1-N6 语义见 src/proxy/models.rs 头部 + contracts.md FWD-7): 无 body
    // 收集 (GET 无 body), 无 route resolution, 无 DAG record (D5). Direct provider
    // 不进此分支, /models 透传行为零变化 (D6). Pool 同样不进此分支 (那是
    // Router 专属) — pool 入口的 /models 落到 resolve_route → 打到当前成员 →
    // Direct 透传语义, 零代码 (spec §7 语义决策; 成员耗尽的 failover 拨号
    // 对 GET /models 同样生效). 非 GET / 非匹配路径落回原流程.
    if parts.method == Method::GET
        && matches!(provider.kind, ProviderKind::Router(_))
        && models::is_model_list_path(ingress, &fp.rest)
    {
        return Ok(models::handle_router_models(&state, ingress, provider).await);
    }

    // 3. 收集请求 body (跨协议和同协议都需要).
    let req_bytes = to_bytes(body, MAX_REQ_BODY)
        .await
        .map_err(|e| AppError::BadBody(e.to_string()))?;

    // 3.5 路由 provider 解析 (#179 多规则化): 提取本请求的顶层 model 后按规则
    // 链解析到链尾实体, 并收集链上生效的规则 model 重写值。**per-request 解析** —
    // 路由现依赖请求 model (规则按 model 匹配), 故必须在 body 收集之后; 切换
    // 规则只影响新请求 (in-flight 请求按已解析目标完成);
    // 坏路由 (无规则命中 / 目标缺失 / disabled / 成环) → 503, message 只含
    // id + model 名 + reason (SEC-2 同型).
    // WARN: 悬空/disabled 指向是路由切换的主要运维事故形态, 静默 503 排障成本高.
    // Direct 条目的 resolve_route 快路径不消费请求 model (无规则匹配),
    // JSON 顶层扫描是纯浪费 — 仅 Router 构造需要. 守卫用 matches! 只读判别
    // (provider 以借用传入 resolve_route, 无需 clone).
    let request_model = if matches!(provider.kind, ProviderKind::Router(_)) {
        helpers::request_model(&req_bytes)
    } else {
        String::new()
    };
    let resolved = match state
        .providers
        .resolve_route(&provider, &request_model, &state.pools)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(router = %fp.name, error = %e, "route resolution failed");
            return Err(AppError::Unavailable(e.to_string()));
        }
    };
    // sum type 红利 (#187): resolved.provider 类型上即 DirectProvider — 转发链
    // 从此处开始只处理实体, 下游 (same/cross/passthrough) 零判别逻辑.
    let ResolvedRoute {
        id: upstream_id,
        provider,
        model_rewrite,
        pool: pool_hop,
    } = resolved;
    // Pool 耗尽检测上下文 (T2): 响应侧旁路检测的归因锚点 + 配置**入口快照**
    // (per-request 解析精神 — 在途配置变更由 PoolStates 按位置对齐收敛; pool
    // 条目在 resolve 后被改成非 Pool 构造的窗口内放弃检测). 非 pool 流量 =
    // None, 检测点零开销短路.
    let pool_watch = pool_hop.as_ref().and_then(|hop| {
        match state.providers.get_effective(&hop.pool_id).map(|p| p.kind) {
            Some(crate::provider::ProviderKind::Pool(cfg)) => {
                Some(crate::pool::PoolWatch::new(hop, cfg, &state.pools))
            }
            _ => None,
        }
    });
    if fp.name != upstream_id {
        tracing::info!(
            router = %fp.name,
            upstream = %upstream_id,
            model = %crate::provider::truncate_model_for_echo(&request_model),
            "route resolved"
        );
    }
    if let Some(m) = &model_rewrite {
        tracing::debug!(router = %fp.name, model_rewrite = %m, "model rewrite active (route)");
    }

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
            &upstream_id,
            model_rewrite,
            started,
            secrets_snapshot,
            pool_watch,
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
        &upstream_id,
        model_rewrite,
        started,
        secrets_snapshot,
        pool_watch,
    )
    .await
}
