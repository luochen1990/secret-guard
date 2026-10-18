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
//! - `provider_id` 决定目标 provider; egress 端点由 ingress 按
//!   [`crate::provider::DirectProvider::select_endpoint`] 选择 (精确匹配 → 同协议, 无匹配 →
//!   首端点跨协议翻译).
//! - 若 provider 不存在 / 被禁用: 返回 404 / 503.
//!
//! # dispatch 路径选择 (`dispatch`)
//!
//! 根据 ingress == egress (端点选择的 exact 位) 与 SecretTable 是否空, 选择三条
//! 路径之一:
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
//! - **跨协议 + `stream=true`** (codec 覆盖族内任意 pair, 含 Responses 任一侧):
//!   StreamTranslate 跨协议流式翻译, 经流式扇出回传 (redact 场景响应侧 restore).
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
//!   完整累积响应, restore, 一次性返回. T5: 客户端 stream=true + 上游 2xx 单块 JSON
//!   (伪流式上游) 且 parse 成功时, 出站合成完整 SSE 生命周期 (`codec::stream::synthesize_sse`)
//!   而非单块 JSON — SDK 流式解析器需要事件流 shape; cross_proto 的 buffered 分支同型.
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
// derive_redactions (redactions 投影的 SSOT) 供 B1 等价性测试复用同一 join
// (derive.rs / redact.rs 的测试); 生产消费方为零 — timeline 走 node.event.redactions,
// 故仅测试构建暴露此出口.
#[cfg(test)]
pub(crate) use recorder::derive_redactions;

use std::time::Instant;

use axum::{
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{Method, Response},
};

use crate::error::AppError;
use crate::provider::{Protocol, ProviderKind, ProviderTable, ResolvedRoute};
use crate::state::AppState;

// AppState (crate::state) 持有 models::ModelListCache 字段: 类型是纯数据 store
// (无 proxy 行为依赖), 在模块根 re-export 供 state / server / 集成测试命名
// (子模块保持私有, 组合根先例同 state.rs 的 api_keys 字段, #196).
pub use models::ModelListCache;

// probe 端点 (web/api/providers) 复用 models 的上游探测基建: 行为借用
// (probe_provider_upstream 执行出站 HTTP 探测, 非纯数据/纯函数), 依赖方向
// 例外已登记在根 AGENTS.md "已接受的例外".
pub(crate) use models::probe_provider_upstream;
/// 模型清单预览 (WebUI endpoints 弹窗; 取数 SSOT 与 router /models 合成同乡).
pub(crate) use models::provider_model_preview;

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
/// ingress 精确匹配端点 → 同协议 (identity passthrough); 无匹配端点 → 首端点
/// 跨协议翻译 (multi-endpoint D2, 见 [`crate::provider::DirectProvider::select_endpoint`]).
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

/// 协议简写清单 join 投影 (SSOT = [`Protocol::ALL`], 分隔符由调用方定 —
/// URL shape 的交替段与 expected-one-of 文案共用同一派生, 新增协议零同步).
fn protocol_shorts(sep: &str) -> String {
    Protocol::ALL
        .iter()
        .map(|(_, _, s)| *s)
        .collect::<Vec<_>>()
        .join(sep)
}

/// forward URL 形状提示段: `/{o|a|g|l|r}/{provider-id}/*rest`.
///
/// 上手指引: 该类 404 最常见的触发是 SDK base_url 漏掉 `/{short}/{id}` 段.
fn url_shape_hint() -> String {
    format!("/{{{}}}/{{provider-id}}/*rest", protocol_shorts("|"))
}

/// unknown provider 404 的指路后缀, 按 provider 表是否为空分两档 (上手指引):
/// 空表 (冷启动零配置) → 引导创建; 非空 → 提示 URL 形状并引导核对 id.
/// 判空用 `effective_snapshot` — 与 WebUI Providers tab 同一视图
/// (仅 disabled 项的表视为空: 用户打开 tab 看到的就是空列表).
fn provider_404_hint(providers: &ProviderTable) -> String {
    if providers.effective_snapshot().is_empty() {
        "no providers configured — create one in the WebUI Providers tab, or via \
         [[providers]] in secret-guard.toml"
            .to_string()
    } else {
        format!(
            "URL shape: {} — check the id in the WebUI Providers tab",
            url_shape_hint()
        )
    }
}

async fn dispatch(
    state: AppState,
    fp: ForwardPath,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    let started = Instant::now();
    let (mut parts, body) = req.into_parts();

    // 1. 解析 ingress 协议. 合法简写清单从 Protocol::ALL 派生 (SSOT, 先例:
    //    web/api/providers.rs 同款投影), 新增协议无需同步此文案 (URL shape 的
    //    简写交替段同源派生, 见 url_shape_hint).
    let ingress = Protocol::from_short(&fp.proto).ok_or_else(|| {
        let shorts = protocol_shorts("/");
        AppError::NotFound(format!(
            "unknown protocol '/{}' (expected one of: {shorts}; URL shape: {})",
            fp.proto,
            url_shape_hint()
        ))
    })?;

    // 2. 查找 effective provider (合并 static + dynamic + decision 后的生效值).
    //    404 文案按表空与否分档指路 (上手指引, 见 provider_404_hint).
    let provider = state.providers.get_effective(&fp.name).ok_or_else(|| {
        AppError::NotFound(format!(
            "unknown provider '/{}' ({})",
            fp.name,
            provider_404_hint(&state.providers)
        ))
    })?;
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

    // 4. 端点选择 (multi-endpoint, D2) + 协议匹配: ingress 精确匹配该协议的
    //    端点 → (endpoint, exact=true) 走 same_proto (透传/IR, 与现状同);
    //    无匹配 → 首端点 (声明序, exact=false) 走 cross_proto (跨协议翻译,
    //    与现状同 — 单端点配置下 exact=false ⟺ 旧 ingress != provider.protocol,
    //    行为逐字节一致). endpoints 为空是绕过 validate 的非法配置 → 503 (ROB).
    //    分叉不变式由 find 谓词结构直接保证 (不命中 ⟹ 全体端点协议 ≠ ingress,
    //    首端点亦然), 不依赖 validate 的唯一性; 唯一性仅让 "精确匹配" 语义无歧义.
    let Some((endpoint, exact)) = provider.select_endpoint(ingress) else {
        return Err(AppError::Unavailable(format!(
            "provider '{}' has no endpoints (invalid config)",
            upstream_id
        )));
    };
    // 立即 owned 化: endpoint 借用 provider, 而下游签名各自 owned provider + endpoint.
    let endpoint = endpoint.clone();
    if !exact {
        tracing::info!(
            ingress = ingress.name(),
            egress = endpoint.protocol.name(),
            provider = %upstream_id,
            "no endpoint for ingress protocol; falling back to first endpoint \
             (cross-protocol translation)"
        );
    }
    // 3.8 #320 SG 凭证自动保护: 在役 sg API token + 登记的 provider key 免配置纳入
    //     出站保护. 字节层 (本函数 "请求 body 收集后" hook 点), 与 user-secret IR
    //     机制正交 — 不改变下方路径选择判据 (SecretTable 是否为空), 对任意协议
    //     (含 codec 未覆盖的 gemini/ollama) 与任意 body 形状一致生效, 永不阻塞
    //     转发 (fail-open). 语义与接线点 SSOT 见 `src/protect.rs` 头部.
    //     secrets_snapshot 先取 (user-secret 优先: 精确重合的 overlay 值让位给
    //     IR 机制, 见 auto_protect_request).
    let secrets_snapshot = state.secrets.effective_raw();
    let req_bytes = auto_protect_request(
        &state,
        &mut parts,
        &provider,
        &upstream_id,
        req_bytes,
        &secrets_snapshot,
    );
    // disabled secret 明文放行按请求 WARN (#161): 挂 dispatch 层 (raw bytes 扫描) 以
    // 覆盖透传快捷分支, 命中才告警. 挂载层级论证见 warn_disabled_secrets_in_body doc.
    let disabled_secrets = state.secrets.disabled_statics();
    if !disabled_secrets.is_empty() {
        crate::redact::warn_disabled_secrets_in_body(&req_bytes, &disabled_secrets);
    }
    if !exact {
        return cross_proto_forward(
            state,
            fp,
            parts,
            req_bytes,
            ingress,
            provider,
            endpoint,
            &upstream_id,
            model_rewrite,
            started,
            secrets_snapshot,
            pool_watch,
        )
        .await;
    }
    // cross 分支已 return, endpoint 在此无后续使用 — 直接 move (零拷贝).
    same_proto::same_proto_forward(
        state,
        fp,
        parts,
        req_bytes,
        ingress,
        provider,
        endpoint,
        &upstream_id,
        model_rewrite,
        started,
        secrets_snapshot,
        pool_watch,
    )
    .await
}

/// #320 SG 凭证自动保护 — dispatch 层收口 (body 收集后, 路径分叉前).
///
/// 三步:
/// 1. **auth 关闭时**的机会性 key 注册 + header 剥离: 客户端 Bearer 若是已知
///    sg key → 注册 (经 `ApiKeyStore::lookup` 的 "呈现 ⇒ 保护", 覆盖重启后动态
///    key 的明文恢复) 并**剥离该 Authorization header** — sg token 对任何上游
///    provider 都不是合法凭证 (是本网关的自有凭证), 转发它没有任何正当用途.
///    剥离判据 = lookup 命中 **或** `known_plaintext` (M2: 注册表已知明文, 含
///    disabled — 与 body 侧保护面同口径 "跟随已知明文而非鉴权态"). 未命中
///    (BYO-key / 垃圾值) 原样保留 (keyless provider 的 BYO-key 透传语义不受
///    影响). auth 启用时 `require_api_key` middleware 已做同型剥离 + 注册,
///    此步跳过 (避免二次 hash).
/// 2. **收集保护集** (sg 注册表 + provider 派生 key), 排除与 `secrets_snapshot`
///    真值**精确相等**的值 (M3: user-secret 优先 — 用户显式登记的凭证由 IR
///    机制接管 redact + RED-6 restore 全链, 字节层让位).
/// 3. **字节层替换**: real→mock 全量替换 (等长, FWD-1 唯一授权的修改类型).
///    命中时 per-credential WARN (只含 id + 次数, SEC-2). 保护集为空 / body
///    无命中 / body 非 UTF-8 → 原样返回 (零拷贝, fail-open).
///
/// per-request 成本注记: `effective_raw` 快照 (P 个 provider 的 clone) + 选中
/// provider 的 `effective_api_key` (api_key_file 形态多一次 page-cached 读,
/// 与转发路径稍后的同型读成对) + K 次 `str::find` (K = 保护集大小, 典型 1-5) —
/// 相对 JSON 解析 / LLM 往返均为噪声.
fn auto_protect_request(
    state: &AppState,
    parts: &mut axum::http::request::Parts,
    provider: &crate::provider::DirectProvider,
    upstream_id: &str,
    body: bytes::Bytes,
    secrets_snapshot: &[crate::secrets::SecretEntry],
) -> bytes::Bytes {
    if !state.auth_enabled {
        let bearer = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        if let Some(key) = bearer
            && (state.api_keys.lookup(key).is_some() || state.api_keys.known_plaintext(key))
        {
            parts.headers.remove(axum::http::header::AUTHORIZATION);
            tracing::warn!(
                "client Authorization carries a secret-guard API token; header stripped \
                 (an sg token is never a valid upstream credential) (#320)"
            );
        }
    }
    let providers_snapshot = state.providers.effective_raw();
    let user_secret_values: Vec<&str> = secrets_snapshot.iter().map(|s| s.value.as_str()).collect();
    let creds = crate::protect::collect_credentials(
        state.api_keys.protected_credentials(),
        &providers_snapshot,
        &provider.effective_api_key(upstream_id),
        upstream_id,
        &user_secret_values,
    );
    if creds.is_empty() {
        return body;
    }
    let (replaced, hits) = crate::protect::redact_request_body(&body, &creds);
    for h in &hits {
        tracing::warn!(
            credential = %h.id,
            occurrences = h.occurrences,
            "auto-protected SG credential found in request body; replaced with mock (#320)"
        );
    }
    match replaced {
        Some(b) => b,
        // None = 无命中 (最常见; 零拷贝原样) 或 body 非 UTF-8 (best-effort 跳过,
        // 见 protect.rs 头注 — 二进制上传不在威胁模型内, 静默跳过).
        None => body,
    }
}
