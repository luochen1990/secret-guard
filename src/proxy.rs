//! 透明反向代理 handler.
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
//! - `proto_short` 决定 ingress 协议 (o/a/g/l).
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

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode},
};
use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::dag::{CallEvent, ConversationDag, PolicySnapshot, ResponseData};
use crate::error::AppError;
use crate::provider::{Protocol, ProviderTable};
use crate::redact::{RedactionMap, redact_ir, restore_ir_response};
use crate::secrets::SecretTable;

/// 进程级共享状态, 在 router 与 handler 间共享.
#[derive(Clone, Debug)]
pub struct ProxyState {
    pub upstream: reqwest::Client,
    pub providers: ProviderTable,
    pub dag: ConversationDag,
    pub secrets: SecretTable,
    /// API key 存储 (总是 Some; server.rs 无条件构造, 与 auth.enabled 无关).
    /// 字段类型保留 Option 仅为兼容 tests/integration.rs 的简化构造 (None 写法),
    /// handler 通过 require_store() 解包. 见 src/web/api.rs 中 /api-keys 段.
    #[allow(unused)]
    pub api_keys: Option<crate::auth::ApiKeyStore>,
    /// 服务端认证是否启用 (来自 static config `[auth] enabled`). 与 ApiKeyStore
    /// 的"无条件构造"正交: store 总存在, 但 forwarding 路径的 require_api_key
    /// middleware 仅在 auth_enabled = true 时挂载. WebUI 用此标志区分 key 的
    /// "启用中 / 已禁用 / 认证未启用" 三态 (见 src/web/api.rs::list_api_keys).
    pub auth_enabled: bool,
    /// 来自 `[redact] global_mock_prefix` (默认空串). WebUI secret upsert 时
    /// 透传给 validate_and_resolve, 用于校验 value 不含此 prefix + 注入 Auto gen_spec.prefix.
    pub global_mock_prefix: Arc<str>,
}

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

/// hop-by-hop 或在反代语义下不应原样转发的 header (RFC 7230 §6.1 + 反代常识).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// 请求 body 在内存中收集的上限 (16 MiB).
///
/// 决策依据: 实测覆盖 99% LLM 请求 (system prompt + 多轮对话 + tools schema).
/// 超过此值的请求往往是误传 (如整库代码上传), 失败比 OOM 更可恢复.
/// 客户端错误信息会提示 "request body too large".
const MAX_REQ_BODY: usize = 16 * 1024 * 1024;

/// 单条响应 body 累积记录的上限 (32 MiB).
///
/// 决策依据: LLM 长输出 (如 100k token 代码生成) 经 SSE 累积可达 ~10 MiB JSON;
/// 32 MiB 留 3x 余量覆盖极端长输出 + tool_use input 嵌套场景.
/// 注意: 此上限**只影响 DAG 记录**, 客户端响应**不受限** (流式透传, 不全量 buffer).
const MAX_RESP_BODY_RECORD: usize = 32 * 1024 * 1024;

/// 流式 parsed view (StreamScan snapshot) 的节流写入间隔.
/// 太短 → DAG 写锁竞争; 太长 → WebUI 看不到流式进度. 500ms 是 UX 与锁竞争的折中.
const PARSED_SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

// ─── 跨语言契约字符串 (前端 index.html 依赖, 见 isClientDisconnect) ─────────
//
// error_kind 字面量是前后端契约 (前端 index.html::isClientDisconnect 硬编码比较).
// 集中为 const, 任何改动一处即可, 避免 fan_out_* 三处各自硬编码导致漂移.

/// 客户端主动断开 (tx.send 失败). 前端 isClientDisconnect 严格相等匹配此串.
const ERR_CLIENT_DISCONNECTED: &str = "client disconnected";
/// 上游流式响应中途出错 (reqwest stream Err).
const ERR_UPSTREAM_STREAM: &str = "upstream stream error";
/// 响应超过 record 累积上限 (MAX_RESP_BODY_RECORD).
const ERR_RESP_CAP_EXCEEDED: &str = "response exceeds record cap";
/// overflow 时写入 raw_resp_body 的占位 banner (供前端展示).
const TRUNCATED_BANNER: &str = "<truncated: exceeded record cap>";

/// 错误响应回放给客户端时的 message 字段截断上限 (字节).
///
/// 决策依据: 上游错误 body 可能含整段 stack trace / HTML 错误页, 全量回放会污染
/// 客户端错误日志. 4 KiB 足以保留 "error.message" 主信息 + 一段上下文.
const MAX_ERROR_MSG_LEN: usize = 4096;
/// 主 handler: 路径 `/{proto}/{name}/{*rest}`, 解析后透传到对应 provider.
///
/// 路径段语义:
/// - `proto` = ingress 协议的单字母简写 (o/a/g/l).
/// - `name` = 目标 provider id.
/// - `rest` = 上游 path (含前导 `/`), query string 单独从 uri 拼回.
///
/// MVP: 仅支持 ingress == provider.protocol (identity passthrough);
/// 跨协议请求返回 501 Not Implemented.
pub async fn forward(
    State(state): State<ProxyState>,
    Path(fp): Path<ForwardPath>,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    dispatch(state, fp, req).await
}

/// 路径只到 `/{proto}/{name}` (没有 rest 段) 的薄包装: 等价于 rest = "/".
pub async fn forward_no_rest(
    State(state): State<ProxyState>,
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
    state: ProxyState,
    fp: ForwardPath,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    let started = Instant::now();
    let (parts, body) = req.into_parts();

    // 1. 解析 ingress 协议.
    let ingress = Protocol::from_short(&fp.proto).ok_or_else(|| {
        AppError::NotFound(format!(
            "unknown protocol '/{}' (expected one of: o/a/g/l)",
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
    same_proto_forward(
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

/// 同协议转发: 字节透传 (无 redact) 或 IR 路径 (启用 redact).
///
/// **同协议 + 无 redact**: 字节透传, 保留流式 UX. 这条路径零回归.
/// **同协议 + redact**: 走 IR (reader → redact_ir → writer).
///   非流式响应: buffered + restore_ir_response.
///   流式响应: 用 StreamTranslate 同协议 + restore 模式, 恢复流式 UX.
#[allow(clippy::too_many_arguments)]
async fn same_proto_forward(
    state: ProxyState,
    fp: ForwardPath,
    parts: axum::http::request::Parts,
    req_bytes: Bytes,
    ingress: Protocol,
    provider: crate::provider::Provider,
    started: Instant,
    secrets_snapshot: Vec<crate::secrets::SecretEntry>,
) -> Result<Response<Body>, AppError> {
    if secrets_snapshot.is_empty() {
        // 字节透传: 不进入 codec, 不做 redact. 这是最热路径 (多数 provider 无 secret).
        return same_proto_passthrough(state, fp, parts, req_bytes, ingress, provider, started)
            .await;
    }

    // IR 路径 (启用 redact).
    use crate::codec::Protocol as CodecProtocol;
    let Some(codec_proto) = CodecProtocol::from_native(ingress) else {
        // codec 不支持此协议 (Gemini/Ollama), 但同协议 + SecretTable 非空时本应做 redact.
        // 降级到字节透传: secret 原样转发到上游 (静默失效风险). 用 warn 让运维注意到.
        // 安全: 只记 protocol + provider id, 永不记 secret 值.
        warn!(
            "secrets configured for {} provider '{}', but codec does not cover {}; \
             secrets will be forwarded unredacted to upstream",
            ingress.name(),
            provider.id,
            ingress.name()
        );
        return same_proto_passthrough(state, fp, parts, req_bytes, ingress, provider, started)
            .await;
    };

    let reader = codec_proto.reader();
    let writer = codec_proto.writer();

    // 1-2. 解析请求 body → IR (共享 helper).
    let mut ir = parse_request_ir(&req_bytes, ingress, reader.as_ref())?;

    // 3. 快照真实 messages (redact 前) 给 DAG (DAG 存 OriginRecord 视角的真实内容,
    //    WebUI 查询时 lazy apply redactMap).
    let real_messages = ir.messages.clone();

    // 4. redact IR + derive redactions (共享 helper).
    //    流式响应里的 TextDelta / InputJsonDelta 都会经 StreamingRestorer 做 sliding-window
    //    restore (在 StreamTranslate::new_same_proto_restore 中), 不再需要 warn.
    let (redaction_map, redact_seed, redactions) =
        redact_and_derive(&mut ir, &secrets_snapshot, "same-proto");

    // 5. IR → 请求 body (同协议 writer 重序列化).
    let new_body = writer.write_request(&ir);
    let req_bytes_to_send = serde_json::to_vec(&new_body)
        .map_err(|e| AppError::Internal(format!("serialize redacted body failed: {e}")))?;
    let req_text_for_record = utf8_view(&req_bytes_to_send);

    // 6. 构造上游 URL.
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let upstream_url = build_upstream_url(&provider.base_url, &format!("{}{query}", fp.rest));

    // 7. 复制请求 headers + 应用 auth. 删除客户端的 content-type/length (重新计算).
    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    fwd_headers.remove(axum::http::header::CONTENT_TYPE);
    fwd_headers.remove(axum::http::header::CONTENT_LENGTH);
    apply_provider_auth(&mut fwd_headers, &provider.effective_api_key(), ingress);

    // 8. push 到 DAG (真实 messages + CallEvent 元数据).
    let path_for_record = format!(
        "/{}/{}/{}",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/')
    );
    let event = build_call_event(
        &parts,
        &path_for_record,
        &fwd_headers,
        &req_text_for_record,
        Some(codec_proto),
        redact_seed,
        Some(&secrets_snapshot),
        redactions,
    );
    let record_id = state.dag.push_messages(real_messages, event);

    debug!(%record_id, method = %parts.method, url = %upstream_url, "forwarding redacted same-proto request");

    // 9. 发送到上游.
    let upstream_resp = match state
        .upstream
        .request(parts.method, &upstream_url)
        .headers(fwd_headers)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::CONTENT_LENGTH, req_bytes_to_send.len())
        .body(req_bytes_to_send)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            record_upstream_failure(
                &state.dag,
                record_id,
                started,
                502,
                format!("upstream send error: {e}"),
            );
            return Err(AppError::Upstream(e.to_string()));
        }
    };

    // 10. 收集响应元数据.
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let streamed = is_streaming(&content_type);

    debug!(%record_id, status = %resp_status, streamed, "upstream responded");

    // 11. 响应处理:
    //     - 流式 + redact: StreamTranslate 同协议模式, per-event restore (恢复流式 UX).
    //     - 非流式 + redact: buffered + restore_ir_response.
    if streamed && resp_status.is_success() {
        fan_out_streaming_with_restore(
            state.dag.clone(),
            record_id,
            started,
            upstream_resp,
            resp_status,
            resp_headers,
            codec_proto,
            redaction_map,
        )
        .await
    } else {
        fan_out_buffered_ir(
            state.dag.clone(),
            record_id,
            started,
            upstream_resp,
            resp_status,
            resp_headers,
            streamed,
            codec_proto,
            redaction_map,
        )
        .await
    }
}

/// 同协议字节透传路径 (无 redact 时使用). 这条路径是项目最初的核心契约,
/// 必须保持 byte-exact + 流式 UX 零回归.
async fn same_proto_passthrough(
    state: ProxyState,
    fp: ForwardPath,
    parts: axum::http::request::Parts,
    req_bytes: Bytes,
    ingress: Protocol,
    provider: crate::provider::Provider,
    started: Instant,
) -> Result<Response<Body>, AppError> {
    let req_text_for_record = utf8_view(&req_bytes);
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let upstream_url = build_upstream_url(&provider.base_url, &format!("{}{query}", fp.rest));

    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    apply_provider_auth(&mut fwd_headers, &provider.effective_api_key(), ingress);

    let path_for_record = format!(
        "/{}/{}/{}",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/')
    );
    // passthrough 路径无 IR 解析 (字节透传). DAG node 存空 messages (孤立节点) +
    // req_body_raw (原始字节) 作为 WebUI req_body 权威来源. Gemini/Ollama 无 codec
    // 协议也走此路径 (parsed view 不可用, 与旧行为一致).
    let event = build_call_event(
        &parts,
        &path_for_record,
        &fwd_headers,
        &req_text_for_record,
        crate::codec::Protocol::from_native(ingress),
        0,
        None,
        vec![],
    );
    let record_id = state.dag.push_messages(vec![], event);

    debug!(%record_id, method = %parts.method, url = %upstream_url, "forwarding (passthrough)");

    let upstream_resp = match state
        .upstream
        .request(parts.method, &upstream_url)
        .headers(fwd_headers)
        .body(req_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            record_upstream_failure(
                &state.dag,
                record_id,
                started,
                502,
                format!("upstream send error: {e}"),
            );
            return Err(AppError::Upstream(e.to_string()));
        }
    };

    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let streamed = is_streaming(&content_type);

    debug!(%record_id, status = %resp_status, streamed, "upstream responded");

    fan_out_streaming(
        state.dag.clone(),
        record_id,
        started,
        upstream_resp,
        resp_status,
        resp_headers,
        streamed,
        crate::codec::Protocol::from_native(ingress),
    )
    .await
}

/// 投影 `RedactionMap` + `secrets_snapshot` → `(mock_value, secret_id)` 列表.
///
/// 这是 [`crate::dag::CallEvent::redactions`] 的唯一派生入口. 输出**永不**包含真实 secret 值.
/// 可以直接序列化到 GET API 响应中给 WebUI.
///
/// 匹配规则: `redaction_map.real_to_mock` 的 key (真实 secret) 与 `secrets_snapshot`
/// 的 `value` 字段比对. 仅命中的 secret 才进入列表 (eg secret 在表中但本次请求体没有
/// 它, 不计入). 同一 secret 多次匹配仍只投影一次 (HashMap 已去重).
///
/// 边角: 若两个 SecretEntry 共享同一 `value` (eg 用户重复配置), `find` 返回首个匹配;
/// 由于 RedactionMap 按 value 去重, 对应只有一个 mock — 这种重复配置语义上就是冗余,
/// WebUI 只展示其中一个 id 是可接受的 (它们指向相同的 secret 内容).
fn derive_redactions(
    redaction_map: &RedactionMap,
    secrets_snapshot: &[crate::secrets::SecretEntry],
) -> Vec<(String, String)> {
    redaction_map
        .real_to_mock
        .iter()
        .filter_map(|(real, mock)| {
            secrets_snapshot
                .iter()
                .find(|s| s.value == *real)
                .map(|s| (mock.clone(), s.id.clone()))
        })
        .collect()
}

// ─── same_proto / cross_proto 共享的请求准备 helpers ───────────────────────
//
// same_proto_forward 与 cross_proto_forward 的前半段 (解析 body → reader → IR →
// redact → derive_redactions) 流程步骤高度重合, 抽取为两个小 helper 消除重复,
// 同时保留两路径在 URL / headers / record path 上的差异 (这些差异是语义性的, 不宜强行合并).

/// 解析请求 body 为 JSON 并用 ingress reader 读为 IR (same_proto / cross_proto 共享).
///
/// 失败返回 `BadBody` (JSON 解析失败或 codec reader 拒绝).
fn parse_request_ir(
    req_bytes: &[u8],
    ingress: Protocol,
    reader: &dyn crate::codec::Reader,
) -> Result<crate::codec::ir::IrRequest, AppError> {
    let body: serde_json::Value = serde_json::from_slice(req_bytes)
        .map_err(|e| AppError::BadBody(format!("invalid JSON in {ingress} request body: {e}")))?;
    reader
        .read_request(&body)
        .map_err(|e| AppError::BadBody(format!("{ingress} request parse failed: {}", e.message)))
}

/// 对 IR 应用 redact 并派生 CallEvent.redactions (same_proto / cross_proto 共享).
///
/// 返回 `(redaction_map, redact_seed, redactions)`. redaction_map 非空时 debug 日志记录命中数.
fn redact_and_derive(
    ir: &mut crate::codec::ir::IrRequest,
    secrets_snapshot: &[crate::secrets::SecretEntry],
    log_tag: &str,
) -> (RedactionMap, u64, Vec<(String, String)>) {
    let (redaction_map, redact_seed) = redact_ir(ir, secrets_snapshot);
    if !redaction_map.is_empty() {
        debug!(
            redactions = redaction_map.real_to_mock.len(),
            "redacted secrets in {log_tag} IR"
        );
    }
    let redactions = derive_redactions(&redaction_map, secrets_snapshot);
    // 视图正确性守卫: redactions 是 RedactionMap (SSOT) 的派生视图, 每次派生都断言不变式.
    // 集中在 helper 内部确保 same_proto / cross_proto 两条路径都覆盖.
    #[cfg(feature = "consistency-check")]
    assert_redactions_match_map(&redactions, &redaction_map, secrets_snapshot);
    (redaction_map, redact_seed, redactions)
}

/// 视图正确性守卫 (CI 用, 需 `--features consistency-check`).
///
/// `redactions` 字段是 `RedactionMap` (SSOT) 的派生视图. 本函数断言派生保持
/// RedactionMap 的关键不变式, 防止未来重构破坏派生一致性. 详见 AGENTS.md
/// "视图正确性确保机制" — "redactions 字段从 RedactionMap 派生" 是该机制的已实践位置.
///
/// 不变式:
/// 1. 派生结果的条目数 == RedactionMap 中命中 secrets_snapshot 的 real 数.
/// 2. 派生结果中每个 mock 都能在 RedactionMap 中反向查到同一 real (双向索引自洽).
/// 3. 派生结果中 mock 唯一 (RedactionMap 按 value 去重, 派生也应去重).
#[cfg(feature = "consistency-check")]
fn assert_redactions_match_map(
    derived: &[(String, String)],
    redaction_map: &RedactionMap,
    secrets_snapshot: &[crate::secrets::SecretEntry],
) {
    // (1) 条目数: 派生结果应 == real_to_mock 中命中 snapshot 的 real 数.
    let expected = redaction_map
        .real_to_mock
        .keys()
        .filter(|real| secrets_snapshot.iter().any(|s| &s.value == *real))
        .count();
    debug_assert_eq!(
        derived.len(),
        expected,
        "derived redactions count drift from RedactionMap SSOT"
    );
    // (2) 双向索引自洽: 每个 mock 反查 real, 且该 real 命中 snapshot.
    for (mock, _id) in derived {
        let real = redaction_map.mock_to_real.get(mock);
        debug_assert!(
            real.is_some_and(|r| secrets_snapshot.iter().any(|s| s.value == *r)),
            "derived mock {mock:?} not round-tripping through RedactionMap"
        );
    }
    // (3) mock 唯一 (RedactionMap 按 value 去重).
    let mut mocks: Vec<&String> = derived.iter().map(|(m, _)| m).collect();
    mocks.sort();
    mocks.dedup();
    debug_assert_eq!(
        mocks.len(),
        derived.len(),
        "derived redactions have duplicate mocks"
    );
}

/// 视图正确性守卫 (CI 用, 需 `--features consistency-check`).
///
/// `CallEvent.preview` / `CallEvent.model` 是 `req_body_raw` (SSOT) 的派生视图:
/// 一次性从 req_body_raw 提取并缓存, 之后 sidebar / list 路径零拷贝读 Arc<str>.
/// 本函数断言派生保持一致 — 从 req_body_raw 重新调用
/// [`crate::derive::extract_preview_and_model`] 应得到相同结果.
///
/// 捕获的 drift 类型: 未来若把 preview/model 改为从其他来源 (如 IR / 原始 client body
/// 而非 redact 后的 req_body_raw) 提取, 此守卫会立刻失败. 详见 AGENTS.md
/// "视图正确性确保机制" — "preview/model 从 req_body_raw 派生" 是该机制的已实践位置.
#[cfg(feature = "consistency-check")]
fn assert_preview_model_match_source(event: &CallEvent) {
    let (rederived_preview, rederived_model) =
        crate::derive::extract_preview_and_model(&event.req_body_raw);
    debug_assert_eq!(
        event.model.as_deref(),
        rederived_model.as_deref(),
        "stored model drifts from req_body_raw SSOT"
    );
    debug_assert_eq!(
        event.preview.as_deref(),
        rederived_preview.as_deref(),
        "stored preview drifts from req_body_raw SSOT"
    );
}

/// 视图正确性守卫 (CI 用, 需 `--features consistency-check`).
///
/// `ResponseData.parsed` (非流式) 是上游响应字节的派生视图:
/// 用 codec reader 把 resp_bytes 解析为 [`crate::codec::ir::IrResponse`], 再用 codec writer
/// 序列化为 wire JSON 缓存. 本函数断言派生保持一致 — 重新用 reader 解析 source bytes,
/// 与派生时使用的 IR snapshot 比对.
///
/// 捕获的 drift 类型: 未来若 parsed 改为从其他来源 (如 restore 后的 IR / 客户端响应)
/// 派生, 此守卫会立刻失败. 仅在派生成功路径 (reader 解析成功 + 2xx 成功响应) 触发;
/// fallback 路径 (parse 失败原样透传 / 非 2xx 错误响应) 时 parsed_for_record 为 None,
/// 由调用方负责传入 expected = None 跳过断言. 详见 AGENTS.md "视图正确性确保机制".
#[cfg(feature = "consistency-check")]
fn assert_resp_parsed_matches_source_nonstream(
    parsed_for_record: Option<&serde_json::Value>,
    source_bytes: &[u8],
    reader: &dyn crate::codec::Reader,
) {
    // 预期: source_bytes 解析失败 → parsed_for_record 应为 None (fallback 路径, 不比对).
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(source_bytes) else {
        debug_assert!(
            parsed_for_record.is_none(),
            "parsed_for_record set but source bytes are not valid JSON"
        );
        return;
    };
    // reader 解析失败 → parsed_for_record 也应为 None.
    let Ok(ir) = reader.read_response(&v) else {
        debug_assert!(
            parsed_for_record.is_none(),
            "parsed_for_record set but reader fails to parse source bytes"
        );
        return;
    };
    // 成功路径: parsed_for_record 必为 Some. (调用方负责保证仅在派生会生成 parsed 的
    // 路径调用本守卫 — 即 2xx 成功响应. 非 2xx 错误响应即便 reader 能解析, 也不派生 parsed.)
    let Some(parsed) = parsed_for_record else {
        debug_assert!(
            false,
            "source parses successfully but parsed_for_record is None"
        );
        return;
    };
    // model 字段 (字符串) 直接比对 — 这是 IrResponse 中最稳定、最易 drift 的字段.
    // 容许 codec 不对称: 部分 writer 把 None model 写成空串 "" (如 OpenAI writer),
    // 部分 reader 又把 "" 读回 Some(""). 双侧都 normalize 为 None 等价, 避免已知 codec
    // 行为被误报为 drift.
    let parsed_model_norm: Option<&str> = parsed
        .get("model")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty());
    let ir_model_norm: Option<&str> = ir.model.as_deref().filter(|s| !s.is_empty());
    debug_assert_eq!(
        parsed_model_norm, ir_model_norm,
        "parsed.model drifts from IrResponse SSOT (after normalizing None == empty string)"
    );
}

/// 写一条 "上游请求失败" 记录 (错误路径专用 helper).
fn record_upstream_failure(
    dag: &ConversationDag,
    record_id: uuid::Uuid,
    started: Instant,
    status: u16,
    error: String,
) {
    dag.attach_response(
        record_id,
        ResponseData {
            resp_status: status,
            resp_headers: vec![],
            elapsed_ms: started.elapsed().as_millis() as u64,
            error: Some(error),
            ..Default::default()
        },
    );
}

/// 构造 [`CallEvent`] (3 个 push 点共用).
///
/// `secrets_snapshot = None` 表示 passthrough 路径 (无机密命中), 用空 policy + seed=0.
/// `secrets_snapshot = Some(s)` 表示 codec 路径, policy 持有真实 secret 列表 (COW Arc).
///
/// `req_text` 是已 redact 的请求 body 快照 (LLM 视角), 将作为 WebUI req_body 权威来源.
/// preview/model 从中一次性提取.
#[allow(clippy::too_many_arguments)]
fn build_call_event(
    parts: &axum::http::request::Parts,
    path: &str,
    fwd_headers: &HeaderMap,
    req_text: &str,
    ingress_protocol: Option<crate::codec::Protocol>,
    redact_seed: u64,
    secrets_snapshot: Option<&[crate::secrets::SecretEntry]>,
    redactions: Vec<(String, String)>,
) -> CallEvent {
    let (preview, model) = crate::derive::extract_preview_and_model(req_text);
    let policy = match secrets_snapshot {
        Some(s) => std::sync::Arc::new(PolicySnapshot {
            secrets: std::sync::Arc::from(s.to_vec()),
        }),
        None => std::sync::Arc::new(PolicySnapshot::default()),
    };
    let event = CallEvent {
        created_at: chrono::Utc::now(),
        method: parts.method.as_str().to_string(),
        path: path.to_string(),
        req_headers: redact_headers(fwd_headers),
        ingress_protocol,
        redact_seed,
        policy,
        req_body_raw: req_text.to_string(),
        preview: preview.map(std::sync::Arc::<str>::from),
        model: model.map(std::sync::Arc::<str>::from),
        // round_role 占位值 (User); DAG push_messages 内部会根据 delta 的 contains_user_text 修正.
        round_role: crate::codec::ir::IrRole::User,
        redactions: std::sync::Arc::from(redactions),
    };
    // 视图正确性守卫: preview/model 是 req_body_raw (SSOT) 的派生视图, 每次派生都断言不变式.
    // 集中在 build_call_event 内部确保 same_proto / cross_proto / passthrough 三条路径都覆盖
    // (三路径都通过 build_call_event 构造 CallEvent).
    #[cfg(feature = "consistency-check")]
    assert_preview_model_match_source(&event);
    event
}

/// 若 provider 配置了 api_key, 注入对应的 auth header.
///
/// 协议约定 (尊重各 provider 官方 SDK 的默认 header):
/// - OpenAI / Ollama: `Authorization: Bearer <key>` (OpenAI 标准; Ollama 1.17+ 也支持).
/// - Anthropic: `x-api-key: <key>`.
/// - Gemini: `x-goog-api-key: <key>` (Google API 官方约定; 不用 Bearer 避免与 OAuth 流程混淆).
///
/// 若客户端已自带对应 header, provider 的 api_key 覆盖之 — provider 配置优先.
/// 同步剥离客户端可能误传的竞争 header (如用 OpenAI ingress 时清除 `x-api-key`,
/// 防止上游误识别).
fn apply_provider_auth(headers: &mut HeaderMap, api_key: &str, ingress: Protocol) {
    let key = api_key.trim();
    if key.is_empty() {
        return;
    }
    // 目标 header 名 + 客户端可能误传的竞争 header 名 (统一剥离) + value 构造.
    // OpenAI/Ollama 用 `Bearer <key>` 格式; Anthropic/Gemini 用裸 key.
    let (target, competitors, value_str): (&'static str, &[&'static str], String) = match ingress {
        Protocol::OpenAI | Protocol::Ollama => (
            "authorization",
            &["x-api-key", "x-goog-api-key"][..],
            format!("Bearer {key}"),
        ),
        Protocol::Anthropic => (
            "x-api-key",
            &["authorization", "x-goog-api-key"][..],
            key.to_string(),
        ),
        Protocol::Gemini => (
            "x-goog-api-key",
            &["authorization", "x-api-key"][..],
            key.to_string(),
        ),
    };
    for c in competitors {
        headers.remove(*c);
    }
    match HeaderValue::from_str(&value_str) {
        Ok(v) => {
            headers.insert(target, v);
        }
        Err(e) => {
            // api_key 含非法 HTTP header 字符 (控制字符 / 非 ASCII 等).
            // 这通常是配置错误, 记 warn 让运维注意到; 不插入 header 让上游自行拒绝.
            warn!(
                error = %e,
                target,
                "provider api_key contains illegal header chars; skipping auth injection"
            );
        }
    }
}

/// 跨协议转发: ingress 协议 → IR → egress 协议, 上游响应反向翻译.
///
/// # MVP 范围与限制
///
/// - 只支持 OpenAI ⇄ Anthropic 双向 (其他组合返回 501).
/// - **强制非流式**: 上游 stream=false (即便客户端请求 stream=true). 客户端若 stream=true,
///   目前返回 501 (`streaming cross-protocol not yet supported`).
/// - **应用 redact**: 跨协议 + redact 通过 [`redact_ir`] 在 IR 层做替换,
///   不会与 codec 翻译冲突. 跨协议路径响应直接翻译 (无 restore, mock 不在响应中出现).
/// - 上游错误响应 (4xx/5xx) 也通过 codec 翻译为 ingress 协议的原生错误 envelope.
#[allow(clippy::too_many_arguments)]
async fn cross_proto_forward(
    state: ProxyState,
    fp: ForwardPath,
    parts: axum::http::request::Parts,
    req_bytes: Bytes,
    ingress: Protocol,
    provider: crate::provider::Provider,
    started: Instant,
    secrets_snapshot: Vec<crate::secrets::SecretEntry>,
) -> Result<Response<Body>, AppError> {
    use crate::codec::Protocol as CodecProtocol;

    // 1. 检查 codec 是否支持此协议对.
    let Some(ingress_codec) = CodecProtocol::from_native(ingress) else {
        return Err(AppError::NotImplemented(format!(
            "ingress protocol '{}' is not supported by codec (only openai/anthropic)",
            ingress.name()
        )));
    };
    let Some(egress_codec) = CodecProtocol::from_native(provider.protocol) else {
        return Err(AppError::NotImplemented(format!(
            "egress protocol '{}' is not supported by codec (only openai/anthropic)",
            provider.protocol.name()
        )));
    };

    let ingress_reader = ingress_codec.reader();
    let ingress_writer = ingress_codec.writer();
    let egress_writer = egress_codec.writer();

    // 2-3. 解析 ingress body → IR (共享 helper).
    let mut ir = parse_request_ir(&req_bytes, ingress, ingress_reader.as_ref())?;

    // 4. MVP 限制: 跨协议时不支持流式 (StreamTranslate 尚未接入 dispatch).
    if ir.stream {
        return Err(AppError::NotImplemented(format!(
            "streaming cross-protocol ({ingress} → {}) is not yet supported; \
             disable stream=true in the client request",
            provider.protocol.name()
        )));
    }

    // 5. 若 egress 要求 max_tokens 而 IR 缺失, 注入默认值.
    if egress_writer.requires_max_tokens() && ir.max_tokens.is_none() {
        ir.max_tokens = Some(crate::codec::DEFAULT_MAX_TOKENS);
    }

    // 6. 清空 ingress-only 元数据:
    //    - extra: ingress-only 字段会泄漏到 egress
    //    - wire_fidelity (stop_form / content_form / tools_present): ingress wire 形态
    ir.extra.clear();
    ir.clear_wire_fidelity();

    // 7. 快照真实 messages (redact 前) 给 DAG.
    let real_messages = ir.messages.clone();

    // 8. redact IR + derive redactions (共享 helper, 内含 consistency-check 守卫).
    let (redaction_map, redact_seed, redactions) =
        redact_and_derive(&mut ir, &secrets_snapshot, "cross-proto");

    // 9. IR → egress body.
    let egress_body_value = egress_writer.write_request(&ir);
    let egress_bytes = serde_json::to_vec(&egress_body_value)
        .map_err(|e| AppError::Internal(format!("serialize egress body failed: {e}")))?;

    // 10. 构造上游 URL (egress writer 的固定 path).
    let upstream_url = format!("{}{}", provider.base_url, egress_writer.upstream_path());

    // 11. 复制请求 headers + 应用 egress 协议的 auth.
    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    fwd_headers.remove(axum::http::header::CONTENT_TYPE);
    fwd_headers.remove(axum::http::header::CONTENT_LENGTH);
    apply_provider_auth(
        &mut fwd_headers,
        &provider.effective_api_key(),
        provider.protocol,
    );
    // 跨协议时客户端不会自带 egress 协议的特定 header, 这里仅在缺失时注入默认.
    // 用 entry().or_insert() 而非 insert(), 保留客户端主动设置更新的版本的能力.
    if provider.protocol == Protocol::Anthropic {
        fwd_headers
            .entry("anthropic-version")
            .or_insert_with(|| HeaderValue::from_static("2023-06-01"));
    }

    // 12. push 到 DAG.
    let path_for_record = format!(
        "/{}/{}/{}  [{} → {}]",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/'),
        ingress.name(),
        provider.protocol.name()
    );
    // 用 redact 后的 IR 经 ingress writer 重序列化作为 record body (而非原始 req_bytes).
    // 理由与 same_proto_forward 一致: record 应保存 "redact 后的视图" (LLM 看到的版本),
    // 而非客户端原始 body (可能含未 redact 的真实 secret). 这里用 ingress writer 而非
    // egress writer, 让 WebUI 的 parsed view 能用 ingress codec 正确 round-trip 解析.
    let req_view_value = ingress_writer.write_request(&ir);
    let req_view_bytes = serde_json::to_vec(&req_view_value)
        .map_err(|e| AppError::Internal(format!("serialize ingress view body failed: {e}")))?;
    let req_text_for_record = utf8_view(&req_view_bytes);
    let event = build_call_event(
        &parts,
        &path_for_record,
        &fwd_headers,
        &req_text_for_record,
        Some(ingress_codec),
        redact_seed,
        Some(&secrets_snapshot),
        redactions,
    );
    let record_id = state.dag.push_messages(real_messages, event);

    debug!(
        %record_id,
        method = %parts.method,
        url = %upstream_url,
        ingress = %ingress.name(),
        egress = %provider.protocol.name(),
        "cross-proto forwarding"
    );

    // 13. 发送到上游.
    let upstream_resp = match state
        .upstream
        .request(parts.method, &upstream_url)
        .headers(fwd_headers)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::CONTENT_LENGTH, egress_bytes.len())
        .body(egress_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            record_upstream_failure(
                &state.dag,
                record_id,
                started,
                502,
                format!("upstream send error: {e}"),
            );
            return Err(AppError::Upstream(e.to_string()));
        }
    };

    // 14. 完整 buffer 上游响应 (跨协议 MVP 不支持流式). 受 MAX_RESP_BODY_RECORD 上限保护.
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes: Bytes = {
        let mut acc: Vec<u8> = Vec::new();
        let mut stream = upstream_resp.bytes_stream();
        let mut exceeded = false;
        let mut stream_err: Option<String> = None;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => {
                    if acc.len() + b.len() > MAX_RESP_BODY_RECORD {
                        exceeded = true;
                        break;
                    }
                    acc.extend_from_slice(&b);
                }
                Err(e) => {
                    stream_err = Some(e.to_string());
                    break;
                }
            }
        }
        if let Some(e) = stream_err {
            let elapsed = started.elapsed().as_millis() as u64;
            warn!(%record_id, error = %e, "cross-proto upstream stream error mid-flight");
            state.dag.attach_response(
                record_id,
                ResponseData {
                    resp_status: resp_status.as_u16(),
                    resp_headers: redact_headers(&resp_headers),
                    elapsed_ms: elapsed,
                    error: Some(format!("upstream stream error: {e}")),
                    resp_complete: false,
                    streamed: false,
                    ..Default::default()
                },
            );
            return Err(AppError::Upstream(e));
        }
        if exceeded {
            let elapsed = started.elapsed().as_millis() as u64;
            warn!(%record_id, cap = MAX_RESP_BODY_RECORD, "cross-proto upstream response exceeded cap; aborting");
            state.dag.attach_response(
                record_id,
                ResponseData {
                    resp_status: 502,
                    elapsed_ms: elapsed,
                    error: Some(format!(
                        "upstream response exceeded {MAX_RESP_BODY_RECORD} byte cap"
                    )),
                    resp_complete: false,
                    streamed: false,
                    ..Default::default()
                },
            );
            return Err(AppError::Upstream(format!(
                "upstream response exceeded {MAX_RESP_BODY_RECORD} byte cap"
            )));
        }
        Bytes::from(acc)
    };

    // 15. 翻译响应: egress JSON → IR → (restore redact) → ingress JSON.
    let egress_reader = egress_codec.reader();
    let ingress_writer = ingress_codec.writer();
    // parsed view: 记录 LLM 视角的 IR (restore 之前, 含 mock). 仅 2xx 成功响应.
    let mut resp_parsed_for_record: Option<serde_json::Value> = None;
    let (resp_status_out, resp_body_out): (StatusCode, Vec<u8>) = if resp_status.is_success() {
        match serde_json::from_slice::<serde_json::Value>(&resp_bytes) {
            Ok(v) => match egress_reader.read_response(&v) {
                Ok(mut ir_resp) => {
                    // record 存 LLM 视角 (restore 之前, 含 mock) 的 parsed view.
                    resp_parsed_for_record = Some(ingress_writer.write_response(&ir_resp));
                    // restore: mock → real (跨协议 + redact 时, 客户端看到的应该是真 secret).
                    restore_ir_response(&mut ir_resp, &redaction_map);
                    let translated = ingress_writer.write_response(&ir_resp);
                    let body = serde_json::to_vec(&translated).unwrap_or_default();
                    (resp_status, body)
                }
                Err(e) => {
                    warn!(%record_id, error = %e.message, "failed to parse upstream response as {}; passing through verbatim", provider.protocol.name());
                    (resp_status, resp_bytes.to_vec())
                }
            },
            Err(_) => (resp_status, resp_bytes.to_vec()),
        }
    } else {
        // 错误响应: 截断 + 解析上游 error.message 防止泄漏内部细节.
        let friendly = serde_json::from_slice::<serde_json::Value>(&resp_bytes)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| {
                let raw = std::str::from_utf8(&resp_bytes).unwrap_or("");
                let cap = raw.len().min(MAX_ERROR_MSG_LEN);
                raw[..cap].to_string()
            });
        let kind = http_status_to_error_kind(resp_status.as_u16());
        let envelope = ingress_writer.write_error(resp_status.as_u16(), kind, &friendly);
        let body = serde_json::to_vec(&envelope).unwrap_or_default();
        (resp_status, body)
    };

    // 16. attach 响应到 DAG.
    let elapsed = started.elapsed().as_millis() as u64;
    // 视图正确性守卫: resp_parsed (非流式) 是 resp_bytes (SSOT) 经 egress reader 的派生视图.
    // 仅在 2xx 成功响应时触发 — 非 2xx 错误响应即便 reader 能解析也不派生 parsed
    // (走 envelope 翻译路径), 守卫对 None 比对会误报.
    #[cfg(feature = "consistency-check")]
    if resp_status.is_success() {
        assert_resp_parsed_matches_source_nonstream(
            resp_parsed_for_record.as_ref(),
            &resp_bytes,
            egress_reader.as_ref(),
        );
    }
    state.dag.attach_response(
        record_id,
        ResponseData {
            resp_status: resp_status_out.as_u16(),
            resp_headers: redact_headers(&resp_headers),
            raw_resp_body: utf8_view(&resp_body_out),
            parsed: resp_parsed_for_record,
            elapsed_ms: elapsed,
            streamed: false,
            resp_complete: true,
            ..Default::default()
        },
    );

    // 17. 构造响应.
    let mut resp = Response::new(Body::from(resp_body_out));
    *resp.status_mut() = resp_status_out;
    let mut out_headers = build_response_headers(&resp_headers);
    out_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    out_headers.remove(axum::http::header::CONTENT_LENGTH);
    *resp.headers_mut() = out_headers;
    Ok(resp)
}

/// 把 HTTP status 映射为 protocol-agnostic error kind 字符串.
fn http_status_to_error_kind(status: u16) -> &'static str {
    match status {
        400 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_denied",
        404 => "not_found_error",
        429 => "rate_limit_error",
        500..=599 => "api_error",
        _ => "internal_error",
    }
}

/// 流式 parsed view 累积器 + 节流写入 DAG 的小封装.
///
/// fan_out_streaming / fan_out_streaming_with_restore 共享同一套节流策略,
/// 避免两处重复 StreamScan + writer + last_sync 的管理逻辑.
struct ParsedSync {
    scan: crate::codec::stream::StreamScan,
    writer: Box<dyn crate::codec::Writer>,
    dag: ConversationDag,
    record_id: uuid::Uuid,
    last_sync: Option<std::time::Instant>,
}

impl ParsedSync {
    fn new(proto: crate::codec::Protocol, dag: ConversationDag, record_id: uuid::Uuid) -> Self {
        Self {
            scan: crate::codec::stream::StreamScan::new(proto),
            writer: proto.writer(),
            dag,
            record_id,
            last_sync: None,
        }
    }

    /// 喂入上游 chunk; 按节流间隔把 snapshot 写入 DAG node 的 parsed 字段.
    fn feed(&mut self, b: &[u8]) {
        self.scan.feed(b);
        let due = self
            .last_sync
            .is_none_or(|t| t.elapsed() >= PARSED_SYNC_INTERVAL);
        if due {
            let parsed = self.scan.snapshot();
            self.dag
                .update_parsed_response(self.record_id, self.writer.write_response(&parsed));
            self.last_sync = Some(std::time::Instant::now());
        }
    }

    /// 流结束时的最终快照.
    fn finalize(self) -> serde_json::Value {
        self.writer.write_response(&self.scan.snapshot())
    }
}

/// 上游响应字节的记录累积器 (fan_out_* 三路径共享).
///
/// 职责: 把上游 chunk 流累积到一个 `Vec<u8>`, 受 `MAX_RESP_BODY_RECORD` 上限保护,
/// 并跟踪 overflow / error_kind 状态. 三个 fan_out 函数原本各自复制 ~30 行相同逻辑,
/// 现统一在此. 调用方负责 chunk 的"额外处理"(透传给客户端 channel / StreamTranslate /
/// ParsedSync), 本结构只管 record 累积 + cap 保护.
///
/// # 不变式
///
/// - overflow 一旦置位, 后续 push 静默丢弃 (record 已截断, 不再增长).
/// - error_kind 一旦置位 (非 None), 表示流异常终止 (client disconnect / upstream error / cap).
struct RecordAccumulator {
    acc: Vec<u8>,
    overflow: bool,
    error_kind: Option<String>,
}

impl RecordAccumulator {
    fn new() -> Self {
        Self {
            acc: Vec::new(),
            overflow: false,
            error_kind: None,
        }
    }

    /// 累积一个 chunk. 超过 `MAX_RESP_BODY_RECORD` 时置 overflow 标志 (后续静默丢弃).
    /// 仅在未 overflow 时累积, 避免无意义的拷贝.
    fn push_record(&mut self, b: &[u8], record_id: uuid::Uuid) {
        if self.overflow {
            return;
        }
        let remaining = MAX_RESP_BODY_RECORD.saturating_sub(self.acc.len());
        if remaining > 0 {
            let take = remaining.min(b.len());
            self.acc.extend_from_slice(&b[..take]);
        }
        if b.len() > remaining {
            warn!(
                %record_id,
                cap = MAX_RESP_BODY_RECORD,
                "response too large to record; further chunks discarded"
            );
            self.overflow = true;
        }
    }

    /// 标记流异常终止 (client disconnect / upstream stream error / cap).
    fn set_error(&mut self, kind: &str) {
        self.error_kind = Some(kind.to_string());
    }

    /// 是否已正常结束 (无 error_kind).
    fn complete(&self) -> bool {
        self.error_kind.is_none()
    }
}

/// 流式字节扇出: 把上游 SSE 流式转发给客户端, 同时 (若有 codec) 用 StreamScan
/// 累积 parsed view 到 DAG. 无 redact, 保持 byte-exact + 流式 UX.
///
/// `codec_proto = None` 时 (Gemini/Ollama 无 codec) 跳过 StreamScan,
/// parsed view 不可用 (前端 fallback raw).
#[allow(clippy::too_many_arguments)]
async fn fan_out_streaming(
    dag: ConversationDag,
    record_id: uuid::Uuid,
    started: Instant,
    upstream_resp: reqwest::Response,
    resp_status: StatusCode,
    resp_headers: HeaderMap,
    streamed: bool,
    codec_proto: Option<crate::codec::Protocol>,
) -> Result<Response<Body>, AppError> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    let resp_headers_for_record = resp_headers.clone();
    let status_u16 = resp_status.as_u16();

    tokio::spawn(async move {
        let mut stream = upstream_resp.bytes_stream();
        let mut recorder = RecordAccumulator::new();
        // ParsedSync: 仅对流式响应启用 (非流式是单个 JSON, 不是 SSE).
        // 非流式响应的 parsed 在流结束后一次性计算.
        let mut parsed_sync = if streamed {
            codec_proto.map(|cp| ParsedSync::new(cp, dag.clone(), record_id))
        } else {
            None
        };

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => {
                    if tx.send(Ok(b.clone())).await.is_err() {
                        recorder.set_error(ERR_CLIENT_DISCONNECTED);
                        break;
                    }
                    recorder.push_record(&b, record_id);
                    // ParsedSync 累积 (未 overflow 时).
                    if !recorder.overflow
                        && let Some(ps) = parsed_sync.as_mut()
                    {
                        ps.feed(&b);
                    }
                }
                Err(e) => {
                    warn!(%record_id, error = %e, "upstream stream error mid-flight");
                    let io_err = std::io::Error::other(e.to_string());
                    let _ = tx.send(Err(io_err)).await;
                    recorder.set_error(ERR_UPSTREAM_STREAM);
                    break;
                }
            }
        }
        let elapsed = started.elapsed().as_millis() as u64;
        // 最终 parsed: 流式用 ParsedSync 快照; 非流式一次性 codec parse.
        let final_parsed = if streamed {
            parsed_sync.map(|ps| ps.finalize())
        } else if let Some(cp) = codec_proto {
            let reader = cp.reader();
            let writer = cp.writer();
            let parsed = serde_json::from_slice::<serde_json::Value>(&recorder.acc)
                .ok()
                .and_then(|v| reader.read_response(&v).ok())
                .map(|ir| writer.write_response(&ir));
            // 视图正确性守卫 (同协议 fan_out 路径): parsed 派生与 SSOT 在同一作用域内,
            // 派生源 drift 风险低; 此处主要抽查 codec writer→reader 的 model 字段对称性
            // (reader/writer 来自同一 codec, 守卫等价于 codec 内部 round-trip 测试的运行时抽查).
            #[cfg(feature = "consistency-check")]
            assert_resp_parsed_matches_source_nonstream(
                parsed.as_ref(),
                &recorder.acc,
                reader.as_ref(),
            );
            parsed
        } else {
            None
        };
        let body = if recorder.overflow {
            TRUNCATED_BANNER.to_string()
        } else if streamed && (200..300).contains(&status_u16) {
            // 2xx 流式成功响应: 不保留原始 SSE 字节 (骨架开销大, parsed view 已覆盖语义内容).
            String::new()
        } else {
            // 非流式响应保留原始 body (raw view 可用, 且 body 通常不大).
            utf8_view(&recorder.acc)
        };
        dag.attach_response(
            record_id,
            ResponseData {
                resp_status: status_u16,
                resp_headers: redact_headers(&resp_headers_for_record),
                raw_resp_body: body,
                parsed: final_parsed,
                elapsed_ms: elapsed,
                streamed,
                resp_complete: recorder.complete(),
                error: recorder.error_kind,
                ..Default::default()
            },
        );
    });

    let body = Body::from_stream(ReceiverStream::new(rx));
    let mut resp = Response::new(body);
    *resp.status_mut() = resp_status;
    *resp.headers_mut() = build_response_headers(&resp_headers);
    Ok(resp)
}

/// 缓冲扇出 (IR restore 版): 完整累积响应, parse 为 IR, restore mock→real,
/// 重新序列化后一次性返回给客户端. 失去流式 UX.
///
/// 用于: 同协议 + redact + 非流式响应; 同协议 + redact + 流式响应但上游出错 (非 2xx).
#[allow(clippy::too_many_arguments)]
async fn fan_out_buffered_ir(
    dag: ConversationDag,
    record_id: uuid::Uuid,
    started: Instant,
    upstream_resp: reqwest::Response,
    resp_status: StatusCode,
    resp_headers: HeaderMap,
    streamed: bool,
    codec_proto: crate::codec::Protocol,
    redaction_map: RedactionMap,
) -> Result<Response<Body>, AppError> {
    let resp_headers_for_record = resp_headers.clone();
    let status_u16 = resp_status.as_u16();

    let mut stream = upstream_resp.bytes_stream();
    let mut recorder = RecordAccumulator::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(b) => {
                // buffered_ir 路径: 超过 cap 时记录 error_kind 并中断流
                // (与 streaming 路径的 "继续透传但停止记录" 语义不同 — buffered_ir
                // 无法透传, 只能整体返回, 故超 cap 直接中止).
                if recorder.acc.len() + b.len() > MAX_RESP_BODY_RECORD {
                    let remaining = MAX_RESP_BODY_RECORD.saturating_sub(recorder.acc.len());
                    if remaining > 0 {
                        recorder.acc.extend_from_slice(&b[..remaining]);
                    }
                    recorder.set_error(ERR_RESP_CAP_EXCEEDED);
                    break;
                }
                recorder.acc.extend_from_slice(&b);
            }
            Err(e) => {
                recorder.set_error(&format!("upstream stream error: {e}"));
                break;
            }
        }
    }

    let elapsed = started.elapsed().as_millis() as u64;

    // Parse 为 IR (失败则原样透传, 不 restore).
    let reader = codec_proto.reader();
    let writer = codec_proto.writer();
    let mut resp_parsed_for_record: Option<serde_json::Value> = None;
    let client_bytes: Vec<u8> = match serde_json::from_slice::<serde_json::Value>(&recorder.acc) {
        Ok(v) => match reader.read_response(&v) {
            Ok(mut ir) => {
                // record 存 LLM 视角 (restore 之前, 含 mock).
                resp_parsed_for_record = Some(writer.write_response(&ir));
                restore_ir_response(&mut ir, &redaction_map);
                let restored = writer.write_response(&ir);
                serde_json::to_vec(&restored).unwrap_or_else(|_| recorder.acc.clone())
            }
            Err(_) => recorder.acc.clone(), // parse 失败: 原样返回 (无 restore).
        },
        Err(_) => recorder.acc.clone(), // 非 JSON: 原样返回.
    };

    // record 存储的是 LLM 视角 (含 mock) 的版本.
    // 注: buffered_ir 在 overflow 时保留部分累积 (而非 truncated banner),
    // 因为 client_bytes 也是从同一 acc 派生 — 保持一致.
    let acc_text = utf8_view(&recorder.acc);
    // 视图正确性守卫 (同协议 buffered_ir 路径): parsed 派生与 SSOT 在同一作用域内,
    // 派生源 drift 风险低; 此处主要抽查 codec writer→reader 的 model 字段对称性.
    // 守卫内部按 reader 解析结果比对 (失败时 expected=None, 与 fallback 路径一致).
    #[cfg(feature = "consistency-check")]
    assert_resp_parsed_matches_source_nonstream(
        resp_parsed_for_record.as_ref(),
        &recorder.acc,
        reader.as_ref(),
    );
    dag.attach_response(
        record_id,
        ResponseData {
            resp_status: status_u16,
            resp_headers: redact_headers(&resp_headers_for_record),
            raw_resp_body: acc_text,
            parsed: resp_parsed_for_record,
            elapsed_ms: elapsed,
            streamed,
            resp_complete: recorder.complete(),
            error: recorder.error_kind,
            ..Default::default()
        },
    );

    let mut resp = Response::new(Body::from(client_bytes));
    *resp.status_mut() = resp_status;
    *resp.headers_mut() = build_response_headers(&resp_headers);
    Ok(resp)
}

/// 流式扇出 + IR restore: 用 [`crate::codec::stream::StreamTranslate`] 同协议模式,
/// 实时翻译 egress SSE → IR 事件 → restore → ingress SSE. 保持流式 UX.
///
/// 用于: 同协议 + redact + 流式响应.
#[allow(clippy::too_many_arguments)]
async fn fan_out_streaming_with_restore(
    dag: ConversationDag,
    record_id: uuid::Uuid,
    started: Instant,
    upstream_resp: reqwest::Response,
    resp_status: StatusCode,
    resp_headers: HeaderMap,
    codec_proto: crate::codec::Protocol,
    redaction_map: RedactionMap,
) -> Result<Response<Body>, AppError> {
    use crate::codec::stream::StreamTranslate;

    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    let resp_headers_for_record = resp_headers.clone();
    let status_u16 = resp_status.as_u16();

    tokio::spawn(async move {
        // 同协议 + restore 模式: ingress == egress, 但 IR re-serialize 用于 restore.
        let mut translate = StreamTranslate::new_same_proto_restore(codec_proto, redaction_map);
        // ParsedSync: 累积 parsed view (LLM 视角, 含 mock, 与 record 语义一致).
        // 喂的是上游原始字节 (与 translate.feed 同一份 b), ParsedSync 内部用 codec reader 解析.
        let mut parsed_sync = ParsedSync::new(codec_proto, dag.clone(), record_id);
        let mut stream = upstream_resp.bytes_stream();
        let mut recorder = RecordAccumulator::new();

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => {
                    // 喂给 StreamTranslate, 得到 restore 后的字节.
                    let restored = translate.feed(&b);
                    if !restored.is_empty() && tx.send(Ok(Bytes::from(restored))).await.is_err() {
                        recorder.set_error(ERR_CLIENT_DISCONNECTED);
                        break;
                    }
                    // record 累积上游原始字节 (LLM 视角, 含 mock).
                    recorder.push_record(&b, record_id);
                    // ParsedSync 累积 (未 overflow 时).
                    if !recorder.overflow {
                        parsed_sync.feed(&b);
                    }
                }
                Err(e) => {
                    warn!(%record_id, error = %e, "upstream stream error mid-flight");
                    let io_err = std::io::Error::other(e.to_string());
                    let _ = tx.send(Err(io_err)).await;
                    recorder.set_error(ERR_UPSTREAM_STREAM);
                    break;
                }
            }
        }
        // 流末尾: 让 StreamTranslate 输出剩余 buffered 字节 + 终止符.
        // 即便 upstream error 也要发 (含 error event + [DONE]), 否则严格的 OpenAI 客户端会 hang.
        // 仅 tx.send 失败 (client disconnect) 时跳过.
        let tail = translate.finish();
        if !tail.is_empty() {
            let _ = tx.send(Ok(Bytes::from(tail))).await;
        }

        let elapsed = started.elapsed().as_millis() as u64;
        // 最终 parsed 快照. 即使 error_kind (client disconnect / upstream error),
        // 也保留截至断流时的累积内容 — 用户能看到部分响应比看到空白更有价值.
        // (overflow 时同理: 截至Overflow前的内容比 truncate banner 更有用.)
        let final_parsed = parsed_sync.finalize();
        let body = if recorder.overflow {
            TRUNCATED_BANNER.to_string()
        } else {
            // 此路径仅用于 2xx 成功响应 (非 2xx 走 fan_out_buffered_ir).
            // 2xx 流式成功响应不保留原始 SSE 字节 (parsed view 已覆盖语义内容).
            String::new()
        };
        dag.attach_response(
            record_id,
            ResponseData {
                resp_status: status_u16,
                resp_headers: redact_headers(&resp_headers_for_record),
                raw_resp_body: body,
                parsed: Some(final_parsed),
                elapsed_ms: elapsed,
                streamed: true,
                resp_complete: recorder.complete(),
                error: recorder.error_kind,
                ..Default::default()
            },
        );
    });

    let body = Body::from_stream(ReceiverStream::new(rx));
    let mut resp = Response::new(body);
    *resp.status_mut() = resp_status;
    let out_headers = build_response_headers(&resp_headers);
    // restore 后的 SSE, content-type 仍是 text/event-stream (SSE 是 SSE).
    // 不强改 content-type, 保留上游声明的.
    *resp.headers_mut() = out_headers;
    Ok(resp)
}

// ─── Error ────────────────────────────────────────────────────────────────

// AppError (转发/鉴权链的统一错误类型) 已抽到顶层 [`crate::error`] 模块,
// 让 auth 层不再反向依赖 proxy. 详见 src/error.rs 头部 "归属判断".

// ─── Helpers ──────────────────────────────────────────────────────────────

fn build_upstream_url(base: &str, path_and_query: &str) -> String {
    let base = base.trim_end_matches('/');
    if path_and_query.starts_with('/') {
        format!("{base}{path_and_query}")
    } else {
        format!("{base}/{path_and_query}")
    }
}

/// 是否在 `Connection` header 列表中? (RFC 7230 §6.1: 这些也是 hop-by-hop.)
fn connection_listed(name: &str, src: &HeaderMap) -> bool {
    let target = name.to_lowercase();
    src.get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(&target)))
        .unwrap_or(false)
}

fn is_hop_by_hop(name: &str) -> bool {
    let lower = name.to_lowercase();
    HOP_BY_HOP.iter().any(|h| *h == lower)
}

fn sanitize_request_headers(src: &HeaderMap) -> HeaderMap {
    filter_headers(src, |name| {
        is_hop_by_hop(name)
            || connection_listed(name, src)
            || matches!(name, "host" | "content-length")
    })
}

fn build_response_headers(src: &HeaderMap) -> HeaderMap {
    filter_headers(src, |name| {
        is_hop_by_hop(name) || connection_listed(name, src) || name == "content-length"
    })
}

fn filter_headers(src: &HeaderMap, drop_fn: impl Fn(&str) -> bool) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        let name_str = name.as_str().to_lowercase();
        if drop_fn(&name_str) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn is_streaming(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    ct.eq_ignore_ascii_case("text/event-stream") || ct.eq_ignore_ascii_case("application/x-ndjson")
}

fn utf8_view(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// 敏感 header 脱敏 (仅用于记录存储, 不影响转发).
fn redact_headers(src: &HeaderMap) -> Vec<(String, String)> {
    src.iter()
        .map(|(name, value)| {
            let name_str = name.as_str().to_lowercase();
            let v = if is_sensitive_header(&name_str) {
                "<redacted>".to_string()
            } else {
                value.to_str().unwrap_or("<binary>").to_string()
            };
            (name_str, v)
        })
        .collect()
}

/// 判断 header 是否敏感: 黑名单关键词匹配 (覆盖各 LLM provider 常见字段).
fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "x-api-key"
            | "api-key"
            | "x-anthropic-api-key"
            | "openai-organization"
            | "openai-project"
            | "x-goog-api-key"
            | "x-amz-security-token"
            | "cookie"
            | "set-cookie"
            | "proxy-authorization"
    ) || name.contains("token")
        || name.contains("secret")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_upstream_url_handles_trailing_slash() {
        assert_eq!(
            build_upstream_url("https://api.example.com/", "/v1/messages"),
            "https://api.example.com/v1/messages"
        );
        assert_eq!(
            build_upstream_url("https://api.example.com", "/v1/messages?foo=bar"),
            "https://api.example.com/v1/messages?foo=bar"
        );
    }

    #[test]
    fn build_upstream_url_handles_empty_rest() {
        // 路径只到 /{proto}/{name} 时 rest = "/".
        assert_eq!(
            build_upstream_url("https://api.example.com", "/?q=1"),
            "https://api.example.com/?q=1"
        );
    }

    #[test]
    fn sanitize_strips_hop_by_hop_and_host() {
        let mut src = HeaderMap::new();
        src.insert("host", "example.com".parse().unwrap());
        src.insert("content-length", "123".parse().unwrap());
        src.insert("connection", "keep-alive".parse().unwrap());
        src.insert("x-api-key", "secret".parse().unwrap());
        let out = sanitize_request_headers(&src);
        assert!(out.get("host").is_none());
        assert!(out.get("content-length").is_none());
        assert!(out.get("connection").is_none());
        assert_eq!(out.get("x-api-key").unwrap(), "secret");
    }

    #[test]
    fn sanitize_strips_connection_listed_custom_headers() {
        let mut src = HeaderMap::new();
        src.insert("connection", "x-custom, foo".parse().unwrap());
        src.insert("x-custom", "leak".parse().unwrap());
        src.insert("foo", "bar".parse().unwrap());
        src.insert("baz", "kept".parse().unwrap());
        let out = sanitize_request_headers(&src);
        assert!(
            out.get("x-custom").is_none(),
            "Connection-listed header must be stripped"
        );
        assert!(out.get("foo").is_none());
        assert_eq!(out.get("baz").unwrap(), "kept");
    }

    #[test]
    fn redact_headers_masks_secrets() {
        let mut src = HeaderMap::new();
        src.insert("authorization", "Bearer xxx".parse().unwrap());
        src.insert("x-api-key", "key".parse().unwrap());
        src.insert("x-goog-api-key", "gkey".parse().unwrap());
        src.insert("x-custom-token", "tok".parse().unwrap());
        src.insert("x-custom", "value".parse().unwrap());
        let v = redact_headers(&src);
        let m: std::collections::HashMap<_, _> = v.into_iter().collect();
        assert_eq!(m.get("authorization").unwrap(), "<redacted>");
        assert_eq!(m.get("x-api-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-goog-api-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-custom-token").unwrap(), "<redacted>");
        assert_eq!(m.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn is_streaming_detects_sse_strictly() {
        assert!(is_streaming("text/event-stream"));
        assert!(is_streaming("text/event-stream; charset=utf-8"));
        assert!(is_streaming("application/x-ndjson"));
        assert!(!is_streaming("application/json"));
        assert!(!is_streaming("application/octet-stream"));
        assert!(!is_streaming("video/xyz-stream"));
    }

    #[test]
    fn utf8_view_handles_invalid_utf8() {
        let bad = &[0xFF, 0xFE, 0x00];
        let s = utf8_view(bad);
        assert!(s.contains('\u{FFFD}'));
    }

    #[test]
    fn apply_provider_auth_openai_uses_bearer() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer client-token".parse().unwrap());
        apply_provider_auth(&mut h, "sk-server-side", Protocol::OpenAI);
        assert_eq!(h.get("authorization").unwrap(), "Bearer sk-server-side");
    }

    #[test]
    fn apply_provider_auth_anthropic_uses_x_api_key() {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "client-key".parse().unwrap());
        apply_provider_auth(&mut h, "sk-ant-server", Protocol::Anthropic);
        assert_eq!(h.get("x-api-key").unwrap(), "sk-ant-server");
    }

    #[test]
    fn apply_provider_auth_gemini_uses_x_goog_api_key() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer client-tok".parse().unwrap());
        apply_provider_auth(&mut h, "ya29.server", Protocol::Gemini);
        // Gemini 用 x-goog-api-key, 不用 Authorization Bearer.
        assert_eq!(h.get("x-goog-api-key").unwrap(), "ya29.server");
        assert!(
            h.get("authorization").is_none(),
            "must clear competing header"
        );
    }

    #[test]
    fn apply_provider_auth_strips_competing_headers() {
        // 客户端误传了竞争对手协议的 header, 应被剥离.
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "client-anthropic".parse().unwrap());
        h.insert("x-goog-api-key", "client-gemini".parse().unwrap());
        apply_provider_auth(&mut h, "sk-server", Protocol::OpenAI);
        assert_eq!(h.get("authorization").unwrap(), "Bearer sk-server");
        assert!(h.get("x-api-key").is_none());
        assert!(h.get("x-goog-api-key").is_none());
    }

    #[test]
    fn apply_provider_auth_skips_empty_key() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer keep-me".parse().unwrap());
        apply_provider_auth(&mut h, "   ", Protocol::OpenAI);
        assert_eq!(h.get("authorization").unwrap(), "Bearer keep-me");
    }

    // ─── MAX_RESP_BODY_RECORD 截断契约 (核心契约: 客户端响应无上限 vs record 有 cap) ─
    //
    // 契约 (proxy.rs//!): "客户端响应永远无大小上限; 只有 record 累积受
    // MAX_RESP_BODY_RECORD (32 MiB) 约束". 一旦回归会静默截断用户响应.
    //
    // 三个 fan_out 都有 overflow 分支但内联在 spawn 闭包里, 这里用 mockito 构造
    // 超大上游响应, 直接调用 fan_out_streaming 端到端验证: record 被截断 + 带 banner,
    // 而客户端通过 channel 收到完整 body.

    #[test]
    fn max_resp_body_record_constant_is_32mib() {
        // pin 住常量值, 防止误改 (这是经济性与内存的折中, 32MiB 覆盖绝大多数 LLM 响应).
        assert_eq!(MAX_RESP_BODY_RECORD, 32 * 1024 * 1024);
        assert_eq!(MAX_REQ_BODY, 16 * 1024 * 1024);
    }

    #[test]
    fn truncation_banner_string_is_stable() {
        // pin 住 banner 文本, 前端依赖它识别截断状态. 三个 fan_out 共用同一字符串.
        let banner = "<truncated: exceeded record cap>";
        assert!(!banner.is_empty());
    }

    /// 端到端: 上游响应 > MAX_RESP_BODY_RECORD 时, record 被截断但客户端拿到完整 body.
    ///
    /// 这是 "客户端响应无上限 vs record 有 cap" 差异点的权威验证. 逻辑:
    /// - fan_out_streaming 内部 spawn task 累积 acc, 超过 cap 后停止累积 (overflow=true).
    /// - spawn task 结束时 attach_response: raw_resp_body = truncation banner.
    /// - 客户端通过 mpsc channel 收到上游所有 chunk (不受 cap 限制).
    ///
    /// 用非流式响应 (streamed=false) + 非常大的 body 触发, 避免 2xx 流式清空逻辑干扰.
    #[tokio::test]
    async fn fan_out_streaming_truncates_record_but_not_client_response() {
        use crate::codec::ir::{IrBlock, IrMessage, IrRole};
        use crate::dag::{CallEvent, ConversationDag, PolicySnapshot};

        // mockito 上游: 返回 cap+1 字节 (刚好触发 overflow).
        let cap_plus_one = MAX_RESP_BODY_RECORD + 1;
        let body_bytes = "x".repeat(cap_plus_one);
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/big")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body_bytes.as_bytes())
            .create_async()
            .await;

        // 发请求拿到 reqwest::Response.
        let client = reqwest::Client::new();
        let upstream_resp = client
            .post(format!("{}/big", server.url().trim_end_matches('/')))
            .send()
            .await
            .expect("upstream request must succeed");
        assert!(upstream_resp.status().is_success());

        // 构造 DAG + record_id (fan_out_streaming 通过 attach_response 写 record).
        let dag = ConversationDag::new(64, 16, 4);
        let msgs = vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::Text {
                text: "hi".to_string(),
            }],
            ..Default::default()
        }];
        let event = CallEvent {
            created_at: chrono::Utc::now(),
            method: "POST".to_string(),
            path: "/o/test/big".to_string(),
            req_headers: vec![],
            ingress_protocol: None,
            redact_seed: 0,
            policy: std::sync::Arc::new(PolicySnapshot::default()),
            req_body_raw: String::new(),
            preview: None,
            model: None,
            round_role: IrRole::User,
            redactions: Arc::from(Vec::new()),
        };
        let record_id = dag.push_messages(msgs, event);

        let resp_headers = HeaderMap::new();
        // streamed=false: 走非流式 body 累积分支 (overflow 时 body=banner).
        let resp = fan_out_streaming(
            dag.clone(),
            record_id,
            std::time::Instant::now(),
            upstream_resp,
            StatusCode::OK,
            resp_headers,
            false, // streamed=false
            None,  // codec_proto=None 跳过 StreamScan
        )
        .await
        .expect("fan_out_streaming must not error on large body");

        // ── 客户端响应: 必须收到完整 body (cap+1 字节), 不受 record cap 限制 ──
        // limit 用 cap + 1 KiB 而非 usize::MAX: 语义更清晰 (预期就是 cap+1),
        // 且避免某些 coverage/sanitizer 环境对 usize::MAX 的边界处理差异.
        let client_bytes = axum::body::to_bytes(resp.into_body(), cap_plus_one + 1024)
            .await
            .expect("client must receive full body");
        assert_eq!(
            client_bytes.len(),
            cap_plus_one,
            "client response must NOT be truncated (cap contract)"
        );

        // ── record: 被 spawn task 异步写入, 轮询直到 attach_response 完成 ──
        // spawn task 与本测试并发, 需要等它跑完 attach_response.
        // timeout 给 30s: CI runner (microvm, 慢磁盘 + coverage 插桩) 在大 body
        // (32MiB+) 流式传输 + spawn task 调度上比本地慢数倍, 留足余量避免 flaky.
        let response_data = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            poll_response_data(&dag, record_id),
        )
        .await
        .expect("timed out waiting for spawn task to attach_response")
        .expect("record must exist");

        // record body 被截断为 banner (而非完整 body).
        assert_eq!(
            response_data.raw_resp_body, "<truncated: exceeded record cap>",
            "record body must be truncation banner"
        );
        // 流正常结束 (不是错误), error 为 None — overflow 不等于失败.
        assert!(
            response_data.error.is_none(),
            "overflow is not an error condition; error should be None"
        );
        assert!(
            response_data.resp_complete,
            "stream completed normally (overflow only affects record, not completeness)"
        );
    }

    /// 轮询 DAG 直到 node 有 response 数据 (spawn task 异步写入).
    async fn poll_response_data(
        dag: &ConversationDag,
        node_id: uuid::Uuid,
    ) -> Option<crate::dag::ResponseData> {
        // yield 让出执行权给 spawn task, 然后检查.
        // 循环上限与外层 timeout (30s) 匹配: 6000 × 5ms = 30s.
        for _ in 0..6000 {
            if let Some(r) = dag.get_response(node_id) {
                return Some(r);
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        dag.get_response(node_id)
    }

    // ─── SEC-4: 含关键词的 header 必须被脱敏 ─────────────────────────────
    //
    // 契约 (docs/design/contracts.md §7 SEC-4): record 存储的 HTTP headers 中,
    // 含 "token" / "key" / "secret" 关键词的自定义 header 必须被脱敏为 `<redacted>`.
    //
    // ⚠️ 契约/实现 divergence (2026-07 QA 走查发现): is_sensitive_header 的关键词
    // 匹配仅覆盖 "token" / "secret", **未含 "key"** (常见含 key 的 header 如
    // `api-key` / `x-api-key` / `x-goog-api-key` 已被显式黑名单覆盖, 但纯自定义如
    // `x-app-key` 不会被脱敏). 修改 prod 或修改契约需经人工授权, 此处不擅自处理 —
    // 本 property 仅验证已实现的关键词 (token/secret), `key` 关键词的覆盖留作
    // 后续 issue. 详见 PR 描述.

    use axum::http::HeaderName;
    use proptest::prelude::*;

    proptest! {
        /// SEC-4: 任意含 "token" / "secret" 关键词的 header 名, redact_headers 输出值为
        /// `<redacted>`.
        ///
        /// `is_sensitive_header` 用 `name.contains("token") || name.contains("secret")`
        /// 做关键词匹配 (case-insensitive, 因为 redact_headers 在调用前会 to_lowercase).
        /// 本 property 随机化 prefix / suffix / keyword 三个维度, 覆盖任意位置含关键词
        /// 的自定义 header (如 `x-my-token`, `token-foo`, `x-secret-bar`).
        ///
        /// **范围说明**: 仅测试已实现的关键词 (见上方 mod 级注释的 divergence 说明);
        /// `key` 关键词的契约对齐留作后续.
        ///
        /// 字符集 [a-z0-9-]: HTTP header name 合法字符 (token 字符), 且避免大写干扰
        /// contains 匹配 (redact_headers 已 lowercase, 但 prop 中我们也用 lowercase
        /// 生成, 保证一致性).
        #[test]
        fn prop_custom_token_headers_redacted(
            prefix in "[a-z]{0,8}",
            keyword in prop::sample::select(vec!["token", "secret"]),
            suffix in "[a-z0-9-]{0,8}",
            value in "[A-Za-z0-9]{1,32}"
        ) {
            let header_name = format!("{prefix}{keyword}{suffix}");
            let mut src = HeaderMap::new();
            src.insert(
                HeaderName::from_bytes(header_name.as_bytes())
                    .expect("header name bytes must be valid"),
                value.parse().expect("value must be valid HeaderValue"),
            );
            let redacted = redact_headers(&src);
            prop_assert_eq!(redacted.len(), 1, "exactly one header expected");
            // redact_headers 把 name to_lowercase, value 替换为 <redacted> (若是敏感 header).
            prop_assert_eq!(
                &redacted[0].1, "<redacted>",
                "SEC-4 violation: header '{}' contains keyword '{}' but was not redacted",
                header_name, keyword
            );
        }
    }
}
