//! 端到端集成测试: 启动 secret-guard + mock 上游, 验证透传功能.
//!
//! 测试覆盖:
//! - 多 provider 路由 (`/{proto}/{name}/*`).
//! - 同协议 identity passthrough (OpenAI / Anthropic / Gemini / Ollama).
//! - 跨协议请求返回 501.
//! - 未知 provider / 禁用 provider 返回 404 / 503.
//! - 未知 protocol 简写返回 404.
//! - 流式 SSE / 非流式 JSON 透传.
//! - 请求 header 透传; provider api_key 覆盖客户端 auth.
//! - 转发记录被持久化.
//! - 上游不可达时返回 502 + record 标记 incomplete.
//! - Web UI: `/` 根路径 HTML; `/api/*` JSON.

use std::time::Duration;

use secret_guard::{
    dag::ConversationDag,
    provider::{
        DirectProvider, Protocol, Provider, ProviderKind, ProviderTable, Route, RouterProvider,
    },
    record::ForwardRecord,
    secrets::{SecretCategory, SecretEntry, SecretTable},
    server,
    state::AppState,
};
use tokio::net::TcpListener;

/// 生成唯一的 state.toml 临时路径, 并确保父目录存在
/// (atomic_write 不创建目录, 集成测试的 CRUD 会触发持久化).
fn tmp_state_path(label: &str) -> std::path::PathBuf {
    let id = uuid::Uuid::new_v4().to_string();
    let path = std::path::PathBuf::from(format!("/tmp/opencode/tmp/test-{label}-{id}.toml"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

/// 构造空 ApiKeyStore (与 server.rs::serve 的真实构造路径一致, 见 #146 顺带项 b:
/// AppState.api_keys 改裸类型后, 测试不再走 `None` 简化写法).
fn test_api_key_store() -> secret_guard::auth::ApiKeyStore {
    secret_guard::auth::ApiKeyStore::new(
        &[],
        std::path::Path::new("."),
        vec![],
        std::collections::HashSet::new(),
        tmp_state_path("api-keys"),
        std::sync::Arc::new(parking_lot::Mutex::new(())),
    )
}

async fn spawn_mock_upstream() -> mockito::ServerGuard {
    mockito::Server::new_async().await
}

/// 启动 secret-guard, 单 provider (默认 OpenAI 协议, base_url = mock 上游).
async fn spawn_proxy_with_provider(provider: Provider) -> String {
    spawn_proxy_full(
        vec![provider],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
}

/// 启动 secret-guard, 默认 OpenAI provider 指向 mock 上游.
async fn spawn_proxy(upstream_base: &str) -> String {
    let provider = openai_provider("oa-main", upstream_base);
    spawn_proxy_with_provider(provider).await
}

fn openai_provider(id: &str, base_url: &str) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Direct(DirectProvider {
            protocol: Protocol::OpenAI,
            base_url: base_url.into(),
            api_key: "sk-test-key".into(),
            api_key_file: None,
        }),
    }
}

fn provider_with(id: &str, proto: Protocol, base_url: &str) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Direct(DirectProvider {
            protocol: proto,
            base_url: base_url.into(),
            api_key: String::new(),
            api_key_file: None,
        }),
    }
}

/// #157 族: 指定 inline api_key 的 OpenAI provider (openai_provider 变体).
fn keyed_provider(id: &str, base_url: &str, api_key: &str) -> Provider {
    let mut p = openai_provider(id, base_url);
    if let ProviderKind::Direct(d) = &mut p.kind {
        d.api_key = api_key.into();
    }
    p
}

/// 路由: model_pattern → target (priority 默认 Some(0) = 启用, 无 upstream_model 改写).
fn route(model_pattern: &str, target: &str) -> Route {
    Route {
        model_pattern: model_pattern.into(),
        target: target.into(),
        upstream_model: None,
        priority: Some(0),
    }
}

/// #179: catch-all 路由 provider (单路由 model_pattern="*" 指向 target — 旧 route_to
/// 硬指向的等价形态). 构造无 protocol 字段 (见 RouterProvider 注释).
fn catch_all_router(id: &str, target: &str) -> Provider {
    router_provider(id, vec![route("*", target)])
}

/// #179 多规则化: 路由 provider (显式路由列表).
fn router_provider(id: &str, routes: Vec<Route>) -> Provider {
    Provider {
        kind: ProviderKind::Router(RouterProvider { routes }),
        ..openai_provider(id, "https://ignored.invalid")
    }
}

/// 路由 (带 upstream_model 改写): model_pattern 匹配的请求路由到 target 且出站 model 重写.
fn rewrite_route(model_pattern: &str, target: &str, model: &str) -> Route {
    Route {
        model_pattern: model_pattern.into(),
        target: target.into(),
        upstream_model: Some(model.into()),
        priority: Some(0),
    }
}
#[allow(clippy::too_many_arguments)]
async fn spawn_proxy_full(
    providers: Vec<Provider>,
    upstream: reqwest::Client,
    records: ConversationDag,
    secrets: SecretTable,
) -> String {
    spawn_proxy_static_dynamic(vec![], providers, upstream, records, secrets)
        .await
        .0
}

/// 显式同时指定 static + dynamic 两层.
/// 返回 (proxy_url, providers 表的 state.toml 路径) — 后者供测试断言 state 文件内容
/// (#157: 验证明文 api_key 不落盘).
/// 旧 helper (`spawn_proxy_full`) 把所有传入视为 dynamic, 仍保持向后兼容.
#[allow(clippy::too_many_arguments)]
async fn spawn_proxy_static_dynamic(
    static_providers: Vec<Provider>,
    dynamic_providers: Vec<Provider>,
    upstream: reqwest::Client,
    records: ConversationDag,
    secrets: SecretTable,
) -> (String, std::path::PathBuf) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("sg-state");

    // 共享 decisions + persist_lock, 模拟生产环境的双表协同.
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));

    let provider_table = ProviderTable::with_persist_lock(
        static_providers,
        dynamic_providers,
        decisions.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );

    // SecretTable 由调用方构造 (内部已带独立的 decisions + persist_lock).
    // 测试场景下 secrets 与 providers 不共享 state 文件, 不影响测试结论.
    let _ = (decisions, persist_lock);
    // [redact] 三 gate 镜像生产默认 (base_app_state SSOT, SEC-10); 需要 opt-in
    // 的测试用 spawn_proxy_with_redact_gates 显式传三 gate.
    let proxy = base_app_state(upstream, provider_table, records, secrets);
    let app = server::build_router(
        proxy,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), state_path)
}

/// 启动 secret-guard, 可配置 global_mock_prefix (用于测试 prefix 拒绝等场景).
async fn spawn_proxy_with_prefix(global_mock_prefix: &str) -> String {
    let upstream = spawn_mock_upstream().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("sg-state-prefix");
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));
    let provider_table = ProviderTable::with_persist_lock(
        vec![openai_provider("oa-main", &upstream.url())],
        vec![],
        decisions.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );
    let secrets = test_secret_table();
    let _ = (decisions, persist_lock, state_path);
    let proxy = AppState {
        global_mock_prefix: std::sync::Arc::from(global_mock_prefix),
        ..base_app_state(
            reqwest::Client::new(),
            provider_table,
            ConversationDag::new(64, 500, 1),
            secrets,
        )
    };
    let app = server::build_router(
        proxy,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// SEC-4: 启动 secret-guard, 显式配置 `[redact] redacted_headers` (自定义敏感
/// header 脱敏名单). 模拟生产 serve() 的装配 (normalize → AppState), 用于
/// redacted_headers 端到端测试.
async fn spawn_proxy_with_redacted_headers(
    redacted_headers: Vec<String>,
    upstream_base: &str,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("sg-state-redacted-headers");
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));
    let provider_table = ProviderTable::with_persist_lock(
        vec![openai_provider("oa-main", upstream_base)],
        vec![],
        decisions.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );
    let secrets = test_secret_table();
    let _ = (decisions, persist_lock, state_path);
    let proxy = AppState {
        redacted_headers: secret_guard::state::normalize_redacted_headers(&redacted_headers),
        ..base_app_state(
            reqwest::Client::new(),
            provider_table,
            ConversationDag::new(64, 500, 1),
            secrets,
        )
    };
    let app = server::build_router(
        proxy,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// AppState 测试构造 SSOT: 恒定字段 (api_keys / auth_enabled / [redact] 三 gate
/// 镜像生产默认 SEC-10 / model_lists / pricing) 收口在此; 差异字段经参数传入,
/// 个别差异用 struct-update 覆盖 (`AppState { field, ..base_app_state(..) }`).
/// 新增 AppState 字段时: 默认值改这里, 非 harness 字面量会因缺字段编译失败 —
/// 强制逐处显式决策, 杜绝镜像漂移 (曾发生: gate 默认翻转漏改 3 处 harness).
fn base_app_state(
    upstream: reqwest::Client,
    providers: ProviderTable,
    dag: ConversationDag,
    secrets: SecretTable,
) -> AppState {
    let redact = secret_guard::config::RedactConfig::default();
    AppState {
        upstream,
        providers,
        dag,
        secrets,
        api_keys: test_api_key_store(),
        auth_enabled: false,
        global_mock_prefix: std::sync::Arc::from(""),
        on_probe_exhausted: redact.on_probe_exhausted,
        on_unsupported_protocol: redact.on_unsupported_protocol,
        on_fallback_restore: redact.on_fallback_restore,
        // SEC-4: 镜像生产装配 (normalize 后入 state); 测试要配置自定义名单时用
        // struct-update 覆盖 (见 spawn_proxy_with_redacted_headers).
        redacted_headers: secret_guard::state::normalize_redacted_headers(&redact.redacted_headers),
        upstream_timeouts: secret_guard::config::UpstreamTimeouts::default(),
        model_lists: std::sync::Arc::new(secret_guard::proxy::ModelListCache::new()),
        usage: std::sync::Arc::new(secret_guard::usage::UsageStore::in_memory()),
        pricing: std::sync::Arc::new(secret_guard::usage::PricingCache::for_tests()),
    }
}

/// 启动 secret-guard, 显式指定三个 `[redact]` 降级 gate (on_probe_exhausted /
/// on_unsupported_protocol / on_fallback_restore) + provider 列表 + secret 表 +
/// upstream client. (`spawn_proxy_with_probe_mode` / codec-less 停损 / RED-8 restore
/// opt-in 测试的共享核心 — 三个 gate 独立配置, 各测试只动其需要的, 其余传
/// `..::default()` 保持生产默认, SEC-10 降级偏安全.)
#[allow(clippy::too_many_arguments)]
async fn spawn_proxy_with_redact_gates(
    on_probe_exhausted: secret_guard::config::OnProbeExhausted,
    on_unsupported_protocol: secret_guard::config::OnUnsupportedProtocol,
    on_fallback_restore: secret_guard::config::OnFallbackRestore,
    providers: Vec<Provider>,
    secrets: SecretTable,
    upstream: reqwest::Client,
    state_tag: &str,
    records: ConversationDag,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path(state_tag);
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));
    let provider_table = ProviderTable::with_persist_lock(
        providers,
        vec![],
        decisions.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );
    let _ = (decisions, persist_lock, state_path);
    let proxy = AppState {
        on_probe_exhausted,
        on_unsupported_protocol,
        on_fallback_restore,
        ..base_app_state(upstream, provider_table, records, secrets)
    };
    let app = server::build_router(
        proxy,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// 启动 secret-guard, 显式指定 `[redact] on_probe_exhausted` 模式 (单个 openai provider).
///
/// 用于 fail_closed / fail_open 集成测试: 构造弱配置 secret + 对抗性 IR → 验证
/// proxy 按 mode 返回 503 (fail_closed) / 正常转发 (fail_open). 其余两 gate
/// 保持生产默认 (on_fallback_restore 仅管响应侧 fallback, 与 probing 耗尽正交).
async fn spawn_proxy_with_probe_mode(
    mode: secret_guard::config::OnProbeExhausted,
    secrets: SecretTable,
    upstream_url: &str,
) -> String {
    spawn_proxy_with_redact_gates(
        mode,
        secret_guard::config::OnUnsupportedProtocol::default(),
        secret_guard::config::OnFallbackRestore::default(),
        vec![openai_provider("oa-main", upstream_url)],
        secrets,
        reqwest::Client::new(),
        "sg-state-probe",
        ConversationDag::new(64, 500, 1),
    )
    .await
}

fn test_secret_table() -> SecretTable {
    test_secret_table_with(vec![])
}

fn test_secret_table_with(entries: Vec<SecretEntry>) -> SecretTable {
    let path = tmp_state_path("secret-table");
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    // 旧测试语义: 把传入 entries 视为 dynamic (供 redact 流程使用).
    SecretTable::new(vec![], entries, decisions, path)
}

fn secret(id: &str, value: &str) -> SecretEntry {
    let mut e = SecretEntry {
        id: id.into(),
        name: Some(id.into()),
        category: SecretCategory::ApiKey,
        value: value.into(),
        value_file: None,
        mock_strategy: secret_guard::mock::MockStrategy::default(),
    };
    // 模拟生产 validate_and_resolve 路径: 让 Auto 模式的 gen spec 被 infer.
    // 测试用空 global_prefix (与原固定无前缀语义对齐).
    e.mock_strategy.resolve_against(&e.value, "");
    e
}

/// 预测 redact 对给定 real_secret 生成的首个 mock (counter=0).
///
/// 与生产 [`secret_guard::redact::redact_ir`] 路径一致:
/// [`secret_guard::mock::deterministic_seed`] + counter=0.
/// 用于集成测试中 mockito 上游响应 fixture (需要预知 mock 值才能构造"LLM echo 了 mock"的场景).
fn predict_mock(real: &str) -> String {
    use secret_guard::mock::{deterministic_seed, gen_candidate};
    let entry = secret("predict", real);
    let seed = deterministic_seed(&entry.value, &entry.mock_strategy);
    gen_candidate(&entry.value, &entry.mock_strategy, seed, 0)
}

async fn proxy_request(
    proxy_url: &str,
    method: &str,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (reqwest::StatusCode, String, reqwest::header::HeaderMap) {
    let mut builder = reqwest::Client::new().request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
        format!("{proxy_url}{path}"),
    );
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let resp = builder.body(body.to_string()).send().await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap();
    (status, text, headers)
}

// ─── 转发链可观测性测试的 tracing 捕获 (#158/#160/#162/#163) ────────────────
//
// thread-scoped capture: `set_default` 设置 thread-local dispatcher 后, 同线程上
// (含 #[tokio::test] current-thread runtime 内 spawn 的 axum server 任务) 的
// tracing 事件都路由到捕获 writer, 无需全局 subscriber (并行测试互不干扰).

/// 捕获 tracing 事件文本的 writer (thread-scoped, 见上).
#[derive(Clone, Default)]
struct CaptureLog {
    buf: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
}

impl CaptureLog {
    fn new() -> Self {
        Self::default()
    }

    /// 返回已捕获日志的文本快照.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock()).into_owned()
    }
}

impl std::io::Write for CaptureLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.lock().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 安装 thread-scoped tracing 捕获, 返回 (日志句柄, guard).
///
/// guard 存活期内同线程 ≥ level 的 tracing 事件全部捕获; guard 保持存活到测试
/// 末尾即可 (无需提前 drop — 捕获窗口只会更大, 断言都是 contains 型).
fn capture_tracing(level: tracing::Level) -> (CaptureLog, tracing::subscriber::DefaultGuard) {
    let log = CaptureLog::new();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(level)
        .with_writer({
            let log = log.clone();
            move || log.clone()
        })
        .finish();
    (log, tracing::subscriber::set_default(subscriber))
}

/// 从 DAG 派生 `Vec<ForwardRecord>` (newest first), 供断言检查.
///
/// 等价于旧 `RecordStore::list()` 的语义: walk 所有 node, 拼接元数据 + 请求 + 响应字段.
/// 集成测试用此 helper 把 DAG 视为"扁平 record 列表"做断言 (DAG 的会话折叠等高级特性
/// 不在集成测试的关注范围).
fn dag_list_forward_records(dag: &ConversationDag) -> Vec<ForwardRecord> {
    dag.list_node_ids_newest_first()
        .into_iter()
        .filter_map(|id| {
            let view = dag.get_node(id)?;
            let detail = dag.get_node_detail(id)?;
            let resp = dag.get_response(id);
            Some(ForwardRecord {
                id: view.id,
                created_at: view.created_at,
                method: view.method,
                path: view.path,
                upstream_id: view.upstream_id.to_string(),
                upstream_model: view.upstream_model.as_deref().map(str::to_string),
                req_headers: detail.req_headers,
                req_body: detail.req_body_raw,
                resp_status: view.resp_status,
                resp_headers: resp
                    .as_ref()
                    .map(|r| r.resp_headers.clone())
                    .unwrap_or_default(),
                resp_body: resp
                    .as_ref()
                    .map(|r| r.raw_resp_body.clone())
                    .unwrap_or_default(),
                resp_parsed: resp.as_ref().and_then(|r| r.parsed.clone()),
                elapsed_ms: view.elapsed_ms,
                streamed: view.streamed,
                resp_complete: view.resp_complete,
                error: view.error,
                redactions: view.redactions.to_vec(),
            })
        })
        .collect()
}

async fn wait_until_or_timeout<F>(
    records: &ConversationDag,
    predicate: F,
    timeout: Duration,
) -> Vec<ForwardRecord>
where
    F: Fn(&[ForwardRecord]) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let list = dag_list_forward_records(records);
        if predicate(&list) {
            return list;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout waiting for record update; current list: {list:?}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ─── 基础转发 ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn forwards_non_streaming_json() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-1","choices":[]}"#)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, body, headers) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"model":"gpt-4"}"#,
        &[],
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(body.contains("chatcmpl-1"));
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
}

#[tokio::test]
async fn forwards_streaming_sse() {
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body(r#"{"model":"gpt-4","stream":true}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();
    assert!(text.contains("\"delta\""));
    assert!(text.contains("[DONE]"));
}

#[tokio::test]
async fn streaming_parsed_view_accumulates_text() {
    // 验证流式响应完成后, parsed view (resp_parsed) 包含累积的完整文本,
    // 而非原始 SSE 字节. 这是本次改动的核心契约.
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = concat!(
        r#"data: {"id":"x","created":0,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"两者"},"finish_reason":null}]}"#,
        "\n\n",
        r#"data: {"id":"x","created":0,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"都可以"},"finish_reason":null}]}"#,
        "\n\n",
        r#"data: {"id":"x","created":0,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"工作"},"finish_reason":"stop"}]}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;
    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
        &[],
    )
    .await;

    // 等 record 完成.
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    assert!(list[0].streamed, "should be streamed");
    assert!(list[0].resp_complete, "should be complete");
    let id = list[0].id;

    // 拉 parsed view, 验证累积文本.
    let client = reqwest::Client::new();
    let env: serde_json::Value = client
        .get(format!("{proxy_url}/api/records/{id}?view=parsed"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let parsed_resp = env["parsed_response"]
        .as_object()
        .expect("parsed_response should exist");
    // OpenAI shape: choices[0].message.content
    let choices = parsed_resp["choices"]
        .as_array()
        .expect("choices should be array");
    let content = choices[0]["message"]["content"]
        .as_str()
        .expect("content should be string");
    assert_eq!(
        content, "两者都可以工作",
        "parsed view should contain accumulated text, got: {content}"
    );
}

#[tokio::test]
async fn provider_api_key_overrides_client_auth() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("authorization", "Bearer sk-test-key")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;
    // 客户端发了个错误的 token; 服务端应使用 provider 配置的 api_key.
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        "{}",
        &[("authorization", "Bearer WRONG-TOKEN")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn provider_api_key_file_reads_secret_from_path() {
    // 端到端验证: provider.api_key_file 指向一个文件, secret-guard 应当在转发时读取其内容
    // (含 trim) 并注入 Authorization header. 这是 sops-nix 等外部 secret manager 集成的关键.
    let key_file = std::env::temp_dir().join(format!(
        "secret-guard-test-api-key-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&key_file, "sk-from-file\n").unwrap(); // 末尾换行应被 trim 掉

    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("authorization", "Bearer sk-from-file")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let provider = Provider {
        id: "oa-file".into(),
        enabled: true,
        name: None,
        kind: ProviderKind::Direct(DirectProvider {
            protocol: Protocol::OpenAI,
            base_url: upstream.url(),
            api_key: String::new(),
            api_key_file: Some(key_file.clone()),
        }),
    };
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-file/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    std::fs::remove_file(&key_file).ok();
}

#[tokio::test]
async fn provider_api_key_file_missing_falls_through_to_no_auth() {
    // api_key_file 指向不存在的文件时, effective_api_key 返回空 → apply_provider_auth 跳过.
    // 这种"软失败"避免单个 provider 配置错误拖垮整个进程 (用户应该看到 401/403 from upstream).
    let mut upstream = spawn_mock_upstream().await;
    // mock 不约束 Authorization header (因为 secret-guard 不会注入任何 auth).
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let provider = Provider {
        id: "oa-broken".into(),
        enabled: true,
        name: None,
        kind: ProviderKind::Direct(DirectProvider {
            protocol: Protocol::OpenAI,
            base_url: upstream.url(),
            api_key: String::new(),
            api_key_file: Some(std::path::PathBuf::from("/nonexistent/secret-guard-test")),
        }),
    };
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-broken/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    // secret-guard 不报错, 转发到上游; 上游 mock 接受了 (实际生产中上游会 401).
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn anthropic_provider_uses_x_api_key() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_header("x-api-key", "sk-ant-test")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let provider = Provider {
        id: "an-main".into(),
        enabled: true,
        name: None,
        kind: ProviderKind::Direct(DirectProvider {
            protocol: Protocol::Anthropic,
            base_url: upstream.url(),
            api_key: "sk-ant-test".into(),
            api_key_file: None,
        }),
    };
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let (status, _, _) =
        proxy_request(&proxy_url, "POST", "/a/an-main/v1/messages", "{}", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn strips_custom_connection_listed_header() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("x-should-not-leak", mockito::Matcher::Missing)
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        "{}",
        &[
            ("connection", "x-should-not-leak"),
            ("x-should-not-leak", "leak-value"),
        ],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn records_request_and_response_snapshots() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"ok":true}"#)
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"q":"hi"}"#,
        &[],
    )
    .await;

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;

    assert_eq!(list.len(), 1, "exactly one record expected");
    let r = &list[0];
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/o/oa-main/v1/chat/completions");
    assert!(r.req_body.contains("\"q\":\"hi\""));
    assert_eq!(r.resp_status, 200);
    assert!(r.resp_body.contains("\"ok\":true"));
    assert!(r.resp_complete);
    assert!(r.error.is_none());
}

#[tokio::test]
async fn upstream_non_2xx_is_forwarded() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(429)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"rate_limited"}"#)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("rate_limited"));
}

#[tokio::test]
async fn upstream_unreachable_returns_502_and_marks_record_incomplete() {
    let dummy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = dummy_listener.local_addr().unwrap();
    drop(dummy_listener);

    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &format!("http://{bad_addr}"));
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert!(body.contains("upstream_error"));

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.error.is_some()).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert_eq!(r.resp_status, 502);
    assert!(!r.resp_complete);
    assert!(r.error.as_deref().unwrap().contains("upstream send error"));
}

#[tokio::test]
async fn get_method_is_forwarded() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("GET", "/healthz")
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, body, _) = proxy_request(&proxy_url, "GET", "/o/oa-main/healthz", "", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn passes_query_string_through() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("GET", "/v1/models")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("limit".into(), "10".into()),
            mockito::Matcher::UrlEncoded("order".into(), "desc".into()),
        ]))
        .with_status(200)
        .with_body("[]")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "GET",
        "/o/oa-main/v1/models?limit=10&order=desc",
        "",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

// ─── 路由错误语义 ───────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_protocol_returns_404() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, body, _) = proxy_request(&proxy_url, "POST", "/x/foo/v1/chat", "{}", &[]).await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    assert!(body.contains("not_found"));
}

#[tokio::test]
async fn unknown_provider_returns_404() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/does-not-exist/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    assert!(body.contains("not_found"));
}

#[tokio::test]
async fn disabled_provider_returns_503() {
    let mut upstream = spawn_mock_upstream().await;
    // 即使上游能响应, 也不应该被调用.
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .with_status(200)
        .with_body("should-not-happen")
        .create_async()
        .await;

    let provider = Provider {
        enabled: false,
        ..openai_provider("oa-disabled", &upstream.url())
    };
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-disabled/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("unavailable"));
}

#[tokio::test]
async fn cross_protocol_translates_system_prompt_to_anthropic_top_level() {
    // OpenAI messages[].role=="system" 应翻译为 Anthropic 顶层 system 字段.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"system": "You are a helpful assistant."}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Hi"}]}"#;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn cross_protocol_anthropic_requires_max_tokens_injected() {
    // OpenAI 客户端不带 max_tokens, 跨协议到 Anthropic 时应注入默认值 4096.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"max_tokens": 4096}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn cross_protocol_translates_tools_and_tool_use_round_trip() {
    // OpenAI tools/tool_calls/tool messages → Anthropic tools/tool_use/tool_result 完整往返.
    // 仅断言关键字段 (tools 名, tool_use 块, tool_result 关联), 不强求完整 body 等价
    // (因为 IR 统一把 string content 升级为 array of text blocks).
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({
                "tools": [{"name": "get_weather"}],
                "messages": [
                    {"role": "user"},
                    {"role": "assistant", "content": [{"type": "tool_use", "id": "call_1", "name": "get_weather", "input": {"city": "SF"}}]},
                    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1"}]}
                ]
            }),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"It's sunny in SF"}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"weather?"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"SF\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"Sunny"}],"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}]}"#;
    let (status, resp_body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    assert!(resp_body.contains("It's sunny in SF"), "got: {resp_body}");
}

#[tokio::test]
async fn cross_protocol_translates_upstream_error_to_ingress_envelope() {
    // 上游错误响应应通过 codec 翻译为 ingress 协议 envelope (不泄漏内部细节).
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(429)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"type":"rate_limit_error","message":"Too many requests"}}"#)
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, resp_body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::TOO_MANY_REQUESTS);
    // OpenAI 风格 envelope.
    assert!(
        resp_body.contains("\"type\":\"rate_limit_error\""),
        "got: {resp_body}"
    );
    assert!(resp_body.contains("Too many requests"), "got: {resp_body}");
}

#[tokio::test]
async fn same_proto_streaming_with_redact_restores_mock_in_sse_chunks() {
    // 同协议 + redact + 流式响应: 用 StreamTranslate restore 模式.
    // 上游 SSE chunk 含 mock → 客户端拿到的是 real_secret (restore 生效).
    // 用 predict_mock(real) 预测首次 mock (gen_mock_for_ir 在 allocated 为空时返回 counter=0 mock).
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = format!(
        concat!(
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"leaked {mock} in chunk\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":3,\"completion_tokens\":1,\"total_tokens\":4}}}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert_eq!(status, reqwest::StatusCode::OK);
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .cloned()
        .unwrap();
    assert!(
        ct.to_str().unwrap().contains("text/event-stream"),
        "should be SSE"
    );
    let text = resp.text().await.unwrap();
    // 客户端应该看到 real_secret (mock 被 restore).
    assert!(
        text.contains(real_secret),
        "client should see real_secret restored in stream; got: {text}"
    );
    // 客户端不应该看到 mock 前缀.
    assert!(
        !text.contains(&expected_mock),
        "client should NOT see mock {expected_mock}; got: {text}"
    );

    // record 里应该不含 real_secret (LLM 视角的请求体已被 redact).
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "record should not contain real secret"
    );
}

#[tokio::test]
async fn same_proto_streaming_with_redact_preserves_include_usage_chunk() {
    // 回归: 同协议 + redact + 流式响应 + 上游支持 stream_options.include_usage.
    //
    // OpenAI `stream_options.include_usage: true` 模式下, 流末尾会有一个独立 chunk:
    //   `choices: []` (空数组) + 顶层 `usage`.
    // 此前 reader 把空数组当成 "无 choice" 直接 return, 丢失 usage; writer 也忽略
    // MessageDelta 的 usage 字段. 两者叠加导致客户端 (如 opencode) 拿到 0 tokens.
    //
    // 该测试覆盖整条链路: 上游发出独立的 usage chunk → reader 识别 → writer 写回.
    let real_secret = "sk-test-123";
    let mut upstream = spawn_mock_upstream().await;
    // 上游 SSE: 1) role chunk  2) text delta  3) finish_reason chunk (无 usage)
    //           4) 独立 usage chunk (choices=[], 顶层 usage)  5) [DONE]
    let sse_body = format!(
        concat!(
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"uses {real_secret}\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{{\"prompt_tokens\":42,\"completion_tokens\":7,\"total_tokens\":49}}}}\n\n",
            "data: [DONE]\n\n",
        ),
        real_secret = real_secret,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"x"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();
    // 关键断言: usage 必须透传给客户端 (修复前丢失, 导致 opencode 显示 "0 tokens").
    assert!(
        text.contains("\"prompt_tokens\":42"),
        "client must see usage.prompt_tokens=42; got: {text}"
    );
    assert!(
        text.contains("\"completion_tokens\":7"),
        "client must see usage.completion_tokens=7; got: {text}"
    );
}

#[tokio::test]
async fn streaming_redact_restores_mock_split_across_sse_chunks() {
    // 跨 SSE chunk 的 mock 也应被 sliding-window restore.
    // 场景: LLM 在响应里 echo 出 mock, mock 恰好被 TCP 切到两个 chunk 中间.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 把 mock 切成连续两半 (mock 本身在文本中是连续的, 只是跨了 chunk 边界):
    //   chunk1 content = "leaked " + mock[..8]
    //   chunk2 content = mock[8..] + " end"
    let split = 8;
    let mock_prefix = &expected_mock[..split];
    let mock_suffix = &expected_mock[split..];
    let sse_body = format!(
        concat!(
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"leaked {mp}\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{ms} end\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":3,\"completion_tokens\":1,\"total_tokens\":4}}}}\n\n",
            "data: [DONE]\n\n",
        ),
        mp = mock_prefix,
        ms = mock_suffix,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();
    // 客户端应该看到完整的 real_secret (跨 chunk mock 被 sliding-window restore).
    assert!(
        text.contains(real_secret),
        "client should see real_secret restored from cross-chunk mock; got: {text}"
    );
    // 客户端不应看到任何 mock 残段.
    assert!(
        !text.contains(mock_prefix),
        "client should NOT see mock prefix {mock_prefix}; got: {text}"
    );
    assert!(
        !text.contains(mock_suffix),
        "client should NOT see mock suffix {mock_suffix}; got: {text}"
    );
}

#[tokio::test]
async fn streaming_redact_restores_input_json_delta_in_tool_use() {
    // 流式 tool_use 的 InputJsonDelta 中含 mock 也应被 restore.
    // 上游 SSE 流里 arguments delta 含 mock, 客户端最终拼接应看到 real_secret.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = format!(
        concat!(
            // 第 1 chunk: assistant role + tool_call 开始.
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"tool_calls\":[{{\"index\":0,\"id\":\"call_x\",\"type\":\"function\",\"function\":{{\"name\":\"run\",\"arguments\":\"\"}}}}]}},\"finish_reason\":null}}]}}\n\n",
            // 第 2 chunk: arguments delta 含完整 mock.
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{{\\\"cmd\\\":\\\"echo {mock}\\\"}}\"}}}}]}},\"finish_reason\":null}}]}}\n\n",
            // 第 3 chunk: finish.
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}],\"usage\":{{\"prompt_tokens\":3,\"completion_tokens\":1,\"total_tokens\":4}}}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"tools":[{{"type":"function","function":{{"name":"run","description":"x","parameters":{{"type":"object","properties":{{"cmd":{{"type":"string"}}}}}}}}}}],"messages":[{{"role":"user","content":"use {real_secret}"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "status mismatch, body: {text}"
    );
    // 客户端应看到 real_secret 在 tool_call arguments 中.
    assert!(
        text.contains(real_secret),
        "client should see real_secret in tool args; got: {text}"
    );
    assert!(
        !text.contains(&expected_mock),
        "client should NOT see mock in tool args; got: {text}"
    );
}

#[tokio::test]
async fn streaming_redact_restores_when_upstream_skips_block_stop() {
    // 上游协议异常: 漏发 content_block_stop / finish_reason chunk, 直接发 message_stop / [DONE].
    // StreamTranslate 应在 MessageStop 时 flush_all_restorers, 把残留 mock tail 还原为 real.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 上游 SSE: 只发 role + 一个 content + message_stop, 没发 content_block_stop.
    // OpenAI 风格: content chunk 后直接 data: [DONE], 跳过 finish_reason chunk.
    let sse_body = format!(
        concat!(
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"leaked {mock}\"}},\"finish_reason\":null}}]}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret}"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();
    // 即使上游漏发 finish_reason / BlockStop, 客户端也应看到 real_secret.
    assert!(
        text.contains(real_secret),
        "client should see real_secret via finish() flush; got: {text}"
    );
    assert!(
        !text.contains(&expected_mock),
        "client should NOT see mock; got: {text}"
    );
}

#[tokio::test]
async fn same_proto_streaming_with_redact_forwards_reasoning_content_deltas() {
    // #176 回归: 思考型模型 (glm 等 OpenAI 兼容 provider) 流式响应的思考阶段,
    // redact 路径 (secrets 非空 → IR 重建) 必须把 delta.reasoning_content 增量
    // 透传给客户端. 修复前 reader 不解码该字段 → 思考期零字节, 客户端空闲
    // 看门狗超时断连 (Chatbox 30s, 生产 499 事故).
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 上游 SSE: 思考阶段 (reasoning chunks, 含 mock — LLM 在思考中 echo secret)
    // → content 阶段 → finish → [DONE].
    let sse_body = format!(
        concat!(
            "data: {{\"id\":\"chatcmpl-r\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-5.3\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"reasoning_content\":\"step one with {mock}\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-r\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-5.3\",\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_content\":\" step two\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-r\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-5.3\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"final answer\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-r\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-5.3\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"glm-5.3","stream":true,"messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();

    // 核心: 思考增量必须到达客户端 (reasoning_content 字段).
    // 注: "≥2" 依赖 mock 位于 delta 末尾 (find_safe_end 的 max_mock_end 迫使首 delta
    // 全量 emit); 若测试帧构造改变 (mock 移到 delta 中间且尾部短于 hold), 两个 delta
    // 可能合并为 1 个 emit — 届时此计数断言需调整, 拼接断言 (下方) 不受影响.
    // 注: sliding window restore 会重组 chunk 边界 (文档化行为), 断言必须基于
    // 同类 delta 的拼接而非裸 substring (reasoning/content 是不同 block 的独立流).
    let reasoning_chunks = text.matches("reasoning_content").count();
    assert!(
        reasoning_chunks >= 2,
        "#176 回归: 客户端思考期零字节 (reasoning_content chunks = {reasoning_chunks})\ntext: {text}"
    );
    let joined_content: String = collect_openai_delta_field(&text, "content");
    let joined_reasoning: String = collect_openai_delta_field(&text, "reasoning_content");
    // reasoning 内容保真: 两段思考拼接完整.
    assert_eq!(
        joined_reasoning,
        format!("step one with {real_secret} step two"),
        "reasoning fidelity; text: {text}"
    );
    // content 阶段也透传.
    assert_eq!(joined_content, "final answer", "text: {text}");
    // restore: reasoning 中的 mock 被还原为 real (secret 可能泄漏进思考流).
    assert!(
        joined_reasoning.contains(real_secret),
        "mock in reasoning must be restored to real; text: {text}"
    );
    assert!(
        !text.contains(&expected_mock),
        "client should NOT see mock {expected_mock}; got: {text}"
    );
}

/// 从客户端 SSE 文本中收集 `choices[].delta.<field>` (string) 的全部值并拼接.
/// 用于流式断言 (sliding window 会拆 chunk, 必须拼接后比较).
fn collect_openai_delta_field(sse_text: &str, field: &str) -> String {
    let mut acc = String::new();
    for line in sse_text.lines() {
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
            continue;
        };
        if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
            for ch in choices {
                if let Some(s) = ch
                    .get("delta")
                    .and_then(|d| d.get(field))
                    .and_then(|s| s.as_str())
                {
                    acc.push_str(s);
                }
            }
        }
    }
    acc
}

#[tokio::test]
async fn cross_protocol_with_redact_round_trips_through_ir_translation() {
    // 跨协议 + redact + restore: 客户端发 OpenAI (含 secret) → codec 翻译为 Anthropic
    // (含 mock) → 上游响应含 mock → codec 翻译回 OpenAI + restore mock 为 real_secret.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 上游响应里含 mock (假设 LLM echo 了它在请求里看到的 mock).
    let upstream_body = format!(
        r#"{{"id":"msg_x","type":"message","role":"assistant","content":[{{"type":"text","text":"echo {expected_mock}"}}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{{"input_tokens":1,"output_tokens":1}}}}"#
    );
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(upstream_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let (status, resp_body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        &body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    // 客户端应看到 real_secret (跨协议翻译 + restore).
    assert!(
        resp_body.contains(real_secret),
        "client should see real_secret (cross-proto + restore); got: {resp_body}"
    );
    assert!(
        !resp_body.contains(&expected_mock),
        "client should NOT see mock; got: {resp_body}"
    );

    // record body 绝不能含真实 secret (cross-proto 路径也必须 redact 后再保存).
    // 这是 pre-existing bug 的回归测试: 早期 cross_proto_forward 直接存原始 req_bytes,
    // 会在 record 里泄漏 secret. 现在改用 ingress writer 重序列化 redact 后的 IR.
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "cross-proto record body must NOT contain real secret; got: {}",
        r.req_body
    );
    assert!(
        r.req_body.contains(&expected_mock),
        "cross-proto record body should contain mock (redacted view); got: {}",
        r.req_body
    );
    // parsed view 应当可用 (record body 是 ingress writer 重序列化的 OpenAI JSON).
    assert_eq!(
        r.redactions.len(),
        1,
        "expected 1 redaction, got: {:?}",
        r.redactions
    );
    assert_eq!(r.redactions[0].1, "api-key");
}

#[tokio::test]
async fn cross_protocol_translates_openai_ingress_to_anthropic_upstream() {
    // OpenAI ingress → Anthropic upstream (端到端跨协议翻译).
    let mut upstream = spawn_mock_upstream().await;
    // mock 上游: 期待收到 Anthropic 格式的 /v1/messages 请求.
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_header("anthropic-version", "2023-06-01")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_01test","type":"message","role":"assistant","content":[{"type":"text","text":"Hi from Claude"}],"model":"claude-3-5-sonnet","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":5}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    // OpenAI ingress 客户端发 OpenAI 格式.
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
    let (status, resp_body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    // 响应应该是 OpenAI 格式.
    assert!(
        resp_body.contains("\"object\":\"chat.completion\""),
        "got: {resp_body}"
    );
    assert!(resp_body.contains("Hi from Claude"), "got: {resp_body}");
    assert!(resp_body.contains("\"prompt_tokens\""), "got: {resp_body}");
    assert!(
        resp_body.contains("\"finish_reason\":\"stop\""),
        "got: {resp_body}"
    );
}

#[tokio::test]
async fn cross_protocol_translates_anthropic_ingress_to_openai_upstream() {
    // 反向: Anthropic ingress → OpenAI upstream.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-test","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hi from GPT"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("oa-main", Protocol::OpenAI, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body =
        r#"{"model":"claude","messages":[{"role":"user","content":"Hello"}],"max_tokens":50}"#;
    let (status, resp_body, _) =
        proxy_request(&proxy_url, "POST", "/a/oa-main/v1/messages", body, &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    // 响应应该是 Anthropic 格式.
    assert!(
        resp_body.contains("\"type\":\"message\""),
        "got: {resp_body}"
    );
    assert!(resp_body.contains("Hi from GPT"), "got: {resp_body}");
    assert!(
        resp_body.contains("\"stop_reason\":\"end_turn\""),
        "got: {resp_body}"
    );
    assert!(
        resp_body.contains("\"input_tokens\":12"),
        "got: {resp_body}"
    );
}

#[tokio::test]
async fn cross_protocol_streaming_translates_openai_ingress_from_anthropic_upstream() {
    // 跨协议流式: OpenAI ingress → Anthropic upstream (SSE) → 翻译回 OpenAI SSE.
    // 上游流形态: message_start(usage) → text block → message_delta → message_stop.
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01test\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-3-5-sonnet\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi from Claude\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":5}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );
    // 上游收到 Anthropic 形态 + stream=true (egress writer 透传流式意图).
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_header("anthropic-version", "2023-06-01")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"stream": true}),
        ))
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}],"stream":true}"#;
    let (status, resp_body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    // 客户端收到 OpenAI 形态 SSE: role chunk + content delta + finish + usage + [DONE].
    assert!(
        resp_body.contains("\"object\":\"chat.completion.chunk\""),
        "got: {resp_body}"
    );
    assert!(
        resp_body.contains("\"content\":\"Hi from Claude\""),
        "text must survive translation: {resp_body}"
    );
    assert!(
        resp_body.contains("\"finish_reason\":\"stop\""),
        "got: {resp_body}"
    );
    // usage 透传: Anthropic input=10/output=5 → OpenAI prompt/completion_tokens
    // (input 经 start_usage backfill).
    assert!(
        resp_body.contains("\"prompt_tokens\":10"),
        "usage input backfill: {resp_body}"
    );
    assert!(
        resp_body.contains("\"completion_tokens\":5"),
        "usage output passthrough: {resp_body}"
    );
    assert!(resp_body.contains("data: [DONE]"), "got: {resp_body}");
    // 终止符恰好一次 (message_stop 在 OpenAI 侧由 finish() 的 [DONE] 承载).
    assert_eq!(resp_body.matches("data: [DONE]").count(), 1);
    // wire 顺序: 最后一个 content chunk 在 finish_reason chunk 之前 (OpenAI 规范
    // finish_reason 后不应再有 content — 锁定 restore 尾部不得延迟到流末).
    let last_content = resp_body
        .rfind("\"content\":\"")
        .expect("content chunks must exist");
    let finish_pos = resp_body
        .find("\"finish_reason\":\"stop\"")
        .expect("finish_reason chunk must exist");
    assert!(
        last_content < finish_pos,
        "content chunk after finish_reason is illegal OpenAI wire order: {resp_body}"
    );
}

#[tokio::test]
async fn cross_protocol_streaming_translates_anthropic_ingress_from_openai_upstream() {
    // 反向: Anthropic ingress → OpenAI upstream (SSE 含 include_usage 末尾 chunk)
    // → 翻译回 Anthropic SSE. 守卫 wire 顺序: message_delta(usage) 必须在
    // message_stop 之前 (deferred stop, 1b).
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = concat!(
        "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hi from GPT\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4,\"total_tokens\":16}}\n\n",
        "data: [DONE]\n\n",
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let provider = provider_with("oa-main", Protocol::OpenAI, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"claude","messages":[{"role":"user","content":"Hello"}],"max_tokens":50,"stream":true}"#;
    let (status, resp_body, _) =
        proxy_request(&proxy_url, "POST", "/a/oa-main/v1/messages", body, &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    // 客户端收到 Anthropic 形态 SSE.
    assert!(
        resp_body.contains("event: message_start"),
        "got: {resp_body}"
    );
    assert!(
        resp_body.contains("\"type\":\"text_delta\""),
        "got: {resp_body}"
    );
    assert!(
        resp_body.contains("\"text\":\"Hi from GPT\""),
        "text must survive translation: {resp_body}"
    );
    // wire 顺序: message_delta (含 usage) 在 message_stop 之前 — OpenAI 末尾
    // include_usage chunk 在 finish_reason 之后到达, 朴素翻译会产出
    // message_stop 之后的 message_delta (Anthropic 非法顺序).
    let delta_pos = resp_body
        .rfind("event: message_delta")
        .expect("message_delta must be present");
    let stop_pos = resp_body
        .find("event: message_stop")
        .expect("message_stop must be present");
    assert!(
        delta_pos < stop_pos,
        "message_delta must precede message_stop (Anthropic wire order): {resp_body}"
    );
    // usage 透传 (OpenAI prompt=12 → Anthropic input_tokens=12).
    assert!(
        resp_body.contains("\"input_tokens\":12"),
        "usage passthrough: {resp_body}"
    );
    // message_stop 恰好一次, 且无 [DONE] (Anthropic 不用该终止符).
    assert_eq!(resp_body.matches("event: message_stop").count(), 1);
    assert!(!resp_body.contains("[DONE]"), "got: {resp_body}");
}

#[tokio::test]
async fn cross_protocol_streaming_redact_restores_mock_no_leak() {
    // 跨协议流式 + redact: 上游 (Anthropic SSE) 在 text 里 echo mock, 客户端
    // (OpenAI SSE) 必须看到 real secret 且绝无 mock (RED-7 流式可逆性, 跨协议路径).
    let real_secret = "sk-cross-proto-stream";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = format!(
        concat!(
            "event: message_start\n",
            "data: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_01m\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-3\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{{\"input_tokens\":3,\"output_tokens\":1}}}}}}\n\n",
            "event: content_block_start\n",
            "data: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n",
            "event: content_block_delta\n",
            "data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"the key is {mock} indeed\"}}}}\n\n",
            "event: content_block_stop\n",
            "data: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n",
            "event: message_delta\n",
            "data: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\",\"stop_sequence\":null}},\"usage\":{{\"output_tokens\":2}}}}\n\n",
            "event: message_stop\n",
            "data: {{\"type\":\"message_stop\"}}\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        secrets,
    )
    .await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        &body,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    // 客户端看到 real secret (响应侧 mock→real restore).
    assert!(
        text.contains(real_secret),
        "client should see real_secret restored; got: {text}"
    );
    // 客户端绝不看到 mock (no leak).
    assert!(
        !text.contains(&expected_mock),
        "client must NOT see mock {expected_mock}; got: {text}"
    );
    // wire 顺序 (OpenAI ingress): 最后一个 content chunk 在 finish_reason 之前 —
    // restore 的 hold 窗口尾部不得延迟到流末 (H-1 回归).
    let last_content = text
        .rfind("\"content\":\"")
        .expect("content chunks must exist");
    let finish_pos = text
        .find("\"finish_reason\":\"stop\"")
        .expect("finish_reason chunk must exist");
    assert!(
        last_content < finish_pos,
        "content chunk after finish_reason is illegal OpenAI wire order: {text}"
    );
}

#[tokio::test]
async fn cross_protocol_streaming_responses_ingress_returns_501() {
    // Responses 作 ingress (egress OpenAI) + stream=true 同样 501 — ingress writer
    // 的 write_response_event 未实现, 放行会翻译出空流 (501 门的另一半分支).
    let upstream = spawn_mock_upstream().await;
    let provider = provider_with("oa-main", Protocol::OpenAI, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","input":"Hi","stream":true}"#;
    let (status, body, _) =
        proxy_request(&proxy_url, "POST", "/r/oa-main/v1/responses", body, &[]).await;
    assert_eq!(status, reqwest::StatusCode::NOT_IMPLEMENTED);
    assert!(
        body.contains("streaming cross-protocol"),
        "501 body should name the cross-proto streaming gate: {body}"
    );
}

#[tokio::test]
async fn cross_protocol_streaming_responses_egress_returns_501() {
    // Responses egress + stream=true 仍 501 (read_response_events 未实现, 放行会
    // 翻译出空流). 原 "跨协议流式一律 501" 的断言已随 dispatch 接入作废, 本测试
    // 锁定 Responses 残留范围.
    let upstream = spawn_mock_upstream().await;
    let provider = provider_with("resp-main", Protocol::OpenAIResponses, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}],"stream":true}"#;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/resp-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_IMPLEMENTED);
    assert!(
        body.contains("streaming cross-protocol"),
        "501 body should name the cross-proto streaming gate: {body}"
    );
    assert!(
        body.contains("Responses SSE event translation unimplemented"),
        "501 body should name the Responses cause: {body}"
    );
}

#[tokio::test]
async fn cross_protocol_unknown_pair_returns_501() {
    // Gemini/Ollama 在 codec 中尚未支持, 跨协议到这些仍应返回 501.
    let upstream = spawn_mock_upstream().await;
    let provider = provider_with("gem-main", Protocol::Gemini, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/gem-main/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("not supported by codec"));
}

#[tokio::test]
async fn no_rest_segment_routes_to_root() {
    // /o/{name} 应当等价于 /o/{name}/ → 上游收到 GET /.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("GET", "/")
        .with_status(200)
        .with_body("root")
        .create_async()
        .await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, body, _) = proxy_request(&proxy_url, "GET", "/o/oa-main", "", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body, "root");
}

#[tokio::test]
async fn unmatched_path_returns_404() {
    // 单段路径不匹配 `/{proto}/{name}` 路由, 应当 404 (不被 catch-all 转发).
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/just-one-segment"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ─── Web UI / API ──────────────────────────────────────────────────────────

#[tokio::test]
async fn root_serves_web_ui() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("secret-guard"));
    assert!(body.contains("<html"));
}

#[tokio::test]
async fn legacy_sg_prefix_returns_404() {
    // URL 硬切: 旧 `/__sg` 前缀已移除. 单段 `/__sg` 无路由匹配 → 404;
    // `/__sg/foo` 匹配 `/{proto}/{name}` 但 proto 解析失败 → 404 (不转发).
    let mut upstream = spawn_mock_upstream().await;
    // 上游零命中断言: 即使 mock 接受 ANY method/ANY path, 也不应被转发命中.
    let mock = upstream
        .mock("GET", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let client = reqwest::Client::new();
    for path in ["/__sg", "/__sg/foo", "/__sg/api/sync"] {
        let resp = client
            .get(format!("{proxy_url}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::NOT_FOUND,
            "legacy prefix {path} must 404 after hard cut"
        );
    }
    mock.assert_async().await;
}

#[tokio::test]
async fn web_api_sync_returns_sessions_after_forward() {
    // 验证 POST /api/sync 返回 sessions (替代旧的 GET /api/records 扁平分页).
    // 转发一次请求后, sync 应返回 1 个 session, 含 1 条 round.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        "{}",
        &[],
    )
    .await;

    wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;

    // POST /api/sync 应返回 1 个 session (record_count=1).
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/api/sync"))
        .json(&serde_json::json!({"expanded": [], "selected": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    let sessions = body.get("sessions").and_then(|v| v.as_array()).unwrap();
    assert_eq!(sessions.len(), 1, "1 个转发 → 1 个 session");
    assert_eq!(sessions[0]["record_count"], 1);
    // 注: 同步未展开该 session, rounds 字段应为空 object.
    let rounds = body.get("rounds").and_then(|v| v.as_object()).unwrap();
    assert!(rounds.is_empty(), "expanded 为空 → rounds 为空");
}

#[tokio::test]
async fn web_api_returns_record_by_id() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body(r#"{"ok":true}"#)
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"q":"hi"}"#,
        &[],
    )
    .await;

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let id = list[0].id;

    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/api/records/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    // 新 envelope: {record, parsed_request, parsed_response, parse_error}.
    // 默认 view=raw, parsed_* 全为 null.
    assert_eq!(body["record"]["id"], id.to_string());
    assert_eq!(body["record"]["resp_status"], 200);
    assert!(body.get("parsed_request").is_some());
    assert!(body["parsed_request"].is_null());
}

#[tokio::test]
async fn web_api_404_for_unknown_record() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "{proxy_url}/api/records/00000000-0000-0000-0000-000000000000"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ─── /records/{id}?view=parsed (单条 raw + parsed view) ────────────────
// 注: 旧的 GET /api/records (扁平分页, list_records handler) 已删除, 由 session-aware
// sync API 替代. 以下测试覆盖保留下来的 GET /api/records/{id}?view=parsed 路径.

#[tokio::test]
async fn web_api_records_view_parsed_openai_returns_structured() {
    // view=parsed 应当用 OpenAI codec 把 req_body 解析成结构化 JSON.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"hello"}}]}"#,
        )
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#,
        &[],
    )
    .await;
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let id = list[0].id;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/api/records/{id}?view=parsed"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["record"]["id"], id.to_string());
    assert!(
        body["parse_error"].is_null(),
        "unexpected parse_error: {}",
        body["parse_error"]
    );
    let parsed_req = &body["parsed_request"];
    assert!(!parsed_req.is_null(), "parsed_request should not be null");
    assert!(
        parsed_req.get("messages").is_some(),
        "parsed_request should have messages"
    );
    let parsed_resp = &body["parsed_response"];
    assert!(!parsed_resp.is_null(), "parsed_response should not be null");
    assert!(
        parsed_resp.get("choices").is_some(),
        "parsed_response should have choices"
    );
}

// ─── gzip 压缩响应解压 (FWD-1 透明中继: 上游 content-encoding: gzip) ──────────
//
// FWD-1 在"压缩编码"维度的回归守卫: 上游返回 gzip 压缩响应时, secret-guard
// 必须先解压再进入 record + codec parse 路径 (reqwest 的 gzip feature 负责).

/// 用 flate2 把字节 gzip 压缩 (模拟上游 LLM provider 的压缩响应).
fn gzip_bytes(raw: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(raw).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn gzip_compressed_upstream_response_is_decompressed_for_record() {
    let raw_json = r#"{"id":"chatcmpl-gz","choices":[{"message":{"role":"assistant","content":"compressed hello"}}]}"#;
    let gz_body = gzip_bytes(raw_json.as_bytes());

    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_header("content-encoding", "gzip")
        .with_body(gz_body)
        .create_async()
        .await;

    // 用生产环境的 client 构造路径 (build_upstream_client), 与 server::serve 一致.
    // reqwest 启用 gzip feature 后, 默认 builder 即自动解压, 无需 .gzip(true).
    let upstream_client = server::build_upstream_client(None).unwrap();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let (status, client_body, client_headers) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#,
        &[],
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(
        client_body.contains("chatcmpl-gz"),
        "client should see decompressed body, got: {client_body}"
    );
    assert!(
        client_headers.get("content-encoding").is_none(),
        "content-encoding header must be stripped after decompression"
    );

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let id = list[0].id;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/api/records/{id}?view=parsed"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // record.resp_body 应是可读 JSON.
    let resp_body = body["record"]["resp_body"].as_str().unwrap_or("");
    assert!(
        resp_body.contains("chatcmpl-gz"),
        "record.resp_body should be decompressed JSON, got: {resp_body}"
    );

    // record.resp_headers 也不应含 content-encoding (reqwest 已剥除).
    let resp_headers = body["record"]["resp_headers"]
        .as_array()
        .expect("resp_headers should be an array");
    let has_content_encoding = resp_headers.iter().any(|h| {
        h.get(0)
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("content-encoding"))
    });
    assert!(
        !has_content_encoding,
        "record.resp_headers should not contain content-encoding after decompression"
    );

    assert!(
        body["parse_error"].is_null(),
        "unexpected parse_error: {}",
        body["parse_error"]
    );
    let parsed_resp = &body["parsed_response"];
    assert!(
        !parsed_resp.is_null(),
        "parsed_response must not be null (gzip decompression enabled codec parse)"
    );
    assert!(
        parsed_resp.get("choices").is_some(),
        "parsed_response should have choices"
    );
}

// ─── 上游响应头超时 (防永久 pending 的回归守卫) ─────────────────────────────
//
// 验证 `[server] upstream_response_header_timeout_secs` 生效: 上游响应头 hang 时,
// secret-guard 在配置的超时后返回 504 + record 标记 error (而非永久 pending).

#[tokio::test]
async fn upstream_response_header_timeout_marks_record_504() {
    // 起一个 5s 后才返回响应头的上游; secret-guard 配置流式档 1s → 1s 后超时.
    let upstream_url = spawn_slow_upstream(Duration::from_secs(5)).await;

    // 构造 AppState, response_header_timeout = 1s (远小于上游的 5s sleep).
    // 显式流式档触发: body 带 "stream": true → 用 response_header 档.
    let upstream_timeouts = secret_guard::config::UpstreamTimeouts {
        connect: None,
        response_header: Some(std::time::Duration::from_secs(1)),
        nonstream_response_header: Some(std::time::Duration::from_secs(10)),
        stream_idle: None,
    };

    // 用显式传 UpstreamTimeouts 的 helper (默认 AppState 无超时保护).
    let (proxy_url, records_handle) =
        spawn_proxy_with_timeouts(&upstream_url, upstream_timeouts).await;

    // 客户端发请求, 应在 ~1s 内收到 504 (而非永久 hang).
    // body 带 "stream": true → 走流式档 (response_header = 1s). #175 分档后
    // 无 stream 字段的 body 会走非流式档 (10s), 等到上游 5s 响应 → 200,
    // 那条路径由 nonstream_slow_upstream_waits_with_nonstream_timeout 单独覆盖.
    let start = std::time::Instant::now();
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body(r#"{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "should fail fast (~1s timeout), not hang 5s; got {:?}",
        elapsed
    );

    // record 应被标记为 504 + error (而非永久 pending).
    // 注: resp_complete=false 是正确的 (上游响应确实未完成),
    // 关键是 resp_status=504 + error 有 timeout 说明 (而非默认 0 + None).
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().is_some_and(|r| r.resp_status == 504),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert_eq!(r.resp_status, 504, "record should be marked 504");
    assert!(
        r.error
            .as_deref()
            .is_some_and(|e| e.contains("not received") || e.contains("timeout")),
        "record.error should mention timeout/not-received, got: {:?}",
        r.error
    );
    assert!(
        r.elapsed_ms >= 900 && r.elapsed_ms < 2000,
        "elapsed should be ~1s (the timeout), got {}ms",
        r.elapsed_ms
    );
}

// ─── 响应头超时分档: 流式 TTFT 档 vs 非流式整响应档 (#175) ─────────────────
//
// 验证按请求 stream 字段动态选超时档: 非流式慢上游 (响应头晚于流式档超时到达)
// 应等到响应; 流式请求仍受流式档快超时保护 (回归守卫). 超时值压到 1s/5s 控制
// 测试时长 (语义与 60s/300s 同构, 无需真等).

/// 起一个 sleep `delay` 后才返回响应头的上游 (response body 为普通 JSON).
async fn spawn_slow_upstream(delay: Duration) -> String {
    // delay 由 move closure 捕获.
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move || async move {
            tokio::time::sleep(delay).await;
            axum::response::Json(serde_json::json!({"choices":[]}))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// 非流式请求 (无 stream 字段): 上游响应头 2s 后到, 流式档 1s / 非流式档 5s —
/// 旧逻辑 (单一 response_header=1s) 会 504, 新逻辑应等到 200.
#[tokio::test]
async fn nonstream_slow_upstream_waits_with_nonstream_timeout() {
    let upstream_url = spawn_slow_upstream(Duration::from_secs(2)).await;
    let upstream_timeouts = secret_guard::config::UpstreamTimeouts {
        connect: None,
        response_header: Some(Duration::from_secs(1)), // 流式档: 会误杀
        // 非流式档 5s: 覆盖 2s 上游且留 3s CI 负载余量 (timeout 只是上界,
        // 测试仍在响应到达的 ~2s 处结束, wall-clock 不变).
        nonstream_response_header: Some(Duration::from_secs(5)),
        stream_idle: None,
    };
    let (proxy_url, records_handle) =
        spawn_proxy_with_timeouts(&upstream_url, upstream_timeouts).await;

    // body 无 stream 字段 (OpenAI 默认非流式; #175 事故请求正是 stream:None).
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body(r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // record 完整标记 200 (而非 504). 窗口 5s 留 CI 负载余量.
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().is_some_and(|r| r.resp_complete),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(list[0].resp_status, 200);
}

/// 流式请求 (显式 stream=true): 上游响应头 4s 后到 → 仍被流式档 1s 快超时杀,
/// 504 record 的 error 消息带上**实际生效**的超时值 (可观测性, 事故排障靠它).
#[tokio::test]
async fn stream_request_still_killed_by_stream_timeout_with_observable_message() {
    // 上游 sleep 4s: 只为保证不早于 1s 流式档返回 (测试仍在 1s 超时处结束,
    // wall-clock 不变), 4s 留足 CI 负载下的区分余量.
    let upstream_url = spawn_slow_upstream(Duration::from_secs(4)).await;
    let upstream_timeouts = secret_guard::config::UpstreamTimeouts {
        connect: None,
        response_header: Some(Duration::from_secs(1)), // 流式档: 生效档
        nonstream_response_header: Some(Duration::from_secs(5)),
        stream_idle: None,
    };
    let (proxy_url, records_handle) =
        spawn_proxy_with_timeouts(&upstream_url, upstream_timeouts).await;

    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body(r#"{"model":"gpt-4","stream":true,"messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().is_some_and(|r| r.resp_status == 504),
        Duration::from_secs(3),
    )
    .await;
    let r = &list[0];
    // 504 消息内嵌实际生效的超时值 (1s 而非 5s), 事后排障能直接读出走了哪档.
    assert!(
        r.error.as_deref().is_some_and(|e| e.contains("1s")),
        "504 error should embed the effective (stream-tier) timeout 1s, got: {:?}",
        r.error
    );
}

// ─── 流式 chunk 空闲超时 (`upstream_stream_idle_timeout_secs`) e2e ──────────
//
// 防御路径: 上游发完响应头 (+首 chunk) 后 body 卡住. 此前 5 处超时 spawn 均为
// `stream_idle: None`, 该档零测试. 覆盖两条 fan_out 分支:
// - 流式 restore 路径 (redact + stream=true + SSE): 客户端已收 200 + 首 chunk,
//   idle 超时后 body 流被终止 (而非永久 hang), record 标记 idle timeout error.
// - buffered_ir 路径 (redact + 非流式): 客户端收到 504 (TimedOut → GATEWAY_TIMEOUT,
//   fan_out.rs client_status 推断; record 的 resp_status 仍是上游原值 200).

/// 起一个上游: 发送响应头 + 1 个 body chunk 后永久 hang (chunk 空闲的最小复现).
///
/// 上游侧 hang 用 `futures::stream::pending` 表达 — 测试必然先于上游 "恢复" 超时,
/// 无需真实长 sleep (测试时长只由 proxy 的 1s idle timeout 决定).
async fn spawn_upstream_first_chunk_then_hang(
    content_type: &'static str,
    first_chunk: &'static [u8],
) -> String {
    use futures::StreamExt as _;
    // Handler 需要 closure: Clone — stream (非 Clone) 只能在 handler 体内构造,
    // closure 仅捕获 &'static 参数 (Clone).
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move || async move {
            // 200 (默认) + content-type + 首 chunk 后永久 hang 的 body 流.
            let body_stream = futures::stream::once(async {
                Ok::<_, std::convert::Infallible>(bytes::Bytes::from_static(first_chunk))
            })
            .chain(futures::stream::pending());
            (
                [("content-type", content_type)],
                axum::body::Body::from_stream(body_stream),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// idle timeout 专用配置: response_header 两档拉高 (10s) 排除干扰, 只留
/// stream_idle = 1s 生效 — 断言到的中断只能来自 idle 档.
fn idle_only_timeouts() -> secret_guard::config::UpstreamTimeouts {
    secret_guard::config::UpstreamTimeouts {
        connect: None,
        response_header: Some(Duration::from_secs(10)),
        nonstream_response_header: Some(Duration::from_secs(10)),
        stream_idle: Some(Duration::from_secs(1)),
    }
}

const IDLE_ERR: &str = "upstream stream idle timeout";

/// 流式 + redact 路径: 上游 SSE 发 1 chunk 后卡住 → 客户端流在 ~1s 内终止
/// (非永久 hang), record 标记 idle timeout error + resp_complete=false.
#[tokio::test]
async fn stream_idle_timeout_terminates_hung_sse_stream_and_marks_record() {
    let upstream_url = spawn_upstream_first_chunk_then_hang(
        "text/event-stream",
        b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
    )
    .await;
    let secrets = test_secret_table_with(vec![secret("gh-idle", "ghp_idle_stream_secret_abcdef")]);
    let (proxy_url, records_handle) =
        spawn_proxy_with_timeouts_and_secrets(&upstream_url, idle_only_timeouts(), secrets).await;

    let start = std::time::Instant::now();
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body(
            r#"{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"use ghp_idle_stream_secret_abcdef to call api"}]}"#,
        )
        .send()
        .await
        .unwrap();
    // 上游响应头 + 首 chunk 已正常到达 (200), hang 发生在 body 中段.
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 读循环必须在有限时间内终止: idle 超时把 Err 推进客户端 body 流 (hyper 终止
    // 连接), 而非让客户端陪上游永久 hang. 上限 10s 只是防 hang 护栏, 预期 ~1s.
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let (received, elapsed) = tokio::time::timeout(Duration::from_secs(10), async {
        let mut received = 0usize;
        while let Some(item) = stream.next().await {
            // Ok = 正常 chunk (首 chunk); Err = 中断信号. 两者都终止循环 — 关键是
            // 循环会终止, 且不等到上游 "恢复" (它永远不会).
            match item {
                Ok(b) => received += b.len(),
                Err(_) => break,
            }
        }
        (received, start.elapsed())
    })
    .await
    .expect("read loop must terminate (not hang with upstream)");
    assert!(received > 0, "first SSE chunk must have reached client");
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(5),
        "stream should terminate at ~1s idle timeout, got {elapsed:?}"
    );

    // record: error = idle timeout label (stream_err_label SSOT), 上游原始 200 保留,
    // resp_complete=false.
    assert_idle_timeout_record(&records_handle).await;
}

/// 等待并断言首条 record 呈现 idle-timeout 终止形态: error label ==
/// `upstream stream idle timeout` + 上游原始 200 保留 + resp_complete=false.
/// 两条 fan_out 分支 (streaming restore / buffered_ir) 共用.
async fn assert_idle_timeout_record(records_handle: &ConversationDag) {
    let list = wait_until_or_timeout(
        records_handle,
        |l| {
            l.first()
                .is_some_and(|r| r.error.as_deref() == Some(IDLE_ERR))
        },
        Duration::from_secs(3),
    )
    .await;
    let r = &list[0];
    assert_eq!(
        r.resp_status, 200,
        "record keeps upstream's original status"
    );
    assert!(!r.resp_complete, "interrupted stream is incomplete");
}

/// buffered_ir 路径 (redact + 非流式): 上游 JSON body 发一半卡住 → 客户端收到
/// 504 (TimedOut → GATEWAY_TIMEOUT 映射), 而非 200 + 截断 JSON 的误导性成功.
#[tokio::test]
async fn stream_idle_timeout_buffered_path_returns_504() {
    let upstream_url = spawn_upstream_first_chunk_then_hang(
        "application/json",
        b"{\"choices\":[{\"index\":0,\"message\":{\"role\":\"ass",
    )
    .await;
    let secrets = test_secret_table_with(vec![secret("gh-idle", "ghp_idle_buffer_secret_abcdef")]);
    let (proxy_url, records_handle) =
        spawn_proxy_with_timeouts_and_secrets(&upstream_url, idle_only_timeouts(), secrets).await;

    // buffered 路径: proxy 读完整个 body 才回客户端 → send() 本身在 ~1s idle
    // 超时后返回 (10s timeout 只是防 hang 护栏).
    let start = std::time::Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        reqwest::Client::new()
            .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
            .body(
                r#"{"model":"gpt-4","messages":[{"role":"user","content":"use ghp_idle_buffer_secret_abcdef to call api"}]}"#,
            )
            .send(),
    )
    .await
    .expect("send must resolve (not hang with upstream)")
    .unwrap();
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(5),
        "should 504 at ~1s idle timeout, got {elapsed:?}"
    );

    assert_idle_timeout_record(&records_handle).await;
}

/// IR 路径 (secrets 非空 → reader → redact → writer) 的非流式分档: 选档信号源
/// 是 `ir.stream` (而非 passthrough 的 `requests_stream` 字节扫描). #175 的实际
/// 事故请求若走 redact 路径 (配置了 secret) 正是此链路, 端到端钉住.
#[tokio::test]
async fn ir_path_nonstream_slow_upstream_waits_with_nonstream_timeout() {
    // 慢上游 + 合法 OpenAI 响应 (choices[0] 存在): ① reader 可正常 parse, 响应侧
    // 走 restore 而非 parse-失败 fallback; ② 不触发 "mock not restored" WARN
    // (#158) 污染测试日志; ③ 不触发 #162 空 content 启发式 WARN.
    async fn ok_handler() -> axum::response::Json<serde_json::Value> {
        axum::response::Json(serde_json::json!({
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]
        }))
    }
    let delay = Duration::from_secs(2);
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move || async move {
            tokio::time::sleep(delay).await;
            ok_handler().await
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let upstream_url = format!("http://{addr}");

    let upstream_timeouts = secret_guard::config::UpstreamTimeouts {
        connect: None,
        response_header: Some(Duration::from_secs(1)), // 流式档: 会误杀
        nonstream_response_header: Some(Duration::from_secs(5)),
        stream_idle: None,
    };
    let secrets = test_secret_table_with(vec![secret("gh-test", "ghp_aaaaaaaaaaaaaaaaaa")]);
    let (proxy_url, records_handle) =
        spawn_proxy_with_timeouts_and_secrets(&upstream_url, upstream_timeouts, secrets).await;

    // body 无 stream 字段 + 含 secret (触发 IR redact 路径, ir.stream = false).
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body(r#"{"model":"gpt-4","messages":[{"role":"user","content":"use ghp_aaaaaaaaaaaaaaaaaa"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().is_some_and(|r| r.resp_complete),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(list[0].resp_status, 200);
    // 钉住 IR 路径确实被触发: redactions 仅在 IR 路径 (redact_and_derive) 填充,
    // passthrough 恒为空 — 无此断言则 dispatch 回退到 passthrough 时本测试仍绿
    // (passthrough 对同 body 同样选非流式档, resp_status 断言无判别力).
    assert_eq!(list[0].redactions.len(), 1, "IR path must be taken");
    assert_eq!(list[0].redactions[0].1, "gh-test");
}

/// 畸形 body (非 JSON) 走非流式档 (保守判定, requests_stream doc 的端到端守卫):
/// 上游 2s 后返回 → 若误判为流式档会在 1s 处 504, 非流式档 5s 等到 200.
#[tokio::test]
async fn malformed_body_falls_back_to_nonstream_timeout() {
    let upstream_url = spawn_slow_upstream(Duration::from_secs(2)).await;
    let upstream_timeouts = secret_guard::config::UpstreamTimeouts {
        connect: None,
        response_header: Some(Duration::from_secs(1)),
        nonstream_response_header: Some(Duration::from_secs(5)),
        stream_idle: None,
    };
    let (proxy_url, _records) = spawn_proxy_with_timeouts(&upstream_url, upstream_timeouts).await;

    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body("this is not json")
        .send()
        .await
        .unwrap();
    // passthrough 路径不 parse body (字节透传), 非 JSON 也转发, 等满 2s 收到 200.
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

/// 启动 secret-guard, 显式指定 UpstreamTimeouts (超时回归测试专用).
///
/// SecretTable 为空 → passthrough 路径; secrets 非空 → same_proto IR 路径
/// (reader → redact → writer). 两个路径的超时选档信号源不同
/// (`requests_stream` vs `ir.stream`, 语义等价), 超时分档测试分别覆盖.
async fn spawn_proxy_with_timeouts_and_secrets(
    upstream_url: &str,
    upstream_timeouts: secret_guard::config::UpstreamTimeouts,
    secrets: SecretTable,
) -> (String, ConversationDag) {
    let provider = openai_provider("oa-main", upstream_url);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("sg-state-timeout");
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));
    let provider_table = ProviderTable::with_persist_lock(
        vec![provider],
        vec![],
        decisions.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );
    let _ = (decisions, persist_lock, state_path);
    let dag = ConversationDag::new(64, 500, 1);
    let proxy = AppState {
        upstream_timeouts,
        ..base_app_state(
            server::build_upstream_client(upstream_timeouts.connect).unwrap(),
            provider_table,
            dag.clone(),
            secrets,
        )
    };
    let app = server::build_router(
        proxy,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), dag)
}

/// 便捷包装: 空 SecretTable (passthrough 路径, 既有超时测试用).
async fn spawn_proxy_with_timeouts(
    upstream_url: &str,
    upstream_timeouts: secret_guard::config::UpstreamTimeouts,
) -> (String, ConversationDag) {
    spawn_proxy_with_timeouts_and_secrets(upstream_url, upstream_timeouts, test_secret_table())
        .await
}

#[tokio::test]
async fn web_api_records_view_parsed_gemini_returns_error() {
    // Gemini 不在 codec 支持范围, view=parsed 应当返回 parse_error.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let provider = provider_with("gem-main", Protocol::Gemini, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/g/gem-main/v1/generateContent",
        r#"{"q":"hi"}"#,
        &[],
    )
    .await;
    let records = wait_for_record_count(&proxy_url, 1).await;
    let id = records[0].id;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/api/records/{id}?view=parsed"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["record"]["id"], id.to_string());
    assert!(body["parsed_request"].is_null());
    let err = body["parse_error"].as_str().unwrap();
    assert!(
        err.contains("gemini") || err.contains("protocol"),
        "parse_error should mention gemini/protocol, got: {err}"
    );
}

// ─── SEC-4: [redact] redacted_headers 自定义脱敏名单 (端到端) ────────────────
//
// 契约 (docs/design/contracts.md §7 SEC-4): 配置进 [redact] redacted_headers 的
// 自定义 header (不含 token/secret 关键词, 不在硬编码黑名单), 其值在 record 的
// req_headers / resp_headers 中必须显示 <redacted>; 未配置的无关 header 不受
// 影响 (并集语义, 非全量脱敏).

#[tokio::test]
async fn redacted_headers_config_masks_custom_header_in_record() {
    let mut upstream = spawn_mock_upstream().await;
    // 上游响应也带同名自定义敏感 header — 同一请求覆盖两条脱敏接线:
    // 请求侧 (recorder::build_call_event) 与响应侧 (fan_out_streaming 的
    // FanoutStreamCtx).
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_header("x-my-service-key", "resp-leak")
        .with_body(r#"{"id":"1","choices":[]}"#)
        .create_async()
        .await;

    // 配置条目故意混大小写 + 带空白: 验证装配点 normalize (trim + lowercase) 生效.
    let proxy_url =
        spawn_proxy_with_redacted_headers(vec!["  X-My-Service-Key ".to_string()], &upstream.url())
            .await;
    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"model":"gpt-4o","messages":[]}"#,
        &[("x-my-service-key", "req-leak"), ("x-innocent", "plain")],
    )
    .await;
    let records = wait_for_record_count(&proxy_url, 1).await;
    let id = records[0].id;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/api/records/{id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // req_headers / resp_headers 序列化为 [["name","value"], ...] 数对数组.
    let header_value = |key: &str, name: &str| -> String {
        body["record"][key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} must be an array"))
            .iter()
            .find_map(|pair| {
                (pair[0].as_str() == Some(name))
                    .then(|| pair[1].as_str().expect("value").to_string())
            })
            .unwrap_or_else(|| panic!("{name} missing from {key}"))
    };
    assert_eq!(
        header_value("req_headers", "x-my-service-key"),
        "<redacted>"
    );
    assert_eq!(
        header_value("resp_headers", "x-my-service-key"),
        "<redacted>"
    );
    // 未配置的无关 header 原样记录 (默认行为不变).
    assert_eq!(header_value("req_headers", "x-innocent"), "plain");
}

#[tokio::test]
async fn web_api_400_for_invalid_uuid() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/api/records/not-a-uuid"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn web_namespace_not_forwarded_to_upstream() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;

    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/api/records/"))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        !status.is_success(),
        "expected /api/* to NOT be forwarded upstream, got status {status}"
    );
}

// ─── secrets API ──────────────────────────────────────────────────────────

#[tokio::test]
async fn secrets_api_lists_empty() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/api/secrets"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    let secrets = body.get("secrets").and_then(|v| v.as_array()).unwrap();
    assert_eq!(secrets.len(), 0);
    let cats = body.get("categories").and_then(|v| v.as_array()).unwrap();
    assert!(cats.len() >= 5);
}

#[tokio::test]
async fn secrets_api_create_lists_update_delete() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{proxy_url}/api/secrets"))
        .json(&serde_json::json!({
            "id": "test-key-1",
            "name": "Test API Key",
            "category": "apikey",
            "value": "sk-test-1234567890abcdef",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(created["id"], "test-key-1");
    assert_ne!(created["value_masked"], "sk-test-1234567890abcdef");

    let resp = client
        .get(format!("{proxy_url}/api/secrets"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let secrets = body.get("secrets").and_then(|v| v.as_array()).unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0]["id"], "test-key-1");

    let resp = client
        .put(format!("{proxy_url}/api/secrets/test-key-1"))
        .json(&serde_json::json!({
            "name": "Renamed",
            "category": "token",
            "value": "new-token-value-9876543210",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["name"], "Renamed");

    let resp = client
        .delete(format!("{proxy_url}/api/secrets/test-key-1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
}

/// #164 子项 6: POST 不传 id 时服务端生成 UUID, 201 响应体以 `generated_id: true`
/// 明示 (脚本用户可感知 id 是服务端生成的, 而非自己传入的); 显式传 id 时无该字段.
#[tokio::test]
async fn secrets_api_generated_id_is_signaled() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let client = reqwest::Client::new();

    // 不传 id → 201 + generated_id: true + UUID 形态的 id.
    let resp = client
        .post(format!("{proxy_url}/api/secrets"))
        .json(&serde_json::json!({ "value": "sk-gen-123456789" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(created["generated_id"], serde_json::json!(true));
    let id = created["id"].as_str().unwrap().to_string();
    assert!(
        uuid::Uuid::parse_str(&id).is_ok(),
        "id should be a generated UUID v4: {id}"
    );

    // 显式传 id → 201 + 无 generated_id 字段 (向后兼容的加法: 老字段原样).
    let resp = client
        .post(format!("{proxy_url}/api/secrets"))
        .json(&serde_json::json!({
            "id": "explicit-id-1",
            "value": "sk-explicit-123456789",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(created["id"], "explicit-id-1");
    assert!(
        created.get("generated_id").is_none(),
        "explicit id must not carry generated_id: {created}"
    );

    // 清理 (两个 secret 均为 dynamic-only, 可删).
    for id in [id.as_str(), "explicit-id-1"] {
        let resp = client
            .delete(format!("{proxy_url}/api/secrets/{id}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    }
}

/// #164 子项 6 (providers 侧同构): POST providers 不传 id 生成 UUID 并明示.
#[tokio::test]
async fn providers_api_generated_id_is_signaled() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{proxy_url}/api/providers"))
        .json(&serde_json::json!({
            "protocol": "openai",
            "base_url": upstream.url(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(created["generated_id"], serde_json::json!(true));
    let id = created["id"].as_str().unwrap().to_string();
    assert!(uuid::Uuid::parse_str(&id).is_ok(), "id: {id}");

    let resp = client
        .delete(format!("{proxy_url}/api/providers/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn secrets_api_rejects_empty_value() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/api/secrets"))
        .json(&serde_json::json!({
            "id": "bad",
            "value": "",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn secrets_api_delete_missing_returns_404() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .delete(format!("{proxy_url}/api/secrets/does-not-exist"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ─── providers API ─────────────────────────────────────────────────────────

#[tokio::test]
async fn providers_api_lists_existing() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    let providers = body.get("providers").and_then(|v| v.as_array()).unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["id"], "oa-main");
    assert_eq!(providers[0]["protocol"], "openai");
    assert_eq!(providers[0]["api_key_masked"], "s*********y"); // "sk-test-key" (11 chars)
    assert!(body.get("protocols").unwrap().as_array().unwrap().len() >= 4);
    assert!(body.get("shorts").unwrap().as_array().unwrap().len() >= 4);
    // webui_protocols: 仅 codec 覆盖族 (openai/anthropic/openairesponses), 不含
    // 透传族 gemini/ollama — WebUI 新建表单词表 (见 list_providers).
    let webui: Vec<String> =
        serde_json::from_value(body.get("webui_protocols").cloned().unwrap()).unwrap();
    assert_eq!(webui, ["openai", "anthropic", "openairesponses"]);
}

#[tokio::test]
async fn providers_api_create_update_delete() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let client = reqwest::Client::new();

    // 创建新 Anthropic provider.
    let resp = client
        .post(format!("{proxy_url}/api/providers"))
        .json(&serde_json::json!({
            "id": "an-main",
            "name": "Anthropic Main",
            "protocol": "anthropic",
            "base_url": "https://api.anthropic.com",
            "api_key": "sk-ant-test-12345",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(created["id"], "an-main");
    assert_eq!(created["protocol"], "anthropic");
    assert_ne!(created["api_key_masked"], "sk-ant-test-12345");
    assert_eq!(created["api_key_length"], 17); // "sk-ant-test-12345"

    // List 看到 2 条.
    let resp = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let providers = body.get("providers").and_then(|v| v.as_array()).unwrap();
    assert_eq!(providers.len(), 2);

    // Update: 改 base_url.
    let resp = client
        .put(format!("{proxy_url}/api/providers/an-main"))
        .json(&serde_json::json!({
            "protocol": "anthropic",
            "base_url": "https://api.anthropic.com/v2",
            "api_key": "sk-ant-new",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["base_url"], "https://api.anthropic.com/v2");

    // Delete.
    let resp = client
        .delete(format!("{proxy_url}/api/providers/an-main"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // 剩 1 条.
    let resp = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let providers = body.get("providers").and_then(|v| v.as_array()).unwrap();
    assert_eq!(providers.len(), 1);
}

/// PUT provider 请求, 物理省略 api_key 字段.
///
/// 用 raw JSON body 而非 `serde_json::json!` 确保 `api_key` 被物理省略
/// (json! 的 null 序列化为 `"api_key":null`, 而非字段缺失).
/// `#[serde(default)]` 把字段缺失反序列化为 None, 把显式 null 也反序列化为 None,
/// 但 raw body 测试更严格地模拟了 WebUI 实际发的请求形态.
async fn put_provider_omit_api_key(
    client: &reqwest::Client,
    proxy_url: &str,
    id: &str,
    base_url: &str,
) -> reqwest::Response {
    client
        .put(format!("{proxy_url}/api/providers/{id}"))
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"protocol":"openai","base_url":"{base_url}"}}"#
        ))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn providers_api_update_preserves_api_key_when_omitted() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let client = reqwest::Client::new();

    // 创建带 api_key 的 provider.
    let resp = client
        .post(format!("{proxy_url}/api/providers"))
        .json(&serde_json::json!({
            "id": "oa-pres",
            "name": "OpenAI Preserve",
            "protocol": "openai",
            "base_url": upstream.url(),
            "api_key": "sk-original-XYZ",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    // PUT 不带 api_key 字段 (JSON 省略 → 后端 None): 应保留旧值.
    let resp =
        put_provider_omit_api_key(&client, &proxy_url, "oa-pres", "https://example.com/v2").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["base_url"], "https://example.com/v2");
    assert_eq!(updated["api_key_length"], 15); // "sk-original-XYZ" 保留
    assert!(updated["api_key_masked"].as_str().unwrap().contains('*'));

    // PUT 显式发空串 api_key: 应清空.
    let resp = client
        .put(format!("{proxy_url}/api/providers/oa-pres"))
        .json(&serde_json::json!({
            "protocol": "openai",
            "base_url": "https://example.com/v3",
            "api_key": "",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let cleared: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cleared["api_key_length"], 0);
}

#[tokio::test]
async fn providers_api_update_preserves_api_key_on_static_fork() {
    // 编辑 static-only provider 时, api_key 省略应从 static baseline 保留.
    let upstream = spawn_mock_upstream().await;
    let static_provider = keyed_provider("oa-static", &upstream.url(), "sk-static-key");
    let (proxy_url, _state_path) = spawn_with_static(static_provider).await;
    let client = reqwest::Client::new();

    // PUT 编辑 static-only id (不传 api_key) → 触发 fork, api_key 应来自 static.
    let resp =
        put_provider_omit_api_key(&client, &proxy_url, "oa-static", "https://new.example.com")
            .await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let forked: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(forked["base_url"], "https://new.example.com");
    assert_eq!(forked["api_key_length"], 13); // "sk-static-key" 保留
    assert_eq!(forked["source"], "dynamic_override");
}

/// #157 现象 A: PUT 编辑 static inline-key provider 且 api_key=null →
/// state.toml 不得含 static 明文 key; effective 仍带旧 key (转发行为不变).
#[tokio::test]
async fn put_static_fork_null_api_key_does_not_persist_plaintext() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("authorization", "Bearer sk-inline-upstream-key")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-1"}"#)
        .create_async()
        .await;

    let static_provider = keyed_provider("p1", &upstream.url(), "sk-inline-upstream-key");
    let (proxy_url, state_path) = spawn_with_static(static_provider).await;
    let client = reqwest::Client::new();

    // PUT api_key=null (意图保留旧值). 旧 bug: 已 resolve 的 static 明文被写进 override.
    let resp = client
        .put(format!("{proxy_url}/api/providers/p1"))
        .json(&serde_json::json!({
            "protocol": "openai",
            "base_url": upstream.url(),
            "api_key": null,
            "enabled": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // state.toml 不得含 static 明文 key (#157 核心 断言).
    let state_text = std::fs::read_to_string(&state_path).unwrap();
    assert!(
        !state_text.contains("sk-inline-upstream-key"),
        "state.toml must not contain the static plaintext api_key, got:\n{state_text}"
    );

    // effective 视图仍带旧 key (length 保留), source 是 dynamic_override.
    let updated: serde_json::Value = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let p = &updated["providers"][0];
    assert_eq!(p["source"], "dynamic_override");
    assert_eq!(p["api_key_length"], 22); // "sk-inline-upstream-key" 继承自 static

    // 转发仍带旧 key: mock 只在 authorization 匹配旧 key 时返回 200.
    let resp = proxy_request(&proxy_url, "POST", "/o/p1/v1/chat/completions", "{}", &[]).await;
    assert_eq!(resp.0, reqwest::StatusCode::OK);
}

/// #157 现象 A 对照: PUT 显式提供新 api_key → 新 key 落盘 state.toml (预期行为,
/// dynamic secret value 本来就落盘) + 转发带新 key.
#[tokio::test]
async fn put_static_fork_new_api_key_persists_and_forwards() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("authorization", "Bearer sk-new-explicit-key")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-2"}"#)
        .create_async()
        .await;

    let static_provider = keyed_provider("p1", &upstream.url(), "sk-inline-upstream-key");
    let (proxy_url, state_path) = spawn_with_static(static_provider).await;
    let client = reqwest::Client::new();

    let resp = client
        .put(format!("{proxy_url}/api/providers/p1"))
        .json(&serde_json::json!({
            "protocol": "openai",
            "base_url": upstream.url(),
            "api_key": "sk-new-explicit-key",
            "enabled": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 显式新 key 落盘 state.toml — 这是预期 (dynamic value 本来就落盘, 见 #157 现象 B 文档).
    let state_text = std::fs::read_to_string(&state_path).unwrap();
    assert!(
        state_text.contains("sk-new-explicit-key"),
        "explicitly provided api_key is expected to persist, got:\n{state_text}"
    );
    assert!(!state_text.contains("sk-inline-upstream-key"));

    // 转发带新 key.
    let resp = proxy_request(&proxy_url, "POST", "/o/p1/v1/chat/completions", "{}", &[]).await;
    assert_eq!(resp.0, reqwest::StatusCode::OK);
}

/// #157: 继承语义也覆盖 api_key_file 来源的 static 基线 — PUT 不传 key 字段时
/// override 不记录, effective 从 static 继承文件引用 (转发时读文件).
#[tokio::test]
async fn put_static_fork_null_api_key_inherits_api_key_file() {
    let keyfile = std::path::PathBuf::from(format!(
        "/tmp/opencode/tmp/test-put-file-key-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(keyfile.parent().unwrap()).unwrap();
    std::fs::write(&keyfile, "sk-from-static-file\n").unwrap();

    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("authorization", "Bearer sk-from-static-file")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-3"}"#)
        .create_async()
        .await;

    let mut static_provider = keyed_provider("pf", &upstream.url(), "");
    if let ProviderKind::Direct(d) = &mut static_provider.kind {
        d.api_key_file = Some(keyfile.clone());
    }
    let (proxy_url, state_path) = spawn_with_static(static_provider).await;
    let client = reqwest::Client::new();

    let resp = client
        .put(format!("{proxy_url}/api/providers/pf"))
        .json(&serde_json::json!({
            "protocol": "openai",
            "base_url": upstream.url(),
            "api_key": null,
            "api_key_file": null,
            "enabled": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // state 不落盘 key 内容; 且 override 未记录任何 key 字段 (api_key_file 路径也不在
    // state 里 — 继承发生在 effective 解析时, static 持有路径).
    let state_text = std::fs::read_to_string(&state_path).unwrap();
    assert!(!state_text.contains("sk-from-static-file"));

    // 正向断言: state 里也不含文件路径引用 (override 未记录该字段).
    assert!(!state_text.contains("test-put-file-key"));

    // 转发仍从文件读到旧 key.
    let resp = proxy_request(&proxy_url, "POST", "/o/pf/v1/chat/completions", "{}", &[]).await;
    assert_eq!(resp.0, reqwest::StatusCode::OK);
    std::fs::remove_file(&keyfile).ok();
}

/// #157 已知限制锁定: static 基线下 PUT api_key="" (显式清空意图) 无法真正清空 —
/// 落盘空串与 "未记录" 形态相同, effective 仍继承 static 旧 key. 该行为已文档化
/// (根 AGENTS.md 已知限制 + providers.rs 字段注释); 本测试固化现状, schema 演进
/// (区分两种空) 时此测试必须同步修改.
#[tokio::test]
async fn put_static_fork_empty_api_key_still_inherits_static() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("authorization", "Bearer sk-inline-upstream-key")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-4"}"#)
        .create_async()
        .await;

    let static_provider = keyed_provider("pe", &upstream.url(), "sk-inline-upstream-key");
    let (proxy_url, _state_path) = spawn_with_static(static_provider).await;
    let client = reqwest::Client::new();

    let resp = client
        .put(format!("{proxy_url}/api/providers/pe"))
        .json(&serde_json::json!({
            "protocol": "openai",
            "base_url": upstream.url(),
            "api_key": "",
            "enabled": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // effective 视图: 空 api_key 显示为继承后的 static key length.
    let updated: serde_json::Value = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["providers"][0]["api_key_length"], 22);

    // 转发仍带 static 旧 key (继承生效 — 显式清空在 static 基线下不可达, 已知限制).
    let resp = proxy_request(&proxy_url, "POST", "/o/pe/v1/chat/completions", "{}", &[]).await;
    assert_eq!(resp.0, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn providers_api_rejects_bad_base_url() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/api/providers"))
        .json(&serde_json::json!({
            "id": "bad",
            "protocol": "openai",
            "base_url": "not-a-url",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ─── providers probe API (POST /api/providers/probe) ─────────────────────

/// 非法 base_url (同 provider validate_base_url 规则) → 400; 各形态都测一遍.
#[tokio::test]
async fn providers_probe_api_rejects_invalid_base_url() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let client = reqwest::Client::new();
    for bad in ["not-a-url", "ftp://x", "http://x/", ""] {
        let resp = client
            .post(format!("{proxy_url}/api/providers/probe"))
            .json(&serde_json::json!({ "base_url": bad, "api_key": "" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "base_url {bad:?} must be rejected"
        );
    }
}

/// id 保留字: "probe" 会阴影 PUT/DELETE /api/providers/{id} (静态段优先),
/// 创建时必须拒绝 (validate_provider_upsert 的路由保留不变量).
#[tokio::test]
async fn providers_api_rejects_probe_reserved_id() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/api/providers"))
        .json(&serde_json::json!({
            "id": "probe",
            "protocol": "openai",
            "base_url": upstream.url(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    // 断言拒绝原因, 防其它先行的校验拦截造成假阳性通过.
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("reserved"),
        "rejection must come from the reserved-id rule: {body}"
    );
}

/// 端到端: OpenAI shape 上游 → 200 + 固定 4 项 probes + recommended; 响应体
/// (raw text) 不含 api_key 子串 (SEC 红线, 双保险于单测的净化断言).
#[tokio::test]
async fn providers_probe_api_end_to_end_openai() {
    let mut upstream = spawn_mock_upstream().await;
    upstream
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"object":"list","data":[{"id":"gpt-4o","object":"model"}]}"#)
        .expect(1)
        .create_async()
        .await;
    for path in ["/v1beta/models", "/api/tags"] {
        upstream
            .mock("GET", path)
            .with_status(404)
            .create_async()
            .await;
    }
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let api_key = "sk-integration-leaky";
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/api/providers/probe"))
        .json(&serde_json::json!({ "base_url": upstream.url(), "api_key": api_key }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let raw = resp.text().await.unwrap();
    assert!(
        !raw.contains(api_key),
        "probe response must not leak api_key: {raw}"
    );
    let body: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let names: Vec<&str> = body["probes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["protocol"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["openai", "anthropic", "gemini", "ollama"]);
    assert_eq!(body["probes"][0]["status"], "ok");
    assert_eq!(body["probes"][0]["models"][0], "gpt-4o");
    assert_eq!(body["probes"][1]["status"], "absent");
    assert_eq!(body["probes"][2]["status"], "absent");
    assert_eq!(body["probes"][3]["status"], "absent");
    assert_eq!(body["recommended"], "openai");
    assert!(body["note"].is_null());
}

/// 探测全失败 (上游三个端点全部 500) 仍是 200 — 失败是数据不是 HTTP 错误,
/// recommended 为 null.
#[tokio::test]
async fn providers_probe_api_all_failures_still_200() {
    let mut upstream = spawn_mock_upstream().await;
    for path in ["/v1/models", "/v1beta/models", "/api/tags"] {
        upstream
            .mock("GET", path)
            .with_status(500)
            .create_async()
            .await;
    }
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/api/providers/probe"))
        .json(&serde_json::json!({ "base_url": upstream.url() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    for probe in body["probes"].as_array().unwrap() {
        assert_eq!(probe["status"], "error");
        assert!(probe["detail"].is_string(), "error 必有 detail");
    }
    assert!(body["recommended"].is_null());
    assert!(body["note"].is_null());
}

/// 路由补齐 (PUT/DELETE /api/providers/probe): 存量 id="probe" 条目可编辑可删除.
///
/// 存量条目在 AppState 构造期直插 (dynamic 层, 绕过 API — 模拟保留字校验上线
/// 前创建的条目, 静态路由阴影 {id} 段曾使其不可管理/405)。补齐后 PUT 改
/// base_url 生效, DELETE 真删除 (dynamic-only 无 static 冲突)。
#[tokio::test]
async fn providers_probe_api_legacy_probe_id_editable_and_deletable() {
    // 初值 base_url 用哑地址即可: 本测试不发转发请求, PUT 第一步就覆盖它.
    let upstream_b = spawn_mock_upstream().await;
    let legacy = openai_provider("probe", "http://127.0.0.1:1");
    let proxy_url = spawn_proxy_full(
        vec![legacy],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await;
    let client = reqwest::Client::new();

    // PUT (改 base_url; 其余 Direct 字段走回填) → 200, effective base_url 已切换.
    let resp = client
        .put(format!("{proxy_url}/api/providers/probe"))
        .json(&serde_json::json!({ "base_url": upstream_b.url() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["id"], "probe");
    assert_eq!(body["base_url"], upstream_b.url());

    // DELETE → 204; 列表再无该条目.
    let resp = client
        .delete(format!("{proxy_url}/api/providers/probe"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    let resp = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    let ids: Vec<&str> = list["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert!(!ids.contains(&"probe"), "probe entry must be gone: {ids:?}");
}

/// PATCH decision 对存量 id="probe" 的可达性 (matchit 回溯语义 pin).
///
/// 静态路由 `/api/providers/probe` 只有 2 段; 3 段的 `/api/providers/probe/decision`
/// 依赖 matchit 0.8 的回溯 (沿静态段下降遇死端后回到 `{id}` 参数分支) 匹配到
/// `/api/providers/{id}/decision`。matchit 0.7 曾移除回溯, 该语义历史上有过翻转 —
/// 本测试把它钉死在契约层: 未来 axum/matchit 升级若再变语义, 这里红灯而非静默 404
/// (存量 id="probe" 条目的 enable/disable 将不可用)。
#[tokio::test]
async fn providers_probe_static_probe_id_decision_reachable() {
    let s = openai_provider("probe", "http://127.0.0.1:1");
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let resp = reqwest::Client::new()
        .patch(format!("{proxy_url}/api/providers/probe/decision"))
        .json(&serde_json::json!({ "mode": "disabled" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

// ─── redact / restore flow ─────────────────────────────────────────────────

#[tokio::test]
async fn redact_strips_secret_from_upstream_request() {
    let real_secret = "sk-test-123";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-1"}"#)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(r#"{{"messages":[{{"content":"use {real_secret} now"}}]}}"#);
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "record body must not contain real secret, got: {}",
        r.req_body
    );
    assert!(
        r.req_body.contains("use") && r.req_body.contains("now"),
        "non-secret content must be preserved, got: {}",
        r.req_body
    );
}

#[tokio::test]
async fn redact_populates_record_redactions_field() {
    // 验证 ForwardRecord.redactions 在 same_proto + redact 路径被正确填充.
    // 这是 WebUI 渲染 "本次请求命中哪些 secret" 的权威数据源.
    let real_secret = "sk-redact-me-456";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-1"}"#)
        .create_async()
        .await;

    let entries = vec![secret("my-api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    // 请求体含 real_secret → codec + redact_ir 会命中.
    let body = format!(r#"{{"messages":[{{"content":"use {real_secret}"}}]}}"#);
    let _ = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    // redactions 应当有 1 条: (mock_value, "my-api-key").
    assert_eq!(
        r.redactions.len(),
        1,
        "expected 1 redaction, got: {:?}",
        r.redactions
    );
    assert_eq!(r.redactions[0].1, "my-api-key", "secret id mismatch");
    assert!(
        !r.redactions[0].0.is_empty() && r.redactions[0].0 != "my-api-key-value",
        "mock should be non-empty and differ from real, got: {}",
        r.redactions[0].0
    );
    // 关键: redactions 中绝不能出现真实 secret.
    assert!(
        !r.redactions.iter().any(|(m, _)| m.contains(real_secret)),
        "redactions must not leak real secret"
    );
    // 记录的 req_body 中也应当看不到真实 secret (mock 替换后).
    assert!(!r.req_body.contains(real_secret));
}

#[tokio::test]
async fn passthrough_path_leaves_redactions_empty() {
    // 无 secret 配置 → passthrough 路径 → redactions 应当为空 vec.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(), // 空 secrets 表
    )
    .await;

    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"q":"no-secret-here"}"#,
        &[],
    )
    .await;

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    assert!(
        list[0].redactions.is_empty(),
        "passthrough path should leave redactions empty, got: {:?}",
        list[0].redactions
    );
}

// ─── on_probe_exhausted = "fail_closed" 端到端 ────────────────────────────
//
// 构造弱配置 secret (digits-only + length_range=(1,1), 仅 10 个候选 "0".."9") +
// 对抗性 IR (含全部 10 个候选) → mock probing 必然耗尽.
// 验证:
// - FailClosed 模式: proxy 返回 503, 不转发到上游.
// - FailOpen 模式 (回归): proxy 正常转发 (200), secret 原样发往上游.

/// 构造一个"探测必耗尽"的 SecretEntry (digits-only + length=1, 仅 10 个候选).
fn weak_secret(id: &str, value: &str) -> SecretEntry {
    use secret_guard::mock::{Charset, GenSpec, InitialValue, MockStrategy};
    let mut e = SecretEntry {
        id: id.into(),
        name: Some(id.into()),
        category: SecretCategory::ApiKey,
        value: value.into(),
        value_file: None,
        mock_strategy: MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: String::new(),
                charset: Charset {
                    digits: true,
                    ..Default::default()
                },
                length_range: (1, 1), // 仅 10 个可能值 "0".."9"
            }),
        },
    };
    e.mock_strategy.resolve_against(value, "");
    e
}

#[tokio::test]
async fn fail_closed_mode_returns_503_when_probing_exhausted() {
    // 弱配置 + IR 含全部 10 个数字候选 → FailClosed 必然拒绝转发.
    let real_secret = "super-secret-fail-closed-DO-NOT-LEAK";
    let mut upstream = spawn_mock_upstream().await;
    // mock 期望: 若被调用说明 FailClosed 失效 (回归). 用 expect(0) + assert 守卫
    // "上游未被调用" (RED-4 fail_closed property 的显式子句). assert() 只读 mockito
    // 共享 state (hit 计数在同步锁内累加, 不跨 await), 此处 client 已收到 503,
    // proxy 侧 future 已结束, 无 "在途请求未计数" 窗口.
    let mock = upstream
        .mock("POST", "/v1/chat/completions")
        .expect(0)
        .with_status(200)
        .with_body(r#"{"id":"should-not-reach"}"#)
        .create_async()
        .await;

    let entries = vec![weak_secret("weak-api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let proxy_url = spawn_proxy_with_probe_mode(
        secret_guard::config::OnProbeExhausted::FailClosed,
        secrets,
        &upstream.url(),
    )
    .await;

    // IR 含 "0 1 2 ... 9" 让 10 个候选全部已出现 → probing 必耗尽.
    let body = format!(
        r#"{{"messages":[{{"content":"0 1 2 3 4 5 6 7 8 9 filler uses {real_secret}"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    // 核心: FailClosed 必须返回 503 (Unavailable), 不转发到上游.
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "FailClosed must return 503 on probing exhaustion"
    );
    let text = resp.text().await.unwrap();
    assert!(
        text.contains("redact probe exhausted") && text.contains("fail_closed"),
        "503 body should explain the refusal; got: {text}"
    );
    // SEC-2 守卫: 错误消息绝不能含真实 secret 明文.
    assert!(
        !text.contains(real_secret),
        "FailClosed 503 body must not leak real secret; got: {text}"
    );
    // 上游 mock 不应被调用: FailClosed 在 redact 完成前就拒绝转发
    // (expect(0) + assert 机制见上方 mock 创建处注释).
    mock.assert();
}

#[tokio::test]
async fn fail_open_mode_remains_forwarding_when_probing_exhausted() {
    // 回归: FailOpen 模式 (显式 opt-in; 默认已翻转为 fail_closed, SEC-10) 下,
    // 即使 probing 耗尽, 请求仍正常转发到上游.
    let real_secret = "super-secret-fail-open-still-forwarded";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-1"}"#)
        .create_async()
        .await;

    let entries = vec![weak_secret("weak-api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let proxy_url = spawn_proxy_with_probe_mode(
        secret_guard::config::OnProbeExhausted::FailOpen,
        secrets,
        &upstream.url(),
    )
    .await;

    let body = format!(
        r#"{{"messages":[{{"content":"0 1 2 3 4 5 6 7 8 9 filler uses {real_secret}"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    // FailOpen: 即便 probing 耗尽, 仍正常转发到上游 (200).
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "FailOpen must forward to upstream (historical behavior, backward compat)"
    );
}

/// fail_closed 的 503 拒绝在 **cross_proto 路径**同样生效 (M-C1 守卫: 错误映射
/// 收口到 probe_exhausted_error 后, same-proto / cross-proto 两路径行为一致).
/// 上游 provider 是 openai, ingress 用 anthropic (`/a/`) → 跨协议翻译路径.
#[tokio::test]
async fn fail_closed_mode_returns_503_when_probing_exhausted_cross_proto() {
    let real_secret = "super-secret-fail-closed-cross-proto";
    let mut upstream = spawn_mock_upstream().await;
    // expect(0) + assert 守卫 "上游未被调用" (与 same-proto 版同型, RED-4 子句).
    let mock = upstream
        .mock("POST", "/v1/chat/completions")
        .expect(0)
        .with_status(200)
        .with_body(r#"{"id":"should-not-reach"}"#)
        .create_async()
        .await;

    let entries = vec![weak_secret("weak-api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let proxy_url = spawn_proxy_with_probe_mode(
        secret_guard::config::OnProbeExhausted::FailClosed,
        secrets,
        &upstream.url(),
    )
    .await;

    // anthropic ingress body (role/max_tokens 为 reader 必填形态) + 全部 10 个
    // 数字候选 → redact_ir 的 mock probing 必然耗尽 → 503 拒绝转发.
    let body = format!(
        r#"{{"model":"m","max_tokens":16,"messages":[{{"role":"user","content":"0 1 2 3 4 5 6 7 8 9 filler {real_secret}"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/a/oa-main/v1/messages"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "FailClosed must return 503 on probing exhaustion (cross-proto path)"
    );
    let text = resp.text().await.unwrap();
    // M-C1 守卫: pin 503 message 全文 (客户端可见契约面, SEC-2 同型 — 两路径
    // 共享 probe_exhausted_error, 文案漂移在此立即暴露). message 无引号/反斜杠,
    // JSON 转义不影响子串形态.
    let expected_msg = "redact probe exhausted, secret forwarding refused by policy \
         (on_probe_exhausted=fail_closed); check secret mock_strategy config \
         (secret_id hint: weak-api-key, reason: ProbingExhausted)";
    assert!(
        text.contains(expected_msg),
        "503 body must pin the exact refusal message; got: {text}"
    );
    assert!(
        !text.contains(real_secret),
        "FailClosed 503 body must not leak real secret; got: {text}"
    );
    mock.assert();
}

#[tokio::test]
async fn restore_inserts_secret_back_for_client() {
    // IR-based redact round-trip: 请求里 secret → mock → LLM, 响应里 mock → secret → client.
    // 用 predict_mock(real) 预测首次 mock, 让上游响应直接含 mock, 验证 restore 生效.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    let upstream_body = format!(
        r#"{{"id":"chatcmpl-x","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{{"index":0,"message":{{"role":"assistant","content":"echo {expected_mock}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}}}"#
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(upstream_body)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let resp_text = resp.text().await.unwrap();
    // 客户端应看到 real_secret (mock 已被 restore).
    assert!(
        resp_text.contains(real_secret),
        "client should see real_secret restored; got: {resp_text}"
    );
    assert!(
        !resp_text.contains(&expected_mock),
        "client should NOT see mock; got: {resp_text}"
    );

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "record body must not contain real secret: {}",
        r.req_body
    );
}

#[tokio::test]
async fn no_redact_when_secret_table_empty() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::Exact("raw-body".into()))
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body("raw-body")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

// ─── static + dynamic 合并 (新设计核心) ────────────────────────────────────

/// spawn proxy, 接受 static_providers (来自声明式 config) + dynamic providers (WebUI 写过).
async fn spawn_with_static_and_dynamic(
    static_providers: Vec<Provider>,
    dynamic_providers: Vec<Provider>,
) -> String {
    spawn_proxy_static_dynamic(
        static_providers,
        dynamic_providers,
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0
}

/// #157 族: 单 static provider + 空 dynamic, 返回 (url, state_path) 供断言落盘内容.
async fn spawn_with_static(p: Provider) -> (String, std::path::PathBuf) {
    spawn_proxy_static_dynamic(
        vec![p],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
}

#[tokio::test]
async fn static_provider_is_listed_with_static_source() {
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("providers").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], "static-p");
    assert_eq!(arr[0]["source"], "static");
    assert_eq!(arr[0]["decision"], "default");
    assert!(arr[0]["static_version"].is_object());
    assert!(arr[0]["dynamic_version"].is_null());
}

#[tokio::test]
async fn static_provider_routes_correctly() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("static-routed")
        .create_async()
        .await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;

    let resp = proxy_request(
        &proxy_url,
        "POST",
        "/o/static-p/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(resp.0, reqwest::StatusCode::OK);
    assert_eq!(resp.1, "static-routed");
}

#[tokio::test]
async fn dynamic_override_replaces_static_in_routing() {
    let mut upstream_static = spawn_mock_upstream().await;
    let _m_static = upstream_static
        .mock("POST", "/v1/chat/completions")
        .with_body("from-static-upstream")
        .create_async()
        .await;
    let mut upstream_dyn = spawn_mock_upstream().await;
    let _m_dyn = upstream_dyn
        .mock("POST", "/v1/chat/completions")
        .with_body("from-dynamic-upstream")
        .create_async()
        .await;

    let static_p = openai_provider("shared-id", &upstream_static.url());
    let mut dynamic_p = openai_provider("shared-id", &upstream_dyn.url());
    if let ProviderKind::Direct(d) = &mut dynamic_p.kind {
        d.api_key = "dynamic-key".into();
    }
    let proxy_url = spawn_with_static_and_dynamic(vec![static_p], vec![dynamic_p]).await;

    let resp = proxy_request(
        &proxy_url,
        "POST",
        "/o/shared-id/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(resp.1, "from-dynamic-upstream", "dynamic 应覆盖 static");
}

#[tokio::test]
async fn decision_disabled_drops_static_provider() {
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-disabled", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    // 切到 disabled.
    let resp = client
        .patch(format!(
            "{proxy_url}/api/providers/static-disabled/decision"
        ))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // List 不再包含.
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("providers").unwrap().as_array().unwrap();
    assert!(arr.is_empty(), "disabled 应从 effective view 中消失");

    // 路由也 404.
    let resp = proxy_request(
        &proxy_url,
        "POST",
        "/o/static-disabled/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(resp.0, reqwest::StatusCode::NOT_FOUND);
}

/// CFG-1 (effective view 排除) 与 WebUI 可见性解耦: disabled 条目经 `disabled`
/// 数组以 masked 形式返回 (SEC: 不回明文), 且 decision 可切回复活 —
/// 修复 "disable 后条目从 WebUI 消失且无恢复入口" (2026-09-13 排查).
#[tokio::test]
async fn disabled_provider_listed_masked_and_recoverable() {
    let s = openai_provider("static-disabled", "https://upstream.example");
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    // 切到 disabled.
    let resp = client
        .patch(format!(
            "{proxy_url}/api/providers/static-disabled/decision"
        ))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // disabled 数组含该条目, 且 api_key masked (SEC: 响应文本不含明文).
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("disabled").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1, "disabled 数组应含被禁条目: {body}");
    assert_eq!(arr[0]["id"], "static-disabled");
    let raw = body.to_string();
    assert!(!raw.contains("sk-test-key"), "SEC: 明文 api_key 不得回传");

    // decision 切回复活: 条目回到 effective (providers 数组), disabled 数组清空.
    let resp = client
        .patch(format!(
            "{proxy_url}/api/providers/static-disabled/decision"
        ))
        .json(&serde_json::json!({"mode": "default"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("providers").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1, "切回 default 后条目应回归 effective: {body}");
    assert_eq!(
        body.get("disabled").unwrap().as_array().unwrap().len(),
        0,
        "disabled 数组应清空"
    );
}

/// secrets 侧同构: disabled secret 经 disabled 数组返回 masked 视图, 可切回.
#[tokio::test]
async fn disabled_secret_listed_masked_and_recoverable() {
    let proxy_url = spawn_with_secrets(vec![secret("s1", "super-secret-value")], vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .patch(format!("{proxy_url}/api/secrets/s1/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = client
        .get(format!("{proxy_url}/api/secrets"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("disabled").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1, "disabled 数组应含被禁 secret: {body}");
    assert_eq!(arr[0]["id"], "s1");
    let raw = body.to_string();
    assert!(
        !raw.contains("super-secret-value"),
        "SEC: 明文 value 不得回传"
    );

    // 切回 prefer_static: 条目回归 effective (static-only id 的生效路径).
    let resp = client
        .patch(format!("{proxy_url}/api/secrets/s1/decision"))
        .json(&serde_json::json!({"mode": "prefer_static"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/api/secrets"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("secrets").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1, "切回后条目应回归 effective: {body}");
    assert_eq!(arr[0]["source"], "static");
    assert_eq!(body.get("disabled").unwrap().as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn decision_prefer_static_beats_dynamic_override() {
    let mut upstream_static = spawn_mock_upstream().await;
    let _m_static = upstream_static
        .mock("POST", "/v1/chat/completions")
        .with_body("static-wins")
        .create_async()
        .await;
    let mut upstream_dyn = spawn_mock_upstream().await;
    let _m_dyn = upstream_dyn
        .mock("POST", "/v1/chat/completions")
        .with_body("dynamic-loses")
        .create_async()
        .await;

    let static_p = openai_provider("both", &upstream_static.url());
    let dynamic_p = openai_provider("both", &upstream_dyn.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![static_p], vec![dynamic_p]).await;
    let client = reqwest::Client::new();

    let resp = client
        .patch(format!("{proxy_url}/api/providers/both/decision"))
        .json(&serde_json::json!({"mode": "prefer_static"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let resp = proxy_request(&proxy_url, "POST", "/o/both/v1/chat/completions", "{}", &[]).await;
    assert_eq!(resp.1, "static-wins");
}

#[tokio::test]
async fn put_static_provider_forks_dynamic_override() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_body("ok")
        .create_async()
        .await;
    let s = openai_provider("static-p", "https://invalid-static.example");
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    // 用 PUT 编辑 static provider → 服务端自动 fork 出 dynamic.
    let resp = client
        .put(format!("{proxy_url}/api/providers/static-p"))
        .json(&serde_json::json!({
            "protocol": "openai",
            "base_url": upstream.url(),
            "api_key": "forked-key",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["source"], "dynamic_override");
    assert_eq!(updated["base_url"], upstream.url());
    assert!(updated["static_version"].is_object());
    assert!(updated["dynamic_version"].is_object());

    // 路由应走 dynamic (指向 mock), 而不是 static (指向 invalid URL).
    let resp = proxy_request(
        &proxy_url,
        "POST",
        "/o/static-p/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(resp.0, reqwest::StatusCode::OK);
    assert_eq!(resp.1, "ok");
}

#[tokio::test]
async fn delete_static_only_provider_is_rejected() {
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .delete(format!("{proxy_url}/api/providers/static-p"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "static 永不可删, 必须走 decision=disabled"
    );
    // #156: 错误体必须含 decision 指引 (与 secrets 侧同构的 409 body).
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("decision"),
        "409 body must point to the decision endpoint, got: {body}"
    );
}

/// #156: static + dynamic override 时 DELETE 也必须 409 (三态之一).
/// 旧行为返回 204 (删 override 露出 static), 让用户误以为删除成功 — 已废除.
#[tokio::test]
async fn delete_provider_with_override_is_rejected() {
    let upstream = spawn_mock_upstream().await;
    let static_p = openai_provider("p", &upstream.url());
    let dynamic_p = openai_provider("p", "https://dynamic-invalid.example");
    let proxy_url = spawn_with_static_and_dynamic(vec![static_p], vec![dynamic_p]).await;
    let client = reqwest::Client::new();

    let resp = client
        .delete(format!("{proxy_url}/api/providers/p"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "static 基线存在时 DELETE 必须拒绝, 无论有无 dynamic override"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("decision"),
        "409 body must point to the decision endpoint, got: {body}"
    );

    // override 未被删除: list 中该 id 仍是 dynamic_override, 路由仍走 dynamic.
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("providers").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["source"], "dynamic_override");
}

/// #156: 纯 dynamic provider DELETE → 204 (三态之一) + 真正删除.
#[tokio::test]
async fn delete_dynamic_only_provider_succeeds() {
    let upstream = spawn_mock_upstream().await;
    let d = openai_provider("dyn-only", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![], vec![d]).await;
    let client = reqwest::Client::new();

    let resp = client
        .delete(format!("{proxy_url}/api/providers/dyn-only"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // 真正删除: list 为空, 转发 404.
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body.get("providers").unwrap().as_array().unwrap().len(), 0);

    let resp = proxy_request(
        &proxy_url,
        "POST",
        "/o/dyn-only/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(resp.0, reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_post_rejects_conflict_with_static_id() {
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{proxy_url}/api/providers"))
        .json(&serde_json::json!({
            "id": "static-p",
            "protocol": "openai",
            "base_url": "https://other.example",
            "api_key": "x",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn decision_endpoint_rejects_non_static_id() {
    let upstream = spawn_mock_upstream().await;
    let d = openai_provider("dynamic-only", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![], vec![d]).await;
    let client = reqwest::Client::new();

    let resp = client
        .patch(format!("{proxy_url}/api/providers/dynamic-only/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "decision 只对 static id 有意义"
    );
}

#[tokio::test]
async fn secret_decision_disabled_drops_from_redaction() {
    // static secret + decision=disabled → redact 流程不应再使用它.
    let mut upstream = spawn_mock_upstream().await;
    let real_secret = "static-secret-value";
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;

    let provider = openai_provider("oa-main", &upstream.url());
    // 把 secret 放入 static 层.
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let secret_path = tmp_state_path("static-secret");
    let static_secrets = vec![secret("static-s", real_secret)];
    let secrets = SecretTable::new(static_secrets, vec![], decisions, secret_path);

    let (proxy_url, _state_path) = spawn_proxy_static_dynamic(
        vec![provider],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        secrets,
    )
    .await;
    let client = reqwest::Client::new();

    // 禁用 static-s.
    let resp = client
        .patch(format!("{proxy_url}/api/secrets/static-s/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 发请求带 secret → 应当原样转发 (redact 不再发生).
    let (_, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        &format!("{{\"prompt\": \"{real_secret}\"}}"),
        &[],
    )
    .await;

    // 等记录写入, 验证 body 仍含 secret.
    let records = wait_for_record_count(&proxy_url, 1).await;
    // list 不返回 req_body, 需通过 detail API 拉取.
    let detail: serde_json::Value = client
        .get(format!("{proxy_url}/api/records/{}", records[0].id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let body = detail["record"]["req_body"].as_str().unwrap_or("");
    assert!(
        body.contains(real_secret),
        "disabled secret 应当不被 redact, body={body}"
    );
}

/// #161: PATCH decision=disabled 的 ack 响应携带 warning (secret 明文放行警示);
/// default / prefer_static 不携带 (向后兼容 shape). provider 的 disabled 不携带
/// (语义是禁转发, 非放行).
#[tokio::test]
async fn secret_decision_disabled_ack_carries_plaintext_warning() {
    let upstream = spawn_mock_upstream().await;
    let provider = openai_provider("oa-main", &upstream.url());
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let secrets = SecretTable::new(
        vec![secret("static-s", "static-secret-value")],
        vec![],
        decisions,
        tmp_state_path("warn-ack-secret"),
    );

    // providers 表也放一个 static, 验证 provider 分支无 warning.
    let (proxy_url, _state_path) = spawn_proxy_static_dynamic(
        vec![provider],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        secrets,
    )
    .await;
    let client = reqwest::Client::new();

    // 1. secret + disabled → warning 字段出现且含 "plaintext".
    let ack: serde_json::Value = client
        .patch(format!("{proxy_url}/api/secrets/static-s/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ack["resource"], "secret");
    assert_eq!(ack["decision"], "disabled");
    let warning = ack["warning"].as_str().unwrap_or_default();
    assert!(
        warning.contains("plaintext"),
        "warning must mention plaintext forwarding, got: {warning:?}"
    );

    // 2. 切回 default → 无 warning 字段 (旧客户端 shape).
    let ack: serde_json::Value = client
        .patch(format!("{proxy_url}/api/secrets/static-s/decision"))
        .json(&serde_json::json!({"mode": "default"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        ack.get("warning").is_none() || ack["warning"].is_null(),
        "default mode must not carry warning, got: {ack}"
    );

    // 3. provider + disabled → 无 warning (禁转发语义).
    let ack: serde_json::Value = client
        .patch(format!("{proxy_url}/api/providers/oa-main/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        ack.get("warning").is_none() || ack["warning"].is_null(),
        "provider disabled must not carry warning, got: {ack}"
    );
}

/// 辅助: 当测试未持有 ConversationDag handle 时, 通过 sync + timeline API 轮询直到
/// 出现 count 条记录 (跨所有 session 累计).
///
/// 注: 旧的实现用 `GET /api/records` (扁平分页, 已删除). 新实现走 session-aware 路径:
/// 1. 轮询 `POST /api/sync` (无 selected), 累加 sessions[*].record_count 直到 >= count.
/// 2. 对每个 session 拉 timeline, 收集 round id 作为 "record" 的代理.
///
/// 返回的 RecordSummary 仅填充 id (测试调用方主要用 id 拉详情; 其他字段留默认).
/// 需要 streamed/resp_complete 等字段的测试应改用 `wait_until_or_timeout` (持 DAG handle).
#[derive(serde::Deserialize, Debug, Default)]
#[allow(dead_code)]
struct RecordSummary {
    id: uuid::Uuid,
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    resp_status: u16,
    #[serde(default)]
    elapsed_ms: u64,
    #[serde(default)]
    streamed: bool,
    #[serde(default)]
    resp_complete: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    redactions: Vec<(String, String)>,
    #[serde(default)]
    preview: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

/// sync 响应中 session 的简化 shape (只取 record_count + session_id).
#[derive(serde::Deserialize, Debug)]
struct SyncSessionBrief {
    /// SessionId 序列化为 UUID (内层 newtype 透明序列化).
    session_id: serde_json::Value,
    record_count: usize,
}

/// sync 响应 shape (仅取 sessions 字段做轮询判定).
#[derive(serde::Deserialize, Debug)]
struct SyncResponseBrief {
    sessions: Vec<SyncSessionBrief>,
}

/// timeline page 中 round 的简化 shape (只取 id).
#[derive(serde::Deserialize, Debug)]
struct TimelineRoundBrief {
    id: uuid::Uuid,
}

/// timeline page shape (仅取 rounds 字段收集 id).
#[derive(serde::Deserialize, Debug)]
struct TimelinePageBrief {
    rounds: Vec<TimelineRoundBrief>,
}

async fn wait_for_record_count(proxy_url: &str, count: usize) -> Vec<RecordSummary> {
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        // 1. POST /api/sync 拿 sessions (含 record_count).
        let sync_url = format!("{proxy_url}/api/sync");
        let sync_resp: SyncResponseBrief = client
            .post(&sync_url)
            .json(&serde_json::json!({"expanded": [], "selected": null}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let total: usize = sync_resp.sessions.iter().map(|s| s.record_count).sum();
        if total >= count {
            // 2. 对每个 session 拉 timeline, 收集 round id.
            let mut summaries: Vec<RecordSummary> = Vec::new();
            for s in &sync_resp.sessions {
                // session_id 可能是 UUID string 或 {"SessionId": uuid} (取决于序列化);
                // SessionId 派生了 Serialize 作为 newtype, 透明序列化为内层 UUID string.
                let sid_str = match &s.session_id {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Object(map) => map
                        .values()
                        .next()
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    _ => continue,
                };
                let tl_url = format!("{proxy_url}/api/sessions/{sid_str}/timeline");
                let resp = client.get(&tl_url).send().await.unwrap();
                if !resp.status().is_success() {
                    continue;
                }
                let page: TimelinePageBrief = resp
                    .json()
                    .await
                    .unwrap_or(TimelinePageBrief { rounds: Vec::new() });
                for r in page.rounds {
                    summaries.push(RecordSummary {
                        id: r.id,
                        ..Default::default()
                    });
                }
            }
            // timeline 路径默认 limit=10, 长 session 可能截断. 总数已由 sync 确认 >= count,
            // 这里只取前 count 条 (测试调用方一般只关心 records[0]).
            summaries.truncate(count);
            return summaries;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout waiting for {count} records; current sync: {sync_resp:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ─── 额外覆盖 (针对 Code Review C1 / M2 / M4 的回归) ─────────────────────

#[tokio::test]
async fn decision_can_reenable_after_disabled() {
    // disable → default 必须能切回, 否则用户永久锁死.
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    // 1. disable.
    let resp = client
        .patch(format!("{proxy_url}/api/providers/static-p/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 2. 切回 default — 此时 effective_snapshot 看不到 static-p, 但 has_static 应当返回 true.
    let resp = client
        .patch(format!("{proxy_url}/api/providers/static-p/decision"))
        .json(&serde_json::json!({"mode": "default"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "Disabled 状态下也必须能切回 Default, 否则用户被永久锁死"
    );

    // 3. 重新出现在 list 中.
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("providers").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], "static-p");
}

#[tokio::test]
async fn delete_disabled_static_id_returns_409() {
    // 用户先 disable 了 static id, 再尝试 DELETE 应当返回 409 (而不是 404).
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    client
        .patch(format!("{proxy_url}/api/providers/static-p/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{proxy_url}/api/providers/static-p"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "disabled 状态下的 static id DELETE 应当 409, 而非 404"
    );
}

#[tokio::test]
async fn cross_table_shared_state_no_lost_update() {
    // 真正共享 persist_lock + decisions + state_path: 并发 POST provider + POST secret,
    // 期望两者最终都出现在同一份 state.toml 中.
    use secret_guard::config::Decisions;
    use secret_guard::provider::ProviderTable;
    use secret_guard::secrets::SecretTable;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("shared-state");

    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(Decisions::default()));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));

    let provider_table = ProviderTable::with_persist_lock(
        vec![],
        vec![],
        decisions.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );
    let secret_table =
        SecretTable::with_persist_lock(vec![], vec![], decisions, state_path.clone(), persist_lock);
    let proxy = base_app_state(
        reqwest::Client::new(),
        provider_table,
        ConversationDag::new(64, 500, 1),
        secret_table,
    );
    let app = server::build_router(
        proxy,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let url = format!("http://{addr}");

    // 并发发起两个 POST. client 可以 clone (Arc-backed, 共享连接池).
    let client = reqwest::Client::new();
    let c1 = client.clone();
    let c2 = client.clone();
    let url1 = url.clone();
    let url2 = url.clone();
    let (r1, r2) = tokio::join!(
        async move {
            c1.post(format!("{url1}/api/providers"))
                .json(&serde_json::json!({
                    "id": "p-concurrent",
                    "protocol": "openai",
                    "base_url": "https://api.openai.com",
                    "api_key": "k",
                }))
                .send()
                .await
                .unwrap()
        },
        async move {
            c2.post(format!("{url2}/api/secrets"))
                .json(&serde_json::json!({
                    "id": "s-concurrent",
                    "value": "some-secret-value",
                }))
                .send()
                .await
                .unwrap()
        }
    );
    assert_eq!(r1.status(), reqwest::StatusCode::CREATED);
    assert_eq!(r2.status(), reqwest::StatusCode::CREATED);

    // state.toml 应当同时包含新 provider 和新 secret.
    let state = secret_guard::config::DynamicState::load_or_empty(&state_path, "").unwrap();
    assert_eq!(state.providers.len(), 1);
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(state.providers[0].id, "p-concurrent");
    assert_eq!(state.secrets[0].id, "s-concurrent");
}

#[tokio::test]
async fn validate_value_rejects_mock_prefix() {
    // 集成层验证 C5 前提: 配置 global_mock_prefix 后, 含该 prefix 的 secret 应被拒绝.
    let proxy_url = spawn_proxy_with_prefix("sgm_").await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/api/secrets"))
        .json(&serde_json::json!({
            "id": "bad",
            "value": "sgm_abc12345",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ─── 回归守卫: 同协议 byte-exact + 跨协议 5xx 错误翻译 ──────────────────────

/// 同协议 + 无 secret (passthrough 路径) 必须保持字节级 byte-exact.
///
/// AGENTS.md 路由策略声明: same-proto + 无 redact 路径仍 byte-exact. 既有
/// `forwards_non_streaming_json` 只断言 body.contains 子串, 未做逐字节相等.
/// 本测试用包含特定空格 / 换行 / 字段顺序 / Unicode 的固定 body, 断言客户端收到的
/// 字节与上游 body 完全相等 (任何 reader → writer 重序列化路径都会破坏此不变式).
#[tokio::test]
async fn same_proto_passthrough_is_byte_exact() {
    let mut upstream = spawn_mock_upstream().await;
    // 故意使用: 字段顺序非字母序、嵌套空格、Unicode (中文/emoji)、特定换行风格.
    // 注: mockito with_body 接受 &str, 不做任何规范化.
    let upstream_body = concat!(
        "{\n",
        "  \"id\":\"chatcmpl-byte-exact\",\n",
        "  \"object\":\"chat.completion\",\n",
        "  \"created\":1700000000,\n",
        "  \"model\":\"gpt-4-byte\",\n",
        "  \"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",",
        "\"content\":\"你好 🌍 byte-exact payload with  trailing space\"},",
        "\"finish_reason\":\"stop\"}],\n",
        "  \"usage\":{\"prompt_tokens\":7,\"completion_tokens\":11,\"total_tokens\":18}\n",
        "}"
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(upstream_body)
        .create_async()
        .await;

    // 无 secret 配置 → 走 same_proto_passthrough (字节透传) 路径.
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"model":"gpt-4"}"#,
        &[],
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::OK);
    // 核心 byte-exact 断言: 客户端收到的字节必须与上游 body 逐字节相等.
    assert_eq!(
        body.as_bytes(),
        upstream_body.as_bytes(),
        "same-proto passthrough must be byte-exact; got body: {body}"
    );
}

/// 跨协议上游错误翻译矩阵: 500 / 502 / 504.
///
/// 既有 `cross_protocol_translates_upstream_error_to_ingress_envelope` 只测 429.
/// 本测试用 test_case 参数化覆盖 5xx (上游宕机 / 网关错误 / 超时), 断言错误被翻译为
/// ingress 协议 (OpenAI) 原生 envelope, 状态码透传.
#[tokio::test]
async fn cross_protocol_translates_upstream_5xx_errors() {
    for (upstream_status, expected_status) in [
        (500u16, reqwest::StatusCode::INTERNAL_SERVER_ERROR),
        (502, reqwest::StatusCode::BAD_GATEWAY),
        (504, reqwest::StatusCode::GATEWAY_TIMEOUT),
    ] {
        let mut upstream = spawn_mock_upstream().await;
        let _m = upstream
            .mock("POST", "/v1/messages")
            .with_status(upstream_status as usize)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"error":{{"type":"server_error","message":"upstream returned {upstream_status}"}}}}"#
            ))
            .create_async()
            .await;
        let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
        let proxy_url = spawn_proxy_with_provider(provider).await;
        // OpenAI ingress → Anthropic upstream (跨协议路径).
        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#;
        let (status, resp_body, _) = proxy_request(
            &proxy_url,
            "POST",
            "/o/an-main/v1/chat/completions",
            body,
            &[],
        )
        .await;
        assert_eq!(
            status, expected_status,
            "status code should pass through for upstream {upstream_status}"
        );
        // 翻译为 OpenAI 风格 envelope (content-type json + 含 error.message).
        assert!(
            resp_body.contains("upstream returned"),
            "ingress envelope should contain upstream error message; got: {resp_body}"
        );
        // 不应泄漏 Anthropic 风格字段 (如顶层 "type" 而非嵌套 error.type 是 anthropic shape).
        assert!(
            resp_body.contains("\"error\""),
            "OpenAI ingress envelope must have top-level error object; got: {resp_body}"
        );
    }
}

// ─── 已知限制回归 / 契约补强 ───────────────────────────────────────────────
//
// 本节针对 AGENTS.md "已知限制 (MVP)" 章节中明确登记的降级行为,
// 以及关键契约 (response header / 路由完整性) 补强回归测试,
// 防止后续重构无意中让降级进一步恶化为真实 secret 泄漏.

/// 已知限制回归: 流式 + Redact + 上游非 2xx 错误时, secret-guard 走 fallback 原样返回路径
/// (无 restore), 客户端可能看到 mock.
///
/// 详见 AGENTS.md "已知限制":
///   "流式 + Redact + 非 2xx 上游错误: SSE 错误流不是单个 JSON, parse 失败时 fallback
///    原样返回 (无 restore), 客户端可能看到 mock."
///
/// 触发路径 (`src/proxy.rs::same_proto_forward`):
///   1. 客户端发 `stream:true` 请求, body 含 real_secret.
///   2. redact 把 real_secret 替换为 mock, 上游收到的 body 只含 mock.
///   3. 上游返回 `Content-Type: text/event-stream` + 非 2xx (这里用 500),
///      body 是 SSE 错误事件 (不是单个 JSON), 内含上游"看到"的 mock.
///   4. `same_proto_forward` 判断 `streamed && resp_status.is_success()` 为 false →
///      进入 `fan_out_buffered_ir`.
///   5. `fan_out_buffered_ir` 用 `serde_json::from_slice` 解析 SSE body 失败 →
///      fallback 到原样透传 (无 restore).
///
/// **本测试锁定的核心不变量**: 即使在 fallback 降级路径, real_secret 也绝不能流出
/// (因为请求侧已 redact, 上游从未收到 real_secret, 自然无法在响应里 echo 它).
/// mock 出现在客户端是已知降级 (改善 restore 覆盖后, 应把 mock 断言换成 real_secret 断言).
#[tokio::test]
async fn streaming_redact_upstream_error_known_limitation_locked() {
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 上游返回 SSE 风格的错误事件 (OpenAI 真实上游在流内出错时的常见形态),
    // 状态码 500, body 不是单个 JSON.
    let sse_error_body = format!(
        concat!(
            "data: {{\"error\":{{\"message\":\"internal error, saw {mock} in prompt\",\"type\":\"server_error\"}}}}\n\n",
            "data: [DONE]\n\n"
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(500)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_error_body)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();

    // 状态码应透传 (500).
    assert_eq!(
        status,
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "non-2xx status should pass through; body: {text}"
    );

    // ★ 关键不变量: real_secret 绝不能出现在客户端响应.
    //    上游从未收到 real_secret (已被 redact), 故即便 fallback 原样返回,
    //    响应里也不应出现 real_secret. 若此断言失败, 说明 redact 链路某处
    //    让 real_secret 流到了上游 → 这是严重 bug, 需立即修复 (而非已知限制).
    assert!(
        !text.contains(real_secret),
        "REGRESSION: real_secret leaked to client in upstream-error fallback path! got: {text}"
    );

    // 已知限制: 客户端可能看到 mock (fallback 无 restore).
    // 改善方向: 让 fan_out_buffered_ir 在 SSE body 上也能 sliding-window restore,
    // 或在 streaming + 非 2xx 路径走 StreamingRestorer. 改善后把下面断言换成
    // `assert!(text.contains(real_secret))` + `assert!(!text.contains(&expected_mock))`.
    assert!(
        text.contains(&expected_mock),
        "known limitation: mock should be visible in fallback (no restore); \
         if this fails, restore may have been improved — update this assertion to \
         require real_secret instead. got: {text}"
    );

    // 记录侧契约: req_body 必须已被 redact (LLM 视角, 不含 real_secret).
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "record req_body must not contain real_secret; got: {}",
        r.req_body
    );
}

/// RED-8 已知限制改善回归 (变体): 流式 + Redact + 上游 4xx (eg 400 bad request) 时,
/// 上游在响应 body 里 echo 了 mock. 与 500 + SSE 场景同样落入 buffered fallback,
/// 但 body 是**单个合法 JSON** + **显式 `on_fallback_restore = "restore"` opt-in**
/// (SEC-10 默认 withhold — 失败响应体正是最高概率被客户端日志采集的内容) →
/// `restore_json_leaves_fallback` 在字符串值叶子上把 mock 还原为 real.
///
/// 实现细节: codec reader 只能解析成功响应 shape (eg OpenAI `{"choices":[...]}`),
/// 无法把 `{"error":{...}}` 解析成 IrResponse, `reader.read_response` 返回 Err →
/// 走 RED-8 JSON 叶子级兜底 (而非原样返回). 与 500 + SSE 变体
/// (`streaming_redact_upstream_error_known_limitation_locked`, SSE 多帧 body
/// 兜底也失败, 仍透传) 分工锁定两分支.
#[tokio::test]
async fn streaming_redact_upstream_4xx_json_restores_mock_via_leaf_fallback() {
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 上游 400 + 单个 JSON (OpenAI 错误响应标准形态), body 含 mock.
    let err_body = format!(
        r#"{{"error":{{"message":"invalid prompt containing {mock}","type":"invalid_request_error"}}}}"#,
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(err_body)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    // RED-8 兜底 restore 是 opt-in 行为 (SEC-10 默认 withhold), 显式配置;
    // records 经 gates harness 传入, 保留 handle 供轮询 record 断言.
    let proxy_url = spawn_proxy_with_redact_gates(
        secret_guard::config::OnProbeExhausted::default(),
        secret_guard::config::OnUnsupportedProtocol::default(),
        secret_guard::config::OnFallbackRestore::Restore,
        vec![provider],
        secrets,
        reqwest::Client::new(),
        "sg-state-r8-restore-4xx",
        records,
    )
    .await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret}"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();

    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    // RED-8: 单 JSON error envelope 的 mock 已被兜底还原 — 客户端看到自己拥有的
    // real secret (而非 mock 逃逸). real 出现在客户端响应来自本地 RedactionMap,
    // 不是上游 echo (上游从未收到 real, 由下方 req_body 断言守卫).
    assert!(
        text.contains(real_secret),
        "RED-8: mock in JSON error envelope must be restored to real; got: {text}"
    );
    assert!(
        !text.contains(&expected_mock),
        "RED-8: no mock should escape to client; got: {text}"
    );
    // 可观测: restored-via-fallback WARN.
    let log_text = log.text();
    assert!(
        log_text.contains("mocks restored via JSON leaf fallback"),
        "RED-8 violation: fallback restore WARN missing; log: {log_text}"
    );
    assert!(
        !log_text.contains(real_secret),
        "WARN must not leak real secret; log: {log_text}"
    );

    // 记录侧契约: req_body 必须已被 redact (LLM 视角, 不含 real_secret) —
    // real 流向上游的方向性泄漏仍由这条守卫.
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "record req_body must not contain real_secret; got: {}",
        r.req_body
    );
}

// ─── Cache-Control: no-store 契约 ──────────────────────────────────────────
//
// web/api.rs 文件头声明: "所有响应都带 Cache-Control: no-store, 避免浏览器对自动刷新
// 返回缓存内容." 该契约在 Web API + auth handler 路径上由 `NO_STORE` 常量统一注入.
// Proxy 转发路径 (`/{o|a|g|l}/{name}/*`) 当前 *不* 注入此 header (透传上游 header),
// 这是当前实现的事实行为 — 本测试分别覆盖两条路径, 锁定各自契约.

/// Web API 路径 (`/api/*`) 必须带 `Cache-Control: no-store` (防浏览器缓存).
#[tokio::test]
async fn web_api_responses_include_cache_control_no_store_header() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    // 用 /api/sessions 端点 (旧的 /api/records 扁平分页已删除, 由 sync API 替代).
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/api/sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let cc = resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .expect("Web API response must have Cache-Control header")
        .to_str()
        .unwrap();
    assert!(
        cc.contains("no-store"),
        "Cache-Control should contain 'no-store', got: {cc}"
    );
}

/// 多个 Web API 端点都注入 no-store (回归 sample, 不是只 records 端点).
#[tokio::test]
async fn web_api_cache_control_no_store_header_on_multiple_endpoints() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let client = reqwest::Client::new();

    for path in ["/api/providers", "/api/secrets"] {
        let resp = client
            .get(format!("{proxy_url}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK, "path: {path}");
        let cc = resp
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .unwrap_or_else(|| panic!("missing Cache-Control on {path}"))
            .to_str()
            .unwrap();
        assert!(
            cc.contains("no-store"),
            "path {path} Cache-Control should contain 'no-store', got: {cc}"
        );
    }
}

// ─── Gemini / Ollama 同协议透传 placeholder ─────────────────────────────────
//
// AGENTS.md 路由表声明 `g`=Gemini, `l`=oLLama 是一等公民, 但 codec 层尚未实现
// Reader/Writer. 当前同协议 + 无 secret 走字节透传 (`same_proto_passthrough`),
// 同协议 + 有 secret 因 codec 缺失会 fallback 到字节透传 (warn, 不 redact).
//
// 这两个 placeholder 测试用 `#[ignore]` 标注, 待 Gemini/Ollama codec 实现后取消 ignore
// 即可有正向透传守护. 当前它们以"无 secret 字节透传"形态运行, 验证 g/l 路由可达.

/// Gemini 同协议透传 (字节级). 待 Gemini codec 实现后, 此测试应扩展为
/// IR 路径 + redact round-trip (取消 ignore 并补强断言).
#[tokio::test]
#[ignore = "待 Gemini codec 实现: 当前仅验证 g/ 路由可达, codec 接入后补 redact 断言"]
async fn gemini_same_proto_passthrough() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1beta/models/gemini-pro:generateContent")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}"#)
        .create_async()
        .await;

    let provider = provider_with("gem-main", Protocol::Gemini, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/g/gem-main/v1beta/models/gemini-pro:generateContent",
        r#"{"contents":[{"parts":[{"text":"hello"}]}]}"#,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert!(
        body.contains("hi"),
        "Gemini passthrough body mismatch: {body}"
    );
}

/// Ollama 同协议透传 (字节级). 待 Ollama codec 实现后扩展为 IR 路径.
#[tokio::test]
#[ignore = "待 Ollama codec 实现: 当前仅验证 l/ 路由可达, codec 接入后补 redact 断言"]
async fn ollama_same_proto_passthrough() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/api/chat")
        .with_status(200)
        .with_header("content-type", "application/x-ndjson")
        .with_body(
            "{\"model\":\"llama3\",\"created_at\":\"\",\"message\":{\"role\":\"assistant\",\"content\":\"hi\"},\"done\":false}\n{\"done\":true}\n",
        )
        .create_async()
        .await;

    let provider = provider_with("ollama-main", Protocol::Ollama, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/l/ollama-main/api/chat",
        r#"{"model":"llama3","messages":[{"role":"user","content":"hello"}]}"#,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert!(
        body.contains("\"role\":\"assistant\""),
        "Ollama passthrough body mismatch: {body}"
    );
}

// ─── 并发转发请求 (DAG 写入并发) ─────────────────────────────────────────────
//
// 现有 `cross_table_shared_state_no_lost_update` 只测配置写入并发 (POST provider + POST secret).
// 本节补一条转发请求并发测试: 多个 HTTP 转发同时写入 DAG, 验证 record 数 == 请求数
// (DAG 的内部锁不会丢节点).

/// 并发发起 10 个转发请求, 验证 DAG 最终累积 10 条完整 record.
#[tokio::test]
async fn concurrent_forward_requests_all_recorded() {
    let mut upstream = spawn_mock_upstream().await;
    // mockito 同一 path 的多次匹配默认串行匹配; 用 Matcher::Any 接住所有 POST.
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{}")
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let client = reqwest::Client::new();
    let url = format!("{proxy_url}/o/oa-main/v1/chat/completions");

    // 并发发起 10 个请求.
    let mut handles = Vec::new();
    for i in 0..10 {
        let c = client.clone();
        let u = url.clone();
        handles.push(tokio::spawn(async move {
            let body = format!(r#"{{"i":{i}}}"#);
            let resp = c.post(&u).body(body).send().await.unwrap();
            assert_eq!(resp.status(), reqwest::StatusCode::OK);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // 等 DAG 累积 10 条 record (每条都 resp_complete).
    let list = wait_for_record_count(&proxy_url, 10).await;
    assert_eq!(
        list.len(),
        10,
        "concurrent forwards should all be recorded; got {}",
        list.len()
    );
}

// ─── 安全回归测试 (PR: fix secret leakage in panic/log paths) ──────────────

#[tokio::test]
async fn streaming_redact_non_2xx_upstream_error_falls_back_gracefully() {
    // 锁定已知限制 (AGENTS.md "已知限制"):
    //   "流式 + Redact + 非 2xx 上游错误: SSE 错误流不是单个 JSON, parse 失败时 fallback
    //    原样返回 (无 restore), 客户端可能看到 mock."
    // 该路径是唯一会让 mock 泄露给客户端的场景. 此测试锁定当前行为 (不崩溃 + 行为可预测),
    // 让未来改动 (eg 接入 StreamTranslate 跨协议错误翻译) 有人发现.
    //
    // 不修复 mock 泄露 (那是已知限制, 需更大重构), 只确保:
    //   (a) 客户端不 panic;
    //   (b) 客户端收到上游 500 状态 + body (含 mock, 文档化的降级行为).
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 上游返回 500 + SSE 错误流 (不是单个 JSON). body 含 mock (模拟 LLM echo 了 mock).
    let sse_body = format!(
        concat!(
            "data: {{\"error\":{{\"message\":\"internal failure, saw {mock}\"}}}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(500)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64, 500, 1);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret}"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    // (a) 不 panic (resp 成功拿到). 状态透传上游 500.
    assert_eq!(resp.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    let text = resp.text().await.unwrap();
    // (b) 文档化降级行为: parse 失败 → 原样返回上游字节 (含 mock). 这是已知限制, 不是 bug.
    //     断言 mock 出现在客户端响应 (锁定当前行为); 未来若修复了 restore, 此断言需更新.
    assert!(
        text.contains(&expected_mock),
        "known limitation: client sees mock on non-2xx SSE fallback; got: {text}"
    );
}

#[tokio::test]
async fn gemini_provider_with_secrets_forwards_unredacted() {
    // 锁定**显式 fail_open opt-in** 行为 (SEC-10 翻转后旧默认成为 opt-in):
    //   Gemini/Ollama 协议 codec 未覆盖, same_proto_passthrough 字节透传, 不做 redact.
    // 用户为 Gemini provider 配置了 secret 且显式配置
    // `[redact] on_unsupported_protocol = "fail_open"` 时, secret 原样转发到上游
    // (静默失效风险). 默认 (fail_closed) 路径由
    // `gemini_secrets_fail_closed_returns_503_zero_upstream_hits` 锁定.
    // 此测试用 match_body 严格锁定: 上游 mock 收到的请求 body 含**原始 secret**.
    //
    // 未来接入 Gemini codec 后, secret 会被 redact 成 mock, 此 mock (匹配原始 secret) 不再命中,
    // 测试会失败 — 提醒维护者更新断言为 "上游收到 mock". 这是预期的演化路径.
    let real_secret = "sk-gemini-secret-DO-NOT-LEAK";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .match_body(mockito::Matcher::PartialJson(serde_json::json!({
            "contents": [{"parts": [{"text": format!("use {real_secret} now")}]}]
        })))
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let provider = provider_with("gem-main", Protocol::Gemini, &upstream.url());
    let proxy_url = spawn_proxy_with_redact_gates(
        secret_guard::config::OnProbeExhausted::default(),
        secret_guard::config::OnUnsupportedProtocol::FailOpen,
        secret_guard::config::OnFallbackRestore::default(),
        vec![provider],
        secrets,
        reqwest::Client::new(),
        "sg-state-gem-open",
        ConversationDag::new(64, 500, 1),
    )
    .await;

    // Gemini 风格请求 body 含 secret.
    let body = format!(r#"{{"contents":[{{"parts":[{{"text":"use {real_secret} now"}}]}}]}}"#);
    let resp = reqwest::Client::new()
        .post(format!(
            "{proxy_url}/g/gem-main/v1beta/models/gemini-pro:generateContent"
        ))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    // proxy 不崩溃 + 上游 mock 命中 (证明 body 含原始 secret, 未被 redact).
    // 若 mock 未命中, mockito 返回 5xx, 此断言失败.
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "Gemini passthrough must hit upstream mock (body contains real secret)"
    );
    let _ = resp.text().await.unwrap();
}

/// codec-less 协议 (gemini) + secrets 的**默认路径** (SEC-10): 默认
/// `on_unsupported_protocol = fail_closed` (2026-09 翻转, 自 FailOpen) → 503
/// 拒绝转发, 上游零请求 (停损), 错误 body 不含 secret 明文 (SEC-2).
/// 默认值本身由 config 单测 `prop_degradation_defaults_are_safe_side` 锁定.
#[tokio::test]
async fn gemini_secrets_fail_closed_returns_503_zero_upstream_hits() {
    let real_secret = "sk-gemini-secret-DO-NOT-LEAK";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .with_status(200)
        .with_body("{}")
        // 停损语义: 上游零请求 (secret 绝不出站) — expect(0) + assert_async 锁定.
        .expect(0)
        .create_async()
        .await;
    let secrets = test_secret_table_with(vec![secret("api-key", real_secret)]);
    let provider = provider_with("gem-main", Protocol::Gemini, &upstream.url());
    let proxy_url = spawn_proxy_with_redact_gates(
        secret_guard::config::OnProbeExhausted::default(),
        secret_guard::config::OnUnsupportedProtocol::default(),
        secret_guard::config::OnFallbackRestore::default(),
        vec![provider],
        secrets,
        reqwest::Client::new(),
        "sg-state-unsup",
        ConversationDag::new(64, 500, 1),
    )
    .await;

    let body = format!(r#"{{"contents":[{{"parts":[{{"text":"use {real_secret} now"}}]}}]}}"#);
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/g/gem-main/v1beta/models/gemini-pro:generateContent",
        &body,
        &[],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "fail_closed must refuse forwarding for codec-less protocol with secrets: {text}"
    );
    // SEC-2: message 只含协议名 + provider id + 出路提示, 不含 secret 明文.
    assert!(
        !text.contains(real_secret),
        "503 body must not leak secret: {text}"
    );
    assert!(
        text.contains("gemini"),
        "503 body names the protocol: {text}"
    );
    assert!(
        text.contains("gem-main"),
        "503 body names the provider id: {text}"
    );
    _m.assert_async().await;
}

/// fail_closed 只管 secret 安全性: 仅 model 重写降级 (无 secret) 的 codec-less
/// 请求在 fail_closed 下仍 WARN + 透传 (body 不改写, 与 fail_open 行为一致).
#[tokio::test]
async fn gemini_rewrite_only_fail_closed_still_passthrough() {
    let mut upstream = spawn_mock_upstream().await;
    let passthrough_body = r#"{"contents":[{"parts":[{"text":"hi"}]}]}"#;
    let _m = upstream
        .mock("POST", "/v1beta/models/gemini-pro:generateContent")
        // Gemini 的 model 在 URL path 而非 body (D2 降级 = body 原样, 无字段可改写);
        // Exact 锁定 byte-exact 透传 (mockito 对 unmatched 请求回 501, 需精确匹配).
        .match_body(mockito::Matcher::Exact(passthrough_body.to_string()))
        .with_status(200)
        .with_body("{}")
        .expect(1)
        .create_async()
        .await;
    let gem = provider_with("gem-main", Protocol::Gemini, &upstream.url());
    let router = router_provider("virt", vec![rewrite_route("*", "gem-main", "gemini-flash")]);
    let proxy_url = spawn_proxy_with_redact_gates(
        secret_guard::config::OnProbeExhausted::default(),
        secret_guard::config::OnUnsupportedProtocol::FailClosed,
        secret_guard::config::OnFallbackRestore::default(),
        vec![gem, router],
        test_secret_table(), // 空: 仅重写, 无 secret
        reqwest::Client::new(),
        "sg-state-unsup",
        ConversationDag::new(64, 500, 1),
    )
    .await;

    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/g/virt/v1beta/models/gemini-pro:generateContent",
        r#"{"contents":[{"parts":[{"text":"hi"}]}]}"#,
        &[],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "rewrite-only (no secrets) must still pass through under fail_closed: {}",
        text
    );
    // D2 降级不变: body byte-exact 未改写 — mock 的 Exact body 匹配命中即证明
    // (expect(1) 锁定恰好一次).
    _m.assert_async().await;
}

// ─── CFG-3: CRUD 操作语义 (HTTP 集成测试, property-based) ──────────────────
//
// 契约 SSOT: `docs/design/contracts.md` §6 CFG-3 (L515-527).
// 这些 property 本质是 HTTP 语义, 必须通过真实 router 验证 (axum::serve 启动完整 app).
// 选用 secrets endpoint (更核心); providers 行为对称 (都用 DynamicTable), 不重复.
//
// 复用既有 helper: `spawn_proxy_static_dynamic` (接受 static/dynamic providers + 自定义
// SecretTable). secrets 的 static/dynamic 两层通过 `SecretTable::new` 显式构造传入.

/// 启动 secret-guard, 接受任意 static + dynamic secrets (providers 为空, 不影响 secrets API).
///
/// 与 `spawn_with_static_and_dynamic` 对称: 后者装配 static/dynamic providers + 空 secrets;
/// 本 helper 装配 static/dynamic secrets + 空 providers, 用于 CFG-3 的 secrets API property.
async fn spawn_with_secrets(
    static_secrets: Vec<SecretEntry>,
    dynamic_secrets: Vec<SecretEntry>,
) -> String {
    let secret_path = tmp_state_path("cfg3-secrets");
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let secrets = SecretTable::new(static_secrets, dynamic_secrets, decisions, secret_path);
    spawn_proxy_static_dynamic(
        vec![],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        secrets,
    )
    .await
    .0
}

/// 拉取 effective secrets 列表, 返回 (id → EffectiveSecret JSON) 映射, 便于断言.
async fn fetch_effective_secrets(
    client: &reqwest::Client,
    proxy_url: &str,
) -> std::collections::HashMap<String, serde_json::Value> {
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/api/secrets"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body.get("secrets")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["id"].as_str().unwrap().to_string(), v.clone()))
        .collect()
}

mod cfg3_proptests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    // ─── 生成器 (对称复制自 src/config.rs::proptests::ConfigScenario) ─────────
    //
    // 注意: 这是 `src/config.rs::proptests` 的 ConfigScenario + arb_scenario 的**逐字对称
    // 复制** (非 use 复用), 因为该 mod 标记为 `#[cfg(test)]` 无法跨 crate (integration test)
    // 引用. 字段名 / 方法名 / 桶前缀 (`s`/`d`/`b`) / HashMap 去重逻辑全相同. **若改动其中一处,
    // 必须同步另一处以保持一致** (隐性重复已升级为显式约定).
    //
    // 三桶分桶 (static_only / dynamic_only / both) 保证三种语义 (conflict / static-only /
    // dynamic-only) 都被每条 property 触达, 不依赖 id 碰撞概率. 桶前缀 `s`/`d`/`b` 互斥.
    //
    // value 用 `[a-z0-9]{4,16}`: ≥3 字节 (过 validate_value), 纯 ASCII (无 PUA),
    // 无 mock prefix (集成测试 global_mock_prefix 为空). id 用 `[a-z][a-z0-9]{0,3}` (过 validate_id).

    fn arb_value() -> impl Strategy<Value = String> {
        "[a-z0-9]{4,16}"
    }

    #[derive(Debug, Clone)]
    struct Scenario {
        static_only: Vec<(String, String)>,
        dynamic_only: Vec<(String, String)>,
        // both: (id, static_value, dynamic_value) — static_value ≠ dynamic_value 保证 conflict 可观测.
        both: Vec<(String, String, String)>,
    }

    impl Scenario {
        fn static_entries(&self) -> Vec<SecretEntry> {
            self.static_only
                .iter()
                .map(|(id, v)| secret(id, v))
                .chain(self.both.iter().map(|(id, sv, _)| secret(id, sv)))
                .collect()
        }
        fn dynamic_entries(&self) -> Vec<SecretEntry> {
            self.dynamic_only
                .iter()
                .map(|(id, v)| secret(id, v))
                .chain(self.both.iter().map(|(id, _, dv)| secret(id, dv)))
                .collect()
        }
        /// 所有 static id (static_only + both), 供 property 挑冲突目标.
        fn static_ids(&self) -> Vec<String> {
            self.static_only
                .iter()
                .map(|(id, _)| id.clone())
                .chain(self.both.iter().map(|(id, _, _)| id.clone()))
                .collect()
        }
    }

    fn arb_scenario() -> impl Strategy<Value = Scenario> {
        (
            prop::collection::vec(("[a-z][a-z0-9]{0,3}", arb_value()), 1..4),
            prop::collection::vec(("[a-z][a-z0-9]{0,3}", arb_value()), 1..4),
            prop::collection::vec(("[a-z][a-z0-9]{0,3}", arb_value(), arb_value()), 1..4),
        )
            .prop_map(|(static_only, dynamic_only, both)| {
                let static_only: Vec<(String, String)> = static_only
                    .into_iter()
                    .map(|(id, v)| (format!("s{id}"), v))
                    .collect::<HashMap<_, _>>()
                    .into_iter()
                    .collect();
                let dynamic_only: Vec<(String, String)> = dynamic_only
                    .into_iter()
                    .map(|(id, v)| (format!("d{id}"), v))
                    .collect::<HashMap<_, _>>()
                    .into_iter()
                    .collect();
                let mut both_map: HashMap<String, (String, String)> = HashMap::new();
                for (id, sv, dv) in both {
                    both_map.insert(format!("b{id}"), (sv, dv));
                }
                let both: Vec<(String, String, String)> = both_map
                    .into_iter()
                    .map(|(id, (sv, dv))| {
                        let dv = if sv == dv { format!("dyn-{dv}") } else { dv };
                        (id, sv, dv)
                    })
                    .collect();
                Scenario {
                    static_only,
                    dynamic_only,
                    both,
                }
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// CFG-3: POST 创建与 static 冲突的 id → 409.
        ///
        /// 任挑一个 static id (static_only 或 both 桶), POST 同 id 创建 → 必须返回 409
        /// (契约: "id 与 static 冲突 → 409", 提示用 PUT 走 fork 流程).
        /// scenario 保证 static_ids() 非空 (两桶均 ≥1), 无需 prop_assume.
        ///
        /// proptest! 生成同步 fn, 内部用 block_on 驱动 async HTTP 调用.
        #[test]
        fn prop_post_conflict_with_static_returns_409(
            scenario in arb_scenario(),
            // 额外的 dynamic-only id 用作 negative control: POST 一个全新 id 应当成功 (201).
            fresh_id in "[a-z][a-z0-9]{3,6}"
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let proxy_url = spawn_with_secrets(
                    scenario.static_entries(),
                    scenario.dynamic_entries(),
                ).await;
                let client = reqwest::Client::new();

                // ── 正向: POST 任一 static id → 409 ──
                // arb_scenario 保证 static_ids() ≥1 (两桶均 ≥1).
                for sid in scenario.static_ids() {
                    let resp = client
                        .post(format!("{proxy_url}/api/secrets"))
                        .json(&serde_json::json!({
                            "id": sid,
                            "value": format!("attempt-{sid}"),
                        }))
                        .send().await.unwrap();
                    prop_assert_eq!(
                        resp.status(), reqwest::StatusCode::CONFLICT,
                        "POST with static-conflicting id '{}' must return 409", sid
                    );
                }

                // ── negative control: POST 全新 dynamic-only id → 201 (验证 409 不是误报) ──
                // fresh_id 前缀 `f` 避开三桶 (`s`/`d`/`b`) 前缀, 保证不冲突.
                let fresh = format!("f{fresh_id}");
                let resp = client
                    .post(format!("{proxy_url}/api/secrets"))
                    .json(&serde_json::json!({
                        "id": &fresh,
                        "value": "fresh-new-value",
                    }))
                    .send().await.unwrap();
                prop_assert_eq!(
                    resp.status(), reqwest::StatusCode::CREATED,
                    "POST with non-conflicting id must succeed (201), got {}",
                    resp.status()
                );
                Ok(())
            })?
        }

        /// CFG-3: PUT 编辑 static id → 创建 dynamic override (git-style fork).
        ///
        /// 任挑一个 static-only id (无 dynamic), PUT 新 value → 必须返回 200, 且:
        /// 1) effective 中该 id 的 source 变为 `dynamic_override`;
        /// 2) value_length 反映新值 (旧 static 被 override).
        /// scenario 保证 static_only 桶 ≥1.
        ///
        /// **对称性说明**: 本测试只挑 static_only 桶的**首个** id 验证 fork 行为, 但 PUT-on-static
        /// 的 fork 语义对**所有** static id (含 both 桶里 static 已被 dynamic override 的) 对称成立
        /// (handler 无 per-id 特判, 任一 static id PUT 都走同一 upsert_dynamic 路径). 故测首个即
        /// 代表 static id 集合的行为正确性, 不重复枚举 (case 数有限时聚焦 representative case).
        #[test]
        fn prop_put_forks_dynamic_when_id_in_static(scenario in arb_scenario()) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let proxy_url = spawn_with_secrets(scenario.static_only.iter()
                    .map(|(id, v)| secret(id, v)).collect(), vec![]).await;
                let client = reqwest::Client::new();

                // arb_scenario 保证 static_only ≥1 项.
                let (target_id, old_value) = scenario.static_only.first().unwrap().clone();
                let new_value = format!("forked-{old_value}-new");
                let new_len = new_value.chars().count();

                let resp = client
                    .put(format!("{proxy_url}/api/secrets/{target_id}"))
                    .json(&serde_json::json!({
                        "value": &new_value,
                    }))
                    .send().await.unwrap();
                prop_assert_eq!(resp.status(), reqwest::StatusCode::OK,
                    "PUT on static id must succeed (fork dynamic override)");

                let updated: serde_json::Value = resp.json().await.unwrap();
                prop_assert_eq!(&updated["source"], &"dynamic_override",
                    "forked id source must be dynamic_override");
                prop_assert_eq!(&updated["value_length"], &new_len,
                    "forked value_length must reflect new (overridden) value");

                // 列表中也应反映 fork.
                let eff = fetch_effective_secrets(&client, &proxy_url).await;
                let forked = eff.get(&target_id).expect("forked id must remain in effective");
                prop_assert_eq!(&forked["source"], &"dynamic_override");
                prop_assert_eq!(&forked["value_length"], &new_len);
                Ok(())
            })?
        }

        /// CFG-3: DELETE 仅作用于 dynamic-only item, static 基线存在 → 409 (#156).
        ///
        /// scenario 提供三类 id:
        /// 1) static-only id (无 dynamic): DELETE 必须返回 409 (static 基线存在).
        /// 2) dynamic-only id (无 static): DELETE 必须返回 204, 且从 effective 消失.
        /// 3) both id (static + dynamic override): DELETE 必须返回 **409** (#156 三态收紧:
        ///    旧 "204 删 override 露出 static" 语义误导用户以为删除成功, 已废除;
        ///    撤销 override 走 decision, 不走 DELETE).
        /// scenario 保证三桶均 ≥1.
        #[test]
        fn prop_delete_static_baseline_rejected(scenario in arb_scenario()) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let proxy_url = spawn_with_secrets(
                    scenario.static_entries(),
                    scenario.dynamic_entries(),
                ).await;
                let client = reqwest::Client::new();

                // ── static-only id → 409 ──
                // arb_scenario 保证 static_only ≥1.
                let static_id = scenario.static_only.first().unwrap().0.clone();
                let resp = client
                    .delete(format!("{proxy_url}/api/secrets/{static_id}"))
                    .send().await.unwrap();
                prop_assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT,
                    "DELETE on static-only id must return 409");

                // ── dynamic-only id → 204 + 从 effective 消失 ──
                // arb_scenario 保证 dynamic_only ≥1.
                let dyn_id = scenario.dynamic_only.first().unwrap().0.clone();
                let resp = client
                    .delete(format!("{proxy_url}/api/secrets/{dyn_id}"))
                    .send().await.unwrap();
                prop_assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT,
                    "DELETE on dynamic-only id must return 204");
                let eff = fetch_effective_secrets(&client, &proxy_url).await;
                prop_assert!(!eff.contains_key(&dyn_id),
                    "deleted dynamic-only id must disappear from effective");

                // ── both id (static + dynamic override) → 409 + override 未被删除 ──
                // arb_scenario 保证 both ≥1 (static + dynamic override 都存在).
                let (both_id, _sv, dv) = scenario.both.first().unwrap().clone();
                let dv_len = dv.chars().count();
                let resp = client
                    .delete(format!("{proxy_url}/api/secrets/{both_id}"))
                    .send().await.unwrap();
                prop_assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT,
                    "DELETE on both id must return 409 (static baseline present, #156)");
                let eff = fetch_effective_secrets(&client, &proxy_url).await;
                let kept = eff.get(&both_id)
                    .expect("both id must remain in effective (DELETE rejected, override kept)");
                prop_assert_eq!(&kept["source"], &"dynamic_override",
                    "both id source must stay dynamic_override (override must NOT be silently dropped)");
                prop_assert_eq!(&kept["value_length"], &dv_len,
                    "both id value_length must still reflect the dynamic override");
                Ok(())
            })?
        }

        /// CFG-3: PATCH decision 正确切换 OverrideMode.
        ///
        /// 对 conflict id (both 桶: static + dynamic 都有), PATCH 三种 mode 分别:
        ///  - default       → effective 取 dynamic, source=dynamic_override, decision=default
        ///  - prefer_static → effective 取 static,  source=static_preferred, decision=prefer_static
        ///  - disabled      → effective 中消失 (但 has_static 仍 true, 切回 default 可恢复)
        /// scenario 保证 both 桶 ≥1 (有 conflict id 可切换).
        #[test]
        fn prop_patch_decision_toggles_override_mode(scenario in arb_scenario()) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let proxy_url = spawn_with_secrets(
                    scenario.static_entries(),
                    scenario.dynamic_entries(),
                ).await;
                let client = reqwest::Client::new();

                // arb_scenario 保证 both ≥1 (conflict id 可切换).
                let (target_id, sv, dv) = scenario.both.first().unwrap().clone();
                let sv_len = sv.chars().count();
                let dv_len = dv.chars().count();

                // ── default: dynamic 胜出 ──
                let resp = client
                    .patch(format!("{proxy_url}/api/secrets/{target_id}/decision"))
                    .json(&serde_json::json!({"mode": "default"}))
                    .send().await.unwrap();
                prop_assert_eq!(resp.status(), reqwest::StatusCode::OK, "PATCH default must succeed");
                let ack: serde_json::Value = resp.json().await.unwrap();
                prop_assert_eq!(&ack["decision"], &"default");
                let eff = fetch_effective_secrets(&client, &proxy_url).await;
                let e = eff.get(&target_id).expect("default mode: id must be effective");
                prop_assert_eq!(&e["source"], &"dynamic_override");
                prop_assert_eq!(&e["decision"], &"default");
                prop_assert_eq!(&e["value_length"], &dv_len, "default: dynamic value wins");

                // ── prefer_static: static 强制 ──
                let resp = client
                    .patch(format!("{proxy_url}/api/secrets/{target_id}/decision"))
                    .json(&serde_json::json!({"mode": "prefer_static"}))
                    .send().await.unwrap();
                prop_assert_eq!(resp.status(), reqwest::StatusCode::OK, "PATCH prefer_static must succeed");
                let eff = fetch_effective_secrets(&client, &proxy_url).await;
                let e = eff.get(&target_id).expect("prefer_static mode: id must be effective");
                prop_assert_eq!(&e["source"], &"static_preferred");
                prop_assert_eq!(&e["decision"], &"prefer_static");
                prop_assert_eq!(&e["value_length"], &sv_len, "prefer_static: static value forced");

                // ── disabled: 从 effective 消失 ──
                let resp = client
                    .patch(format!("{proxy_url}/api/secrets/{target_id}/decision"))
                    .json(&serde_json::json!({"mode": "disabled"}))
                    .send().await.unwrap();
                prop_assert_eq!(resp.status(), reqwest::StatusCode::OK, "PATCH disabled must succeed");
                let eff = fetch_effective_secrets(&client, &proxy_url).await;
                prop_assert!(!eff.contains_key(&target_id),
                    "disabled mode: id must disappear from effective");

                // ── 切回 default: 必须能恢复 (回归守卫, 防 "disabled 永久锁死") ──
                let resp = client
                    .patch(format!("{proxy_url}/api/secrets/{target_id}/decision"))
                    .json(&serde_json::json!({"mode": "default"}))
                    .send().await.unwrap();
                prop_assert_eq!(resp.status(), reqwest::StatusCode::OK,
                    "PATCH back to default after disabled must succeed (no permanent lockout)");
                let eff = fetch_effective_secrets(&client, &proxy_url).await;
                let e = eff.get(&target_id).expect("default restore: id must reappear");
                prop_assert_eq!(&e["source"], &"dynamic_override");
                prop_assert_eq!(&e["value_length"], &dv_len, "restored default: dynamic value wins again");
                Ok(())
            })?
        }
    }
}

// ─── SEC-6: 内部 URL 不外泄 (/api/* 未匹配 → 404, 不转发) ───────────────
//
// 契约 (docs/design/contracts.md §7 SEC-6): `/api/*` 未匹配的子路径返回 404,
// 绝不进入 forward. 这是安全不变量 — 防止 `/api/unknown` 这类内部路径被误当成
// provider 转发到上游 (泄露请求细节 / 触发意外上游调用).
//
// 用 proptest 参数化 unknown 子路径的变体 (单段 / 多段 / 带 query string),
// 确保所有未匹配的 `/api/*` 形态都走 404 + 不转发.

mod sec6_proptests {
    use proptest::prelude::*;

    /// 发起一次 GET 请求, 返回 (status, body).
    async fn get(proxy_url: &str, path: &str) -> (reqwest::StatusCode, String) {
        let resp = reqwest::Client::new()
            .get(format!("{proxy_url}{path}"))
            .send()
            .await
            .expect("request must complete");
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        (status, body)
    }

    proptest! {
        /// SEC-6: 任意 `/api/<unknown>` 子路径 → 404, 且上游收到 0 个请求.
        ///
        /// 生成器: 随机化 unknown 段 (1-3 段, 字符集 [a-z0-9]) + 可选 query string,
        /// 覆盖单段 (`/api/foo`) / 多段 (`/api/foo/bar`) / 带 query (`/api/foo?x=1`)
        /// 三种形态. 关键: 即便上游 mock 配置成接受 ANY method/ANY path, 也不应被命中.
        ///
        /// **范围限定**: 已注册的 `/api/*` 子路由首段为 records / sessions / sync /
        /// secrets / providers / api-keys / me. 用 prop_assume 跳过这些 seg1
        /// (会命中已注册 handler 或其 deeper 404, 不是本 property 的转发守卫场景).
        ///
        /// 异步 + proptest 协作: async 块返回 Result<(), TestCaseError>, prop_assert_eq!
        /// 用 `return Err(...)` 短路; block_on 的结果 expect 把 TestCaseError 转为 panic
        /// (proptest 捕获 panic 视为 case 失败).
        #[test]
        fn prop_internal_url_404_no_forward(
            seg1 in "[a-z0-9-]{1,8}",
            extra_segs in prop::collection::vec("[a-z0-9]{1,6}", 0..3),
            with_query in any::<bool>(),
        ) {
            // 跳过会命中已注册 /api/* handler 的路径 (那些不是 404 no-forward 场景;
            // 已注册路由的 deeper unknown 由各资源组的单元/集成测试守卫).
            let registered = [
                "records", "sessions", "sync", "secrets", "providers", "api-keys", "me",
            ];
            prop_assume!(
                !registered.contains(&seg1.as_str()),
                "seg1 would hit a registered /api/* route"
            );
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            let result: Result<(), proptest::test_runner::TestCaseError> = rt.block_on(async {
                let mut upstream = super::spawn_mock_upstream().await;
                // 上游 mock: 匹配 ANY method/ANY path, expect(0) 表示期望零命中
                // (命中即说明转发发生了 = 违约). 用 .expect(0) + .assert_async() 守卫.
                let mock = upstream
                    .mock(reqwest::Method::GET.as_str(), mockito::Matcher::Any)
                    .expect(0)
                    .with_status(200)
                    .with_body("{}")
                    .create_async()
                    .await;

                let proxy_url = super::spawn_proxy(&upstream.url()).await;

                // 构造 unknown 路径: /api/<seg1>[/seg2/...][?query]
                let mut path = format!("/api/{seg1}");
                for s in &extra_segs {
                    path.push('/');
                    path.push_str(s);
                }
                if with_query {
                    path.push_str("?x=1");
                }

                let (status, _body) = get(&proxy_url, &path).await;
                prop_assert_eq!(
                    status,
                    reqwest::StatusCode::NOT_FOUND,
                    "SEC-6 violation: /api/* unknown subpath must return 404, got {} for path {}",
                    status, path
                );

                // 核心: 上游 mock 不应被命中 (未转发). expect(0) + assert_async 验证零命中.
                // assert_async 在命中数 ≠ 0 时 panic (非 TestCaseError, 但违约即 panic 合理).
                mock.assert_async().await;
                Ok(())
            });
            // 把 async 块返回的 TestCaseError 转为 panic (proptest 捕获 = case 失败).
            result.expect("SEC-6 proptest case failed");
        }
    }
}

/// #163: 上游不可达 502 body 的 message 必须携带可读原因 (上游 host:port + 根因),
/// 让 SDK 用户区分网关故障 vs 上游故障; 且不得携带 provider api_key.
/// #160 (交叉): 错误终态 (502) 也必须有 forward 摘要行 (不只成功路径).
#[tokio::test]
async fn upstream_unreachable_502_body_carries_readable_cause() {
    let dummy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = dummy_listener.local_addr().unwrap();
    drop(dummy_listener);

    // provider 带非空 api_key: 断言它不出现在 502 body (issue 明确要求).
    let mut provider = openai_provider("oa-dead", &format!("http://{bad_addr}"));
    if let ProviderKind::Direct(d) = &mut provider.kind {
        d.api_key = "sk-live-supersecret-0123456789".into();
    }
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (log, _log_guard) = capture_tracing(tracing::Level::INFO);
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-dead/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);

    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "upstream_error", "body kind: {body}");
    let msg = v["message"]
        .as_str()
        .expect("502 body message must be a non-null string (#163)");
    // 可读原因: 根因 (连接拒绝) + 上游定位 (host:port).
    // (io 错误文案大小写随平台, 断言用小写不敏感.)
    assert!(
        msg.to_lowercase().contains("connection refused"),
        "message must carry the underlying cause, got: {msg}"
    );
    assert!(
        msg.contains(&bad_addr.to_string()),
        "message must name the upstream host:port for diagnosis, got: {msg}"
    );
    // 卫生: provider api_key 不得泄漏进错误 body.
    assert!(
        !body.contains("sk-live-supersecret"),
        "502 body must not leak provider api_key: {body}"
    );

    // #160 交叉: 错误终态 (上游不可达 502) 也有 forward 摘要行.
    let log_text = log.text();
    assert!(
        log_text.lines().any(|l| l.contains("forward")
            && l.contains("method=POST")
            && l.contains("path=/o/oa-dead/v1/chat/completions")
            && l.contains("status=502")
            && l.contains("provider=oa-dead")
            && l.contains("complete=false")),
        "#160: error-terminal forward summary missing; log: {log_text}"
    );
}

/// #160: 成功转发完成时打一行 INFO 摘要 (method/path/status/redactions/provider).
#[tokio::test]
async fn forward_completion_logs_info_summary() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}"#,
        )
        .create_async()
        .await;

    // 带 secret → redact 路径 (redactions=1), 走 fan_out_buffered_ir 完成点.
    let real_secret = "sk-summary-secret-456";
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        secrets,
    )
    .await;

    let (log, _log_guard) = capture_tracing(tracing::Level::INFO);
    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"use {real_secret}"}}]}}"#
    );
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        &body,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    // 摘要行存在且含关键字段 (结构化字段经 fmt 展开为 key=value 形态).
    let log_text = log.text();
    let summary_line = log_text
        .lines()
        .find(|l| l.contains("forward") && l.contains("method=POST"))
        .unwrap_or_else(|| panic!("#160 violation: no forward summary line; log: {log_text}"));
    for field in [
        "method=POST",
        "path=/o/oa-main/v1/chat/completions",
        "status=200",
        "provider=oa-main",
    ] {
        assert!(
            summary_line.contains(field),
            "#160: summary line missing {field}; got: {summary_line}"
        );
    }
    assert!(
        summary_line.contains("redactions=1"),
        "#160: redactions count missing/wrong; got: {summary_line}"
    );
    assert!(
        summary_line.contains("elapsed_ms="),
        "#160: elapsed_ms missing; got: {summary_line}"
    );
    // 卫生: 摘要不泄漏 secret.
    assert!(
        !summary_line.contains(real_secret),
        "#160: summary must not leak secret; got: {summary_line}"
    );
}

/// #160 补充: 流式请求的摘要日志在流结束时打 (而非响应头到达时) —
/// elapsed 覆盖完整流, 客户端拿完所有 chunk 后才出现摘要行.
#[tokio::test]
async fn forward_summary_for_streaming_logs_after_stream_end() {
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;

    // 无 secret → passthrough 路径 (fan_out_streaming 完成点).
    let proxy_url = spawn_proxy(&upstream.url()).await;

    let (log, _log_guard) = capture_tracing(tracing::Level::INFO);
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"model":"gpt-4","stream":true}"#,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(text.contains("[DONE]"));

    // 客户端消费完整流之后, 摘要行应已出现 (流式路径的 record 完成点在流末).
    let log_text = log.text();
    assert!(
        log_text.lines().any(|l| l.contains("forward")
            && l.contains("method=POST")
            && l.contains("streamed=true")),
        "#160: streaming forward summary missing or lacks streamed=true; log: {log_text}"
    );
}

// ─── 转发链可观测性 (#158 / #160 / #162 / #163) ────────────────────────────
//
// 四条可观测性增强的集成锁定. 日志断言设施 (`capture_tracing` / `CaptureLog`)

/// #158: 请求 stream=true + 配置 secret, 上游回 200 + Content-Type: application/json
/// (body 为 SSE 形态含 mock) → mock 不被 restore (行为不变, 已知限制), 但必须打 WARN.
#[tokio::test]
async fn stream_request_with_non_sse_upstream_warns_mock_not_restored() {
    let real_secret = "sk-live-zzz123456789";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // MRE (issue #158): 上游对 stream=true 回 application/json + SSE 格式 body
    // (delta content 回显 mock, 模拟 LLM echo 了 redact 后的请求内容).
    let sse_body = format!(
        concat!(
            "data: {{\"choices\": [{{\"delta\": {{\"content\": \"saw {mock}\"}}}}]}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(sse_body.clone())
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let records = ConversationDag::new(64, 500, 1);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url =
        spawn_proxy_full(vec![provider], reqwest::Client::new(), records, secrets).await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"keep {real_secret}"}}]}}"#
    );
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        &body,
        &[("content-type", "application/json")],
    )
    .await;

    // (i) 行为不变: 200 + 原样透传 (mock 可见 — 已知限制, 本 issue 只加日志).
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        text, sse_body,
        "fallback path must pass body through verbatim"
    );

    // (ii) WARN 被捕获: 逃逸点 (fan_out_buffered_ir parse 失败) + 上游信号
    // (same_proto 判型) 至少一处. 断言核心文案 + 可定位字段.
    let log_text = log.text();
    assert!(
        log_text.contains("mock not restored"),
        "#158 violation: no WARN about mock not restored; log: {log_text}"
    );
    assert!(
        log_text.contains("non-SSE content-type"),
        "#158: upstream-side signal (non-SSE content-type for stream=true) missing; log: {log_text}"
    );
    // 可定位: 逃逸点 WARN 行本身必须带 record_id 字段 (行级断言, 防 warn! 漏带).
    let warn_line = log_text
        .lines()
        .find(|l| l.contains("mock not restored"))
        .expect("#158: WARN line must exist (checked above)");
    assert!(
        warn_line.contains("record_id="),
        "#158: WARN lacks record_id for locating; got: {warn_line}"
    );
    // 卫生: 日志不得含真实 secret.
    assert!(
        !log_text.contains(real_secret),
        "#158: WARN must not leak real secret; log: {log_text}"
    );

    // record 侧: streamed=false (content-type 判型结果), 行为与 issue 描述一致.
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    assert!(
        !list[0].streamed,
        "non-SSE content-type must record streamed=false"
    );
}

// ─── RED-8: JSON 叶子级 restore 兜底 (parse-失败 fallback 不让 mock 逃逸) ────
//
// codec 无法 parse 上游响应时 (reader 拒绝 / 非 JSON body), fan_out_buffered_ir 与
// cross_proto_forward 的 fallback 分支按 `[redact] on_fallback_restore` 分流
// (SEC-10 降级偏安全): 默认 withhold 保留 Mock 透传; 显式 `restore` opt-in 时先
// 尝试 restore_json_leaves_fallback — body 仍是合法 JSON 的场景下, mock 在字符串
// 值叶子被还原, 客户端拿到 real.

/// 同协议 + secret 命中 + 非流式 + 上游 200 但响应 JSON 无法被 codec reader 解析
/// (choices 类型错配) 且含 mock + **默认配置** (on_fallback_restore = withhold,
/// SEC-10) → 保留 Mock 透传: 客户端 body 含 mock 不含 real + mock-not-restored
/// WARN (detail 含 opt-in 提示). 失败响应体高概率被客户端日志采集, 默认不把
/// real 还原进去.
#[tokio::test]
async fn reader_reject_withholds_real_secret_by_default_same_proto() {
    let real_secret = "sk-live-wh1234567890";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // reader 拒绝形态: `choices` 是 string (openai reader 要求 array 且非空) —
    // 合法 JSON 但非协议 shape; echo 字段携带 mock (模拟 LLM 回响 redacted 内容).
    let upstream_body = format!(r#"{{"choices":"wrongtype","echo":"saw {expected_mock} end"}}"#);
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(upstream_body.clone())
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let provider = openai_provider("oa-main", &upstream.url());
    // spawn_proxy_full 镜像生产默认 (withhold) — 本测试即默认路径守卫 (SEC-10).
    let proxy_url = spawn_proxy_full(
        vec![provider],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        secrets,
    )
    .await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"keep {real_secret}"}}]}}"#
    );
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        &body,
        &[("content-type", "application/json")],
    )
    .await;

    // withhold: 200 + 原字节透传 (mock 保留, real 不出现 — SEC-10 降级偏安全).
    assert_eq!(status, reqwest::StatusCode::OK, "body: {text}");
    assert_eq!(
        text, upstream_body,
        "withhold must pass body through verbatim (mock kept)"
    );
    assert!(
        !text.contains(real_secret),
        "SEC-10 violation: real secret must NOT be restored into the degraded response; got: {text}"
    );

    // 可观测: mock-not-restored WARN + opt-in 提示 (行级断言).
    let log_text = log.text();
    let warn_line = log_text
        .lines()
        .find(|l| l.contains("mock not restored"))
        .unwrap_or("");
    assert!(
        !warn_line.is_empty(),
        "SEC-10 violation: no mock-not-restored WARN; log: {log_text}"
    );
    assert!(
        warn_line.contains("on_fallback_restore"),
        "SEC-10: WARN must carry the opt-in hint; got: {warn_line}"
    );
    // 卫生: 日志不得含真实 secret.
    assert!(
        !log_text.contains(real_secret),
        "WARN must not leak real secret; log: {log_text}"
    );
}

/// 跨协议 (o→a) + secret + 上游 200 返回 reader 拒绝的 JSON + **默认配置**
/// (withhold) → 对称保留 Mock 透传 (cross_proto 的 reader 拒绝臂同受 SEC-10 管约).
#[tokio::test]
async fn reader_reject_withholds_real_secret_by_default_cross_proto() {
    let real_secret = "sk-live-xwh12345678";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // anthropic reader 拒绝形态: 顶层是 array (reader 要求 JSON object) — 合法 JSON
    // 但非协议 shape; 元素携带 mock.
    let upstream_body = format!(r#"[{{"content":"echo {expected_mock}"}}]"#);
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(upstream_body.clone())
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        secrets,
    )
    .await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        &body,
        &[("content-type", "application/json")],
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::OK, "body: {text}");
    assert_eq!(
        text, upstream_body,
        "withhold must pass body through verbatim (mock kept)"
    );
    assert!(
        !text.contains(real_secret),
        "SEC-10 violation: real secret must NOT be restored; got: {text}"
    );
    let log_text = log.text();
    assert!(
        log_text.contains("mock not restored") && log_text.contains("on_fallback_restore"),
        "SEC-10: mock-not-restored WARN with opt-in hint missing; log: {log_text}"
    );
    assert!(
        !log_text.contains(real_secret),
        "WARN must not leak real secret; log: {log_text}"
    );
}

/// 同协议 + secret 命中 + 非流式 + 上游 200 但响应 JSON 无法被 codec reader 解析
/// (choices 类型错配) 且含 mock + **显式 `on_fallback_restore = "restore"` opt-in**
/// (RED-8 行为) → 兜底 restore: 客户端收到 real (不再逃逸 mock).
#[tokio::test]
async fn buffered_reader_reject_restores_mock_via_json_leaf_fallback() {
    let real_secret = "sk-live-leaf12345678";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // reader 拒绝形态: `choices` 是 string (openai reader 要求 array 且非空) —
    // 合法 JSON 但非协议 shape; echo 字段携带 mock (模拟 LLM 回响 redacted 内容).
    let upstream_body = format!(r#"{{"choices":"wrongtype","echo":"saw {expected_mock} end"}}"#);
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(upstream_body)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let provider = openai_provider("oa-main", &upstream.url());
    // RED-8 兜底 restore 是 opt-in 行为 (SEC-10 默认 withhold), 显式配置.
    let proxy_url = spawn_proxy_with_redact_gates(
        secret_guard::config::OnProbeExhausted::default(),
        secret_guard::config::OnUnsupportedProtocol::default(),
        secret_guard::config::OnFallbackRestore::Restore,
        vec![provider],
        secrets,
        reqwest::Client::new(),
        "sg-state-r8-restore",
        ConversationDag::new(64, 500, 1),
    )
    .await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"keep {real_secret}"}}]}}"#
    );
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        &body,
        &[("content-type", "application/json")],
    )
    .await;

    // 兜底 restore: 200 + echo 字段的 mock 已还原为 real.
    assert_eq!(status, reqwest::StatusCode::OK, "body: {text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!("fallback output must remain valid JSON; got: {text}, err: {e}")
    });
    assert_eq!(
        v["echo"],
        format!("saw {real_secret} end"),
        "mock must be restored to real; got: {text}"
    );
    assert!(!text.contains(&expected_mock), "got: {text}");

    // 可观测: restored-via-fallback WARN (body 经过了非 codec 的改写路径).
    let log_text = log.text();
    assert!(
        log_text.contains("mocks restored via JSON leaf fallback"),
        "RED-8 violation: no WARN about fallback restore; log: {log_text}"
    );
    // 卫生: 日志不得含真实 secret.
    assert!(
        !log_text.contains(real_secret),
        "WARN must not leak real secret; log: {log_text}"
    );
}

/// 跨协议 (o→a) + secret + 上游 200 返回 reader 拒绝的 JSON (非 object 形态) 含
/// mock + **显式 `restore` opt-in** → 客户端收到还原后的 JSON (cross_proto 的
/// reader 拒绝分支对称接入兜底).
#[tokio::test]
async fn cross_proto_reader_reject_restores_mock_via_json_leaf_fallback() {
    let real_secret = "sk-live-xleaf34567";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // anthropic reader 拒绝形态: 顶层是 array (reader 要求 JSON object) — 合法 JSON
    // 但非协议 shape; 元素携带 mock.
    let upstream_body = format!(r#"[{{"content":"echo {expected_mock}"}}]"#);
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(upstream_body)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    // RED-8 兜底 restore 是 opt-in 行为 (SEC-10 默认 withhold), 显式配置.
    let proxy_url = spawn_proxy_with_redact_gates(
        secret_guard::config::OnProbeExhausted::default(),
        secret_guard::config::OnUnsupportedProtocol::default(),
        secret_guard::config::OnFallbackRestore::Restore,
        vec![provider],
        secrets,
        reqwest::Client::new(),
        "sg-state-r8-restore",
        ConversationDag::new(64, 500, 1),
    )
    .await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        &body,
        &[("content-type", "application/json")],
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::OK, "body: {text}");
    // 兜底 restore 后的 JSON: 叶子里的 mock 已还原 (仍是 array 形态的透传 shape).
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!("fallback output must remain valid JSON; got: {text}, err: {e}")
    });
    assert_eq!(
        v[0]["content"],
        format!("echo {real_secret}"),
        "mock must be restored to real; got: {text}"
    );
    assert!(!text.contains(&expected_mock), "got: {text}");

    // 可观测: cross_proto 此前缺 restored/mock-not-restored 信号, 现在对称.
    let log_text = log.text();
    assert!(
        log_text.contains("mocks restored via JSON leaf fallback"),
        "RED-8 violation: cross-proto fallback restore WARN missing; log: {log_text}"
    );
    assert!(
        !log_text.contains(real_secret),
        "WARN must not leak real secret; log: {log_text}"
    );
}

/// 上游返回非 JSON body (SSE 形态) 含 mock → 兜底无法 parse → 仍原样透传
/// (行为守卫: 保持现状不劣化) + mock-not-restored WARN.
#[tokio::test]
async fn non_json_body_with_mock_still_passes_through_when_fallback_fails() {
    let real_secret = "sk-live-njson456789";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = format!(
        concat!(
            "data: {{\"choices\": [{{\"delta\": {{\"content\": \"saw {mock}\"}}}}]}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(sse_body.clone())
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        secrets,
    )
    .await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"keep {real_secret}"}}]}}"#
    );
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        &body,
        &[("content-type", "application/json")],
    )
    .await;

    // 兜底失败 (非单 JSON Value): 原样透传 (已知限制, 行为不变).
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        text, sse_body,
        "fallback failure must pass body through verbatim"
    );
    // mock-not-restored WARN 仍在 (非 JSON body 无兜底可试, 直接透传).
    let log_text = log.text();
    assert!(
        log_text.contains("mock not restored"),
        "mock-not-restored WARN must still fire; log: {log_text}"
    );
    assert!(
        log_text.contains("not a single JSON value"),
        "WARN detail should name the non-JSON cause; log: {log_text}"
    );
}

// ─── T5: 跨协议丢弃字段的可观测性 (reasoning / hosted tools 丢弃点 WARN) ──────
//
// 三个 WARN 发射点 (cross_proto_forward 请求侧历史 / 响应侧 / extra 的 hosted
// tools) 的接线守卫 — 纯函数计数已有单测, 这里锁定 "丢弃确实发生在预期路径上",
// 防未来重构把计数挪到 clear/翻译之后 (恒 0) 而测试不红. WARN 只记计数不记内容.

/// o→a: assistant 历史携带 `reasoning_content` (reader 解析为 ReasoningContent,
/// anthropic writer 无法合成 signature 而丢弃) → 请求侧丢弃 WARN.
#[tokio::test]
async fn cross_proto_request_reasoning_history_drop_warns() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"},{"role":"assistant","reasoning_content":"pondering deeply","content":"answer"},{"role":"user","content":"go on"}]}"#;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let log_text = log.text();
    assert!(
        log_text.contains("dropping reasoning block(s) from request history"),
        "T5: request-side reasoning drop WARN missing; log: {log_text}"
    );
}

/// a→o: OpenAI 兼容上游响应携带 `message.reasoning_content` (reader 解析为
/// ReasoningContent, anthropic ingress writer 跳过) → 响应侧丢弃 WARN.
#[tokio::test]
async fn cross_proto_response_reasoning_drop_warns() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-r","object":"chat.completion","created":1700000000,"model":"glm-5.3","choices":[{"index":0,"message":{"role":"assistant","reasoning_content":"let me think","content":"final answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":5}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("oa-main", Protocol::OpenAI, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body =
        r#"{"model":"claude-3","max_tokens":64,"messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, _, _) =
        proxy_request(&proxy_url, "POST", "/a/oa-main/v1/messages", body, &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let log_text = log.text();
    assert!(
        log_text.contains("dropping reasoning block(s) from response"),
        "T5: response-side reasoning drop WARN missing; log: {log_text}"
    );
}

/// Responses 入站的 hosted tools (web_search 等非 function 类型) 不进 IR
/// (reader 的 filter_map 丢弃, 也不进 extra — tools 是 modeled 字段) → 读取点 WARN.
/// 该 choke point 同时覆盖同协议 IR 重建路径与跨协议路径, 故用 r→a 场景锁接线.
#[tokio::test]
async fn cross_proto_hosted_tools_drop_warns() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let body = r#"{"model":"gpt-4o","input":"hi","tools":[{"type":"function","name":"f","parameters":{"type":"object"}},{"type":"web_search"}]}"#;
    let (status, _, _) =
        proxy_request(&proxy_url, "POST", "/r/an-main/v1/responses", body, &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let log_text = log.text();
    assert!(
        log_text.contains("dropping tool definition(s) not representable in IR"),
        "T5: hosted tools drop WARN missing; log: {log_text}"
    );
}

/// #162: provider 协议错配 (anthropic provider 指向 OpenAI shape 端点) →
/// 2xx 宽松解析出空 content + 零 usage, 行为不变 (仍翻译返回), 但必须打 WARN.
#[tokio::test]
async fn protocol_mismatch_silent_empty_response_warns() {
    let mut upstream = spawn_mock_upstream().await;
    // OpenAI shape 响应: choices[] 而非 content[]. Anthropic reader 宽松解析:
    // content 缺失 → 空数组, usage 字段名不匹配 → 全零 → 200 + 空 content (MRE).
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-mock-1","object":"chat.completion","model":"claude","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}"#,
        )
        .create_async()
        .await;

    // provider: protocol=anthropic, base_url 指向 OpenAI shape 端点 (错配).
    // 配置一个 secret → same_proto 走 IR 路径 (MRE 路径; 无 secret 时是纯透传).
    let real_secret = "sk-mismatch-secret-123";
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let provider = provider_with("mixed", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        secrets,
    )
    .await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    // body 命中 secret → redaction map 非空 → 响应走 restore 路径 (buffered_ir,
    // reader 宽松解析发生处). 注: #183 M1 后, "配置了 secret 但未命中" 的请求响应
    // 字节透传 (map 空), 客户端不再看到 MRE 形态 — 但 record 派生侧仍经过 reader
    // (fan_out_streaming 非流式一次性 parse, protocol_mismatch WARN 亦挂于此).
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/a/mixed/v1/messages",
        r#"{"model":"claude","max_tokens":100,"messages":[{"role":"user","content":"hi sk-mismatch-secret-123"}]}"#,
        &[("content-type", "application/json")],
    )
    .await;

    // (i) 行为不变: 200 + Anthropic 壳 (content 空数组 + usage 全零, MRE 形态).
    assert_eq!(status, reqwest::StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        v["content"].as_array().map(Vec::len),
        Some(0),
        "body: {text}"
    );
    assert_eq!(v["usage"]["input_tokens"], 0, "body: {text}");

    // (ii) WARN 被捕获: 协议错配信号 (空 content + 零 usage + 协议提示).
    let log_text = log.text();
    assert!(
        log_text.contains("empty content and zero usage"),
        "#162 violation: no WARN about empty content/zero usage; log: {log_text}"
    );
    assert!(
        log_text.contains("does the upstream actually speak"),
        "#162: WARN should hint protocol mismatch; log: {log_text}"
    );
    // 可定位: record_id (uuid 格式字段) 必须出现.
    assert!(
        log_text.contains("record_id"),
        "#162: WARN lacks record_id for locating; log: {log_text}"
    );
}

/// #162 覆盖面补全: 纯 passthrough 家族 (无 secret 配置 → same_proto 字节透传) 的
/// 非流式 2xx 响应协议错配 → 空 content + 零 usage, 行为不变 (byte-exact 透传),
/// 但必须打 WARN (此前该家族无 WARN 触点, 错配静默).
#[tokio::test]
async fn protocol_mismatch_warns_on_pure_passthrough_nonstream() {
    let mut upstream = spawn_mock_upstream().await;
    // OpenAI shape 响应 (choices[]) 喂给 anthropic provider — 错配 MRE 同
    // protocol_mismatch_silent_empty_response_warns, 差异仅在不配 secret.
    let openai_shape_body = r#"{"id":"chatcmpl-mock-1","object":"chat.completion","model":"claude","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}"#;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(openai_shape_body)
        .create_async()
        .await;

    // 无 secret → same_proto 走纯字节透传 (passthrough 家族, fan_out_streaming
    // 非流式分支做一次性 parse 仅为派生 parsed view).
    let provider = provider_with("mixed-pt", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (log, _log_guard) = capture_tracing(tracing::Level::WARN);
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/a/mixed-pt/v1/messages",
        r#"{"model":"claude","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}"#,
        &[("content-type", "application/json")],
    )
    .await;

    // (i) 行为不变: 200 + byte-exact 透传 (passthrough 家族无 IR 改写).
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        text, openai_shape_body,
        "passthrough family must stay byte-exact; body: {text}"
    );

    // (ii) WARN 被捕获: 协议错配信号 (与 redact 路径同文案, 两路径统一可 grep).
    let log_text = log.text();
    assert!(
        log_text.contains("empty content and zero usage"),
        "#162 coverage gap: pure-passthrough non-stream family emits no mismatch WARN; log: {log_text}"
    );
    assert!(
        log_text.contains("does the upstream actually speak"),
        "#162: WARN should hint protocol mismatch; log: {log_text}"
    );
    assert!(
        log_text.contains("record_id"),
        "#162: WARN lacks record_id for locating; log: {log_text}"
    );
}

// ─── 虚拟 provider 路由 (#179, FWD-5) ───────────────────────────────────────
//
// 契约: per-request 解析 (切换只影响新请求) / 坏路由 503 / 环 upsert 拒绝 /
// upstream_id 可观测 / 跨协议虚拟切换.

/// OpenAI chat completion mock (区分度 body: `{"upstream":"<tag>"}` 注入 content).
fn openai_chat_mock(server: &mut mockito::ServerGuard, tag: &str) -> mockito::Mock {
    server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"gpt-4o","choices":[{{"index":0,"message":{{"role":"assistant","content":"from {tag}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}}"#
        ))
}

const CHAT_REQ_BODY: &str = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#;

/// 读 DAG 最新 node 的 upstream_id (CallEvent 权威字段, #179).
fn latest_upstream_id(dag: &ConversationDag) -> String {
    let id = dag
        .list_node_ids_newest_first()
        .first()
        .copied()
        .expect("at least one node pushed");
    dag.get_node(id)
        .expect("node exists")
        .upstream_id
        .to_string()
}

#[tokio::test]
async fn router_provider_switches_routes_mid_session() {
    // FWD-5 per-request 解析: 同一路由 endpoint, PUT 切换路由后新请求走新目标;
    // 响应体区分两个上游; DAG 每轮 upstream_id 如实记录各自的实际归属.
    let mut upstream1 = spawn_mock_upstream().await;
    let mut upstream2 = spawn_mock_upstream().await;
    let _m1 = openai_chat_mock(&mut upstream1, "one").create_async().await;
    let _m2 = openai_chat_mock(&mut upstream2, "two").create_async().await;

    let real1 = openai_provider("real1", &upstream1.url());
    let real2 = openai_provider("real2", &upstream2.url());
    let rt = catch_all_router("virt", "real1");

    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real1, real2, rt],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table(),
    )
    .await
    .0;

    // 1. 初始指向 real1.
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "via real1 must succeed");
    assert!(text.contains("from one"), "body: {text}");
    assert_eq!(latest_upstream_id(&dag_probe), "real1");

    // 2. WebUI 即席切换: PUT override router 的 routes 指向 real2.
    let (status, body, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/virt",
        r#"{"routes":[{"model_pattern":"*","target":"real2","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "switch PUT must succeed");
    // 切换落在 effective 层 (PUT 响应即 effective 视图, 锁住可观测性).
    let updated: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        updated["routes"][0]["target"], "real2",
        "effective view: {body}"
    );

    // 3. 新请求走 real2 (per-request 解析; 历史轮次的 upstream_id 不被改写).
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "via real2 must succeed");
    assert!(text.contains("from two"), "body: {text}");
    assert_eq!(latest_upstream_id(&dag_probe), "real2");
}

#[tokio::test]
async fn router_provider_dangling_returns_503() {
    // FWD-5 坏路由: 目标缺失 → 503, message 指名目标 id (SEC-2 同型: 无 secret).
    let rt = catch_all_router("virt", "ghost");
    let proxy_url = spawn_proxy_with_provider(rt).await;
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert!(text.contains("ghost"), "message names target: {text}");
    assert!(text.contains("not found"), "message states reason: {text}");
}

#[tokio::test]
async fn router_provider_disabled_target_returns_503() {
    // FWD-5 坏路由: 链上目标 entry-level disabled → 503 (与入口自身 disabled 区分).
    let mut real = openai_provider("real", "https://upstream.invalid");
    real.enabled = false;
    let rt = catch_all_router("virt", "real");
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real, rt],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert!(text.contains("real"), "message names target: {text}");
    assert!(
        text.contains("is disabled"),
        "message states entry-level disabled (区别于 missing 的 'disabled by decision'): {text}"
    );
}

#[tokio::test]
async fn router_provider_cycle_upsert_rejected() {
    // FWD-5 环防护: 静态 a → b 已存在; PUT b 的路由指向 a (闭环) → 400;
    // 自环 → 400 (Provider::validate); 悬空目标 → 放行 (运行时 503 兜底).
    // 纯 CRUD 测试, 无转发 — 目标用字面量 URL (过 validate_base_url 即可).
    let a = catch_all_router("a", "b");
    let b = catch_all_router("b", "real1");
    let real1 = openai_provider("real1", "https://u.invalid");
    let proxy_url = spawn_proxy_static_dynamic(
        vec![a, b, real1],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;

    // 跨条目环: b → a 闭环 (a → b 已存在).
    let (status, text, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/b",
        r#"{"routes":[{"model_pattern":"*","target":"a","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "body: {text}");
    assert!(text.contains("cycle"), "reason is cycle: {text}");

    // 自环.
    let (status, text, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/b",
        r#"{"routes":[{"model_pattern":"*","target":"b","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "body: {text}");
    assert!(text.contains("itself"), "reason is self-loop: {text}");

    // 悬空目标放行 (创建顺序无关).
    let (status, _, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/b",
        r#"{"routes":[{"model_pattern":"*","target":"not-yet-created","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "dangling route target allowed"
    );
}

#[tokio::test]
async fn router_provider_cross_protocol_translates() {
    // 路由 endpoint 指向异协议实体: ingress 由 URL (openai) 决定, egress 由目标
    // (anthropic) 决定 → 自动落入既有 cross_proto 翻译 (#179 头线能力).
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;
    let ant = provider_with("ant-main", Protocol::Anthropic, &upstream.url());
    let rt = catch_all_router("virt", "ant-main");
    let proxy_url = spawn_proxy_static_dynamic(
        vec![ant, rt],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        r#"{"model":"gpt-4o","max_tokens":16,"messages":[{"role":"user","content":"Hi"}]}"#,
        &[],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "cross-proto via router must translate"
    );
}

// ─── model 改写 (路由的 Route.upstream_model, #183 语义被路由吸收) ────────
//
// 契约: prop_model_rewrite_injects_into_egress_ir (egress model 无条件改写,
// 无-secret 强制 IR 路径) / pipeline 后者覆盖 (单元已锁) / no_codec passthrough
// (D2 降级).

#[tokio::test]
async fn model_rewrite_reaches_upstream() {
    // 路由的 upstream_model 重写到达上游: egress body 的 model 字段被改写 (含无 secret 场景).
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": "claude-sonnet-4"}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"claude-sonnet-4","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
        )
        .create_async()
        .await;

    let real = openai_provider("oa-main", &upstream.url());
    let router = router_provider(
        "virt",
        vec![rewrite_route("*", "oa-main", "claude-sonnet-4")],
    );
    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real, router],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table(),
    )
    .await
    .0;

    // 客户端请求 model=gpt-4o, 上游必须收到 model=claude-sonnet-4 (match_body 已断言).
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    // 可观测性: record 的 model (egress 视角) = 重写值, upstream_model 同值.
    let id = dag_probe
        .list_node_ids_newest_first()
        .first()
        .copied()
        .unwrap();
    let node = dag_probe.get_node(id).unwrap();
    assert_eq!(node.model.as_deref(), Some("claude-sonnet-4"));
    assert_eq!(
        node.upstream_model.as_deref(),
        Some("claude-sonnet-4"),
        "upstream_model must be Some(override) when rewritten"
    );
}

#[tokio::test]
async fn model_rewrite_no_secret_forces_ir_path() {
    // 无 secret + 路由改写 → 不走字节直传, 强制 IR 路径 (FWD-1 修订的契约代价).
    // 判据: egress body 的 model 被改写 (直传路径不可能改写); 无 model 字段的
    // body 也被注入重写值 (D3).
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": "injected-model"}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"injected-model","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
        )
        .create_async()
        .await;

    let real = openai_provider("oa-main", &upstream.url());
    let router = router_provider(
        "virt",
        vec![rewrite_route("*", "oa-main", "injected-model")],
    );
    // 前提由结构保证: test_secret_table() = 空表 (仅改写场景, 验证 IR 路径被
    // 路由的 model 重写单独强制).
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real, router],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;

    // body 无 model 字段 (OpenAI reader 容忍缺失 → IR.model 为空串 → 注入重写值).
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        r#"{"messages":[{"role":"user","content":"Hi"}]}"#,
        &[],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "route rewrite injects model even when client body omits it"
    );
}

#[tokio::test]
async fn model_rewrite_switch_via_put() {
    // 即席切换模型: 路由 endpoint PUT 路由的 upstream_model 后, 新请求用新 model
    // (per-request; 历史轮次 record 不改写).
    let mut upstream = spawn_mock_upstream().await;
    let _m1 = upstream
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": "model-v1"}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"a","object":"chat.completion","created":1,"model":"model-v1","choices":[{"index":0,"message":{"role":"assistant","content":"1"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#)
        .create_async()
        .await;
    let _m2 = upstream
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": "model-v2"}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"b","object":"chat.completion","created":1,"model":"model-v2","choices":[{"index":0,"message":{"role":"assistant","content":"2"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#)
        .create_async()
        .await;

    let real = openai_provider("real", &upstream.url());
    let rt = catch_all_router("virt", "real");
    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real, rt],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table(),
    )
    .await
    .0;

    // 1. PUT 设置路由 upstream_model = model-v1.
    let (status, body, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/virt",
        r#"{"routes":[{"model_pattern":"*","target":"real","upstream_model":"model-v1","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "set rewrite: {body}");

    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    // 2. 切换 model (PUT 路由 upstream_model = model-v2) → 新请求用 v2.
    let (status, _, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/virt",
        r#"{"routes":[{"model_pattern":"*","target":"real","upstream_model":"model-v2","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    // 3. 两轮 record 各自如实记录 (egress model + upstream_model).
    let ids = dag_probe.list_node_ids_newest_first();
    assert_eq!(ids.len(), 2);
    let latest = dag_probe.get_node(ids[0]).unwrap();
    assert_eq!(latest.model.as_deref(), Some("model-v2"));
    assert_eq!(latest.upstream_model.as_deref(), Some("model-v2"));
    let prev = dag_probe.get_node(ids[1]).unwrap();
    assert_eq!(prev.model.as_deref(), Some("model-v1"));
    assert_eq!(prev.upstream_model.as_deref(), Some("model-v1"));
}

#[tokio::test]
async fn model_rewrite_gemini_passthrough_unrewritten() {
    // D2 降级: 无 codec 协议 (Gemini) + 路由改写 → body 不改写 (原样 model 到上游)
    // + WARN (可观测). FWD-5 prop_model_rewrite_no_codec_passthrough.
    let mut upstream = spawn_mock_upstream().await;
    // match_body 断言: 上游收到的仍是客户端原始 model (未被 override 改写).
    let _m = upstream
        .mock("POST", "/v1beta/models/gemini-pro:generateContent")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": "gemini-pro"}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}"#)
        .create_async()
        .await;

    let gem = provider_with("gem-main", Protocol::Gemini, &upstream.url());
    let router = router_provider("virt", vec![rewrite_route("*", "gem-main", "gemini-flash")]);
    let (log, _guard) = capture_tracing(tracing::Level::WARN);
    let proxy_url = spawn_proxy_static_dynamic(
        vec![gem, router],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;

    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/g/virt/v1beta/models/gemini-pro:generateContent",
        r#"{"model":"gemini-pro","contents":[{"parts":[{"text":"hello"}]}]}"#,
        &[],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "gemini + route rewrite still forwards"
    );

    let log_text = log.text();
    assert!(
        log_text.contains("model rewrite") && log_text.contains("does not"),
        "#183 D2: no-codec rewrite must WARN; log: {log_text}"
    );
}

// M3 补强: FWD-1 联合公式 (改写 × secret 共存) / D5 (Responses 流式 501) /
// cross_proto 注入 / PUT 清空往返.

#[tokio::test]
async fn model_rewrite_with_secret_joint() {
    // FWD-1 修订联合公式: egress == normalize(client).replace(real, mock).replace(model, rewrite).
    // 两个替换同时成立: 上游收到 model=重写值 (match_body), 且 egress body 含 mock
    // 不含 real (DAG record 的 req_body_raw 即 egress 视角, 直接断言).
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": "target-model"}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"c1","object":"chat.completion","created":1,"model":"target-model","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
        )
        .create_async()
        .await;

    let real = openai_provider("oa-main", &upstream.url());
    let router = router_provider("virt", vec![rewrite_route("*", "oa-main", "target-model")]);
    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real, router],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table_with(vec![secret("joint-secret", "sk-live-joint-secret")]),
    )
    .await
    .0;

    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"key sk-live-joint-secret"}]}"#,
        &[],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "joint redact+rewrite forwards: {body}"
    );

    // egress body (record req_body_raw): secret 已 redact + model 已重写.
    let id = dag_probe.list_node_ids_newest_first()[0];
    let detail = dag_probe.get_node_detail(id).unwrap();
    assert!(
        !detail.req_body_raw.contains("sk-live-joint-secret"),
        "real secret must not reach egress body"
    );
    assert!(detail.req_body_raw.contains("target-model"));
}

/// #183 D5 收窄: 仅 model 重写 (无 secret 命中) 的 Responses 流式请求**放行** —
/// 请求半段 model 被重写 (IR 路径), 响应半段 SSE 字节透传 (map 空, 无需 restore).
#[tokio::test]
async fn model_rewrite_responses_streaming_passthrough() {
    let sse = "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Hi\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\"}}\n\n";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/responses")
        // 上游收到重写后的 model (gpt-5, 非 gpt-4o) + stream 保真 (Responses writer
        // 保留 stream: true, 单测锁定见 codec::fwd_responses_property 的
        // responses_request_preserves_wire_semantics).
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": "gpt-5", "stream": true}),
        ))
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse)
        .expect(1)
        .create_async()
        .await;
    let resp = provider_with("resp-main", Protocol::OpenAIResponses, &upstream.url());
    let router = router_provider("virt", vec![rewrite_route("*", "resp-main", "gpt-5")]);
    let proxy_url = spawn_proxy_static_dynamic(
        vec![resp, router],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/r/virt/v1/responses",
        r#"{"model":"gpt-4o","stream":true,"input":"Hi"}"#,
        &[],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "rewrite-only must stream: {body}"
    );
    // 响应半段 byte-exact: map 空 → fan_out_streaming 字节透传, 不经 codec 事件层.
    assert_eq!(body, sse, "client must receive upstream SSE bytes verbatim");
    _m.assert_async().await;
}

/// #183 D5 收窄: Responses 流式 + **Redact 命中** (secret 在 body 中) 仍 501 —
/// 响应需要 restore 而 Responses 的 SSE 事件翻译未实现, 放行会让 mock 静默外流.
#[tokio::test]
async fn responses_streaming_with_secret_hit_returns_501() {
    let real_secret = "sk-live-resp-secret";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body("data: {}\n\n")
        .expect(0)
        .create_async()
        .await;
    let resp = provider_with("resp-main", Protocol::OpenAIResponses, &upstream.url());
    let router = router_provider("virt", vec![rewrite_route("*", "resp-main", "gpt-5")]);
    let proxy_url = spawn_proxy_static_dynamic(
        vec![resp, router],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table_with(vec![secret("api-key", real_secret)]),
    )
    .await
    .0;
    let body = format!(r#"{{"model":"gpt-4o","stream":true,"input":"key {real_secret}"}}"#);
    let (status, text, _) =
        proxy_request(&proxy_url, "POST", "/r/virt/v1/responses", &body, &[]).await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_IMPLEMENTED,
        "redact-hit streaming must still 501: {text}"
    );
    // SEC-2: message 不含 secret 明文; 提示 "移除 secrets 即可流式".
    assert!(
        !text.contains(real_secret),
        "501 body must not leak secret: {text}"
    );
    assert!(
        text.contains("secrets"),
        "501 message must hint removing secrets unlocks streaming: {text}"
    );
    _m.assert_async().await;
}

#[tokio::test]
async fn model_rewrite_cross_protocol() {
    // cross_proto + 改写: OpenAI ingress → Anthropic egress, /v1/messages 的
    // model 字段 = 重写值 (注入点共享 parse_request_ir, egress writer 写出).
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": "claude-target"}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"model":"claude-target","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;

    let ant = provider_with("ant-main", Protocol::Anthropic, &upstream.url());
    let router = router_provider(
        "virt",
        vec![rewrite_route("*", "ant-main", "claude-target")],
    );
    let proxy_url = spawn_proxy_static_dynamic(
        vec![ant, router],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        r#"{"model":"gpt-4o","max_tokens":16,"messages":[{"role":"user","content":"Hi"}]}"#,
        &[],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "cross-proto rewrite translates model"
    );
}

#[tokio::test]
async fn model_rewrite_put_clear_roundtrip() {
    // 清空分支: PUT 路由不带 upstream_model → effective 清空 → 后续请求 model 透传.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": "gpt-4o"}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"c","object":"chat.completion","created":1,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
        )
        .create_async()
        .await;

    let real = openai_provider("real", &upstream.url());
    let rt = catch_all_router("virt", "real");
    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real, rt],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table(),
    )
    .await
    .0;

    // 1. 设置路由 upstream_model = tmp-model.
    let (status, body, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/virt",
        r#"{"routes":[{"model_pattern":"*","target":"real","upstream_model":"tmp-model","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["routes"][0]["upstream_model"], "tmp-model");

    // 2. 清空 (PUT 路由省略 upstream_model 字段) → 后续请求 model 透传.
    let (status, body, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/virt",
        r#"{"routes":[{"model_pattern":"*","target":"real","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["routes"][0]["upstream_model"].is_null(),
        "cleared: {body}"
    );

    // 3. 后续请求 model 透传 (gpt-4o 原样到上游, match_body 已断言) + record 无改写痕迹.
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/virt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let id = dag_probe.list_node_ids_newest_first()[0];
    let node = dag_probe.get_node(id).unwrap();
    assert_eq!(node.model.as_deref(), Some("gpt-4o"));
    assert_eq!(node.upstream_model, None, "no rewrite after clear");
}

#[tokio::test]
async fn model_rewrite_response_stays_byte_exact_streaming() {
    // M1 (#183): 改写只作用于请求半段; 响应半段在 redaction map 为空时保持
    // **字节透传** — 用带非常规格式 (紧凑空白 / [DONE] 前空行) 的 SSE 断言逐字节相等.
    let sse_body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "\n",
        "data: [DONE]\n\n"
    );
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;

    let real = openai_provider("oa-main", &upstream.url());
    let router = router_provider("virt", vec![rewrite_route("*", "oa-main", "target-model")]);
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real, router],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;

    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/virt/v1/chat/completions"))
        .body(r#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"Hi"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();
    assert_eq!(
        text, sse_body,
        "response must be byte-exact when rewrite-only (map empty)"
    );
}

// ─── provider 表单构造分野 (#190): protocol 字段的 API 语义 ─────────────────
//
// Router 构造不存在 protocol 字段 (ingress per-request URL / egress per-route
// 链尾决定, 无可陈述的事实 — 见 RouterProvider 注释); Direct 构造必填.

#[tokio::test]
async fn provider_create_router_ignores_protocol() {
    // Router 无 protocol: 不带 → 201 (不再是 400); 残留发送 (旧客户端习惯) →
    // 静默忽略, 同样 201 — protocol 只进 Direct 构造, 不因它报错.
    let proxy_url =
        spawn_proxy_with_provider(openai_provider("oa-main", "https://u.invalid")).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/api/providers",
        r#"{"id":"rt-no-proto","routes":[{"model_pattern":"*","target":"oa-main","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "body: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(created["kind"], "router", "created as router: {body}");
    assert!(
        created.get("protocol").is_none(),
        "router view carries no protocol: {body}"
    );

    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/api/providers",
        r#"{"id":"rt-stray-proto","protocol":"openai","routes":[{"model_pattern":"*","target":"oa-main","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "body: {body}");
}

#[tokio::test]
async fn provider_create_direct_without_protocol_rejected() {
    // Direct 构造 protocol 必填 — 缺失 → 400 (可行动消息), 非 serde 422.
    let proxy_url =
        spawn_proxy_with_provider(openai_provider("oa-main", "https://u.invalid")).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/api/providers",
        r#"{"id":"no-proto","base_url":"https://api.example.com","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "body: {body}");
    assert!(
        body.contains("protocol is required"),
        "actionable message: {body}"
    );
}

#[tokio::test]
async fn provider_update_partial_put_keeps_protocol() {
    // PUT 保留语义 (#190): 只改 name 不带 protocol → 从 Direct 旧值回填, 不 400.
    let upstream = spawn_mock_upstream().await;
    let real = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;
    // static 条目 → PUT 创建 dynamic override (protocol 省略 → 回填 static 的 openai;
    // routes 省略 + effective 是 Direct → 不回填 → Direct 意图).
    let (status, body, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/oa-main",
        r#"{"name":"renamed","base_url":"https://api.example.com","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["protocol"], "openai",
        "protocol backfilled from old direct value"
    );
}

// ─── 路由 (#179 多规则化): 按 model 分流 / priority / NoMatch / PUT 覆盖 ──

/// OpenAI chat mock (带 model match 断言): 上游收到的 body 含指定 model.
async fn openai_chat_mock_matching_model(
    upstream: &mut mockito::ServerGuard,
    model: &str,
) -> mockito::Mock {
    upstream
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"model": model}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-x","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
        )
        .create_async()
        .await
}

#[tokio::test]
async fn router_routes_route_by_model() {
    // 双上游分流: gpt-* → realA (路由改写 model=gpt-4o), claude-* → realB (透传).
    // mockito match_body 断言各自收到的 model 值 (改写 vs 原样).
    let mut upstream_a = spawn_mock_upstream().await;
    let mut upstream_b = spawn_mock_upstream().await;
    let _ma = openai_chat_mock_matching_model(&mut upstream_a, "gpt-4o").await;
    let _mb = openai_chat_mock_matching_model(&mut upstream_b, "claude-3").await;

    let real_a = openai_provider("real-a", &upstream_a.url());
    let real_b = openai_provider("real-b", &upstream_b.url());
    let rt = router_provider(
        "rt",
        vec![
            rewrite_route("gpt-*", "real-a", "gpt-4o"),
            route("claude-*", "real-b"),
        ],
    );
    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real_a, real_b, rt],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table(),
    )
    .await
    .0;

    // 1. model gpt-3.5 → 路由 gpt-* 命中 → real-a 收到改写后的 gpt-4o.
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        r#"{"model":"gpt-3.5","messages":[{"role":"user","content":"Hi"}]}"#,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(latest_upstream_id(&dag_probe), "real-a");

    // 2. model claude-3 → 路由 claude-* 命中 → real-b 收到原样 claude-3 (透传).
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        r#"{"model":"claude-3","messages":[{"role":"user","content":"Hi"}]}"#,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(latest_upstream_id(&dag_probe), "real-b");
}

#[tokio::test]
async fn router_routes_priority_decides_winner() {
    // 两条路由都匹配: 高 priority 胜; 并列按列表序 (低 priority 在前也不抢).
    let mut upstream = spawn_mock_upstream().await;
    let _m = openai_chat_mock(&mut upstream, "hi").create_async().await;
    let real_a = openai_provider("real-a", &upstream.url());
    let real_b = openai_provider("real-b", &upstream.url());

    let mut low_first = route("*", "real-a"); // priority 0, 列表序在前
    low_first.priority = Some(1);
    let mut high_later = route("gpt-*", "real-b"); // priority 10, 列表序在后
    high_later.priority = Some(10);
    let rt = router_provider("rt", vec![low_first, high_later]);

    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real_a.clone(), real_b.clone(), rt],
        vec![],
        reqwest::Client::new(),
        dag.clone(),
        test_secret_table(),
    )
    .await
    .0;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        latest_upstream_id(&dag_probe),
        "real-b",
        "higher priority wins regardless of list order"
    );

    // 并列 priority: 列表序先者胜 (共享 dag probe 断言胜者, 非仅 200).
    let rt_tie = router_provider("tie", vec![route("*", "real-a"), route("*", "real-b")]);
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real_a.clone(), real_b.clone(), rt_tie],
        vec![],
        reqwest::Client::new(),
        dag.clone(),
        test_secret_table(),
    )
    .await
    .0;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/tie/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        latest_upstream_id(&dag_probe),
        "real-a",
        "priority tie breaks by list order (first wins)"
    );

    // 负 priority 值域: 排序方向不因符号翻转 (-1 仍胜 -5).
    let mut neg_wide = route("*", "real-a"); // priority -5, 列表序在前
    neg_wide.priority = Some(-5);
    let mut neg_precise = route("gpt-*", "real-b"); // priority -1, 列表序在后
    neg_precise.priority = Some(-1);
    let rt_neg = router_provider("rt-neg", vec![neg_wide, neg_precise]);
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real_a, real_b, rt_neg],
        vec![],
        reqwest::Client::new(),
        dag.clone(),
        test_secret_table(),
    )
    .await
    .0;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt-neg/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        latest_upstream_id(&dag_probe),
        "real-b",
        "-1 beats -5: ordering holds in negative range"
    );
}

#[tokio::test]
async fn router_routes_disabled_route_skipped() {
    // priority null = 禁用: 精确匹配的禁用路由让位于启用兜底路由.
    let mut upstream = spawn_mock_upstream().await;
    let _m = openai_chat_mock(&mut upstream, "hi").create_async().await;
    let real_a = openai_provider("real-a", &upstream.url());
    let real_b = openai_provider("real-b", &upstream.url());

    let mut disabled_precise = route("gpt-4o", "real-a");
    disabled_precise.priority = None; // 禁用
    let rt = router_provider("rt", vec![disabled_precise, route("*", "real-b")]);

    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real_a, real_b, rt],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table(),
    )
    .await
    .0;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        CHAT_REQ_BODY, // model = gpt-4o: 禁用路由本应精确命中
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        latest_upstream_id(&dag_probe),
        "real-b",
        "disabled route must be skipped"
    );
}

#[tokio::test]
async fn router_routes_no_match_returns_503() {
    // 无启用路由匹配请求 model → 503, body 含 router id 与 model 名 (SEC-2 同型).
    let rt = router_provider("rt", vec![route("gpt-*", "real")]);
    let proxy_url = spawn_proxy_with_provider(rt).await;
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        r#"{"model":"claude-3","messages":[{"role":"user","content":"Hi"}]}"#,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert!(text.contains("rt"), "message names router id: {text}");
    assert!(
        text.contains("no route matching") && text.contains("claude-3"),
        "message states no-match with model: {text}"
    );
}

#[tokio::test]
async fn router_routes_put_overrides_static() {
    // per-request 语义: PUT 覆盖 static router 的 routes (调整指向 / 改写 / 禁用 /
    // 新增路由) 后, 新请求立即按新路由转发.
    let mut upstream_a = spawn_mock_upstream().await;
    let mut upstream_b = spawn_mock_upstream().await;
    let _ma = openai_chat_mock_matching_model(&mut upstream_a, "gpt-4o").await;
    // claude-* → real-a 分支 (透传): real-a 也要能收到 claude-3.
    let _ma2 = openai_chat_mock_matching_model(&mut upstream_a, "claude-3").await;
    let _mb = openai_chat_mock_matching_model(&mut upstream_b, "gpt-5").await;

    let real_a = openai_provider("real-a", &upstream_a.url());
    let real_b = openai_provider("real-b", &upstream_b.url());
    // static: gpt-* → real-a (无改写).
    let rt = router_provider("rt", vec![route("gpt-*", "real-a")]);

    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real_a, real_b, rt],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table(),
    )
    .await
    .0;

    // 1. 初始: gpt-4o → real-a 原样.
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(latest_upstream_id(&dag_probe), "real-a");

    // 2. PUT 覆盖 routes: 旧路由禁用 (priority null) + 新路由 gpt-* → real-b
    //    (model 改写 gpt-5) + claude-* → real-a.
    let (status, body, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/rt",
        r#"{"routes":[{"model_pattern":"gpt-*","target":"real-a","priority":null},{"model_pattern":"gpt-*","target":"real-b","upstream_model":"gpt-5","priority":10},{"model_pattern":"claude-*","target":"real-a","priority":0}],"base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "override routes: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["routes"].as_array().map(Vec::len),
        Some(3),
        "effective view: {body}"
    );

    // 3. 新请求: 禁用路由让位, gpt-* → real-b 且 model 改写为 gpt-5
    //    (match_body 已断言 real-b 收到 gpt-5).
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(latest_upstream_id(&dag_probe), "real-b");

    // 4. 新增路由分支生效: claude-3 → real-a.
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        r#"{"model":"claude-3","messages":[{"role":"user","content":"Hi"}]}"#,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(latest_upstream_id(&dag_probe), "real-a");
}

/// m3-1: PUT "保留" 语义 — 对 static router 发**不带 routes** 的 PUT (仅改
/// name 的 SDK 形态) → 200; effective routes 从旧值回填 (不变), kind 仍 router.
#[tokio::test]
async fn router_routes_put_omitted_routes_keeps_old() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = openai_chat_mock(&mut upstream, "hi").create_async().await;
    let real_a = openai_provider("real-a", &upstream.url());
    let rt = router_provider("rt", vec![route("gpt-*", "real-a")]);

    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real_a, rt],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table(),
    )
    .await
    .0;

    // PUT 省略 routes: static router (dynamic 无旧条目) 从 effective 回填.
    let (status, body, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/rt",
        r#"{"name":"renamed","base_url":"","enabled":true}"#,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "put omitted routes: {body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["kind"], "router", "kind stays router: {body}");
    assert_eq!(
        v["routes"].as_array().map(Vec::len),
        Some(1),
        "routes backfilled from effective: {body}"
    );
    assert_eq!(
        v["routes"][0]["target"], "real-a",
        "route content unchanged: {body}"
    );

    // 路由行为不变: gpt-4o 仍按旧路由到 real-a.
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(latest_upstream_id(&dag_probe), "real-a");
}

/// m3-2: PUT `routes: []` + Direct 完整字段 → kind 变 direct (空数组 = 显式
/// "改回实体" 的 SDK 形态; 前端已有 Playwright 覆盖, 这里锁 API 契约).
#[tokio::test]
async fn router_routes_empty_array_switches_to_direct() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = openai_chat_mock(&mut upstream, "hi").create_async().await;
    let real = openai_provider("real", &upstream.url());
    let rt = router_provider("rt", vec![route("*", "real")]);

    let proxy_url = spawn_proxy_static_dynamic(
        vec![real, rt],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    )
    .await
    .0;

    // PUT 空数组 + Direct 完整字段 (protocol + base_url): override 变实体.
    let (status, body, _) = proxy_request(
        &proxy_url,
        "PUT",
        "/api/providers/rt",
        &format!(
            r#"{{"routes":[],"protocol":"openai","base_url":"{}","enabled":true}}"#,
            upstream.url()
        ),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "switch to direct: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["kind"], "direct", "kind switched to direct: {body}");
    assert_eq!(
        v["base_url"],
        upstream.url(),
        "direct fields active: {body}"
    );

    // 转发不再走路由: rt 自身即实体, 直连 PUT 的 base_url.
    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/rt/v1/chat/completions",
        CHAT_REQ_BODY,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {text}");
    assert!(
        text.contains("from hi"),
        "served by the new direct target: {text}"
    );
}

/// m3-4: 两跳 pipeline 端到端 — R1 (gpt-* → R2, 改写 m2-in) → R2 按改写后的
/// m2-in 匹配 (m2-* → real-a, 改写 m2-tail-a). HTTP 层断言: 上游选择由**改写值**
/// 决定 (若第二跳用原始 gpt-4o 匹配会走 real-b 的 * 兜底, 其 mock 不匹配 → 501),
/// 最终 model = 第二跳链尾改写 (后写覆盖前写). mockito 双上游.
#[tokio::test]
async fn router_routes_two_hop_pipeline_rewrite_e2e() {
    let mut upstream_a = spawn_mock_upstream().await;
    let mut upstream_b = spawn_mock_upstream().await;
    let _ma = openai_chat_mock_matching_model(&mut upstream_a, "m2-tail-a").await;
    let _mb = openai_chat_mock_matching_model(&mut upstream_b, "gpt-4o").await;

    let real_a = openai_provider("real-a", &upstream_a.url());
    let real_b = openai_provider("real-b", &upstream_b.url());
    // R2: m2-* → real-a (改写 m2-tail-a); 其余 → real-b (透传).
    let r2 = router_provider(
        "r2",
        vec![
            rewrite_route("m2-*", "real-a", "m2-tail-a"),
            route("*", "real-b"),
        ],
    );
    // R1: gpt-* → r2, 第一跳改写 m2-in (第二跳的匹配输入; 注意 "m2" 不匹配
    // "m2-*" — 前缀 "m2-" 不可省, 改写值必须落在第二跳 model_pattern 的语言内).
    let r1 = router_provider("r1", vec![rewrite_route("gpt-*", "r2", "m2-in")]);

    let dag = ConversationDag::new(64, 500, 1);
    let dag_probe = dag.clone();
    let proxy_url = spawn_proxy_static_dynamic(
        vec![real_a, real_b, r1, r2],
        vec![],
        reqwest::Client::new(),
        dag,
        test_secret_table(),
    )
    .await
    .0;

    let (status, text, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/r1/v1/chat/completions",
        CHAT_REQ_BODY, // model = gpt-4o
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {text}");
    assert_eq!(
        latest_upstream_id(&dag_probe),
        "real-a",
        "second hop matches the REWRITTEN model m2-in, not the request model"
    );
    // match_body 已断言 real-a 收到 m2-tail-a (第二跳改写覆盖第一跳的 m2-in):
    // real-a 的 mock 只匹配 model=m2-tail-a, 收到 m2-in 会 unmatched → 501.
}

// ─── usage-stats: 端到端 (proxy → UsageCtx → store → SQLite → API) ────────

/// usage E2E fixture: 临时目录 + 全新文件 store (WAL 侧车一并清理).
/// 返回 (store, db path); 用后 remove_file(db) 清理.
fn usage_e2e_store(
    tag: &str,
) -> (
    std::sync::Arc<secret_guard::usage::UsageStore>,
    std::path::PathBuf,
) {
    let dir = std::env::temp_dir().join(format!("sg-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("usage.sqlite3");
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
    }
    let store = std::sync::Arc::new(secret_guard::usage::UsageStore::open(
        &secret_guard::config::UsageConfig {
            enabled: true,
            retention_days: 90,
            ..Default::default()
        },
        &db,
    ));
    (store, db)
}

/// 轮询 /api/usage/summary 直到谓词满足 (writer 线程异步落库的等待收敛).
async fn poll_usage_summary(
    client: &reqwest::Client,
    base: &str,
    satisfied: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    for _ in 0..100 {
        let s = client
            .get(format!("{base}/api/usage/summary?hours=24"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        if satisfied(&s) {
            return s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("usage summary condition not met within poll budget");
}
//
// 契约: USAGE-1/2/4/5 的集成层锚. 单元层 (store/summary/UsageCtx) 已分别覆盖,
// 此处验证全链路接线: 上游回显 usage → codec 归一化 → 落账 (含 SQLite 持久化)
// → GET /api/usage/summary 聚合. USAGE-5 的方法过滤 (GET /models 不计入) 一并守卫.

/// usage-stats E2E 专用: 文件落盘的 UsageStore + 独立 AppState (空 secrets).
async fn spawn_proxy_with_usage_store(
    usage: std::sync::Arc<secret_guard::usage::UsageStore>,
) -> String {
    spawn_proxy_with_usage_store_and_secrets(usage, test_secret_table()).await
}

/// 同上, 但 secrets 表可注入 (redact 审计 E2E 用).
async fn spawn_proxy_with_usage_store_and_secrets(
    usage: std::sync::Arc<secret_guard::usage::UsageStore>,
    secrets: SecretTable,
) -> String {
    let upstream_client = reqwest::Client::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("sg-usage-state");
    // 直接构造 (不走 spawn_proxy_full — 它固定 in_memory store):
    let provider_table = ProviderTable::with_persist_lock(
        vec![openai_provider("oa-main", "http://127.0.0.1:1")],
        vec![],
        std::sync::Arc::new(parking_lot::RwLock::new(
            secret_guard::config::Decisions::default(),
        )),
        state_path,
        std::sync::Arc::new(parking_lot::Mutex::new(())),
    );
    let proxy = AppState {
        usage,
        ..base_app_state(
            upstream_client,
            provider_table,
            ConversationDag::new(64, 500, 1),
            secrets,
        )
    };
    let app = server::build_router(
        proxy,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

// ─── USAGE-7 + USAGE-1 (rounds) 穿透 E2E ─────────────────────────────────
//
// 全链路: 请求 body 含 secret → same-proto redact → record_redactions (请求侧,
// push 后立即) → SQLite redact_events → /api/usage/summary 的 redactions 视图;
// 同时验证 rounds 三态接线: 完全相同的 messages 重发 → RoundKind::Retry →
// summary.totals.retries == 1 (round_kind 真值透传自 dag push 判定).
#[tokio::test]
async fn usage_stats_redact_audit_and_retry_round_recorded() {
    let mut server = mockito::Server::new_async().await;
    let chat_body = serde_json::json!({
        "id": "chatcmpl-redact",
        "model": "gpt-r",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2}
    });
    let _chat = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&chat_body).unwrap())
        .create_async()
        .await;

    let (store, db) = usage_e2e_store("redact-e2e");
    let base = spawn_proxy_with_usage_store_and_secrets(
        store.clone(),
        test_secret_table_with(vec![secret("sid-e2e", "sk-live-e2e-secret-value")]),
    )
    .await;
    let client = reqwest::Client::new();
    let create = serde_json::json!({
        "id": "oa-mock", "enabled": true, "protocol": "openai",
        "base_url": server.url(), "api_key": "sk-x"
    });
    let resp = client
        .post(format!("{base}/api/providers"))
        .json(&create)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // 两次完全相同的 chat (body 含 secret): 第一次 Normal + redact, 第二次 Retry.
    let body = serde_json::json!({"model": "gpt-r", "messages": [
        {"role": "user", "content": "use sk-live-e2e-secret-value to call api"}]});
    for _ in 0..2 {
        let r = client
            .post(format!("{base}/o/oa-mock/v1/chat/completions"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());
        let _ = r.json::<serde_json::Value>().await;
    }
    store.flush_for_test();

    let s = poll_usage_summary(&client, &base, |s| {
        s["totals"]["requests"].as_u64() == Some(2)
    })
    .await;
    // USAGE-1 rounds 三态: 第二次全前缀重发 → Retry.
    assert_eq!(s["totals"]["retries"].as_u64(), Some(1), "retry round: {s}");
    // USAGE-7: redact 审计视图 (by_secret + recent), mock 不含 secret 明文.
    let by_secret = s["redactions"]["by_secret"].as_array().expect("by_secret");
    assert_eq!(by_secret.len(), 1, "one secret hit: {s}");
    assert_eq!(by_secret[0]["secret_id"].as_str(), Some("sid-e2e"));
    assert_eq!(by_secret[0]["hits"].as_u64(), Some(2));
    let mock = by_secret[0]["mock"].as_str().unwrap();
    assert!(
        !mock.contains("sk-live-e2e-secret-value"),
        "mock must not leak secret"
    );
    // 治理归因: 位置分类 — secret 在 user message 里 (两次请求各 1 次).
    let cats = &by_secret[0]["categories"];
    assert_eq!(cats["user"].as_u64(), Some(2), "user-message category: {s}");
    assert_eq!(cats["system"].as_u64(), None, "no system-prompt hit: {s}");
    let recent = s["redactions"]["recent"].as_array().expect("recent");
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0]["provider"].as_str(), Some("oa-mock"));
    // 治理溯源: node 列非空 (DAG 关联, 内存态可 drill down); auth 未启用 → key null.
    assert!(recent[0]["node"].as_str().is_some_and(|n| !n.is_empty()));
    assert!(recent[0]["api_key_label"].is_null());
    assert_eq!(recent[0]["category"].as_str(), Some("user"));
    assert!(!format!("{recent:?}").contains("sk-live-e2e-secret-value"));
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn usage_stats_end_to_end_records_replayed_and_served() {
    // 1. mock 上游: chat completion 回显 usage (prompt_tokens 含 cached → 归一化校验点).
    let mut server = mockito::Server::new_async().await;
    let chat_body = serde_json::json!({
        "id": "chatcmpl-e2e",
        "model": "gpt-echoed",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50,
                  "prompt_tokens_details": {"cached_tokens": 30}}
    });
    let _chat = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&chat_body).unwrap())
        .create_async()
        .await;
    // GET /models 透传 (USAGE-5: 方法过滤 — 不产生 usage 事件).
    let _models = server
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{\"data\":[]}")
        .create_async()
        .await;

    // 2. 文件落盘的 store.
    let (store, db) = usage_e2e_store("usage-e2e");
    let base = spawn_proxy_with_usage_store(store.clone()).await;

    // 3. provider base_url 指向 mock: 通过 state.toml 写 dynamic override 不可行 (helper
    //    固定 127.0.0.1:1) — 改用 WebUI API 创建 provider (dynamic 路径), 指向 mock.
    let client = reqwest::Client::new();
    let create = serde_json::json!({
        "id": "oa-mock", "enabled": true, "name": "mock",
        "protocol": "openai", "base_url": server.url(), "api_key": "sk-x"
    });
    let resp = client
        .post(format!("{base}/api/providers"))
        .json(&create)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "create provider: {}",
        resp.status()
    );

    // 4. POST chat → 回显 usage 应被采集; GET /models → 不应计入.
    let chat = client
        .post(format!("{base}/o/oa-mock/v1/chat/completions"))
        .json(&serde_json::json!({"model": "gpt-req", "messages": [
            {"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert!(chat.status().is_success());
    let _ = chat.json::<serde_json::Value>().await;
    let _ = client
        .get(format!("{base}/o/oa-mock/v1/models"))
        .send()
        .await
        .unwrap();

    // 5. 轮询 summary 直到事件落地 (writer 线程异步 + record 同步进内存聚合,
    //    summary 读内存 — 立即可见; 轮询是防御 scheduler 延迟).
    let s = poll_usage_summary(&client, &base, |s| {
        s["totals"]["requests"].as_u64() == Some(1)
    })
    .await;
    let t = &s["totals"];
    assert_eq!(
        t["requests"].as_u64(),
        Some(1),
        "GET /models must not be counted (USAGE-5): {s}"
    );
    assert_eq!(t["requests_without_usage"].as_u64(), Some(0));
    // OpenAI 归一化: prompt_tokens(100) - cached(30) = input 70; cr=30; out=50.
    assert_eq!(t["input"].as_u64(), Some(70));
    assert_eq!(t["cache_read"].as_u64(), Some(30));
    assert_eq!(t["output"].as_u64(), Some(50));
    // by_model: 回显 model 优先于请求 model (gpt-req).
    let m0 = &s["by_model"][0];
    assert_eq!(
        m0["model"].as_str(),
        Some("gpt-echoed"),
        "echo model wins: {s}"
    );
    assert_eq!(m0["provider"].as_str(), Some("oa-mock"));

    // 6. SQLite 持久化: flush 屏障 (writer 线程批量落库) 后, 重开同一路径的
    //    store, 明细行应恢复 (USAGE-1 持久一致性 — SQL 直查, 明细即真相).
    store.flush_for_test();
    let store2 = secret_guard::usage::UsageStore::open(
        &secret_guard::config::UsageConfig {
            enabled: true,
            retention_days: 90,
            ..Default::default()
        },
        &db,
    );
    assert_eq!(store2.total_events(), 1, "row must persist in sqlite");
    let cells = store2.query_cells("", secret_guard::usage::Granularity::Hour);
    assert_eq!(cells.len(), 1);
    let ((_, provider, model), agg) = &cells[0];
    assert_eq!(provider, "oa-mock");
    assert_eq!(
        model.as_deref(),
        Some("gpt-echoed"),
        "echo model wins in persisted row"
    );
    assert_eq!(agg.input, 70);
    assert_eq!(agg.cache_read, 30);
    assert_eq!(agg.output, 50);
    let _ = std::fs::remove_file(&db);
}

/// 流式采集 E2E (USAGE-2/5): OpenAI 流式 + include_usage 终末 chunk → usage 落账.
/// 链路: StreamScan 累积 (MessageStop 之后的 usage chunk) → ParsedSync.finalize
/// 回显摘要 → UsageCtx 落账 → summary.
#[tokio::test]
async fn usage_stats_streaming_include_usage_recorded() {
    let mut server = mockito::Server::new_async().await;
    // SSE 帧: 每帧 data: 后必须是**单行** JSON (跨行续行会被 SSE 协议丢弃).
    let c1 = r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-s","choices":[{"index":0,"delta":{"role":"assistant","content":"he"},"finish_reason":null}]}"#;
    let c2 = r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-s","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#;
    let c3 = r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-s","choices":[],"usage":{"prompt_tokens":42,"completion_tokens":7}}"#;
    let sse = format!("data: {c1}\n\ndata: {c2}\n\ndata: {c3}\n\ndata: [DONE]\n\n");
    let _m = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse)
        .create_async()
        .await;

    let (store, db) = usage_e2e_store("usage-s-e2e");
    let base = spawn_proxy_with_usage_store(store).await;
    let client = reqwest::Client::new();
    let create = serde_json::json!({
        "id": "oa-mock", "enabled": true, "protocol": "openai",
        "base_url": server.url(), "api_key": "sk-x"
    });
    let resp = client
        .post(format!("{base}/api/providers"))
        .json(&create)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let chat = client
        .post(format!("{base}/o/oa-mock/v1/chat/completions"))
        .json(&serde_json::json!({"model": "gpt-s", "stream": true,
            "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert!(chat.status().is_success());
    // 读完流 (spawn task 在流结束后 attach + 落账).
    use futures::StreamExt;
    let mut stream = chat.bytes_stream();
    while let Some(_c) = stream.next().await {}

    let s = poll_usage_summary(&client, &base, |s| {
        s["totals"]["requests"].as_u64() == Some(1)
    })
    .await;
    assert_eq!(
        s["totals"]["input"].as_u64(),
        Some(42),
        "include_usage chunk collected: {s}"
    );
    assert_eq!(s["totals"]["output"].as_u64(), Some(7));
    let _ = std::fs::remove_file(&db);
}

/// cross_proto 采集 E2E: anthropic ingress → openai 上游, 回显 usage 经 egress reader
/// 归一化 (OpenAI→IR) 后落账; 响应侧翻译回 anthropic envelope 不影响 usage.
#[tokio::test]
async fn usage_stats_cross_proto_recorded() {
    let mut server = mockito::Server::new_async().await;
    let oai_body = serde_json::json!({
        "id": "chatcmpl-x", "model": "gpt-cross",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "yo"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4}
    });
    let _m = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&oai_body).unwrap())
        .create_async()
        .await;

    let (store, db) = usage_e2e_store("usage-x-e2e");
    let base = spawn_proxy_with_usage_store(store).await;
    let client = reqwest::Client::new();
    let create = serde_json::json!({
        "id": "oa-mock", "enabled": true, "protocol": "openai",
        "base_url": server.url(), "api_key": "sk-x"
    });
    let resp = client
        .post(format!("{base}/api/providers"))
        .json(&create)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // anthropic 协议 ingress (path /a/...), 上游是 openai → cross_proto 路径.
    let resp = client
        .post(format!("{base}/a/oa-mock/v1/messages"))
        .header("x-api-key", "ignored")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({"model": "gpt-cross", "max_tokens": 32,
            "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let s = poll_usage_summary(&client, &base, |s| {
        s["totals"]["requests"].as_u64() == Some(1)
    })
    .await;
    assert_eq!(
        s["totals"]["input"].as_u64(),
        Some(10),
        "egress reader normalization: {s}"
    );
    assert_eq!(s["totals"]["output"].as_u64(), Some(4));
    assert_eq!(s["by_model"][0]["model"].as_str(), Some("gpt-cross"));
    let _ = std::fs::remove_file(&db);
}

// ─── SEC-1: 读端点穷举扫描 (real secret / provider api_key 永不泄漏) ────────
//
// 契约: `prop_no_real_secret_in_any_json_response` /
// `prop_no_real_api_key_in_any_json_response` (contracts.md SEC-1, P0).
// 现状只有点状断言 (单端点单字段 mask), 穷举式扫描保证任何端点 / 任何字段
// (含 ForwardRecord / SessionSummary / SyncSnapshot / usage 聚合) 都不含明文.

/// SEC-1 植入敏感值 (setup 植入与扫描 needle 同源 — 改一处即处处改, 防止
/// needle 与植入值漂移导致扫描恒空过的 vacuous 绿).
/// 约束: 值只含 JSON 序列化无需转义的字符 (否则响应序列化后子串形态改变会漏检).
const SEC1_SECRET: &str = "sk-real-secret-abc123xyz";
const SEC1_API_KEY: &str = "sk-live-provider-key-777xyz";

/// SEC-1 扫描共享前置: 构造 "record / session / usage / redact 审计全有数据"
/// 的实例 — 1 个 secret + 1 个带 api_key 的 dynamic provider (mockito 上游) +
/// 1 次带 secret 的转发. 返回 (client, base, db) — db 供测试末尾清理.
async fn sec1_scan_setup(tag: &str) -> (reqwest::Client, String, std::path::PathBuf) {
    let mut upstream = spawn_mock_upstream().await;
    let chat_body = serde_json::json!({
        "id": "chatcmpl-sec1",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                     "finish_reason": "stop"}]
    });
    let _chat = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&chat_body).unwrap())
        .create_async()
        .await;

    let (store, db) = usage_e2e_store(tag);
    let base = spawn_proxy_with_usage_store_and_secrets(
        store,
        test_secret_table_with(vec![secret("sec1", SEC1_SECRET)]),
    )
    .await;
    let client = reqwest::Client::new();

    // provider 显式带 api_key (明文落 state.toml, GET 必须返回 mask).
    let create = serde_json::json!({
        "id": "oa-sec1", "enabled": true, "protocol": "openai",
        "base_url": upstream.url(), "api_key": SEC1_API_KEY
    });
    let resp = client
        .post(format!("{base}/api/providers"))
        .json(&create)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "create provider");

    // 1 次带 secret 的转发 → record / session / usage / redact_events 均有数据.
    let chat = client
        .post(format!("{base}/o/oa-sec1/v1/chat/completions"))
        .json(&serde_json::json!({"model": "gpt-4", "messages": [
            {"role": "user", "content": format!("use {SEC1_SECRET} to call api")}]}))
        .send()
        .await
        .unwrap();
    assert!(chat.status().is_success());

    // 等待 usage 事件落库 (writer 线程异步) — 数据面全部就绪后再扫描.
    poll_usage_summary(&client, &base, |s| {
        s["totals"]["requests"].as_u64().is_some_and(|n| n >= 1)
    })
    .await;

    (client, base, db)
}

/// 遍历全部 JSON API 读端点, 返回 (label, body) 列表.
///
/// 端点清单以 `src/web/mod.rs` 实际路由为准 (全部 GET + 数据面聚合 POST /api/sync;
/// 无 GET /api/records 列表端点 — record 经 timeline/sync 暴露). 含路径参数的端点
/// 从 sessions / timeline 响应派生真实 id (setup 保证 ≥1 session/round, 故用
/// expect fail-closed — if-let 静默跳过会让扫描面收窄而测试照绿); 所有端点断言
/// 2xx (非 2xx 的错误 body 无扫描价值, 且会静默弱化穷举).
async fn sec1_read_all_endpoints(client: &reqwest::Client, base: &str) -> Vec<(String, String)> {
    async fn fetch(client: &reqwest::Client, base: &str, path: &str) -> (String, String) {
        let resp = client.get(format!("{base}{path}")).send().await.unwrap();
        assert!(
            resp.status().is_success(),
            "GET {path} should be 2xx, got {}",
            resp.status()
        );
        (path.to_string(), resp.text().await.unwrap())
    }

    let mut out: Vec<(String, String)> = vec![
        fetch(client, base, "/api/secrets").await,
        fetch(client, base, "/api/providers").await,
        fetch(client, base, "/api/api-keys").await,
        fetch(client, base, "/api/usage/summary?hours=24").await,
    ];
    let (sessions_label, sessions_body) = fetch(client, base, "/api/sessions").await;
    let sessions: serde_json::Value = serde_json::from_str(&sessions_body).unwrap();
    out.push((sessions_label, sessions_body));
    let sid = sessions["sessions"][0]["session_id"]
        .as_str()
        .expect("setup 保证 ≥1 session (已成功转发)");
    let timeline_path = format!("/api/sessions/{sid}/timeline");
    let (timeline_label, timeline_body) = fetch(client, base, &timeline_path).await;
    let timeline: serde_json::Value = serde_json::from_str(&timeline_body).unwrap();
    out.push((timeline_label, timeline_body));
    let rid = timeline["rounds"][0]["id"]
        .as_str()
        .expect("setup 保证 ≥1 round (已成功转发)");
    out.push(fetch(client, base, &format!("/api/records/{rid}")).await);
    out.push(fetch(client, base, &format!("/api/records/{rid}?view=parsed")).await);
    // sync: 数据面聚合 DTO (sessions + rounds + timeline diff 一次拿全).
    let sync_resp = client
        .post(format!("{base}/api/sync"))
        .json(&serde_json::json!({
            "selected": {"session_id": sid, "latest_round": null, "response_length": 0},
            "expanded": [sid]
        }))
        .send()
        .await
        .unwrap();
    assert!(
        sync_resp.status().is_success(),
        "POST /api/sync should be 2xx"
    );
    out.push((
        "POST /api/sync".to_string(),
        sync_resp.text().await.unwrap(),
    ));
    out
}

/// 遍历全部读端点, 返回 body 含 `needle` 明文的端点 label 列表 (空 = 通过).
/// needle 须为 JSON 序列化后原样保留的子串 (植入值见 SEC1_* 常量约束).
async fn sec1_scan_leaks(client: &reqwest::Client, base: &str, needle: &str) -> Vec<String> {
    sec1_read_all_endpoints(client, base)
        .await
        .into_iter()
        .filter(|(_, body)| body.contains(needle))
        .map(|(label, _)| label)
        .collect()
}

/// SEC-1 `prop_no_real_secret_in_any_json_response`:
/// 任意读端点响应体不含配置的 real secret 明文 (穷举式扫描, 非点状 mask 断言).
#[tokio::test]
async fn prop_no_real_secret_in_any_json_response() {
    let (client, base, db) = sec1_scan_setup("sec1-secret").await;
    let leaks = sec1_scan_leaks(&client, &base, SEC1_SECRET).await;
    assert!(leaks.is_empty(), "SEC-1: real secret leaks via: {leaks:?}");
    let _ = std::fs::remove_file(&db);
}

/// SEC-1 `prop_no_real_api_key_in_any_json_response`:
/// 任意读端点响应体不含 provider 的 api_key 明文 (同上, api_key 维度).
#[tokio::test]
async fn prop_no_real_api_key_in_any_json_response() {
    let (client, base, db) = sec1_scan_setup("sec1-apikey").await;
    let leaks = sec1_scan_leaks(&client, &base, SEC1_API_KEY).await;
    assert!(
        leaks.is_empty(),
        "SEC-1: provider api_key leaks via: {leaks:?}"
    );
    let _ = std::fs::remove_file(&db);
}

// ─── SEC-7: Host guard / Origin 校验 (防 DNS rebinding + CSRF 纵深) ─────────
//
// 白名单语义的单元级覆盖在 src/server_host_guard.rs; 此处验证全链路接线:
// middleware 挂载在最外层, 对所有路由生效 (含 `/` WebUI 与 `/api/*`).
// 负例 Host 校验用裸 socket — reqwest 以 URL 派生 Host, 覆盖语义不保证.

/// SEC-7 专用 spawn: 最小 AppState + 带 Host guard 的 Router (与生产 serve()
/// 同构 — guard 用实际监听 port 构造), 返回 (base_url, addr).
/// `allowed_domains`: `[server] allowed_domains` 的直通 (域名白名单).
async fn spawn_guarded(
    config_host: &str,
    allowed_domains: &[&str],
) -> (String, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("sg-state-hostguard");
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));
    let provider_table =
        ProviderTable::with_persist_lock(vec![], vec![], decisions, state_path, persist_lock);
    let proxy = base_app_state(
        reqwest::Client::new(),
        provider_table,
        ConversationDag::new(64, 500, 1),
        test_secret_table(),
    );
    let app = server::build_router(
        proxy,
        secret_guard::server_host_guard::HostGuard::new(config_host, addr.port())
            .allow_domains(allowed_domains.iter().copied()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), addr)
}

/// 裸 HTTP/1.1 请求 (精确控制 Host header), 返回响应 status code.
/// `Connection: close` 让服务器主动关连接, read_to_end 以 EOF 终止.
async fn raw_http_status(addr: std::net::SocketAddr, request: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _n = sock.read_to_end(&mut buf).await;
    let head = String::from_utf8_lossy(&buf);
    head.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("malformed HTTP response: {head}"))
}

#[tokio::test]
async fn host_guard_rejects_domain_host_on_all_routes() {
    let (_base, addr) = spawn_guarded("127.0.0.1", &[]).await;
    // rebinding 载体: 域名形式 Host 一律 403 — WebUI 根路径 / /api/* / 转发族.
    // guard 包裹所有 route 与 fallback service (axum Router::layer 语义), 先于
    // handler 执行 — /o/p 未配 provider 本应 404, 收到 403 即证明 guard 生效,
    // 断言语义不依赖具体 handler 的路由匹配结果.
    for target in ["/", "/api/sessions", "/o/p"] {
        let status = raw_http_status(
            addr,
            &format!(
                "GET {target} HTTP/1.1\r\nHost: attacker.com:{}\r\nConnection: close\r\n\r\n",
                addr.port()
            ),
        )
        .await;
        assert_eq!(status, 403, "domain Host must be rejected on {target}");
    }
    // port 不匹配的合法 IP Host 同样拒绝
    let status = raw_http_status(
        addr,
        &format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            addr.port() + 1
        ),
    )
    .await;
    assert_eq!(status, 403, "port-mismatched Host must be rejected");
}

#[tokio::test]
async fn host_guard_allows_loopback_host() {
    let (base, addr) = spawn_guarded("127.0.0.1", &[]).await;
    let client = reqwest::Client::new();
    // reqwest 从 URL 派生 Host = 127.0.0.1:port → 放行
    let resp = client
        .get(format!("{base}/api/sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // 裸请求显式验证 localhost 形态 + 空 host 形态
    for host in [
        format!("localhost:{}", addr.port()),
        format!("127.0.0.1:{}", addr.port()),
        format!(":{}", addr.port()),
    ] {
        let status = raw_http_status(
            addr,
            &format!("GET /api/sessions HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 200, "Host {host} should be allowed");
    }
}

#[tokio::test]
async fn api_post_rejects_cross_origin() {
    let (base, _addr) = spawn_guarded("127.0.0.1", &[]).await;
    let client = reqwest::Client::new();
    // 恶意 Origin (host 不在白名单) → 403
    let resp = client
        .post(format!("{base}/api/sync"))
        .header("Origin", "http://attacker.com:8080")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "cross-origin API write must be rejected"
    );
    // Sec-Fetch-Site: cross-site → 403
    let resp = client
        .post(format!("{base}/api/sync"))
        .header("Sec-Fetch-Site", "cross-site")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "cross-site API write must be rejected");
    // Origin: null (沙箱 iframe / 隐私上下文) → 403
    let resp = client
        .post(format!("{base}/api/sync"))
        .header("Origin", "null")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "Origin: null must be rejected");
}

#[tokio::test]
async fn api_post_allows_missing_or_same_origin_headers() {
    let (base, addr) = spawn_guarded("127.0.0.1", &[]).await;
    let client = reqwest::Client::new();
    // 非浏览器 SDK: 两个 header 都缺 → 放行
    let resp = client
        .post(format!("{base}/api/sync"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "SDK without Origin must pass");
    // 浏览器同源: Origin = 本机白名单 + Sec-Fetch-Site: same-origin → 放行
    let resp = client
        .post(format!("{base}/api/sync"))
        .header("Origin", format!("http://127.0.0.1:{}", addr.port()))
        .header("Sec-Fetch-Site", "same-origin")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "same-origin browser write must pass");
    // Sec-Fetch-Site: none (用户直接发起, 如地址栏/书签) → 放行
    let resp = client
        .post(format!("{base}/api/sync"))
        .header("Sec-Fetch-Site", "none")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "Sec-Fetch-Site: none must pass");
    // GET 不校验 Origin (安全方法豁免 — 恶意 Origin 的 GET 放行, 泄漏由 SEC-1 守卫)
    let resp = client
        .get(format!("{base}/api/sessions"))
        .header("Origin", "http://attacker.com:8080")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "GET must skip Origin check");
}

/// SEC-7 域名白名单 (`[server] allowed_domains`): 声明的信任域名放行 (端口宽松,
/// 反代 + 域名部署形态), 未声明域名仍 403 (rebinding 攻击域名进不了名单)。
#[tokio::test]
async fn allowed_domains_lets_declared_domain_pass_and_others_reject() {
    let (_base, addr) = spawn_guarded("127.0.0.1", &["sg.example.com", "sg.lan"]).await;
    // 声明域名: 无端口 (反代 proxy_set_header Host $host 形态) → 放行
    assert_eq!(
        raw_http_status(
            addr,
            "GET /api/sessions HTTP/1.1\r\nHost: sg.example.com\r\nConnection: close\r\n\r\n"
        )
        .await,
        200
    );
    // 声明域名: 保留外部端口 ($http_host 形态) → 放行
    assert_eq!(
        raw_http_status(
            addr,
            "GET /api/sessions HTTP/1.1\r\nHost: sg.lan:8443\r\nConnection: close\r\n\r\n"
        )
        .await,
        200
    );
    // 未声明域名 (rebinding 载体) → 仍 403
    assert_eq!(
        raw_http_status(
            addr,
            "GET /api/sessions HTTP/1.1\r\nHost: attacker.com\r\nConnection: close\r\n\r\n"
        )
        .await,
        403
    );
    // 声明域名的浏览器写: /api/* POST 带 https://sg.example.com Origin → 放行
    // (reqwest 经 IP URL 连接, 手动覆盖 Origin 模拟反代后浏览器).
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/sync"))
        .header("Host", "sg.example.com")
        .header("Origin", "https://sg.example.com")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "declared-domain Origin write must pass");
}

/// SEC-S1 (nosniff): WebUI `/` 与 `/api/*` 响应必须带 `x-content-type-options:
/// nosniff` (NO_STORE header 组成员)。转发链响应**不带** — 由 FWD-1 byte-exact
/// 契约 (fwd_* property 族) 隐式守卫, 网关不向上游响应追加 header。
#[tokio::test]
async fn webui_and_api_responses_carry_nosniff() {
    let (base, _addr) = spawn_guarded("127.0.0.1", &[]).await;
    let client = reqwest::Client::new();
    for (label, url) in [
        ("webui html", format!("{base}/")),
        ("api json", format!("{base}/api/sessions")),
        ("api 404 fallback", format!("{base}/api/nonexistent")),
    ] {
        let resp = client.get(&url).send().await.unwrap();
        let nosniff = resp
            .headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok());
        assert_eq!(nosniff, Some("nosniff"), "{label} must carry nosniff");
    }
}

/// SEC-3 (SEC-C4a): http.request trace span 只记 path 不记 query — 用
/// FmtSpan::NEW 捕获 span 创建行 (渲染 span 字段), 断言敏感 query 不进日志。
/// (server.rs 的 `trace_span_no_query_string` 单测只锁定 Uri::path() 性质,
/// 本测试锁定 span 字段的实际接线。)
#[tokio::test]
async fn trace_span_omits_query_string() {
    // capture_tracing 变体: 追加 span 创建事件, 让 span 字段可被文本断言。
    let log = CaptureLog::new();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .with_writer({
            let log = log.clone();
            move || log.clone()
        })
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (base, _addr) = spawn_guarded("127.0.0.1", &[]).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/api/sessions?api-key=sk-probe-secret&x=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = log.text();
    assert!(
        text.contains("path=/api/sessions"),
        "span must record path field, got: {text}"
    );
    assert!(
        !text.contains("sk-probe-secret"),
        "span must not carry query string, got: {text}"
    );
}
