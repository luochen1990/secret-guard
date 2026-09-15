//! #196: router provider 原生 GET /models 的集成测试.
//!
//! 覆盖 (对应 contracts.md FWD-7, brief §3.2):
//! - default-plan 主验收: 别名(路由表序) + 过滤后上游模型(walk 序 × 上游序) 有序合并;
//! - 缓存: 同 server 连续两次查询, 每个 upstream mock 恰命中 1 次;
//! - exact-only router: 零上游请求 + 响应只含别名 (N6);
//! - 上游 fetch 500: 响应仍 200 仅别名; 再次查询仍 200 (best-effort, ROB);
//! - Direct provider 回归: /models 透传 byte-exact, 不进缓存;
//! - 嵌套 router + 链上 disabled target 不贡献;
//! - Anthropic ingress 的响应 shape;
//! - D5: /models 查询不产生 DAG session.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use secret_guard::provider::{
    DirectProvider, Protocol, Provider, ProviderKind, ProviderTable, Route, RouterProvider,
};
use secret_guard::proxy::ModelListCache;
use secret_guard::server;
use secret_guard::state::AppState;
use tokio::net::TcpListener;

// ─── helpers (参考 tests/integration.rs 的既有形态, 仅保留本文件所需子集) ────

fn tmp_state_path(label: &str) -> std::path::PathBuf {
    let id = uuid::Uuid::new_v4().to_string();
    let path = std::path::PathBuf::from(format!("/tmp/opencode/tmp/test-rm-{label}-{id}.toml"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

fn test_api_key_store() -> secret_guard::auth::ApiKeyStore {
    secret_guard::auth::ApiKeyStore::new(
        &[],
        std::path::Path::new("."),
        vec![],
        std::collections::HashSet::new(),
        tmp_state_path("api-keys"),
        Arc::new(parking_lot::Mutex::new(())),
    )
}

fn test_secret_table() -> secret_guard::secrets::SecretTable {
    let decisions = Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    secret_guard::secrets::SecretTable::new(vec![], vec![], decisions, tmp_state_path("secrets"))
}

fn openai_provider(id: &str, base_url: &str) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Direct(DirectProvider {
            protocol: Protocol::OpenAI,
            base_url: base_url.into(),
            api_key: String::new(),
            api_key_file: None,
        }),
    }
}

fn anthropic_provider(id: &str, base_url: &str) -> Provider {
    Provider {
        kind: ProviderKind::Direct(DirectProvider {
            protocol: Protocol::Anthropic,
            base_url: base_url.into(),
            api_key: String::new(),
            api_key_file: None,
        }),
        ..openai_provider(id, base_url)
    }
}

fn route(pattern: &str, target: &str, priority: i64) -> Route {
    Route {
        model_pattern: pattern.into(),
        target: target.into(),
        upstream_model: None,
        priority: Some(priority),
    }
}

fn rewrite_route(pattern: &str, target: &str, model: &str, priority: i64) -> Route {
    Route {
        upstream_model: Some(model.into()),
        ..route(pattern, target, priority)
    }
}

fn router_provider(id: &str, routes: Vec<Route>) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Router(RouterProvider { routes }),
    }
}

/// 启动 secret-guard (providers 视为 dynamic 层), 返回 proxy url.
async fn spawn(providers: Vec<Provider>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("state");
    let decisions = Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = Arc::new(parking_lot::Mutex::new(()));
    let provider_table =
        ProviderTable::with_persist_lock(providers, vec![], decisions, state_path, persist_lock);
    let redact = secret_guard::config::RedactConfig::default();
    let proxy = AppState {
        upstream: reqwest::Client::new(),
        providers: provider_table,
        dag: secret_guard::dag::ConversationDag::new(64, 500, 1),
        secrets: test_secret_table(),
        api_keys: test_api_key_store(),
        auth_enabled: false,
        global_mock_prefix: Arc::from(""),
        // [redact] 三 gate 镜像生产默认 (SEC-10); 本 harness 不触降级路径.
        on_probe_exhausted: redact.on_probe_exhausted,
        on_unsupported_protocol: redact.on_unsupported_protocol,
        on_fallback_restore: redact.on_fallback_restore,
        // SEC-4: 镜像生产装配 (normalize 后入 state); 本 harness 无自定义名单.
        redacted_headers: secret_guard::state::normalize_redacted_headers(&redact.redacted_headers),
        upstream_timeouts: secret_guard::config::UpstreamTimeouts::default(),
        model_lists: Arc::new(ModelListCache::new()),
        usage: std::sync::Arc::new(secret_guard::usage::UsageStore::in_memory()),
        pricing: std::sync::Arc::new(secret_guard::usage::PricingCache::for_tests()),
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

async fn get(proxy_url: &str, path: &str) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}{path}"))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.text().await.unwrap())
}

/// 从响应 JSON 提取 `data[].id` (OpenAI / Anthropic shape).
fn model_ids(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_string())
        .collect()
}

async fn spawn_mock_upstream() -> mockito::ServerGuard {
    mockito::Server::new_async().await
}

// ─── 主验收用例 (default-plan 推演示例, brief §3.2 原样落地) ────────────────

/// 路由: ultra/flash/vision (exact + rewrite, prio 30) → glm-main;
/// glm-* (prio 20) → glm-main; * (prio 10) → glm-fallback.
/// 期望: [ultra, flash, vision, glm-4.7, glm-4.8-flash, glm-4.6v, glm-4.9, qwen-3]
/// (glm-4.7-air 被过滤: 匹配 glm-* 落 main, main 无它).
/// 同 server 连续两次查询, 每个 upstream mock 恰命中 1 次 (TTL 缓存).
/// D5: 查询不产生 DAG session.
#[tokio::test]
async fn router_models_default_plan_merge() {
    let mut main = spawn_mock_upstream().await;
    let mut fallback = spawn_mock_upstream().await;
    let main_mock = main
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"object":"list","data":[
                {"id":"glm-4.7"},{"id":"glm-4.8-flash"},{"id":"glm-4.6v"},{"id":"glm-4.9"}
            ]}"#,
        )
        .expect(1)
        .create_async()
        .await;
    let fallback_mock = fallback
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"object":"list","data":[{"id":"qwen-3"},{"id":"glm-4.7-air"}]}"#)
        .expect(1)
        .create_async()
        .await;

    let providers = vec![
        openai_provider("glm-main", &main.url()),
        openai_provider("glm-fallback", &fallback.url()),
        router_provider(
            "default-plan",
            vec![
                rewrite_route("ultra", "glm-main", "glm-4.7", 30),
                rewrite_route("flash", "glm-main", "glm-4.8-flash", 30),
                rewrite_route("vision", "glm-main", "glm-4.6v", 30),
                route("glm-*", "glm-main", 20),
                route("*", "glm-fallback", 10),
            ],
        ),
    ];
    let proxy = spawn(providers).await;

    let expected = [
        "ultra",
        "flash",
        "vision",
        "glm-4.7",
        "glm-4.8-flash",
        "glm-4.6v",
        "glm-4.9",
        "qwen-3",
    ];
    for _ in 0..2 {
        let (status, body) = get(&proxy, "/o/default-plan/v1/models").await;
        assert_eq!(status, 200, "body: {body}");
        let ids = model_ids(&body);
        assert_eq!(
            ids, expected,
            "default-plan 合并序 (别名 → walk 序 × 上游序, 遮蔽过滤): {body}"
        );
        // N5: owned_by 统一 "router", 不泄漏内部 provider id.
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            v["data"]
                .as_array()
                .unwrap()
                .iter()
                .all(|m| m["owned_by"] == "router")
        );
    }
    // 缓存: 两次查询, 每个 upstream 恰命中 1 次.
    main_mock.assert_async().await;
    fallback_mock.assert_async().await;

    // D5: /models 查询不产生 DAG session.
    let (status, body) = get(&proxy, "/api/sessions").await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["total"], 0,
        "router /models 本地终结 + cache-fill fetch 都不进 DAG (D5): {body}"
    );
}

// ─── N6: exact-only router 零上游请求 ───────────────────────────────────────

#[tokio::test]
async fn router_models_exact_only_skips_upstream() {
    let mut upstream = spawn_mock_upstream().await;
    let mock = upstream
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"should-not-appear"}]}"#)
        // expect(0): exact-only router 必须零 fetch (N6 gate).
        .expect(0)
        .create_async()
        .await;

    let providers = vec![
        openai_provider("direct-a", &upstream.url()),
        router_provider("exact-only", vec![route("foo", "direct-a", 30)]),
    ];
    let proxy = spawn(providers).await;

    // 两个 ingress 路径形态都拦截 ("/models" 与 "/v1/models"), 都零 fetch;
    // query 参数忽略 (Anthropic ?limit= 之类不影响拦截判定)。
    for path in [
        "/o/exact-only/v1/models",
        "/o/exact-only/models",
        "/o/exact-only/v1/models?limit=1",
    ] {
        let (status, body) = get(&proxy, path).await;
        assert_eq!(
            status, 200,
            "exact-only 不再 503 (GET 无 body 不再 NoMatch): {body}"
        );
        assert_eq!(model_ids(&body), ["foo"], "只含别名: {body}");
    }
    mock.assert_async().await;
}

// ─── 上游 fetch 失败: best-effort, 永不 fail 查询 (ROB) + 失败退避 (M1) ──────

/// 失败退避语义 (M1): 首次 fetch 500 → 响应仍 200 仅别名 (best-effort);
/// 退避窗口 (prod 30s) 内的后续查询**立即**返回, 不再重试 (mockito 恰命中 1 次),
/// 不被 dead upstream 逐查询阻塞. 窗口过后允许重试的行为由单测覆盖
/// (`model_list_cache_failure_backoff_blocks_retry_within_window`, cfg(test) 短退避).
#[tokio::test]
async fn router_models_upstream_error_serves_aliases_only() {
    let mut upstream = spawn_mock_upstream().await;
    let mock = upstream
        .mock("GET", "/v1/models")
        .with_status(500)
        .with_body("internal error")
        // 首查触发一次 fetch; 退避窗口内的第二次查询不再 fetch.
        .expect(1)
        .create_async()
        .await;

    let providers = vec![
        openai_provider("direct-a", &upstream.url()),
        router_provider(
            "with-wildcard",
            vec![route("foo", "direct-a", 30), route("*", "direct-a", 10)],
        ),
    ];
    let proxy = spawn(providers).await;

    for i in 0..2 {
        let (status, body) = get(&proxy, "/o/with-wildcard/v1/models").await;
        assert_eq!(
            status,
            200,
            "上游 500 不 fail 查询 (第 {} 次): {body}",
            i + 1
        );
        assert_eq!(
            model_ids(&body),
            ["foo"],
            "fetch 失败 → 无数据降级, 仅别名 (第 {} 次): {body}",
            i + 1
        );
    }
    mock.assert_async().await;
}

// ─── Direct provider 回归: /models 透传不变 (byte-exact, 不进缓存) ──────────

#[tokio::test]
async fn direct_provider_models_passthrough_byte_exact() {
    let mut upstream = spawn_mock_upstream().await;
    let raw_body =
        r#"{"object":"list","data":[{"id":"x","object":"model","owned_by":"org","created":123}]}"#;
    let mock = upstream
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_body)
        // Direct 不缓存: 每次查询都透传上游.
        .expect(2)
        .create_async()
        .await;

    let proxy = spawn(vec![openai_provider("direct-a", &upstream.url())]).await;

    for _ in 0..2 {
        let (status, body) = get(&proxy, "/o/direct-a/v1/models").await;
        assert_eq!(status, 200);
        assert_eq!(body, raw_body, "Direct /models 必须上游字节原样透传 (D6)");
    }
    mock.assert_async().await;
}

// ─── 嵌套 router + 链上 disabled target 不贡献 ──────────────────────────────

#[tokio::test]
async fn nested_router_disabled_target_not_contributing() {
    let mut up_a = spawn_mock_upstream().await;
    let mut up_b = spawn_mock_upstream().await;
    let mock_a = up_a
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"a1"}]}"#)
        .expect(1)
        .create_async()
        .await;
    let mock_b = up_b
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"b1"}]}"#)
        // disabled target 不被 fetch.
        .expect(0)
        .create_async()
        .await;

    let providers = vec![
        openai_provider("a", &up_a.url()),
        // enabled=false: top 的 x-* 路由指向它, 但它不贡献 (不 fetch, 不广告).
        Provider {
            enabled: false,
            ..openai_provider("b", &up_b.url())
        },
        router_provider("mid", vec![route("*", "a", 0)]),
        router_provider(
            "top",
            vec![
                // exact → disabled target: D2 过滤 (不可解析).
                route("dead", "b", 40),
                route("t-*", "mid", 20),
                route("x-*", "b", 30),
                route("*", "mid", 10),
            ],
        ),
    ];
    let proxy = spawn(providers).await;

    let (status, body) = get(&proxy, "/o/top/v1/models").await;
    assert_eq!(status, 200, "body: {body}");
    // "dead" 被 D2 过滤 (disabled target 不可解析); a1 经 *→mid 链解析进 a 的清单;
    // b 从未被 fetch / 广告.
    assert_eq!(
        model_ids(&body),
        ["a1"],
        "嵌套链贡献 a1, disabled b 不贡献: {body}"
    );
    mock_a.assert_async().await;
    mock_b.assert_async().await;
}

// ─── Anthropic ingress 的响应 shape ────────────────────────────────────────

#[tokio::test]
async fn router_models_anthropic_ingress_shape() {
    let mut upstream = spawn_mock_upstream().await;
    // match_header: 锁定对 Anthropic 上游的 fetch 带 anthropic-version (M1 回归,
    // 缺失会被真实 Anthropic API 400 拒绝 → 该 provider 永无贡献).
    let _mock = upstream
        .mock("GET", "/v1/models")
        .match_header("anthropic-version", "2023-06-01")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"claude-1"},{"id":"claude-2"}]}"#)
        .create_async()
        .await;

    let providers = vec![
        anthropic_provider("anthropic-main", &upstream.url()),
        router_provider(
            "r",
            vec![
                route("alias", "anthropic-main", 30),
                route("*", "anthropic-main", 10),
            ],
        ),
    ];
    let proxy = spawn(providers).await;

    let (status, body) = get(&proxy, "/a/r/v1/models").await;
    assert_eq!(status, 200, "body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let data = v["data"].as_array().unwrap();
    assert_eq!(data.len(), 3);
    assert_eq!(data[0]["type"], "model");
    assert_eq!(data[0]["id"], "alias");
    assert_eq!(data[0]["display_name"], "alias");
    assert_eq!(data[0]["created_at"], "1970-01-01T00:00:00Z");
    assert_eq!(data[1]["id"], "claude-1");
    assert_eq!(v["has_more"], false);
}

// ─── single-flight: 并发查询不 stampede 上游 (M2, N4) ───────────────────────

/// 起一个"慢上游" axum server: GET /v1/models 先 sleep `delay` 再返回固定清单,
/// 每次请求对 `counter` +1 (命中计数).
async fn spawn_slow_models_upstream(
    delay: std::time::Duration,
    counter: Arc<AtomicUsize>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter_for_handler = counter.clone();
    let app = axum::Router::new().route(
        "/v1/models",
        axum::routing::get(move || {
            let counter = counter_for_handler.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                (
                    [("content-type", "application/json")],
                    r#"{"data":[{"id":"slow-1"}]}"#,
                )
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// M2: single-flight — 两个并发 /models 查询, 首个 fetch 进行中到达第二个时,
/// 上游**恰被命中 1 次** (等锁者随后读新鲜缓存), 两响应一致. 若退化成 stampede
/// (并发各自 fetch), 计数会 ≥ 2, 本测试红.
#[tokio::test]
async fn router_models_single_flight_under_concurrency() {
    let hits = Arc::new(AtomicUsize::new(0));
    let base =
        spawn_slow_models_upstream(std::time::Duration::from_millis(200), hits.clone()).await;

    let providers = vec![
        openai_provider("slow", &base),
        router_provider("sf-router", vec![route("*", "slow", 10)]),
    ];
    let proxy = spawn(providers).await;

    let (first, second) = tokio::join!(
        get(&proxy, "/o/sf-router/v1/models"),
        get(&proxy, "/o/sf-router/v1/models"),
    );
    for (label, (status, body)) in [("first", first), ("second", second)] {
        assert_eq!(status, 200, "{label}: {body}");
        assert_eq!(model_ids(&body), ["slow-1"], "{label} 响应一致: {body}");
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "single-flight: 并发查询对同一上游恰发起一次 fetch"
    );
}
