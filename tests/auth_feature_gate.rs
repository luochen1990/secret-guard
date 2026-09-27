//! 默认档 (无 `oidc` feature, #276) 的行为守卫.
//!
//! 两个职责:
//! 1. **fail-fast**: `[auth] enabled = true` + 默认档二进制 → 启动报错退出,
//!    信息含 "rebuild with --features oidc" (serve() 入口的 AuthConfig::validate,
//!    先例: oidc.issuer_url Discovery fail-fast). 单元级 (validate 直调) 由
//!    src/auth/mod.rs::enabled_true_without_oidc_feature_fails_fast 守卫, 本文件
//!    锁定 **启动路径** 真的调了它 (防未来重构把 validate 挪出启动链).
//! 2. **冒烟**: 启动 (build_router 装配) + 转发 + API key 路径的最小集成 —
//!    证明默认档砍掉 OIDC 后, 核心网关路径完整. 全量行为契约由
//!    tests/integration.rs (两档共跑) 承担, 此处不重复.
//!
//! 全量档 (`--features oidc`) 下本文件整体 cfg 掉 — 测试对象只存在于默认档.

#![cfg(not(feature = "oidc"))]

use std::sync::Arc;

use secret_guard::auth::AuthConfig;
use secret_guard::dag::ConversationDag;
use secret_guard::provider::{DirectProvider, Endpoint, Provider, ProviderKind, ProviderTable};
use secret_guard::secrets::SecretTable;
use secret_guard::server;
use secret_guard::state::AppState;

/// ─── fail-fast: 启动路径拒绝 enabled=true ───────────────────────────────

#[tokio::test]
async fn serve_rejects_auth_enabled_without_oidc_feature() {
    let auth_config = AuthConfig {
        enabled: true,
        // oidc 段配齐合法值: 证明错误源于 feature 缺失而非配置缺失.
        oidc: Some(secret_guard::auth::OidcConfig {
            issuer_url: "https://idp.example.com".into(),
            client_id: "sg".into(),
            client_secret_file: None,
            redirect_url: None,
        }),
        ..Default::default()
    };
    let err = server::serve(
        "127.0.0.1",
        0, // 不会真的 bind — validate 在 bind 之前失败
        16,
        vec![],
        vec![],
        secret_guard::config::DynamicState::default(),
        "/tmp/opencode/sg-gate-state.toml".into(),
        "/tmp/opencode/sg-gate-config.toml".into(),
        auth_config,
        secret_guard::config::RedactConfig::default(),
        secret_guard::config::UpstreamTimeouts::default(),
        secret_guard::config::UsageConfig::default(),
        vec![],
    )
    .await
    .expect_err("serve must fail fast when [auth] enabled without oidc feature");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("rebuild with --features oidc"),
        "error must tell user how to rebuild, got: {msg}"
    );
}

/// ─── 冒烟: 默认档的启动 + 转发 + API key 路径 ──────────────────────────
/// 最小 AppState (镜像 integration.rs::base_app_state, 字段语义注释见彼处).
fn minimal_app_state(upstream: reqwest::Client, providers: ProviderTable) -> AppState {
    let redact = secret_guard::config::RedactConfig::default();
    AppState {
        pools: secret_guard::pool::PoolStates::new(),
        upstream,
        providers,
        dag: ConversationDag::new(64, 500, 1),
        secrets: SecretTable::new(
            vec![],
            vec![],
            Arc::new(parking_lot::RwLock::new(
                secret_guard::config::Decisions::default(),
            )),
            "/tmp/opencode/sg-gate-secrets.toml".into(),
        ),
        api_keys: secret_guard::auth::ApiKeyStore::new(
            &[],
            std::path::Path::new("."),
            vec![],
            std::collections::HashSet::new(),
            "/tmp/opencode/sg-gate-api-keys.toml".into(),
            Arc::new(parking_lot::Mutex::new(())),
        ),
        auth_enabled: false,
        global_mock_prefix: Arc::from(""),
        on_probe_exhausted: redact.on_probe_exhausted,
        on_unsupported_protocol: redact.on_unsupported_protocol,
        on_fallback_restore: redact.on_fallback_restore,
        redacted_headers: secret_guard::state::normalize_redacted_headers(&redact.redacted_headers),
        upstream_timeouts: secret_guard::config::UpstreamTimeouts::default(),
        model_lists: Arc::new(secret_guard::proxy::ModelListCache::new()),
        usage: Arc::new(secret_guard::usage::UsageStore::in_memory()),
        pricing: Arc::new(secret_guard::usage::PricingCache::for_tests()),
        audit_capture: secret_guard::state::AuditCapture::for_tests(
            secret_guard::config::AuditCaptureMode::Full,
        ),
        // shutdown flag: 本 harness 不消费 /api/events (sender drop 语义见
        // integration.rs::base_app_state 同字段注释).
        shutdown: tokio::sync::watch::channel(false).1,
    }
}

#[tokio::test]
async fn default_tier_smoke_startup_forward_and_api_key_path() {
    // 1. 启动: build_router 装配不 panic + listener 可服务.
    let mut upstream = mockito::Server::new_async().await;
    let provider = Provider {
        id: "oa-main".into(),
        enabled: true,
        name: None,
        kind: ProviderKind::Direct(DirectProvider {
            endpoints: vec![Endpoint {
                protocol: secret_guard::provider::Protocol::OpenAI,
                base_url: upstream.url().clone(),
                common_uri: None,
            }],
            api_key: String::new(),
            api_key_file: None,
        }),
    };
    let _mock = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"x","choices":[{"message":{"role":"assistant","content":"hi"}}]}"#)
        .create_async()
        .await;

    let state = minimal_app_state(
        reqwest::Client::new(),
        ProviderTable::new(
            vec![provider],
            vec![],
            Arc::new(parking_lot::RwLock::new(
                secret_guard::config::Decisions::default(),
            )),
            "/tmp/opencode/sg-gate-providers.toml".into(),
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = server::build_router(
        state,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // 2. 转发: 同协议透传路径 (无 secret 场景, 字节透传).
    let resp = client
        .post(format!("{base}/o/oa-main/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], "hi");

    // 3. API key 路径: ApiKeyStore 无条件构造 + /api/api-keys 无条件挂载
    //    (不 gate 的本地 key 路径, "只认证, 不隔离" 哲学).
    let resp = client
        .get(format!("{base}/api/api-keys"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["auth_enabled"], false, "default tier has auth off");

    // 4. OIDC 路由不存在: 单段路径 /login 无路由匹配 → axum 默认 404
    //    (与 docs/design/url-layout.md "默认档不编译此路由" 的承诺一致).
    let resp = client.get(format!("{base}/login")).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}
