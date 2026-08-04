//! OIDC 认证流程集成测试: 起本地 mock IdP server, 覆盖 `auth/oidc.rs` +
//! `auth/handlers.rs` 的完整 OIDC 流程 (discovery / token exchange / id_token 验证 /
//! login_start / oauth_callback / logout / me).
//!
//! # 为什么不用 mockito
//!
//! OIDC 流程涉及 3 个 endpoint 协作 (discovery + token + jwks), 且 discovery 返回的
//! metadata 里 URL 字段必须指向同一个 server 的实际端口. mockito 适合单 endpoint mock,
//! 多 endpoint 协作 + URL 自引用场景用 axum 直接起 server 更自然.
//!
//! # 为什么用 openidconnect 自己的 signing API 签 id_token
//!
//! 手拼 RS256 JWT 容易踩编码坑 (base64url-no-pad / 字段顺序 / 签名输入是
//! base64(header).base64(payload) 而非原文). openidconnect 内部生成 id_token 字节级
//! 兼容自己的 verifier, 故 mock IdP 直接用 `CoreRsaPrivateSigningKey` + `CoreIdToken::new`
//! 签 token, 把 `as_verification_key()` 派生的公钥放 JWKS, 全链路保证一致.
//!
//! # 覆盖契约
//!
//! - **RED-CRYPTO-1**: id_token 签名链路 (RS256 + JWKS 公钥验签) round-trip.
//! - **RED-CRYPTO-2**: nonce 精确匹配 (login 时生成, id_token 的 nonce claim 必须相等).
//! - **FWD-AUTH-1**: OidcBackend discover + exchange_and_verify happy path.
//! - **FWD-AUTH-2**: handlers login_start / oauth_callback / logout / me.
//! - **SEC-AUTH-1**: CSRF state mismatch / id_token 缺失 / 签名错误 均正确拒绝.

use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::extract::State as AxumState;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EndUserEmail, EndUserName, IssuerUrl, JsonWebKeyId,
    LocalizedClaim, Nonce, StandardClaims, SubjectIdentifier,
};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use secret_guard::auth::handlers::{AuthState, login_start, logout, me, oauth_callback};
use secret_guard::auth::oidc::{OidcBackend, OidcCredentials, OidcError};
use secret_guard::auth::{ApiKeyStore, build_session_layer};
use serde_json::json;
use tokio::net::TcpListener;

// AuthnBackend + PrivateSigningKey traits 在 scope: 前者调 get_user, 后者调
// as_verification_key (派生 JWKS 公钥).
use axum_login::AuthnBackend;
use openidconnect::PrivateSigningKey;

// ─── mock IdP 核心: 密钥 + 签名工具 ─────────────────────────────────────

/// 一次性生成一对 RSA 密钥 (主 + 野), 启动时 ~100ms.
///
/// 主密钥的公钥进 JWKS (供客户端验签), 野密钥不公布 (用于 WrongSignature 测试).
/// 两个都用 openidconnect 自己的 `CoreRsaPrivateSigningKey::from_pem` 包装,
/// 这样后续签 id_token 用 openidconnect 的 API, 字节级兼容其 verifier.
///
/// # 关键: 主/野密钥共用同一个 `kid`
///
/// WrongSignature 测试的目标是验证"签名比较失败" (SignatureDoesNotMatch), 而非
/// "JWKS 找不到 kid" (NoMatchingKey). 若两把密钥用不同 kid, openidconnect 在 JWKS
/// 按 kid 查不到野密钥的公钥, 直接报 NoMatchingKey 跳过签名比较 — 测试就无法
/// 守卫 RSA 签名验证逻辑本身. 让两把密钥共用 kid, openidconnect 会用 JWKS 里
/// 主密钥的公钥去验证野密钥签的 token, 命中签名 mismatch, 真正走完整验签路径.
struct IdpKeys {
    signing_key: CoreRsaPrivateSigningKey,
    rogue_key: CoreRsaPrivateSigningKey,
}

/// 主/野密钥共用的 key id (强制 WrongSignature 走签名比较而非 NoMatchingKey).
const SHARED_KID: &str = "test-key-1";

fn generate_keys() -> IdpKeys {
    let mut rng = OsRng;
    let main_priv = RsaPrivateKey::new(&mut rng, 2048).expect("gen main rsa key");
    let rogue_priv = RsaPrivateKey::new(&mut rng, 2048).expect("gen rogue rsa key");

    let main_pem = main_priv
        .to_pkcs1_pem(LineEnding::LF)
        .expect("main to pkcs1 pem");
    let rogue_pem = rogue_priv
        .to_pkcs1_pem(LineEnding::LF)
        .expect("rogue to pkcs1 pem");

    // 主/野密钥故意共用 kid — 详见 IdpKeys 文档.
    let kid = JsonWebKeyId::new(SHARED_KID.to_string());
    let signing_key =
        CoreRsaPrivateSigningKey::from_pem(&main_pem, Some(kid.clone())).expect("main from pem");
    let rogue_key =
        CoreRsaPrivateSigningKey::from_pem(&rogue_pem, Some(kid)).expect("rogue from pem");

    IdpKeys {
        signing_key,
        rogue_key,
    }
}

/// 用 openidconnect 自己的 API 签一个合法 RS256 id_token.
///
/// 关键不变量 (openidconnect 字符串精确校验, 必须三方一致):
/// - `issuer` == 客户端 discover 时传的 issuer
/// - `client_id` == 客户端 discover 时传的 client_id
/// - `nonce` == 客户端 authorize_url 生成并存 session 的 nonce
fn sign_id_token(
    signing_key: &CoreRsaPrivateSigningKey,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    sub: &str,
    email: Option<&str>,
    name: Option<&str>,
) -> String {
    let mut standard = StandardClaims::new(SubjectIdentifier::new(sub.to_string()));
    if let Some(e) = email {
        standard = standard.set_email(Some(EndUserEmail::new(e.to_string())));
        standard = standard.set_email_verified(Some(true));
    }
    if let Some(n) = name {
        standard = standard.set_name(Some(LocalizedClaim::from(EndUserName::new(n.to_string()))));
    }

    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(issuer.to_string()).expect("issuer url"),
        vec![Audience::new(client_id.to_string())],
        chrono::Utc::now() + chrono::Duration::seconds(3600),
        chrono::Utc::now(),
        standard,
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(nonce.to_string())));

    CoreIdToken::new(
        claims,
        signing_key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .expect("sign id token")
    .to_string()
}

// ─── mock IdP 状态 + server ────────────────────────────────────────────

/// /token 端点返回什么. 测试用 `set_token_policy` 注入, mock server 取出后构造响应.
#[derive(Clone)]
enum TokenPolicy {
    /// Happy path: 签合法 id_token, nonce 用登录时生成的值.
    Happy { nonce: String },
    /// 合法 token response 但 **不含** id_token 字段.
    NoIdToken,
    /// 合法 id_token 但 nonce claim 错误.
    WrongNonce { wrong_nonce: String },
    /// 合法 id_token 但用**另一把** (不公布 JWKS 的) 私钥签名.
    WrongSignature { nonce: String },
    /// HTTP 错误响应 (任意 status + body).
    Error { status: u16, body: String },
}

/// mock IdP 的共享状态 (跨多 handler 协作).
#[derive(Clone)]
struct IdpState {
    /// IdP 的 issuer URL (= server origin, 三处复用保证字符串相等).
    issuer: String,
    /// 客户端预期的 client_id (id_token aud claim 用).
    client_id: String,
    /// 主签名密钥 (公钥进 JWKS) + 野密钥 (WrongSignature 用). 静态共享 (跨所有测试,
    /// 避免每个测试重复生成 RSA 密钥对的 ~100ms 开销).
    keys: &'static IdpKeys,
    /// JWKS JSON (预序列化, /jwks 直接返回).
    jwks_json: String,
    /// 下一次 /token 请求的策略. 一次性 (取出即清, 防串扰).
    token_policy: Arc<Mutex<Option<TokenPolicy>>>,
    /// 所有收到的 /token 请求 body (PKCE verifier 断言用).
    token_requests: Arc<Mutex<Vec<String>>>,
}

/// 已启动的 mock IdP handle (测试用).
struct MockIdp {
    state: IdpState,
}

impl MockIdp {
    fn set_token_policy(&self, policy: TokenPolicy) {
        *self.state.token_policy.lock() = Some(policy);
    }

    /// 取出所有收到的 /token 请求 body (PKCE verifier round-trip 断言用).
    fn token_requests(&self) -> Vec<String> {
        self.state.token_requests.lock().clone()
    }

    fn issuer(&self) -> &str {
        &self.state.issuer
    }

    fn client_id(&self) -> &str {
        &self.state.client_id
    }
}

/// 启动 mock IdP server (返回控制 handle).
///
/// IdP endpoint 布局:
/// - `GET /.well-known/openid-configuration`: discovery metadata (issuer == self origin).
/// - `GET /jwks`: JWKS 公钥 (仅主密钥).
/// - `POST /token`: token exchange (按 token_policy 返回).
/// - `GET /authorize`: 占位 (OIDC flow 不会真访问, 因为客户端 login 直接重定向 IdP
///   但本测试不发真实授权请求; 此路由存在仅是为了 discovery metadata 字段合法).
async fn spawn_mock_idp() -> MockIdp {
    // 跨测试共享 RSA 密钥对 (避免每个测试重复 ~100ms 生成开销, ~13 个测试 → 省 ~1.3s).
    // 安全性: 密钥仅用于测试签 id_token, 不持有任何真实凭证; 共享不影响测试隔离性
    // (每个测试的 nonce/state/code 仍独立生成, 验签只关心公钥-签名匹配而非密钥独占).
    static SHARED_KEYS: OnceLock<IdpKeys> = OnceLock::new();
    let keys: &'static IdpKeys = SHARED_KEYS.get_or_init(generate_keys);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");

    let jwks = CoreJsonWebKeySet::new(vec![keys.signing_key.as_verification_key()]);
    let jwks_json = serde_json::to_string(&jwks).expect("serialize jwks");

    let state = IdpState {
        issuer: issuer.clone(),
        client_id: "test-client".to_string(),
        keys,
        jwks_json,
        token_policy: Arc::new(Mutex::new(None)),
        token_requests: Arc::new(Mutex::new(vec![])),
    };

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get({
                let iss = issuer.clone();
                move || async move { discovery_response(&iss) }
            }),
        )
        .route(
            "/jwks",
            get({
                let jwks = state.jwks_json.clone();
                move || std::future::ready(idp_json_response(&jwks))
            }),
        )
        .route("/token", post(handle_token).with_state(state.clone()))
        .route("/authorize", get(|| async { "authorize placeholder" }));

    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    MockIdp { state }
}

/// 构造 discovery metadata JSON (最小必填字段集).
///
/// 关键不变量: `issuer` 字段必须逐字符等于 server 的真实 origin (openidconnect
/// 字符串精确校验, 不做 URL 规范化).
fn discovery_response(issuer: &str) -> Response {
    let metadata = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    });
    idp_json_response(&metadata.to_string())
}

/// application/json 响应. openidconnect 严格要求 discovery/jwks 的 Content-Type.
fn idp_json_response(body: &str) -> Response {
    let mut resp = Response::new(body.to_string().into());
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// /token handler: 取出当前策略, 用 IdpState 的 key 签 id_token, 构造响应.
async fn handle_token(AxumState(state): AxumState<IdpState>, body: String) -> Response {
    state.token_requests.lock().push(body);

    let policy = state
        .token_policy
        .lock()
        .take()
        .unwrap_or(TokenPolicy::Error {
            status: 500,
            body: r#"{"error":"test setup: token_policy not set"}"#.to_string(),
        });

    match policy {
        TokenPolicy::Happy { nonce } => {
            let id_token = sign_id_token(
                &state.keys.signing_key,
                &state.issuer,
                &state.client_id,
                &nonce,
                "user-42",
                Some("alice@example.com"),
                Some("Alice"),
            );
            token_response_with_id_token(id_token)
        }
        TokenPolicy::NoIdToken => token_response_no_id_token(),
        TokenPolicy::WrongNonce { wrong_nonce } => {
            // nonce 故意错: 用 wrong_nonce 当 id_token 的 nonce claim, 但客户端
            // 会用真实 nonce 验证 → InvalidNonce.
            let id_token = sign_id_token(
                &state.keys.signing_key,
                &state.issuer,
                &state.client_id,
                &wrong_nonce,
                "user-42",
                Some("alice@example.com"),
                Some("Alice"),
            );
            token_response_with_id_token(id_token)
        }
        TokenPolicy::WrongSignature { nonce } => {
            // 用 rogue_key 签 (不公布 JWKS), 客户端验签必失败.
            let id_token = sign_id_token(
                &state.keys.rogue_key,
                &state.issuer,
                &state.client_id,
                &nonce,
                "user-42",
                Some("alice@example.com"),
                Some("Alice"),
            );
            token_response_with_id_token(id_token)
        }
        TokenPolicy::Error { status, body } => {
            // 测试构造 TokenPolicy::Error 时必须用合法 HTTP status; 不合法说明
            // 测试 setup 有错, 直接 panic 而非 fallback 掩盖.
            let mut resp = Response::new(body.into());
            *resp.status_mut() =
                StatusCode::from_u16(status).expect("TokenPolicy::Error: valid u16 status");
            resp
        }
    }
}

fn token_response_with_id_token(id_token: String) -> Response {
    let body = json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
    });
    idp_json_response(&body.to_string())
}

fn token_response_no_id_token() -> Response {
    let body = json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer",
        "expires_in": 3600
    });
    idp_json_response(&body.to_string())
}

// ─── client router (secret-guard 侧 handlers 装配) ─────────────────────

/// 装配最小 client router: 只有 OIDC auth 路由 (无 forwarding / proxy).
///
/// 与 `server.rs::build_router_with_auth_layers` 的差异: 不挂 ProxyState /
/// forwarding 路由, 只保留 OIDC session + handlers, 让测试聚焦 auth 行为.
///
/// # 端口隔离
///
/// 每次 `build_test_router` 都 `TcpListener::bind("127.0.0.1:0")` 让 OS 分配
/// 空闲端口, 多个测试并行跑不会冲突. ApiKeyStore 的 state_path 也用 UUID 唯一化
/// (避免跨测试 state 持久化文件污染).
async fn build_test_router(backend: OidcBackend) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");

    // 构造空 ApiKeyStore (无 static key + 无 dynamic entry). 用临时 state_path 满足
    // 构造签名; 测试不触发 CRUD 持久化, 路径仅占位.
    let tmp_state =
        std::env::temp_dir().join(format!("sg-auth-oidc-test-{}.toml", uuid::Uuid::new_v4()));
    let api_keys = ApiKeyStore::new(
        &[],
        std::path::Path::new("."),
        vec![],
        std::collections::HashSet::new(),
        tmp_state,
        std::sync::Arc::new(parking_lot::Mutex::new(())),
    );
    let auth_state = AuthState {
        backend: backend.clone(),
        api_keys,
    };

    use axum_login::AuthManagerLayerBuilder;
    let auth_routes: Router = Router::new()
        .route("/login", get(login_start).post(login_start))
        .route("/oauth2/callback", get(oauth_callback))
        .route("/logout", post(logout))
        .route("/api/me", get(me))
        .layer(axum::Extension(auth_state));

    let session_layer = build_session_layer();
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    let app = Router::new().nest("/__sg", auth_routes).layer(auth_layer);

    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    base
}

// ─── 测试用例 ──────────────────────────────────────────────────────────

/// 启动 mock IdP + 用它 discover 出 OidcBackend (exchange_and_verify_* 测试共用).
///
/// redirect_url 用占位值 (这些测试不触发真实 callback).
async fn spawn_idp_with_backend() -> (MockIdp, OidcBackend) {
    let idp = spawn_mock_idp().await;
    let backend = OidcBackend::discover(
        idp.issuer(),
        idp.client_id(),
        None,
        "http://127.0.0.1:1/__sg/oauth2/callback",
    )
    .await
    .expect("discover");
    (idp, backend)
}

/// 启动完整 client stack: mock IdP + OidcBackend + client router (handler 测试共用).
///
/// 返回 (MockIdp 控制柄, client base URL).
async fn spawn_idp_with_client() -> (MockIdp, String) {
    let (idp, backend) = spawn_idp_with_backend().await;
    let base = build_test_router(backend).await;
    (idp, base)
}

/// 从一组 authorize_url 生成的 (pkce_verifier, nonce, csrf_state) 构造 OidcCredentials.
///
/// 默认假设 CSRF state 匹配 (old == new), 这是绝大多数测试的默认情形.
/// `exchange_and_verify_csrf_mismatch` 显式覆写 new_state 来违反契约.
fn creds_from_parts(pkce_verifier: String, nonce: String, csrf_state: String) -> OidcCredentials {
    OidcCredentials {
        code: "fake-auth-code".to_string(),
        pkce_verifier,
        nonce,
        old_state: csrf_state.clone(),
        new_state: csrf_state,
    }
}

#[tokio::test]
async fn discover_happy_path() {
    let (idp, backend) = spawn_idp_with_backend().await;
    // discover 成功即证明: metadata 解析 + issuer 字符串校验 + JWKS 拉取全部通过.
    // 进一步用 authorize_url 验证 client typestate 完整可用.
    let parts = backend.authorize_url();
    assert!(
        parts.auth_url.as_str().starts_with(idp.issuer()),
        "auth_url should point to IdP"
    );
    assert!(!parts.pkce_verifier.is_empty());
    assert!(!parts.nonce.is_empty());
    assert!(!parts.csrf_state.is_empty());
}

#[tokio::test]
async fn discover_invalid_issuer_url_format() {
    // issuer URL 格式非法 (openidconnect::IssuerUrl::new 校验).
    let err = OidcBackend::discover("not-a-url", "client", None, "http://127.0.0.1:1/cb")
        .await
        .unwrap_err();
    assert!(err.contains("invalid issuer_url"), "got: {err}");
}

#[tokio::test]
async fn discover_unreachable() {
    // 用一个几乎肯定空闲的端口 (1), 让 discovery HTTP 请求失败.
    let err = OidcBackend::discover(
        "http://127.0.0.1:1",
        "client",
        None,
        "http://127.0.0.1:1/cb",
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("discovery failed") || err.contains("OIDC"),
        "got: {err}"
    );
}

#[tokio::test]
async fn discover_missing_token_endpoint() {
    // 起 IdP 但 discovery metadata 故意省略 token_endpoint → secret-guard 显式报错
    // (而非依赖 openidconnect 内部 EndpointMaybeSet typestate).
    //
    // 注: openidconnect::discover_async 会先拉 metadata 再拉 jwks_uri, 故 jwks 路由必须
    // 返回 200 (空 JWKS 即可); 错误会在 secret-guard 自己的 `no token_endpoint` 校验触发.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get({
                let iss = issuer.clone();
                move || async move {
                    let metadata = json!({
                        "issuer": iss,
                        "authorization_endpoint": format!("{iss}/authorize"),
                        // 故意省略 token_endpoint
                        "jwks_uri": format!("{iss}/jwks"),
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"]
                    });
                    idp_json_response(&metadata.to_string())
                }
            }),
        )
        .route(
            "/jwks",
            get(|| async move { idp_json_response(r#"{"keys":[]}"#) }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    let err = OidcBackend::discover(&issuer, "cid", None, &format!("{issuer}/cb"))
        .await
        .unwrap_err();
    assert!(err.contains("no token_endpoint"), "got: {err}");
}

#[tokio::test]
async fn exchange_and_verify_happy() {
    let (idp, backend) = spawn_idp_with_backend().await;

    // authorize_url 生成一组真实 nonce + state (与生产 login_start 路径一致).
    let parts = backend.authorize_url();
    // 保留 verifier 副本, exchange 后断言它确实被发给 IdP (PKCE round-trip).
    let verifier_sent = parts.pkce_verifier.clone();

    // 预设 token response 策略: 用真实 nonce 签 id_token.
    idp.set_token_policy(TokenPolicy::Happy {
        nonce: parts.nonce.clone(),
    });

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let user = backend
        .exchange_and_verify(creds)
        .await
        .expect("exchange should succeed");

    // 守卫 RED-CRYPTO-1 (签名 round-trip) + RED-CRYPTO-2 (nonce 匹配) + claims 提取.
    assert_eq!(user.sub, "user-42");
    assert_eq!(user.email.as_deref(), Some("alice@example.com"));
    assert_eq!(user.name.as_deref(), Some("Alice"));

    // 守卫 PKCE verifier round-trip: secret-guard 确实把 authorize_url 生成的 verifier
    // 经 /token form body 发给 IdP (而非放 query string 或前端可见位置).
    let token_reqs = idp.token_requests();
    assert_eq!(token_reqs.len(), 1, "exactly one /token request expected");
    assert!(
        token_reqs[0].contains(&verifier_sent),
        "/token body should carry PKCE verifier; got: {}",
        token_reqs[0]
    );

    // 同时验证: get_user 缓存命中 (authenticate 写入, 后续请求恢复).
    // OidcBackend 内部 Arc<RwLock<HashMap>>, clone 是 Arc 引用拷贝, 共享同一份缓存.
    let cached = backend
        .get_user(&user.sub)
        .await
        .expect("get_user")
        .expect("user should be cached");
    assert_eq!(cached.sub, "user-42");
}

#[tokio::test]
async fn exchange_and_verify_csrf_mismatch() {
    // SEC-AUTH-1: CSRF state 不匹配必须拒绝 (防 CSRF 攻击).
    let (_idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    // 显式构造不匹配的 CSRF state (违反 old == new 契约), 突出本测试的意图.
    let creds = OidcCredentials {
        code: "x".into(),
        pkce_verifier: parts.pkce_verifier,
        nonce: parts.nonce,
        old_state: parts.csrf_state,
        new_state: "different-state".to_string(),
    };

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    assert!(matches!(err, OidcError::CsrfMismatch), "got: {err:?}");
}

#[tokio::test]
async fn exchange_and_verify_token_http_error() {
    // token endpoint 返回 4xx → TokenExchange 错误 (不要泄漏内部 IdP 细节).
    let (idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    idp.set_token_policy(TokenPolicy::Error {
        status: 400,
        body: r#"{"error":"invalid_grant"}"#.to_string(),
    });

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    match err {
        OidcError::TokenExchange(msg) => {
            // openidconnect 包装 oauth2 的错误, message 含 "Server returned error response"
            // 或具体 status. 不验细节 (依赖库版本), 只确认错误类别.
            assert!(!msg.is_empty(), "TokenExchange error message empty");
        }
        other => panic!("expected TokenExchange, got: {other:?}"),
    }
}

#[tokio::test]
async fn exchange_and_verify_no_id_token() {
    // token response 合法但不含 id_token → NoIdToken (OIDC 要求 id_token).
    let (idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    idp.set_token_policy(TokenPolicy::NoIdToken);

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    assert!(matches!(err, OidcError::NoIdToken), "got: {err:?}");
}

#[tokio::test]
async fn exchange_and_verify_wrong_signature() {
    // RED-CRYPTO-1 反向: id_token 用 JWKS 未公布的私钥签名 → 验签必失败.
    let (idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    idp.set_token_policy(TokenPolicy::WrongSignature {
        nonce: parts.nonce.clone(),
    });

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    match err {
        OidcError::IdTokenVerification(msg) => {
            // openidconnect 报 "SignatureDoesNotMatch" 或 "NoMatchingKey" (取决于 kid 不在 JWKS).
            assert!(!msg.is_empty());
        }
        other => panic!("expected IdTokenVerification, got: {other:?}"),
    }
}

#[tokio::test]
async fn exchange_and_verify_wrong_nonce() {
    // RED-CRYPTO-2 反向: id_token nonce claim 不匹配 → InvalidNonce (防重放).
    let (idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    idp.set_token_policy(TokenPolicy::WrongNonce {
        wrong_nonce: "totally-different-nonce".to_string(),
    });

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    // openidconnect 在 nonce 不匹配时报 ClaimsVerificationError, 我们的代码包成
    // IdTokenVerification. 仅断言 variant (不耦合 openidconnect 错误文案, 它跨版本
    // 可能变).
    assert!(
        matches!(err, OidcError::IdTokenVerification(_)),
        "expected IdTokenVerification, got: {err:?}"
    );
}

// ─── handlers 端到端测试 (login_start / oauth_callback / logout / me) ───
//
// # oauth_callback happy path 为何不在此处端到端覆盖
//
// OIDC nonce 是 client-only 的安全凭证, 从不发给 IdP. 真实 OIDC 流程中:
//   client.authorize_url() 生成 nonce → 存 server-side session → callback 时取出
//   传给 exchange_and_verify → id_token 的 nonce claim 必须与之一致.
// 在外部 HTTP 测试里, 测试既无法读到 session 内的 nonce (HttpOnly cookie + server
// 内存), 也不能让 IdP 知道 nonce (违反 OIDC 安全模型).
// 故 oauth_callback happy path 的 nonce round-trip 由 `exchange_and_verify_happy`
// (直接构造 OidcCredentials 调用) 覆盖核心逻辑; 此处只覆盖端到端的:
//   - login_start (session 写入 + redirect + sanitize_next_url 守卫)
//   - oauth_callback 错误路径 (IdP error / 缺 PKCE verifier)
//   - logout (session 清除)
//   - me (未登录态)
//
// 完整的 happy path 端到端需要 mocking AuthSession (axum-login extractor), 复杂度
// 优于本 PR 范围, 留作 followup (见 PR body).

/// 装配一个 reqwest client, **禁用自动 redirect** (手动跟 redirect 以断言 Location).
///
/// 注: 不用 reqwest 的 `cookie_store` feature (主依赖 reqwest 没开, 加 dev-dep 会
/// 因 feature unification 影响生产构建). 测试若需跨请求共享 session, 手动从
/// Set-Cookie 提取并回传 Cookie header (见 `extract_session_cookie`).
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build http client")
}

/// 从响应的 Set-Cookie 头集合中提取 sg.sid 的完整 cookie 字符串 (用于后续请求回传).
///
/// tower-sessions 写回的 cookie 形如 `sg.sid=...; HttpOnly; SameSite=Lax; Path=/`.
/// 遍历所有 Set-Cookie 头 (middleware 链可能附加其他 cookie 如 CSRF token),
/// 取出 sg.sid 的 pair 部分 (到第一个 `;`), 后续请求作为 `Cookie: sg.sid=...` 回传.
fn extract_session_cookie(resp: &reqwest::Response) -> Option<String> {
    for set_cookie in resp.headers().get_all(header::SET_COOKIE) {
        let Ok(val) = set_cookie.to_str() else {
            continue;
        };
        let cookie_pair = val.split(';').next().unwrap_or("").trim();
        if cookie_pair.starts_with("sg.sid=") {
            return Some(cookie_pair.to_string());
        }
    }
    None
}

#[tokio::test]
async fn login_start_redirects_to_idp_with_pkce_in_session() {
    // 守卫: login_start 必须重定向到 IdP authorize URL, 并通过 Set-Cookie 写回 session
    // (含 PKCE verifier + nonce + state, 这些绝不能放 query string).
    let (idp, base) = spawn_idp_with_client().await;
    let client = http_client();
    let resp = client
        .get(format!("{base}/__sg/login"))
        .send()
        .await
        .unwrap();

    // 1. 必须 302 redirect 到 IdP.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap();
    assert!(
        location.starts_with(idp.issuer()),
        "should redirect to IdP, got: {location}"
    );
    // authorize URL 必须含 state + scope.
    assert!(location.contains("state="), "state in query: {location}");
    assert!(
        location.contains("scope=openid"),
        "scope in query: {location}"
    );

    // 2. Set-Cookie 必须写回 session id (HttpOnly + name=sg.sid, 见 session.rs).
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie must be present (session was modified)");
    let cookie_str = set_cookie.to_str().unwrap();
    assert!(cookie_str.contains("sg.sid="), "cookie name: {cookie_str}");
    assert!(
        cookie_str.to_ascii_lowercase().contains("httponly"),
        "HttpOnly red line: {cookie_str}"
    );

    // 注: login_start 是 redirect (非 error_response), 不挂 NO_STORE header.
    // NO_STORE 红线只在 error_response 守卫 (见 handlers::tests 的对应测试).
}

#[tokio::test]
async fn login_start_sanitizes_next_url() {
    // SEC-AUTH-2: next 参数必须是站内相对路径, 防 open redirect.
    // 合法 next: 存入 session (后续 callback 重定向用).
    // 非法 next: 清除旧值, 不影响流程.
    let (idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    // 合法 next: 仍正常 redirect 到 IdP (next 已存入 session).
    let resp = client
        .get(format!("{base}/__sg/login?next=/__sg/records"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // 非法 next (//evil.com): 不阻断流程, 仍 redirect 到 IdP (next 被丢弃, 不进 session).
    // 守卫的是 "next 不会被用作 redirect 目标除非合法", 此处验证非法 next 不抛错.
    let resp2 = client
        .get(format!("{base}/__sg/login?next=//evil.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::SEE_OTHER,
        "illegal next should not abort login flow"
    );
    let loc = resp2
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc.starts_with(idp.issuer()),
        "should still go to IdP, got: {loc}"
    );
}

#[tokio::test]
async fn oauth_callback_rejects_idp_error_param() {
    // IdP 在 callback 里返回 error (用户拒绝授权等): 必须返回 401 + JSON envelope.
    let (_idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    // 先 login 一次拿 cookie (建立 session). 提取 Set-Cookie 用于后续 callback 回传.
    let login_resp = client
        .get(format!("{base}/__sg/login"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        login_resp.status(),
        StatusCode::SEE_OTHER,
        "login should succeed before testing callback"
    );
    let session_cookie =
        extract_session_cookie(&login_resp).expect("login should set sg.sid cookie");

    // 模拟 IdP 回调时带 error 参数 (回传 session cookie 让 handler 能读 session).
    // 注: CallbackQuery 的 code/state 字段必填 (即使 IdP 返回 error 也要传, axum Query
    // 反序列化要求), 故这里随便填 dummy 值 — handler 会先检查 error 字段短路返回 401.
    let resp = client
        .get(format!(
            "{base}/__sg/oauth2/callback?code=dummy&state=dummy&error=access_denied&error_description=user+cancelled"
        ))
        .header(header::COOKIE, session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(
        body["error"],
        "OIDC provider error: access_denied (user cancelled)"
    );
}

#[tokio::test]
async fn oauth_callback_rejects_missing_session_credentials() {
    // 不先 login 直接访问 callback: session 缺 PKCE verifier / nonce / state → 400.
    let (_idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    // 不 login, 直接 callback. session 是空的 (无 cookie 回传).
    let resp = client
        .get(format!(
            "{base}/__sg/oauth2/callback?code=fake&state=anything"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    let err_msg = body["error"].as_str().unwrap();
    assert!(
        err_msg.contains("missing") && err_msg.contains("session"),
        "should mention missing session, got: {err_msg}"
    );
}

#[tokio::test]
async fn me_returns_unauthenticated_when_not_logged_in() {
    // 未登录访问 /api/me: 返回 authenticated=false (不报 401, 因为 me 是公开路由).
    let (_idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    let resp = client
        .get(format!("{base}/__sg/api/me"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["authenticated"], false);
}

#[tokio::test]
async fn logout_clears_session_and_redirects() {
    // logout handler: 调 auth_session.logout() + redirect 到 /__sg/login.
    // 即使未登录, logout 也不报错 (幂等, 调 logout on empty session 是 no-op).
    let (_idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    let resp = client
        .post(format!("{base}/__sg/logout"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(loc, "/__sg/login", "logout should redirect to login");
}
