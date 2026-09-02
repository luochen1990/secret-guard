//! OIDC 认证后端: 桥接 openidconnect::CoreClient + axum-login.
//!
//! # 流程
//!
//! 1. `/login`: 生成 PKCE challenge + verifier + nonce + CSRF state, 存 server-side
//!    session, redirect 到 IdP authorize URL.
//! 2. IdP 回调 `/oauth2/callback?code=X&state=Y`: 从 session 取 verifier + nonce,
//!    exchange code → token, 验证 ID token (签名 + nonce), 提取 sub/email/name.
//! 3. axum-login 的 `auth_session.login(&user)` 把 User 存入 session.
//! 4. 后续请求: axum-login middleware 从 session 恢复 User, 注入 AuthSession extractor.
//!
//! # 关键不变式
//!
//! - PKCE verifier + nonce **必须存服务端 session**, 绝不放 cookie (安全红线).
//! - ID token 必须验证签名 (JWKS) + nonce (防重放).
//! - CoreClient 在启动时通过 OIDC Discovery 初始化, 进程内共享.
//! - **JWKS 轮换恢复** (#198): openidconnect 的 client 持 discovery 时抓取的 JWKS
//!   快照且无公开刷新 API, 刷新责任在本模块 — 验签遇 `SignatureVerification` 类
//!   失败时重跑 discovery 重建 client 并有界重验一次 (见 `exchange_and_verify`).
//!
//! # 类型状态 (typestate)
//!
//! `from_provider_metadata().set_redirect_uri()` 返回的 CoreClient 带 typestate:
//! `HasAuthUrl = EndpointSet`, `HasTokenUrl = EndpointMaybeSet` (token URL 来自 discovery,
//! 可能缺失). 为避免把完整泛型签名写到字段类型里, 本模块用 `OidcClient` 类型别名固定.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use axum_login::{AuthUser, AuthnBackend, UserId};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthType, AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// 类型别名: from_provider_metadata + set_token_uri + set_redirect_uri 后的 CoreClient.
///
/// 显式设置 token_uri 让 HasTokenUrl = EndpointSet (所有 IdP 都有 token endpoint).
/// 这样 exchange_code 在编译期保证可用.
type OidcClient = CoreClient<
    EndpointSet,                   // HasAuthUrl
    openidconnect::EndpointNotSet, // HasDeviceAuthUrl
    openidconnect::EndpointNotSet, // HasIntrospectionUrl
    openidconnect::EndpointNotSet, // HasRevocationUrl
    EndpointSet,                   // HasTokenUrl
    EndpointMaybeSet,              // HasUserInfoUrl
>;

/// OIDC 用户身份 (存入 session, 序列化为 JSON).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    /// OIDC subject (唯一标识). M1 中也作为 tenant_id.
    pub sub: String,
    /// email (需 IdP 返回 email scope).
    pub email: Option<String>,
    /// 显示名.
    pub name: Option<String>,
    /// session_auth_hash 的种子 (sub 的字节), 用于 session 完整性校验.
    auth_hash: Vec<u8>,
}

impl AuthUser for User {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.sub.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        &self.auth_hash
    }
}

impl User {
    fn from_claims(sub: &str, email: Option<&str>, name: Option<&str>) -> Self {
        Self {
            sub: sub.to_string(),
            email: email.map(|s| s.to_string()),
            name: name.map(|s| s.to_string()),
            auth_hash: sub.as_bytes().to_vec(),
        }
    }
}

/// OIDC 认证后端 (实现 axum-login 的 AuthnBackend trait).
///
/// 持有 CoreClient + 内存用户缓存 (sub → User).
/// 用户缓存在 authenticate 成功时写入, 供 get_user 在后续请求中恢复完整 User
/// (含 email/name). 进程重启后缓存清空, 但 session 也同步失效, 用户需重登.
#[derive(Clone)]
pub struct OidcBackend {
    /// discovery 构造参数快照 (JWKS 轮换刷新时用同参数重跑 discovery, #198).
    ctor: Arc<DiscoverParams>,
    /// 当前 client (启动时构造; 验签遇签名类失败触发轮换刷新时整体替换).
    /// 读锁不跨 await: 一律先 clone (KB 级小结构体, 拷贝廉价) 再异步操作.
    client: Arc<RwLock<OidcClient>>,
    http_client: reqwest::Client,
    /// 内存用户缓存: OIDC sub → User (含 email/name).
    users: Arc<RwLock<HashMap<String, User>>>,
}

/// `OidcBackend::discover` 的构造参数 (快照留存, 供 JWKS 轮换刷新重放, #198).
struct DiscoverParams {
    issuer_url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_url: String,
}

/// 登录时从 session 取出的临时凭证 (PKCE + nonce + CSRF state).
#[derive(Clone, Deserialize)]
pub struct OidcCredentials {
    /// IdP 返回的 authorization code.
    pub code: String,
    /// PKCE verifier (login 时生成的 secret).
    pub pkce_verifier: String,
    /// Nonce (login 时生成, 用于 ID token 验证).
    pub nonce: String,
    /// login 时存的 CSRF state.
    pub old_state: String,
    /// callback query 中的 state.
    pub new_state: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("CSRF state mismatch")]
    CsrfMismatch,
    #[error("missing ID token in token response")]
    NoIdToken,
    #[error("OIDC token exchange failed: {0}")]
    TokenExchange(String),
    #[error("ID token verification failed: {0}")]
    IdTokenVerification(String),
}

impl std::fmt::Debug for OidcBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcBackend").finish_non_exhaustive()
    }
}

/// login 时生成的授权 URL + 需要存入 session 的 verifier/nonce/state.
pub struct AuthUrlParts {
    /// 重定向到 IdP 的 URL.
    pub auth_url: openidconnect::url::Url,
    /// PKCE verifier (secret, 必须存 server-side session).
    pub pkce_verifier: String,
    /// Nonce (必须存 server-side session).
    pub nonce: String,
    /// CSRF state token.
    pub csrf_state: String,
}

impl OidcBackend {
    /// 通过 OIDC Discovery 初始化 CoreClient.
    ///
    /// 启动时调用一次 (异步). 失败则 fail-fast (返回 Err).
    pub async fn discover(
        issuer_url: &str,
        client_id: &str,
        client_secret: Option<String>,
        redirect_url: &str,
    ) -> Result<Self, String> {
        // HTTP client: 禁止 redirect 防 SSRF (openidconnect 官方建议).
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("build OIDC http client: {e}"))?;

        let ctor = DiscoverParams {
            issuer_url: issuer_url.to_string(),
            client_id: client_id.to_string(),
            client_secret,
            redirect_url: redirect_url.to_string(),
        };
        let client = discover_client(&ctor, &http_client).await?;

        Ok(Self {
            ctor: Arc::new(ctor),
            client: Arc::new(RwLock::new(client)),
            http_client,
            users: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// 重跑 OIDC Discovery 重建 client (JWKS 轮换刷新, #198).
    ///
    /// 成功则整体替换 `self.client`; 失败保留旧 client (调用方返回原始验签错误,
    /// 刷新失败不掩盖). CoreClient 无公开 API 就地替换 JWKS 快照, 故走完整
    /// discovery 重建 — 轮换是月频事件, 性能无需精打细算. 并发调用幂等
    /// (同参数重建, 后写者胜), 无需 single-flight.
    async fn refresh_client(&self) -> Result<(), String> {
        let client = discover_client(&self.ctor, &self.http_client).await?;
        *self.client.write() = client;
        Ok(())
    }

    /// 生成授权 URL + PKCE verifier + nonce + CSRF state.
    /// 返回的 verifier/nonce/state 必须由调用方存入 server-side session.
    pub fn authorize_url(&self) -> AuthUrlParts {
        let client = self.client.read().clone();
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_state, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        AuthUrlParts {
            auth_url,
            pkce_verifier: pkce_verifier.secret().clone(),
            nonce: nonce.secret().clone(),
            csrf_state: csrf_state.secret().clone(),
        }
    }

    /// 从 IdP callback 交换 token 并验证 ID token, 返回 User.
    ///
    /// 步骤:
    /// 1. CSRF 校验 (old_state == new_state).
    /// 2. exchange code + PKCE verifier → token response (async).
    /// 3. 验证 ID token 签名 + nonce; 签名类失败时刷新 JWKS (重跑 discovery)
    ///    并有界重验一次 (#198: IdP 轮换签名密钥后旧快照查无新 kid).
    /// 4. 提取 sub/email/name → User.
    pub async fn exchange_and_verify(&self, creds: OidcCredentials) -> Result<User, OidcError> {
        // 1. CSRF 校验.
        if creds.old_state != creds.new_state {
            return Err(OidcError::CsrfMismatch);
        }

        let client = self.client.read().clone();

        // 2. exchange code + PKCE verifier → token (async, 不阻塞 tokio worker).
        let token_response = client
            .exchange_code(AuthorizationCode::new(creds.code))
            .set_pkce_verifier(PkceCodeVerifier::new(creds.pkce_verifier))
            .request_async(&self.http_client)
            .await
            .map_err(|e| OidcError::TokenExchange(e.to_string()))?;

        // 3. 验证 ID token + nonce.
        let id_token = token_response.id_token().ok_or(OidcError::NoIdToken)?;
        let nonce = Nonce::new(creds.nonce);
        // 签名类失败 (SignatureVerification, 含 NoMatchingKey / CryptoError)
        // 是 JWKS 轮换的典型信号: 新 kid 不在快照, 或 IdP 原地换 key 不换 kid. 重跑
        // discovery 刷新 client 后重验一次 — 有界重试 (只此一次), 恶意 token 最多
        // 触发一轮刷新, 不构成刷新风暴. 非签名类失败 (nonce/issuer/audience/expired)
        // 与 JWKS 无关, 不触发刷新. 刷新失败保留旧 client, 返回原始错误 (不掩盖).
        let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
            Ok(claims) => claims,
            Err(e) if matches!(e, ClaimsVerificationError::SignatureVerification(_)) => {
                // Debug (而非 Display): 内层 SignatureVerificationError 是 #[source]
                // 不参与 Display (固定文案 "Signature verification failed"), Debug
                // 才能区分 NoMatchingKey (轮换信号) 与 CryptoError, 且
                // 不含敏感字节.
                tracing::warn!(
                    error = ?e,
                    "ID token signature verification failed; refreshing JWKS (possible key rotation)"
                );
                if let Err(refresh_err) = self.refresh_client().await {
                    tracing::warn!(
                        error = %refresh_err,
                        "JWKS refresh failed; keeping stale client"
                    );
                    return Err(OidcError::IdTokenVerification(e.to_string()));
                }
                let refreshed = self.client.read().clone();
                id_token
                    .claims(&refreshed.id_token_verifier(), &nonce)
                    .map_err(|e| OidcError::IdTokenVerification(e.to_string()))?
            }
            Err(e) => return Err(OidcError::IdTokenVerification(e.to_string())),
        };

        // 4. 提取 user 信息 + 缓存 (供 get_user 恢复完整 User).
        let user = User::from_claims(
            claims.subject().as_str(),
            claims.email().map(|e| e.as_str()),
            claims.name().and_then(|n| n.get(None)).map(|n| n.as_str()),
        );
        self.users.write().insert(user.sub.clone(), user.clone());
        Ok(user)
    }
}

/// 执行一次 OIDC Discovery 并构造 client (`OidcBackend::discover` 与
/// `refresh_client` 共用; 同参数重放保证重建等价, #198).
async fn discover_client(
    ctor: &DiscoverParams,
    http_client: &reqwest::Client,
) -> Result<OidcClient, String> {
    let issuer = IssuerUrl::new(ctor.issuer_url.clone())
        .map_err(|e| format!("invalid issuer_url '{}': {e}", ctor.issuer_url))?;
    let redirect = RedirectUrl::new(ctor.redirect_url.clone())
        .map_err(|e| format!("invalid redirect_url '{}': {e}", ctor.redirect_url))?;

    let metadata = CoreProviderMetadata::discover_async(issuer, http_client)
        .await
        .map_err(|e| format!("OIDC discovery failed for '{}': {e}", ctor.issuer_url))?;

    // 显式提取 token endpoint 并 set_token_uri, 让 typestate 变为 EndpointSet
    // (保证 exchange_code 编译期可用).
    let token_endpoint = metadata.token_endpoint().cloned().ok_or_else(|| {
        format!(
            "OIDC discovery '{}': no token_endpoint found",
            ctor.issuer_url
        )
    })?;

    Ok(CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(ctor.client_id.clone()),
        ctor.client_secret.clone().map(ClientSecret::new),
    )
    .set_token_uri(token_endpoint)
    .set_redirect_uri(redirect)
    // 用 RequestBody 传 client credentials 而非默认的 BasicAuth.
    //
    // oauth2 的 BasicAuth 按 RFC 6749 §2.3.1 url-encode secret, 但 kanidm (1.10) 取字面值
    // 不 url-decode, 导致 base64 secret 末尾 `=` → `%3D` 与存储不等 → 401. RequestBody 把
    // secret 放进 form body, kanidm 解 form 时还原原字符. 其他主流 IdP 两种都接受, 故更稳.
    .set_auth_type(AuthType::RequestBody))
}

impl AuthnBackend for OidcBackend {
    type User = User;
    type Credentials = OidcCredentials;
    type Error = OidcError;

    fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
        let fut = self.exchange_and_verify(creds);
        async move { fut.await.map(Some) }
    }

    fn get_user(
        &self,
        user_id: &UserId<Self>,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
        // 从内存缓存恢复完整 User (含 email/name).
        // 缓存未命中 (进程重启后) 返回 None → session 自动失效 → 用户重登.
        let user = self.users.read().get(user_id).cloned();
        async move { Ok(user) }
    }
}

/// 构造 axum-login 的 Backend type alias (供 router 装配用).
pub type AuthSession = axum_login::AuthSession<OidcBackend>;
