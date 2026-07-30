//! API key 校验 middleware + AuthenticatedTenant Extension.
//!
//! # 用法
//!
//! 作为 layer 挂在 forward 路由上:
//! ```ignore
//! Router::new()
//!     .route("/{proto}/{name}/{*rest}", any(forward))
//!     .route_layer(middleware::from_fn_with_state(api_key_store, require_api_key));
//! ```
//!
//! 校验成功后, `AuthenticatedTenant` 被注入 request extension,
//! 下游 handler 可通过 `Extension(tenant)` 提取.
//! (M1 中 tenant_id 不用于数据隔离, M2 起作为 scope key.)

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::ApiKeyStore;
use crate::error::AppError;

/// 已认证的租户身份. 注入 request extension, 供下游 handler 用.
/// M1 不做隔离 (所有 tenant 共享数据), M2 起作为 scope key.
#[derive(Clone, Debug)]
pub struct AuthenticatedTenant {
    pub tenant_id: String,
}

/// API key 校验 middleware.
///
/// 从 `Authorization: Bearer <key>` 提取 key, SHA-256 hash 后查 ApiKeyStore.
/// 命中 → 注入 AuthenticatedTenant; 未命中 → 401 Unauthorized.
///
/// 安全边界: 校验成功后**剥离** Authorization header.
/// 原因: 若 provider 未配 api_key (如 Ollama), apply_provider_auth 会跳过注入,
/// 导致 secret-guard 自己的 API key 原样到达上游 LLM provider —
/// 这正是 secret-guard 要防止的 secret 泄漏事故.
/// 剥离后, apply_provider_auth 只负责注入 provider 的 key, 不再隐式依赖"覆盖"语义.
pub async fn require_api_key(
    State(store): State<ApiKeyStore>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let key = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("missing Authorization: Bearer header".into()))?;

    let entry = store
        .lookup(key)
        .ok_or_else(|| AppError::Unauthorized("invalid or revoked API key".into()))?;

    // 剥离客户端的 API key, 防止泄漏到上游.
    // apply_provider_auth 会注入 provider 自己的 api_key (若有).
    req.headers_mut().remove(axum::http::header::AUTHORIZATION);

    req.extensions_mut().insert(AuthenticatedTenant {
        tenant_id: entry.tenant_id,
    });
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    //! require_api_key middleware 的纯逻辑单测.
    //!
    //! 用 axum::serve + TcpListener 起一个最小 server (与 tests/integration.rs 同模式,
    //! 不引入 tower ServiceExt 依赖), 端到端验证鉴权决策. 覆盖五条决策路径:
    //!   1. 缺 Authorization header → 401.
    //!   2. Authorization 非 Bearer → 401.
    //!   3. Bearer key 在 store 中不存在 → 401.
    //!   4. 合法 Bearer key → 200, tenant 注入 Extension.
    //!   5. 合法 Bearer key → Authorization header **被剥离** (SEC 红线, 防客户端 key
    //!      泄漏到上游 LLM provider, 尤其 provider 未配 api_key 时如 Ollama 直通).

    use std::sync::Arc;

    use axum::Extension;
    use axum::Router;
    use axum::http::HeaderMap;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use parking_lot::Mutex;

    use super::*;

    /// 构造一个挂了 require_api_key 的最小 Router + 两个探针:
    /// - `/probe`        : 回显 tenant_id (证明 middleware 放行 + AuthenticatedTenant 注入).
    /// - `/probe/headers`: 回显上游侧收到的 Authorization header (证明已被剥离, 见用例 5).
    fn probe_router(store: ApiKeyStore) -> Router {
        Router::new()
            .route(
                "/probe",
                get(
                    |Extension(tenant): Extension<AuthenticatedTenant>| async move {
                        (axum::http::StatusCode::OK, tenant.tenant_id)
                    },
                ),
            )
            .route(
                "/probe/headers",
                get(|headers: HeaderMap| async move {
                    // 回显上游侧 (handler 视角) 见到的 Authorization header.
                    // 预期: middleware 剥离后这里应为 None (见 middleware.rs 头部安全边界注释).
                    match headers.get(axum::http::header::AUTHORIZATION) {
                        Some(v) => format!("present:{}", v.to_str().unwrap_or("?")),
                        None => "absent".to_string(),
                    }
                }),
            )
            .route_layer(from_fn_with_state(store, require_api_key))
    }

    fn make_store() -> ApiKeyStore {
        use std::collections::HashSet;
        ApiKeyStore::new(
            &[],
            std::path::Path::new("."),
            vec![],
            HashSet::new(),
            std::path::PathBuf::from(format!(
                "/tmp/opencode/test-middleware-{}.toml",
                uuid::Uuid::new_v4()
            )),
            Arc::new(Mutex::new(())),
        )
    }

    /// 起一个最小 server, 返回 base_url (http://127.0.0.1:<port>).
    /// 用 127.0.0.1:0 让 OS 分配空闲端口 (与 tests/integration.rs spawn_proxy 同模式).
    async fn spawn(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });
        format!("http://{addr}")
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn missing_authorization_header_is_rejected() {
        let url = spawn(probe_router(make_store())).await;
        let resp = client().get(format!("{url}/probe")).send().await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_bearer_scheme_is_rejected() {
        let url = spawn(probe_router(make_store())).await;
        let resp = client()
            .get(format!("{url}/probe"))
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_bearer_key_is_rejected() {
        let url = spawn(probe_router(make_store())).await;
        let resp = client()
            .get(format!("{url}/probe"))
            .header("Authorization", "Bearer sg_unknown_key")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_bearer_key_passes_and_injects_tenant() {
        let store = make_store();
        let issued = store.issue("tenant-1", "tester", "probe-key").unwrap();
        let url = spawn(probe_router(store)).await;

        let resp = client()
            .get(format!("{url}/probe"))
            .header("Authorization", format!("Bearer {}", issued.key))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), "tenant-1");
    }

    #[tokio::test]
    async fn valid_bearer_key_strips_authorization_header() {
        // SEC 红线: 合法 key 放行后, Authorization header **必须**被 middleware 剥离,
        // 防止 secret-guard 自己的客户端 key 泄漏到上游 LLM provider.
        // (尤其 provider 未配 api_key 时, 如 Ollama, apply_provider_auth 跳过注入,
        //  客户端 key 会原样直通上游 — 这正是 require_api_key 存在的第二个核心理由.)
        // 若此断言失败 = 安全防线被破坏, 必须立即修.
        let store = make_store();
        let issued = store.issue("tenant-1", "tester", "probe-key").unwrap();
        let url = spawn(probe_router(store)).await;

        let resp = client()
            .get(format!("{url}/probe/headers"))
            .header("Authorization", format!("Bearer {}", issued.key))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            resp.text().await.unwrap(),
            "absent",
            "Authorization header must be stripped before reaching upstream handler"
        );
    }

    #[tokio::test]
    async fn disabled_key_is_rejected() {
        // disabled key 不在 hash_index 中 (ApiKeyStore::lookup 跳过 disabled),
        // 故 middleware 视为 invalid → 401. 守卫 disabled 状态在鉴权链路正确传播.
        let store = make_store();
        let issued = store.issue("t2", "tester", "will-disable").unwrap();
        store.set_disabled(&issued.id, true).unwrap();

        let url = spawn(probe_router(store)).await;
        let resp = client()
            .get(format!("{url}/probe"))
            .header("Authorization", format!("Bearer {}", issued.key))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
}
