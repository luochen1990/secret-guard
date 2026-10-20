//! `GET /api/search?q=<text>` — 会话文本搜索 (#317) 薄壳 handler.
//!
//! 职责只有**集中预处理** (查询参数验证): `q` 缺失 / trim 后为空 / 超过
//! [`MAX_QUERY_CHARS`] → 400. 扫描算法与性能红线 (结果 cap + 扫描预算) 的
//! SSOT 在 `src/dag/search.rs` — 本层零扫描逻辑, 与 sessions.rs 的
//! "handler 是 dag 视图的薄壳" 分工一致.
//!
//! 响应 shape 见 `crate::dto::{SearchHit, SearchResponse}`. 独立 GET 端点,
//! 天然不阻塞 `/api/sync` 轮询 (共享的只是 DagInner 读锁, 预算保证持锁上界).

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;

use super::error::ApiError;
use crate::state::{AppState, NO_STORE};

/// query 的最大字符数 (超出 400): 上限是防御性的 — 超长 query 的 find 成本
/// 与叶子长度线性相关, 且真实搜索意图不会超过此长度.
pub(crate) const MAX_QUERY_CHARS: usize = 512;

/// 集中预处理 (纯函数, 单测点): 原始 query 参数 → 合法搜索串.
fn validate_query(raw: Option<&String>) -> Result<&str, &'static str> {
    let q = raw.ok_or("missing query parameter 'q'")?;
    let q = q.trim();
    if q.is_empty() {
        return Err("query must not be empty");
    }
    if q.chars().count() > MAX_QUERY_CHARS {
        return Err("query too long");
    }
    Ok(q)
}

/// GET /api/search?q=<text> handler.
pub async fn search(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    let q = validate_query(params.get("q")).map_err(ApiError::validation)?;
    Ok((NO_STORE, Json(state.dag.search(q))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_query_rejects_missing_empty_and_oversized() {
        assert!(validate_query(None).is_err(), "missing q");
        assert!(validate_query(Some(&String::new())).is_err(), "empty q");
        assert!(
            validate_query(Some(&"   \t ".to_string())).is_err(),
            "whitespace q"
        );
        let oversized = "x".repeat(MAX_QUERY_CHARS + 1);
        assert!(validate_query(Some(&oversized)).is_err(), "oversized q");
    }

    #[test]
    fn validate_query_passes_and_trims() {
        assert_eq!(validate_query(Some(&"hello".to_string())), Ok("hello"));
        // 前后空白被 trim (trim 结果作为搜索串传入 dag 层).
        assert_eq!(validate_query(Some(&"  hello ".to_string())), Ok("hello"));
        // 恰好等于上限的合法.
        let exact = "y".repeat(MAX_QUERY_CHARS);
        assert_eq!(validate_query(Some(&exact)), Ok(exact.as_str()));
        // 多字节字符按字符数 (非字节数) 计.
        let cjk = "密".repeat(MAX_QUERY_CHARS);
        assert!(
            validate_query(Some(&cjk)).is_ok(),
            "cjk chars count as chars"
        );
    }
}
