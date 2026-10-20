//! `GET /records/{id}` 单条 record 的三档 view (WebUI 轮次详情弹窗按需拉取).
//!
//! 从 api.rs 单文件拆出 (见 #146 残留 1).
//!
//! 注: 旧的 `GET /api/records` (扁平分页) + `GET /api/nodes/{id}/timeline` (基于 node_id
//! 的 timeline) 已删除, 由 session-aware sync API 替代 (POST /api/sync + GET
//! /api/sessions/{sid}/timeline). 详见 dag 模块的 session_rounds / timeline_view /
//! timeline_diff / sync_snapshot. 本文件只保留单条 record 的 view 端点.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dag::ResponseData;
use crate::dto::{NodeDetail, NodeView};
use crate::provider::Protocol;
use crate::record::ForwardRecord;
use crate::state::{AppState, NO_STORE};

pub async fn get_record(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<RecordQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    // 从 DAG 派生 ForwardRecord DTO.
    let view = state.dag.get_node(id).ok_or(StatusCode::NOT_FOUND)?;
    // meta view (quant#305): 轮次详情弹窗概览 tab 的补全路径 — 只需元数据小字段
    // (method/path/model/status/error 等), 不为几行元数据传输 MB 级 body.
    // 早退同时跳过 get_node_detail (BlockPool resolve) 与 parsed 派生.
    if q.view.as_deref() == Some("meta") {
        let record = build_forward_record(view, None, None);
        return Ok((NO_STORE, Json(GetRecordResponse::record_only(record))));
    }
    let detail = state.dag.get_node_detail(id).ok_or(StatusCode::NOT_FOUND)?;
    let mut resp = state.dag.get_response(id);
    // B1 双态单点 (dag.derive_response_parsed → derive::parsed_view): 流式中读
    // stored 节流 parsed, finalize 后从 message + 元字段派生.
    if let Some(r) = resp.as_mut()
        && r.parsed.is_none()
    {
        r.parsed = state.dag.derive_response_parsed(id);
    }
    let record = build_forward_record(view, Some(detail), resp);
    // 我们总是返回 GetRecordResponse envelope, 让前端 shape 固定.
    // raw view: parsed_*/parse_error 全 None.
    // parsed view: parsed_response 直接从 record.resp_parsed 读取 (流式/非流式统一);
    //   parsed_request 仍需按需从 req_body 计算.
    let wants_parsed = q.view.as_deref() == Some("parsed");
    if !wants_parsed {
        return Ok((NO_STORE, Json(GetRecordResponse::record_only(record))));
    }
    let resp = build_parsed_response(record);
    Ok((NO_STORE, Json(resp)))
}

/// 从 DAG 视图构造 [`ForwardRecord`] DTO (Web API 的 record 字段).
///
/// 拼接 NodeView (元数据) + NodeDetail (req_headers / req_body_raw) + ResponseData (响应字段).
/// `detail` / `resp` 为 None 时 (= `view=meta`, quant#305) bodies / headers / parsed 全空,
/// 元数据 (status / elapsed / model / error 等, 来自 NodeView) 照常填充 — 单一字段映射
/// 服务 raw / meta 两档, 防两份构造漂移. ResponseData 缺失时 (上游错误 / 尚未响应),
/// 响应字段填默认空值 (resp_status=0 等).
fn build_forward_record(
    view: NodeView,
    detail: Option<NodeDetail>,
    resp: Option<ResponseData>,
) -> ForwardRecord {
    // meta 档 (detail=None) 与 "详情未捕获" 共用同一空值语义: headers/bodies 全空.
    let (req_headers, req_body_raw) = detail
        .map(|d| (d.req_headers, d.req_body_raw))
        .unwrap_or_default();
    ForwardRecord {
        id: view.id,
        created_at: view.created_at,
        method: view.method,
        path: view.path,
        // 请求的顶层 model (egress 视角: 路由改写生效时与 upstream_model 同值,
        // SSOT 在 NodeView.model; 走查 M1).
        model: view.model.as_deref().map(str::to_string),
        upstream_id: view.upstream_id.to_string(),
        upstream_model: view.upstream_model.as_deref().map(str::to_string),
        req_headers,
        req_body: req_body_raw,
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
        // B2: 未捕获标记 (off 档全部 / latest 档被会话更新请求取代) — 前端区分 "空 body"
        // vs "未捕获" 的契约字段.
        audit_capture_off: !view.audit_retained,
        // CDAG-7: 孤儿标记透传 (meta 档元数据照常 — 详情弹窗概览横幅数据源).
        is_orphan: view.is_orphan,
        // ForwardRecord 持有 Vec (需 Deserialize); 此处从 NodeView 的 Arc 切片
        // 实化一次. build_forward_record 仅用于 GET /records/{id} 详情路径 (非高频).
        redactions: view.redactions.to_vec(),
        // 蜜罐检测命中 (RED-10): 永不含真值 (id 列表), 空 = 无命中/未检测.
        leak_alerts: view.leak_alerts,
    }
}

/// `GET /api/records/{id}?view=` 的查询参数.
///
/// - `view=raw` (默认 / 省略): 仅返回 record 原文 (含 req/resp bodies + headers).
/// - `view=meta`: 元数据档 (quant#305) — bodies / headers / parsed 全空, 其余字段照常.
///   供 WebUI 轮次详情弹窗概览 tab 小字段补全 (不为元数据传输 MB 级 body).
/// - `view=parsed`: parsed_response 直接从 record.resp_parsed 读取;
///   parsed_request 按需用 ingress codec 从 req_body 计算.
#[derive(Debug, Deserialize)]
pub(crate) struct RecordQuery {
    #[serde(default)]
    pub view: Option<String>,
}

/// `GET /api/records/{id}` 的统一响应 envelope.
///
/// - raw view: `record` 是原文, `parsed_*` 全 None.
/// - parsed view: `parsed_response` 直接从 `record.resp_parsed` 读取
///   (流式/非流式统一, 由 proxy 层的 StreamScan 累积或非流式路径一次性计算);
///   `parsed_request` 按需用 codec 计算.
///
/// 前端拿到固定 shape 后, 根据 `parse_error` 决定 fallback 到原文展示.
#[derive(Serialize)]
pub(crate) struct GetRecordResponse {
    pub record: ForwardRecord,
    pub parsed_request: Option<serde_json::Value>,
    pub parsed_response: Option<serde_json::Value>,
    pub parse_error: Option<String>,
}

impl GetRecordResponse {
    /// raw / meta 档的 envelope: 仅 record, parsed_*/parse_error 全 None.
    fn record_only(record: ForwardRecord) -> Self {
        Self {
            record,
            parsed_request: None,
            parsed_response: None,
            parse_error: None,
        }
    }
}

/// 解析 record 的 req body 为结构化 JSON (ingress writer 投影).
///
/// parsed_response 直接从 `record.resp_parsed` 读取 (proxy 层已计算).
/// parsed_request 仍需按需从 `record.req_body` 计算:
/// - protocol 短名未知 → `parsed view not available for protocol '<X>'`
/// - codec 不支持此协议 (Gemini/Ollama) → 同上
/// - body 不是合法 JSON → `invalid JSON: <err>`
/// - codec reader 解析失败 → `<reader error message>`
/// - audit_capture 未保留 (off 全部 / latest 档被会话更新请求取代; req_body 为空) → `req_body not captured ...`
///   (B2: 显式区分 "未捕获" 与 "空 body 解析失败" 两种 None 语义)
fn build_parsed_response(record: ForwardRecord) -> GetRecordResponse {
    // parsed_response 直接取 record 内的累积结果.
    let parsed_response = record.resp_parsed.clone();

    // B2: 未捕获的请求无 raw 可算 — parsed_request 恒 None, parse_error 给出
    // 明确原因 (前端区分于解析失败).
    if record.audit_capture_off {
        return GetRecordResponse {
            record,
            parsed_request: None,
            parsed_response,
            parse_error: Some("req_body not captured (audit_capture not retained)".to_string()),
        };
    }

    // parsed_request: 从 req_body 计算.
    let proto_short = record
        .path
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    let Some(native) = Protocol::from_short(&proto_short) else {
        return GetRecordResponse {
            record,
            parsed_request: None,
            parsed_response,
            parse_error: Some(format!(
                "parsed view not available for protocol '{proto_short}'"
            )),
        };
    };
    let Some(codec_proto) = crate::codec::Protocol::from_native(native) else {
        return GetRecordResponse {
            record,
            parsed_request: None,
            parsed_response,
            parse_error: Some(format!(
                "parsed view not available for protocol '{}'",
                native.name()
            )),
        };
    };

    let reader = codec_proto.reader();
    let writer = codec_proto.writer();

    let mut parsed_request = None;
    let mut parse_error: Option<String> = None;
    match serde_json::from_str::<serde_json::Value>(&record.req_body) {
        Ok(v) => match reader.read_request(&v) {
            Ok(ir) => parsed_request = Some(writer.write_request(&ir)),
            Err(e) => parse_error = Some(e.message),
        },
        Err(e) => parse_error = Some(format!("invalid JSON in req_body: {e}")),
    }

    GetRecordResponse {
        record,
        parsed_request,
        parsed_response,
        parse_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小可用的 ForwardRecord for parsed-view 测试.
    fn parsed_test_record(
        path: &str,
        req_body: &str,
        resp_body: &str,
        streamed: bool,
    ) -> crate::record::ForwardRecord {
        let mut r =
            crate::record::ForwardRecord::new("POST".into(), path.into(), vec![], req_body.into());
        r.resp_status = 200;
        r.resp_body = resp_body.into();
        r.streamed = streamed;
        r.resp_complete = true;
        r
    }

    /// 构造 meta-view 测试用的 NodeView (字段值仅服务于断言, 无业务含义).
    fn meta_test_node_view() -> NodeView {
        use crate::codec::ir::IrRole;
        use crate::dag::RoundKind;
        NodeView {
            id: Uuid::new_v4(),
            parent: None,
            is_orphan: false,
            session_id: crate::dag::SessionId(Uuid::new_v4()),
            round_role: IrRole::User,
            round_kind: RoundKind::Normal,
            req_delta_count: 1,
            has_response: true,
            created_at: chrono::Utc::now(),
            elapsed_ms: 42,
            method: "POST".into(),
            path: "/o/oa-main/v1/chat/completions".into(),
            resp_status: 502,
            redact_seed: 0,
            preview: Some("meta-view-test".into()),
            model: Some("test-model-abc".into()),
            upstream_id: "oa-main".into(),
            upstream_model: None,
            streamed: false,
            resp_complete: false,
            audit_retained: true,
            error: Some("upstream 502".into()),
            redactions: vec![("mock-x".into(), "secret-1".into())].into(),
            parsed_response: None,
            req_delta_messages: Vec::new(),
            leak_alerts: vec!["secret-1".into()],
        }
    }

    #[test]
    fn meta_view_omits_bodies_but_keeps_metadata() {
        // view=meta (quant#305): detail/resp 双 None → bodies/headers/parsed 全空,
        // 但 NodeView 元数据 (status/elapsed/model/error/leak_alerts 等) 照常到达 —
        // 概览 tab 依赖这些字段, 缺一个就是 "加载中…" 永久占位.
        let rec = build_forward_record(meta_test_node_view(), None, None);
        assert_eq!(rec.method, "POST");
        assert_eq!(rec.path, "/o/oa-main/v1/chat/completions");
        assert_eq!(rec.model.as_deref(), Some("test-model-abc"));
        assert_eq!(rec.upstream_id, "oa-main");
        assert_eq!(rec.resp_status, 502);
        assert_eq!(rec.elapsed_ms, 42);
        assert!(!rec.resp_complete);
        assert_eq!(rec.error.as_deref(), Some("upstream 502"));
        assert_eq!(rec.redactions.len(), 1);
        assert_eq!(rec.leak_alerts, vec!["secret-1".to_string()]);
        // 大数据面: bodies / headers / parsed 必须为空 (概览不发大数据请求的 wire 保证).
        assert!(rec.req_headers.is_empty());
        assert!(rec.req_body.is_empty());
        assert!(rec.resp_headers.is_empty());
        assert!(rec.resp_body.is_empty());
        assert!(rec.resp_parsed.is_none());
    }

    #[test]
    fn orphan_flag_propagates_through_meta_view() {
        // CDAG-7 wire 传播: NodeView.is_orphan → ForwardRecord.is_orphan.
        // meta 档 (detail/resp 双 None) 元数据照常透传 — 详情弹窗概览的
        // 孤儿横幅数据源, 缺失即横幅永不出现.
        let mut view = meta_test_node_view();
        view.is_orphan = true;
        let rec = build_forward_record(view, None, None);
        assert!(rec.is_orphan, "meta 档必须透传孤儿标记");
    }

    #[test]
    fn parsed_view_openai_request_returns_structured_json() {
        // 合法 OpenAI chat request: codec 应当 parse 成功, write_request 输出
        // 一个含 messages 数组的 JSON (前端 chat-bubble 渲染的基础).
        let req_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#;
        let record = parsed_test_record("/o/oa-main/v1/chat/completions", req_body, "", false);
        let resp = build_parsed_response(record);
        assert!(
            resp.parse_error.is_none(),
            "unexpected: {:?}",
            resp.parse_error
        );
        let parsed_req = resp.parsed_request.expect("parsed_request should be set");
        assert!(
            parsed_req.get("messages").is_some(),
            "parsed_request should have messages"
        );
    }

    #[test]
    fn parsed_view_unsupported_protocol_returns_error() {
        // Gemini 的 codec 尚未实现 → parse_error 应当包含 protocol 名.
        let req_body = r#"{"prompt":"hi"}"#;
        let record = parsed_test_record("/g/gem/v1/generateContent", req_body, "", false);
        let resp = build_parsed_response(record);
        assert!(resp.parsed_request.is_none());
        let err = resp.parse_error.expect("gemini should report parse_error");
        assert!(
            err.contains("gemini") || err.contains("protocol"),
            "error should mention protocol, got: {err}"
        );
    }

    #[test]
    fn parsed_view_unknown_proto_short_returns_error() {
        // 路径首段是未知简写 (非 Protocol::ALL 内的任一 short) → from_short 返回 None.
        let req_body = r#"{"q":"hi"}"#;
        let record = parsed_test_record("/x/foo/bar", req_body, "", false);
        let resp = build_parsed_response(record);
        assert!(resp.parsed_request.is_none());
        let err = resp
            .parse_error
            .expect("unknown proto should report parse_error");
        assert!(
            err.contains("'x'"),
            "error should mention the short, got: {err}"
        );
    }

    #[test]
    fn parsed_view_malformed_body_returns_error() {
        // req_body 不是合法 JSON → parse_error 应当包含 "invalid JSON".
        let record = parsed_test_record("/o/oa-main/v1/chat/completions", "not-json{", "", false);
        let resp = build_parsed_response(record);
        assert!(resp.parsed_request.is_none());
        let err = resp
            .parse_error
            .expect("malformed body should report parse_error");
        assert!(
            err.contains("invalid JSON"),
            "error should mention invalid JSON, got: {err}"
        );
    }

    #[test]
    fn parsed_view_streamed_response_uses_resp_parsed() {
        // streamed record 的 parsed_response 直接来自 record.resp_parsed
        // (由 proxy 层的 StreamScan 累积), 不再从 resp_body fold.
        let req_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#;
        let mut record = parsed_test_record("/o/oa-main/v1/chat/completions", req_body, "", true);
        // 模拟 StreamScan 产出的 resp_parsed.
        record.resp_parsed = Some(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "hello"}}]
        }));
        let resp = build_parsed_response(record);
        // request 仍应被解析.
        assert!(resp.parsed_request.is_some());
        // response 直接来自 resp_parsed.
        let parsed_resp = resp
            .parsed_response
            .expect("resp_parsed should be returned");
        assert!(parsed_resp.get("choices").is_some());
        assert!(resp.parse_error.is_none());
    }

    #[test]
    fn parsed_view_non_2xx_response_no_resp_parsed() {
        // 非 2xx 响应: proxy 层不会设置 resp_parsed (只处理 2xx 成功响应).
        let req_body = r#"{"model":"gpt-4","messages":[]}"#;
        let mut record =
            parsed_test_record("/o/oa-main/v1/chat/completions", req_body, "err", false);
        record.resp_status = 500;
        let resp = build_parsed_response(record);
        assert!(resp.parsed_request.is_some());
        assert!(resp.parsed_response.is_none());
        assert!(resp.parse_error.is_none());
    }
}
