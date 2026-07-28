//! 转发记录 DTO (web 层响应序列化用).
//!
//! 历史上这里是 RecordStore (扁平 VecDeque 存储), 现已迁移到 [`crate::dag::ConversationDag`]
//! (内容寻址 + Merkle prefix + FIFO 淘汰). 本文件仅保留 [`ForwardRecord`] DTO,
//! 作为 Web API GET /records/{id} 响应的 JSON shape (供 `crate::web::api` 构造).
//!
//! 注: 旧的 `RecordFilter` enum + `GET /api/records` 扁平分页已删除 (由 session-aware
//! sync API 替代), 故本文件不再含 RecordFilter.
//!
//! DTO 字段从 [`crate::dag`] 的 NodeView / NodeDetail / ResponseData 派生, 由
//! `crate::web::api` 在查询时填充. 保留这个独立 DTO (而非直接 serialize DAG 内部类型)
//! 是为了:
//! - 维持 Web API JSON shape 稳定 (不随 DAG 内部结构变化而漂移);
//! - 集中"暴露哪些字段给前端"的决策 (eg `redactions` 不含真实 secret value).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 单条转发记录 (Web DTO).
///
/// 字段从 `crate::web::dto::NodeView` / `crate::web::dto::NodeDetail` / `crate::dag::ResponseData`
/// 派生, 由 `crate::web::api` 构造. 不再是存储后端 (那是 DAG 的职责).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRecord {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub method: String,
    pub path: String,
    /// 客户端请求的所有 header (敏感 header 如 Authorization 会被脱敏).
    pub req_headers: Vec<(String, String)>,
    /// 客户端请求 body (LLM 视角, 已 redact; UTF-8 视图).
    pub req_body: String,
    /// 上游响应状态码 (0 表示尚未收到响应 / 上游错误).
    pub resp_status: u16,
    /// 上游响应的所有 header.
    pub resp_headers: Vec<(String, String)>,
    /// 上游响应 body.
    ///
    /// - **非流式响应**: 原始 JSON body (与上游返回的字节一致, UTF-8 视图).
    /// - **流式响应**: **不再保留原始 SSE 字节** (骨架开销大、可读性差).
    ///   流式响应的语义内容通过 [`resp_parsed`](Self::resp_parsed) 累积.
    ///   raw view 在流式场景下显示 "raw bytes not retained for streamed responses".
    pub resp_body: String,
    /// 解析后的响应 (ingress 协议的 canonical chat JSON, chat-bubble 友好).
    ///
    /// - **非流式**: 在响应完成时由 codec reader → IR → writer 计算一次.
    /// - **流式**: 在流过程中由 `StreamScan` 增量累积, 节流写入.
    ///
    /// `None` 表示尚未有解析结果 (流刚开始 / codec 不支持此协议 / 解析失败).
    /// 对应 `GET /records/{id}?view=parsed` 的 `parsed_response` 字段.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_parsed: Option<serde_json::Value>,
    /// 端到端耗时 (毫秒).
    pub elapsed_ms: u64,
    /// 流式标记: true 表示响应是 chunked / SSE.
    pub streamed: bool,
    /// 响应完整性: false 表示上游错误/客户端断开导致响应中断.
    pub resp_complete: bool,
    /// 错误诊断 (仅在出错时填入; 用于 Web UI 展示).
    pub error: Option<String>,
    /// 本次请求中实际发生的 redact 结果 (权威投影, 供 WebUI 渲染).
    ///
    /// 每个 tuple = `(mock_value, secret_id)`. **永不**包含真实 secret 值, 因此可以
    /// 直接序列化到 GET API 响应. 空 vec 表示本次请求没有发生 redact
    /// (passthrough 路径, 或同/跨协议路径但 IR 中没有 secret 命中).
    ///
    /// 来源: 在 [`crate::proxy`] 三处 push 点, 从 `RedactionMap` + `secrets_snapshot`
    /// 派生而来. 仅记录命中的 secret — 若 secret 在表中但本次请求体没有, 不进入此列表.
    ///
    /// `#[serde(default)]` 让旧版序列化数据 (无此字段) 仍能反序列化为空 vec.
    #[serde(default)]
    pub redactions: Vec<(String, String)>,
}

impl ForwardRecord {
    pub fn new(
        method: String,
        path: String,
        req_headers: Vec<(String, String)>,
        req_body: String,
    ) -> Self {
        Self {
            id: Uuid::nil(),
            created_at: Utc::now(),
            method,
            path,
            req_headers,
            req_body,
            resp_status: 0,
            resp_headers: Vec::new(),
            resp_body: String::new(),
            resp_parsed: None,
            elapsed_ms: 0,
            streamed: false,
            resp_complete: false,
            error: None,
            redactions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小合法 ForwardRecord JSON, 缺省字段 (resp_parsed / redactions) 模拟旧版序列化.
    /// 注入点: 调用方按需往 JSON 里塞老格式数据, 验证反序列化的向后兼容契约.
    fn legacy_record_json(extras: &str) -> String {
        format!(
            r#"{{
                "id": "00000000-0000-0000-0000-000000000000",
                "created_at": "2024-01-01T00:00:00Z",
                "method": "POST",
                "path": "/o/p1/v1/chat",
                "req_headers": [],
                "req_body": "hello",
                "resp_status": 200,
                "resp_headers": [],
                "resp_body": "world",
                "elapsed_ms": 5,
                "streamed": false,
                "resp_complete": true{extras}
            }}"#
        )
    }

    // ─── redactions 字段向后兼容 (核心契约: 旧版数据无此字段仍能反序列化) ──────
    //
    // `#[serde(default)]` 的契约注释明确要求: 让旧版序列化数据 (无 redactions 字段)
    // 仍能反序列化为空 vec. 这是 Web API DTO 的核心向后兼容保证, 一旦回归会让前端
    // timeline 渲染在解析旧版缓存时崩溃.

    #[test]
    fn legacy_json_without_redactions_deserializes_to_empty_vec() {
        // 旧版 JSON: 完全没有 redactions 字段.
        let json = legacy_record_json("");
        let rec: ForwardRecord = serde_json::from_str(&json).expect("legacy JSON must parse");
        assert!(
            rec.redactions.is_empty(),
            "missing redactions field must default to empty vec"
        );
        // 其他字段仍正确填充.
        assert_eq!(rec.method, "POST");
        assert_eq!(rec.resp_body, "world");
        assert!(rec.resp_complete);
    }

    #[test]
    fn json_with_redactions_deserializes_correctly() {
        // 当前版本 JSON: 带 redactions, 验证正常 round-trip.
        let json = legacy_record_json(
            r#",
                "redactions": [["sgm_abc", "secret-id-1"]]"#,
        );
        let rec: ForwardRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(
            rec.redactions,
            vec![("sgm_abc".into(), "secret-id-1".into())]
        );
    }

    // ─── ForwardRecord::new 默认值契约 (11 个默认字段) ──────────────────────
    //
    // new() 是构造一条"请求已收到, 响应未到"的占位记录的标准入口, 其默认值
    // 必须与 DAG Node 的初始状态语义对齐 (resp_status=0, resp_complete=false 等).
    // 任一默认值漂移会让 web 层误判请求状态.

    #[test]
    fn new_sets_expected_defaults_for_pending_response() {
        let rec = ForwardRecord::new(
            "POST".into(),
            "/o/p1/v1/chat".into(),
            vec![("content-type".into(), "application/json".into())],
            "hello".into(),
        );
        // 显式传入的字段.
        assert_eq!(rec.method, "POST");
        assert_eq!(rec.path, "/o/p1/v1/chat");
        assert_eq!(
            rec.req_headers,
            vec![("content-type".into(), "application/json".into())]
        );
        assert_eq!(rec.req_body, "hello");
        // 11 个默认字段: 必须逐一 pin 住, 任一变化都会让前端状态判断出错.
        assert_eq!(rec.id, Uuid::nil(), "new record id must be nil placeholder");
        assert_eq!(rec.resp_status, 0, "pending response must have status 0");
        assert!(rec.resp_headers.is_empty(), "no response headers yet");
        assert!(rec.resp_body.is_empty(), "no response body yet");
        assert!(rec.resp_parsed.is_none(), "no parsed view until response");
        assert_eq!(rec.elapsed_ms, 0, "elapsed not measured until response");
        assert!(!rec.streamed, "streamed flag set after response");
        assert!(
            !rec.resp_complete,
            "pending record must be marked incomplete"
        );
        assert!(rec.error.is_none(), "no error until one occurs");
        assert!(rec.redactions.is_empty(), "no redactions until redact runs");
    }

    // ─── resp_parsed 字段 skip_serializing_if = Option::is_none ─────────────
    //
    // `#[serde(skip_serializing_if = "Option::is_none")]` 让 None 字段不出现在 JSON 中,
    // 保持响应 payload 精简. 这个测试 pin 住该行为, 防止未来误改成 default + 不 skip
    // 导致前端收到额外的 "resp_parsed": null 字段.

    #[test]
    fn none_resp_parsed_is_omitted_from_json() {
        let rec = ForwardRecord::new("POST".into(), "/p".into(), vec![], "body".into());
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            !json.contains("resp_parsed"),
            "None resp_parsed must be omitted from JSON, got: {json}"
        );
    }

    #[test]
    fn some_resp_parsed_is_included_in_json() {
        let mut rec = ForwardRecord::new("POST".into(), "/p".into(), vec![], "body".into());
        rec.resp_parsed = Some(serde_json::json!({"role": "assistant"}));
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            json.contains("resp_parsed"),
            "Some resp_parsed must be present in JSON, got: {json}"
        );
    }

    // ─── SEC-5: PolicySnapshot 不进 WebUI DTO ────────────────────────────
    //
    // 契约 (docs/design/contracts.md §7 SEC-5): DAG Node 持有的 PolicySnapshot (含
    // secret value) 仅后端用, 永不序列化进 WebUI DTO. ForwardRecord 是 GET /records/{id}
    // 响应的 DTO, 由 web::api::build_forward_record 从 DAG 视图派生; 它的字段集合
    // (见 struct 定义) 不含 policy. 本 property 是防御性第二道闸 — 即便未来有人误加
    // policy 字段或字段值被污染, 序列化扫描会 fail.
    //
    // 类型系统层: ForwardRecord 的字段集合不含 PolicySnapshot / Arc<PolicySnapshot>
    // (见 struct 定义, 每个字段都是 String / Vec / Option<serde_json::Value> 等基础类型).
    // property 层: 用包含可识别 marker 的字段构造 ForwardRecord, 序列化后扫描 JSON.

    use proptest::prelude::*;

    proptest! {
        /// SEC-5: ForwardRecord 序列化后的 JSON 不含 PolicySnapshot 字段.
        ///
        /// 验证两层:
        /// 1. JSON 不含字段名 "policy" (PolicySnapshot 若被误加为字段, serde 默认用
        ///    字段名 "policy" 序列化).
        /// 2. JSON 不含类型名 "PolicySnapshot" (即便用 rename, 类型名也不会自然出现).
        ///
        /// 生成器: 用任意可识别 marker 填充 ForwardRecord 的字符串字段 (method / path /
        /// req_body / resp_body / error), 确保扫描覆盖所有字符串字段. marker 字符集
        /// [a-z] 避免与 "policy"/"PolicySnapshot" 子串意外重叠.
        #[test]
        fn prop_policy_snapshot_not_in_forward_record(
            method_marker in "[a-z]{3,8}",
            path_marker in "[a-z]{3,8}",
            body_marker in "[a-z]{3,8}",
            error_marker in "[a-z]{3,8}",
        ) {
            // 假设 marker 不含 "policy" 子串 (字符集 [a-z] 理论上可能拼出 "policy",
            // 但概率极低; 此 assume 确保断言不被假阳性干扰).
            prop_assume!(
                !method_marker.contains("policy") && !path_marker.contains("policy")
                    && !body_marker.contains("policy") && !error_marker.contains("policy"),
                "marker must not contain 'policy' substring"
            );
            let mut rec = ForwardRecord::new(
                format!("POST-{method_marker}"),
                format!("/o/{path_marker}/v1/chat"),
                vec![],
                format!("body-{body_marker}"),
            );
            rec.error = Some(format!("err-{error_marker}"));
            rec.resp_parsed = Some(serde_json::json!({"k": "v"}));
            rec.redactions = vec![("mock-x".into(), "secret-id-1".into())];

            let json = serde_json::to_string(&rec).expect("serialize ForwardRecord");
            // 核心: JSON 不得含字段名 "policy" 或类型名 "PolicySnapshot".
            prop_assert!(
                !json.contains("\"policy\"") && !json.contains("PolicySnapshot"),
                "SEC-5 violation: ForwardRecord JSON contains PolicySnapshot. json={}",
                json
            );
        }
    }

    /// SEC-5 扫描器灵敏度守卫: 验证 `json.contains("\"policy\"")` 在 JSON 真含该字段时
    /// 返回 true. 若 serde_json 改变序列化格式 (如字段名加引号方式变化) 导致扫描器永远
    /// false, 上方 proptest 会退化为空洞断言 (恒真), 静默放过 PolicySnapshot 泄漏.
    /// 本 sanity test 把这条隐患显式化为编译期断言.
    #[test]
    fn sec5_scanner_detects_policy_field_when_present() {
        let json_with_policy = serde_json::json!({"policy": "secret-value"});
        let serialized = serde_json::to_string(&json_with_policy).unwrap();
        assert!(
            serialized.contains("\"policy\""),
            "SEC-5 scanner broken: json.contains(\"\\\"policy\\\"\") is false even when field \
             present. sec5 proptest would pass vacuously. json={serialized}"
        );
    }
}
