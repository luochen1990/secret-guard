//! 响应扇出路径 (fan_out): 把上游响应既回传给客户端, 又累积到 DAG record.
//!
//! # 职责边界
//!
//! 三条 fan_out 路径, 按 "redact / 流式" 两维度选择 (调用方 same_proto / cross_proto
//! 负责选路):
//!
//! - [`fan_out_streaming`]: 字节流式透传, 用于 same-proto + 无 Redact. 客户端响应 = 上游字节.
//! - [`fan_out_streaming_with_restore`]: 流式 + IR restore, 用于 same-proto + Redact + 流式响应.
//!   用 StreamTranslate 同协议 restore 模式 (egress SSE → IR event → restore → ingress SSE).
//!   失去 byte-exact (IR re-serialize), 但保留流式 UX.
//! - [`fan_out_buffered_ir`]: 非流式 + IR restore, 用于 same-proto + Redact + 非流式 / cross-proto.
//!   完整累积响应, restore, 一次性返回.
//!
//! 两条流式路径的 spawn task 骨架 (chunk 循环 / 错误分支 / 记录累积 / attach_response)
//! 逐行同构, 抽为共享的 [`fanout_stream_task`] + [`ChunkPipeline`] (chunk 变换策略),
//! 仅 final parsed / body 计算作闭包注入 (差异是语义性的: 流式 vs 非流式 parse / body
//! 保留策略). `fan_out_buffered_ir` 结构差异大, 不参与合并.
//!
//! **客户端响应永远无大小上限**; 只有 record 累积受 `MAX_RESP_BODY_RECORD` (32 MiB) 约束.
//!
//! # 流式响应处理
//!
//! 用 mpsc channel 做扇出: 一个后台 task 读取上游 chunk, 同时写一份给客户端 channel
//! 一份累积给记录. 顺序上**先 send 后 acc**, 让客户端反向压力能尽早传到上游.
//! 流结束 / 客户端断开 / 上游错误 都触发记录更新 (带 incomplete 标记).

use std::time::Instant;

use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::warn;

use crate::dag::{ConversationDag, ResponseData};
use crate::error::AppError;
use crate::redact::RedactionMap;

use super::helpers::{build_response_headers, redact_headers, utf8_view};
#[cfg(feature = "consistency-check")]
use super::recorder::assert_resp_parsed_matches_source_nonstream;
use super::recorder::{
    ERR_CLIENT_DISCONNECTED, ERR_RESP_CAP_EXCEEDED, ERR_STREAM_IDLE_TIMEOUT, ParsedSync,
    RecordAccumulator, next_chunk,
};

// ─── 流式 chunk 变换策略 (两条流式路径的差异点) ─────────────────────────────

/// 流式扇出的 chunk 管道: [`fanout_stream_task`] 的 chunk 变换策略.
///
/// - [`PassthroughPipe`]: 字节透传 ([`fan_out_streaming`], 无 Redact).
/// - [`RestorePipe`]: StreamTranslate 同协议 restore ([`fan_out_streaming_with_restore`]).
trait ChunkPipeline {
    /// 变换单个上游 chunk (identity clone / IR restore 翻译), 返回要发给客户端的字节.
    /// `None` = 本 chunk 无输出 (restore 模式下 chunk 不足以构成完整 SSE 帧是常态;
    /// 透传模式恒 `Some` — 即便空 chunk 也照发, 保持与历史行为逐字节一致).
    fn transform(&mut self, chunk: &Bytes) -> Option<Bytes>;
    /// 流结束后输出尾巴字节 (identity: 空; restore: flush 残留 + 终止符). 上游错误 /
    /// 客户端断开也调用 — 严格的 OpenAI 客户端需要 `[DONE]` 终止符才不 hang.
    fn finish_tail(&mut self) -> Bytes;
}

/// 字节透传管道 (无 Redact, byte-exact).
struct PassthroughPipe;

impl ChunkPipeline for PassthroughPipe {
    fn transform(&mut self, chunk: &Bytes) -> Option<Bytes> {
        Some(chunk.clone()) // Bytes clone 是 ref-count, 无拷贝.
    }
    fn finish_tail(&mut self) -> Bytes {
        Bytes::new()
    }
}

/// IR restore 管道: egress SSE → IR 事件 → restore (mock→real) → ingress SSE.
struct RestorePipe {
    translate: crate::codec::stream::StreamTranslate,
}

impl ChunkPipeline for RestorePipe {
    fn transform(&mut self, chunk: &Bytes) -> Option<Bytes> {
        let out = self.translate.feed(chunk);
        (!out.is_empty()).then(|| Bytes::from(out))
    }
    fn finish_tail(&mut self) -> Bytes {
        Bytes::from(self.translate.finish())
    }
}

// ─── 流式扇出共享骨架 ────────────────────────────────────────────────────────

/// 流式扇出骨架的固定上下文 (差异部分 — pipe / finalize 闭包 — 单独传).
struct FanoutStreamCtx {
    dag: ConversationDag,
    record_id: uuid::Uuid,
    started: Instant,
    /// 供 record 用的响应 headers (已脱敏前 clone; 原始 headers 归客户端响应构造).
    resp_headers_for_record: HeaderMap,
    status_u16: u16,
    /// record 的 streamed 标志 (restore 路径恒 true).
    streamed: bool,
    stream_idle_timeout: Option<std::time::Duration>,
}

/// 两条流式扇出路径的共享骨架: spawn task 内的 chunk 循环 + 记录 + 收尾.
///
/// 共享 (逐行同构, 历史 bug 修一处即两处生效):
/// next_chunk 超时保护循环 → pipe.transform (空输出跳过) → tx.send (失败 =
/// ERR_CLIENT_DISCONNECTED break) → recorder.push_record → parsed_sync.feed
/// (未 overflow 时) → 错误分支 (ERR label + warn + send Err + break) →
/// pipe.finish_tail 发送 → elapsed → finalize 闭包 → attach_response.
///
/// 差异 (闭包注入):
/// - `pipe`: chunk 变换 (透传 / restore).
/// - `finalize_parsed`: 最终 parsed view (流式 ParsedSync 快照 / 非流式一次性 parse).
/// - `finalize_body`: record 的 raw_resp_body (banner / 空 / utf8_view 策略).
async fn fanout_stream_task(
    ctx: FanoutStreamCtx,
    upstream_resp: reqwest::Response,
    tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
    parsed_sync: Option<ParsedSync>,
    mut pipe: impl ChunkPipeline + Send + 'static,
    finalize_parsed: impl FnOnce(Option<ParsedSync>, &RecordAccumulator) -> Option<serde_json::Value>
    + Send
    + 'static,
    finalize_body: impl FnOnce(&RecordAccumulator) -> String + Send + 'static,
) {
    let FanoutStreamCtx {
        dag,
        record_id,
        started,
        resp_headers_for_record,
        status_u16,
        streamed,
        stream_idle_timeout,
    } = ctx;

    let mut stream = upstream_resp.bytes_stream();
    let mut recorder = RecordAccumulator::new();
    let mut parsed_sync = parsed_sync;

    while let Some(chunk) = next_chunk(&mut stream, stream_idle_timeout, &record_id).await {
        match chunk {
            Ok(b) => {
                // 先 send 后 acc: 让客户端反向压力尽早传到上游.
                if let Some(out) = pipe.transform(&b)
                    && tx.send(Ok(out)).await.is_err()
                {
                    recorder.set_error(ERR_CLIENT_DISCONNECTED);
                    break;
                }
                // record 累积上游原始字节 (LLM 视角; restore 路径同 — 与 transform 喂同一份 b).
                recorder.push_record(&b, record_id);
                // ParsedSync 累积 (未 overflow 时).
                if !recorder.overflow
                    && let Some(ps) = parsed_sync.as_mut()
                {
                    ps.feed(&b);
                }
            }
            Err(e) => {
                let err_label = super::recorder::stream_err_label(&e);
                warn!(%record_id, error = %e, err = err_label, "upstream stream error mid-flight");
                let _ = tx.send(Err(e)).await;
                recorder.set_error(err_label);
                break;
            }
        }
    }
    // 流末尾: 管道尾巴 (restore 模式 = flush 残留 + 终止符; 即便 upstream error 也要发,
    // 否则严格的 OpenAI 客户端会 hang). 仅 tx.send 失败 (client disconnect) 时由 `let _` 吞掉.
    let tail = pipe.finish_tail();
    if !tail.is_empty() {
        let _ = tx.send(Ok(tail)).await;
    }

    let elapsed = started.elapsed().as_millis() as u64;
    let final_parsed = finalize_parsed(parsed_sync, &recorder);
    let body = finalize_body(&recorder);
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
    // record 最终态写入后再打摘要 (#160): status/elapsed 覆盖完整流时长,
    // error (client disconnect / upstream error / overflow) 已就位.
    super::recorder::log_forward_summary(&dag, record_id);
}

/// 流式字节扇出: 把上游 SSE 流式转发给客户端, 同时 (若有 codec) 用 StreamScan
/// 累积 parsed view 到 DAG. 无 redact, 保持 byte-exact + 流式 UX.
///
/// `codec_proto = None` 时 (Gemini/Ollama 无 codec) 跳过 StreamScan,
/// parsed view 不可用 (前端 fallback raw).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fan_out_streaming(
    dag: ConversationDag,
    record_id: uuid::Uuid,
    started: Instant,
    upstream_resp: reqwest::Response,
    resp_status: StatusCode,
    resp_headers: HeaderMap,
    streamed: bool,
    codec_proto: Option<crate::codec::Protocol>,
    stream_idle_timeout: Option<std::time::Duration>,
) -> Result<Response<Body>, AppError> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    let resp_headers_for_record = resp_headers.clone();
    let status_u16 = resp_status.as_u16();

    // ParsedSync: 仅对流式响应启用 (非流式是单个 JSON, 不是 SSE).
    // 非流式响应的 parsed 在流结束后一次性计算.
    let parsed_sync = if streamed {
        codec_proto.map(|cp| ParsedSync::new(cp, dag.clone(), record_id))
    } else {
        None
    };

    tokio::spawn(fanout_stream_task(
        FanoutStreamCtx {
            dag,
            record_id,
            started,
            resp_headers_for_record,
            status_u16,
            streamed,
            stream_idle_timeout,
        },
        upstream_resp,
        tx,
        parsed_sync,
        PassthroughPipe,
        move |parsed_sync, recorder| {
            // 最终 parsed: 流式用 ParsedSync 快照; 非流式一次性 codec parse.
            if streamed {
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
            }
        },
        move |recorder| {
            if recorder.overflow {
                super::TRUNCATED_BANNER.to_string()
            } else if streamed && (200..300).contains(&status_u16) {
                // 2xx 流式成功响应: 不保留原始 SSE 字节 (骨架开销大, parsed view 已覆盖语义内容).
                // 注: recorder.acc 仍累积了原始字节 (最大 32 MiB) 但此处丢弃. 见
                // RecordAccumulator 文档 "内存开销" 段 (followup: 分片存储优化).
                String::new()
            } else {
                // 非流式响应保留原始 body (raw view 可用, 且 body 通常不大).
                utf8_view(&recorder.acc)
            }
        },
    ));

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
pub(crate) async fn fan_out_buffered_ir(
    dag: ConversationDag,
    record_id: uuid::Uuid,
    started: Instant,
    upstream_resp: reqwest::Response,
    resp_status: StatusCode,
    resp_headers: HeaderMap,
    streamed: bool,
    codec_proto: crate::codec::Protocol,
    redaction_map: RedactionMap,
    stream_idle_timeout: Option<std::time::Duration>,
) -> Result<Response<Body>, AppError> {
    let resp_headers_for_record = resp_headers.clone();
    let status_u16 = resp_status.as_u16();

    let mut stream = upstream_resp.bytes_stream();
    let mut recorder = RecordAccumulator::new();
    while let Some(chunk) = next_chunk(&mut stream, stream_idle_timeout, &record_id).await {
        match chunk {
            Ok(b) => {
                // buffered_ir 路径: 超过 cap 时记录 error_kind 并中断流
                // (与 streaming 路径的 "继续透传但停止记录" 语义不同 — buffered_ir
                // 无法透传, 只能整体返回, 故超 cap 直接中止).
                if recorder.acc.len() + b.len() > super::MAX_RESP_BODY_RECORD {
                    let remaining = super::MAX_RESP_BODY_RECORD.saturating_sub(recorder.acc.len());
                    if remaining > 0 {
                        recorder.acc.extend_from_slice(&b[..remaining]);
                    }
                    recorder.set_error(ERR_RESP_CAP_EXCEEDED);
                    break;
                }
                recorder.acc.extend_from_slice(&b);
            }
            Err(e) => {
                recorder.set_error(super::recorder::stream_err_label(&e));
                break;
            }
        }
    }

    let elapsed = started.elapsed().as_millis() as u64;

    // Parse 为 IR (失败则原样透传, 不 restore).
    // 注: 若 stream 中途出错 (idle timeout / upstream error / cap exceeded),
    // recorder.acc 是**截断**的字节, parse 大概率失败且即使"成功"也是不完整 JSON.
    // 这种情况返回错误响应 (而非截断 JSON 的 200), 让客户端知道响应不完整.
    let reader = codec_proto.reader();
    let writer = codec_proto.writer();
    let mut resp_parsed_for_record: Option<serde_json::Value> = None;
    // #158: parse 失败 fallback 时, 若本请求做过 redact (map 非空), body 中的 mock
    // 不会被 restore — 客户端拿到假 secret. 记一条 WARN 让该逃逸可感知
    // (行为不变: 仍原样透传, best-effort 原则).
    let warn_mock_not_restored = |detail: &str| {
        if !redaction_map.is_empty() {
            warn!(
                %record_id,
                detail,
                "response parse failed with redactions in flight; \
                 mock not restored; client will see mock values"
            );
        }
    };
    let client_bytes: Vec<u8> = if recorder.error_kind.is_some() {
        // stream 中途中断 → 不 parse, 返回空 body (状态码下方调整为 502/504).
        Vec::new()
    } else {
        match serde_json::from_slice::<serde_json::Value>(&recorder.acc) {
            Ok(v) => match reader.read_response(&v) {
                Ok(mut ir) => {
                    // record 存 LLM 视角 (restore 之前, 含 mock).
                    resp_parsed_for_record = Some(writer.write_response(&ir));
                    crate::redact::restore_ir_response(&mut ir, &redaction_map);
                    let restored = writer.write_response(&ir);
                    serde_json::to_vec(&restored).unwrap_or_else(|_| recorder.acc.clone())
                }
                Err(e) => {
                    warn_mock_not_restored(&format!(
                        "codec reader ({}) rejected response: {}",
                        reader.name(),
                        e.message
                    ));
                    recorder.acc.clone() // parse 失败: 原样返回 (无 restore).
                }
            },
            Err(e) => {
                warn_mock_not_restored(&format!(
                    "response body is not a single JSON value ({e}); \
                     likely SSE-shaped body under a non-SSE content-type"
                ));
                recorder.acc.clone() // 非 JSON: 原样返回.
            }
        }
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
    // stream 中途中断时, 客户端响应用错误状态码 (而非原始 2xx),
    // 避免给客户端返回"200 但 body 是截断/空"的误导性成功响应.
    // 在 attach_response 之前计算 (error_kind 之后会被 move 到 ResponseData).
    let client_status = if let Some(err) = recorder.error_kind.as_deref() {
        if err == ERR_STREAM_IDLE_TIMEOUT {
            StatusCode::GATEWAY_TIMEOUT
        } else {
            StatusCode::BAD_GATEWAY
        }
    } else {
        resp_status
    };
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
    // record 最终态写入后打摘要 (#160). 注意: client_status (错误中断时 502/504)
    // 只影响客户端响应, record 的 resp_status 仍是上游原值 — 摘要以 record 为准.
    super::recorder::log_forward_summary(&dag, record_id);

    let mut resp = Response::new(Body::from(client_bytes));
    *resp.status_mut() = client_status;
    *resp.headers_mut() = build_response_headers(&resp_headers);
    Ok(resp)
}

/// 流式扇出 + IR restore: 用 [`crate::codec::stream::StreamTranslate`] 同协议模式,
/// 实时翻译 egress SSE → IR 事件 → restore → ingress SSE. 保持流式 UX.
///
/// 用于: 同协议 + redact + 流式响应.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fan_out_streaming_with_restore(
    dag: ConversationDag,
    record_id: uuid::Uuid,
    started: Instant,
    upstream_resp: reqwest::Response,
    resp_status: StatusCode,
    resp_headers: HeaderMap,
    codec_proto: crate::codec::Protocol,
    redaction_map: RedactionMap,
    stream_idle_timeout: Option<std::time::Duration>,
) -> Result<Response<Body>, AppError> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    let resp_headers_for_record = resp_headers.clone();
    let status_u16 = resp_status.as_u16();

    // 同协议 + restore 模式: ingress == egress, 但 IR re-serialize 用于 restore.
    // restore hook 由本层 (proxy) 注入 — codec::stream 不依赖 redact (解环 #145).
    let translate = crate::codec::stream::StreamTranslate::new_same_proto_restore(
        codec_proto,
        Box::new(crate::redact::StreamingRestorerSet::new(redaction_map)),
    );
    // ParsedSync: 累积 parsed view (LLM 视角, 含 mock, 与 record 语义一致).
    // 喂的是上游原始字节 (与 pipe.transform 同一份 b), ParsedSync 内部用 codec reader 解析.
    let parsed_sync = ParsedSync::new(codec_proto, dag.clone(), record_id);

    tokio::spawn(fanout_stream_task(
        FanoutStreamCtx {
            dag,
            record_id,
            started,
            resp_headers_for_record,
            status_u16,
            streamed: true,
            stream_idle_timeout,
        },
        upstream_resp,
        tx,
        Some(parsed_sync),
        RestorePipe { translate },
        move |parsed_sync, _recorder| {
            // 最终 parsed 快照. 即使 error_kind (client disconnect / upstream error),
            // 也保留截至断流时的累积内容 — 用户能看到部分响应比看到空白更有价值.
            // (overflow 时同理: 截至 Overflow 前的内容比 truncate banner 更有用.)
            Some(parsed_sync.expect("restore 路径恒有 ParsedSync").finalize())
        },
        move |recorder| {
            if recorder.overflow {
                super::TRUNCATED_BANNER.to_string()
            } else {
                // 此路径仅用于 2xx 成功响应 (非 2xx 走 fan_out_buffered_ir).
                // 2xx 流式成功响应不保留原始 SSE 字节 (parsed view 已覆盖语义内容).
                String::new()
            }
        },
    ));

    let body = Body::from_stream(ReceiverStream::new(rx));
    let mut resp = Response::new(body);
    *resp.status_mut() = resp_status;
    let out_headers = build_response_headers(&resp_headers);
    // restore 后的 SSE, content-type 仍是 text/event-stream (SSE 是 SSE).
    // 不强改 content-type, 保留上游声明的.
    *resp.headers_mut() = out_headers;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::http::StatusCode;

    use crate::codec::ir::{IrBlock, IrMessage, IrRole};
    use crate::dag::{CallEvent, ConversationDag, PolicySnapshot};

    // ─── MAX_RESP_BODY_RECORD 截断契约 (核心契约: 客户端响应无上限 vs record 有 cap) ─
    //
    // 契约 (proxy//!): "客户端响应永远无大小上限; 只有 record 累积受
    // MAX_RESP_BODY_RECORD (32 MiB) 约束". 一旦回归会静默截断用户响应.
    //
    // 三个 fan_out 都有 overflow 分支但内联在 spawn 闭包里, 这里用 mockito 构造
    // 超大上游响应, 直接调用 fan_out_streaming 端到端验证: record 被截断 + 带 banner,
    // 而客户端通过 channel 收到完整 body.

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
        // mockito 上游: 返回 cap+1 字节 (刚好触发 overflow).
        let cap_plus_one = super::super::MAX_RESP_BODY_RECORD + 1;
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
            policy: Arc::new(PolicySnapshot::default()),
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
            None,  // stream_idle_timeout=None (测试不禁用超时保护)
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
}
