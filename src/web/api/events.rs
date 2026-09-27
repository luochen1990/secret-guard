//! `GET /api/events`: SSE 失效通知流 (rt-push 方案 A).
//!
//! # 设计哲学
//!
//! 事件只说"变了" (data = DAG 变更计数, u64 十进制), 不携带数据 — 数据以
//! `POST /api/sync` 为 SSOT; 前端 (index.html) 收到事件后调用既有 sync。
//! 事件丢失无害: 前端保留兜底轮询 (SSE 断开时回到轮询间隔)。计数本身也只作
//! invalidation 信号: `WatchStream::new` 初值即推当前计数, 连接建立/重连自动
//! "对账"一轮 — 前端拿到任何事件都只是触发 sync, 重复触发幂等无害。
//!
//! # wire 契约 (与前端消费方 T3 冻结)
//!
//! - **未命名事件** (无 `event:` 行): 前端 `es.onmessage` 直接收 (无需
//!   addEventListener); data = 计数十进制字符串。
//! - 响应头: `NO_STORE` (cache-control + nosniff, 与其余 /api/* 同组) +
//!   `x-accel-buffering: no` (反向代理禁缓冲, SSE 帧逐跳下发)。
//! - KeepAlive: 默认 15s 空注释帧 (`:`) — EventSource 忽略注释行, 不触发
//!   onmessage, 仅保活中间设备/代理的连接表项。
//!
//! # 生命周期 (流的结束方式)
//!
//! (a) shutdown flag (`AppState.shutdown`, graceful shutdown 置 true) —
//! `with_graceful_shutdown` 会等在途连接完成, SSE 无限流必须可被唤醒终止,
//! 否则 shutdown 挂起; (b) DAG drop → watch channel 关闭 → WatchStream 自然
//! 结束 (进程退出路径); (c) 客户端断开 → hyper 取消 → 流被 drop。

use std::convert::Infallible;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::StreamExt;
use tokio_stream::wrappers::WatchStream;

use crate::state::{AppState, NO_STORE};

/// GET /api/events handler: DAG 变更计数的 SSE 流.
pub async fn events(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    // shutdown 感知: graceful shutdown 置 flag 后流在此终止 (见模块文档).
    let shutdown = shutdown_once(state.shutdown.clone());
    // WatchStream::new (而非 from_changes): 初值即推当前计数 — 连接建立/重连
    // 自动对账一轮, 消费幂等 (见模块文档).
    let stream = WatchStream::new(state.dag.subscribe_changes())
        .map(|count| Ok::<_, Infallible>(Event::default().data(count.to_string())))
        .take_until(shutdown);
    (
        NO_STORE,
        [("x-accel-buffering", "no")],
        Sse::new(stream).keep_alive(KeepAlive::new()),
    )
}

/// shutdown flag → 单次 future: flag 为 true (或 channel 关闭 = serve 已离开) 时完成.
async fn shutdown_once(mut rx: tokio::sync::watch::Receiver<bool>) {
    // wait_for 先查当前值再等变更: shutdown 在连接建立前已触发时不漏
    // (changed() 只等"下一次"变更, 会错过已置位的 flag)。Err (sender 全
    // drop) 视同 shutdown — 连接即将被拆, 主动结束流是唯一体面动作.
    let _ = rx.wait_for(|v| *v).await;
}
