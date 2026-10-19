//! graceful shutdown 生命周期端到端契约 (FWD-8 drain + USAGE-8 尾批落库, #365).
//!
//! 与 tests/integration.rs 的进程内装配 (直接构造 AppState) 不同, 本文件 spawn
//! 真实二进制, 覆盖 [`server::serve`] 全路径: 真实 SIGTERM → shutdown flag →
//! drain → (USAGE-8) usage 尾批落库屏障 → 进程退出. socket_activation.rs 的
//! SIGTERM 测试发信号时**无在途请求**, 本文件补 "慢上游在途请求 + SIGTERM" 的
//! 完整 drain 语义断言.
//!
//! 测试边界 (如实): 慢上游是进程内 axum server (current_thread runtime 下
//! `tokio::spawn`, 主流程全异步不阻塞它); 与 integration.rs `spawn_slow_upstream`
//! 同型, 但集成测试文件间不共享代码 (各自独立 binary).

#![cfg(unix)]

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::json;

/// 慢上游: `POST /v1/chat/completions` → sleep(delay) → 200 JSON (含 usage 字段,
/// 供 USAGE-8 断言事件来源). 返回 base URL (裸根, 不含 /v1 — 同协议透传下请求
/// 路径原样流过, 与 integration.rs `openai_provider` 的 base_url 约定一致).
async fn spawn_slow_upstream(delay: Duration) -> String {
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move || async move {
            tokio::time::sleep(delay).await;
            axum::response::Json(json!({
                "model": "test-model",
                "choices": [{"message": {"role": "assistant", "content": "drained-ok"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8}
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

struct SgProc {
    child: Child,
    port: u16,
    /// state.toml 所在目录 — usage.sqlite3 与其同目录 (state_dir_artifact).
    dir: std::path::PathBuf,
}

/// spawn 真实 secret-guard 二进制 + 就绪探测 (GET / 收 200).
async fn spawn_secret_guard(upstream_base: &str) -> SgProc {
    let dir = std::env::temp_dir().join(format!("sg-drain-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("secret-guard.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[[providers]]
id = "up"
kind = "direct"
enabled = true

[[providers.endpoints]]
protocol = "openai"
base_url = "{upstream_base}"
"#
        ),
    )
    .unwrap();

    // 空闲端口探测 (bind :0 → 取 port → drop; race 窗口极小, 失败形态 =
    // secret-guard bind 报错退出, try_wait 断言可诊断).
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let state = dir.join("state.toml");
    let child = Command::new(env!("CARGO_BIN_EXE_secret-guard"))
        .args([
            "run",
            "--config",
            config.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        // tracing 日志走 stdout — piped 供退出后断言/诊断 (日志量 << pipe 容量,
        // 无死锁风险); stderr 同 piped 防泄漏到测试输出.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut proc = SgProc { child, port, dir };
    // 就绪探测: GET / 200 (WebUI 入口, 不触上游). Host 带 127.0.0.1:port 过
    // SEC-7 Host guard.
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "secret-guard did not become ready in 30s"
        );
        assert!(
            proc.child.try_wait().unwrap().is_none(),
            "secret-guard exited prematurely (bind failed?)"
        );
        let resp = client
            .get(format!("http://127.0.0.1:{}/", proc.port))
            .timeout(Duration::from_secs(2))
            .send()
            .await;
        if let Ok(r) = resp
            && r.status().as_u16() == 200
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    proc
}

impl SgProc {
    /// 发起在途转发请求 (OpenAI 非流式 chat), 返回持有响应 future 的 task.
    /// 请求体 model "test-model" 供 usage 断言归因.
    fn start_inflight_request(
        &self,
    ) -> tokio::task::JoinHandle<Result<reqwest::Response, reqwest::Error>> {
        let url = format!("http://127.0.0.1:{}/o/up/v1/chat/completions", self.port);
        let client = reqwest::Client::new();
        let body = json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hello"}],
        });
        tokio::spawn(async move { client.post(url).json(&body).send().await })
    }

    fn sigterm(&mut self) {
        // child.pid 即 secret-guard 进程号 (直接 spawn, 无中间编排进程).
        let pid = self.child.id() as libc::pid_t;
        let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
        assert_eq!(rc, 0, "kill(SIGTERM) failed");
    }

    /// 等进程退出 (deadline 内), 返回 (exit success, stdout 日志).
    /// 消费 child (wait_with_output 取所有权).
    async fn wait_exit(mut self, secs: u64) -> (bool, String) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "secret-guard did not exit within {secs}s after SIGTERM (drain hung?)"
            );
            if self.child.try_wait().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let out = self.child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }
}

/// FWD-8: 在途慢请求 (上游 2s) 收到 SIGTERM 后, drain 等待其完成 — 客户端
/// 仍收到完整 200 响应 (body 完整), 进程 exit 0 (优雅关停, 非 kill).
#[tokio::test]
async fn sigterm_drains_inflight_request_to_completion() {
    let upstream = spawn_slow_upstream(Duration::from_secs(2)).await;
    let mut sg = spawn_secret_guard(&upstream).await;

    let inflight = sg.start_inflight_request();
    // 等请求已到上游 (上游 sleep 中) — 500ms << 2s 上游延迟, 确保发信号时
    // 请求确实"在途"而非尚未出发.
    tokio::time::sleep(Duration::from_millis(500)).await;
    sg.sigterm();

    let resp = inflight
        .await
        .expect("task join")
        .expect("inflight request must complete during drain (FWD-8)");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.expect("complete JSON body");
    assert_eq!(
        body["choices"][0]["message"]["content"], "drained-ok",
        "response body must be delivered intact, got: {body}"
    );

    let sg_dir = sg.dir.clone();
    let (ok, logs) = sg.wait_exit(15).await;
    assert!(ok, "secret-guard should exit 0 after drain; logs:\n{logs}");
    let _ = std::fs::remove_dir_all(&sg_dir);
}

