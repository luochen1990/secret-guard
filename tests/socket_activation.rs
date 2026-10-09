//! socket activation 端到端仿真 (#242 建议②): LISTEN_FDS fd 传递 → serve 接管.
//!
//! 单元级覆盖 (src/socket_activation.rs): 协议解析全臂 + 真实 fd 接管核心.
//! 本文件补集成级: 经 python `subprocess.Popen(pass_fds=(3,), preexec_fn=...)`
//! 精确复刻 systemd 的 fd 传递语义 —
//! 1. 子进程链创建 listening TCP socket 并 dup2 到 fd 3 (dup2 产物无 CLOEXEC;
//!    注: 不能用 `os.execv` 传 fd — CPython 在 exec 前主动关闭 fd 3+, 实验证实);
//! 2. preexec_fn (fork 后 exec 前, 子进程侧) 置 `LISTEN_PID`=自身 pid /
//!    `LISTEN_FDS`=1;
//! 3. 子进程即 secret-guard 二进制 — 覆盖 serve 全路径 (env 读取 → 接管 →
//!    from_std → axum serve).
//!
//! 断言设计: 若 Rust 侧 fail-open 回退 bind, 端口已被 fd 3 的 listener 占用
//! → bind 失败进程退出; 因此 "HTTP 响应 200 + 日志含接管 INFO + SIGTERM 后
//! 退出码 0" 共同证明走了 fd 接管路径且优雅关停.
//!
//! 测试边界 (如实): python3 缺席的环境静默 skip — fd 接管核心已由单元测试
//! 覆盖, 本测试是端到端加强; systemd backlog 语义 (服务重启期间新连接排队)
//! 需要 systemd manager 本体, 不在此仿真范围.

#![cfg(unix)]

use std::io::{BufRead, Read, Write};
use std::time::Duration;

/// 朴素 HTTP/1.0 GET (无 reqwest blocking 依赖; Host 带 loopback:port 过 SEC-7
/// Host guard 白名单). 返回 `None` = 连接/读失败 (服务未就绪或已退出).
fn http_get(addr: &str) -> Option<String> {
    let mut s = std::net::TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(format!("GET / HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes())
        .ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    Some(buf)
}

/// python 侧编排 (systemd 语义仿真, 见文件头).
/// stderr 第一行输出 `SGPID=<pid>` (secret-guard 进程号, 供 rust 侧发 SIGTERM),
/// stdout 承载 secret-guard 日志 (Popen 子进程继承), 退出码透传 secret-guard 的.
const SCRIPT: &str = r#"
import os, socket, subprocess, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(os.environ["SG_TEST_PORT"])))
s.listen(64)
os.dup2(s.fileno(), 3)
if s.fileno() != 3:
    s.close()
def pre():
    os.environ["LISTEN_PID"] = str(os.getpid())
    os.environ["LISTEN_FDS"] = "1"
p = subprocess.Popen(
    [os.environ["SG_TEST_BIN"], "run",
     "--config", os.environ["SG_TEST_CONFIG"],
     "--state", os.environ["SG_TEST_STATE"],
     "--host", "127.0.0.1",
     "--port", os.environ["SG_TEST_PORT"]],
    pass_fds=(3,), preexec_fn=pre)
print("SGPID=%d" % p.pid, file=sys.stderr, flush=True)
sys.exit(p.wait())
"#;

#[test]
fn serve_takes_systemd_passed_listener_end_to_end() {
    // python3 缺席的环境 (部分 CI runner) skip — 见文件头测试边界说明.
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: python3 not available");
        return;
    }

    // 空闲端口探测 (bind :0 → 取 port → drop; python 侧 bind 同 port, race 窗口
    // 极小且失败形态 = python 异常退出, 日志可诊断).
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let addr = format!("127.0.0.1:{port}");

    // 最小 config: 单 direct provider (本测试只打 `/`, provider 不会被访问).
    let dir = std::env::temp_dir().join(format!("sg-sockact-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("secret-guard.toml");
    std::fs::write(
        &config,
        r#"
[[providers]]
id = "up"
kind = "direct"
enabled = true

[[providers.endpoints]]
protocol = "openai"
base_url = "http://127.0.0.1:9/v1"
"#,
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_secret-guard");
    let state = dir.join("state.toml");
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(SCRIPT)
        .env("SG_TEST_BIN", bin)
        .env("SG_TEST_CONFIG", &config)
        .env("SG_TEST_STATE", &state)
        .env("SG_TEST_PORT", port.to_string())
        // tracing_subscriber fmt 默认写 stdout (main.rs 无 with_writer) — 捕获它;
        // stderr 承载 SGPID 行 (与日志流分离).
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // SGPID 行 (stderr 第一行): secret-guard 进程号, 供探测循环外的 SIGTERM.
    let mut err_line = String::new();
    {
        let mut err_reader = std::io::BufReader::new(child.stderr.take().unwrap());
        err_reader
            .read_line(&mut err_line)
            .expect("read SGPID line from python stderr");
    }
    let sg_pid: libc::pid_t = err_line
        .trim()
        .strip_prefix("SGPID=")
        .unwrap_or_else(|| panic!("unexpected python stderr first line: {err_line}"))
        .parse()
        .expect("SGPID numeric");

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut resp = None;
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "secret-guard exited prematurely with {status} (bind fallback? — see captured stdout on rerun)"
            );
        }
        if let Some(r) = http_get(&addr) {
            resp = Some(r);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let resp = resp.unwrap_or_else(|| panic!("secret-guard did not serve HTTP on {addr} in 30s"));
    assert!(resp.contains(" 200 "), "unexpected response: {resp}");

    // SIGTERM → graceful shutdown (顺带覆盖关停路径); python 透传退出码.
    unsafe {
        libc::kill(sg_pid, libc::SIGTERM);
    }
    let out = child.wait_with_output().unwrap();
    let logs = String::from_utf8_lossy(&out.stdout);
    assert!(
        logs.contains("socket activation: using systemd-passed listener"),
        "expected takeover INFO log in stdout:\n{logs}"
    );
    assert!(
        out.status.success(),
        "secret-guard should exit 0 after SIGTERM (graceful shutdown); logs:\n{logs}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
