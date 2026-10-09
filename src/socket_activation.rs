//! systemd socket activation 的 LISTEN_FDS 协议接管 (#242 建议②).
//!
//! # 职责
//! 启动时检测 systemd socket activation 环境变量 (`LISTEN_PID` / `LISTEN_FDS`),
//! 有效时从 fd 3 接管 systemd 传入的监听 socket, 交给 [`crate::server::serve`]
//! 替代自行 bind. 背景: 服务重启 (nixos-rebuild switch) 期间 listening socket 由
//! systemd 持有, 新连接进 socket backlog 排队而非被 RST — 停机窗口不再受
//! "消费方最小重试窗口" 约束, drain 期可放心放长让 in-flight LLM 流跑完.
//!
//! # 协议 (sd_listen_fds(3), 手写最小实现 — 无 libsystemd 依赖)
//! - `LISTEN_PID` == 当前 pid 且 `LISTEN_FDS` >= 1 → fd 3..3+N 是 systemd 传入的
//!   listener (起点 fd 3 = SD_LISTEN_FDS_START, stdin/out/err 之后).
//! - 协议要求对传入 fd 置 FD_CLOEXEC (libsystemd 的 sd_listen_fds 同款行为).
//!
//! # fail-open 语义 (ROB: best-effort, 永不 panic)
//! 任何检测 / 校验失败都回退正常 bind: 无环境变量的常规部署路径行为零变化、
//! 日志零噪音 (NotActivated 静默); env 存在但无效 (pid 不符 / 非数字) 或 fd
//! 校验失败时 WARN 一次后回退 (Invalid / fd 校验路径).
//!
//! 注意: "回退 bind 成功" 仅适用于非激活环境的 env 异常场景 — systemd 已激活
//! (端口被 manager 持有) 而接管失败时, 回退 bind 会因端口占用而失败退出;
//! 快速失败是有意的 (优于静默双端口/半残状态).
//!
//! # 假设声明 (ROB)
//! - 假设传入 fd 是 systemd socket unit (ListenStream) 的 listening TCP socket —
//!   仍做 SO_TYPE == SOCK_STREAM + SO_ACCEPTCONN == 1 的 getsockopt 校验, 拒绝
//!   即回退 bind (优于 "构造 + local_addr 可解析" 的保守判断: 后者放行 UDP fd,
//!   其 getsockname 同样返回 IPv4/IPv6 SocketAddr).
//! - 假设单监听端口 (本服务单 ListenStream): 多 fd 只取第一个, 其余 WARN 忽略.
//! - 环境变量不清理 (libsystemd 的 unset_environment 等价物不做):
//!   `std::env::remove_var` 在 Rust 2024 是 unsafe 且多线程下 getenv 并发有 UB
//!   风险 (serve 已在 tokio runtime 内); 残留 `LISTEN_PID` 对子进程无误导性 —
//!   协议的 pid 校验保证子进程 (pid 必不同) 不误接管.
//! - 多余 fd 与校验失败路径的 fd **不 close** (与 libsystemd sd_listen_fds 行为
//!   一致): 残留 fd 随进程生命期终结, 无泄漏放大面; 不 close 换取 fd ownership
//!   单点清晰 (调用方对象不被偷偷夺走 fd).

use std::net::SocketAddr;

/// SD_LISTEN_FDS_START: 协议规定的传入 fd 起点 (fd 3 — stdin/out/err 之后).
#[cfg(unix)]
const SD_LISTEN_FDS_START: std::os::fd::RawFd = 3;

/// LISTEN_FDS 协议解析结果 (分类承载调用方的日志决策, 纯函数便于全臂测试).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListenFdsStatus {
    /// 未激活 (env 缺失 / `LISTEN_FDS=0`): 非 systemd 部署常态, 静默走正常 bind.
    NotActivated,
    /// pid 匹配且 n >= 1: fd 3..3+n 是 systemd 传入的 listener.
    Activated(usize),
    /// env 存在但无效 (pid 不符 / 非数字): WARN 一次后按未激活处理 (fail-open).
    Invalid(&'static str),
}

/// 解析 LISTEN_PID / LISTEN_FDS 环境变量值 (sd_listen_fds(3) 语义, 纯函数).
///
/// 输入是已读取的 env 值 (而非函数内读 env) — 便于全臂单元测试; 环境读取的
/// 薄封装见 [`take_systemd_listener`]. trim 容忍手写 env 的边缘空白.
pub(crate) fn parse_listen_fds(
    pid: u32,
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
) -> ListenFdsStatus {
    // 协议要求两变量同时存在; 缺任一即未激活.
    let (Some(lp), Some(lf)) = (listen_pid, listen_fds) else {
        return ListenFdsStatus::NotActivated;
    };
    let Ok(parsed_pid) = lp.trim().parse::<u32>() else {
        return ListenFdsStatus::Invalid("LISTEN_PID is not a number");
    };
    if parsed_pid != pid {
        return ListenFdsStatus::Invalid("LISTEN_PID does not match current pid");
    }
    let Ok(n) = lf.trim().parse::<usize>() else {
        return ListenFdsStatus::Invalid("LISTEN_FDS is not a number");
    };
    if n == 0 {
        // LISTEN_FDS=0: 协议上等价未激活 (systemd 不会设置该值, 出现亦无 fd 可接管).
        return ListenFdsStatus::NotActivated;
    }
    ListenFdsStatus::Activated(n)
}

/// 启动入口: 检测并接管 systemd socket activation 传入的 listener.
///
/// 返回 `Some((listener, addr))` 表示接管成功 — listener 已设 nonblocking 且
/// local_addr 已验证, 可直接 `tokio::net::TcpListener::from_std`; 返回 `None`
/// 表示未激活 / 无效, 调用方回退正常 bind (fail-open).
///
/// 非 unix 平台 (无 systemd / fcntl) 恒返回 None — socket activation 是
/// Linux systemd 机制, 其他平台走正常 bind.
#[cfg(unix)]
pub(crate) fn take_systemd_listener() -> Option<(std::net::TcpListener, SocketAddr)> {
    // var_os (而非 var): 非 UTF-8 env 值保持走 Invalid 臂 WARN, 不静默降级;
    // into_owned: Cow 借用闭包局部会悬垂, env 值极短, 直接 owned 无妨.
    let pid_str = std::env::var_os("LISTEN_PID").map(|s| s.to_string_lossy().into_owned());
    let fds_str = std::env::var_os("LISTEN_FDS").map(|s| s.to_string_lossy().into_owned());
    let status = parse_listen_fds(std::process::id(), pid_str.as_deref(), fds_str.as_deref());
    match status {
        ListenFdsStatus::NotActivated => None,
        ListenFdsStatus::Invalid(reason) => {
            tracing::warn!(
                reason,
                "socket activation env present but invalid; ignoring (fail-open to normal bind)"
            );
            None
        }
        ListenFdsStatus::Activated(n) => take_listener_from_fds(SD_LISTEN_FDS_START, n),
    }
}

/// 非 unix 编译存根: 恒未激活 (见 [`take_systemd_listener`] unix 版头部契约).
#[cfg(not(unix))]
pub(crate) fn take_systemd_listener() -> Option<(std::net::TcpListener, SocketAddr)> {
    None
}

/// fd 接管核心 (fd 起点参数化, 便于用真实 fd 做单元测试).
///
/// 成功路径: 第一个 fd 校验为 listening TCP socket → FD_CLOEXEC → nonblocking →
/// `from_raw_fd` 接管 ownership (此后 fd 生命周期由返回的 TcpListener 管理, drop
/// 即 close). set_nonblocking / local_addr 失败时 listener 已接管, drop 自然收尾.
#[cfg(unix)]
fn take_listener_from_fds(
    first_fd: std::os::fd::RawFd,
    count: usize,
) -> Option<(std::net::TcpListener, SocketAddr)> {
    use std::os::fd::FromRawFd;

    if count > 1 {
        tracing::warn!(
            count,
            "socket activation: multiple fds passed; using only the first (single-listen service), ignoring the rest"
        );
    }
    if !fd_is_tcp_listening(first_fd) {
        tracing::warn!(
            fd = first_fd,
            "socket activation: passed fd is not a listening TCP socket; falling back to bind"
        );
        return None;
    }
    // 协议要求对全部传入 fd 置 CLOEXEC (sd_listen_fds(3) 对 all passed fds 设置,
    // 不仅是被接管的第一个; CLOEXEC ≠ close, 与 "多余 fd 不 close" 决策正交).
    // 多余 fd 的设置失败忽略 (无接管面); 第一个 fd 失败则回退 bind.
    // saturating_add: count 来自 env, 极端值下 RawFd 相加溢出会破坏 ROB 的
    // "永不 panic" 承诺 (debug 构建溢出即 panic), 饱和为空区间即无害.
    for fd in first_fd + 1..first_fd.saturating_add(count as std::os::fd::RawFd) {
        let _ = fd_set_cloexec(fd);
    }
    if !fd_set_cloexec(first_fd) {
        tracing::warn!(
            fd = first_fd,
            "socket activation: failed to set FD_CLOEXEC; falling back to bind"
        );
        return None;
    }
    let listener = unsafe { std::net::TcpListener::from_raw_fd(first_fd) };
    // tokio from_std 的前置要求: listener 必须处于 nonblocking 模式
    // (systemd 传入的 fd 默认 blocking).
    if let Err(e) = listener.set_nonblocking(true) {
        tracing::warn!(
            fd = first_fd,
            error = %e,
            "socket activation: set_nonblocking failed; falling back to bind"
        );
        return None;
    }
    match listener.local_addr() {
        Ok(addr) => Some((listener, addr)),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "socket activation: local_addr unavailable; falling back to bind"
            );
            None
        }
    }
}

/// getsockopt(SOL_SOCKET, opt) 的 int 值; 失败 (非 socket fd / EBADF / ENOTSOCK)
/// → None.
#[cfg(unix)]
fn getsockopt_int(fd: std::os::fd::RawFd, opt: libc::c_int) -> Option<libc::c_int> {
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(val)
}

/// 校验 fd 是 listening TCP socket: SO_TYPE == SOCK_STREAM 且 SO_ACCEPTCONN == 1.
#[cfg(unix)]
fn fd_is_tcp_listening(fd: std::os::fd::RawFd) -> bool {
    getsockopt_int(fd, libc::SO_TYPE) == Some(libc::SOCK_STREAM)
        && getsockopt_int(fd, libc::SO_ACCEPTCONN) == Some(1)
}

/// 对 fd 置 FD_CLOEXEC (LISTEN_FDS 协议要求 — 防 fd 泄漏给 exec 的子进程).
#[cfg(unix)]
fn fd_set_cloexec(fd: std::os::fd::RawFd) -> bool {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return false;
        }
        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── parse_listen_fds 全臂 (纯函数, 全平台) ───────────────────────────

    #[test]
    fn parse_valid_single_fd() {
        assert_eq!(
            parse_listen_fds(42, Some("42"), Some("1")),
            ListenFdsStatus::Activated(1)
        );
    }

    #[test]
    fn parse_valid_multiple_fds() {
        assert_eq!(
            parse_listen_fds(42, Some("42"), Some("3")),
            ListenFdsStatus::Activated(3)
        );
    }

    #[test]
    fn parse_leading_zero_pid_is_valid_number() {
        // "042" 是合法数字解析 (= 42), 与 libsystemd 的 atoi 族行为一致.
        assert_eq!(
            parse_listen_fds(42, Some("042"), Some("1")),
            ListenFdsStatus::Activated(1)
        );
    }

    #[test]
    fn parse_missing_either_env_not_activated() {
        assert_eq!(
            parse_listen_fds(42, None, Some("1")),
            ListenFdsStatus::NotActivated
        );
        assert_eq!(
            parse_listen_fds(42, Some("42"), None),
            ListenFdsStatus::NotActivated
        );
        assert_eq!(
            parse_listen_fds(42, None, None),
            ListenFdsStatus::NotActivated
        );
    }

    #[test]
    fn parse_pid_mismatch_invalid() {
        assert_eq!(
            parse_listen_fds(42, Some("1234"), Some("1")),
            ListenFdsStatus::Invalid("LISTEN_PID does not match current pid")
        );
    }

    #[test]
    fn parse_pid_non_numeric_invalid() {
        assert_eq!(
            parse_listen_fds(42, Some("abc"), Some("1")),
            ListenFdsStatus::Invalid("LISTEN_PID is not a number")
        );
    }

    #[test]
    fn parse_fds_non_numeric_invalid() {
        assert_eq!(
            parse_listen_fds(42, Some("42"), Some("many")),
            ListenFdsStatus::Invalid("LISTEN_FDS is not a number")
        );
    }

    #[test]
    fn parse_zero_fds_not_activated() {
        // 协议等价未激活 (systemd 不设置该值), 静默而非 WARN.
        assert_eq!(
            parse_listen_fds(42, Some("42"), Some("0")),
            ListenFdsStatus::NotActivated
        );
    }

    #[test]
    fn parse_fds_overflow_invalid() {
        // 超出 usize 的数字 → 非数字臂 (不 panic).
        assert_eq!(
            parse_listen_fds(42, Some("42"), Some("99999999999999999999999999")),
            ListenFdsStatus::Invalid("LISTEN_FDS is not a number")
        );
    }

    #[test]
    fn parse_trims_surrounding_whitespace() {
        assert_eq!(
            parse_listen_fds(42, Some(" 42 "), Some(" 1 ")),
            ListenFdsStatus::Activated(1)
        );
    }

    // ─── take_systemd_listener 无 env 冒烟 (启动路径分支决策点) ───────────
    //
    // 测试进程环境无 LISTEN_* (常规 cargo test 环境) 时断言未激活; 若在本机
    // 经 systemd-run 等方式跑测试 (env 会被注入), 本测试静默跳过而非 flaky.

    #[test]
    fn take_without_env_is_none() {
        if std::env::var_os("LISTEN_FDS").is_none() && std::env::var_os("LISTEN_PID").is_none() {
            assert!(take_systemd_listener().is_none());
        }
    }

    // ─── fd 接管核心: 真实 fd 传递 (unix) ─────────────────────────────────

    #[cfg(unix)]
    mod fd_take {
        use super::*;
        use std::os::fd::AsRawFd;

        /// 真实 listening TCP listener 的 fd 接管: 返回 addr 与源一致, 且
        /// CLOEXEC 已置 / nonblocking 已设 (tokio from_std 前置).
        #[test]
        fn takes_real_tcp_listener_fd() {
            let src = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let (taken, addr) =
                take_listener_from_fds(src.as_raw_fd(), 1).expect("listening TCP fd must be taken");
            assert_eq!(addr, src.local_addr().unwrap());
            // fd ownership 已转移给 taken; 源对象 forget 防 double close.
            std::mem::forget(src);
            // CLOEXEC (协议要求): F_GETFD 直接验证.
            let flags = unsafe { libc::fcntl(taken.as_raw_fd(), libc::F_GETFD) };
            assert!(flags & libc::FD_CLOEXEC != 0, "FD_CLOEXEC must be set");
            // nonblocking (tokio from_std 前置): accept 立即返回 WouldBlock
            // 而非阻塞 (阻塞会让本测试挂死 — 挂死本身就是失败信号).
            let err = taken.accept().expect_err("no pending connection");
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::WouldBlock,
                "taken listener must be nonblocking"
            );
        }

        /// 多 fd: 只取第一个, 其余被忽略 (不 close — 丢弃路径见函数注释).
        #[test]
        fn takes_first_fd_and_ignores_rest() {
            let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let (_taken, addr) =
                take_listener_from_fds(first.as_raw_fd(), 2).expect("first fd must be taken");
            assert_eq!(addr, first.local_addr().unwrap());
            std::mem::forget(first); // ownership → taken
            drop(second); // 第二个 fd 未被触碰, 正常关闭
        }

        /// UDP socket (SO_TYPE != SOCK_STREAM) 被拒 — 这是放弃 "构造 + local_addr
        /// 可解析" 保守判断的理由: UDP fd 的 getsockname 同样返回合法 SocketAddr.
        #[test]
        fn rejects_udp_socket() {
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            assert!(take_listener_from_fds(udp.as_raw_fd(), 1).is_none());
            // 失败路径未接管 fd, udp 正常 drop.
        }

        /// 已连接的 TCP stream (SO_ACCEPTCONN = 0) 被拒: 类型对但非 listening.
        #[test]
        fn rejects_connected_tcp_socket() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let laddr = listener.local_addr().unwrap();
            // connect 侧 fd: SO_TYPE=STREAM 但 SO_ACCEPTCONN=0 (backlog 在 listener 侧).
            let stream = std::net::TcpStream::connect(laddr).unwrap();
            assert!(take_listener_from_fds(stream.as_raw_fd(), 1).is_none());
        }

        /// 非 socket fd (普通文件) 被拒 (getsockopt → ENOTSOCK).
        #[test]
        fn rejects_non_socket_fd() {
            let f = std::fs::File::open("/dev/null").unwrap();
            assert!(take_listener_from_fds(f.as_raw_fd(), 1).is_none());
        }
    }
}
