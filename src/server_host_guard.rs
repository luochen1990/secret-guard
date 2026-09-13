//! Host / Origin 校验 middleware (SEC-7: 防 DNS rebinding + CSRF 纵深).
//!
//! # 职责边界
//!
//! server.rs (组合根) 在装配 Router 时以最外层 layer 挂载本 middleware,
//! 对**所有**路由生效, 做两类校验 (失败一律 403, 不泄露判定细节):
//!
//! 1. **Host 白名单** (所有请求, SEC-7 主体): 防 DNS rebinding — 默认单用户模式
//!    (auth disabled) 下无认证, 攻击者页面把自己的域名 rebind 到 127.0.0.1 后,
//!    浏览器发出的请求 Host 仍是攻击者域名; 域名形式 Host 一律拒绝即可击穿该攻击
//!    (本项目是本地工具, 合法访问不会用域名)。
//! 2. **`/api/*` 非安全方法的 Origin / Sec-Fetch-Site 校验**: auth enabled 时的
//!    CSRF 纵深 (cookie session 不会被跨站伪造); auth disabled 时与 Host 校验
//!    共同防 rebinding 写操作 (改 provider base_url / 关 redact decision)。
//!    非浏览器 SDK 不带这两个 header → 放行 (不破坏 SDK 转发)。
//!
//! # 白名单语义 (normative)
//!
//! 启动时由 `[server] host` + 实际监听 port 构建一次 (`HostGuard::new`):
//! - **port 必须匹配**监听 port (无显式 port 的 Host 仅在监听 80 时合法 — 浏览器
//!   对默认端口省略 port; 其余视为可疑拒绝)。
//! - host 部分属于以下之一即放行:
//!   a. 任意 **IP 字面量** (IPv4 / `[IPv6]`) 且是 loopback (`127.0.0.0/8`, `[::1]`);
//!   b. 配置 host 为非 loopback (如 `0.0.0.0` / `::` / LAN IP) 时 — 任意 **IP 字面量**
//!   (无法枚举本机非环回地址, 保守放行 IP 形态);
//!   c. 等于配置 host 或 `localhost` (大小写不敏感; 配置 host 是字符串白名单成员
//!   — 生产 `serve()` 要求 host 可解析为 SocketAddr, 域名 host 启动即报错,
//!   该"域名例外"仅对测试/程序化直接构造 `HostGuard` 的调用方可达);
//!   d. 空 host (`":port"` 形态, HTTP/1.0 边缘)。
//! - **域名形式 Host 一律拒绝** — 已知限制: 经反向代理以域名暴露的部署会被 403
//!   (见根 AGENTS.md 已知限制)。
//!
//! # 已知边界
//!
//! - HTTP/1.1 以下 / 缺 Host header 的请求放行: rebinding 攻击必带域名 Host,
//!   无 Host 的客户端 (裸 SDK / HTTP/1.0) 不在本威胁模型内。
//! - 转发路径 (`/{o|a|g|l|r}/...`) 不做 Origin 校验 (SDK 场景, Host 校验已覆盖
//!   rebinding)。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// 浏览器对 http 默认端口 (80) 省略 Host 的 `:port` 部分 — 仅此场景接受无 port Host。
const HTTP_DEFAULT_PORT: u16 = 80;

/// 启动时构建一次的 Host 白名单 (每请求只做查表 + 至多一次 IP parse)。
#[derive(Debug, Clone)]
pub struct HostGuard {
    /// 监听 port (Host 显式 port 必须等于它)。
    port: u16,
    /// 字符串 host 白名单 (小写): 配置 host + `localhost`。
    /// IP 字面量 host 不走此表 (见 `host_allowed` 的 loopback / any-ip 分支)。
    allowed_hosts: HashSet<String>,
    /// 配置 host 为非 loopback (bind `0.0.0.0` / `::` / LAN IP) 时为 true:
    /// 额外接受任意 IP 字面量 host (本机非环回地址无法枚举)。
    allow_any_ip_literal: bool,
}

impl HostGuard {
    /// 由 `[server] host` (配置原串) + 实际监听 port 构建。
    pub fn new(configured_host: &str, port: u16) -> Self {
        let configured = normalize_configured_host(configured_host);
        let configured_loopback = configured == "localhost"
            || parse_ip_literal(&configured).is_some_and(|ip| ip.is_loopback());
        Self {
            port,
            allowed_hosts: HashSet::from([configured, "localhost".to_string()]),
            allow_any_ip_literal: !configured_loopback,
        }
    }

    /// `host[:port]` 形态的 authority 是否在白名单内 (Host header / Origin 共用)。
    pub fn authority_allowed(&self, authority: &str) -> bool {
        let Some((host, port)) = split_authority(authority) else {
            return false; // 畸形 authority (如 port 非 u16) — 保守拒绝
        };
        match port {
            Some(p) if p != self.port => false,
            // 无显式 port: 仅监听 80 (浏览器默认省略) 时接受
            None if self.port != HTTP_DEFAULT_PORT => false,
            _ => self.host_allowed(&host),
        }
    }

    /// host 部分 (无 port) 是否放行, 语义见模块头 "白名单语义"。
    fn host_allowed(&self, host: &str) -> bool {
        if host.is_empty() {
            return true; // ":port" 空 host 形态
        }
        if let Some(ip) = parse_ip_literal(host) {
            return self.allow_any_ip_literal || ip.is_loopback();
        }
        self.allowed_hosts.contains(&host.to_ascii_lowercase())
    }

    /// Origin header 值 (`scheme://host[:port]` / `null`) 是否放行。
    ///
    /// 只接受带 `http(s)://` scheme 的形态 (浏览器恒发此形态); 无 scheme 的值
    /// (含 `null`) 一律拒绝 — 与 Host 校验的保守立场一致。
    fn origin_allowed(&self, origin: &str) -> bool {
        let Some(rest) = origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
        else {
            return false;
        };
        // Origin 规范上无 path, 宽容截断到首个 '/' 后按 authority 校验
        let authority = rest.split('/').next().unwrap_or("");
        self.authority_allowed(authority)
    }
}

/// 配置 host 归一化: 小写 + 裸 IPv6 补方括号 (`::1` → `[::1]`, 与 Host header 形态对齐)。
fn normalize_configured_host(host: &str) -> String {
    let lower = host.trim().to_ascii_lowercase();
    if lower.contains(':') && !lower.starts_with('[') {
        format!("[{lower}]")
    } else {
        lower
    }
}

/// 拆 `host[:port]` → `(host, Option<port>)`; 畸形 (port 非 u16 / 括号不配对) 返回 None。
fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    let s = authority.trim();
    if let Some(inner) = s.strip_prefix('[') {
        // `[IPv6]` / `[IPv6]:port`
        let end = inner.find(']')?;
        let host = format!("[{}]", &inner[..end]);
        let after = &inner[end + 1..];
        let port = match after.strip_prefix(':') {
            None if after.is_empty() => None,
            Some(p) => Some(p.parse().ok()?),
            _ => return None, // `]` 后跟非 `:port` 内容
        };
        Some((host, port))
    } else {
        match s.rfind(':') {
            // 无 port (域名 / IPv4); 裸 IPv6 含多个 ':' — 按 HTTP 规范本就非法,
            // rfind 语义下畸形归类为 None/畸形 port, 保守拒绝。
            None => Some((s.to_string(), None)),
            Some(i) => {
                let port = s[i + 1..].parse::<u16>().ok()?;
                Some((s[..i].to_string(), Some(port)))
            }
        }
    }
}

/// host 是否为 IP 字面量 (IPv4 / `[IPv6]` 括号形式), 是则返回解析结果。
fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
    } else if host.contains(':') {
        None // 未加括号的 IPv6 是非法 Host 形态, 不猜
    } else {
        host.parse::<IpAddr>().ok()
    }
}

/// 是否 `/api` 命名空间 (Origin 校验的作用域)。
fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// 403 响应 (统一出口; body 固定 "forbidden", 不回显被拒的 Host/Origin — 无信息增益)。
fn forbidden(reason: &'static str) -> Response {
    // 可观测性: 拒绝原因进日志 (不记攻击者可控的 Host/Origin 值, 防刷日志;
    // reason 已足够定位 "为什么 403", 如反向代理域名部署)。
    tracing::warn!(reason, "request rejected by host guard");
    (StatusCode::FORBIDDEN, "forbidden").into_response()
}

/// Host / Origin 校验 middleware (由 server.rs 经 `from_fn_with_state` 挂载,
/// state 为启动时构建的 [`HostGuard`])。
pub async fn guard(State(guard): State<HostGuard>, req: Request, next: Next) -> Response {
    // (1) Host 白名单 — 所有请求 (SEC-7 主体, 防 DNS rebinding)。
    // 缺 Host header 放行: rebinding 攻击必带域名 Host, 无 Host 的是裸 SDK/HTTP1.0。
    if let Some(h) = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        && !guard.authority_allowed(h)
    {
        return forbidden("bad Host header");
    }

    // (2) /api/* 非安全方法: Origin / Sec-Fetch-Site 校验 (CSRF 纵深)。
    // 两个 header 都缺 → 放行 (非浏览器 SDK); 任一存在则必须通过。
    if is_api_path(req.uri().path()) && !req.method().is_safe() {
        if let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            && !guard.origin_allowed(origin)
        {
            return forbidden("cross-origin API write");
        }
        if let Some(site) = req
            .headers()
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            && !matches!(site, "same-origin" | "same-site" | "none")
        {
            return forbidden("cross-site API write");
        }
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 18787;

    fn loopback_guard() -> HostGuard {
        HostGuard::new("127.0.0.1", PORT)
    }

    #[test]
    fn loopback_config_allows_loopback_hosts() {
        let g = loopback_guard();
        for ok in [
            format!("127.0.0.1:{PORT}"),
            format!("localhost:{PORT}"),
            format!("LOCALHOST:{PORT}"),
            format!("[::1]:{PORT}"),
            format!("127.0.0.99:{PORT}"), // loopback /8 全段
            format!(":{PORT}"),           // 空 host 形态
        ] {
            assert!(g.authority_allowed(&ok), "should allow: {ok}");
        }
    }

    #[test]
    fn loopback_config_rejects_domain_and_foreign_ip() {
        let g = loopback_guard();
        for bad in [
            format!("attacker.com:{PORT}"),    // 域名 (rebinding 载体) — 一律拒绝
            format!("sub.localhost:{PORT}"),   // localhost 的子域也是域名
            format!("192.168.1.5:{PORT}"),     // 非 loopback IP: 未配置放行
            format!("127.0.0.1:{}", PORT + 1), // port 不匹配
            format!("[fe80::1]:{PORT}"),       // 非 loopback v6
            "host:notaport".to_string(),       // 畸形 port
            "[unbalanced:80".to_string(),      // 括号不配对
        ] {
            assert!(!g.authority_allowed(&bad), "should reject: {bad}");
        }
    }

    #[test]
    fn portless_host_only_allowed_on_default_port() {
        // 监听 80: 浏览器省略 port 的 Host 合法
        let g80 = HostGuard::new("127.0.0.1", 80);
        assert!(g80.authority_allowed("127.0.0.1"));
        assert!(g80.authority_allowed("localhost"));
        // 监听非 80: 无 port 的 Host 可疑 (合法客户端对非默认端口必带 port)
        let g = loopback_guard();
        assert!(!g.authority_allowed("127.0.0.1"));
        assert!(!g.authority_allowed("attacker.com"));
    }

    #[test]
    fn non_loopback_config_allows_any_ip_literal() {
        // bind 0.0.0.0 / LAN IP: 无法枚举本机非环回地址 → 放行任意 IP 字面量, 域名仍拒
        for cfg in ["0.0.0.0", "192.168.1.5", "[::]"] {
            let g = HostGuard::new(cfg, PORT);
            assert!(
                g.authority_allowed(&format!("192.168.1.7:{PORT}")),
                "cfg={cfg}"
            );
            assert!(
                g.authority_allowed(&format!("10.0.0.2:{PORT}")),
                "cfg={cfg}"
            );
            assert!(
                !g.authority_allowed(&format!("myproxy.example:{PORT}")),
                "cfg={cfg}"
            );
        }
    }

    #[test]
    fn origin_parsing_uses_authority_whitelist() {
        let g = loopback_guard();
        assert!(g.origin_allowed(&format!("http://127.0.0.1:{PORT}")));
        assert!(g.origin_allowed(&format!("https://localhost:{PORT}")));
        assert!(g.origin_allowed(&format!("http://127.0.0.1:{PORT}/"))); // 宽容 path
        assert!(!g.origin_allowed("http://attacker.com"));
        assert!(!g.origin_allowed(&format!("http://attacker.com:{PORT}")));
        assert!(!g.origin_allowed("null")); // 沙箱 iframe / 隐私上下文 — 保守拒绝
    }

    #[test]
    fn is_api_path_scope() {
        assert!(is_api_path("/api"));
        assert!(is_api_path("/api/sync"));
        assert!(!is_api_path("/apisync")); // 前缀但不属于命名空间
        assert!(!is_api_path("/o/x/v1"));
        assert!(!is_api_path("/"));
    }
}
