//! Host / Origin 校验 middleware (SEC-7: 防 DNS rebinding + CSRF 纵深).
//!
//! # 职责边界
//!
//! server.rs (组合根) 在装配 Router 时以最外层 layer 挂载本 middleware,
//! 对**所有**路由生效, 做两类校验 (失败一律 403, 不泄露判定细节):
//!
//! 1. **Host 白名单** (所有请求, SEC-7 主体): 防 DNS rebinding — 默认单用户模式
//!    (auth disabled) 下无认证, 攻击者页面把自己的域名 rebind 到 127.0.0.1 后,
//!    浏览器发出的请求 Host 仍是攻击者域名; 拒绝未声明的域名形式 Host 即可击穿
//!    该攻击 (声明信任域名见 `[server] allowed_domains`, 白名单语义段 e 条)。
//! 2. **`/api/*` 非安全方法的 Origin / Sec-Fetch-Site 校验**: auth enabled 时的
//!    CSRF 纵深 (cookie session 不会被跨站伪造); auth disabled 时与 Host 校验
//!    共同防 rebinding 写操作 (改 provider base_url / 关 redact decision)。
//!    非浏览器 SDK 不带这两个 header → 放行 (不破坏 SDK 转发)。
//!
//! # 白名单语义 (normative)
//!
//! 启动时由 `[server] host` + 实际监听 port 构建一次 (`HostGuard::new`),
//! 可选经 `.allow_domains(...)` 声明信任域名 (`[server] allowed_domains`):
//! - **port 必须匹配**监听 port (无显式 port 的 Host 仅在监听 80 时合法 — 浏览器
//!   对默认端口省略 port; 其余视为可疑拒绝)。**例外**: 命中 `allowed_domains`
//!   的域名端口宽松 (见 e 条)。
//! - host 部分属于以下之一即放行:
//!   a. 任意 **IP 字面量** (IPv4 / `[IPv6]`) 且是 loopback (`127.0.0.0/8`, `[::1]`);
//!   b. 配置 host 为非 loopback (如 `0.0.0.0` / `::` / LAN IP) 时 — 任意 **IP 字面量**
//!   (无法枚举本机非环回地址, 保守放行 IP 形态);
//!   c. 等于配置 host 或 `localhost` (大小写不敏感; 配置 host 是字符串白名单成员
//!   — 生产 `serve()` 要求 host 可解析为 SocketAddr, 域名 host 启动即报错,
//!   该"域名例外"仅对测试/程序化直接构造 `HostGuard` 的调用方可达);
//!   d. 空 host (`":port"` 形态, HTTP/1.0 边缘);
//!   e. 命中 **`allowed_domains`** (用户显式声明的信任域名, 反代 + 域名部署形态):
//!   按**名字**精确匹配 (大小写不敏感), **忽略端口** — 反代转发的 Host 形态
//!   不可穷举 (`proxy_set_header Host $host` 无端口 / `$http_host` 保留外部端口)。
//!   安全性: 攻击者的域名无法进入这份用户手写的名单 — 这正是"显式声明"
//!   与"放行所有域名"的本质区别 (rebinding 攻击域名不在名单, 仍被拒)。
//! - **未声明的域名形式 Host 一律拒绝** (SEC-7 主体: rebinding 载体是域名)。
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
    /// 用户显式声明的信任域名 (`[server] allowed_domains`, 小写):
    /// 命中即放行且**端口宽松** — 反代链路的 Host 形态不可穷举
    /// (`$host` 无端口 / `$http_host` 保留外部端口)。
    /// 攻击者的域名进不了这份名单, 这是与"放行所有域名"的本质区别。
    domain_allowlist: HashSet<String>,
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
            domain_allowlist: HashSet::new(),
        }
    }

    /// 声明信任的域名 (builder, `[server] allowed_domains` 的消费入口)。
    ///
    /// 归一化: trim + 小写; **跳过**对域名白名单无意义的条目并 WARN —
    /// 含 `:` 的形态 (host:port / 裸 IPv6)、IP 字面量 (走 `host_allowed`
    /// 专门分支)、`localhost` (已在基础白名单)、空串。
    /// 跳过 ≠ 放行: 名单里写 IP / host:port 不会让该目标被放行。
    pub fn allow_domains<I, S>(mut self, domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for raw in domains {
            let d = raw.as_ref().trim().to_ascii_lowercase();
            if d.is_empty() || d.contains(':') || d == "localhost" || parse_ip_literal(&d).is_some()
            {
                tracing::warn!(
                    domain = %d,
                    "allowed_domains entry skipped (host:port / IP literal / localhost / empty is meaningless here)"
                );
                continue;
            }
            self.domain_allowlist.insert(d);
        }
        self
    }

    /// `host[:port]` 形态的 authority 是否在白名单内 (Host header / Origin 共用)。
    pub fn authority_allowed(&self, authority: &str) -> bool {
        let Some((host, port)) = split_authority(authority) else {
            return false; // 畸形 authority (如 port 非 u16) — 保守拒绝
        };
        // 用户声明域名: 按名字匹配, 端口宽松 (反代转发形态不可穷举, 见字段注释)。
        // is_empty 前置: 默认空名单时热路径零分配 (Host 校验每请求都跑)。
        if !self.domain_allowlist.is_empty()
            && self.domain_allowlist.contains(&host.to_ascii_lowercase())
        {
            return true;
        }
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

    // ─── allowed_domains (域名白名单, 反代 + 域名部署形态) ─────────────────

    #[test]
    fn declared_domain_ignores_port_and_case() {
        // 反代链路 Host 形态不可穷举 (proxy_set_header Host $host 无端口 /
        // $http_host 保留外部端口) — 名单内域名按**名字**匹配, 端口宽松.
        let g = HostGuard::new("127.0.0.1", PORT).allow_domains(["sg.example.com"]);
        assert!(g.authority_allowed("sg.example.com")); // 无端口 (反代 $host)
        assert!(g.authority_allowed(&format!("sg.example.com:{PORT}")));
        assert!(g.authority_allowed(&format!("sg.example.com:{}", PORT + 1))); // 外部端口
        assert!(g.authority_allowed(&format!("SG.Example.COM:{PORT}"))); // 大小写
    }

    #[test]
    fn undeclared_domain_still_rejected_even_with_allowlist() {
        // 域名白名单不弱化对未声明域名的拒绝 (rebinding 攻击域名进不了名单).
        let g = HostGuard::new("127.0.0.1", PORT).allow_domains(["sg.example.com"]);
        assert!(!g.authority_allowed("attacker.com"));
        assert!(!g.authority_allowed(&format!("attacker.com:{PORT}")));
        assert!(!g.authority_allowed("sg.example.com.evil.io")); // 后缀拼接不是子串匹配
        assert!(!g.authority_allowed("not-sg.example.com")); // 前缀拼接
    }

    #[test]
    fn allow_domains_skips_ip_literals_and_noise() {
        // IP 字面量 / host:port / 裸 IPv6 / localhost / 空串对域名白名单无意义
        // (IP 走专门分支, 域名不含 ':') — 归一化时跳过, 不进集合.
        let g = HostGuard::new("127.0.0.1", PORT).allow_domains([
            "SG.Example.COM", // 归一化为小写
            "  sg.lan  ",     // trim
            "10.0.0.5",       // IP 字面量 → 跳过
            "sg.lan:8443",    // host:port 形态 → 跳过 (合法域名不含 ':')
            "::1",            // 裸 IPv6 (无括号) → 含 ':' 跳过
            "localhost",      // 已在基础白名单 → 跳过
            "",               // 空串 → 跳过
        ]);
        assert!(g.authority_allowed(&format!("sg.example.com:{PORT}")));
        assert!(g.authority_allowed(&format!("sg.lan:{PORT}")));
        // IP 条目被跳过 ≠ IP 被放行 (loopback 配置下非 loopback IP 仍拒).
        assert!(!g.authority_allowed(&format!("10.0.0.5:{PORT}")));
    }

    #[test]
    fn origin_with_declared_domain_allowed() {
        // 浏览器经 https://sg.example.com 访问 WebUI: Origin 域名在名单内 →
        // /api/* 非安全方法放行 (与 Host 校验共享 authority 判定).
        let g = HostGuard::new("127.0.0.1", PORT).allow_domains(["sg.example.com"]);
        assert!(g.origin_allowed("https://sg.example.com"));
        assert!(g.origin_allowed("https://sg.example.com:8443"));
        assert!(!g.origin_allowed("https://attacker.com"));
    }
}
