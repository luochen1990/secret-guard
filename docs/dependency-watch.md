# 依赖观察 (duplicate 清单 + 升级等待队列)

> 职责边界: 本文件是 **依赖多版本共存现状快照 + 归因 + 升级等待点** 的唯一事实来源.
> 消费入口: 根 `AGENTS.md` cargo-deny 段 (multiple-versions 策略) 与 "后续工作" 段的指针 hook.
> 领取新 duplicate 告警 / 评估依赖升级时读本文件.
>
> 维护约定: 登记类 — 每个家族 / 每个升级等待点一个单行 bullet, 按依赖名字母序插入;
> 实时清单以 `cargo tree -d` 与 Cargo.lock 为准 (快照注明口径与日期), 本文件只维护
> 归因与消解时点 (环境查不到的部分).

## 总立场

- 依赖升级滞后是**稳态**, 非风险: Cargo.lock 锁定保证可复现构建; 触发条件满足时再升.
- 默认触发条件 = CVE / 解 duplicate / 需要 feature, 各子项仅标注例外.
- 2026-09 已完成: CVE 批量 update (rustls 0.23.45, RUSTSEC-2026-0285) / rand 0.10 / criterion 0.8.

## 当前重复清单 (2026-09 实测, 两个口径)

- linux 构建图 (`cargo tree -d`): **11 个家族** — base64 / cpufeatures / getrandom (3 版) / itertools / rand (3 版) / rand_chacha / rand_core (3 版) / syn / thiserror + thiserror-impl / tower-http.
- Cargo.lock 全平台口径: **17 个家族** — 上述 11 个再加 bitflags / hashbrown / indexmap / r-efi / schemars / windows-sys.

## 归因 (三类)

- **rand 簇** (rand / rand_core / rand_chacha / getrandom / cpufeatures): 我方 rand 0.8→0.10 (2026-09) 后的固有 spread — openidconnect / oauth2 钉 0.8, proptest / mockito (dev) 用 0.9, 我方 0.10; rand 0.10 的 default feature 链 (default → `std_rng` / `thread_rng` → chacha20) 把 chacha20 + cpufeatures 0.3 带进构建图 (ThreadRng 以 chacha20 为核心, 无法在保留 thread_rng 的前提下裁掉), cpufeatures 0.2 来自 sha2 0.10 时代 crypto 链. 消解时点 = rand 0.8 侧持有者 (openidconnect / oauth2 / tower-sessions-core / rsa→num-bigint-dig 链) 集体升级.
- **itertools**: criterion 0.8 (dev) 用 0.13 vs openidconnect 钉 0.10 (2026-09 criterion 0.5→0.8 引入), dev-only, 发布二进制无感.
- **lock-only 家族**: indexmap 1.9 + schemars 0.9 + hashbrown 0.12 孤立老版本簇是 serde_with 的 legacy optional feature (serde_with 本身在 linux 构建图内, 经 openidconnect 引入; 簇成员不进构建图); base64 0.23 / bitflags 1 / hashbrown 0.16 / r-efi / windows-sys 为禁用 optional feature 或非 linux target (wasm / windows / UEFI) 专属暂态 — 消解时点取决于上游移除对应 optional feature, openidconnect / reqwest 自身升级只是载体, 均无独立升级条目. 构建图内家族的解法已记录于升级等待队列: tower-http (reqwest 0.13 条目, 但 oauth2 钉 reqwest 0.12, 实际被上游阻塞); base64 0.21 (openidconnect 钉) / getrandom / syn / thiserror 为生态暂态, 无独立条目.

## 升级等待队列 (按依赖名字母序)

- **parking_lot 0.12.5** (当前最新): 长期可评估迁移到 `std::sync::Mutex/RwLock` (Rust 1.62+ 后 std 锁性能已接近 parking_lot, 可减少一个依赖). 触发条件 = 解 duplicate / 减少依赖数.
- **reqwest 0.12 → 0.13**: **被 oauth2 上游阻塞** — oauth2 5.0.0 (2025-01, 仍是最新) 的 reqwest 集成 (openidconnect 的 `reqwest` feature 所启用) 钉 `^0.12`; 单独升我方会形成双 HTTP 栈 (OIDC 走 0.12 / 转发走 0.13, hyper 连接池与 TLS 各两套), 解 tower-http duplicate 的收益不抵双栈成本. 升级时点 = oauth2 上游支持 0.13. 届时注意 0.13 breaking 较多 (`rustls-tls` feature 改名 `rustls`, rustls roots 改用 `rustls-platform-verifier`, 需验证行为).
- **sha2 0.10 → 0.11**: 注意 openidconnect 4.0.1 **直接**依赖 `sha2 ^0.10.6`, 且经 oauth2 5.0.0 再依赖 `sha2 ^0.10` (双重阻塞), **升级主依赖也无法解 duplicate**, 直到 openidconnect 上游升级.
- **tower-sessions 0.14 → 0.15**: **需与 axum-login 同步升级** (axum-login 0.18 当前硬依赖 tower-sessions 0.14, 单独升会 duplicate).
