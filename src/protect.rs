//! SG 自有凭证自动保护 (auto-protect overlay, issue #320).
//!
//! # 职责边界
//!
//! 把 secret-guard **自身的两类凭证**免配置纳入出站保护, 防止 Agent Harness 把它们
//! 粘贴进对话后随请求体流向 LLM Provider (进日志 / 训练语料):
//!
//! 1. **sg API token** — WebUI 动态签发 (`sg_` + 32 slug) 与静态装载
//!    (`[[auth.api_keys]]`) 的 key. 明文注册表内嵌在
//!    [`crate::auth::ApiKeyStore`] (内存态, 永不持久化 — 见其头注 "明文驻留
//!    trade-off"), 签发 / 静态装载 / lookup 命中三个时点同步注册, 撤销时移除.
//! 2. **登记的 provider key** — provider 条目的 `api_key` / `api_key_file`.
//!    **不落注册表**: per-request 从 provider 表 effective 视图派生 (SSOT =
//!    provider 表本身, 无第二份簿记 ⇒ 无陈旧漂移). 选中 provider 的
//!    `api_key_file` 值经 [`crate::provider::DirectProvider::effective_api_key`]
//!    现场解析 (与转发路径同源; 非 selected 的 file-mode key 不读文件 — 保护面
//!    以零额外 IO 为界, 见 known-limitations).
//!
//! # 机制: 字节层替换 (与 user-secret IR 机制正交)
//!
//! 保护在 **dispatch 请求 body 收集后** 的原始字节上执行 (proxy DoD-5 预留的
//! "请求 body 收集后" hook 点):
//!
//! - **不参与路径选择判据** — same_proto 透传快捷分支 / codec-less 协议停损的
//!   判据仍是 *user* SecretTable 是否为空. 自动保护因此对任意协议 (含 codec 未
//!   覆盖的 gemini/ollama) 与任意 body 形状 (embeddings / 非 chat JSON) 一致生效,
//!   不会把既有透传路径升级成 IR 解析 (perf / BadBody / 503 三重回归源).
//! - **只进不出** — 响应侧不还原: 这类凭证没有 "本地工具从 LLM 响应读回真值" 的
//!   正当用例 (对比 RED-6 restore 服务于对话内容), mock 即 LLM 视角的稳定替身.
//! - **fail-open** — 替换永不失败 (非 UTF-8 body 跳过 + debug 日志), 绝不因保护
//!   动作本身阻塞转发 (ROB-1 同型; 与 RED 域的 fail-closed 语义不同 — 那里是
//!   *用户显式登记* 的 secret, 这里是叠加的 best-effort 防护层).
//! - **确定性 mock** — 同一明文恒产生同一 mock ([`mock_for`]: 纯函数, 跨请求 /
//!   跨进程稳定), 已被替换的历史消息在后续请求中字节不变 (C3 前缀缓存友好同型).
//!   shape 强制 [`crate::mock::SecretShape::Plain`] (等长随机串): ① 不带任何已知
//!   公开前缀 ⇒ 永不命中 privacy-scan 的 pattern 集 (前缀/形状驱动, 无通用
//!   high-entropy 规则), 零误报零排除集接线; ② 无结构分段, 字节层替换语义最简.
//!
//! # 命中语义
//!
//! `redact_request_body` 对每个凭证做 `str::find` + 全量替换 (mock 为等长
//! 随机串, 替换即 FWD-1 唯一授权的 real↔mock 修改). 命中时 per-credential WARN
//! 一条 (只含 id 与次数, 永不含明文/mock, SEC-2 同型). 已知盲区 (best-effort,
//! 见 docs/known-limitations.md): JSON `\uXXXX` 转义形态的凭证字节层不命中
//! (user-secret 的 IR 层扫描可命中 — 两层互补).
//!
//! # 保护面地板 (`MIN_PROTECTED_CHARS`)
//!
//! 短于地板的值不进保护集: 真实 provider key / sg token 实际长度都 ≥20, 而短串
//! (如测试值 `sk-test-key`) 在普通文本中误命中会破坏请求体 — 宁可漏保 (可用
//! `[[secrets.entries]]` 显式登记补上) 不可误替换.

use bytes::Bytes;

use crate::mock::{GenSpec, InitialValue, MockStrategy, SecretCategory, SecretShape};

/// 进入保护集的最小字符数 (地板). 理由见模块头 "保护面地板".
pub(crate) const MIN_PROTECTED_CHARS: usize = 16;

/// 一条受自动保护的凭证 (内存态快照项).
///
/// 手写 `Debug`: value / mock 永不进日志面 (SEC-2 同型纪律, derive 会连带泄露).
/// 字段 `pub(crate)`: 构造与消费都在 crate 内 (auth 注册表 / proxy 收集);
/// crate 外 (集成测试) 只接触 [`mock_for`] 的返回值.
pub struct ProtectedCredential {
    /// 稳定标识: sg token = `sgkey_<api key entry id>`, provider key =
    /// `sgprov_<provider id>`. 仅用于 WARN 日志归因, 不进 SecretTable / WebUI
    /// secrets 列表 (与用户 secret id 无碰撞面 — 两套 id 空间互不可见).
    pub(crate) id: String,
    /// 明文 (仅在进程内存中流转, 永不持久化 / 永不经 API 返回).
    pub(crate) value: String,
    /// 确定性 mock (等长随机串, 见 [`mock_for`]).
    pub(crate) mock: String,
}

impl std::fmt::Debug for ProtectedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedCredential")
            .field("id", &self.id)
            .field("value_len", &self.value.chars().count())
            .field("mock_len", &self.mock.chars().count())
            .finish()
    }
}

/// 为明文凭证生成确定性 mock (纯函数: 同一输入恒同一输出).
///
/// 复用 [`crate::mock`] 的候选生成器 (等长不变量 + C5 内部重试链同源), 但 shape
/// 强制 Plain (理由见模块头). 空 / 单字符输入的 length_range 地板为 1 (生成器
/// validate 要求 > 0); 实际保护集入口 (`collect_credentials`) 已挡短值, 此处
/// 容错仅为 ROB.
pub fn mock_for(value: &str) -> String {
    let n = value.chars().count().max(1);
    let mut spec = GenSpec::infer_default_for(value, SecretCategory::Other, "");
    // 强制 Plain + 无前缀 + 等长 (覆盖 infer 可能给出的 PublicPrefixed/Pem/Jwt —
    // 结构化 mock 会带公开前缀/边界行, 违反 "privacy 不可见" 与字节层最简性).
    spec.shape = SecretShape::Plain;
    spec.prefix = String::new();
    spec.length_range = (n, n);
    let strategy = MockStrategy {
        initial: InitialValue::Auto,
        gen_spec: Some(spec),
        ..MockStrategy::default()
    };
    let seed = crate::mock::deterministic_seed(value, &strategy);
    crate::mock::gen_candidate(value, &strategy, seed, 0)
}

/// 合并保护集: sg token 注册表快照 + provider key 派生条目 → 去重 + 长度排序.
///
/// - provider 内联 key: 来自 `providers` effective 快照的全部 Direct 条目
///   (disabled 已被 effective 视图排除 — "在役" 语义).
/// - `selected_provider_key`: 本次请求选中 provider (`selected_id`) 的 effective
///   api_key (覆盖 api_key_file 形态 — dispatch 处现场解析, 与转发路径同源).
/// - 值去重 (sg 优先保留), 按 value 长度降序 (长串先替换, 与 redact_ir_inner
///   的排序同型 — 处理值互为子串的边角).
/// - 短于 `MIN_PROTECTED_CHARS` 的值丢弃 (地板, 见模块头).
pub(crate) fn collect_credentials(
    sg_registry: Vec<ProtectedCredential>,
    providers: &[crate::provider::Provider],
    selected_provider_key: &str,
    selected_id: &str,
) -> Vec<ProtectedCredential> {
    let mut out: Vec<ProtectedCredential> = Vec::new();
    let mut push = |c: ProtectedCredential| {
        if c.value.chars().count() < MIN_PROTECTED_CHARS {
            return;
        }
        if out.iter().any(|e| e.value == c.value) {
            return;
        }
        out.push(c);
    };
    for c in sg_registry {
        push(c);
    }
    for p in providers {
        if let crate::provider::ProviderKind::Direct(d) = &p.kind
            && !d.api_key.is_empty()
        {
            push(ProtectedCredential {
                id: format!("sgprov_{}", p.id),
                value: d.api_key.clone(),
                mock: String::new(),
            });
        }
    }
    if !selected_provider_key.is_empty() {
        // selected 的 key 常与内联条目重复 — 去重由 push 收口; file-mode 且非空时
        // 是唯一新增来源 (id 用 provider id, WARN 归因可读).
        push(ProtectedCredential {
            id: format!("sgprov_{selected_id}"),
            value: selected_provider_key.to_string(),
            mock: String::new(),
        });
    }
    for c in out.iter_mut() {
        if c.mock.is_empty() {
            c.mock = mock_for(&c.value);
        }
    }
    out.sort_by_key(|c| std::cmp::Reverse(c.value.len()));
    out
}

/// 一次替换命中的归因 (仅 id + 次数; 永不含明文/mock).
pub(crate) struct ProtectionHit {
    pub(crate) id: String,
    pub(crate) occurrences: usize,
}

/// 在请求 body 原始字节上执行 real→mock 全量替换.
///
/// 检查 / 计数 / 替换都在**当前链** (前序凭证替换后的最新文本) 上进行 — 长度降序
/// 下, 与前序值互为子串的短值会被前序替换自然吞掉 (链上不再出现 → 不计命中,
/// 真值已不在出站文本中, 语义正确). 返回 `(新 body, 命中列表)`. `None` = 无命中
/// (零拷贝原样返回) 或 body 非 UTF-8 (best-effort 跳过; 二进制上传体不在威胁
/// 模型内 — 凭证粘贴发生在 JSON 文本层). 凭证集为空时调用方应短路 (本函数不假设).
pub(crate) fn redact_request_body(
    body: &Bytes,
    creds: &[ProtectedCredential],
) -> (Option<Bytes>, Vec<ProtectionHit>) {
    // 非 UTF-8: 字节层查找仍可行但 str::find 不可用; 跳过 (ROB, 模块头 fail-open).
    let Ok(s) = std::str::from_utf8(body) else {
        return (None, Vec::new());
    };
    let mut text: Option<String> = None;
    let mut hits = Vec::new();
    for c in creds {
        let target: &str = text.as_deref().unwrap_or(s);
        if !target.contains(c.value.as_str()) {
            continue;
        }
        let occurrences = target.matches(c.value.as_str()).count();
        text = Some(target.replace(c.value.as_str(), c.mock.as_str()));
        hits.push(ProtectionHit {
            id: c.id.clone(),
            occurrences,
        });
    }
    match text {
        Some(t) => (Some(Bytes::from(t)), hits),
        None => (None, hits),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cred(id: &str, value: &str) -> ProtectedCredential {
        ProtectedCredential {
            id: id.into(),
            value: value.into(),
            mock: mock_for(value),
        }
    }

    // ─── mock_for: 确定性 / 等长 / C5-lite / privacy 不可见 ─────────────────

    #[test]
    fn mock_is_deterministic_and_equal_length() {
        for real in [
            "sg_abcdefghij0123456789ABCDEFGH",
            "sk-ant-api03-real-key-1234567890",
        ] {
            let m1 = mock_for(real);
            let m2 = mock_for(real);
            assert_eq!(m1, m2, "deterministic");
            assert_eq!(m1.chars().count(), real.chars().count(), "equal char len");
            assert_ne!(m1, real, "mock never equals real");
        }
    }

    #[test]
    fn mock_is_plain_shape_no_known_prefix() {
        // privacy 不可见的结构论证: 全部 10 条 pattern 都要求公开前缀 / 点分隔 /
        // PEM 边界; Plain 等长随机串天然不满足. 这里对 pattern 引擎做端到端断言
        // (防未来 pattern 集加入通用形状规则时静默破坏本模块前提).
        let reals = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
            "sk-ant-api03-real-key-1234567890abcdef",
            "sk-proj-0123456789abcdef0123456789abcdef",
            "AIzaSyA0123456789abcdefghijklmnopqrstuv",
            "xoxb-0123456789-0123456789-0123456789",
            // JWT (三段点分)
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c",
        ];
        for real in reals {
            let m = mock_for(real);
            assert!(
                !crate::privacy::matches_any_pattern(&m),
                "mock of a {real:.12}…-shaped value must stay privacy-invisible"
            );
        }
    }

    // ─── collect_credentials: 地板 / 去重 / 排序 ────────────────────────────

    fn direct_provider(id: &str, api_key: &str) -> crate::provider::Provider {
        crate::provider::Provider {
            id: id.into(),
            enabled: true,
            name: None,
            kind: crate::provider::ProviderKind::Direct(crate::provider::DirectProvider {
                endpoints: vec![crate::provider::Endpoint {
                    protocol: crate::provider::Protocol::OpenAI,
                    base_url: "https://up.example".into(),
                    common_uri: None,
                }],
                api_key: api_key.into(),
                api_key_file: None,
            }),
        }
    }

    #[test]
    fn collect_enforces_floor_and_dedups() {
        let sg = vec![
            cred("sgkey_ak_1", "sg_1111111111111111111111111111111"),
            // 与 provider 重复的值: 去重保 sg (先入).
            cred("sgkey_ak_2", "sk-dup-value-0123456789abcdefghij"),
        ];
        let providers = vec![
            direct_provider("p1", "sk-dup-value-0123456789abcdefghij"),
            direct_provider("p2", "short"), // < 地板: 丢弃
            direct_provider("p3", "sk-live-0123456789abcdefghijklmnop"),
        ];
        let out = collect_credentials(sg, &providers, "", "p-sel");
        let ids: Vec<&str> = out.iter().map(|c| c.id.as_str()).collect();
        // 长度降序: sgkey_ak_1 (35) > sgprov_p3 (34) > sgkey_ak_2 (32).
        assert_eq!(ids, vec!["sgkey_ak_1", "sgprov_p3", "sgkey_ak_2"]);
        assert!(
            out.windows(2).all(|w| w[0].value.len() >= w[1].value.len()),
            "sorted by value length descending"
        );
    }

    #[test]
    fn collect_selected_file_mode_key_extends_set() {
        let file_key = "sk-from-file-0123456789abcdefghijk";
        let out = collect_credentials(
            vec![],
            &[direct_provider("p1", "sk-inline-0123456789abcdefgh")],
            file_key,
            "p1",
        );
        let ids: Vec<&str> = out.iter().map(|c| c.id.as_str()).collect();
        assert!(
            ids.contains(&"sgprov_p1"),
            "file-mode key of the selected provider carries its provider id: {ids:?}"
        );
    }

    // ─── redact_request_body: 替换 / 零拷贝 / 非 UTF-8 ──────────────────────

    #[test]
    fn redact_replaces_all_occurrences() {
        let c = cred("sgkey_x", "sg_TOKEN0123456789abcdefghijk");
        let body = Bytes::from(
            r#"{"messages":[{"role":"user","content":"my key is sg_TOKEN0123456789abcdefghijk yes"}]}"#,
        );
        let (out, hits) = redact_request_body(&body, std::slice::from_ref(&c));
        let new = out.expect("hit");
        let s = std::str::from_utf8(&new).unwrap();
        assert!(
            !s.contains("sg_TOKEN0123456789abcdefghijk"),
            "real must be gone"
        );
        assert!(s.contains(c.mock.as_str()), "mock must be present");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "sgkey_x");
        assert_eq!(hits[0].occurrences, 1);
    }

    #[test]
    fn redact_no_hit_returns_none_zero_copy() {
        let c = cred("sgkey_x", "sg_TOKEN0123456789abcdefghijk");
        let body = Bytes::from_static(b"{\"messages\":[]}");
        let (out, hits) = redact_request_body(&body, std::slice::from_ref(&c));
        assert!(out.is_none());
        assert!(hits.is_empty());
    }

    #[test]
    fn redact_non_utf8_body_is_skipped() {
        let c = cred("sgkey_x", "sg_TOKEN0123456789abcdefghijk");
        let body = Bytes::from(vec![0xff, 0xfe, 0x00, 0x01]);
        let (out, hits) = redact_request_body(&body, std::slice::from_ref(&c));
        assert!(out.is_none(), "non-UTF8 skipped (fail-open)");
        assert!(hits.is_empty());
    }

    #[test]
    fn redact_unicode_body_untouched_around_hit() {
        // 非 ASCII body + ASCII 凭证: 替换只动凭证子串, 其余字节 (含多字节字符) 原样.
        let c = cred("sgkey_x", "sg_TOKEN0123456789abcdefghijk");
        let body = Bytes::from("中文内容 sg_TOKEN0123456789abcdefghijk 结束");
        let (out, _) = redact_request_body(&body, std::slice::from_ref(&c));
        let new = out.unwrap();
        let s = std::str::from_utf8(&new).unwrap();
        assert!(s.starts_with("中文内容 "));
        assert!(s.ends_with(" 结束"));
        assert!(s.contains(c.mock.as_str()));
    }

    #[test]
    fn redact_overlap_shorter_value_absorbed_by_longer() {
        // 值 B 是值 A 真值的子串: A (长) 先替换 → 链上 B 的真值已随之消失 → B 不再
        // 计命中 (出站文本已无 B 真值, 语义正确 — 不产生空替换的假命中).
        let long = ProtectedCredential {
            id: "sgprov_long".into(),
            value: "sk-super-secret-0123456789abcdefgh".into(),
            mock: mock_for("sk-super-secret-0123456789abcdefgh"),
        };
        let short = ProtectedCredential {
            id: "sgkey_short".into(),
            value: "super-secret-0123456789".into(), // 24 chars > 地板, 是 long 的子串
            mock: mock_for("super-secret-0123456789"),
        };
        // 手工构造乱序 (短在前) 也应稳定: 排序由 collect 负责, 这里直接验证链语义 —
        // 先替换者吞掉后续子串.
        let body = Bytes::from("x sk-super-secret-0123456789abcdefgh y");
        let (out, hits) = redact_request_body(&body, &[long, short]);
        let new_bytes = out.unwrap();
        let s = std::str::from_utf8(&new_bytes).unwrap();
        assert!(!s.contains("sk-super-secret-0123456789abcdefgh"));
        assert!(!s.contains("super-secret-0123456789"));
        assert!(s.contains(&mock_for("sk-super-secret-0123456789abcdefgh")));
        assert_eq!(
            hits.len(),
            1,
            "substring credential absorbed, not double-hit"
        );
        assert_eq!(hits[0].id, "sgprov_long");
    }

    // ─── property: 任意合格凭证替换后 body 不含真值且幂等 ───────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn prop_redact_removes_real_and_is_idempotent(
            prefix in "[a-z ,.!?'\"\n]{0,32}",
            suffix in "[a-z ,.!?'\"\n]{0,32}",
            token in "[A-Za-z0-9_]{16,48}",
        ) {
            let c = cred("sgkey_prop", &token);
            let body = Bytes::from(format!("{prefix}{token}{suffix}{token}"));
            let (out, hits) = redact_request_body(&body, std::slice::from_ref(&c));
            let new = out.expect("token always present");
            let s = std::str::from_utf8(&new).unwrap();
            proptest::prop_assert!(!s.contains(token.as_str()));
            proptest::prop_assert_eq!(hits.len(), 1);
            proptest::prop_assert_eq!(hits[0].occurrences, 2);
            // 幂等: 已替换 body 再跑一轮零命中.
            let (again, hits2) = redact_request_body(&new, std::slice::from_ref(&c));
            proptest::prop_assert!(again.is_none());
            proptest::prop_assert!(hits2.is_empty());
        }
    }
}
