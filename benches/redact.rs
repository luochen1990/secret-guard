//! redact 模块的性能基线 bench.
//!
//! # 测什么
//!
//! 覆盖 secret-guard 两条 redact 热路径:
//! - [`redact::redact_ir`]: 请求侧 IR 改写 (扫描 + 替换 secret).
//! - [`redact::StreamingRestorer::push`]: 流式响应侧 sliding-window restore
//!   (尾部缓冲, 跨 chunk 还原 mock→real).
//!
//! 两者在 AGENTS.md "后续工作" 标注为 K * n 复杂度 (K = secret 数, n = body 字节数),
//! 长期计划用 Aho-Corasick 多模式匹配优化. 本 bench 提供优化前的回归基线,
//! 让优化收益可量化 (criterion 自动与历史基线比对).
//!
//! # 三场景设计理由
//!
//! 覆盖 K (secret 数) 与 n (body 字节数) 两个维度的代表性点:
//!
//! | 场景 | body 字节 | secret 数 | 模拟场景 |
//! |---|---|---|---|
//! | small  | ~500 B   | 1  | 单轮简短对话 (本地 dev 调试) |
//! | medium | ~10 KB   | 10 | 典型 agent 多工具调用 (生产典型负载) |
//! | large  | ~100 KB  | 1  | 长上下文历史 (RAG / 长文档对话) |
//!
//! - small/large 都跑 K=1: 隔离 n 对 `redact_ir` 全字符串扫描的影响 (扫描 n 字节
//!   × K 次 = K * n 复杂度, K=1 时 n 为唯一变量).
//! - medium 跑 K=10: 让 K * n 项中 K * (K-1)/2 的 allocated 集合 probing 也进入观测,
//!   真实生产典型负载的复合开销.
//! - `StreamingRestorer` 同样三场景, 每个 body 切成 ~1 KB chunk 逐个 push,
//!   模拟真实流式 SSE (单 event payload 量级).
//!
//! # 为什么手动构造 RedactionMap 而非调用真实 mock 生成
//!
//! 生产路径 [`redact::redact_ir`] 内部调用 [`mock::gen_candidate`] 做带 C5 重试链的
//! mock 探测 (内部 10000 次重试上界, 见 `src/mock.rs` 头部 C5 段落). 这部分逻辑:
//! 1. 自身有开销 (会污染 `redact_ir` 的纯扫描开销测量);
//! 2. 与 redact 扫描算法解耦 (本 bench 关注的优化目标是扫描算法, 不是 mock 生成);
//! 3. 高度依赖 seed / IR 内容 (每次 benchmark 重跑数据可能漂移, 影响基线稳定性).
//!
//! 因此对 `StreamingRestorer` 本 bench 直接用 [`RedactionMap::insert`] 手动构造固定的
//! real↔mock 对 (例如 `"sk-real-secret-{i}"` → `"MOCK-{i:015}"`), 把测量范围限定在
//! restore 的扫描 + 替换算法本身. `redact_ir` bench 仍传真实 [`SecretEntry`] (生产路径),
//! 但通过 `resolve_against` 让 mock 生成在少数几次 probing 内命中 (IR 中不预置 mock 候选,
//! 保证首次 counter=0 命中), 排除 mock 生成的不稳定开销对扫描算法测量的污染.
//!
//! # 运行
//!
//! ```bash
//! just bench                              # 完整 bench (criterion 默认 100 samples)
//! cargo bench --bench redact -- --quick   # 快速验证 setup (1 sample, criterion 0.5 支持)
//! cargo bench --bench redact --no-run     # 仅编译验证
//! ```

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use secret_guard::codec::ir::{IrBlock, IrMessage, IrRequest, IrRole};
use secret_guard::mock::MockStrategy;
use secret_guard::redact::{RedactionMap, StreamingRestorer, redact_ir};
use secret_guard::secrets::{SecretCategory, SecretEntry};

// ─── 场景参数 ─────────────────────────────────────────────────────────────

/// 单个场景的描述: body 大小 + secret 数 + chunk 大小.
#[derive(Clone, Copy)]
struct Scenario {
    /// 场景名 (criterion group id).
    name: &'static str,
    /// 目标 body 字节数 (近似, 实际由消息条数与每条长度决定).
    target_body_bytes: usize,
    /// secret 数量 (K).
    num_secrets: usize,
    /// 流式 chunk 字节数 (StreamingRestorer 用).
    chunk_bytes: usize,
}

const SMALL: Scenario = Scenario {
    name: "small",
    target_body_bytes: 500,
    num_secrets: 1,
    chunk_bytes: 256,
};

const MEDIUM: Scenario = Scenario {
    name: "medium",
    target_body_bytes: 10_000,
    num_secrets: 10,
    chunk_bytes: 1_024,
};

const LARGE: Scenario = Scenario {
    name: "large",
    target_body_bytes: 100_000,
    num_secrets: 1,
    chunk_bytes: 1_024,
};

const SCENARIOS: &[Scenario] = &[SMALL, MEDIUM, LARGE];

// ─── 数据构造 ─────────────────────────────────────────────────────────────

/// 构造 `num` 个真实 secret entry (空 global_prefix, Auto 模式, 内部 resolve 好 gen spec).
///
/// 值形如 `"sk-real-secret-{i:03}"`, 长度 ~20 字节, charset 覆盖 [a-z0-9-].
fn make_secrets(num: usize) -> Vec<SecretEntry> {
    (0..num)
        .map(|i| {
            let value = format!("sk-real-secret-{i:03}");
            let mut e = SecretEntry {
                id: format!("bench-secret-{i:03}"),
                name: None,
                category: SecretCategory::ApiKey,
                value: value.clone(),
                value_file: None,
                mock_strategy: MockStrategy::default(),
            };
            // 与生产路径一致: resolve_against 把 Auto 模式的 gen_spec infer 出来
            // (否则 gen_candidate 会 panic). 空 global_prefix.
            e.mock_strategy.resolve_against(&value, "");
            e
        })
        .collect()
}

/// 构造一个 IrRequest, body 字节数近似 `target_bytes`, 内嵌全部 `secrets`.
///
/// 设计:
/// - 用 `target_bytes / 200` 条 IrMessage (每条 ~200 字节), 至少 1 条.
/// - 每条 message 的 text 是固定 prefix + 第 i 个 secret (循环嵌入, 确保所有 secret 都被命中).
/// - 不预置 mock 候选字串 (保证 gen_mock_for_ir 首次 counter=0 命中, 不触发 probing 重试).
fn make_ir_with_secrets(target_bytes: usize, secrets: &[SecretEntry]) -> IrRequest {
    const MSG_BYTES: usize = 200; // 每条 message 近似字节数
    let num_msgs = (target_bytes / MSG_BYTES).max(1);
    let messages = (0..num_msgs)
        .map(|i| {
            let secret = &secrets[i % secrets.len()].value;
            // padding 到 ~MSG_BYTES 字节; secret 在中间, 保证 redact_ir 的 find 与 replace 都触发.
            let padding = "lorem ipsum dolor sit amet consectetur adipiscing elit "
                .repeat((MSG_BYTES / 56).max(1));
            IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text {
                    text: format!("{padding} auth_token={secret} end_marker_{i}"),
                }],
                ..Default::default()
            }
        })
        .collect();
    IrRequest {
        messages,
        model: "bench-model".to_string(),
        ..Default::default()
    }
}

/// 手动构造 RedactionMap (绕过真实 mock 生成) + 对应的 mock 列表.
///
/// real = `secrets[i].value`, mock = `MOCK-{i:015}` (15 位补零, 固定长度便于稳定 bench).
/// 返回 (map, mocks): mocks 是 map 中所有 mock 的有序列表, 供 `make_chunks_with_mocks`
/// 在 body 中均匀嵌入. 让 mock 字面量只在此一处生成 (SSOT), 避免调用方重复 `format!`
/// 导致格式漂移后 bench 静默退化 (restorer 匹配不到 mock, 实际只测扫描不测替换).
fn make_redaction_map(secrets: &[SecretEntry]) -> (RedactionMap, Vec<String>) {
    let mut map = RedactionMap::default();
    let mut mocks = Vec::with_capacity(secrets.len());
    for (i, e) in secrets.iter().enumerate() {
        let mock = format!("MOCK-{:015}", i);
        map.insert(e.value.clone(), mock.clone(), &e.id).unwrap();
        mocks.push(mock);
    }
    (map, mocks)
}

/// 构造一段含全部 mock 的响应 body (近似 `target_bytes`), 切成 ~`chunk_bytes` 的 chunk.
///
/// 用于 StreamingRestorer::push bench. 每个 chunk 是字节数组的 String 视图 (UTF-8 安全,
/// 全 ASCII 内容). mock 在 body 中均匀分布, 保证 sliding-window 命中.
fn make_chunks_with_mocks(
    target_bytes: usize,
    mocks: &[String],
    chunk_bytes: usize,
) -> Vec<String> {
    const SENTINEL: &str = "MOCKMARKER";
    // chunk_bytes.max(64) 已 > SENTINEL.len()+1, 无需再与 sentinel 长度取 max.
    let per_unit = chunk_bytes.max(64);
    // 每个 chunk 单元: 一个 mock (循环) + padding. mock 散布在各 chunk 内.
    let num_units = (target_bytes / per_unit).max(1);
    let units: Vec<String> = (0..num_units)
        .map(|i| {
            let mock = &mocks[i % mocks.len()];
            // chunk = mock + 凑齐 per_unit 的 ASCII padding.
            let pad_len = per_unit.saturating_sub(mock.len() + SENTINEL.len() + 2);
            let padding = "x".repeat(pad_len);
            format!("{SENTINEL}{padding}{mock}")
        })
        .collect();
    let joined = units.join("");
    // 把 joined 切成 chunk_bytes 大小的 chunk (最后一个可能更短).
    joined
        .as_bytes()
        .chunks(chunk_bytes)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect()
}

// ─── bench 函数 ───────────────────────────────────────────────────────────

/// bench `redact_ir`: 每次迭代用全新 IR 副本 (redact 原地修改), secrets 复用.
fn bench_redact_ir(c: &mut Criterion) {
    let mut group = c.benchmark_group("redact_ir");
    for s in SCENARIOS {
        let secrets = make_secrets(s.num_secrets);
        // 模板 IR: 每次迭代 clone 后 redact (避免上一轮 redact 后的 IR 污染下一轮).
        let template = make_ir_with_secrets(s.target_body_bytes, &secrets);
        // 近似 body 字节数 (用 message text 长度估算), 让 criterion 显示 throughput.
        let body_bytes: usize = template
            .messages
            .iter()
            .map(|m| {
                m.content
                    .iter()
                    .map(|b| match b {
                        IrBlock::Text { text } => text.len(),
                        _ => 0,
                    })
                    .sum::<usize>()
            })
            .sum();
        group.throughput(Throughput::Bytes(body_bytes as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(s.name),
            &template,
            |b, template| {
                b.iter(|| {
                    let mut ir = template.clone();
                    let (map, _seed) = redact_ir(&mut ir, black_box(&secrets));
                    black_box(map);
                });
            },
        );
    }
    group.finish();
}

/// bench `StreamingRestorer::push`: 预构造好 map + chunks, 每次迭代新建 restorer 并 push 全部 chunk.
fn bench_streaming_restorer(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_restorer");
    for s in SCENARIOS {
        let secrets = make_secrets(s.num_secrets);
        let (map, mocks) = make_redaction_map(&secrets);
        let chunks = make_chunks_with_mocks(s.target_body_bytes, &mocks, s.chunk_bytes);
        let total_bytes: usize = chunks.iter().map(|c| c.len()).sum();
        group.throughput(Throughput::Bytes(total_bytes as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(s.name),
            &(map.clone(), chunks.clone()),
            |b, (map, chunks)| {
                b.iter(|| {
                    let mut r = StreamingRestorer::new(map.clone());
                    let mut acc = String::new();
                    for chunk in chunks {
                        acc.push_str(&r.push(black_box(chunk.clone())));
                    }
                    let (_, tail) = r.flush();
                    acc.push_str(&tail);
                    black_box(acc);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_redact_ir, bench_streaming_restorer);
criterion_main!(benches);
