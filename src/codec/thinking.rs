//! sg-thinking envelope: provider opaque 思考上下文容器的跨协议搬运格式 (T7)。
//!
//! # 定位 (cc-switch 模式)
//!
//! Anthropic thinking block 的 `signature` 与 Responses reasoning item 的
//! `encrypted_content` 都是 "provider opaque 思考上下文容器" — stateless tool
//! loop 要求客户端回传它们, 而 secret-guard 无法合成 (旧裁决只否定**合成**)。
//! 本模块提供第三条路: **不合成只搬运** — 把己方 block 完整序列化 base64 藏进
//! 对方协议的 opaque 容器, 带版本前缀; 回传方向识别前缀解包还原。参照 cc-switch
//! `reasoning_bridge.rs` 的 `ccswitch-openai-reasoning-v1:` 先例。
//!
//! # 格式
//!
//! `sg-thinking-v1:` + base64 (URL_SAFE_NO_PAD) of 版本化 JSON:
//! - ReasoningContent: `{"v":1,"t":"rc","text":...,"o":null|{"k":"sig"|"red","d":...}}`
//! - Reasoning:        `{"v":1,"t":"r","s":[...],"e":null|"..."}`
//!
//! # 安全链 (C1-C7, redact/restore pipeline 的位置契约)
//!
//! envelope 是 base64(**明文 JSON**) — 打包/解包位置是安全链的关键:
//! - **打包只在 writer** (请求侧 post-redact / 响应侧 post-restore): writer 收到的
//!   IR 已经过 redact (文本叶子为 mock) 或 restore (文本叶子为 real 且本就该交付
//!   客户端) — 请求方向的 envelope **不含未脱敏 secret**。
//! - **解包只在 reader** (redact/restore 之前): 解包出的 text/summary 成为 IR
//!   字符串叶子, 必然流经 redact 扫描 (请求) / restore (响应)。
//! - opaque 本身 (真 signature/encrypted_content) 是签名/密文非明文, 不进扫描
//!   (假设声明: 密文不构成 secret 泄漏面; envelope 打包时内部文本已过扫描)。
//! - reader 见 sg- 前缀解包后, **envelope 块是权威源**, wire 上的 body 文本丢弃
//!   (我们合成的块两者一致; 恶意构造不一致时丢弃 wire body = over-redaction,
//!   安全方向)。
//!
//! # ROB (best-effort, 永不 panic)
//!
//! 解包失败 (前缀不匹配 / base64 损坏 / JSON 损坏 / 超过大小上限 1 MiB)
//! 一律返回 None — 调用方把原串当 plain opaque 继续透传 (真 signature 不误判)。

use base64::Engine as _;

use super::ir::{IrBlock, ThinkingOpaque};

/// envelope 版本前缀 (SSOT — reader 的识别标记, 与 cc-switch 的
/// `ccswitch-openai-reasoning-v1:` 同构但命名空间独立)。
pub const ENVELOPE_PREFIX: &str = "sg-thinking-v1:";

/// 解包大小上限 (base64 解码前): 防恶意超长 blob 的 DoS。真 signature/encrypted_content
/// 本就在数 KB 量级; 超限按 plain opaque 处理 (透传不解析)。
const MAX_ENVELOPE_BYTES: usize = 1 << 20; // 1 MiB

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// 打包 [`IrBlock::ReasoningContent`] → envelope 字符串 (writer 侧专用)。
pub fn pack_reasoning_content(text: &str, opaque: &Option<ThinkingOpaque>) -> String {
    let o = opaque.as_ref().map(|op| match op {
        ThinkingOpaque::Signature(d) => serde_json::json!({"k": "sig", "d": d}),
        ThinkingOpaque::RedactedData(d) => serde_json::json!({"k": "red", "d": d}),
    });
    seal(&serde_json::json!({"v": 1, "t": "rc", "text": text, "o": o}))
}

/// 打包 [`IrBlock::Reasoning`] → envelope 字符串 (writer 侧专用)。
pub fn pack_reasoning(summary: &[String], opaque: &Option<String>) -> String {
    seal(&serde_json::json!({
        "v": 1, "t": "r",
        "s": summary,
        "e": opaque,
    }))
}

/// envelope 封装 SSOT: 前缀 + base64(payload)。序列化失败降级为空载荷
/// (解包必失败 → 调用方按 plain opaque 处理, ROB 闭环)。
fn seal(payload: &serde_json::Value) -> String {
    format!(
        "{ENVELOPE_PREFIX}{}",
        b64().encode(serde_json::to_string(payload).unwrap_or_default())
    )
}

/// 识别并解包 envelope → IR block (reader 侧专用)。
///
/// 只还原 Reasoning / ReasoningContent 两种块 (envelope 的合法载荷); 任何解析
/// 失败返回 None (ROB-1: 调用方按 plain opaque 处理, 真 signature 不误判)。
pub fn unpack(s: &str) -> Option<IrBlock> {
    let b64_part = s.strip_prefix(ENVELOPE_PREFIX)?;
    if b64_part.len() > MAX_ENVELOPE_BYTES {
        return None;
    }
    let raw = b64().decode(b64_part).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    if v.get("v")?.as_u64()? != 1 {
        return None;
    }
    match v.get("t")?.as_str()? {
        "rc" => {
            let text = v.get("text").and_then(|t| t.as_str()).unwrap_or("");
            let opaque = v.get("o").and_then(|o| {
                let d = o.get("d").and_then(|d| d.as_str())?;
                match o.get("k").and_then(|k| k.as_str())? {
                    "sig" => Some(ThinkingOpaque::Signature(d.to_string())),
                    "red" => Some(ThinkingOpaque::RedactedData(d.to_string())),
                    _ => None,
                }
            });
            if text.is_empty() && opaque.is_none() {
                // 零信息块: 与 reader 的退化丢弃规则一致 (不产出空气泡)。
                return None;
            }
            Some(IrBlock::ReasoningContent {
                text: text.to_string(),
                opaque,
            })
        }
        "r" => {
            let summary = v
                .get("s")
                .and_then(|s| s.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let opaque = v.get("e").and_then(|e| e.as_str()).map(str::to_string);
            if summary.is_empty() && opaque.is_none() {
                return None;
            }
            Some(IrBlock::Reasoning { summary, opaque })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pack → unpack 双向恒等 (两种块 × opaque 形态矩阵)。
    #[test]
    fn envelope_roundtrip_all_shapes() {
        let cases = vec![
            IrBlock::ReasoningContent {
                text: "think about sk-live".into(),
                opaque: Some(ThinkingOpaque::Signature("SIGabc123".into())),
            },
            IrBlock::ReasoningContent {
                text: "".into(),
                opaque: Some(ThinkingOpaque::RedactedData("REDACTEDblob".into())),
            },
            IrBlock::ReasoningContent {
                text: "o-origin plain".into(),
                opaque: None,
            },
            IrBlock::Reasoning {
                summary: vec!["sum-a".into(), "sum-b".into()],
                opaque: Some("enc-blob".into()),
            },
            IrBlock::Reasoning {
                summary: vec![],
                opaque: Some("enc-only".into()),
            },
        ];
        for block in cases {
            let packed = match &block {
                IrBlock::ReasoningContent { text, opaque } => pack_reasoning_content(text, opaque),
                IrBlock::Reasoning { summary, opaque } => pack_reasoning(summary, opaque),
                _ => unreachable!("fixture 只含两种块"),
            };
            assert!(packed.starts_with(ENVELOPE_PREFIX));
            // envelope 是 base64(明文 JSON): 文本以 base64 形态出现, 不构成裸明文泄漏
            // (安全语义由打包位置保证, 这里锁格式事实)。
            assert!(!packed.contains("sum-a"));
            assert_eq!(unpack(&packed).as_ref(), Some(&block));
        }
    }

    /// ROB: 真 signature / 损坏 envelope / 未知版本 / 超限 → None (不误判不 panic)。
    #[test]
    fn envelope_unpack_rejects_plain_and_corrupt() {
        assert!(unpack("EuYBCgYKARgBEg..").is_none(), "真 signature 不误判");
        assert!(unpack(&format!("{ENVELOPE_PREFIX}!!!not-base64!!!")).is_none());
        // base64 合法但 JSON 损坏。
        let corrupt = b64().encode(b"not json");
        assert!(unpack(&format!("{ENVELOPE_PREFIX}{corrupt}")).is_none());
        // 版本未知。
        let v2 = b64().encode(br#"{"v":2,"t":"rc","text":"x","o":null}"#);
        assert!(unpack(&format!("{ENVELOPE_PREFIX}{v2}")).is_none());
        // 零信息块。
        let empty = b64().encode(br#"{"v":1,"t":"rc","text":"","o":null}"#);
        assert!(unpack(&format!("{ENVELOPE_PREFIX}{empty}")).is_none());
        // 超限 (构造 > MAX 的 base64 段)。
        let huge = "A".repeat(MAX_ENVELOPE_BYTES + 1);
        assert!(unpack(&format!("{ENVELOPE_PREFIX}{huge}")).is_none());
    }
}
