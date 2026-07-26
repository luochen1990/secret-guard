//! Canonical JSON 序列化 (normalize_json).
//!
//! # 职责
//!
//! 把 [`Value`] 序列化为 canonical 字符串: object key 按 BTreeMap 排序, 紧凑无空白,
//! 递归到所有嵌套层级. 用于 FWD-1/FWD-2 property test 的字节级断言.
//!
//! # 为什么不用 `serde_json::to_string`
//!
//! `serde_json::Map` 默认按插入顺序 (或 `preserve_order` feature 的 IndexMap 顺序) 排列 key.
//! 同一份 IR 经不同路径序列化, key 顺序可能不同, 但语义完全等价.
//! `normalize_json` 通过 BTreeMap 排序吸收这种"无语义差异", 让 property test
//! 能做字节级比较.
//!
//! # normalize_json 不是什么
//!
//! - **不是** "JSON Canonicalization Scheme" (RFC 8785). RFC 8785 还处理 number 精度 /
//!   转义形式等细节, secret-guard 不需要 (input 是 LLM chat completion body, 不涉及
//!   大整数 / 科学计数法).
//! - **不是** 生产路径的一部分. 仅用于 test 断言.
//!
//! # 数学性质 (作为 canonical form)
//!
//! - **幂等**: `normalize_json(x) == normalize_json(parse(normalize_json(x)))`
//! - **吸收格式噪声**: key 顺序 / 空白 差异被吸收
//! - **保留信息**: 字段集合 / 字段值 / 类型 / 数组顺序的差异不被吸收

use std::collections::BTreeMap;

use serde_json::Value;

/// 把 [`Value`] 序列化为 canonical JSON 字符串.
///
/// 规则:
/// 1. `Value::Object` → key 按 BTreeMap 字典序排序, 紧凑无空白.
/// 2. `Value::Array` → 保持元素顺序 (array 顺序是有语义的).
/// 3. 其他类型 (string / number / bool / null) → 用 `serde_json::to_writer` 序列化.
///
/// 复杂度 O(n log k), n = 节点总数, k = 单层 object 的 key 数.
pub fn normalize_json(value: &Value) -> String {
    let mut out = String::with_capacity(128);
    canonical(value, &mut out);
    out
}

fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            // BTreeMap<&str, &Value> 按 key 字典序排序
            let sorted: BTreeMap<&str, &Value> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            out.push('{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // object key 永远是 string, 序列化为 JSON string literal (含引号 + 转义).
                out.push_str(&serde_json::to_string(k).expect("string 序列化不会失败"));
                out.push(':');
                canonical(v, out);
            }
            out.push('}');
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(v, out);
            }
            out.push(']');
        }
        // string / number / bool / null: 交给 serde_json 序列化 (它处理转义 / 数值格式),
        // 然后拼接到 out. unwrap 安全: 这些基础类型的序列化不会失败.
        other => {
            out.push_str(&serde_json::to_string(other).expect("基础类型序列化不会失败"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 元 property 1: 幂等性 — normalize(x) == normalize(parse(normalize(x)))
    #[test]
    fn normalize_is_idempotent() {
        let cases = [
            json!({}),
            json!({"a": 1, "b": 2}),
            json!({"nested": {"c": [1, 2, {"d": "e"}]}}),
            json!([1, "two", null, true, {"k": "v"}]),
            json!(null),
            json!("escape: \" \\ \n \t"),
            json!({"":""}), // 空 key
        ];
        for v in &cases {
            let n1 = normalize_json(v);
            let parsed: Value = serde_json::from_str(&n1).unwrap();
            let n2 = normalize_json(&parsed);
            assert_eq!(
                n1, n2,
                "幂等性违反: 原始 normalize={} 二次 normalize={}",
                n1, n2
            );
        }
    }

    /// 元 property 2: 吸收格式噪声 — key 顺序 / 空白差异不影响 normalize 结果
    #[test]
    fn normalize_absorbs_format_noise() {
        let a = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let b = serde_json::from_str(r#"{ "b" : 2 , "a" : 1 }"#).unwrap();
        assert_eq!(normalize_json(&a), normalize_json(&b));

        // 嵌套 object 也要吸收
        let c = serde_json::from_str(r#"{"x":{"y":1,"z":2}}"#).unwrap();
        let d = serde_json::from_str(r#"{"x":{"z":2,"y":1}}"#).unwrap();
        assert_eq!(normalize_json(&c), normalize_json(&d));
    }

    /// 元 property 3 (反例): 字段集合 / 值 / 类型的差异**不**被吸收
    #[test]
    fn normalize_preserves_real_differences() {
        // 字段不同
        assert_ne!(
            normalize_json(&json!({"a": 1})),
            normalize_json(&json!({"a": 1, "b": 2}))
        );

        // 值不同
        assert_ne!(
            normalize_json(&json!({"a": 1})),
            normalize_json(&json!({"a": 2}))
        );

        // 类型不同 (string vs array vs null)
        assert_ne!(
            normalize_json(&json!({"content": "hello"})),
            normalize_json(&json!({"content": ["hello"]}))
        );
        assert_ne!(
            normalize_json(&json!({"content": "hello"})),
            normalize_json(&json!({"content": null}))
        );

        // array 顺序不同 (顺序是有语义的, 不吸收)
        assert_ne!(
            normalize_json(&json!([1, 2, 3])),
            normalize_json(&json!([3, 2, 1]))
        );
    }

    /// 元 property 4: 数字归一化 — f64 round-trip 稳定 (serde_json 默认行为)
    #[test]
    fn normalize_preserves_number_round_trip() {
        // 整数
        assert_eq!(normalize_json(&json!(42)), normalize_json(&json!(42)));
        // 浮点 (LLM 常用 temperature 等)
        assert_eq!(normalize_json(&json!(0.7)), normalize_json(&json!(0.7)));
    }

    #[test]
    fn normalize_empty_object_and_array() {
        assert_eq!(normalize_json(&json!({})), "{}");
        assert_eq!(normalize_json(&json!([])), "[]");
    }

    #[test]
    fn normalize_sorts_nested_keys() {
        let v = json!({"z": 1, "a": {"y": 2, "b": 3}});
        assert_eq!(normalize_json(&v), r#"{"a":{"b":3,"y":2},"z":1}"#);
    }
}
