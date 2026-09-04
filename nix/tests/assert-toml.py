# 职责: 断言 services.secret-guard 结构化选项生成的 toml 形状 (build 期执行)
#
# 消费方: nix/tests/module-eval.nix (flake check 接入). 为什么在 build 期跑:
# eval 期无法 readFile 未构建的 store path, 而 python tomllib 提供了真实的
# TOML 语法 + 结构 round-trip — 字段断言与 nix/tests/render.nix 的 eval 期断言
# 互补, 共同锁定 "模块选项 → configFile 生成" 链路.
#
# 用法: assert-toml.py <mode> <toml-path>
#   mode = minimal : 全字段形态 (direct+router+secrets+auth+usage), 对齐 module-eval
#                     的最小 host config
#   mode = inline  : 内联 key 合成组合形态 (apiKey 直值 + 默认路由 router)
# 字段名断言与 src serde schema (provider.rs/config.rs/auth/mod.rs/secrets.rs)
# 逐字段对应 — schema 变更时同步改.
import sys
import tomllib

mode, path = sys.argv[1], sys.argv[2]
with open(path, "rb") as f:
    cfg = tomllib.load(f)

if mode == "minimal":
    assert [p["id"] for p in cfg["providers"]] == ["a-router", "b-upstream"], cfg["providers"]
    by_id = {p["id"]: p for p in cfg["providers"]}

    d = by_id["b-upstream"]
    assert d["kind"] == "direct"
    assert d["enabled"] is True
    assert d["name"] == r'Z "quoted" \\ backslash', d["name"]
    assert d["protocol"] == "openai"
    assert d["base_url"] == "https://open.example.com/v4"
    assert d["api_key_file"] == "/run/secrets/upstream_key"
    assert "api_key" not in d  # 内联 key 未设 → 不生成行

    r = by_id["a-router"]
    assert r["kind"] == "router"
    assert "base_url" not in r and "protocol" not in r  # sum type: router 无 direct 字段
    assert len(r["routes"]) == 2
    rt0, rt1 = r["routes"]
    assert rt0["model_pattern"] == "*" and rt0["target"] == "b-upstream" and rt0["priority"] == 100
    assert "upstream_model" not in rt0  # 省略 = 透传 (serde None)
    assert rt1["model_pattern"] == "gpt-*" and rt1["upstream_model"] == "glm-4.7"
    assert "priority" not in rt1  # 省略 = 该路由禁用 (serde None)

    e = cfg["secrets"]["entries"][0]
    assert e["id"] == "llm__k_api_key" and e["category"] == "apikey"
    assert e["value_file"] == "/run/secrets/llm__k_api_key"

    s = cfg["server"]
    assert s["host"] == "127.0.0.1" and s["port"] == 18787
    # 超时字段不渲染 (回归上游 #175 分档默认)
    assert "upstream_response_header_timeout_secs" not in s
    assert "upstream_connect_timeout_secs" not in s

    a = cfg["auth"]
    assert a["enabled"] is True
    o = a["oidc"]
    assert o["issuer_url"] == "https://idp.example.com/v1/"
    assert o["client_id"] == "test-client"
    assert o["client_secret_file"] == "/run/secrets/oidc_client_secret"
    assert o["redirect_url"] == "https://sg.example.com/oauth2/callback"
    k = a["api_keys"][0]
    assert k["label"] == "opencode" and k["key_file"] == "/run/secrets/sdk_api_key"

    u = cfg["usage"]
    assert u["enabled"] is True
    assert u["retention_days"] == 90  # minimal 未显式设 → 默认值 e2e 镜像锁 (与 Rust impl Default 同步义务)
    assert u["pricing_url"] == "https://models.dev/api.json"
    assert u["pricing_refresh_secs"] == 86400  # 未显式设 → module 默认全量渲染
    po = u["pricing_override"]["glm-5.3"]
    assert po["input"] == 1.4 and po["output"] == 4.4
    assert po["cache_read"] == 0.26 and po["cache_write"] == 0.0

elif mode == "inline":
    assert [p["id"] for p in cfg["providers"]] == ["a-router", "b-upstream"], cfg["providers"]
    by_id = {p["id"]: p for p in cfg["providers"]}
    d = by_id["b-upstream"]
    assert d["kind"] == "direct" and d["protocol"] == "openai"
    assert d["base_url"] == "https://up.example.com/v1"
    assert d["api_key"] == "test-inline-key"
    assert "api_key_file" not in d  # 内联 key 形态 → 不生成 file 行
    assert d["enabled"] is True
    r = by_id["a-router"]
    assert r["kind"] == "router"
    rt = r["routes"][0]
    assert rt["model_pattern"] == "*" and rt["target"] == "b-upstream" and rt["priority"] == 100
    # 全默认段不渲染 (module 层 usageUsed/authUsed 判定 → serde default 兜底):
    # 锁定 "nix options defaults ↔ usageDefaults 镜像 ↔ render 跳过" 的端到端一致
    # 性 — 任一侧默认值漂移都会让本断言失败 (usage/auth 段出现即漂移)
    assert "usage" not in cfg
    assert "auth" not in cfg
else:
    raise SystemExit(f"unknown mode: {mode}")

print(f"[sg-module-eval] assert-toml({mode}): OK")
