# 部署示例 (NixOS + sops-nix)

> `api_key_file` / `value_file` 字段让 `secret-guard.toml` 可以完全脱敏 — 直接进 nix store,
> secret 由 sops-nix 解密到独立路径. 两种 value 来源的 fail-fast vs 热路径差异见
> `src/provider.rs` 与 `src/secrets.rs` 头部.

## 姿势 1: sops.secrets + systemd LoadCredential (推荐)

适合 secret 被多个模块共享的场景 (例如 claude-code 模块也用同一个 api_key, 已经
设了 `owner = "lc"`). LoadCredential 让 systemd 在服务启动时把 secret mount 到
`/run/credentials/<service>/<id>`, 自动设 mode=0400 owner=<service User>, 不需要
修改 sops.secrets owner 避免与其他模块冲突.

```nix
systemd.services.secret-guard.serviceConfig.LoadCredential = [
  "zai_key:${config.sops.secrets."llm__zai_coding_plan_api_key".path}"
];

services.secret-guard.configFile = (pkgs.writeText "secret-guard.toml" ''
  [[providers]]
  id = "zai-coding-plan"
  protocol = "openai"
  base_url = "https://open.bigmodel.cn/api/coding/paas/v4"
  api_key_file = "/run/credentials/secret-guard.service/zai_key"
  enabled = true
'');
```

## 姿势 2: sops.secrets + 直接路径 (需要 owner = "secret-guard")

适合 secret 只给 secret-guard 用的场景. 与姿势 1 的唯一差异是 `api_key_file` 直接
指向 sops 解密路径, 而不是经 LoadCredential 转手:

```nix
sops.secrets."zai_api_key" = { owner = "secret-guard"; };

services.secret-guard.configFile = (pkgs.writeText "secret-guard.toml" ''
  [[providers]]
  id = "zai-coding-plan"
  protocol = "openai"
  base_url = "https://open.bigmodel.cn/api/coding/paas/v4"
  api_key_file = "${config.sops.secrets."zai_api_key".path}"
  enabled = true
'');
```

**不推荐**: `sops.templates` 渲染整个 toml 把 api_key 嵌入明文 — toml 无法进 nix
store, 调试不便, 与 nixos 生态主流模式 (hermes-agent / bazarr) 不一致.

## secret entries 的批量注入 (value_file + LoadCredential)

`SecretEntry` 同样支持 `value_file` (启动时一次性 resolve, fail-fast), 所以
**redact 用的 secrets 列表** 也能完全脱敏地注入. 姿势与 provider 的 `api_key_file`
完全对称: LoadCredential + toml `value_file` 引用.

适合场景: 把一批符合命名模式的 sops secrets (如 `*_api_key` / `*_api_token` / `*_secret`)
批量注入 secret-guard 做 redact, 防止 agent 不经意把它们写入 LLM prompt.

```nix
let
  # 从 config.sops.secrets 中按模式筛选要 redact 的 key (SSOT: 只列一次).
  redactKeys = lib.filter (k:
    lib.hasSuffix "_api_key" k ||
    lib.hasSuffix "_api_token" k ||
    lib.hasSuffix "_secret" k
  ) (builtins.attrNames config.sops.secrets);
in {
  # LoadCredential 与 toml entries 都从 redactKeys 派生, 永远同步.
  systemd.services.secret-guard.serviceConfig.LoadCredential = map (k:
    "${k}:${config.sops.secrets.${k}.path}"
  ) redactKeys;

  services.secret-guard.configFile = (pkgs.writeText "secret-guard.toml" ''
    ${...providers 段...}
    ${lib.concatStrings (map (k: ''
      [[secrets.entries]]
      id = "${k}"
      value_file = "/run/credentials/secret-guard.service/${k}"
    '') redactKeys)}
  '');
}
```
