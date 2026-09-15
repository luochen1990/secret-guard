# 部署示例 (NixOS + sops-nix)

> `api_key_file` / `value_file` 字段让 `secret-guard.toml` 可以完全脱敏 — 直接进 nix store,
> secret 由 sops-nix 解密到独立路径. 两种 value 来源的 fail-fast vs 热路径差异见
> `src/provider.rs` 与 `src/secrets.rs` 头部.

## 姿势 0: 结构化选项 + 自动 render (推荐)

`services.secret-guard` 的结构化选项 (`providers` / `secrets.entries` / `auth` / `usage` /
`upstreamTimeouts`) 在未显式设 `configFile` 时自动生成 `secret-guard.toml` (渲染 SSOT:
`nix/render.nix`, 字段校验 — sum type / base_url 卫生 / 路由悬空与环检测 — 全部 eval 期
fail-fast, 配错在 `nixos-rebuild` 时即报错而非部署后 crash-loop). 生成物暴露在只读选项
`services.secret-guard.resolvedConfigFile`, 调试可直接
`nix eval .#nixosConfigurations.<host>.config.services.secret-guard.resolvedConfigFile` 后 cat.

上游超时 (`upstreamTimeouts`) 随部署网络环境差异大 — 本地 ollama vs 公网高延迟上游的合理
取值不同, 非流式整响应超时 (`nonstreamResponseHeaderTimeoutSecs`, 默认 300s = 单次生成
时长上限) 在消费方都有自身超时预算时可设 0 (无限) 拆墙, 见 option description.

```nix
# flake.nix:
{
  inputs.secret-guard.url = "git+ssh://forgejo@git.lambda.lc:5522/lc-studio/secret-guard";
  # 本 flake 的 nixosModules.secret-guard 自带 overlay (pkgs.secret-guard 可用)
}

# NixOS module 内:
{
  # 凭据注入: *File 选项是纯路径直通, 本模块不做 sops/LoadCredential 派生 —
  # 部署侧自选注入姿势 (下方 LoadCredential 为推荐, 见姿势 1 的说明)
  systemd.services.secret-guard.serviceConfig.LoadCredential = [
    "zai_key:${config.sops.secrets."llm__zai_coding_plan_api_key".path}"
  ];

  services.secret-guard = {
    enable = true;

    providers."zai-coding-plan" = {
      name = "Zhipuai Coding Plan";
      kind = "direct";
      protocol = "openai";
      baseUrl = "https://open.bigmodel.cn/api/coding/paas/v4";
      apiKeyFile = "/run/credentials/secret-guard.service/zai_key";
    };
    # router 形态 (虚拟端点, 按 model 通配符路由; attrsOf 跨模块可合并)
    providers."default-route" = {
      kind = "router";
      routes = [{ modelPattern = "*"; target = "zai-coding-plan"; priority = 100; }];
    };

    # redact 保护清单 ([[secrets.entries]] 段)
    secrets.entries = [
      { id = "llm__zai_coding_plan_api_key";
        valueFile = "/run/credentials/secret-guard.service/zai_key"; }
    ];

    # 账号系统 (可选; [auth] 段, 对齐 src/auth/mod.rs 的 AuthConfig)
    auth = {
      enable = true;
      oidc = {
        issuerUrl = "https://idp.example.com/realms/main/";
        clientId = "secret-guard";
        clientSecretFile = "/run/credentials/secret-guard.service/oidc_secret";
        redirectUrl = "https://sg.example.com/oauth2/callback"; # 省略 = host/port 派生
      };
      apiKeys = [{ label = "opencode"; keyFile = "/run/credentials/secret-guard.service/sdk_key"; }];
    };
  };
}
```

**configFile 互斥**: 显式设 `configFile` (见姿势 1/2) 与结构化选项**不能同设** (eval 期
throw, 手写是"完全接管", 同设会静默竞争); 两者都不设也 throw. 手写 toml 仍是 escape hatch —
结构化选项覆盖不了的字段 (如 `[redact]` 段调参、secret entry 的 `name`/`mock_strategy`)
走此通道.

## 姿势 1: sops.secrets + systemd LoadCredential (手写 configFile)

适合 secret 被多个模块共享的场景 (例如 claude-code 模块也用同一个 api_key, 已经
设了 `owner = "lc"`). LoadCredential 让 systemd 在服务启动时把 secret mount 到
`/run/credentials/<service>/<id>`, 自动设 mode=0400 owner=<service User>, 不需要
修改 sops.secrets owner 避免与其他模块冲突. toml 本身可用姿势 0 的结构化选项替代 —
下面的手写 configFile 是 escape hatch (与结构化选项互斥).

```nix
systemd.services.secret-guard.serviceConfig.LoadCredential = [
  "zai_key:${config.sops.secrets."llm__zai_coding_plan_api_key".path}"
];

services.secret-guard.configFile = (pkgs.writeText "secret-guard.toml" ''
  [[providers]]
  id = "zai-coding-plan"
  kind = "direct"
  protocol = "openai"
  base_url = "https://open.bigmodel.cn/api/coding/paas/v4"
  api_key_file = "/run/credentials/secret-guard.service/zai_key"
  enabled = true
'');
```

## 姿势 2: sops.secrets + 直接路径 (手写 configFile, 需要 owner = "secret-guard")

适合 secret 只给 secret-guard 用的场景. 与姿势 1 的唯一差异是 `api_key_file` 直接
指向 sops 解密路径, 而不是经 LoadCredential 转手:

```nix
sops.secrets."zai_api_key" = { owner = "secret-guard"; };

services.secret-guard.configFile = (pkgs.writeText "secret-guard.toml" ''
  [[providers]]
  id = "zai-coding-plan"
  kind = "direct"
  protocol = "openai"
  base_url = "https://open.bigmodel.cn/api/coding/paas/v4"
  api_key_file = "${config.sops.secrets."zai_api_key".path}"
  enabled = true
'');
```

**不推荐**: `sops.templates` 渲染整个 toml 把 api_key 嵌入明文 — toml 无法进 nix
store, 调试不便, 与 nixos 生态主流模式 (hermes-agent / bazarr) 不一致.

## HTTPS 反向代理: session cookie 的 Secure flag

`secret-guard` 的 session cookie Secure flag 由 `[auth] secure_cookie` 控制, **默认
`false`** — 这是本地 HTTP 开发模式必须的设置: `Secure` flag 会让浏览器拒绝在 HTTP
连接上回传 cookie, 导致 OIDC 流程在 `localhost` 调试时无法登录.

**生产部署**: 若把 `secret-guard` 暴露在公网并通过反向代理 (nginx / Caddy /
Traefik) 终止 TLS, 应显式设 `[auth] secure_cookie = true`, 让 session cookie 带
`Secure` flag. 不设的隐患: 浏览器与反代之间虽然是 HTTPS, 但 cookie 不带 `Secure`
flag, 浏览器若误用 HTTP 访问相同 origin (如用户手输 URL 漏 `https://`), cookie
会被明文发送, 构成 MITM 风险.

```toml
[auth]
enabled = true
secure_cookie = true
```

> NixOS 结构化选项 (`services.secret-guard.auth.*`) 暂未暴露此字段 — 用
> `configFile` escape hatch 手写 toml (与结构化选项互斥, 见 "configFile 互斥" 段),
> 或暂以反代 HTTP→HTTPS 301 重定向 (nginx `return 301 https://$host$request_uri`)
> 缓解: 让浏览器无法通过 HTTP 访问 origin. 从 `X-Forwarded-Proto` header 动态推断
> 仍是后续工作.

**Host guard 推荐姿势 (SEC-7)**: 反向代理**显式保留原始域名 Host** 并在
secret-guard 声明信任该域名 (NixOS 选项 `services.secret-guard.allowedDomains`,
手写 toml 形态 `[server] allowed_domains = [...]`):

```nix
services.secret-guard.allowedDomains = [ "sg.example.com" ];
```

```nginx
# 注意: nginx 默认 proxy_set_header Host $proxy_host (即 proxy_pass 的 IP:port),
# 不保留客户端域名 — 必须显式声明:
proxy_set_header Host $host;
```

声明域名按**名字**精确匹配且端口宽松 (反代转发的 Host 形态不可穷举); 未声明的
域名形式 Host 一律 403 — 这是防 DNS rebinding 的设计 (攻击者的域名进不了这份
你手写的名单), 见 `src/server_host_guard.rs` 头部白名单语义。
备选 (不推荐): 反代把 Host 改写为 IP 形态 (`proxy_set_header Host 127.0.0.1:18787;`)
也可放行, 但浏览器侧 OIDC redirect / cookie 域语义可能受影响。

## secret entries 的批量注入 (value_file + LoadCredential)

`SecretEntry` 同样支持 `value_file` (启动时一次性 resolve, fail-fast), 所以
**redact 用的 secrets 列表** 也能完全脱敏地注入. 姿势与 provider 的 `api_key_file`
完全对称: LoadCredential + toml `value_file` 引用.

> 结构化选项形态: `services.secret-guard.secrets.entries` (见姿势 0) — 下方是手写
> configFile 的等价派生写法 (escape hatch), 新部署优先用结构化选项.

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
