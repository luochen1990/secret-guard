# 职责: nix/render.nix 纯渲染函数的契约测试 (flake check 经 checks.render-test 接入)
#
# 覆盖:
#   - 结构 round-trip: 生成物是合法 TOML (fromTOML), 字段名/嵌套与 src serde
#     定义吻合 (provider sum type / routes / auth / secrets.entries)
#   - 确定性: providers 按 id 字典序输出
#   - 转义: 字符串值经 toJSON, 引号/反斜杠 round-trip 不损
#   - 路径直通: apiKeyFile / valueFile / clientSecretFile / keyFile 原样写入
#     (无 LoadCredential 派生 — 与 nixos 侧原型的语义差异)
#   - 布局: 文件单换行结尾, 头部注释存在
#   - fail-fast: sum type 违规 / base_url 卫生 / id 卫生 / auth 互斥 /
#     悬空 target / 环检测 全部 eval 期 throw
#
# 模块接线 (选项 → configFile 自动生成) 的冒烟在 nix/tests/module-eval.nix,
# 本文件只测 render 纯函数. 语义断言 (priority null=禁用/并列列表序) 属上游
# 行为, 由 cargo 测试锁定, 不在此重复.
{
  lib,
  pkgs,
}: let
  render = import ../render.nix;

  baseArgs = {
    inherit lib;
    host = "127.0.0.1";
    port = 18787;
    # attr 名故意非字母序, 验证输出按 id 字典序
    providers = {
      b-upstream = {
        name = ''Z "quoted" \\ backslash'';
        kind = "direct";
        protocol = "openai";
        baseUrl = "https://open.example.com/v4";
        apiKeyFile = "/run/secrets/llm__k_api_key";
      };
      a-router = {
        kind = "router";
        routes = [
          {modelPattern = "*"; target = "b-upstream"; priority = 100;}
          # 省略 upstreamModel/priority = 透传/禁用行
          {modelPattern = "gpt-*"; target = "b-upstream";}
        ];
      };
    };
    secretsEntries = [
      {id = "llm__k_api_key"; valueFile = "/run/secrets/llm__k_api_key";}
    ];
    auth = {
      enabled = true;
      oidc = {
        issuerUrl = "https://idp.example.com/v1/";
        clientId = "test-client";
        clientSecretFile = "/run/secrets/idp_client_secret";
        redirectUrl = "https://sg.example.com/oauth2/callback";
      };
      apiKeys = [{label = "opencode"; keyFile = "/run/secrets/sdk_api_key";}];
    };
  };

  toml = render baseArgs;
  parsed = builtins.fromTOML toml;
  byId = builtins.listToAttrs (map (p: lib.nameValuePair p.id p) parsed.providers);

  # eval 失败/成功断言: 契约核心是 "违规 → eval 失败 / 合法 → eval 通过"
  fails = e: !(builtins.tryEval e).success;
  renderFails = overrides: fails (render (baseArgs // overrides));
  renderOk = overrides: !fails (render (baseArgs // overrides));
  # 单 provider 覆盖的合并逻辑只声明一份 (失败/成功断言共用, 保留 kind 等其余
  # 字段, 保证 throw 源于被测字段)
  providerToml = id: overrides:
    render (baseArgs // {
      providers = baseArgs.providers // {${id} = baseArgs.providers.${id} // overrides;};
    });
  renderProviderFails = id: overrides: fails (providerToml id overrides);

  assertions = [
    {
      name = "结构 round-trip: 2 个 provider, 字段与上游 serde 吻合";
      ok = builtins.length parsed.providers == 2 && byId.b-upstream.kind == "direct" && byId.a-router.kind == "router";
    }
    {
      # fromTOML 保留文档序 — 消费者 (上游 Rust serde) 看到的正是这个序
      name = "确定性: providers 按 id 字典序输出";
      ok = map (p: p.id) parsed.providers == ["a-router" "b-upstream"];
    }
    {
      name = "路径直通: apiKeyFile 原样写入 (无 LoadCredential 派生)";
      ok = byId.b-upstream.api_key_file == "/run/secrets/llm__k_api_key";
    }
    {
      name = "apiKey 内联渲染 (非文件凭据形态)";
      ok =
        let
          t = providerToml "b-upstream" {apiKeyFile = null; apiKey = "inline-key";};
          p = (builtins.fromTOML t).providers;
        in (builtins.elemAt p 1).api_key == "inline-key" && !(builtins.elemAt p 1) ? api_key_file;
    }
    {
      name = "转义: 引号/反斜杠 round-trip 不损";
      ok = byId.b-upstream.name == ''Z "quoted" \\ backslash'';
    }
    {
      name = "路由省略字段: priority/upstream_model 行不生成 (serde None)";
      ok =
        (builtins.length byId.a-router.routes) == 2
        && (builtins.elemAt byId.a-router.routes 0).priority == 100
        && ((builtins.elemAt byId.a-router.routes 1).priority or null) == null
        && !((builtins.elemAt byId.a-router.routes 1) ? upstream_model);
    }
    {
      name = "路由显式 upstreamModel 渲染";
      ok =
        let
          t = providerToml "a-router" {routes = [{modelPattern = "gpt-*"; target = "b-upstream"; upstreamModel = "glm-4.7"; priority = 10;}];};
        in (builtins.elemAt (builtins.elemAt (builtins.fromTOML t).providers 0).routes 0).upstream_model == "glm-4.7";
    }
    {
      name = "secrets.entries: id/category 默认/valueFile 直通";
      ok =
        (builtins.elemAt parsed.secrets.entries 0).id == "llm__k_api_key"
        && (builtins.elemAt parsed.secrets.entries 0).category == "apikey"
        && (builtins.elemAt parsed.secrets.entries 0).value_file == "/run/secrets/llm__k_api_key";
    }
    {
      name = "auth 段: enabled + oidc 字段 + clientSecretFile 直通 + apiKeys keyFile";
      ok =
        parsed.auth.enabled == true
        && parsed.auth.oidc.client_id == "test-client"
        && parsed.auth.oidc.issuer_url == "https://idp.example.com/v1/"
        && parsed.auth.oidc.client_secret_file == "/run/secrets/idp_client_secret"
        && parsed.auth.oidc.redirect_url == "https://sg.example.com/oauth2/callback"
        && (builtins.elemAt parsed.auth.api_keys 0).label == "opencode"
        && (builtins.elemAt parsed.auth.api_keys 0).key_file == "/run/secrets/sdk_api_key";
    }
    {
      name = "auth: oidc 无 clientSecretFile (public client) → 不生成该行";
      ok =
        let
          t = render (baseArgs // {
            auth = baseArgs.auth // {oidc = builtins.removeAttrs baseArgs.auth.oidc ["clientSecretFile"];};
          });
        in !(builtins.fromTOML t).auth.oidc ? client_secret_file;
    }
    {
      name = "auth: redirectUrl 省略 → 不生成该行 (上游由 host/port 派生)";
      ok =
        let
          t = render (baseArgs // {
            auth = baseArgs.auth // {oidc = builtins.removeAttrs baseArgs.auth.oidc ["redirectUrl"];};
          });
        in !(builtins.fromTOML t).auth.oidc ? redirect_url;
    }
    {
      name = "auth: enable=false 仅配 apiKeys (上游无条件加载 key 池) → [auth] 段 enabled=false + keys 渲染";
      ok =
        let
          t = render (baseArgs // {auth = baseArgs.auth // {enabled = false;};});
          p = (builtins.fromTOML t).auth;
        in p.enabled == false && (builtins.elemAt p.api_keys 0).label == "opencode";
    }
    {
      name = "apiKeys 内联 key 渲染";
      ok =
        let
          t = render (baseArgs // {auth = baseArgs.auth // {apiKeys = [{label = "ci"; key = "sg_x";}];};});
        in (builtins.elemAt (builtins.fromTOML t).auth.api_keys 0).key == "sg_x";
    }
    {
      name = "server 段: host/port 生成, 超时字段不渲染 (回归上游 #175 分档默认)";
      ok = parsed.server.port == 18787 && parsed.server.host == "127.0.0.1" && !(parsed.server ? upstream_response_header_timeout_secs);
    }
    {
      name = "头部注释: Auto-generated 标记存在";
      ok = lib.hasInfix "# Auto-generated by services.secret-guard structured options" toml;
    }
    {
      name = "布局: 文件单换行结尾";
      ok = lib.hasSuffix "\n" toml && !lib.hasSuffix "\n\n" toml;
    }
    {
      name = "secretsEntries 空 → 不渲染 [[secrets.entries]] 段";
      ok =
        let t = render (baseArgs // {secretsEntries = [];});
        in !lib.hasInfix "secrets.entries" t;
    }
    {
      name = "auth=null → 不渲染 [auth] 段";
      ok =
        let t = render (baseArgs // {auth = null;});
        in !lib.hasInfix "[auth]" t;
    }

    # ── fail-fast: sum type / 字段卫生 ──────────────────────────────────
    {
      name = "fail-fast: direct 缺 protocol → throw";
      ok = renderProviderFails "b-upstream" {protocol = null;};
    }
    {
      name = "fail-fast: direct 缺 baseUrl → throw";
      ok = renderProviderFails "b-upstream" {baseUrl = null;};
    }
    {
      name = "fail-fast: direct baseUrl 空 → throw";
      ok = renderProviderFails "b-upstream" {baseUrl = "";};
    }
    {
      name = "fail-fast: baseUrl 非 http(s) → throw (对齐上游 validate_base_url)";
      ok = renderProviderFails "b-upstream" {baseUrl = "ftp://x";};
    }
    {
      name = "fail-fast: baseUrl 尾带 / → throw (对齐上游 validate_base_url)";
      ok = renderProviderFails "b-upstream" {baseUrl = "https://x/";};
    }
    {
      name = "fail-fast: direct 带路由分支专属 routes → throw";
      ok = renderProviderFails "b-upstream" {routes = [{modelPattern = "*"; target = "x";}];};
    }
    {
      name = "fail-fast: direct 同设 apiKeyFile/apiKey (互斥) → throw";
      ok = renderProviderFails "b-upstream" {apiKey = "k";};
    }
    {
      name = "fail-fast: apiKeyFile 相对路径 → throw (上游三种 *_file 解析基各异, 统一要求绝对路径)";
      ok = renderProviderFails "b-upstream" {apiKeyFile = "secrets/api-key";};
    }
    {
      name = "fail-fast: router 空 routes → throw";
      ok = renderProviderFails "a-router" {routes = [];};
    }
    {
      name = "fail-fast: router 带 direct 分支专属 baseUrl → throw";
      ok = renderProviderFails "a-router" {baseUrl = "https://x";};
    }
    {
      name = "fail-fast: router 带 direct 分支专属 protocol → throw";
      ok = renderProviderFails "a-router" {protocol = "openai";};
    }
    {
      name = "fail-fast: router 带 direct 分支专属 apiKeyFile → throw";
      ok = renderProviderFails "a-router" {apiKeyFile = "/run/secrets/x";};
    }
    {
      name = "fail-fast: router 带 direct 分支专属 apiKey → throw";
      ok = renderProviderFails "a-router" {apiKey = "k";};
    }
    {
      name = "fail-fast: kind 非法 → throw";
      ok = renderProviderFails "a-router" {kind = "virtual";};
    }
    {
      name = "fail-fast: tomlComment 多行 → throw";
      ok = renderProviderFails "a-router" {tomlComment = ["line1\nline2"];};
    }
    {
      name = "fail-fast: route modelPattern 空 → throw";
      ok = renderProviderFails "a-router" {routes = [{modelPattern = ""; target = "b-upstream"; priority = 1;}];};
    }
    {
      name = "fail-fast: provider id 非法 (含空格) → throw";
      ok =
        fails (render (baseArgs // {
          providers = baseArgs.providers // {"bad id" = baseArgs.providers.b-upstream;};
        }));
    }
    {
      name = "fail-fast: secrets id 非法 → throw";
      ok = renderFails {secretsEntries = [{id = "bad id"; valueFile = "/x";}];};
    }
    {
      name = "fail-fast: secrets 缺 valueFile → throw";
      ok = renderFails {secretsEntries = [{id = "k";}];};
    }

    # ── fail-fast: auth ────────────────────────────────────────────────
    {
      name = "fail-fast: auth 启用但 oidc=null → throw";
      ok = renderFails {auth = {enabled = true; oidc = null; apiKeys = [];};};
    }
    {
      name = "fail-fast: apiKeys 同设 key/keyFile → throw";
      ok = renderFails {auth = baseArgs.auth // {apiKeys = [{label = "x"; key = "k"; keyFile = "/f";}];};};
    }
    {
      name = "fail-fast: apiKeys 全无 key/keyFile → throw";
      ok = renderFails {auth = baseArgs.auth // {apiKeys = [{label = "x";}];};};
    }
    {
      name = "fail-fast: redirectUrl 形状非法 (path 不对) → throw";
      ok = renderFails {auth = baseArgs.auth // {oidc = baseArgs.auth.oidc // {redirectUrl = "https://sg.example.com/wrong/path";};};};
    }
    {
      name = "fail-fast: apiKeys label 重复 → throw (上游无条件校验, 启动即拒绝)";
      ok = renderFails {auth = baseArgs.auth // {apiKeys = [{label = "x"; key = "k1";} {label = "x"; key = "k2";}];};};
    }
    {
      # 故意加严 pin (见 renderOidc 注释): 上游仅在 enabled 时校验, eval 期一律拦
      name = "fail-fast(加严): enabled=false + 空 issuerUrl → 仍 throw";
      ok = renderFails {auth = {enabled = false; oidc = {issuerUrl = ""; clientId = "c";}; apiKeys = [];};};
    }
    {
      name = "fail-fast: secrets.entries id 重复 → throw (上游 first-wins 静默, 这里加严)";
      ok = renderFails {secretsEntries = [{id = "k"; valueFile = "/a";} {id = "k"; valueFile = "/b";}];};
    }

    # ── fail-fast: 跨 provider 图校验 ──────────────────────────────────
    {
      name = "fail-fast: route target 不存在 → throw";
      ok = renderProviderFails "a-router" {routes = [{modelPattern = "*"; target = "ghost"; priority = 1;}];};
    }
    {
      name = "fail-fast: 禁用路由 target 不存在 → 仍 throw (声明式配置悬空即错误)";
      ok = renderProviderFails "a-router" {routes = [{modelPattern = "*"; target = "ghost";}];};
    }
    {
      name = "fail-fast: 两 provider 路由成环 → throw";
      ok =
        renderFails {
          providers = {
            r1 = {kind = "router"; routes = [{modelPattern = "*"; target = "r2"; priority = 1;}];};
            r2 = {kind = "router"; routes = [{modelPattern = "*"; target = "r1"; priority = 1;}];};
          };
        };
    }
    {
      name = "fail-fast: 路由自环 → throw";
      ok =
        renderFails {
          providers.self = {
            kind = "router";
            routes = [{modelPattern = "*"; target = "self"; priority = 1;}];
          };
        };
    }
    {
      name = "ok: 禁用自环路由不报环 (priority=null 不构成边, 对齐上游 would_cycle)";
      ok =
        renderOk {
          providers.self = {
            kind = "router";
            routes = [{modelPattern = "*"; target = "self";}];
          };
        };
    }
    {
      name = "ok: 链式路由 (router → router → direct) 合法";
      ok =
        renderOk {
          providers = {
            r1 = {kind = "router"; routes = [{modelPattern = "*"; target = "a-router"; priority = 1;}];};
            a-router = baseArgs.providers.a-router;
            b-upstream = baseArgs.providers.b-upstream;
          };
        };
    }
  ];

  failed = builtins.filter (a: !a.ok) assertions;

  testRunner = pkgs.runCommand "secret-guard-render-tests" {} ''
    ${lib.concatMapStrings (a: ''
        echo "[sg-render-test] ${a.name}: ${if a.ok then "PASS" else "FAIL"}" >&2
      '')
      assertions}

    ${if failed == []
      then ''
        echo "[sg-render-test] 全部 ${toString (builtins.length assertions)} 项断言通过" >&2
      ''
      else ''
        echo "[sg-render-test] ${toString (builtins.length failed)} 项断言失败, 详情见上" >&2
        exit 1
      ''}

    touch $out
  '';
in {
  inherit testRunner assertions;
}
