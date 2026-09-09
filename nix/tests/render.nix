# 职责: nix/render.nix 纯渲染函数的契约测试 (flake check 经 checks.render-test 接入)
#
# 覆盖:
#   - 结构 round-trip: 生成物是合法 TOML (fromTOML), 字段名/嵌套与 src serde
#     定义吻合 (provider sum type / routes / auth / secrets.entries / usage
#     定价覆盖段)
#   - 确定性: providers 按 id 字典序输出
#   - 转义: 字符串值经 toJSON, 引号/反斜杠 round-trip 不损
#   - 路径直通: apiKeyFile / valueFile / clientSecretFile / keyFile 原样写入
#     (无 LoadCredential 派生 — 与 nixos 侧原型的语义差异)
#   - 布局: 文件单换行结尾, 头部注释存在
#   - fail-fast: sum type 违规 / base_url 卫生 / id 卫生 / auth 互斥 /
#     usage 键卫生与负价 / pricingUrl 形状 / 悬空 target / 环检测 全部 eval 期 throw
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
    # usage 全字段形态: 覆盖两模型 — 键故意非字母序 (验证输出按字典序) + 一个
    # 含 '/' 与 '.' 的键 (验证 quoted key 形态), cache 字段一有一无 (验证省略)
    usage = {
      enable = true;
      retentionDays = 30;
      pricingUrl = "https://models.dev/api.json";
      pricingRefreshSecs = 3600;
      pricingOverride = {
        "zhipuai/glm-5.3" = {input = 1.4; output = 4.4; cacheRead = 0.26; cacheWrite = 0.0;};
        "glm-5.3" = {input = 1.4; output = 4.4;};
      };
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

  # usage 覆盖的合并逻辑只声明一份 (providerToml 同模式: 保留其余字段,
  # 保证 throw 源于被测字段)
  usageFails = o: renderFails {usage = baseArgs.usage // o;};
  # pricingOverride 单模型覆盖 (attr 键合并)
  overrideFails = model: o: usageFails {pricingOverride = baseArgs.usage.pricingOverride // {${model} = o;};};

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
      name = "server 段: host/port 生成, upstreamTimeouts 缺省 → 超时行不渲染 (serde default 兜底, 回归 #175 分档默认)";
      ok = parsed.server.port == 18787 && parsed.server.host == "127.0.0.1" && !(parsed.server ? upstream_response_header_timeout_secs);
    }
    {
      name = "server 段: upstreamTimeouts 显式 → 四行全量渲染, snake_case round-trip 与上游 serde 吻合";
      ok =
        let
          t = render (baseArgs // {
            upstreamTimeouts = {
              connectTimeoutSecs = 10;
              responseHeaderTimeoutSecs = 90;
              nonstreamResponseHeaderTimeoutSecs = 600;
              streamIdleTimeoutSecs = 180;
            };
          });
          s = (builtins.fromTOML t).server;
        in
          s.host == "127.0.0.1" && s.port == 18787
          && s.upstream_connect_timeout_secs == 10
          && s.upstream_response_header_timeout_secs == 90
          && s.upstream_nonstream_response_header_timeout_secs == 600
          && s.upstream_stream_idle_timeout_secs == 180;
    }
    {
      # 拆墙场景 (agent-service#130): 非流式整响应超时 300 → 0 (无限), 慢判定权
      # 交消费方预算; 0 是合法值 (上游 serde 语义: 0 = None = reqwest 无限)
      name = "server 段: nonstream=0 拆墙形态 → 合法渲染 (0 = 无限)";
      ok =
        let
          t = render (baseArgs // {
            upstreamTimeouts = {
              connectTimeoutSecs = 15;
              responseHeaderTimeoutSecs = 60;
              nonstreamResponseHeaderTimeoutSecs = 0;
              streamIdleTimeoutSecs = 120;
            };
          });
          s = (builtins.fromTOML t).server;
        in s.upstream_nonstream_response_header_timeout_secs == 0;
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

    # ── usage: 定价覆盖 (UsageConfig) ───────────────────────────────────
    {
      name = "usage 段: 标量四字段 round-trip 与上游 serde 吻合";
      ok =
        parsed.usage.enabled == true
        && parsed.usage.retention_days == 30
        && parsed.usage.pricing_url == "https://models.dev/api.json"
        && parsed.usage.pricing_refresh_secs == 3600;
    }
    {
      # fromTOML 后 attrNames 恒字典序 (attrset 无序), 文档序只有原始串可观测 —
      # splitString (字面量子串, 非正则) head 长度 = 段头首现位置 (未找到时 head
      # 为整串, 长度=全长, 比较为 false, 兜底安全)
      name = "usage: pricingOverride 键字典序输出 (确定性)";
      ok =
        let
          pos = s: builtins.stringLength (builtins.head (lib.splitString s toml));
        in pos ''[usage.pricing_override."glm-5.3"]'' < pos ''[usage.pricing_override."zhipuai/glm-5.3"]'';
    }
    {
      name = "usage: 含 '/' 键 quoted-key round-trip 不损";
      ok =
        let o = parsed.usage.pricing_override."zhipuai/glm-5.3";
        in o.input == 1.4 && o.output == 4.4 && o.cache_read == 0.26 && o.cache_write == 0.0;
    }
    {
      name = "usage: cacheRead/cacheWrite 省略 → 不生成行 (serde None, 上游回退)";
      ok =
        !(parsed.usage.pricing_override."glm-5.3" ? cache_read)
        && !(parsed.usage.pricing_override."glm-5.3" ? cache_write);
    }
    {
      name = "usage: enable=false + 空覆盖 → [usage] enabled=false 正常渲染 (显式关闭采集)";
      ok =
        let
          t = render (baseArgs // {usage = baseArgs.usage // {enable = false; pricingOverride = {};};});
          p = (builtins.fromTOML t).usage;
        in p.enabled == false && !(p ? pricing_override);
    }
    {
      # "0." 同时匹配 "0.0" (官方 Nix) 与 "0.000000" (Lix 定点表示), 排除裸 int "0";
      # 跨实现锁定 fmtFloat 的 float 形态保证
      name = "usage: 整数值渲染为 float 形态 (cache_write=0 → 0.x)";
      ok = lib.hasInfix "cache_write = 0." toml;
    }
    {
      # 汇率换算形态 (CNY 刊例 ÷ 汇率常量): 双精度除法结果 >6 位有效数字,
      # 序列化必然舍入但属表示属性而非语义改值, 守卫须放行 (混合容差:
      # 绝对项 5e-7 = 定点 6 位小数舍入半宽 / 相对项覆盖有效数字形态,
      # 两种 Nix 实现的舍入差异都远在容差内). 大小两档价格都验 — 小价格
      # (CNY ¥0.1 档 ÷ 6.78 ≈ $0.0147) 是纯相对容差会误拦的值域 (守卫曾因此
      # 过严), 绝对项正是为其引入.
      name = "usage: 长小数价格 (汇率换算形态) 放行 — 表示舍入非语义改值";
      ok =
        renderOk {
          usage = baseArgs.usage // {
            pricingOverride = baseArgs.usage.pricingOverride // {
              "glm-5.3" = {input = 8.0 / 6.78; output = 28.0 / 6.78; cacheRead = 2.0 / 6.78;};
              "glm-5.3-flash" = {input = 0.1 / 6.78; output = 2.8 / 6.78; cacheRead = 0.23 / 6.78;};
            };
          };
        };
    }
    {
      name = "usage=null → 不渲染 [usage] 段 (全默认走 serde default)";
      ok =
        let t = render (baseArgs // {usage = null;});
        in !lib.hasInfix "[usage]" t;
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

    # ── fail-fast: usage ───────────────────────────────────────────────
    {
      name = "fail-fast: pricingOverride 键为空串 → throw";
      ok = overrideFails "" {input = 1.0; output = 2.0;};
    }
    {
      name = "fail-fast: pricingOverride 键带前后空格 → throw (精确匹配下永不生效)";
      ok = overrideFails " glm-5.3" {input = 1.0; output = 2.0;};
    }
    {
      name = "fail-fast: pricingOverride 负 input 价 → throw";
      ok = overrideFails "glm-5.3" {input = -1.4; output = 4.4;};
    }
    {
      name = "fail-fast: pricingOverride 负 output 价 → throw";
      ok = overrideFails "glm-5.3" {input = 1.4; output = -4.4;};
    }
    {
      name = "fail-fast: pricingOverride 负 cacheRead 价 → throw";
      ok = overrideFails "glm-5.3" {input = 1.4; output = 4.4; cacheRead = -0.1;};
    }
    {
      name = "fail-fast: pricingOverride 负 cacheWrite 价 → throw";
      ok = overrideFails "glm-5.3" {input = 1.4; output = 4.4; cacheWrite = -0.01;};
    }
    {
      name = "fail-fast: usage.enable=false 仍配 pricingOverride → throw (死配置)";
      ok = usageFails {enable = false;};
    }
    {
      name = "fail-fast: pricingUrl 空串 → throw";
      ok = usageFails {pricingUrl = "";};
    }
    {
      name = "fail-fast: pricingUrl 非 http(s) → throw (加严对齐 baseUrl 前缀检查)";
      ok = usageFails {pricingUrl = "ftp://models.local/api.json";};
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
