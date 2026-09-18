# NixOS module: services.secret-guard
#
# 职责: 把 secret-guard 二进制装成 systemd service, 并提供两代配置姿势:
#   1. 结构化选项 (推荐): providers / secrets.entries / redact / auth / usage /
#      upstreamTimeouts / allowedDomains — 未显式设 configFile 时自动经 ./render.nix 生成
#      secret-guard.toml (eval 期校验内置, 字段名与 src serde schema 同步
#      契约见 render.nix 文件头);
#   2. 手写 toml (escape hatch): 显式设 configFile 完全接管, 适配生成器覆盖不了
#      的字段 ([redact] 三降级开关 / global_mock_prefix 等调参).
#   两代互斥 (同设 throw), 双缺也 throw (保留历史必填语义的兜底).
#
# 关键设计:
# - 固定 user/group = "secret-guard" (非 DynamicUser): sops-nix 等外部模块在 eval
#   时需要 resolve owner.group (DynamicUser 在 eval 时无 user 记录).
# - 不负责 secret 解密: 结构化选项的 *File 字段 (apiKeyFile/valueFile/
#   clientSecretFile/keyFile) 是纯路径直通 (与上游 toml *_file 字段 1:1), sops /
#   systemd LoadCredential 注入姿势由部署侧决定 (见 docs/deployment-nixos.md).
# - resolvedConfigFile 只读选项暴露实际传给 --config 的路径 (用户 configFile 或
#   自动 render 产物), 供调试 (cat 生成的 toml) 与测试消费.
#
# 加固: NoNewPrivileges + ProtectSystem=strict 等 (参考 systemd.exec(5) hardening).
# ProtectSystem=strict 不影响读 /run/credentials/ (LoadCredential 标准注入路径)
# 也不影响 StateDirectory = "secret-guard" (mode 0750).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.secret-guard;

  # auth 段是否被使用 (四项任一非默认). apiKeys/oidc 在 enable=false 时也可配 —
  # 上游"只认证, 不隔离"哲学: key 池无条件加载. secureCookie 同理可先行配置
  # (仅影响 OIDC session cookie, enable=false 时无行为但配置合法).
  authUsed =
    cfg.auth.enable || cfg.auth.oidc != null || cfg.auth.apiKeys != [ ] || cfg.auth.secureCookie;

  # [redact] 段是否被使用 (redactedHeaders 非空). 不参与 structuredUsed: 单设
  # header 名单而无 provider/secrets/auth/usage 仍是"缺配置" — 名单只是脱敏调参,
  # 不构成网关有内容可跑的配置存在性 (与 upstreamTimeouts 同理).
  redactUsed = cfg.redact.redactedHeaders != [ ];

  # usage 段的 serde 默认值 (src/config.rs UsageConfig::default 的 nix 镜像,
  # 改上游默认时同步). 用途: ① 判定 usage 是否被使用 (深比较); ② option default
  # 的单一来源 (字面量只在此声明一次, 三份同步从结构上收敛为两份);
  # ③ render 传参 (全默认 → null → 不渲染段, serde default 兜底).
  usageDefaults = {
    enable = true;
    retentionDays = 90;
    pricingUrl = "https://models.dev/api.json";
    pricingRefreshSecs = 86400;
    pricingOverride = { };
  };

  # usage 段是否被使用 (任一字段偏离默认; 深比较 submodule 合并值与默认结构).
  usageUsed = cfg.usage != usageDefaults;

  # render 的 usage 入参: 全默认 → null (跳过 [usage] 段); 偏离默认 → 全量渲染
  # (显式优于隐式). 与 authArg 对称的具名绑定.
  usageArg = if usageUsed then cfg.usage else null;

  # 上游超时段的 serde 默认值 (src/config.rs ServerConfig::default 的 nix 镜像,
  # 改上游默认时同步 — 与 usageDefaults 同模式). 用途: ① option default 的单一
  # 来源; ② 判定超时是否被使用 (深比较); ③ render 传参 (全默认 → null → 不渲染
  # 超时行, serde default 兜底).
  upstreamTimeoutsDefaults = {
    connectTimeoutSecs = 15;
    responseHeaderTimeoutSecs = 60;
    nonstreamResponseHeaderTimeoutSecs = 300;
    streamIdleTimeoutSecs = 120;
  };

  # 超时段是否被使用 (任一字段偏离默认). 不参与 structuredUsed: 单设超时而无
  # provider/secrets/auth/usage 仍是"缺配置" (throw) — 超时只是 server 段调参,
  # 不构成网关有内容可跑的配置存在性.
  timeoutsUsed = cfg.upstreamTimeouts != upstreamTimeoutsDefaults;

  # render 的超时入参: 全默认 → null (跳过超时行); 偏离默认 → 全量渲染四行
  # (显式优于隐式, 与 usageArg 对称).
  timeoutsArg = if timeoutsUsed then cfg.upstreamTimeouts else null;

  # 结构化选项是否被使用 (任一非默认).
  structuredUsed = cfg.providers != { } || cfg.secrets.entries != [ ] || authUsed || usageUsed;

  # render 的 auth 入参: auth 全默认时传 null (跳过 [auth] 段), 否则传完整结构
  # (选项 enable → toml enabled 的命名映射在此完成).
  authArg =
    if authUsed then
      {
        enabled = cfg.auth.enable;
        inherit (cfg.auth) oidc apiKeys;
        secureCookie = cfg.auth.secureCookie;
      }
    else
      null;

  renderedConfig = pkgs.writeText "secret-guard.toml" (
    import ./render.nix {
      inherit lib;
      inherit (cfg)
        host
        port
        providers
        allowedDomains
        ;
      upstreamTimeouts = timeoutsArg;
      secretsEntries = cfg.secrets.entries;
      redactedHeaders = cfg.redact.redactedHeaders;
      auth = authArg;
      usage = usageArg;
    }
  );

  # configFile 三态: 显式路径 (手写接管) / 结构化自动 render / 双缺 throw.
  # 显式 + 结构化同设 → throw (互斥): 手写会静默胜出, 几乎肯定是迁移残留.
  # 互斥守卫涵盖 upstreamTimeouts (虽不计入 structuredUsed): 手写 configFile
  # 下超时设置会无声丢失, 与 "显式 + usage 偏离" 同属迁移残留形态. redact
  # (redactedHeaders) 同理 — 手写接管下脱敏名单会无声丢失.
  resolvedConfigFile =
    if cfg.configFile != null then
      lib.throwIf (structuredUsed || timeoutsUsed || redactUsed || cfg.allowedDomains != [ ])
        "services.secret-guard: configFile 与结构化选项 (providers/secrets.entries/redact/auth/usage/upstreamTimeouts/allowedDomains) 互斥, 二选一 — 手写 toml 是完全接管, 与自动 render 会静默竞争"
        cfg.configFile
    else if structuredUsed then
      renderedConfig
    else
      throw "services.secret-guard: 缺配置 — configFile (手写 toml) 与结构化选项 (providers/secrets.entries/auth/usage) 至少设其一";
in
{
  options.services.secret-guard = {
    enable = lib.mkEnableOption "secret-guard: lightweight LLM gateway that prevents secret leakage";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.secret-guard;
      defaultText = lib.literalExpression "pkgs.secret-guard";
      description = ''
        secret-guard 二进制 package. 默认取 nixpkgs overlay 暴露的 `pkgs.secret-guard`
        (该 overlay 由本 flake 的 `nixosModules.default` 自动注入).
        若要在非本 flake 的环境中使用, 可手动通过 flake 的 packages output 引用.
      '';
    };

    host = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        监听地址. 默认仅本机可见, 因为 secret-guard 通常作为本地 LLM SDK 的代理.
        若要让局域网内其他主机访问, 设为 "0.0.0.0" 并同时 openFirewall = true.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 18787;
      description = "监听端口.";
    };

    allowedDomains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        SEC-7 Host guard 信任域名 ([server] allowed_domains), 反代 + 域名部署形态:
        经反向代理以域名 (如 sg.example.com) 暴露 secret-guard 时, 反代保留原始
        Host (proxy_set_header Host $host) 并在此声明该域名, 域名 Host/Origin 即放行
        (端口宽松). 未声明的域名形式 Host 一律 403 (防 DNS rebinding — 攻击者的
        域名进不了这份用户手写的名单). 条目归一化: trim + 小写; 含 : 的形态
        (host:port / 裸 IPv6) / IP 字面量 / localhost / 空串条目无意义, 启动时
        WARN 跳过. 空 (默认) = 拒绝所有域名.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        指向手写 `secret-guard.toml` (声明式 static 配置) — **escape hatch, 完全接管**.

        与结构化选项 (providers / secrets.entries / redact / auth / usage /
        upstreamTimeouts / allowedDomains) 互斥, 同设会在 eval 期 throw; 两者都
        不设也 throw. 未设此选项且结构化选项有内容时,
        自动经 ./render.nix 生成 toml (结果暴露在 `services.secret-guard.resolvedConfigFile`).

        手写场景推荐 `pkgs.writeText` 生成纯文本 toml (可进 nix store, 调试可直接
        `cat`), 并让 toml 中的 `api_key_file` / `value_file` 字段引用外部 secret 路径
        (sops.secrets 或 systemd LoadCredential 注入), 保持 toml 本身不含敏感数据.

        仅在用历史姿势 `api_key = "sk-..."` 时才需要 sops.templates 渲染整个 toml
        (不推荐, 调试不便且依赖 sops.templates 副作用).
      '';
    };

    resolvedConfigFile = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      description = ''
        实际传给 `--config` 的路径 (只读): 用户显式设置的 configFile, 或结构化选项
        自动 render 的产物. 调试时可直接 `cat` 查看生成的 toml; 测试消费见
        nix/tests/module-eval.nix.
      '';
    };

    stateFile = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/secret-guard/state.toml";
      description = ''
        指向 `secret-guard.state.toml` (dynamic 状态, 由 WebUI 写回).
        默认放在 systemd StateDirectory 下, 跨重启保留.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "是否在防火墙开放端口 (仅 host != 127.0.0.1 时有意义).";
    };

    # 上游超时四项: 合理取值随部署网络环境差异大 (本地 ollama vs 公网高延迟
    # 上游), 故整体可配置. 类型对齐上游 u64 (ints.unsigned, 0 合法 = 无限).
    # 量纲与分档语义的完整论证见 src/config.rs ServerConfig 字段注释
    # (流式 TTFT 档 vs 非流式整响应档, #175).
    upstreamTimeouts = {
      connectTimeoutSecs = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = upstreamTimeoutsDefaults.connectTimeoutSecs;
        description = ''
          上游 DNS+TCP+TLS 握手超时秒 ([server] upstream_connect_timeout_secs).
          正常 < 3s; 异常 (上游不可达/网络黑洞) 时该超时让 secret-guard 快速失败
          而非永久挂死. 0 = 无限 (reqwest 默认行为, 不建议).
        '';
      };

      responseHeaderTimeoutSecs = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = upstreamTimeoutsDefaults.responseHeaderTimeoutSecs;
        description = ''
          流式请求 (显式 stream=true) 的响应头到达超时秒 ([server]
          upstream_response_header_timeout_secs), TTFT 量纲 — 响应头在首 token
          生成后即返回, 长思考发生在 body 流不受此限. 0 = 无限 (向后兼容,
          不建议 — 上游 hang 时该超时是唯一的活性检测).
        '';
      };

      nonstreamResponseHeaderTimeoutSecs = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = upstreamTimeoutsDefaults.nonstreamResponseHeaderTimeoutSecs;
        description = ''
          非流式请求的响应头到达超时秒 ([server]
          upstream_nonstream_response_header_timeout_secs), 整响应量纲 — 非流式
          响应头要等整个响应生成完才返回, 该值实际是单次生成时长上限.

          默认 300 覆盖 74k token 上下文的整响应生成 (#175). 注意: 非流式请求
          在生成完成前零字节流动, 网关侧无法区分"慢生成"与"hang 死", 任何墙钟
          都会误杀超过它的合法慢生成 (agent-service#130: 思考模型大首轮 >300s
          被掐断 → 消费方重试风暴). 若所有消费方都有自身超时预算兜底 (客户端
          断连会取消上游请求), 可设 0 (无限) 拆墙 — 让"慢"的判定权归消费方/上游.
        '';
      };

      streamIdleTimeoutSecs = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = upstreamTimeoutsDefaults.streamIdleTimeoutSecs;
        description = ''
          流式响应相邻 chunk 空闲超时秒 ([server] upstream_stream_idle_timeout_secs).
          正常 chunk 间隔 < 1s; reasoning model 思考静默可能较长 (通常有心跳
          chunk). 超过视为上游 hang. 0 = 无限.
        '';
      };
    };

    providers = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            name = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "可选人类可读名称 (WebUI 显示).";
            };
            enable = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "是否启用 (映射 toml enabled; false 时转发到该 provider 返回 503).";
            };
            tomlComment = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "生成 toml 中该 provider 块前的注释行 (来源/用途说明, 随配置声明走 SSOT; 须单行).";
            };
            kind = lib.mkOption {
              type = lib.types.enum [
                "direct"
                "router"
                "pool"
              ];
              description = "构造判别: direct=直连上游 (protocol/baseUrl/apiKey*) / router=虚拟路由表 (routes) / pool=套餐池 (members, 窗口限额耗尽自动 failover).";
            };
            protocol = lib.mkOption {
              type = lib.types.nullOr (
                lib.types.enum [
                  "openai"
                  "anthropic"
                  "gemini"
                  "ollama"
                  "openairesponses"
                ]
              );
              default = null;
              description = "kind=direct 必填: 上游协议 (决定 egress protocol, 跨协议请求自动走 codec 翻译).";
            };
            baseUrl = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "kind=direct 必填: 上游 base URL, 须 http(s):// 开头且末尾不带 /.";
            };
            apiKey = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "内联 api key 直值 — 仅用于非敏感场景 (toml 会明文携带该值); 敏感凭据一律走 apiKeyFile. 与 apiKeyFile 互斥 (render 层同设即 throw, 与上游 validate 的互斥语义对齐).";
            };
            apiKeyFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = "api key 文件路径 (与上游 api_key_file 字段 1:1 纯路径直通, 每次转发时读取并 trim). 敏感凭据推荐走此通道: sops.secrets 路径或 systemd LoadCredential 注入路径 (姿势见 docs/deployment-nixos.md), 保持 toml 本身脱敏.";
            };
            routes = lib.mkOption {
              type = lib.types.listOf (
                lib.types.submodule {
                  options = {
                    modelPattern = lib.mkOption {
                      type = lib.types.str;
                      description = "model 名通配符 (仅 '*' 是元字符, 其余字面匹配).";
                    };
                    target = lib.mkOption {
                      type = lib.types.str;
                      description = "目标 provider id (可链式指向另一 router; render 层校验存在性 + 环检测).";
                    };
                    upstreamModel = lib.mkOption {
                      type = lib.types.nullOr lib.types.str;
                      default = null;
                      description = "出站 model 重写值; null = 透传请求原 model.";
                    };
                    priority = lib.mkOption {
                      type = lib.types.nullOr lib.types.int;
                      default = null;
                      description = "优先级 (越大越优先, 并列按列表序); null = 该路由禁用 (省略 priority 行).";
                    };
                  };
                }
              );
              default = [ ];
              description = "kind=router 的路由表 (上游 validate 要求非空).";
            };
            members = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "kind=pool 的成员列表 (Direct provider id, 每成员 = 一份独立套餐凭证). 顺序 failover: 列表序即优先级, 正常全打第一个可用成员. render 层校验存在性 + 环检测 (上游 validate 拒绝空表/自环).";
            };
            exhaust = lib.mkOption {
              type = lib.types.nullOr (
                lib.types.submodule {
                  options = {
                    statuses = lib.mkOption {
                      # nullOr + default null: null = 不渲染该行 (上游字段级
                      # default 兜底), [] = 显式关闭 — nix 的 default = [] 无法
                      # 区分 "没配" 与 "配空", 会静默吞掉内置默认表 (M1 修复).
                      type = lib.types.nullOr (lib.types.listOf (lib.types.ints.between 0 65535));
                      default = null;
                      description = "status 触发线: 上游 HTTP status ∈ 此列表 → 耗尽. null = 省略行 (上游字段级默认 = 关闭); [] = 显式关闭通道 (与 null 等效但渲染为空数组); 非 null = 替换.";
                    };
                    codes = lib.mkOption {
                      type = lib.types.nullOr (lib.types.listOf lib.types.str);
                      default = null;
                      description = "body 码触发线 (error.code/error.type/error.status/顶层 code 四位置的字符串码). null = 省略行 (上游字段级默认 = 内置智谱窗口限额表 [\"1308\",\"1310\"]); [] = 显式关闭通道; 非 null = 替换 (想删默认表某个码 = 重抄剩余码).";
                    };
                    headers = lib.mkOption {
                      type = lib.types.nullOr (lib.types.listOf lib.types.str);
                      default = null;
                      description = "header 触发线 \"name=value\" 精确匹配 (name 大小写不敏感). null = 省略行 (上游字段级默认 = 内置 Claude 订阅 unified 两项); [] = 显式关闭通道; 非 null = 替换.";
                    };
                  };
                }
              );
              default = null;
              description = "kind=pool 的耗尽信号配置 (三通道 OR). null = 省略整段 = 上游内置窗口限额默认表; 非 null 时按字段渲染 — 字段 null 省略行 (保留上游该通道默认), 字段 [] 显式关闭, 字段非空替换.";
            };
            cooldownSecs = lib.mkOption {
              type = lib.types.nullOr lib.types.ints.unsigned;
              default = null;
              description = "kind=pool 的兜底闹钟时长 (秒): 信号命中但解析不出精确恢复时刻时成员挂起 now+cooldown. null = 省略 = 上游默认 60.";
            };
          };
        }
      );
      default = { };
      description = "provider 集 (attr 名 = provider id; attrsOf 跨模块/跨文件可合并, 各设各的 key). 渲染按 id 字典序, 字段校验 fail-fast 见 nix/render.nix.";
    };

    secrets = {
      entries = lib.mkOption {
        type = lib.types.listOf (
          lib.types.submodule {
            options = {
              id = lib.mkOption {
                type = lib.types.str;
                description = "secret 唯一 id (1..=64, 首字符字母数字, 其余 [A-Za-z0-9_-]).";
              };
              category = lib.mkOption {
                type = lib.types.enum [
                  "password"
                  "apikey"
                  "token"
                  "cookie"
                  "privatekey"
                  "other"
                ];
                default = "apikey";
                description = "类别 (影响 mock 生成策略, 对齐上游 SecretCategory serde lowercase 命名).";
              };
              valueFile = lib.mkOption {
                type = lib.types.path;
                description = "secret 明文文件路径 (与上游 value_file 1:1; 启动时一次性 resolve, 读不到 → fail-fast 启动失败). 保持 toml 脱敏的推荐通道.";
              };
            };
          }
        );
        default = [ ];
        description = "redact 保护清单 ([[secrets.entries]] 段): 这些 secret 会在 LLM 请求字节流中被扫描并替换为 mock, 防止 agent 泄漏到上游.";
      };
    };

    redact = {
      redactedHeaders = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = ''
          自定义敏感 header 名单 ([redact] redacted_headers, SEC-4): 追加进 WebUI
          record 脱敏名单的 header 名, 与硬编码黑名单并集. 上游启动时对条目
          trim + lowercase 归一化后按名**精确匹配** (非子串: 配 x-my-key 不波及
          x-my-key-v2), 仅影响 record 脱敏不影响转发字节. 空 (默认) = 仅硬编码
          黑名单, 行为不变. 空白条目在 eval 期 fail-fast (笔误).
        '';
      };
    };

    auth = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "启用账号系统 ([auth] enabled): OIDC 登录 + SDK api key 鉴权. 默认单用户模式 (所有路由无认证). 注意 apiKeys/oidc 在 enable=false 时也可配置 — 上游会无条件加载静态 key 池 (预配后启用即生效).";
      };

      oidc = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.submodule {
            options = {
              issuerUrl = lib.mkOption {
                type = lib.types.str;
                description = "IdP issuer URL, 必须与 IdP metadata 的 issuer 逐字一致 (含/不含尾斜杠是不同值).";
              };
              clientId = lib.mkOption {
                type = lib.types.str;
                description = "OAuth2 client id.";
              };
              clientSecretFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "client secret 文件路径 (与上游 client_secret_file 1:1). public client (PKCE 无 secret) 可省略.";
              };
              redirectUrl = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "回调 URL, 必须与 IdP 侧注册值逐字节一致 (IdP 严格校验); 须以 /oauth2/callback 结尾 (只能换 scheme/host/port). 省略 = 由监听 host/port 派生.";
              };
            };
          }
        );
        default = null;
        description = "OIDC 接入参数 (auth.enable=true 时必填, render 层 fail-fast).";
      };

      apiKeys = lib.mkOption {
        type = lib.types.listOf (
          lib.types.submodule {
            options = {
              label = lib.mkOption {
                type = lib.types.str;
                description = "api key 展示标签 (如消费方名 opencode), 不得重复留空.";
              };
              key = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "内联 api key 直值. 与 keyFile 恰设其一 (render 层 fail-fast).";
              };
              keyFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "api key 文件路径 (与上游 key_file 1:1). 与 key 恰设其一.";
              };
            };
          }
        );
        default = [ ];
        description = "预填 SDK api key 列表 ([[auth.api_keys]] 段, 上游启动时 hash 后注入 key 池).";
      };

      secureCookie = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          session cookie 是否带 Secure flag ([auth] secure_cookie). 默认 false —
          本地 HTTP 开发必须 false (true 时浏览器不回传 cookie, OIDC 无法登录).
          经反向代理以 HTTPS 暴露 secret-guard 时应设 true (见
          docs/deployment-nixos.md "HTTPS 反向代理" 段). 仅 true 时渲染进 toml
          (false 是上游 serde default).
        '';
      };
    };

    usage = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = usageDefaults.enable;
        description = ''
          模型用量统计总开关 ([usage] enabled). false = 不采集不落盘 (record
          路径零开销). 全 usage 段保持默认时整段不渲染 (serde default 兜底).
        '';
      };

      retentionDays = lib.mkOption {
        type = lib.types.ints.u32;
        default = usageDefaults.retentionDays;
        description = "用量明细保留天数 ([usage] retention_days). 0 = 永久保留; 启动时按 ts 清理. 类型对齐上游 u32.";
      };

      pricingUrl = lib.mkOption {
        type = lib.types.str;
        default = usageDefaults.pricingUrl;
        description = "定价数据源 URL ([usage] pricing_url, models.dev api.json 格式; 可指向自托管镜像).";
      };

      pricingRefreshSecs = lib.mkOption {
        type = lib.types.ints.positive;
        default = usageDefaults.pricingRefreshSecs;
        description = "定价表刷新间隔秒 ([usage] pricing_refresh_secs; 故意加严: 类型拒 0, 上游 u64 接受但 0 会让每次查询都触发刷新打爆上游). 表过期后首个 usage 查询触发刷新.";
      };

      pricingOverride = lib.mkOption {
        type = lib.types.attrsOf (
          lib.types.submodule {
            options = {
              input = lib.mkOption {
                type = lib.types.float;
                description = "输入价 ($/1M tokens).";
              };
              output = lib.mkOption {
                type = lib.types.float;
                description = "输出价 ($/1M tokens).";
              };
              cacheRead = lib.mkOption {
                type = lib.types.nullOr lib.types.float;
                default = null;
                description = "缓存读价 ($/1M tokens). null = 省略字段, 上游回退按 input 价.";
              };
              cacheWrite = lib.mkOption {
                type = lib.types.nullOr lib.types.float;
                default = null;
                description = "缓存写价 ($/1M tokens). null = 省略字段, 上游回退按 1.25×input (Anthropic 惯例近似); 供应商缓存写免费时应显式设 0.0 (注意 types.float 不收整数字面量).";
              };
            };
          }
        );
        default = { };
        description = ''
          用户定价覆盖 ([usage.pricing_override], 键 = 聚合用 model 字符串).
          最高优先于 models.dev 远程表 — 典型场景: 套餐/包年入口在 models.dev
          登记为零价 (或域名消歧命中零价 vendor), 按官方 API 刊例价覆盖以真实
          反映消耗. 聚合 model 串取上游回显 model (计费模型), fallback 请求 model.
        '';
      };
    };
  };

  config = {
    services.secret-guard.resolvedConfigFile = resolvedConfigFile;

    users.users.secret-guard = lib.mkIf cfg.enable {
      isSystemUser = true;
      group = "secret-guard";
      home = "/var/lib/secret-guard";
      createHome = false;
    };
    users.groups.secret-guard = lib.mkIf cfg.enable { };

    systemd.services.secret-guard = lib.mkIf cfg.enable {
      description = "secret-guard: lightweight LLM gateway that prevents secret leakage";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = lib.concatStringsSep " " [
          "${cfg.package}/bin/secret-guard"
          "run"
          "--config"
          "${resolvedConfigFile}"
          "--state"
          "${cfg.stateFile}"
          "--host"
          "${cfg.host}"
          "--port"
          "${toString cfg.port}"
        ];
        Type = "simple";
        Restart = "on-failure";
        RestartSec = "5s";

        User = "secret-guard";
        Group = "secret-guard";

        # state.toml 持久化 (默认路径 /var/lib/secret-guard/state.toml)
        StateDirectory = "secret-guard";
        StateDirectoryMode = "0750";

        # 加固 (参考 systemd.exec(5) hardening defaults, 仅保留 secret-guard 需要的能力).
        # 注意: ProtectSystem=strict 不影响读 /run/credentials/ (systemd LoadCredential 的标准注入路径),
        # 也不影响 StateDirectory = "secret-guard" (自动以 user 拥有, mode 0750).
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
      };
    };

    networking.firewall.allowedTCPPorts = lib.mkIf (cfg.enable && cfg.openFirewall) [ cfg.port ];
  };
}
