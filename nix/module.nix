# NixOS module: services.secret-guard
#
# 职责: 把 secret-guard 二进制装成 systemd service, 并提供两代配置姿势:
#   1. 结构化选项 (推荐): providers / secrets.entries / auth / usage — 未显式设
#      configFile 时自动经 ./render.nix 生成 secret-guard.toml (eval 期校验内置,
#      字段名与 src serde schema 同步契约见 render.nix 文件头);
#   2. 手写 toml (escape hatch): 显式设 configFile 完全接管, 适配生成器覆盖不了
#      的字段 (redact 段调参等).
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
}: let
  cfg = config.services.secret-guard;

  # auth 段是否被使用 (三项任一非默认). apiKeys/oidc 在 enable=false 时也可配 —
  # 上游"只认证, 不隔离"哲学: key 池无条件加载.
  authUsed = cfg.auth.enable || cfg.auth.oidc != null || cfg.auth.apiKeys != [];

  # usage 段的 serde 默认值 (src/config.rs UsageConfig::default 的 nix 镜像,
  # 改上游默认时同步). 用途: ① 判定 usage 是否被使用 (深比较); ② option default
  # 的单一来源 (字面量只在此声明一次, 三份同步从结构上收敛为两份);
  # ③ render 传参 (全默认 → null → 不渲染段, serde default 兜底).
  usageDefaults = {
    enable = true;
    retentionDays = 90;
    pricingUrl = "https://models.dev/api.json";
    pricingRefreshSecs = 86400;
    pricingOverride = {};
  };

  # usage 段是否被使用 (任一字段偏离默认; 深比较 submodule 合并值与默认结构).
  usageUsed = cfg.usage != usageDefaults;

  # render 的 usage 入参: 全默认 → null (跳过 [usage] 段); 偏离默认 → 全量渲染
  # (显式优于隐式). 与 authArg 对称的具名绑定.
  usageArg =
    if usageUsed
    then cfg.usage
    else null;

  # 结构化选项是否被使用 (任一非默认).
  structuredUsed = cfg.providers != {} || cfg.secrets.entries != [] || authUsed || usageUsed;

  # render 的 auth 入参: auth 全默认时传 null (跳过 [auth] 段), 否则传完整结构
  # (选项 enable → toml enabled 的命名映射在此完成).
  authArg =
    if authUsed
    then {
      enabled = cfg.auth.enable;
      inherit (cfg.auth) oidc apiKeys;
    }
    else null;

  renderedConfig = pkgs.writeText "secret-guard.toml" (import ./render.nix {
    inherit lib;
    inherit (cfg) host port providers;
    secretsEntries = cfg.secrets.entries;
    auth = authArg;
    usage = usageArg;
  });

  # configFile 三态: 显式路径 (手写接管) / 结构化自动 render / 双缺 throw.
  # 显式 + 结构化同设 → throw (互斥): 手写会静默胜出, 几乎肯定是迁移残留.
  resolvedConfigFile =
    if cfg.configFile != null
    then
      lib.throwIf structuredUsed
      "services.secret-guard: configFile 与结构化选项 (providers/secrets.entries/auth/usage) 互斥, 二选一 — 手写 toml 是完全接管, 与自动 render 会静默竞争"
      cfg.configFile
    else if structuredUsed
    then renderedConfig
    else throw "services.secret-guard: 缺配置 — configFile (手写 toml) 与结构化选项 (providers/secrets.entries/auth/usage) 至少设其一";
in {
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

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        指向手写 `secret-guard.toml` (声明式 static 配置) — **escape hatch, 完全接管**.

        与结构化选项 (providers / secrets.entries / auth / usage) 互斥, 同设会在 eval 期
        throw; 两者都不设也 throw. 未设此选项且结构化选项有内容时, 自动经
        ./render.nix 生成 toml (结果暴露在 `services.secret-guard.resolvedConfigFile`).

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

    providers = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
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
            default = [];
            description = "生成 toml 中该 provider 块前的注释行 (来源/用途说明, 随配置声明走 SSOT; 须单行).";
          };
          kind = lib.mkOption {
            type = lib.types.enum ["direct" "router"];
            description = "构造判别: direct=直连上游 (protocol/baseUrl/apiKey*) / router=虚拟路由表 (routes).";
          };
          protocol = lib.mkOption {
            type = lib.types.nullOr (lib.types.enum ["openai" "anthropic" "gemini" "ollama" "openairesponses"]);
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
            type = lib.types.listOf (lib.types.submodule {
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
            });
            default = [];
            description = "kind=router 的路由表 (上游 validate 要求非空).";
          };
        };
      });
      default = {};
      description = "provider 集 (attr 名 = provider id; attrsOf 跨模块/跨文件可合并, 各设各的 key). 渲染按 id 字典序, 字段校验 fail-fast 见 nix/render.nix.";
    };

    secrets = {
      entries = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
          options = {
            id = lib.mkOption {
              type = lib.types.str;
              description = "secret 唯一 id (1..=64, 首字符字母数字, 其余 [A-Za-z0-9_-]).";
            };
            category = lib.mkOption {
              type = lib.types.enum ["password" "apikey" "token" "cookie" "privatekey" "other"];
              default = "apikey";
              description = "类别 (影响 mock 生成策略, 对齐上游 SecretCategory serde lowercase 命名).";
            };
            valueFile = lib.mkOption {
              type = lib.types.path;
              description = "secret 明文文件路径 (与上游 value_file 1:1; 启动时一次性 resolve, 读不到 → fail-fast 启动失败). 保持 toml 脱敏的推荐通道.";
            };
          };
        });
        default = [];
        description = "redact 保护清单 ([[secrets.entries]] 段): 这些 secret 会在 LLM 请求字节流中被扫描并替换为 mock, 防止 agent 泄漏到上游.";
      };
    };

    auth = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "启用账号系统 ([auth] enabled): OIDC 登录 + SDK api key 鉴权. 默认单用户模式 (所有路由无认证). 注意 apiKeys/oidc 在 enable=false 时也可配置 — 上游会无条件加载静态 key 池 (预配后启用即生效).";
      };

      oidc = lib.mkOption {
        type =
          lib.types.nullOr
          (lib.types.submodule {
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
          });
        default = null;
        description = "OIDC 接入参数 (auth.enable=true 时必填, render 层 fail-fast).";
      };

      apiKeys = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
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
        });
        default = [];
        description = "预填 SDK api key 列表 ([[auth.api_keys]] 段, 上游启动时 hash 后注入 key 池).";
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
        type = lib.types.attrsOf (lib.types.submodule {
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
        });
        default = {};
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
    users.groups.secret-guard = lib.mkIf cfg.enable {};

    systemd.services.secret-guard = lib.mkIf cfg.enable {
      description = "secret-guard: lightweight LLM gateway that prevents secret leakage";
      wantedBy = ["multi-user.target"];
      after = ["network.target"];

      serviceConfig = {
        ExecStart = lib.concatStringsSep " " [
          "${cfg.package}/bin/secret-guard"
          "run"
          "--config" "${resolvedConfigFile}"
          "--state" "${cfg.stateFile}"
          "--host" "${cfg.host}"
          "--port" "${toString cfg.port}"
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
        RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = ["@system-service"];
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
      };
    };

    networking.firewall.allowedTCPPorts = lib.mkIf (cfg.enable && cfg.openFirewall) [cfg.port];
  };
}
