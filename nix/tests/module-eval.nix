# 职责: nix/module.nix 的 eval 冒烟测试 (flake check 经 checks.module-eval 接入)
#
# 覆盖 (render 纯函数本身的契约在 nix/tests/render.nix, 这里只测模块接线):
#   - 最小 host config 设结构化选项 → configFile 自动 render 生成 (resolvedConfigFile
#     只读选项暴露), 生成物经 python tomllib round-trip + 全字段断言
#     (nix/tests/assert-toml.py, build 期执行 — eval 期无法 readFile 未构建 store path)
#   - systemd unit 接线: ExecStart 含 --config <生成路径>
#   - configFile 互斥: 显式 configFile + 结构化同设 → eval throw
#   - 双缺: 无 configFile 无结构化 → eval throw (历史必填语义的兜底)
#   - 手写 configFile (escape hatch): 显式设置时原样透传, 不触发 render
#   - 内联 key 组合: 独立 host config 的合成 provider 组合 (非文件凭据形态)
{
  lib,
  pkgs,
  system,
  secretGuardModule,
}:
let
  # nixosSystem 脚手架: 主模块 + 额外 modules (hostPlatform 由各 config 自带)
  sgEv = extra: lib.nixosSystem { modules = [ secretGuardModule ] ++ extra; };

  # 最小 direct provider fixture (单 openai 端点): 五处 host config 的被测对象
  # 都在 endpoints 之外 (互斥/超时/停机窗口/旧选项删除), endpoints 纯属让
  # config 合法的样板 — 单点声明, schema 再演进只改这里. (双端点 fixture 是
  # assert-toml 的被测对象, 保持 minimalConfig 内显式 inline.)
  directFixture = url: {
    kind = "direct";
    endpoints = [
      {
        protocol = "openai";
        baseUrl = url;
      }
    ];
  };

  # 结构化最小 host config: direct + router + secrets + auth + usage 全字段形态.
  minimalConfig = {
    nixpkgs.hostPlatform = system;
    services.secret-guard = {
      enable = true;
      providers = {
        "b-upstream" = {
          name = ''Z "quoted" \\ backslash'';
          kind = "direct";
          # 双端点 (multi-endpoint): commonUri 一有一无 — e2e 覆盖 省略 (None)
          # 与 显式 "" (版本前缀已含) 两种形态 (assert-toml 断言)
          endpoints = [
            {
              protocol = "openai";
              baseUrl = "https://open.example.com/v4";
            }
            {
              protocol = "anthropic";
              baseUrl = "https://open.example.com/anthropic";
              commonUri = "";
            }
          ];
          apiKeyFile = "/run/secrets/upstream_key";
        };
        "a-router" = {
          kind = "router";
          routes = [
            {
              modelPattern = "*";
              target = "b-upstream";
              priority = 100;
            }
            {
              modelPattern = "gpt-*";
              target = "b-upstream";
              upstreamModel = "glm-4.7";
            }
          ];
        };
      };
      secrets.entries = [
        {
          id = "llm__k_api_key";
          valueFile = "/run/secrets/llm__k_api_key";
        }
      ];
      # SEC-4 + cookie 旋钮的 e2e 镜像链 (assert-toml 断言渲染形态)
      redact.redactedHeaders = [ "x-my-service-key" ];
      auth = {
        enable = true;
        secureCookie = true;
        oidc = {
          issuerUrl = "https://idp.example.com/v1/";
          clientId = "test-client";
          clientSecretFile = "/run/secrets/oidc_client_secret";
          redirectUrl = "https://sg.example.com/oauth2/callback";
        };
        apiKeys = [
          {
            label = "opencode";
            keyFile = "/run/secrets/sdk_api_key";
          }
        ];
      };
      usage = {
        # retentionDays 故意不设 — 锁定默认值 90 的 e2e 镜像链 (assert-toml 断言);
        # 显式值 30 的 round-trip 由 nix/tests/render.nix 单测覆盖
        pricingOverride = {
          "glm-5.3" = {
            input = 1.4;
            output = 4.4;
            cacheRead = 0.26;
            cacheWrite = 0.0;
          };
        };
      };
    };
  };

  ev = sgEv [ minimalConfig ];

  # --config 路径在 ExecStart 中 (eval 期断言; 不插值进 build 脚本以免把
  # secret-guard package 拖进 check 的构建闭包)
  execStart = ev.config.systemd.services.secret-guard.serviceConfig.ExecStart;
  execStartOk = lib.hasPrefix "${ev.config.services.secret-guard.package}/bin/secret-guard run --config " execStart;
  generatedConfig = ev.config.services.secret-guard.resolvedConfigFile;

  # 内联 key 合成组合 (独立 host config): 验证非文件凭据形态 (apiKey 直值) 的
  # provider 组合同样走 render 链路 — direct + 默认路由 router
  inlineEv = sgEv [
    {
      nixpkgs.hostPlatform = system;
      services.secret-guard = {
        enable = true;
        providers = {
          "b-upstream" = directFixture "https://up.example.com/v1" // {
            name = "Upstream B";
            apiKey = "test-inline-key";
          };
          "a-router" = {
            kind = "router";
            routes = [
              {
                modelPattern = "*";
                target = "b-upstream";
                priority = 100;
              }
            ];
          };
        };
      };
    }
  ];
  inlineConfig = inlineEv.config.services.secret-guard.resolvedConfigFile;

  # 超时调参形态 (独立 host config): 验证 upstreamTimeouts 选项 → [server] 超时行
  # 的模块接线. 场景取拆墙形态 (agent-service#130: 非流式整响应 300 → 0), 只显式设
  # nonstream 一项 — 锁定 "任一偏离默认 → 四行全量渲染 (未设字段带 option
  # default)" 的 e2e 镜像链 (assert-toml 断言).
  timeoutsEv = sgEv [
    {
      nixpkgs.hostPlatform = system;
      services.secret-guard = {
        enable = true;
        providers."b-upstream" = directFixture "https://up.example.com/v1" // {
          apiKeyFile = "/run/secrets/upstream_key";
        };
        upstreamTimeouts.nonstreamResponseHeaderTimeoutSecs = 0;
      };
    }
  ];
  timeoutsConfig = timeoutsEv.config.services.secret-guard.resolvedConfigFile;

  # 停机窗口契约 (#242): 部署侧显式覆写 TimeoutStopSec 须胜出模块 mkDefault —
  # 若模块侧被误改为 plain (同优先级) 或 mkForce, 本 host config 会 eval 冲突/
  # 覆写失效, 断言即红 (默认值 15s 的接线由下方最小 config 断言锁定).
  stopTimeoutOverrideEv = sgEv [
    {
      nixpkgs.hostPlatform = system;
      services.secret-guard = {
        enable = true;
        providers."b-upstream" = directFixture "https://up.example.com/v4" // {
          apiKeyFile = "/run/secrets/upstream_key";
        };
      };
      systemd.services.secret-guard.serviceConfig.TimeoutStopSec = "60s";
    }
  ];
  stopTimeoutOverrideOk =
    stopTimeoutOverrideEv.config.systemd.services.secret-guard.serviceConfig.TimeoutStopSec == "60s";

  # eval 失败/成功断言 (强制点: ExecStart 会连带强制 resolvedConfigFile 的三态解析)
  fails = e: !(builtins.tryEval e).success;
  unitOf = e: e.config.systemd.services.secret-guard.serviceConfig.ExecStart;

  mutualExclusionFails = fails (
    unitOf (sgEv [
      {
        nixpkgs.hostPlatform = system;
        services.secret-guard = {
          enable = true;
          configFile = "/etc/secret-guard.toml";
          providers."x" = directFixture "https://x";
        };
      }
    ])
  );

  missingConfigFails = fails (
    unitOf (sgEv [
      {
        nixpkgs.hostPlatform = system;
        services.secret-guard.enable = true;
      }
    ])
  );

  # 互斥守卫涵盖 upstreamTimeouts (不计入 structuredUsed 但属迁移残留形态):
  # 手写 configFile 下超时设置会无声丢失, 必须与 providers 等同拦.
  # 注意不带 providers — structuredUsed 保持 false, 使 throw 只能源于
  # timeoutsUsed (带 providers 会让本断言退化为既有 mutualExclusionFails
  # 的重复, 对 "|| timeoutsUsed" 的回退零防护).
  timeoutsMutualExclusionFails = fails (
    unitOf (sgEv [
      {
        nixpkgs.hostPlatform = system;
        services.secret-guard = {
          enable = true;
          configFile = "/etc/secret-guard.toml";
          upstreamTimeouts.streamIdleTimeoutSecs = 1;
        };
      }
    ])
  );

  # redact (redactedHeaders) 同型: 不计入 structuredUsed 但手写 configFile 下
  # 脱敏名单会无声丢失 — 不带 providers 使 throw 只能源于 redactUsed.
  redactMutualExclusionFails = fails (
    unitOf (sgEv [
      {
        nixpkgs.hostPlatform = system;
        services.secret-guard = {
          enable = true;
          configFile = "/etc/secret-guard.toml";
          redact.redactedHeaders = [ "x-my-service-key" ];
        };
      }
    ])
  );

  # 手写 configFile (escape hatch): 原样透传 (resolvedConfigFile = 用户路径, 非 store render)
  handWritten = sgEv [
    {
      nixpkgs.hostPlatform = system;
      services.secret-guard = {
        enable = true;
        configFile = pkgs.writeText "hand-written.toml" ''
          [[providers]]
          id = "hand"
          kind = "direct"
          enabled = true

          [[providers.endpoints]]
          protocol = "openai"
          base_url = "https://hand.example.com"
        '';
      };
    }
  ];
  handWrittenOk =
    handWritten.config.services.secret-guard.resolvedConfigFile
    == handWritten.config.services.secret-guard.configFile;

  # D1 直接切 (无兼容): 旧单端点原子选项 protocol/baseUrl 已删除 — 残留配置
  # eval 期即报 "option 不存在", 而非静默渲染旧 schema 被 upstream validate 拒绝
  # (T4 收口的 "假绿" 形态). commonUri 同属旧 provider 级字段清单.
  legacyOptionFails = fails (
    unitOf (sgEv [
      {
        nixpkgs.hostPlatform = system;
        services.secret-guard = {
          enable = true;
          providers."x" = directFixture "https://x" // {
            protocol = "openai";
          };
        };
      }
    ])
  );

  assertions = [
    {
      name = "ExecStart 接线: --config <resolvedConfigFile>";
      ok = execStartOk;
    }
    {
      name = "停机窗口契约: 默认 TimeoutStopSec = 15s (#242)";
      ok = ev.config.systemd.services.secret-guard.serviceConfig.TimeoutStopSec == "15s";
    }
    {
      name = "停机窗口契约: 部署侧覆写 TimeoutStopSec 胜出 mkDefault (#242)";
      ok = stopTimeoutOverrideOk;
    }
    {
      name = "configFile 互斥: 显式 + 结构化同设 → eval throw";
      ok = mutualExclusionFails;
    }
    {
      name = "configFile 互斥: 显式 + upstreamTimeouts 偏离 → eval throw (防设置无声丢失)";
      ok = timeoutsMutualExclusionFails;
    }
    {
      name = "configFile 互斥: 显式 + redact.redactedHeaders → eval throw (防脱敏名单无声丢失)";
      ok = redactMutualExclusionFails;
    }
    {
      name = "双缺: 无 configFile 无结构化 → eval throw";
      ok = missingConfigFails;
    }
    {
      name = "手写 configFile (escape hatch) 原样透传";
      ok = handWrittenOk;
    }
    {
      name = "D1 直接切: 旧原子选项 protocol 已删除 → 残留配置 eval throw";
      ok = legacyOptionFails;
    }
  ];
  failed = builtins.filter (a: !a.ok) assertions;

  testRunner =
    pkgs.runCommand "secret-guard-module-eval-tests"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        ${lib.concatMapStrings (a: ''
          echo "[sg-module-eval] ${a.name}: ${if a.ok then "PASS" else "FAIL"}" >&2
        '') assertions}

        ${
          if failed == [ ] then
            ''
              echo "[sg-module-eval] 全部 ${toString (builtins.length assertions)} 项 eval 断言通过" >&2
            ''
          else
            ''
              echo "[sg-module-eval] ${toString (builtins.length failed)} 项断言失败, 详情见上" >&2
              exit 1
            ''
        }

        # 生成物 round-trip (build 期 tomllib): minimal 全字段 + 内联 key 合成组合形态
        # + 超时调参形态
        python3 ${./assert-toml.py} minimal ${generatedConfig}
        python3 ${./assert-toml.py} inline ${inlineConfig}
        python3 ${./assert-toml.py} timeouts ${timeoutsConfig}

        grep -q "Auto-generated by services.secret-guard structured options" ${generatedConfig} \
          || { echo "[sg-module-eval] 头部注释缺失" >&2; exit 1; }

        touch $out
      '';
in
{
  inherit testRunner assertions;
}
