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
}: let
  # nixosSystem 脚手架: 主模块 + 额外 modules (hostPlatform 由各 config 自带)
  sgEv = extra: lib.nixosSystem {modules = [secretGuardModule] ++ extra;};

  # 结构化最小 host config: direct + router + secrets + auth + usage 全字段形态.
  minimalConfig = {
    nixpkgs.hostPlatform = system;
    services.secret-guard = {
      enable = true;
      providers = {
        "b-upstream" = {
          name = ''Z "quoted" \\ backslash'';
          kind = "direct";
          protocol = "openai";
          baseUrl = "https://open.example.com/v4";
          apiKeyFile = "/run/secrets/upstream_key";
        };
        "a-router" = {
          kind = "router";
          routes = [
            {modelPattern = "*"; target = "b-upstream"; priority = 100;}
            {modelPattern = "gpt-*"; target = "b-upstream"; upstreamModel = "glm-4.7";}
          ];
        };
      };
      secrets.entries = [
        {id = "llm__k_api_key"; valueFile = "/run/secrets/llm__k_api_key";}
      ];
      auth = {
        enable = true;
        oidc = {
          issuerUrl = "https://idp.example.com/v1/";
          clientId = "test-client";
          clientSecretFile = "/run/secrets/oidc_client_secret";
          redirectUrl = "https://sg.example.com/oauth2/callback";
        };
        apiKeys = [{label = "opencode"; keyFile = "/run/secrets/sdk_api_key";}];
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

  ev = sgEv [minimalConfig];

  # --config 路径在 ExecStart 中 (eval 期断言; 不插值进 build 脚本以免把
  # secret-guard package 拖进 check 的构建闭包)
  execStart = ev.config.systemd.services.secret-guard.serviceConfig.ExecStart;
  execStartOk = lib.hasPrefix "${ev.config.services.secret-guard.package}/bin/secret-guard run --config " execStart;
  generatedConfig = ev.config.services.secret-guard.resolvedConfigFile;

  # 内联 key 合成组合 (独立 host config): 验证非文件凭据形态 (apiKey 直值) 的
  # provider 组合同样走 render 链路 — direct + 默认路由 router
  inlineEv = sgEv [{
    nixpkgs.hostPlatform = system;
    services.secret-guard = {
      enable = true;
      providers = {
        "b-upstream" = {
          name = "Upstream B";
          kind = "direct";
          protocol = "openai";
          baseUrl = "https://up.example.com/v1";
          apiKey = "test-inline-key";
        };
        "a-router" = {
          kind = "router";
          routes = [{modelPattern = "*"; target = "b-upstream"; priority = 100;}];
        };
      };
    };
  }];
  inlineConfig = inlineEv.config.services.secret-guard.resolvedConfigFile;

  # eval 失败/成功断言 (强制点: ExecStart 会连带强制 resolvedConfigFile 的三态解析)
  fails = e: !(builtins.tryEval e).success;
  unitOf = e: e.config.systemd.services.secret-guard.serviceConfig.ExecStart;

  mutualExclusionFails = fails (unitOf (sgEv [{
    nixpkgs.hostPlatform = system;
    services.secret-guard = {
      enable = true;
      configFile = "/etc/secret-guard.toml";
      providers."x".kind = "direct";
      providers."x".protocol = "openai";
      providers."x".baseUrl = "https://x";
    };
  }]));

  missingConfigFails =
    fails (unitOf (sgEv [{
      nixpkgs.hostPlatform = system;
      services.secret-guard.enable = true;
    }]));

  # 手写 configFile (escape hatch): 原样透传 (resolvedConfigFile = 用户路径, 非 store render)
  handWritten = sgEv [{
    nixpkgs.hostPlatform = system;
    services.secret-guard = {
      enable = true;
      configFile = pkgs.writeText "hand-written.toml" ''
        [[providers]]
        id = "hand"
        kind = "direct"
        protocol = "openai"
        base_url = "https://hand.example.com"
        enabled = true
      '';
    };
  }];
  handWrittenOk = handWritten.config.services.secret-guard.resolvedConfigFile == handWritten.config.services.secret-guard.configFile;

  assertions = [
    {name = "ExecStart 接线: --config <resolvedConfigFile>"; ok = execStartOk;}
    {name = "configFile 互斥: 显式 + 结构化同设 → eval throw"; ok = mutualExclusionFails;}
    {name = "双缺: 无 configFile 无结构化 → eval throw"; ok = missingConfigFails;}
    {name = "手写 configFile (escape hatch) 原样透传"; ok = handWrittenOk;}
  ];
  failed = builtins.filter (a: !a.ok) assertions;

  testRunner = pkgs.runCommand "secret-guard-module-eval-tests" {
    nativeBuildInputs = [pkgs.python3];
  } ''
    ${lib.concatMapStrings (a: ''
        echo "[sg-module-eval] ${a.name}: ${if a.ok then "PASS" else "FAIL"}" >&2
      '')
      assertions}

    ${if failed == []
      then ''
        echo "[sg-module-eval] 全部 ${toString (builtins.length assertions)} 项 eval 断言通过" >&2
      ''
      else ''
        echo "[sg-module-eval] ${toString (builtins.length failed)} 项断言失败, 详情见上" >&2
        exit 1
      ''}

    # 生成物 round-trip (build 期 tomllib): minimal 全字段 + 内联 key 合成组合形态
    python3 ${./assert-toml.py} minimal ${generatedConfig}
    python3 ${./assert-toml.py} inline ${inlineConfig}

    grep -q "Auto-generated by services.secret-guard structured options" ${generatedConfig} \
      || { echo "[sg-module-eval] 头部注释缺失" >&2; exit 1; }

    touch $out
  '';
in {
  inherit testRunner assertions;
}
