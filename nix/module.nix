# NixOS module: services.secret-guard
#
# 把 secret-guard 二进制装成 systemd service. 提供 `services.secret-guard.*` options.
#
# 关键设计:
# - 固定 user/group = "secret-guard" (非 DynamicUser): sops-nix 等外部模块在 eval
#   时需要 resolve owner.group (DynamicUser 在 eval 时无 user 记录).
# - 不负责 secret 解密 (configFile 内容 / sops.secrets 路径由调用方提供, SSOT).
# - secret-guard 支持 `api_key_file` 字段 → toml 可不含敏感数据直接进 nix store;
#   具体 sops/LoadCredential 注入姿势见 AGENTS.md "部署示例".
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
      type = lib.types.path;
      description = ''
        指向 `secret-guard.toml` (声明式 static 配置).

        推荐用 `pkgs.writeText` 生成纯文本 toml (可进 nix store, 调试可直接 `cat`),
        并让 toml 中的 `api_key_file` 字段引用外部 secret 路径
        (sops.secrets 或 systemd LoadCredential 注入).
        这样 toml 本身完全不含敏感数据.

        仅在用历史姿势 `api_key = "sk-..."` 时才需要 sops.templates 渲染整个 toml
        (不推荐, 调试不便且依赖 sops.templates 副作用).
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
  };

  config = lib.mkIf cfg.enable {
    # 固定系统用户 (非 DynamicUser), 让 sops-nix 等外部模块能 resolve owner.group.
    users.users.secret-guard = {
      isSystemUser = true;
      group = "secret-guard";
      home = "/var/lib/secret-guard";
      createHome = false;
    };
    users.groups.secret-guard = {};

    systemd.services.secret-guard = {
      description = "secret-guard: lightweight LLM gateway that prevents secret leakage";
      wantedBy = ["multi-user.target"];
      after = ["network.target"];

      serviceConfig = {
        ExecStart = lib.concatStringsSep " " [
          "${cfg.package}/bin/secret-guard"
          "run"
          "--config" "${cfg.configFile}"
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

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [cfg.port];
  };
}

