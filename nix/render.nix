# 职责: secret-guard 结构化选项 → toml 的纯渲染函数 (SSOT)
#
# 输入为结构化 attrset (nix/module.nix 的 providers / secrets.entries / auth /
# usage / upstreamTimeouts 选项形态), 输出为 secret-guard.toml 字符串. 字段序/注释/排序规则只在此处
# 声明一次, 消费侧 (module.nix 自动 render + 本文件契约测试) 只传结构化数据 —
# 新增 provider 只需设选项, 消灭"手抄 toml 模板 + mkForce 覆盖"模式.
#
# ── 与 src serde schema 的同步契约 (schema 变更时本文件同步改, 测试锁定) ──
# 生成的 toml 字段名/嵌套必须与上游 serde 定义逐字段吻合 (选项 camelCase →
# toml snake_case 的映射单源于本文件):
#   - Provider (src/provider.rs, kind internally tagged): id / enabled / name?
#     + direct: endpoints[] (protocol / base_url / common_uri? — 多协议端点,
#       每协议至多一条, 数组序 = fallback 序) + api_key? / api_key_file?
#       (凭证 provider 级共享, 所有端点共用)
#     + router: routes[] (model_pattern / target / upstream_model? / priority?,
#       省略 = 透传 / 该路由禁用)
#     + pool: members[] (Direct provider id) / cooldown_secs? (省略 = 60) /
#       [providers.exhaust] (字段级三态: 字段 null = 省略行 = 上游 serde
#       字段级 default (内置表/关闭); 字段 [] = 显式关闭该通道; 非空 = 替换.
#       省略整段 = 上游内置窗口限额默认表)
#   - SecretEntry (src/secrets.rs): id / category / value_file (本函数只渲染脱敏
#     形态 value_file, 不支持内联 value)
#   - AuthConfig (src/auth/mod.rs): enabled + oidc{issuer_url / client_id /
#     client_secret_file? / redirect_url?} + api_keys[]{label / key? / key_file?}
#     + secure_cookie (secureCookie, 仅 true 渲染 — false 是 serde default)
#   - RedactConfig (src/config.rs): redacted_headers (redactedHeaders, 非空才
#     渲染 [redact] 段; 条目空白 fail-fast — 上游 trim+lowercase 归一化后
#     精确匹配, 与硬编码黑名单并集, SEC-4)
#   - UsageConfig (src/config.rs): enabled / retention_days / pricing_url /
#     pricing_refresh_secs / pricing_override{model → input / output /
#     cache_read? / cache_write?} (cache 两维省略 = serde None → 上游回退
#     input / 1.25×input)
#   - ServerConfig (src/config.rs): host / port (恒渲染, 实际由 ExecStart 参数
#     覆盖) + 上游超时四项 upstreamTimeouts{connectTimeoutSecs /
#     responseHeaderTimeoutSecs / nonstreamResponseHeaderTimeoutSecs /
#     streamIdleTimeoutSecs} → snake_case *_secs (null = 全默认 → 不渲染,
#     serde default 兜底; 非 null = 全量渲染四行; 0 = 无限) +
#     allowedDomains → allowed_domains (空 = 不渲染 = 拒绝所有域名 Host,
#     SEC-7; 非空 = 渲染字符串数组, 排序保确定性)
#
# eval 期校验单点收敛 (历史原型散在 render 与 checkToml 两处, 此处合一):
#   - 语法: 生成物 fromTOML round-trip, 非法 TOML 在 eval 期即 throw
#   - sum type fail-fast: direct 空/缺 endpoints、endpoints 内 protocol 重复、
#     endpoint baseUrl/common_uri 卫生、旧单端点字段残留 (protocol/baseUrl/
#     commonUri — multi-endpoint D1 直接切无兼容, 残留即指路 endpoints)、
#     分支专属字段串用、kind 非法、router 空 routes、pool 空 members、
#     apiKey/apiKeyFile 互斥、tomlComment 多行
#   - base_url 卫生: 非空 + http(s):// 前缀 + 末尾不带 / (对齐上游 validate_base_url,
#     per-endpoint)
#   - id 卫生: provider id / secrets entry id / route target / pool member
#     符合上游 validate_id (1..=64, 首字符字母数字, 其余 [A-Za-z0-9_-])
#   - auth fail-fast: enabled 但无 oidc、apiKeys 的 key/keyFile 恰一、redirect_url
#     形状 (对齐上游 AuthConfig::validate)
#   - 跨 provider: route target / pool member 存在性 (声明式静态配置中所有 id
#     已知, 悬空即配置错误, 比上游 WebUI upsert 语义更严) + 启用边环检测
#     (对齐上游 would_cycle — 路由的禁用边不算; pool members 全算)
#
# 与 nixos 侧原型的语义差异: apiKeyFile / clientSecretFile / keyFile / valueFile
# 均为纯路径直通 (与上游 *_file 字段 1:1), 不做任何 sops-key → LoadCredential
# 路径派生 — 凭据注入姿势由部署侧决定 (见 docs/deployment-nixos.md).
{
  lib,
  host,
  port,
  # attrsOf provider, attr 名 = provider id:
  #   { <id> = { name ? str; enable ? bool; tomlComment ? [str];
  #              kind == "direct": endpoints = [{ protocol, baseUrl,
  #                                              commonUri ? str|null }],
  #                              apiKey ? "", apiKeyFile ? path
  #            | kind == "router": routes = [{ modelPattern, target,
  #                                           upstreamModel ?, priority ? }]
  #            | kind == "pool": members = [str],
  #                              exhaust ? { statuses = [int]; codes = [str];
  #                                           headers = [str]; } | null,
  #                              cooldownSecs ? int | null } }
  providers,
  # [server] 上游超时四项: null = 全默认 → 不渲染 (serde default 兜底); 否则
  # { connectTimeoutSecs, responseHeaderTimeoutSecs,
  #    nonstreamResponseHeaderTimeoutSecs, streamIdleTimeoutSecs } 全量渲染
  # (见上方 schema 注释; 0 = 无限)
  upstreamTimeouts ? null,
  # [server] allowed_domains (SEC-7 域名白名单): [] = 不渲染 (serde default
  # 空 = 拒绝所有域名 Host); 非空 = 渲染为 toml 字符串数组 (反代 + 域名部署形态)
  allowedDomains ? [ ],
  # redact 段 ([[secrets.entries]]): [{ id, category ? "apikey", valueFile }]
  secretsEntries ? [ ],
  # [redact] redacted_headers (SEC-4 自定义敏感 header 名单): [] = 不渲染段
  # (serde default 空); 非空 = 渲染 [redact] 段, 按字典序保确定性 (上游匹配是
  # 集合语义, 顺序无关; 空白条目 fail-fast)
  redactedHeaders ? [ ],
  # null = 跳过 [usage] 段; 否则 { enable, retentionDays, pricingUrl,
  # pricingRefreshSecs, pricingOverride ? {} } (见上方 schema)
  usage ? null,
  # null = 跳过 [auth] 段; 否则 { enabled, oidc ? null, apiKeys ? [] } (见上方 schema)
  auth ? null,
}:
let
  # JSON 字符串字面量是合法 TOML basic string (转义规则子集), 统一走它防注入.
  q = lib.strings.toJSON;

  # 浮点渲染为带小数点的 TOML float 形态. 不同 Nix 实现 float 序列化形态不同
  # (Lix 定点 6 位小数 "1.400000" / 官方 Nix 最短 round-trip 表示, 整数值 float
  # 可能无小数点 "0"), fmtFloat 兜底补 ".0" 保 float 形态防未来严格 parser.
  # round-trip 守卫拦"语义改值"(归零/数量级跳变), 放行"表示舍入"(如汇率换算
  # 的长小数 8.0/6.78 = 1.179941…) — 混合容差两种序列化形态都完备覆盖:
  #   - 绝对项 5.0e-7 = 定点 6 位小数的舍入半宽 (与量级无关), 覆盖 Lix 形态;
  #   - 相对项 1.0e-5 × 对称 max 分母, 覆盖假想的"6 位有效数字"形态 (大数时
  #     绝对项不够).
  # 归零拦截的有效值域随之为 |v| > 5.0e-7 — 现实 LLM 价格 ≥ ~1e-3 ($0.015/M
  # cache 档), 量级余量充足; 对齐本层 fail-fast 立场而不误伤换算形态.
  fmtFloat =
    v:
    let
      s = toString v;
      floted = if lib.hasInfix "." s then s else "${s}.0";
      rt = (builtins.fromTOML "v = ${floted}").v;
      # 注 1: Nix float 字面量必须带小数点 (1e-5 非法), 故写 5.0e-7 / 1.0e-5;
      # 注 2: abs 不用 builtins.abs (部分实现缺失), 内联分支式; 0 - x 是 Nix 的
      # 一元负写法 (-x 非法).
      abs = x: if x < 0 then 0 - x else x;
      diff = abs (rt - v);
      drifted = rt != v && !(diff <= 5.0e-7 || diff <= 1.0e-5 * lib.max (abs rt) (abs v));
    in
    lib.throwIf drifted
      "secret-guard render: 浮点 '${s}' 经 TOML 序列化后语义改值 (${toString rt}), 价格数量级超出 TOML 文本表示能力"
      floted;

  # 上游 validate_id 的 Nix 镜像: 1..=64, 首字符字母数字, 其余 [A-Za-z0-9_-].
  # 长度按字节计 (builtins.stringLength), 上游按 chars().count() — ASCII 场景等价,
  # 多字节 model 名会被偏严拦截 (实际模型名均为 ASCII).
  validId = id: builtins.match "[A-Za-z0-9][A-Za-z0-9_-]{0,63}" id != null;

  # 上游 validate_base_url 的 Nix 镜像: 非空 + http(s):// + 末尾不带 /.
  baseUrlOk =
    url:
    url != ""
    && (lib.hasPrefix "http://" url || lib.hasPrefix "https://" url)
    && !lib.hasSuffix "/" url;

  # *File 字段统一绝对路径校验: 上游三种 *_file 的相对路径解析语义各异
  # (api_key_file/value_file 按进程 CWD 原样读, auth key_file 按 config 目录 join),
  # 自动 render 产物在 /nix/store 下, 相对路径的解析基不可控 → eval 期统一拦截
  # (手写 configFile 不经本函数, 语义不受影响).
  absFile =
    ctx: v:
    if !lib.hasPrefix "/" (toString v) then
      throw "secret-guard render: ${ctx} 须为绝对路径 (以 / 开头): '${toString v}'"
    else
      toString v;

  # 重复元素检测 (O(n²), 配置规模下无碍): 返回出现 >1 次的元素.
  dups = xs: lib.filter (x: lib.count (y: y == x) xs > 1) (lib.unique xs);

  # 公共头: 可选块前注释行 + 表头 + id + 可选 name + kind 判别行注释.
  # tomlComment 必须单行 (多行注释会注入合法 toml 行静默改变语义, 且注释不走
  # toJSON 转义 — 本函数唯一的原文插值点). LF/CR 都拦 (CR 不是合法 TOML 注释字符).
  providerHead =
    id: p:
    lib.concatStringsSep "\n" (
      map (
        c:
        lib.throwIf (
          lib.hasInfix "\n" c || lib.hasInfix "\r" c
        ) "secret-guard render: provider '${id}' 的 tomlComment 须为单行" "# ${c}"
      ) (p.tomlComment or [ ])
      ++ [
        "[[providers]]"
        "id = ${q id}"
      ]
      ++ lib.optional ((p.name or null) != null) "name = ${q p.name}"
      ++ [ "# kind: provider 构造判别 (direct=直连上游 / router=虚拟路由 / pool=套餐池), sum type 必填." ]
    );

  # toml 数组渲染: 字符串数组 (JSON 转义) / 整数数组 (toString).
  qStrList = xs: "[${lib.concatMapStringsSep ", " q xs}]";
  intList = xs: "[${lib.concatMapStringsSep ", " toString xs}]";

  # 单条路由: 省略 upstream_model / priority 行 = 上游 serde 的 None
  # (透传请求原 model / 该路由禁用).
  renderRoute =
    id: r:
    if r.modelPattern == "" || builtins.stringLength r.modelPattern > 64 then
      throw "secret-guard render: provider '${id}' 的 route modelPattern 须为 1..=64 字符"
    else if
      (r.upstreamModel or null) != null
      && (lib.trim r.upstreamModel == "" || builtins.stringLength r.upstreamModel > 128)
    then
      throw "secret-guard render: provider '${id}' 的 route upstreamModel 须为非空非空白且 ≤128 字符 (清空语义 = 省略字段)"
    else if !validId r.target then
      throw "secret-guard render: provider '${id}' 的 route target '${r.target}' id 非法 (须 1..=64, 首字符字母数字, 其余 [A-Za-z0-9_-])"
    else
      lib.concatStringsSep "\n" (
        [
          "[[providers.routes]]"
          "model_pattern = ${q r.modelPattern}"
          "target = ${q r.target}"
        ]
        ++ lib.optional ((r.upstreamModel or null) != null) "upstream_model = ${q r.upstreamModel}"
        ++ lib.optional ((r.priority or null) != null) "priority = ${toString r.priority}"
      );

  # 上游 Endpoint validate 的 common_uri 值域 Nix 镜像: "" (版本前缀已含) 或
  # 以 / 开头的合法 path 片段 — 无尾 /、无 ?/#/空格、≤64 字符 (长度按字节计,
  # 同 validId 的 ASCII 等价注记).
  commonUriOk =
    cu:
    cu == ""
    || (
      lib.hasPrefix "/" cu
      && !lib.hasSuffix "/" cu
      && !lib.hasInfix "?" cu
      && !lib.hasInfix "#" cu
      && !lib.hasInfix " " cu
      && builtins.stringLength cu <= 64
    );

  # 旧单端点 schema (provider 级 protocol+baseUrl 原子字段) 的迁移残留检测:
  # multi-endpoint schema 直接切换无兼容 (设计裁决 D1), 出现旧字段即指路
  # endpoints[]. module 侧选项已删除 (eval 期即拦 "option不存在"), 此处兜底
  # 绕过 module 直接调用 render 的手写 attrset (契约测试路径).
  legacyDirectFields =
    p:
    lib.filter (f: (p.${f} or null) != null) [
      "protocol"
      "baseUrl"
      "commonUri"
    ];

  # 单个端点 (multi-endpoint): common_uri 行省略 = 上游 serde None (未探测,
  # fetch 侧候选序列现场推导); 显式 "" = 版本前缀已含布局 (与 None 语义不同,
  # 必须渲染成空串行). 段序: endpoints 段块跟在 provider 键值块之后 (与
  # routes 同型 — TOML 数组-of-tables 必须后置, 否则键会被吸进子表).
  renderEndpoint =
    id: e:
    if !baseUrlOk e.baseUrl then
      throw "secret-guard render: direct provider '${id}' 的 endpoint (${e.protocol}) baseUrl 非法: '${e.baseUrl}' (须 http(s):// 开头且末尾不带 /)"
    else if (e.commonUri or null) != null && !commonUriOk e.commonUri then
      throw "secret-guard render: direct provider '${id}' 的 endpoint (${e.protocol}) commonUri 非法: '${e.commonUri}' (须空串 (版本前缀已含) 或 / 开头的 path 片段, 无尾 /、?、#、空格, ≤64 字符)"
    else
      lib.concatStringsSep "\n" (
        [
          "[[providers.endpoints]]"
          "protocol = ${q e.protocol}"
          "base_url = ${q e.baseUrl}"
        ]
        ++ lib.optional ((e.commonUri or null) != null) "common_uri = ${q e.commonUri}"
      );

  renderProvider =
    id: p:
    # 旧单端点字段残留守卫先于 kind dispatch (kind 无关, 单点): 迁移残留的用户
    # 最先看到指路信息, 而非 "routes 为空" 之类的次生错误.
    let
      legacy = legacyDirectFields p;
    in
    if legacy != [ ] then
      throw "secret-guard render: provider '${id}' 仍在用旧单端点字段 ${toString legacy} — multi-endpoint schema 已切换 (D1 直接切, 无兼容), 请改写为 endpoints = [ { protocol; baseUrl; commonUri ? null; } ]"
    else if p.kind == "direct" then
      let
        eps = p.endpoints or [ ];
        # 每协议至多一条 (上游 validate 拒绝重复; 报重复的 protocol 名便于定位)
        dupProtos = dups (map (e: e.protocol) eps);
      in
      if eps == [ ] then
        throw "secret-guard render: direct provider '${id}' 缺 endpoints (kind=direct 必填, 至少一条端点; 上游 validate 拒绝空端点表)"
      else if dupProtos != [ ] then
        throw "secret-guard render: direct provider '${id}' 的 endpoints 内 protocol 重复: ${toString dupProtos} (每协议至多一条, 上游 validate 拒绝)"
      else if (p.routes or [ ]) != [ ] then
        throw "secret-guard render: direct provider '${id}' 不该有 routes (router 分支专属字段; kind 改写后遗留的 stray 字段会被上游静默忽略, 此处 fail-fast)"
      else if (p.apiKeyFile or null) != null && (p.apiKey or "") != "" then
        throw "secret-guard render: direct provider '${id}' 不该同时设 apiKeyFile/apiKey (互斥, 上游 validate 拒绝同设)"
      else
        # provider 键值块 (id/kind/凭证/enabled) 在前, endpoints 段块在后 —
        # TOML 数组-of-tables 后置 (与 routes 同型), 否则裸键会被吸进端点子表.
        lib.concatStringsSep "\n\n" (
          [
            (lib.concatStringsSep "\n" (
              [ (providerHead id p) ]
              ++ [ "kind = \"direct\"" ]
              ++ (
                if (p.apiKeyFile or null) != null then
                  [
                    "# api_key 从文件读取: 每次转发时 read+trim (容忍换行), 读不到 → 空 key + warn."
                    "api_key_file = ${q (absFile "direct provider '${id}' 的 apiKeyFile" p.apiKeyFile)}"
                  ]
                else
                  lib.optional ((p.apiKey or "") != "") "api_key = ${q p.apiKey}"
              )
              ++ [ "enabled = ${lib.boolToString (p.enable or true)}" ]
            ))
          ]
          ++ map (renderEndpoint id) eps
        )
    else if p.kind == "router" then
      if (p.routes or [ ]) == [ ] then
        throw "secret-guard render: router provider '${id}' routes 为空 (上游 validate 拒绝空路由表)"
      else if (p.endpoints or [ ]) != [ ] || (p.apiKeyFile or null) != null || (p.apiKey or "") != "" then
        throw "secret-guard render: router provider '${id}' 不该有 endpoints/apiKey/apiKeyFile (direct 分支专属字段, 上游 sum type 下不存在)"
      else
        lib.concatStringsSep "\n\n" (
          [
            (lib.concatStringsSep "\n" (
              [ (providerHead id p) ]
              ++ [
                "kind = \"router\""
                "enabled = ${lib.boolToString (p.enable or true)}"
              ]
            ))
          ]
          ++ map (renderRoute id) p.routes
        )
    else if p.kind == "pool" then
      let
        badMembers = lib.filter (m: !validId m) (p.members or [ ]);
        # [providers.exhaust] 段: 传入时渲染. 字段级三态 (module 侧 nullOr 的
        # 语义收敛): null = 不渲染该行 (上游 serde 字段级 default = 内置表/
        # 关闭), [] = 渲染空数组 (显式关闭该通道 — 与 null 的区别是**显式**),
        # 非空列表 = 替换. nix 的 default 无法区分 "没配" 与 "配空", 故用
        # nullOr 把决策权交给配置者.
        exhaustField = render-line: xs: lib.optional (xs != null) (render-line xs);
        exhaustLines = lib.optionals ((p.exhaust or null) != null) (
          [
            ""
            "[providers.exhaust]"
          ]
          ++ exhaustField (xs: "statuses = ${intList xs}") p.exhaust.statuses
          ++ exhaustField (xs: "codes = ${qStrList xs}") p.exhaust.codes
          ++ exhaustField (xs: "headers = ${qStrList xs}") p.exhaust.headers
        );
      in
      if (p.members or [ ]) == [ ] then
        throw "secret-guard render: pool provider '${id}' members 为空 (上游 validate 拒绝空成员表)"
      else if badMembers != [ ] then
        throw "secret-guard render: pool provider '${id}' 的 member id 非法 (须 1..=64, 首字符字母数字, 其余 [A-Za-z0-9_-]): ${toString badMembers}"
      else if
        (p.endpoints or [ ]) != [ ]
        || (p.apiKeyFile or null) != null
        || (p.apiKey or "") != ""
        || (p.routes or [ ]) != [ ]
      then
        throw "secret-guard render: pool provider '${id}' 不该有 endpoints/apiKey/apiKeyFile/routes (其他分支专属字段, 上游 sum type 下不存在)"
      else
        # cooldown_secs 行必须在 [providers.exhaust] 段头之前 (TOML 表段后的
        # 键归属该子表); 省略 = 上游 serde default 60.
        lib.concatStringsSep "\n" (
          [ (providerHead id p) ]
          ++ [
            "kind = \"pool\""
            "members = ${qStrList p.members}"
          ]
          ++ lib.optional ((p.cooldownSecs or null) != null) "cooldown_secs = ${toString p.cooldownSecs}"
          ++ [ "enabled = ${lib.boolToString (p.enable or true)}" ]
          ++ exhaustLines
        )
    else
      throw "secret-guard render: provider '${id}' kind 非法: ${toString p.kind}";

  renderApiKey =
    k:
    # key/keyFile 恰设其一 (对齐上游 StaticApiKey::resolve 的互斥与必设).
    if ((k.key or null) != null) == ((k.keyFile or null) != null) then
      throw "secret-guard render: auth.apiKeys '${k.label}' 须恰设 key/keyFile 之一 (同设/全无均被上游启动拒绝)"
    else if lib.trim k.label == "" then
      throw "secret-guard render: auth.apiKeys label 不得为空"
    else
      lib.concatStringsSep "\n" (
        [
          "[[auth.api_keys]]"
          "label = ${q k.label}"
        ]
        ++ lib.optional ((k.key or null) != null) "key = ${q k.key}"
        ++ lib.optional (
          (k.keyFile or null) != null
        ) "key_file = ${q (absFile "auth.apiKeys '${k.label}' 的 keyFile" k.keyFile)}"
      );

  renderOidc =
    o:
    let
      ru = o.redirectUrl or null;
      # 对齐上游 AuthConfig::validate: http(s):// 前缀 + /oauth2/callback 结尾.
      # 故意加严: 上游仅在 auth.enabled 时校验 issuer/client_id/redirect_url, 本函数
      # 对 oidc != null 一律校验 — 声明式配置里配了 oidc 就该配完整, 半截配置
      # 几乎肯定是迁移残留 (enabled=false 的占位值也应显式写全).
      redirectOk =
        ru == null
        || (
          lib.trim ru != ""
          && (lib.hasPrefix "http://" ru || lib.hasPrefix "https://" ru)
          && lib.hasSuffix "/oauth2/callback" ru
        );
    in
    if lib.trim o.issuerUrl == "" || lib.trim o.clientId == "" then
      throw "secret-guard render: auth.oidc 的 issuerUrl/clientId 不得为空"
    else if !redirectOk then
      throw "secret-guard render: auth.oidc 的 redirectUrl 形状非法: '${toString ru}' (须 http(s)://… 且以 /oauth2/callback 结尾, 只能换 scheme/host/port)"
    else
      lib.concatStringsSep "\n" (
        [
          "[auth.oidc]"
          "# issuer 必须与 IdP metadata 的 issuer 字段逐字一致 (含/不含尾斜杠是不同值)."
          "issuer_url = ${q o.issuerUrl}"
          "client_id = ${q o.clientId}"
        ]
        ++ lib.optional (
          (o.clientSecretFile or null) != null
        ) "client_secret_file = ${q (absFile "auth.oidc 的 clientSecretFile" o.clientSecretFile)}"
        ++ lib.optionals (ru != null) [
          "# 必须与 IdP 侧注册的 redirect URI 逐字节一致 (IdP 严格校验); 省略 = 由监听 host/port 派生."
          "redirect_url = ${q ru}"
        ]
      );

  renderAuth =
    a:
    let
      # 重复 label 检查 (对齐上游 AuthConfig::validate — 该校验无条件执行, 与
      # enabled 无关; 重复 label 会让 sg 启动即失败, 必须拦在 eval 期).
      dupLabels = dups (map (k: k.label) (a.apiKeys or [ ]));
    in
    if a.enabled && (a.oidc or null) == null then
      throw "secret-guard render: auth 启用但 auth.oidc 未配置 (上游 validate 拒绝 enabled 无 oidc)"
    else if dupLabels != [ ] then
      throw "secret-guard render: auth.apiKeys label 重复 (上游启动即拒绝): ${toString dupLabels}"
    else
      lib.concatStringsSep "\n\n" (
        [
          (lib.concatStringsSep "\n" (
            [
              "[auth]"
              "enabled = ${lib.boolToString a.enabled}"
            ]
            # secure_cookie 仅 true 渲染 (false 是 serde default; HTTPS 反代部署
            # 用, 本地 HTTP dev 必须保持 false — 浏览器不回传带 Secure 的 cookie)
            ++ lib.optional (a.secureCookie or false) "secure_cookie = true"
          ))
        ]
        ++ lib.optional ((a.oidc or null) != null) (renderOidc a.oidc)
        ++ map renderApiKey (a.apiKeys or [ ])
      );

  renderSecretEntry =
    e:
    if !validId e.id then
      throw "secret-guard render: secrets.entries 的 id '${e.id}' 非法 (须 1..=64, 首字符字母数字, 其余 [A-Za-z0-9_-])"
    else if (e.valueFile or null) == null then
      throw "secret-guard render: secrets.entries '${e.id}' 缺 valueFile (本渲染器只支持脱敏形态 value_file, 不支持内联 value)"
    else
      lib.concatStringsSep "\n" [
        "[[secrets.entries]]"
        "id = ${q e.id}"
        "category = ${q (e.category or "apikey")}"
        "value_file = ${q (absFile "secrets.entries '${e.id}' 的 valueFile" e.valueFile)}"
      ];

  # 单模型定价覆盖: 键是聚合用 model 字符串 (上游无字符集约束, 仅要求非空且
  # 无前后空格 — 键是精确匹配, 带空白的覆盖静默永不生效; 含 '.'/'/' 等特殊字符
  # 的键经 q 转义为 TOML quoted key). 价格非负性在此 fail-fast (上游 f64 接受
  # 负值但语义荒谬, 声明式配置中负价几乎肯定是笔误).
  renderPricingOverride =
    model: o:
    if lib.trim model == "" then
      throw "secret-guard render: usage.pricingOverride 键 (model 字符串) 不得为空或纯空白"
    else if model != lib.trim model then
      throw "secret-guard render: usage.pricingOverride 键 '${model}' 带前后空格 (精确匹配下覆盖永不生效, 几乎肯定是笔误)"
    else if
      lib.any (v: v != null && v < 0) [
        o.input
        o.output
        (o.cacheRead or null)
        (o.cacheWrite or null)
      ]
    then
      throw "secret-guard render: usage.pricingOverride '${model}' 价格不得为负"
    else
      lib.concatStringsSep "\n" (
        [
          "[usage.pricing_override.${q model}]"
          "input = ${fmtFloat o.input}"
          "output = ${fmtFloat o.output}"
        ]
        ++ lib.optional ((o.cacheRead or null) != null) "cache_read = ${fmtFloat o.cacheRead}"
        ++ lib.optional ((o.cacheWrite or null) != null) "cache_write = ${fmtFloat o.cacheWrite}"
      );

  renderUsage =
    u:
    let
      # 字典序渲染 (确定性, 对齐 providers id 字典序先例)
      overrideModels = lib.sort (a: b: a < b) (builtins.attrNames (u.pricingOverride or { }));
    in
    # pricingUrl 加严对齐 baseUrl 的 http(s) 前缀检查 (上游无校验, 但非 http(s)
    # URL 会让每次定价刷新静默失败 → offline, eval 期拦截指向配置笔误)
    if lib.trim u.pricingUrl == "" then
      throw "secret-guard render: usage.pricingUrl 不得为空 (定价数据源 URL)"
    else if !lib.hasPrefix "http://" u.pricingUrl && !lib.hasPrefix "https://" u.pricingUrl then
      throw "secret-guard render: usage.pricingUrl 非法: '${u.pricingUrl}' (须 http(s):// 开头)"
    else if !u.enable && overrideModels != [ ] then
      throw "secret-guard render: usage.enable=false 时不应配置 pricingOverride (统计禁用, 覆盖永不生效的死配置)"
    else
      lib.concatStringsSep "\n\n" (
        [
          (lib.concatStringsSep "\n" [
            "[usage]"
            "enabled = ${lib.boolToString u.enable}"
            "retention_days = ${toString u.retentionDays}"
            "pricing_url = ${q u.pricingUrl}"
            "pricing_refresh_secs = ${toString u.pricingRefreshSecs}"
          ])
        ]
        ++ map (m: renderPricingOverride m u.pricingOverride.${m}) overrideModels
      );

  header = lib.concatStringsSep "\n" [
    "# Auto-generated by services.secret-guard structured options"
    "# DO NOT EDIT — 改 toml 内容请编辑 services.secret-guard.* 结构化选项 (或改用 configFile 手写接管)."
  ];

  secretsSection = lib.concatStringsSep "\n" (
    [
      "# ── redact secrets: 防泄漏清单 (services.secret-guard.secrets.entries) ──"
      "# 这些 secret 会被 redact_ir 在 LLM 请求字节流中扫描并替换为 mock,"
      "# 防止 agent 不经意把它们写入 prompt 泄漏到上游 LLM provider."
      "# secret-guard 启动时一次性 resolve (fail-fast: 文件读不到 → 启动失败)."
    ]
    ++ map renderSecretEntry secretsEntries
  );

  # [redact] redacted_headers (SEC-4): 非空才渲染 (空 = serde default 兜底 =
  # 仅硬编码黑名单). 空白条目 fail-fast — 上游 trim 后为空的条目只会 WARN 跳过,
  # 声明式配置中它几乎肯定是笔误, eval 期拦截比运行期 WARN 更早暴露.
  # 字典序渲染保确定性 (上游匹配是集合语义, 顺序无影响; 重复条目无害 —
  # 并集匹配下无数据损失, 与 secrets id first-wins 不同性质, 故不拦).
  blankHeaders = lib.filter (h: lib.trim h == "") redactedHeaders;

  redactSection = lib.concatStringsSep "\n" ([
    "[redact]"
    "# 自定义敏感 header 名单 (services.secret-guard.redact.redactedHeaders, SEC-4):"
    "# 启动时 trim+lowercase 归一化后按名精确匹配, 与硬编码黑名单并集, 仅影响"
    "# WebUI record 脱敏, 不影响转发字节."
    "redacted_headers = [${lib.concatMapStringsSep ", " q (lib.sort (a: b: a < b) redactedHeaders)}]"
  ]);

  # [server] 恒写 host/port (实际由 ExecStart --host/--port 参数覆盖, 此处仅作
  # fallback/调试参考); 超时四项仅在 upstreamTimeouts 非 null (任一字段偏离
  # serde 默认, module 层深比较判定) 时全量渲染, records_capacity 仍由上游
  # serde default 兜底 (与 host/port 一样是无需暴露的部署细节).
  # 量纲: connect=握手 / response_header=流式 TTFT / nonstream_response_header=
  # 非流式整响应 (单次生成时长上限) / stream_idle=chunk 空闲; 0 = 无限.
  timeoutLines = lib.optionals (upstreamTimeouts != null) [
    "# 上游超时 (services.secret-guard.upstreamTimeouts, 偏离默认时全量渲染): 0 = 无限."
    "upstream_connect_timeout_secs = ${toString upstreamTimeouts.connectTimeoutSecs}"
    "upstream_response_header_timeout_secs = ${toString upstreamTimeouts.responseHeaderTimeoutSecs}"
    "upstream_nonstream_response_header_timeout_secs = ${toString upstreamTimeouts.nonstreamResponseHeaderTimeoutSecs}"
    "upstream_stream_idle_timeout_secs = ${toString upstreamTimeouts.streamIdleTimeoutSecs}"
  ];

  # SEC-7 域名白名单: 非空才渲染 (空 = serde default 兜底 = 拒绝所有域名).
  allowedDomainsLines = lib.optionals (allowedDomains != [ ]) [
    "# SEC-7 Host guard 信任域名 (反代 + 域名部署; 未声明的域名 Host 一律 403)."
    "allowed_domains = [${lib.concatMapStringsSep ", " q (lib.sort (a: b: a < b) allowedDomains)}]"
  ];

  serverSection = lib.concatStringsSep "\n" (
    [
      "[server]"
      "# 与 services.secret-guard.host/port 保持一致 (实际由 ExecStart --host/--port 参数覆盖, 此处仅作 fallback/调试参考)."
      "host = ${q host}"
      "port = ${toString port}"
    ]
    ++ timeoutLines
    ++ allowedDomainsLines
  );

  providerIds = lib.sort (a: b: a < b) (builtins.attrNames providers);

  # 跨 provider 校验 1: provider id 卫生 (attr 名即 id).
  badIds = lib.filter (id: !validId id) providerIds;

  # 跨 provider 校验 2: route target / pool member 存在性 (含禁用路由 —
  # 声明式配置中悬空即错误).
  dangling = lib.concatMap (
    id:
    let
      p = providers.${id};
      routeDangling = map (r: "${id} → ${r.target}") (
        lib.filter (r: !providers ? ${r.target}) (p.routes or [ ])
      );
      # pool members 全量校验 (无禁用语义 — 与上游 would_cycle 边集一致).
      memberDangling = map (m: "${id} → ${m}") (lib.filter (m: !providers ? ${m}) (p.members or [ ]));
    in
    if p.kind == "router" then
      routeDangling
    else if p.kind == "pool" then
      memberDangling
    else
      [ ]
  ) providerIds;

  # 跨 provider 校验 3: 启用路由边 + pool 成员边环检测 (对齐上游 would_cycle
  # — priority=null 的禁用路由不构成边; pool members 全算; 悬空目标已由校验 2
  # 拦截, 边只含存在的 id).
  # 与上游的已知偏差: 入口级 enable=false 的 provider 仍算图节点 (上游
  # effective_snapshot 会排除) — 指向 disabled provider 的路由运行时必 503,
  # fail-fast 合理, 仅错误归因可能显示为 "成环" 而非 "指向 disabled".
  enabledEdges = lib.mapAttrs (
    _: p:
    if p.kind == "router" then
      map (r: r.target) (lib.filter (r: (r.priority or null) != null) (p.routes or [ ]))
    else if p.kind == "pool" then
      p.members or [ ]
    else
      [ ]
  ) providers;

  # DFS: 沿启用边走, 回到 path 上的节点即环. enabledEdges.${node} 不设 or 兜底 —
  # 悬空检查先行保证了所有 target 都在图中, 若未来校验链重排破坏此不变式,
  # 缺 attr 会显式崩 (而非静默漏报环), 与 fail-fast 立场一致.
  reachesPath =
    node: path: lib.any (t: lib.elem t path || reachesPath t (path ++ [ t ])) enabledEdges.${node};

  cyclicId = lib.findFirst (id: reachesPath id [ id ]) null providerIds;

  # secrets.entries 重复 id 检查 (listOf 没有 attrsOf 的结构性去重; 上游 static
  # 加载对重复 id first-wins 静默容忍, 这里加严 fail-fast — 声明式配置中重复
  # id 几乎肯定是复制粘贴错误, redact 清单少一条是安全损失).
  dupSecretIds = dups (map (e: e.id) secretsEntries);

  result =
    lib.concatStringsSep "\n\n" (
      [ header ]
      ++ map (id: renderProvider id providers.${id}) providerIds
      ++ lib.optional (secretsEntries != [ ]) secretsSection
      ++ lib.optional (redactedHeaders != [ ]) redactSection
      ++ [ serverSection ]
      ++ lib.optional (auth != null) (renderAuth auth)
      ++ lib.optional (usage != null) (renderUsage usage)
    )
    + "\n";
in
# 校验链 (全部在 eval 期强制): id 卫生 → 重复 secret id → 悬空 target → 环 →
# 空白 redacted_headers → 语法 round-trip. 逐 provider 的 sum type fail-fast
# 与 auth 重复 label 检查在 result 被 fromTOML 强制时触发.
lib.throwIf (badIds != [ ])
  "secret-guard render: provider id 非法 (须 1..=64, 首字符字母数字, 其余 [A-Za-z0-9_-]): ${toString badIds}"
  (
    lib.throwIf (dupSecretIds != [ ])
      "secret-guard render: secrets.entries id 重复: ${toString dupSecretIds}"
      (
        lib.throwIf (dangling != [ ])
          "secret-guard render: route target / pool member 不存在于 providers (声明式配置中悬空即错误): ${toString dangling}"
          (
            lib.throwIf (cyclicId != null)
              "secret-guard render: provider 路由成环, 沿启用路由边回到 '${cyclicId}' (禁用路由不构成边)"
              (
                lib.throwIf (blankHeaders != [ ])
                  "secret-guard render: redactedHeaders 空白条目无意义 (上游归一化时 WARN 跳过, 几乎肯定是笔误): ${toString blankHeaders}"
                  (builtins.seq (builtins.fromTOML result) result)
              )
          )
      )
  )
