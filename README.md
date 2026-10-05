# syan-clash —— 多内核代理客户端

思路是**集百家所长**：协议实现不自己写，交给现成的开源内核；自己写的是"壳"——
中立模型、配置编译器、订阅导入、内核进程看护、统一控制 API、系统集成和一个像样的控制台。
换内核只加一个配置编译器，界面和规则语义都不用动。

可搬运清单（内核 / GUI / 订阅转换 / 规则数据 / 系统集成，含许可证结论）见 `docs/REUSE.md`。

自检步骤与自动化脚本见 `VERIFY.md`。

使用前请先读 **`DISCLAIMER.md`（免责声明）**：本项目仅供学习与技术研究，不提供任何服务器、节点或订阅。

## 一切都在项目目录里

项目不往系统临时目录、用户目录或注册表写任何东西：

* 客户端配置、订阅列表、内核二进制与生成的配置都在 `lab\`（可换目录，见 `core.dir`）
* 脚本的临时文件一律放 `lab\tmp\`
* 开机自启与系统代理是**显式开关**，默认关闭
* 整个项目可以直接复制一个文件夹搬走

## 分层

```
控制台 UI（内嵌单文件 Web，internal/control/web/index.html）
    │  JSON API + SSE
┌───┴─────────────────────────────────────────────────────────┐
│ internal/app        装配与业务：配置 / 订阅导入 / 内核生命周期   │
│ internal/core       多内核适配层                              │
│   ├ ir.go           中立模型 Profile                          │
│   ├ emit_singbox.go Profile → sing-box JSON                   │
│   ├ emit_mihomo.go  Profile → mihomo YAML                     │
│   └ supervisor.go   下载 / 校验 / 拉起 / 看护 / 控制地址         │
│ internal/subscription 订阅导入：分享链接 / base64 / Clash YAML │
│                       / sing-box JSON → 中立节点                │
│ internal/clashapi   统一控制 API 客户端（mihomo 与 sing-box 通用）│
│ internal/yamlmin    极简 YAML 读写（自研，无第三方依赖）          │
│ internal/proxy      自研轻量内核（内置兜底模式）                 │
│ internal/rules      规则引擎（中立语义基准）                     │
│ internal/sysproxy   Windows 系统代理开关                        │
└─────────────────────────────────────────────────────────────┘
    │ 子进程 + 原生配置文件
    └─ sing-box / mihomo / Xray
```

两种运行模式：

* **内置模式**：不依赖任何外部内核，`internal/proxy` 直接提供 SOCKS5/HTTP 入站。
* **内核模式**：`core.id` 指定内核，本程序生成该内核的原生配置、拉起并看护它，
  并通过统一的 Clash 兼容 API 管理节点、代理组、延迟和连接。

## 快速开始

```powershell
go build -o syan-clash.exe ./cmd/core
.\syan-clash.exe -config config.json          # 首次运行会写出默认配置
```

控制台：<http://127.0.0.1:9090/>（地址由 `api.addr` 决定）。

只渲染配置、不启动进程：

```powershell
.\syan-clash.exe -render-core sing-box -profile profile.json > singbox.json
.\syan-clash.exe -render-core mihomo  -profile profile.json > mihomo.yaml
```

## 控制台

单文件内嵌 UI，深色/浅色主题，8 个页面：

| 页面 | 能做什么 |
|---|---|
| 概览 | 运行指标、实时上下行流量曲线、本地入口地址 |
| 节点 | 代理组切换（下拉即生效）、节点列表、单个/批量延迟测速 |
| 订阅 | 粘贴订阅链接或内容，先预览再一键导入并热重载内核 |
| 连接 | 内核连接表 / 内置连接表切换、关键字过滤、单条或全部断开 |
| 规则 | 规则列表 + 匹配测试（域名/IP + 端口 → 命中哪条规则） |
| 内核 | 下载 / 启动 / 停止 sing-box、mihomo；查看生成的原生配置 |
| 日志 | SSE 实时日志，级别过滤 + 关键字搜索 + 自动滚动 |
| 设置 | 原始配置编辑、保存并热重载、一键复制 |
| （托盘） | 通知区图标：打开控制台 / 开关系统代理 / 退出，左键直达控制台 |

## 订阅导入

支持以下格式，自动识别：

* 订阅链接（`http(s)://…`，直接抓取，带 UA）
* base64 订阅（标准 / URL-safe、带或不带 padding）
* 分享链接逐行列表：`ss://`（SIP002 与 legacy 两种写法）、`vmess://`、`vless://`（含 REALITY）、`trojan://`、`hysteria2://`、`socks5://`、`http(s)://`
* Clash / mihomo 配置（`proxies` / `proxy-groups` / `rules` 一并导入）
* sing-box 配置（读取 `outbounds`）

导入后节点、代理组、规则会写进 `core.profile`，并重新编译、校验、热重载内核。

## 配置要点

```jsonc
{
  "inbound":  { "socks5_addr": "127.0.0.1:7891", "http_addr": "127.0.0.1:7890", "allow_lan": false },
  "outbound": { "type": "direct" },            // 内置模式的出口：direct | socks5
  "rules":    [ { "kind": "final", "value": "", "action": "proxy" } ],
  "api":      { "addr": "127.0.0.1:9090" },
  "core": {
    "id": "mihomo",                            // 空 = 用内置内核
    "auto_start": true,
    "dir": "cores",                            // 内核二进制与生成配置的存放目录
    "profile": { /* 中立模型：inbounds / dns / nodes / groups / rules / final / clash_api */ }
  }
}
```

中立模型字段见 `internal/core/ir.go`。节点类型：`socks5`、`http`、`ss`、`vmess`、`vless`（含 REALITY）、`trojan`、`hysteria2`；传输：`tcp` / `ws` / `grpc` / `http`；代理组：`select` / `url-test` / `fallback`；规则：`domain` / `domain-suffix` / `domain-keyword` / `ip-cidr` / `port` / `geoip` / `geosite` / `final`。

另有两条进程规则用于分流：`process-name`（按可执行文件名）与 `process-path`（按完整路径）。
sing-box 与 mihomo 两者都支持，Xray 只有按进程名的 `process` 字段，所以按路径的规则在 Xray 下会被降级为按名匹配。

`proxy` 作为动作表示"走默认出口"，与具体代理组名解耦，因此预设与导入的规则不会因为改了组名而失效。

## 预设规则集

内置 6 组规则，一键应用、一键移除，全部写在中立模型上，三个内核都能编译：

| 预设 | 内容 |
|---|---|
| 内网直连 | 局域网、回环、组播与本机链路直连 |
| 广告与追踪拦截 | 常见广告、统计、归因与遥测域名（12 个关键字 + 6 个国内 SDK 域名） |
| 国内直连 | `geosite:cn` / `geolocation-cn` / `private` 与 `geoip:cn` / `private` |
| AI 服务走代理 | OpenAI / Anthropic / Gemini / Perplexity / Copilot / HuggingFace 等 |
| 开发资源直连 | GitHub raw / npm / PyPI / crates / goproxy / Maven / NuGet |
| 屏蔽常见扫描与探测 | NetBIOS、SMB、mDNS、SSDP 端口丢弃 |

应用是幂等的：已存在的规则不会被重复添加。测试套件会验证每个预设都能被三个内核编译通过。

## 控制 API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 运行状态、连接计数、系统代理状态 |
| GET/PUT | `/api/config` | 读取 / 热重载配置（失败自动回滚） |
| GET/PUT | `/api/profile` | 读取 / 替换中立模型（自动重启内核） |
| GET/POST | `/api/subscriptions` | 列出 / 保存订阅（保存即抓取解析并热重载内核） |
| DELETE | `/api/subscriptions?name=` | 删除已保存的订阅 |
| POST | `/api/subscriptions/update` | 更新一个订阅 `{name}` 或全部 `{all:true}` |
| POST | `/api/profile/nodes` | 手动添加节点（写入 profile 并重启内核） |
| DELETE | `/api/profile/nodes?name=` | 删除节点并从所有代理组摘除 |
| GET | `/api/system` | 平台、管理员权限、TUN 可用性 |
| GET/POST | `/api/system/autostart` | 查询 / 设置开机自启（HKCU Run 项） |
| POST | `/api/subscription/parse` | 只解析订阅，返回节点/组/规则预览 |
| POST | `/api/subscription/import` | 解析并应用订阅（可传链接或原始内容） |
| GET | `/api/connections` | 内置内核连接表 |
| POST | `/api/connections/close?id=` | 断开一条内置连接 |
| GET | `/api/logs`、`/api/logs/stream` | 日志快照 / SSE 实时流 |
| POST | `/api/rules/match` | 规则匹配测试 |
| POST | `/api/system-proxy` | 开关 Windows 系统代理 |
| GET | `/api/cores` | 内核列表与状态 |
| POST | `/api/cores/install` | 下载并解压指定内核（`{"id":"mihomo"}`） |
| POST | `/api/cores/start`、`/api/cores/stop` | 启动 / 停止内核 |
| GET | `/api/cores/config?id=` | 预览生成的该内核原生配置 |
| GET | `/api/cores/version?id=` | 内核版本（走 Clash API） |
| GET | `/api/cores/proxies?id=` | 节点与代理组（统一后的结构） |
| POST | `/api/cores/select` | 切换代理组成员 `{id, group, name}` |
| GET | `/api/cores/delay?id=&name=&url=&timeout=` | 延迟测速（节点或整组） |
| GET | `/api/cores/traffic?id=` | 单次上下行速率采样 |
| GET | `/api/cores/connections?id=` | 内核连接表 |
| POST | `/api/cores/connections/close` | 断开内核的一条连接 `{id, conn}` |
| GET | `/api/cores/updates` | 查询各内核上游最新版本（GitHub releases，结果缓存 10 分钟） |
| POST | `/api/cores/update` | 升级到最新版（先停内核，装完自动拉起） |
| POST | `/api/cores/pick` | 测速整个代理组并切到最快节点 `{id, group, test_url}` |
| POST | `/api/profile/rules` | 添加规则（`index: -1` 追加到兜底规则之前，不会产生死规则） |
| DELETE | `/api/profile/rules?index=` | 删除指定位置的规则 |
| GET | `/api/backup` | 导出配置备份 zip（配置 + 订阅列表 + manifest） |
| POST | `/api/backup` | 从备份 zip 恢复（先全量校验再应用） |
| GET | `/api/presets` | 内置预设规则集及其应用进度 |
| POST | `/api/presets` | 应用预设规则集（幂等，重复应用不会重复添加） |
| DELETE | `/api/presets?id=` | 移除预设规则集带进来的所有规则 |

## 功能与状态

### 自检脚本

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File lab\regress.ps1
```

脚本自己起测试源与客户端，跑完 42 项检查（单元测试、构建、单实例、18 个 API、
内置代理三条路径、规则与预设、备份往返、订阅元数据、内核生命周期、孤儿进程防护），
逐项打印 PASS/FAIL，结束时清理自己启动的进程。当前：**42 通过 / 0 失败**。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File lab\cores.ps1
```

第二个脚本验证「一份 profile，多个内核」这个前提本身：对每个装了编译器的内核，
渲染配置、确认输出可解析、用自己的校验器启动、再干净停止。当前：
**sing-box / mihomo / xray 各 4 项，12 通过 / 0 失败**。

### 控制台结构测试

`go test ./internal/control/` 直接对**内嵌的那个 HTML 资源**做检查。控制台是单文件手写的，
没有别的东西会发现「某个页面丢了」或「脚本引用了被改名的元素」：

* 每个导航项都有对应页面，每个页面都有对应导航项
* 脚本引用的每个 `#id` 都真实存在（当前 79 个）
* 控制台调用的每个 `/api/...` 都能在 `api.go` 的路由里找到对应（反向也检查：
  没有路由被写完后无人调用）
* 14 项关键功能仍然在页面上（系统代理、TUN、主题、流量图、代理组、测速、选优、
  订阅、预设规则、进程分流、内核管理、备份、自启、日志过滤）
* 标签配平与编码正确

### 已经修正的问题

1. **内置引擎与 profile 规则脱节**：UI 里编辑的规则只写进了 `core.profile`，
   而内置引擎读的是顶层 `rules`，内置模式下用户加的规则会静默失效。
2. **`ip-cidr` 规则挡住了后面的域名规则**：引擎遇到需要解析地址的 IP 规则时
   立即返回「需要解析」，而不是继续扫描；解析失败就整体退化为走代理，
   使后面的 `reject` / `direct` 域名规则永远无法命中。
3. **同一规则可重复添加**：现在会拒绝完全相同的规则并说明原因。

顺带修掉了两个测试脚本自身的 bug：`curl.exe` 的输出是逐行数组，`.Length`
拿到的是行数而不是字符数，长度断言与状态判定都因此失准。

### 各项功能现状
* `go test ./...` 全绿：规则引擎、配置、代理端到端、配置编译器、YAML 读写、订阅解析（分享链接 / base64 / Clash YAML / sing-box JSON）。
* 内置内核：SOCKS5 / HTTP 明文 / HTTP CONNECT 三条路径取到真实响应；`reject` 规则返回 403；入站鉴权（SOCKS5 用户名密码 + HTTP 407）生效；`allow_lan=false` 时把 `0.0.0.0` 绑定强制改回 `127.0.0.1` 并告警；上游 socks5 出口级联可用；`PUT /api/config` 热重载后流量正常。
* 内核模式：本程序从 GitHub 下载 sing-box 1.14.2 与 mihomo 1.19.31，生成配置后先跑内核自带校验（`sing-box check` / `mihomo -t`）再启动；两个内核均成功拉起，Clash API 返回版本，经其混合入站的流量取到真实响应。
* 编译器被内核打回过两次并已修正：sing-box 1.14 废弃 `independent_cache`、强制要求 `route.default_domain_resolver`。
* 订阅链路：base64 订阅（3 条链接）→ 解析出 ss / vless+REALITY+grpc / trojan → 写入 profile → 重新生成 mihomo 配置 → 内核重启后节点表可见 → 代理组切换生效（`PROXY → seoul-1`）→ 延迟测速返回真实数值（DIRECT 2 ms）。
* 控制台：单文件 UI 由内核内嵌提供（HTTP 200），前端脚本通过 `node --check`；UI 调用的 13 个端点全部返回 200。
* 孤儿进程防护：内核子进程被放进 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 作业对象，强制杀掉控制台后内核随之退出、端口全部释放。Windows 对 `JobObjectExtendedLimitInformation` 的 ABI 要求是 144 字节，136 字节会被 `ERROR_BAD_LENGTH` 拒绝，代码里按这个值处理。
* 端口冲突防护：控制地址已有内核在应答时，启动会直接拒绝并说明原因（`control address 127.0.0.1:29099 is already answering (v1.19.31)`），不再产生第二个坏实例。
* 节点管理：手动添加节点 → 写入 profile → 重启内核 → 内核代理表即时可见（自动进入 PROXY 与 AUTO 组）；删除节点同步从所有组里摘除，内核侧同步消失。
* 运行环境检测：`/api/system` 报告平台、是否具备管理员权限、TUN 是否可用，并在界面「设置」页给出结论。
* TUN 模式：一键开关生效——开启后系统出现 `syan-clash0`（Meta Tunnel，Status Up）网卡并接管默认路由（`0.0.0.0/0 → 198.18.0.2 via vvpn0`）；关闭后网卡被移除、默认路由回到物理网卡、外网连通性正常。缺管理员权限时接口直接返回中文原因，不会让内核在深处失败。
* 第三个内核 Xray-core（MPL-2.0）：新增配置编译器，由本程序下载、经其自带校验（`xray run -test`）后启动，经其 SOCKS 入站的流量取到真实响应。Xray 与 Clash 系内核的三处差异按事实处理并显式告警：没有代理组（组名解析为首个成员）、没有 mixed 入站（按 SOCKS5 生成）、不支持 TUN 入站与 hysteria2 节点（跳过并记日志）。
* 下载镜像回退：GitHub release CDN 在部分网络下可能完全不可达（直连与 `curl` 均返回 000），而镜像前缀可用。安装内核现在按「用户指定镜像 → 官方地址 → 内置镜像列表」依次尝试，逐个记录失败原因；镜像产物仍必须通过 zip 与可执行文件校验，避免被静默替换。配置项 `core.mirror` 可换成自己的前缀。
* 内核版本检查：`/api/cores/updates` 实时查询 GitHub releases（结果缓存 10 分钟以避开匿名配额），三个内核均正确报告当前版本与是否可升级；资源选择器会跳过 CPU 级别（`-v1/-v2/-v3`）与工具链变体，优先选名字最短的通用构建。
* 单实例守卫：命名互斥体实现，第二个实例以退出码 2 退出并打印 `another instance is already running (configuration: …)`。
* 开机自启：真实的 HKCU `Run` 项读写，写入后 `reg query` 可见完整命令行，关闭后条目消失。
* 订阅管理：订阅保存到 `subscriptions.json`。添加订阅 → 抓取 → 解析 3 个节点 → 写 profile → 重启 mihomo → 内核代理表可见」全链路；再次更新会重新抓取并刷新更新时间。
* 多订阅合并：导入第二个订阅**不再覆盖**第一个的节点（此前会静默丢失，只剩新订阅的 2 个）；删除订阅会**一并移除它的节点**（此前节点残留，会继续往已删除的供应商发流量）。手加的节点不属于任何订阅，永远不会被这两类操作影响。更新单个订阅时，其他订阅的节点位置保持不变。
* 订阅归属持久化与重启重建：节点归属原本只在内存里，重启后丢失，导致更新订阅时重复插入同名节点、报 `duplicate outbound name`。现在订阅会记录自己贡献的节点名，启动时从磁盘重建归属；同时合并逻辑加了最终去重 —— 无论归属记录是什么状态，都不会产出重名节点。重启 → 更新 → 仍是 3 个节点、无报错。
* 配置自愈：`final` 或规则指向已不存在的代理组时（改过组、删过订阅），不再是直接拒绝启动，而是自动改指向可用的出口 —— 能起来再改，比起不来强。一份 `final: PROXY` 但无该组的配置，修复前报 `startup failed`，修复后正常启动并把 final 落为 `direct`。
* mihomo 许可证已核实：直接读取仓库 LICENSE 原文为完整 MIT 文本（Copyright 2023 KT），**不是 GPL-3.0**。它是三个内核里唯一可无条件闭源商用的（sing-box GPL-3.0，Xray MPL-2.0）。
* 启动任务：启动 3 秒后自动刷新已保存订阅，日志出现 `启动任务：刷新 1 个订阅` 且订阅的 `updated_at` 被刷新到本次启动时间。
* 自动选优：`/api/cores/pick` 逐节点测速后切换，把 `PROXY` 从不可达节点切到可用链路、把 `AUTO` 保持在最快的 `local-hop`（1–2 ms），并返回每个成员的延迟与失败列表。
* 托盘：直接用 `Shell_NotifyIcon` 实现（无第三方依赖），托盘窗口已创建（`FindWindow("syan-clashTrayWindow")` 返回有效句柄）。另外修掉一个缺陷：Go 协程会在 OS 线程间迁移，而 Win32 窗口与消息循环必须绑定同一线程，已加 `runtime.LockOSThread`。
* 连接页进程归属：内核连接表新增 `process_name`，UI 改为「进程 / 来源」列，mihomo 上报的进程路径被正确归一为可执行文件名。
* 进程分流：中立模型新增 `process-name` / `process-path`，三个内核各自生成原生写法（sing-box `process_name`/`process_path`、mihomo `PROCESS-NAME`/`PROCESS-PATH`、Xray `process`），mihomo 接受含进程规则的配置并正常启动；规则的增删走 `POST/DELETE /api/profile/rules`，追加时会自动插在兜底规则之前，避免生成永不命中的死规则。
* Xray 双入站：Xray 没有 mixed 监听，编译器把中立模型的单个 mixed 入站拆成 SOCKS5 与 HTTP 两个监听（HTTP 用下一个端口），两个入口都取到 HTTP 200；端口已占用到 65535 时只生成 SOCKS5 并明确告警，不会产出无法绑定的配置。
* 进程归属回退：mihomo 在部分构建下不填 `processPath`，此时客户端通过 Windows TCP 所有者表把连接的本地端口反查成进程（`GetExtendedTcpTable` → PID → 可执行文件名），连接表显示 `process_name: "curl.exe"`。规则页因此可以给出「已见进程」下拉，不必手敲路径。
* 订阅导入的保护：导入会替换节点与规则，因此在缺少等价规则时自动补上内网/回环直连（8 条），避免导入后本机与局域网请求被送到远端节点。该补全是幂等的，已有等价规则不会重复添加。
* 订阅用量：解析 `subscription-userinfo` 响应头（兼容 `;` 与 `,` 分隔、空白、非数字字段）与 `content-disposition`（含 RFC 5987 `filename*=` 中文名），本地订阅源上报的 100 GB 配额与 2030 年到期时间被正确解析、存储并展示在订阅页。
* 配置备份：导出为 zip（`config.json` + `subscriptions.json` + `manifest.json`），大小 1628 字节；把 socks5 端口改成 27999 并生效后，再从备份恢复，端口回到 27891，订阅与节点一并还原。导入会先完整解析与校验，损坏的备份不会改动现有配置。
* 预设规则集：应用「广告与追踪拦截」（18 条）后规则总数 4 → 22；重复应用数量不变（幂等）。mihomo 日志明确记录 `match DomainKeyword(doubleclick) using REJECT`，移除预设后同一域名变成 `match Match/` 走代理，规则增删双向生效。测试套件会编译每个预设在三个内核下的输出，确保不会产出无法启动的配置。

## 还没做

| 项 | 说明 |
|---|---|
| 进程级分流 | Windows 需要 WFP callout 或 WinDivert，是唯一绕不开的重活 |
| 进程级分流的界面开关 | 后端已能识别进程归属，按进程走不同出口仍需 TUN 规则或 WinDivert |
| Xray 的节点切换 | Xray 无代理组，运行中无法切换节点；需要切换请用 sing-box / mihomo |
| 自动更新 | 客户端自更新与内核版本检查 |

## 免责声明

**syan-clash 仅供个人学习、技术研究与本地实验环境使用。**
任何人在下载、安装、复制、运行或以其他方式使用本软件（含其源代码、编译产物与附带文档）时，
即视为已完整阅读、理解并同意本声明的全部内容；若不同意，请立即停止使用并删除本软件。

### 一、用途限定

1. 本项目是一个**代理客户端外壳**，只负责中立模型、配置编译、内核进程看护与本地控制台。
   它**不提供**任何服务器、节点、订阅、账号、带宽或网络接入服务。
2. 使用者只能将其用于本人拥有、或已获得明确授权的设备与网络环境。
3. 禁止将本项目用于任何违反使用者所在地法律法规的用途，包括但不限于：
   未经授权访问他人系统或网络、绕过网络与信息安全保护措施、侵犯他人隐私或通信自由、
   传播违法信息、实施网络攻击、以及任何形式的商业侵权。
4. 使用者应自行确认其使用行为（包括自行导入的订阅、节点、规则与内核）合法合规，
   并**自行承担由此产生的全部责任**。

### 二、无担保

本软件按**「现状」（AS IS）**提供，不附带任何明示或暗示的担保，
包括但不限于对适销性、特定用途适用性、无中断运行或无错误的担保。
作者不保证本软件能够正常工作、不会中断、不会损坏数据，也不保证其兼容任何特定环境或设备。

### 三、责任限制

在适用法律允许的最大范围内，作者与贡献者**不对**因使用或无法使用本软件而产生的
任何直接、间接、附带、特殊、惩罚性或后果性损失承担责任，
包括但不限于数据丢失、业务中断、设备损坏、账号封禁、法律纠纷或经济损失。
**使用本软件的全部风险由使用者自行承担。**

### 四、第三方组件

本项目捆绑或以其他方式使用多个第三方开源组件，其著作权归各自作者所有，
各自适用其自身的许可证条款（见下方「许可证」一节与 `docs/REUSE.md`）。
本项目与上述组件的作者**无任何隶属、赞助或背书关系**，
也不对第三方组件的功能、安全性或合法性作任何承诺。

### 五、许可证与声明变更

本项目自身以 **GNU General Public License v3.0** 发布，全文见 `LICENSE`。
本免责声明不修改、不替代、也不豁免 `LICENSE` 中的任何条款；两者如有冲突，以 `LICENSE` 为准。
本免责声明可能随项目更新而调整，最新版本以仓库中的 [`DISCLAIMER.md`](DISCLAIMER.md) 为准。
## 许可证

本项目以 **GNU General Public License v3.0** 发布，全文见 `LICENSE`。

捆绑的第三方组件：

| 组件 | 位置 | 许可证 |
|---|---|---|
| mihomo | `internal/corebundle/assets/mihomo.exe.gz` | MIT（Copyright 2023 KT） |
| geosite.dat / geoip.metadb | `internal/corebundle/assets/*.gz` | GPL-3.0（MetaCubeX/meta-rules-dat） |
| wintun.dll | `internal/corebundle/assets/wintun.dll.gz`、`third_party/wintun/` | WireGuard Prebuilt Binaries License，见 `third_party/wintun/LICENSE-wintun.txt` |
| WebView2Loader.dll | `third_party/webview2/`、`cmd/desktop/assets/` | Microsoft WebView2 SDK 条款 |
| 界面字体 `syan-round.woff2` | `internal/control/web/fonts/` | 本项目自有（自制字体，非第三方素材） |

完整清单（含各组件许可证全文位置）见 [`THIRD-PARTY.md`](THIRD-PARTY.md)；更细的选型与许可证核对记录见 `docs/REUSE.md`。
