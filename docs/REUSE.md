# 集百家所长：可搬运清单与组装方案

> 数据来源：GitHub REST API 实时查询，2026-09-30 抓取，原始记录见 `lab/landscape.json`。
> 星标数为抓取时的值。**许可证以仓库 LICENSE 文件为准**：GitHub 自动识别不出（NOASSERTION）
> 的条目我在表里标了「需核实」，用之前必须自己去仓库确认，不要凭这张表下结论。

## 0. 三条路线，选 C

| 路线 | 做法 | 代表 | 成本 | 上限 |
|---|---|---|---|---|
| A 全自研内核 | 自己实现协议栈 | 本仓库 v0.1 的 `internal/proxy` | 极高 | 低（协议覆盖永远追不上） |
| B 单内核 + 自研壳 | 绑死一个内核，做配置生成 + UI | Clash Verge Rev、FlClash | 低 | 中（受限于该内核） |
| **C 多内核适配 + 自研壳** | 中立模型 → 各内核原生配置，内核当子进程跑 | NekoRay、Karing | 中 | 高（谁强用谁） |

**选 C**。A 的成果不丢：它降级成「内置轻量模式」，同时它的规则引擎就是 C 里"中立模型"的语义基准。

## 1. 内核层（真正干活的，直接搬二进制/当子进程）

| 项目 | 许可证 | 语言 | 最新版 | 强在哪 | 搬法 |
|---|---|---|---|---|---|
| SagerNet/sing-box | **需核实**（API 报 NOASSERTION，仓库实际声明 GPL-3.0） | Go | v1.14.2 | 协议/传输最全，内置 TUN、DNS、rule-set(.srs)、端到端加密 | 子进程 + `config.json` |
| MetaCubeX/mihomo | **MIT（已核实）** | Go | v1.19.31 | Clash 生态最大，rule-provider / 代理组 / 订阅兼容性最好 | 子进程 + `config.yaml` |
| XTLS/Xray-core | MPL-2.0 | Go | v26.3.27 | VLESS + XTLS/REALITY 最强，协议实现最激进 | 子进程 + `config.json` |
| v2fly/v2ray-core | MIT | Go | — | 兼容目标，自身已进入维护模式 | 子进程 |
| HyNetworks/hysteria (v2) | MIT | Go | app/v2.12.3 | QUIC 大带宽，抗封锁强 | 子进程 + `config.yaml` |
| tuic-protocol/tuic | GPL-3.0 | Rust | — | QUIC 系，最后提交 2025-05，维护转弱 | 子进程 |
| shadowsocks/shadowsocks-rust | MIT | Rust | — | 纯 SS 场景最轻 | 子进程 |
| klzgrad/naiveproxy | BSD-3-Clause | C++ | — | HTTP/2 伪装抗封锁 | 子进程 |
| ihciah/shadow-tls | MIT | Rust | — | 给 SS 套 TLS 伪装 | 子进程 |
| daeuniverse/dae | **AGPL-3.0** | Go | — | eBPF 透明代理，仅 Linux | 子进程（AGPL 传染性强，慎用） |
| google/gvisor | Apache-2.0 | Go | — | 用户态 TCP/IP 栈（TUN 场景自己写内核时用） | 库 |

**Dreamacro/clash 已经 404，仓库不存在了，别再找它。** Clash 系现在的事实标准是 mihomo。

### mihomo 许可证：已核实（此前误标为"需核实"）

2026-09-30 直接读取仓库 LICENSE 文件，原文开头为：

> Copyright 2023 KT
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software ... to deal in the Software without restriction

这是标准 MIT 全文，不是 GPL。Clash 系历史上的许可证争议不适用于 mihomo。
**mihomo 是本项目三个内核里唯一可无条件闭源商用的**（sing-box 为 GPL-3.0，
Xray 为 MPL-2.0 文件级 copyleft）。

### 关于 "Clash Verge Rev"

常被推荐，但它是**壳不是内核**：GitHub 描述为 *"A modern GUI client based on
Tauri"*，148k⭐，Rust + Tauri，**GPL-3.0**，其内核正是 mihomo。

所以"用 Clash Verge Rev（mihomo 内核）"实际是两件事：

* **内核 mihomo**（MIT）—— 本项目已集成 ✅
* **壳 Clash Verge Rev**（GPL-3.0）—— 未采用，原因见下

不采用其壳的三条理由：

1. 它是 GPL-3.0，搬代码会导致本客户端必须整体 GPL-3.0 开源；而用 mihomo
   **二进制 + 自研壳**可以自由选择许可证。
2. 它只能驱动 mihomo 一个内核；本项目要驱动 sing-box / mihomo / Xray 三个。
3. 其设计思路（Windows 服务提权、profile 管理、订阅更新、Clash API 封装）
   已作为参考吸收，见下方「壳 / GUI」表。

### 许可证结论（这是决策，不是科普）

- **GPL-3.0**（sing-box、nekoray、subconverter、clash-verge-rev）→ 你分发客户端时必须整体 GPL-3.0 开源。
- **AGPL-3.0**（Sub-Store、dae）→ 只要你对外提供网络服务就得开源，内嵌风险最高。
- **MIT（最宽松）**：**mihomo**（已核实）、v2ray-core、hysteria、shadowsocks-rust、naiveproxy(BSD-3)。
- **MPL-2.0**：Xray-core，文件级 copyleft —— 改哪个文件开源哪个文件。
- 子进程 + 配置文件方式分发通常按「独立程序」处理，但 GPL 下仍有解释空间。**想省事就整体 GPL-3.0 开源**——Clash Verge Rev 148k⭐、FlClash 53.8k⭐ 都是 GPL-3.0，社区完全接受。

## 2. 壳 / GUI（抄交互和功能设计，代码是 GPL 就抄思路）

| 客户端 | 许可证 | 技术栈 | 星标 | 抄什么 |
|---|---|---|---|---|
| clash-verge-rev/clash-verge-rev | GPL-3.0 | Rust + Tauri | 148,297 | Windows 服务提权模型、profile 管理、订阅更新、mihomo API 封装、TUN 开关流程 |
| 2dust/v2rayN | GPL-3.0 | C# | 117,287 | Windows 桌面交互、分享链接解析、多内核切换 |
| 2dust/v2rayNG | GPL-3.0 | Kotlin | 63,292 | Android VPNService 集成、二维码、路由模式 UI |
| chen08209/FlClash | GPL-3.0 | Dart/Flutter | 53,842 | 移动端 UI、多平台打包、内核下载与校验 |
| hiddify/hiddify-app | **需核实** | Dart/Flutter | 32,969 | sing-box 配置生成模板、一键测速 |
| mihomo-party-org/clash-party | GPL-3.0 | TypeScript/Electron | 26,645 | Electron 桌面壳、订阅管理 |
| MatsuriDayo/NekoBoxForAndroid | **需核实** | Kotlin | 22,913 | Android 多内核（sing-box + 插件）架构 |
| MatsuriDayo/nekoray | GPL-3.0 | C++/Qt | 15,339（2024-12 归档） | **多内核适配层的最佳参考**，Xray/sing-box 双内核切换 |
| GUI-for-Cores/GUI.for.SingBox | GPL-3.0 | Vue | 8,193 | sing-box 全配置项的 UI 映射 |
| SagerNet/sing-box-for-android | **需核实** | Kotlin | 1,337 | 官方 Android 集成方式 |

## 3. 订阅 / 转换 / 规则数据（搬数据和转换逻辑，别自己写解析器）

| 项目 | 许可证 | 星标 | 用途 |
|---|---|---|---|
| tindy2013/subconverter | GPL-3.0 | 17,080 | 订阅格式互转（Clash / v2ray / sing-box / Quantumult）。**自建一个实例，别自己写解析** |
| sub-store-org/Sub-Store | AGPL-3.0 | 10,575 | 功能最强，但 AGPL，客户端内嵌要谨慎 |
| MetaCubeX/meta-rules-dat | GPL-3.0 | 5,251 | geoip/geosite `.dat` + `.mrs` 规则集（mihomo 直接吃） |
| SagerNet/sing-geosite | **需核实** | 983 | sing-box `.srs` 规则集 |
| SagerNet/sing-geoip | **需核实** | 332 | sing-box geoip |
| Loyalsoldier/clash-rules | GPL-3.0 | 28,617 | 分域名规则集（广告/直连/代理分流） |
| v2fly/domain-list-community | MIT | 9,591 | 域名分类源数据（geosite 上游） |
| IrineSistiana/mosdns | GPL-3.0 | 3,754 | 需要更强 DNS 分流时独立部署 |
| AdguardTeam/AdGuardHome | GPL-3.0 | 37,126 | DNS 去广告 |

## 4. Windows 系统集成（这块必须自己写，没有现成整件）

| 项目 | 许可证 | 用途 |
|---|---|---|
| WireGuard/wintun | **需核实**（仓库自带专门许可，不是标准 SPDX） | TUN 驱动，NDIS 轻量，比 TAP 干净 |
| basil00/WinDivert | **需核实**（LGPL 系 + 静态链接例外） | 用户态抓包/重定向，做进程分流兜底 |
| clash-verge-rev/clash-verge-service | **需核实**（15⭐，已归档） | 抄「GUI 不提权、服务提权」的模型 |

进程级分流（per-app proxy）在 Windows 上必须走 WFP callout 驱动或 WinDivert，内核本身不提供。
这是自研壳里唯一绕不开的重活，建议放到 Phase 3。

## 5. 组装方案

```
你的壳（Go + WebView2/Tauri）
 ├─ Core Supervisor     下载 / 校验 / 启动 / 看护内核进程          ← 本轮已实现雏形
 ├─ Config Compiler     中立模型 → 各内核原生配置（sing-box/mihomo/Xray）← 本轮已实现雏形
 ├─ Unified API         把 mihomo Clash API / sing-box Clash API / Xray gRPC
 │                      统一成一套 UI 接口                        ← 下一步
 └─ System Integration  系统代理（已有）/ TUN / 服务提权           ← 系统代理已实现
内核（子进程，按需切换）：sing-box / mihomo / Xray / hysteria
```

关键点：**中立模型只写一次，配置编译器按内核出多种方言**。这是"集百家所长"能落地的前提——
换内核不用改 UI，只加一个 emitter。

## 6. 分阶段路线

| 阶段 | 目标 | 验收 |
|---|---|---|
| P0（已做） | 自研轻量内核：SOCKS5/HTTP 入站 + 规则引擎 + 连接表 + 系统代理 + 控制台 | `go test ./...` 通过；curl 经代理取到真实响应 |
| P1（本轮） | 中立模型 + sing-box/mihomo 配置编译器 + 内核进程看护 | 生成的配置能被真内核 `check` 通过；能起进程并读到 Clash API 版本 |
| P2 | 订阅导入（调 subconverter）+ 代理组 + 延迟测试 + 统一 API | 导入真实订阅链接 → 节点列表 → 切换 → 延迟可见 |
| P3 | TUN 模式 + 服务提权 + 进程分流 | 全局接管，无需逐个应用配代理 |
| P4 | 打包签名 + 自动更新 + 多平台 | 安装包可分发 |

## 7. 本轮之后本仓库的定位

- `internal/proxy`：自研轻量内核，作为「无内核依赖的兜底模式」和规则语义基准。
- `internal/core`：多内核适配层（中立模型 + 配置编译器 + 进程看护）。接上真内核即成为完整客户端。
- `internal/sysproxy` / `internal/control`：系统集成与控制台，与内核选择无关，可长期复用。
