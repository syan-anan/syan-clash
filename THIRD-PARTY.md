# 第三方组件与许可

本仓库、以及从这里分发的 `syan-clash.exe` 里包含下列第三方组件。它们的著作权归各自作者所有，
各自适用其自身的许可证条款；本项目（GPL-3.0）不对这些组件作任何额外授权、担保或背书。

## 随仓库 / 随 exe 分发

| 组件 | 位置 | 许可证 | 许可证全文 |
|---|---|---|---|
| mihomo | `internal/corebundle/assets/mihomo.exe.gz`（首次运行解出到 `cores/mihomo/`） | MIT（Copyright 2023 KT） | `third_party/mihomo/LICENSE-mihomo.txt` |
| geosite.dat / geoip.metadb | `internal/corebundle/assets/geosite.dat.gz`、`geoip.metadb.gz` | GPL-3.0（MetaCubeX/meta-rules-dat） | 与本项目同源，见 `LICENSE` |
| wintun.dll | `internal/corebundle/assets/wintun.dll.gz`、`third_party/wintun/` | WireGuard Prebuilt Binaries License | `third_party/wintun/LICENSE-wintun.txt` |
| WebView2Loader.dll | `third_party/webview2/`、`cmd/desktop/assets/` | Microsoft WebView2 SDK 条款 | <https://learn.microsoft.com/microsoft-edge/webview2/> |
| 界面字体 `syan-round.woff2` | `internal/control/web/fonts/` | 本项目自有（自制字体，非第三方素材） | — |
| 图标与品牌图 | `syan-clash.ico`、`syan-V.ico`、`syanlogo.png` | 本项目自有 | — |

## 运行时按需下载（仓库与 exe 里都不含其二进制）

| 组件 | 许可证 | 来源 |
|---|---|---|
| sing-box | GPL-3.0 | SagerNet/sing-box |
| Xray-core | MPL-2.0 | XTLS/Xray-core |
| mihomo | MIT | MetaCubeX/mihomo |

## 选型与许可证核对记录

见 `docs/REUSE.md`。