# 本地自检清单

控制台地址由 `config.json` 的 `api.addr` 决定（默认 <http://127.0.0.1:3090/>）；内核随客户端一起启动。

## 一分钟自检

| 步骤 | 操作 | 期望结果 |
|---|---|---|
| 1 | 打开控制台（默认 <http://127.0.0.1:3090/>） | 概览页显示运行时长、出口、连接数、规则数；左上角有 syan-clash 标识 |
| 2 | 点侧栏「节点」 | 看到代理组卡片与节点表；下拉切换组内成员立即生效 |
| 3 | 点「自动选优」 | 提示测速并切换到最快节点；延迟徽标变绿/黄/红 |
| 4 | 点侧栏「订阅」 | 看到已保存的 lab-sub（含流量 100 GB 与到期时间）；可粘贴新链接导入 |
| 5 | 点侧栏「规则」 | 6 组预设规则集卡片，点「应用」即写入；规则表可增删 |
| 6 | 点侧栏「内核」 | sing-box / mihomo / Xray 三个内核，显示版本、许可证、状态；可下载/启动/停止/看配置 |
| 7 | 点侧栏「日志」 | 实时日志滚动；级别过滤与关键字搜索可用 |
| 8 | 点侧栏「设置」 | 运行环境（管理员权限、TUN 可用性）、开机自启开关、配置备份导出/导入 |
| 9 | 顶栏「TUN」开关 | 开启后系统出现 syan-clash0 网卡并接管默认路由；关闭后完全还原 |
| 10 | 右键托盘图标 | 菜单：打开控制台 / 开关系统代理 / 退出 |

## 自动化自检

```powershell
cd <项目根目录>
go test ./...                                        # 全部 Go 单元测试
node test/ui/run-all.cjs                             # 界面回归（Playwright，mock 控制台）
powershell -ExecutionPolicy Bypass -File lab\regress.ps1   # 端到端：42 项（本地 lab 脚本，未入库）
powershell -ExecutionPolicy Bypass -File lab\cores.ps1     # 三内核交叉验证：12 项（本地 lab 脚本，未入库）
```

`lab\` 里的两个 PowerShell 脚本会自己起服务、跑完检查、清理进程，可反复执行。

## 手动快捷键

```powershell
# 重新构建并启动
cd <项目根目录>
go build -o syan-clash.exe ./cmd/core       # 控制台/托盘版；带窗口的发布版见 .\build.ps1
.\syan-clash.exe -config lab\coretest.json

# 只渲染配置、不启动
.\syan-clash.exe -render-core xray -profile profile.json

# 不带托盘启动（服务/无桌面会话）
.\syan-clash.exe -config lab\coretest.json -no-tray
```

## 界面深链接

页面可以直接用地址栏打开，方便收藏或分享：

| 地址 | 效果 |
|---|---|
| `/?page=nodes` | 直接进节点页（`subs` / `conns` / `rules` / `cores` / `logs` / `settings` 同理） |
| `/?theme=light` | 强制浅色主题（`?theme=dark` 强制深色） |

## 说明

- lab 自检脚本用实验配置 `lab/coretest.json`（端口 27890/27891，控制台 29090）；
  日常使用走 `config.json`，默认端口 2890/2891、控制台 3090（见 `internal/config/config.go` 的 `Default()`）。
- 订阅里是我本地起的测试源（`http://127.0.0.1:18081/sub`），换成你自己的订阅链接即可；
  `lab/subsrv.ps1` 是那个测试源，不再需要可以关掉。
- 三个内核二进制在 `lab/cores/` 下，由客户端自己下载并校验。

## 关于截图

界面没有用浏览器截图来验：本机 Chrome 与 Edge 访问 `127.0.0.1` 上的 HTTP 服务会被拦
（外网、本地文件、curl 都正常）。替代做法是 `go test ./internal/control/` 直接检查
内嵌的那份 HTML：页面与导航是否一一对应、
脚本引用的 79 个元素是否都存在、控制台调用的每个接口是否都有对应路由（并反向检查
没有写了却无人调用的路由）、14 项关键功能是否都还在。

浏览器级的交互（点击 / toast / 虚拟列表滚动）由 `test/ui` 的 Playwright 套件覆盖：
每个 `verify-*.cjs` 自带 mock 控制台，不需要真实服务，`node test/ui/run-all.cjs` 汇总一行结论。
