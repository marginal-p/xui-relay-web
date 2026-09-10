# 🛰️ x-ui-relay-web: 全协议中转与多服务器统一调度平台

<p align="center">
  <img src="https://img.shields.io/badge/Release-v2.0-indigo.svg" alt="Release">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/x--ui-yg%20%2F%20standard-green.svg" alt="x-ui">
  <img src="https://img.shields.io/badge/License-MIT-purple.svg" alt="License">
</p>

一套专为 `x-ui` / `x-ui-yg` 打造的**现代化全协议中转与多服务器集群调度系统**。  
支持将任何第三方静态落地节点（**Socks5 / VMess / VLESS / Trojan / Shadowsocks / HTTP**）一键封装为统一高隐蔽性的 **VLESS + Reality** 前置中转，并提供**前后端解耦的统一控制面板**、**节点分组管理**、**分组流量自动熔断限额**与 **Clash Meta (Mihomo) 一键订阅导出**。

---

## ⚡ 一键部署命令 (Linux Server)

在任意全新的 Debian / Ubuntu / CentOS / AlmaLinux / Rocky 服务器上使用 root 权限运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/marginal-p/xui-relay-web/main/install.sh)
```
*(注：如果尚未创建 GitHub 仓库，也可以直接使用当前中转机在线分发链接：`bash <(curl -fsSL http://212.135.38.177:27095/install.sh)`)*

安装完成后，终端会显示面板访问地址（默认端口 `27095`）及登录账密。

---

## 🌟 核心特性

- 🚀 **全协议落地支持**：
  - 静态 Socks5 / 纯 IP:Port:User:Pass
  - VMess (支持 WS / TCP / TLS)
  - VLESS (支持 TCP / Reality / TLS)
  - Trojan / Shadowsocks / HTTP
- 🛡️ **底层 Xray 核心联动与安全预检**：
  - 自动生成符合 Xray 规范的出站与路由分流规则，并在重启前进行 `xray -test` 预检与异常自愈。
  - 严格校验 UUID 十六进制规范，杜绝坏节点导致核心崩溃死循环。
- 🏷️ **节点分组与流量熔断限额**：
  - 支持按业务自定义分组（如亚太线路、专线落地等）。
  - 支持为每个分组单独设置总流量上限（GB），后台常驻守护线程（30s 周期）超限自动暂停该组节点，防止流量透支。
  - 支持分组一键流量清零并自动恢复、手动整组启停。
- 🖥️ **前后端解耦与多服务器统一调度**：
  - 后端 Agent 原生支持 CORS 跨域与 Bearer Token 无状态认证。
  - 前端为纯静态 SPA（`frontend/index.html`），可托管于 **GitHub Pages**、任意静态服务器或本地直接双击打开。
  - 单一前端支持绑定无限台 Linux 中转服务器，顶部下拉框一键切换，并附带实时连通性与网络延迟探测（ms）。
- ⚡ **Clash Meta (Mihomo) 配置文件与订阅**：
  - 纯落地 IP 规范命名（不带端口号）。
  - 支持按分组或单服务器一键生成/订阅。
  - 支持**🌟 聚合导出**：一键将所有绑定的中转服务器节点聚合生成一个统一的 Clash Meta 配置文件。

---

## 🛠️ 服务器命令行管理工具 (`x-relay`)

一键安装后即可在终端全局使用：

```bash
x-relay status      # 查看中转服务状态
x-relay restart     # 重启中转服务
x-relay log         # 查看运行实时日志
x-relay info        # 查看当前面板地址与账号密码
x-relay uninstall   # 一键彻底卸载
```

---

## 🌐 前端静态部署 (GitHub Pages)

您可以直接开启本仓库的 **GitHub Pages**：
1. 进入 GitHub 仓库设置 `Settings` -> `Pages`；
2. 构建分支选择 `main`，目录选择 `/ (root)` 或把 `frontend/index.html` 设为主页；
3. 即可免费获得一个专属的云端中转管理后台（例如 `https://marginal-p.github.io/xui-relay-web/frontend/`），在任何设备上随时随地管理所有中转服务器！

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 开源。
