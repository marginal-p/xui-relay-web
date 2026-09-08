# x-ui 静态IP中转节点 Web 网页管理系统

专为基于 x-ui / Xray 的代理服务器设计，支持在网页上一键将任意 Socks5 静态 IP 转换为高性能、抗封锁的 VLESS + Reality 落地中转节点。

## 🌟 核心特性

- **前端网页可视化管理**：单页面精美 SPA 界面（Tailwind CSS + Vue 3），手机端/PC端自适应。
- **一键中转**：直接粘贴 `ip:port:user:pass` 或 `socks5://...`，自动生成 Reality 密钥与 UUID，自动绑定出站与精准路由规则。
- **批量导入**：支持多行文本一次性粘贴几十甚至上百个静态 IP，一键批量生成。
- **一键导入客户端**：支持一键复制 VLESS 链接、扫码二维码、以及一键批量导出所有链接。
- **实时连通性探测**：内置 Socks5 握手探测，实时检测落地代理可用性、往返延迟及真实出口公网 IP。
- **无缝集成 x-ui**：直接操作 x-ui SQLite 数据库，每次变更自动平滑重载 Xray 核心，在 x-ui 面板中亦可直接查看入站与流量统计。
- **轻量零依赖**：基于 Python 3 原生标准库开发，无需 pip 安装繁重的第三方包，开箱即用。

## 🚀 访问地址与登录

- **Web 访问地址**：`http://服务器IP:27095`
- **默认用户名**：`marginal`
- **默认密码**：`pbs483212595`

## 🛠 服务管理命令

```bash
# 查看服务状态
systemctl status x-relay-web

# 重启服务
systemctl restart x-relay-web

# 停止服务
systemctl stop x-relay-web
```
