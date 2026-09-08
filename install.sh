#!/bin/bash
# ==========================================================
# x-ui 静态IP中转 Web 管理系统 一键安装部署脚本
# ==========================================================
set -e

INSTALL_DIR="/usr/local/x-ui-relay-web"
SERVICE_NAME="x-relay-web"
PORT="27095"

echo "==== 正在安装 x-ui 静态IP中转 Web 管理服务 ===="

mkdir -p "$INSTALL_DIR/templates"
cp app.py "$INSTALL_DIR/"
cp templates/index.html "$INSTALL_DIR/templates/"
chmod +x "$INSTALL_DIR/app.py"

# 创建 systemd 服务
cat <<EOF > /etc/systemd/system/${SERVICE_NAME}.service
[Unit]
Description=x-ui Static IP Relay Web Service
After=network.target x-ui.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

# 防火墙端口放行（如果存在 ufw 或 iptables）
if which ufw >/dev/null 2>&1; then
    ufw allow ${PORT}/tcp >/dev/null 2>&1 || true
fi
if which iptables >/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT >/dev/null 2>&1 || true
fi

SERVER_IP=$(curl -s4 https://api.ipify.org || curl -s4 ifconfig.co || echo "212.135.38.177")

echo "=========================================================="
echo "🎉 安装完成！x-ui 静态IP中转 Web 管理服务已启动！"
echo "🌐 Web 后台访问地址: http://${SERVER_IP}:${PORT}"
echo "👤 默认用户名: marginal"
echo "🔑 默认密码: pbs483212595"
echo "=========================================================="
