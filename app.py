#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
x-ui 全协议中转节点 Web 管理服务
支持将 Socks5 / VMess / VLESS / Trojan / Shadowsocks / HTTP 落地节点
一键封装为统一的 VLESS + Reality 落地中转节点，并提供现代化网页管理面板。
支持节点分组管理、分组流量统计、总流量限制、超限自动暂停保护与 Clash Meta 导出。
"""

import os
import sys
import json
import uuid
import time
import socket
import sqlite3
import secrets
import base64
import threading
import urllib.parse
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# 默认配置
CONFIG_FILE = "/etc/x-relay-web.json"
DEFAULT_PORT = 27095
DEFAULT_USER = "marginal"
DEFAULT_PASS = "pbs483212595"
SERVER_IP = "212.135.38.177"
XRAY_BIN = "/usr/local/x-ui/bin/xray-linux-amd64"
DEFAULT_DB_PATH = "/etc/x-ui-yg/x-ui-yg.db"
DEFAULT_SNI = "apple.com"
DEFAULT_GROUP = "默认分组"

SESSIONS = set()

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "port": DEFAULT_PORT,
        "username": DEFAULT_USER,
        "password": DEFAULT_PASS,
        "db_path": DEFAULT_DB_PATH,
        "server_ip": SERVER_IP,
        "default_sni": DEFAULT_SNI,
        "sub_token": secrets.token_hex(16),
        "listen": "0.0.0.0"
    }

def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

CURRENT_CONFIG = load_config()
if "sub_token" not in CURRENT_CONFIG:
    CURRENT_CONFIG["sub_token"] = secrets.token_hex(16)
    save_config(CURRENT_CONFIG)

def detect_server_ip():
    try:
        import urllib.request
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.88.1"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            ip = resp.read().decode().strip()
            if ip:
                return ip
    except Exception:
        pass
    return CURRENT_CONFIG.get("server_ip", SERVER_IP)

CURRENT_CONFIG["server_ip"] = detect_server_ip()

# ==================== Xray 工具类 ====================
class XrayHelper:
    @staticmethod
    def generate_x25519():
        if os.path.exists(XRAY_BIN):
            try:
                res = subprocess.run([XRAY_BIN, "x25519"], capture_output=True, text=True, timeout=5)
                out = res.stdout
                priv, pub = None, None
                for line in out.splitlines():
                    if "PrivateKey:" in line:
                        priv = line.split(":", 1)[1].strip()
                    elif "PublicKey" in line:
                        pub = line.split(":", 1)[1].strip()
                if priv and pub and priv != pub:
                    return priv, pub
            except Exception as e:
                print(f"[Error] Xray x25519 failed: {e}")
                raise Exception(f"生成 X25519 密钥对失败: {e}")
        raise Exception(f"未找到 Xray 核心工具: {XRAY_BIN}")

    @staticmethod
    def generate_uuid():
        return str(uuid.uuid4())

    @staticmethod
    def generate_short_id():
        return secrets.token_hex(4)

# ==================== 通用全协议节点解析器 ====================

def is_valid_hex_uuid(val):
    if not val or not isinstance(val, str):
        return False
    clean = val.replace("-", "").strip()
    if len(clean) != 32:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in clean)

class NodeParser:
    @staticmethod
    def parse(raw: str):
        raw = (raw or "").strip()
        if not raw:
            return None

        # 1. VMess
        if raw.startswith("vmess://"):
            b64_str = raw[8:].strip()
            missing_padding = len(b64_str) % 4
            if missing_padding != 0:
                b64_str += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            host = data.get("add", "").strip()
            port = int(data.get("port", 0))
            uuid_str = data.get("id", "").strip()
            if not is_valid_hex_uuid(uuid_str):
                raise Exception(f"VMess 节点 UUID 格式非法: '{uuid_str}' (必须为32位十六进制字符)")
            alter_id = int(data.get("aid", 0))
            security = data.get("scy", "auto") or "auto"
            network = data.get("net", "tcp") or "tcp"
            path = data.get("path", "")
            ws_host = data.get("host", "")
            tls = data.get("tls", "")
            remark = data.get("ps", host) or host

            outbound_tag = f"vmess-{host}-{port}"
            outbound = {
                "tag": outbound_tag,
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid_str,
                            "alterId": alter_id,
                            "security": security
                        }]
                    }]
                }
            }
            stream = {"network": network}
            if tls == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {"serverName": data.get("sni", ws_host or host)}
            else:
                stream["security"] = "none"

            if network == "ws":
                ws_settings = {}
                if path:
                    ws_settings["path"] = path
                if ws_host:
                    ws_settings["headers"] = {"Host": ws_host}
                if ws_settings:
                    stream["wsSettings"] = ws_settings

            outbound["streamSettings"] = stream
            return {
                "protocol": "vmess",
                "host": host,
                "port": port,
                "remark": remark,
                "outbound_tag": outbound_tag,
                "outbound": outbound,
                "display": f"VMess ({network}) {host}:{port}"
            }

        # 2. VLESS
        if raw.startswith("vless://"):
            u = urllib.parse.urlparse(raw)
            uuid_str = u.username or ""
            if not is_valid_hex_uuid(uuid_str):
                raise Exception(f"VLESS 节点 UUID 格式非法: '{uuid_str}' (必须为32位十六进制字符)")
            host = u.hostname
            port = u.port or 443
            remark = urllib.parse.unquote(u.fragment) or host
            params = urllib.parse.parse_qs(u.query)
            network = params.get("type", ["tcp"])[0]
            security = params.get("security", ["none"])[0]
            sni = params.get("sni", [""])[0] or host

            outbound_tag = f"vless-{host}-{port}"
            outbound = {
                "tag": outbound_tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid_str,
                            "encryption": params.get("encryption", ["none"])[0]
                        }]
                    }]
                },
                "streamSettings": {
                    "network": network,
                    "security": security
                }
            }
            if security == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": sni,
                    "publicKey": params.get("pbk", [""])[0],
                    "shortId": params.get("sid", [""])[0],
                    "fingerprint": params.get("fp", ["chrome"])[0]
                }
            elif security == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": sni
                }
            return {
                "protocol": "vless",
                "host": host,
                "port": port,
                "remark": remark,
                "outbound_tag": outbound_tag,
                "outbound": outbound,
                "display": f"VLESS ({security}) {host}:{port}"
            }

        # 3. Trojan
        if raw.startswith("trojan://"):
            u = urllib.parse.urlparse(raw)
            pwd = u.username or ""
            host = u.hostname
            port = u.port or 443
            remark = urllib.parse.unquote(u.fragment) or host
            params = urllib.parse.parse_qs(u.query)
            sni = params.get("sni", [""])[0] or params.get("peer", [""])[0] or host

            outbound_tag = f"trojan-{host}-{port}"
            outbound = {
                "tag": outbound_tag,
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "password": pwd
                    }]
                },
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": sni
                    }
                }
            }
            return {
                "protocol": "trojan",
                "host": host,
                "port": port,
                "remark": remark,
                "outbound_tag": outbound_tag,
                "outbound": outbound,
                "display": f"Trojan {host}:{port}"
            }

        # 4. Shadowsocks
        if raw.startswith("ss://"):
            body = raw[5:]
            remark = host = ""
            if "#" in body:
                body, remark = body.split("#", 1)
                remark = urllib.parse.unquote(remark)
            if "@" in body:
                auth_part, hp_part = body.split("@", 1)
                try:
                    missing_padding = len(auth_part) % 4
                    if missing_padding != 0: auth_part += '=' * (4 - missing_padding)
                    decoded_auth = base64.b64decode(auth_part).decode()
                    if ":" in decoded_auth:
                        method, pwd = decoded_auth.split(":", 1)
                    else:
                        method, pwd = auth_part.split(":", 1)
                except Exception:
                    method, pwd = auth_part.split(":", 1)
                host, port_str = hp_part.split(":", 1)
                port = int(port_str.split("/")[0])
            else:
                missing_padding = len(body) % 4
                if missing_padding != 0: body += '=' * (4 - missing_padding)
                decoded = base64.b64decode(body).decode()
                auth_part, hp = decoded.split("@", 1)
                method, pwd = auth_part.split(":", 1)
                host, port_str = hp.split(":", 1)
                port = int(port_str.split("/")[0])

            remark = remark or host
            outbound_tag = f"ss-{host}-{port}"
            outbound = {
                "tag": outbound_tag,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "method": method,
                        "password": pwd
                    }]
                }
            }
            return {
                "protocol": "shadowsocks",
                "host": host,
                "port": port,
                "remark": remark,
                "outbound_tag": outbound_tag,
                "outbound": outbound,
                "display": f"Shadowsocks {host}:{port}"
            }

        # 5. HTTP
        if raw.startswith("http://"):
            line = raw[7:]
            user = pwd = ""
            if "@" in line:
                auth, hp = line.split("@", 1)
                if ":" in auth: user, pwd = auth.split(":", 1)
                else: user = auth
                h, p = hp.split(":", 1)
                host = h
                port = int(p.split("/")[0])
            else:
                h, p = line.split(":", 1)
                host = h
                port = int(p.split("/")[0])
            outbound_tag = f"http-{host}-{port}"
            srv_obj = {"address": host, "port": port}
            if user or pwd:
                srv_obj["users"] = [{"user": user, "pass": pwd}]
            outbound = {
                "tag": outbound_tag,
                "protocol": "http",
                "settings": {"servers": [srv_obj]}
            }
            return {
                "protocol": "http",
                "host": host,
                "port": port,
                "user": user,
                "pass": pwd,
                "remark": host,
                "outbound_tag": outbound_tag,
                "outbound": outbound,
                "display": f"HTTP {host}:{port}"
            }

        # 6. Socks5 / 纯 IP:Port:User:Pass
        line = raw
        if line.startswith("socks5://"): line = line[9:]
        elif line.startswith("socks://"): line = line[8:]
        host = user = pwd = ""
        port = 0
        if "@" in line:
            auth_part, host_part = line.split("@", 1)
            if ":" in auth_part: user, pwd = auth_part.split(":", 1)
            else: user = auth_part
            if ":" in host_part:
                h, p = host_part.split(":", 1)
                host = h
                port = int(p.split("/")[0])
            else:
                host = host_part
        else:
            parts = line.split(":")
            if len(parts) == 4:
                host = parts[0]; port = int(parts[1]); user = parts[2]; pwd = parts[3]
            elif len(parts) == 2:
                host = parts[0]; port = int(parts[1].split("/")[0])
            elif len(parts) == 3:
                host = parts[0]; port = int(parts[1]); user = parts[2]
            else:
                return None

        outbound_tag = f"socks5-{host}-{port}"
        srv_obj = {"address": host, "port": port}
        if user or pwd:
            srv_obj["users"] = [{"user": user, "pass": pwd}]
        outbound = {
            "tag": outbound_tag,
            "protocol": "socks",
            "settings": {"servers": [srv_obj]}
        }
        return {
            "protocol": "socks",
            "host": host,
            "port": port,
            "user": user,
            "pass": pwd,
            "remark": host,
            "outbound_tag": outbound_tag,
            "outbound": outbound,
            "display": f"Socks5 {host}:{port}"
        }

# ==================== 节点连通性测试 ====================
def test_node_connectivity(node_data, timeout=5):
    protocol = node_data.get("protocol", "tcp")
    host = node_data.get("host")
    port = int(node_data.get("port", 0))
    user = node_data.get("user", "")
    pwd = node_data.get("pass", "")

    if protocol == "socks":
        start_time = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            if user and pwd:
                s.sendall(b"\x05\x02\x00\x02")
                resp = s.recv(2)
                if len(resp) < 2 or resp[0] != 0x05:
                    return {"ok": False, "error": "Socks5握手失败"}
                if resp[1] == 0x02:
                    u_b, p_b = user.encode(), pwd.encode()
                    s.sendall(b"\x01" + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b)
                    auth_resp = s.recv(2)
                    if len(auth_resp) < 2 or auth_resp[1] != 0x00:
                        return {"ok": False, "error": "Socks5认证失败(密码错误)"}
            else:
                s.sendall(b"\x05\x01\x00")
                resp = s.recv(2)
                if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
                    return {"ok": False, "error": "需要认证或握手失败"}

            domain = b"api.ipify.org"
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + (80).to_bytes(2, "big"))
            connect_resp = s.recv(10)
            if len(connect_resp) < 4 or connect_resp[1] != 0x00:
                return {"ok": False, "error": "目标连接失败"}

            s.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
            http_resp = s.recv(1024)
            elapsed = int((time.time() - start_time) * 1000)
            s.close()
            exit_ip = ""
            content = http_resp.decode(errors="replace")
            if "\r\n\r\n" in content:
                exit_ip = content.split("\r\n\r\n", 1)[1].strip().splitlines()[0].strip()
            return {"ok": True, "latency": elapsed, "exit_ip": exit_ip or host}
        except Exception as e:
            return {"ok": False, "error": str(e)}
        finally:
            try: s.close()
            except Exception: pass

    start_time = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        elapsed = int((time.time() - start_time) * 1000)
        s.close()
        return {"ok": True, "latency": elapsed, "exit_ip": host}
    except Exception as e:
        return {"ok": False, "error": f"端口连接失败: {e}"}
    finally:
        try: s.close()
        except Exception: pass

# ==================== Clash Meta (Mihomo) 配置生成器 ====================
def generate_clash_meta_yaml(nodes, group_name="全部节点", server_ip=SERVER_IP):
    lines = []
    lines.append("# ========================================================")
    lines.append(f"# Clash Meta (Mihomo) 配置文件 - 分组: {group_name}")
    lines.append(f"# 服务器: {server_ip} | 节点数量: {len(nodes)}")
    lines.append("# ========================================================\n")
    lines.append("port: 7890")
    lines.append("socks-port: 7891")
    lines.append("allow-lan: true")
    lines.append("mode: rule")
    lines.append("log-level: info")
    lines.append("external-controller: 127.0.0.1:9090\n")
    lines.append("dns:")
    lines.append("  enable: true")
    lines.append("  ipv6: false")
    lines.append("  enhanced-mode: fake-ip")
    lines.append("  fake-ip-range: 198.18.0.1/16")
    lines.append("  nameserver:")
    lines.append("    - 119.29.29.29")
    lines.append("    - 223.5.5.5")
    lines.append("  fallback:")
    lines.append("    - 8.8.8.8")
    lines.append("    - 1.1.1.1\n")

    lines.append("proxies:")
    node_names = []
    ip_counter = {}
    for n in nodes:
        out = n.get("outbound") or {}
        exit_ip = (out.get("host") or n.get("remark") or "node").strip()
        # 剥离任何可能存在的端口（如 1.1.1.1:8080 或 1.1.1.1-8080）
        if ":" in exit_ip and not exit_ip.startswith("["):
            exit_ip = exit_ip.split(":")[0].strip()
        if "-" in exit_ip:
            parts = exit_ip.rsplit("-", 1)
            if parts[1].isdigit():
                exit_ip = parts[0].strip()

        # 如果出现相同落地 IP，为保证 Clash Meta 规范不冲突，追加序号；单节点直接为纯落地 IP
        if exit_ip not in ip_counter:
            ip_counter[exit_ip] = 1
            name = exit_ip
        else:
            ip_counter[exit_ip] += 1
            name = f"{exit_ip} ({ip_counter[exit_ip]})"

        node_names.append(name)
        lines.append(f'  - name: "{name}"')
        lines.append("    type: vless")
        lines.append(f"    server: {server_ip}")
        lines.append(f"    port: {n.get('port')}")
        lines.append(f'    uuid: "{n.get("uuid")}"')
        lines.append("    network: tcp")
        lines.append("    udp: true")
        lines.append("    tls: true")
        lines.append('    flow: ""')
        lines.append(f'    servername: "{n.get("sni", "apple.com")}"')
        lines.append("    reality-opts:")
        lines.append(f'      public-key: "{n.get("public_key")}"')
        lines.append(f'      short-id: "{n.get("short_id", "")}"')
        lines.append("    client-fingerprint: chrome\n")

    if not node_names:
        node_names = ["DIRECT"]

    lines.append("proxy-groups:")
    lines.append('  - name: "节点选择"')
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append('      - "自动选择"')
    for name in node_names:
        lines.append(f'      - "{name}"')
    lines.append('      - "DIRECT"\n')

    lines.append('  - name: "自动选择"')
    lines.append("    type: url-test")
    lines.append('    url: "http://www.gstatic.com/generate_204"')
    lines.append("    interval: 300")
    lines.append("    tolerance: 50")
    lines.append("    proxies:")
    for name in node_names:
        lines.append(f'      - "{name}"')
    lines.append("\nrules:")
    lines.append("  - GEOIP,CN,DIRECT")
    lines.append("  - GEOSITE,CN,DIRECT")
    lines.append("  - MATCH,节点选择")

    return "\n".join(lines)

# ==================== x-ui 数据库管理 ====================
class XuiManager:
    def __init__(self, db_path=None):
        self.db_path = db_path or CURRENT_CONFIG.get("db_path", DEFAULT_DB_PATH)
        self.init_db()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        """确保 relay_groups 与 relay_groups_config 表结构存在"""
        try:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS relay_groups_config (
                    name TEXT PRIMARY KEY,
                    traffic_limit INTEGER DEFAULT 0,
                    is_paused INTEGER DEFAULT 0
                );
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS relay_groups (
                    inbound_id INTEGER PRIMARY KEY,
                    group_name TEXT NOT NULL
                );
            """)
            c.execute("INSERT OR IGNORE INTO relay_groups_config (name, traffic_limit, is_paused) VALUES (?, 0, 0);", (DEFAULT_GROUP,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Warn] init_db failed: {e}")

    def ensure_xray_alive(self):
        """检查 Xray 进程及配置文件自愈"""
        try:
            cfg_path = "/usr/local/x-ui/bin/config.json"
            if os.path.exists(cfg_path) and os.path.exists(XRAY_BIN):
                res = subprocess.run([XRAY_BIN, "-test", "-config", cfg_path], capture_output=True, text=True, timeout=5)
                if res.returncode != 0:
                    print(f"[Self-Healing] Xray config test failed: {res.stdout} {res.stderr}")
                    conn = self.get_connection()
                    c = conn.cursor()
                    tpl = self.get_template_config(c)
                    tpl = self.verify_template_safety(tpl)
                    self.save_template_config(c, tpl)
                    conn.commit()
                    conn.close()
                    self.restart_xui()
        except Exception as e:
            print(f"[Self-Healing Error] {e}")

    def restart_xui(self):
        try:
            subprocess.run(["systemctl", "restart", "x-ui"], check=True, timeout=10)
            return True, "x-ui 重启成功"
        except Exception as e:
            return False, f"x-ui 重启失败: {e}"

    def get_template_config(self, cursor):
        cursor.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig';")
        row = cursor.fetchone()
        if not row:
            raise Exception("未在数据库中找到 xrayTemplateConfig 设置")
        return json.loads(row[0])

    def save_template_config(self, cursor, cfg_dict):
        json_str = json.dumps(cfg_dict, indent=4, ensure_ascii=False)
        cursor.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig';", (json_str,))

    def get_used_ports(self):
        used = set()
        try:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("SELECT port FROM inbounds;")
            for r in c.fetchall():
                used.add(r[0])
            conn.close()
        except Exception:
            pass
        return used

    def allocate_port(self, preferred_port=None):
        used = self.get_used_ports()
        if preferred_port and 1024 <= preferred_port <= 65535:
            if preferred_port not in used:
                return preferred_port
        import random
        for _ in range(100):
            p = random.randint(20000, 60000)
            if p not in used:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind(("0.0.0.0", p))
                    s.close()
                    return p
                except Exception:
                    used.add(p)
        raise Exception("无法在 20000-60000 范围找到空闲端口")

    def get_all_group_names(self):
        names = set([DEFAULT_GROUP])
        try:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("SELECT name FROM relay_groups_config;")
            for r in c.fetchall():
                if r[0]: names.add(r[0])
            c.execute("SELECT DISTINCT group_name FROM relay_groups WHERE group_name IS NOT NULL AND group_name != '';")
            for r in c.fetchall():
                if r[0]: names.add(r[0])
            conn.close()
        except Exception:
            pass
        return sorted(list(names))

    def get_groups_detail(self):
        """获取所有分组的详细数据（节点数、流量统计、限额、超限状态）"""
        conn = self.get_connection()
        c = conn.cursor()

        c.execute("SELECT name, traffic_limit, is_paused FROM relay_groups_config;")
        config_rows = {r[0]: {"limit": r[1], "is_paused": r[2]} for r in c.fetchall()}

        c.execute("""
            SELECT 
                COALESCE(relay_groups.group_name, ?) as gname,
                COUNT(inbounds.id) as node_count,
                COALESCE(SUM(inbounds.up), 0) as total_up,
                COALESCE(SUM(inbounds.down), 0) as total_down
            FROM inbounds
            LEFT JOIN relay_groups ON inbounds.id = relay_groups.inbound_id
            GROUP BY gname;
        """, (DEFAULT_GROUP,))
        stats_rows = c.fetchall()
        conn.close()

        groups = []
        seen = set()
        for r in stats_rows:
            gname = r[0]
            seen.add(gname)
            cfg = config_rows.get(gname, {"limit": 0, "is_paused": 0})
            total_bytes = r[2] + r[3]
            limit_bytes = cfg["limit"]
            is_exceeded = (limit_bytes > 0 and total_bytes >= limit_bytes)
            groups.append({
                "name": gname,
                "node_count": r[1],
                "up": r[2],
                "down": r[3],
                "total": total_bytes,
                "limit": limit_bytes,
                "is_paused": bool(cfg["is_paused"]),
                "is_exceeded": is_exceeded
            })

        for gname, cfg in config_rows.items():
            if gname not in seen:
                groups.append({
                    "name": gname,
                    "node_count": 0,
                    "up": 0,
                    "down": 0,
                    "total": 0,
                    "limit": cfg["limit"],
                    "is_paused": bool(cfg["is_paused"]),
                    "is_exceeded": False
                })

        return sorted(groups, key=lambda x: x["name"])

    def create_or_update_group(self, name, limit_bytes=0):
        name = (name or DEFAULT_GROUP).strip()
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO relay_groups_config (name, traffic_limit, is_paused)
            VALUES (?, ?, 0)
            ON CONFLICT(name) DO UPDATE SET traffic_limit=?;
        """, (name, limit_bytes, limit_bytes))
        conn.commit()
        conn.close()
        # 立即检查是否需要恢复或暂停
        self.check_traffic_limits()
        return True

    def set_group_pause(self, group_name, pause: bool):
        """暂停或恢复某个分组（开启/关闭该分组所有节点）"""
        conn = self.get_connection()
        c = conn.cursor()
        enable_val = 0 if pause else 1
        is_paused_val = 1 if pause else 0
        c.execute("""
            UPDATE inbounds 
            SET enable=?
            WHERE id IN (
                SELECT inbounds.id FROM inbounds 
                LEFT JOIN relay_groups ON inbounds.id = relay_groups.inbound_id
                WHERE COALESCE(relay_groups.group_name, ?) = ?
            );
        """, (enable_val, DEFAULT_GROUP, group_name))
        c.execute("UPDATE relay_groups_config SET is_paused=? WHERE name=?;", (is_paused_val, group_name))
        conn.commit()
        conn.close()
        self.restart_xui()
        return True

    def reset_group_traffic(self, group_name):
        """重置某个分组内所有节点的上下行流量统计"""
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("""
            UPDATE inbounds 
            SET up=0, down=0
            WHERE id IN (
                SELECT inbounds.id FROM inbounds 
                LEFT JOIN relay_groups ON inbounds.id = relay_groups.inbound_id
                WHERE COALESCE(relay_groups.group_name, ?) = ?
            );
        """, (DEFAULT_GROUP, group_name))
        conn.commit()
        conn.close()
        # 流量重置后自动恢复该分组节点
        self.set_group_pause(group_name, pause=False)
        return True

    def delete_group(self, group_name):
        """删除分组（组内节点转移至默认分组）"""
        if group_name == DEFAULT_GROUP:
            return False, "默认分组不可删除"
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("UPDATE relay_groups SET group_name=? WHERE group_name=?;", (DEFAULT_GROUP, group_name))
        c.execute("DELETE FROM relay_groups_config WHERE name=?;", (group_name,))
        conn.commit()
        conn.close()
        return True, "分组已删除"

    def set_node_group(self, inbound_id, group_name):
        group_name = (group_name or DEFAULT_GROUP).strip()
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO relay_groups_config (name, traffic_limit, is_paused) VALUES (?, 0, 0);", (group_name,))
        c.execute("INSERT INTO relay_groups (inbound_id, group_name) VALUES (?, ?) ON CONFLICT(inbound_id) DO UPDATE SET group_name=?;", (inbound_id, group_name, group_name))
        conn.commit()
        conn.close()
        self.check_traffic_limits()
        return True

    def check_traffic_limits(self):
        """核心风控：巡检各分组流量，超出限额则暂停该组全部节点"""
        groups = self.get_groups_detail()
        triggered = False
        for g in groups:
            limit = g["limit"]
            total = g["total"]
            gname = g["name"]
            is_paused = g["is_paused"]

            if limit > 0 and total >= limit:
                if not is_paused:
                    print(f"[Traffic Limiter] 警告: 分组 [{gname}] 累计流量 {total} 超过限制 {limit} 字节，执行暂停所有节点！")
                    self.set_group_pause(gname, pause=True)
                    triggered = True
        return triggered

    def list_relay_nodes(self, target_group=None):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        template = self.get_template_config(c)
        rules = template.get("routing", {}).get("rules", [])
        outbounds = {o.get("tag"): o for o in template.get("outbounds", []) if o.get("tag")}

        inbound_to_outbound = {}
        for r in rules:
            in_tags = r.get("inboundTag", [])
            out_tag = r.get("outboundTag")
            if out_tag and in_tags:
                for tag in in_tags:
                    if out_tag in outbounds:
                        inbound_to_outbound[tag] = outbounds[out_tag]

        c.execute("""
            SELECT inbounds.*, relay_groups.group_name
            FROM inbounds
            LEFT JOIN relay_groups ON inbounds.id = relay_groups.inbound_id
            ORDER BY inbounds.id DESC;
        """)
        inbound_rows = c.fetchall()
        conn.close()

        nodes = []
        server_ip = CURRENT_CONFIG.get("server_ip", SERVER_IP)

        for row in inbound_rows:
            tag = row["tag"]
            out_info = inbound_to_outbound.get(tag)

            try: in_settings = json.loads(row["settings"])
            except Exception: in_settings = {}
            try: in_streams = json.loads(row["stream_settings"])
            except Exception: in_streams = {}

            clients = in_settings.get("clients", [])
            client_id = clients[0].get("id", "") if clients else ""
            
            reality = in_streams.get("realitySettings", {})
            pub_key = reality.get("publicKey", "")
            short_ids = reality.get("shortIds", [""])
            sid = short_ids[0] if short_ids else ""
            server_names = reality.get("serverNames", [DEFAULT_SNI])
            sni = server_names[0] if server_names else DEFAULT_SNI

            remark = row["remark"] or f"relay-{row['port']}"
            port = row["port"]
            group_name = row["group_name"] or DEFAULT_GROUP

            if target_group and target_group not in ("全部", "全部分组") and group_name != target_group:
                continue

            clean_remark = remark
            if ":" in clean_remark and not clean_remark.startswith("["):
                clean_remark = clean_remark.split(":")[0].strip()
            if "-" in clean_remark:
                parts = clean_remark.rsplit("-", 1)
                if parts[1].isdigit():
                    clean_remark = parts[0].strip()

            vless_link = f"vless://{client_id}@{server_ip}:{port}?security=reality&encryption=none&pbk={pub_key}&headerType=none&fp=chrome&type=tcp&sni={sni}&sid={sid}#{urllib.parse.quote(clean_remark)}"

            node_outbound_info = None
            if out_info:
                proto = out_info.get("protocol", "unknown")
                display = f"{proto.upper()} [{out_info.get('tag')}]"
                target_host = ""
                target_port = 0
                user_str = ""

                if proto in ("socks", "http", "shadowsocks", "trojan"):
                    srvs = out_info.get("settings", {}).get("servers", [{}])
                    if srvs:
                        target_host = srvs[0].get("address", "")
                        target_port = srvs[0].get("port", 0)
                        users = srvs[0].get("users", [{}])
                        if users: user_str = users[0].get("user", "")
                elif proto in ("vmess", "vless"):
                    vnext = out_info.get("settings", {}).get("vnext", [{}])
                    if vnext:
                        target_host = vnext[0].get("address", "")
                        target_port = vnext[0].get("port", 0)

                net = out_info.get("streamSettings", {}).get("network", "")
                if net:
                    display = f"{proto.upper()} ({net}) {target_host}:{target_port}"
                elif target_host:
                    display = f"{proto.upper()} {target_host}:{target_port}"

                node_outbound_info = {
                    "protocol": proto,
                    "host": target_host,
                    "port": target_port,
                    "user": user_str,
                    "tag": out_info.get("tag", ""),
                    "display": display
                }

            nodes.append({
                "id": row["id"],
                "port": port,
                "protocol": row["protocol"],
                "remark": remark,
                "group": group_name,
                "enable": bool(row["enable"]),
                "up": row["up"],
                "down": row["down"],
                "total": row["total"],
                "uuid": client_id,
                "public_key": pub_key,
                "short_id": sid,
                "sni": sni,
                "vless_link": vless_link,
                "is_relay": node_outbound_info is not None,
                "outbound": node_outbound_info
            })

        return nodes

    def add_relay_node(self, node_info, remark=None, custom_port=None, sni=None, group_name=DEFAULT_GROUP):
        outbound_tag = node_info["outbound_tag"]
        new_outbound = node_info["outbound"]
        host = node_info.get("host", "")
        remark = remark or node_info.get("remark") or host
        group_name = (group_name or DEFAULT_GROUP).strip()

        conn = self.get_connection()
        c = conn.cursor()

        try:
            port = self.allocate_port(custom_port)
            inbound_tag = f"inbound-{port}"
            sni = sni or CURRENT_CONFIG.get("default_sni", DEFAULT_SNI)

            priv_key, pub_key = XrayHelper.generate_x25519()
            client_id = XrayHelper.generate_uuid()
            sid = XrayHelper.generate_short_id()

            template = self.get_template_config(c)
            outbounds = template.get("outbounds", [])
            rules = template.get("routing", {}).get("rules", [])

            outbounds = [o for o in outbounds if o.get("tag") != outbound_tag]
            outbounds.append(new_outbound)
            template["outbounds"] = outbounds

            new_rule = {
                "type": "field",
                "inboundTag": [inbound_tag],
                "outboundTag": outbound_tag
            }
            rules = [r for r in rules if r.get("inboundTag") != [inbound_tag]]
            rules.insert(0, new_rule)
            template["routing"]["rules"] = rules

            self.save_template_config(c, template)

            in_settings = {
                "clients": [{"id": client_id, "flow": ""}],
                "decryption": "none",
                "encryption": "none",
                "selectedAuth": "none"
            }
            in_streams = {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "fingerprint": "chrome",
                    "target": f"{sni}:443",
                    "xver": 0,
                    "serverNames": [sni],
                    "privateKey": priv_key,
                    "publicKey": pub_key,
                    "mldsa65Seed": "",
                    "mldsa65Verify": "",
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimeDiff": 0,
                    "shortIds": [sid]
                },
                "tcpSettings": {
                    "header": {"type": "none"}
                }
            }
            in_sniffing = {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"]
            }

            c.execute("""
                INSERT INTO inbounds (
                    user_id, up, down, total, remark, enable, expiry_time,
                    listen, port, protocol, settings, stream_settings, tag, sniffing
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                1, 0, 0, 0, remark, 1, 0,
                "", port, "vless",
                json.dumps(in_settings, indent=2),
                json.dumps(in_streams, indent=2),
                inbound_tag,
                json.dumps(in_sniffing, indent=2)
            ))

            new_inbound_id = c.lastrowid
            c.execute("INSERT OR IGNORE INTO relay_groups_config (name, traffic_limit, is_paused) VALUES (?, 0, 0);", (group_name,))
            c.execute("INSERT OR REPLACE INTO relay_groups (inbound_id, group_name) VALUES (?, ?);", (new_inbound_id, group_name))

            conn.commit()
            conn.close()

            self.restart_xui()

            server_ip = CURRENT_CONFIG.get("server_ip", SERVER_IP)
            vless_link = f"vless://{client_id}@{server_ip}:{port}?security=reality&encryption=none&pbk={pub_key}&headerType=none&fp=chrome&type=tcp&sni={sni}&sid={sid}#{urllib.parse.quote(remark)}"

            return {
                "success": True,
                "id": new_inbound_id,
                "port": port,
                "remark": remark,
                "group": group_name,
                "uuid": client_id,
                "public_key": pub_key,
                "short_id": sid,
                "sni": sni,
                "vless_link": vless_link,
                "outbound": node_info
            }
        except Exception as e:
            conn.rollback()
            conn.close()
            raise e

    def delete_node(self, inbound_id):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        try:
            c.execute("SELECT * FROM inbounds WHERE id=?;", (inbound_id,))
            inbound = c.fetchone()
            if not inbound:
                conn.close()
                return False, "未找到该入站节点"

            inbound_tag = inbound["tag"]
            template = self.get_template_config(c)
            rules = template.get("routing", {}).get("rules", [])
            outbounds = template.get("outbounds", [])

            matched_outbounds = set()
            new_rules = []
            for r in rules:
                if inbound_tag in r.get("inboundTag", []):
                    matched_outbounds.add(r.get("outboundTag"))
                else:
                    new_rules.append(r)
            template["routing"]["rules"] = new_rules

            for out_tag in matched_outbounds:
                still_used = False
                for r in new_rules:
                    if r.get("outboundTag") == out_tag:
                        still_used = True
                        break
                if not still_used:
                    outbounds = [o for o in outbounds if o.get("tag") != out_tag]
            template["outbounds"] = outbounds

            self.save_template_config(c, template)

            c.execute("DELETE FROM inbounds WHERE id=?;", (inbound_id,))
            c.execute("DELETE FROM relay_groups WHERE inbound_id=?;", (inbound_id,))
            conn.commit()
            conn.close()

            self.restart_xui()
            return True, "删除成功并已重载配置"
        except Exception as e:
            conn.rollback()
            conn.close()
            return False, f"删除失败: {e}"

# 后台流量巡检守护线程
def traffic_guard_worker():
    mgr = XuiManager()
    while True:
        try:
            mgr.check_traffic_limits()
            # 检查 xray 核心是否正常运行，若不正常则执行自愈与重启
            mgr.ensure_xray_alive()
        except Exception as e:
            print(f"[Guard Worker Error] {e}")
        time.sleep(30)

guard_thread = threading.Thread(target=traffic_guard_worker, daemon=True)
guard_thread.start()

# ==================== Web Request Handler ====================
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class RelayWebHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def send_json(self, data, status=200, cookie=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def is_authenticated(self):
        # 1. Bearer Token 或 X-API-Key
        auth_header = self.headers.get("Authorization", "").strip()
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token in (CURRENT_CONFIG.get("password"), CURRENT_CONFIG.get("sub_token")):
                return True
        api_key = self.headers.get("X-API-Key", "").strip()
        if api_key and api_key in (CURRENT_CONFIG.get("password"), CURRENT_CONFIG.get("sub_token")):
            return True

        # 2. Query 参数 token
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if "token" in qs:
            token = qs["token"][0]
            if token in (CURRENT_CONFIG.get("password"), CURRENT_CONFIG.get("sub_token")):
                return True

        # 3. Cookie session
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            for c in cookie_header.split(";"):
                c = c.strip()
                if c.startswith("relay_session="):
                    token = c.split("=", 1)[1]
                    if token in SESSIONS:
                        return True
        return False

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/ping":
            return self.send_json({
                "pong": True,
                "server_ip": CURRENT_CONFIG.get("server_ip", SERVER_IP),
                "version": "2.0",
                "auth": self.is_authenticated()
            })

        if path == "/api/qrcode":
            txt = query.get("text", [""])[0]
            if not txt:
                self.send_response(400)
                self.end_headers()
                return
            try:
                res = subprocess.run(["qrencode", "-t", "SVG", "-m", "2", "-o", "-", txt], capture_output=True, timeout=3)
                if res.returncode == 0:
                    self.send_response(200)
                    self.send_header("Content-Type", "image/svg+xml")
                    self.send_header("Content-Length", str(len(res.stdout)))
                    self.end_headers()
                    self.wfile.write(res.stdout)
                    return
            except Exception:
                pass
            self.send_response(500)
            self.end_headers()
            return

        # Clash Meta 订阅 / 下载接口
        if path in ("/api/clash/config.yaml", "/clash"):
            req_token = query.get("token", [""])[0]
            valid_token = CURRENT_CONFIG.get("sub_token")
            if not self.is_authenticated() and (not req_token or req_token != valid_token):
                return self.send_json({"error": "Unauthorized subscription token"}, 401)

            target_group = urllib.parse.unquote(query.get("group", [""])[0]).strip() or None
            mgr = XuiManager()
            nodes = mgr.list_relay_nodes(target_group=target_group)
            yaml_content = generate_clash_meta_yaml(nodes, group_name=target_group or "全部分组", server_ip=CURRENT_CONFIG.get("server_ip", SERVER_IP))
            yaml_bytes = yaml_content.encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/x-yaml; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Disposition", 'attachment; filename="clash_meta.yaml"')
            self.send_header("Content-Length", str(len(yaml_bytes)))
            self.end_headers()
            self.wfile.write(yaml_bytes)
            return

        if path == "/api/status":
            if not self.is_authenticated():
                return self.send_json({"error": "Unauthorized", "auth": False}, 401)
            mgr = XuiManager()
            return self.send_json({
                "auth": True,
                "server_ip": CURRENT_CONFIG.get("server_ip", SERVER_IP),
                "port": CURRENT_CONFIG.get("port", DEFAULT_PORT),
                "db_path": CURRENT_CONFIG.get("db_path", DEFAULT_DB_PATH),
                "default_sni": CURRENT_CONFIG.get("default_sni", DEFAULT_SNI),
                "sub_token": CURRENT_CONFIG.get("sub_token"),
                "groups": mgr.get_all_group_names()
            })

        if path == "/api/nodes":
            if not self.is_authenticated():
                return self.send_json({"error": "Unauthorized"}, 401)
            target_group = urllib.parse.unquote(query.get("group", [""])[0]).strip() or None
            try:
                mgr = XuiManager()
                nodes = mgr.list_relay_nodes(target_group=target_group)
                groups_detail = mgr.get_groups_detail()
                return self.send_json({
                    "success": True, 
                    "nodes": nodes, 
                    "groups": [g["name"] for g in groups_detail],
                    "groups_detail": groups_detail
                })
            except Exception as e:
                return self.send_json({"success": False, "error": str(e)}, 500)

        if path == "/api/groups":
            if not self.is_authenticated():
                return self.send_json({"error": "Unauthorized"}, 401)
            mgr = XuiManager()
            return self.send_json({
                "success": True, 
                "groups": mgr.get_groups_detail()
            })

        if path == "/api/clash/export":
            if not self.is_authenticated():
                return self.send_json({"error": "Unauthorized"}, 401)
            target_group = urllib.parse.unquote(query.get("group", [""])[0]).strip() or None
            try:
                mgr = XuiManager()
                nodes = mgr.list_relay_nodes(target_group=target_group)
                yaml_content = generate_clash_meta_yaml(nodes, group_name=target_group or "全部分组", server_ip=CURRENT_CONFIG.get("server_ip", SERVER_IP))
                sub_url = f"http://{CURRENT_CONFIG.get('server_ip', SERVER_IP)}:{CURRENT_CONFIG.get('port', DEFAULT_PORT)}/api/clash/config.yaml?token={CURRENT_CONFIG.get('sub_token')}"
                if target_group:
                    sub_url += f"&group={urllib.parse.quote(target_group)}"
                return self.send_json({
                    "success": True,
                    "yaml": yaml_content,
                    "group": target_group or "全部分组",
                    "count": len(nodes),
                    "sub_url": sub_url
                })
            except Exception as e:
                return self.send_json({"success": False, "error": str(e)}, 500)

        if path == "/api/export":
            if not self.is_authenticated():
                return self.send_json({"error": "Unauthorized"}, 401)
            target_group = urllib.parse.unquote(query.get("group", [""])[0]).strip() or None
            try:
                mgr = XuiManager()
                nodes = mgr.list_relay_nodes(target_group=target_group)
                links = [n["vless_link"] for n in nodes if n.get("vless_link")]
                return self.send_json({"success": True, "links": links, "raw": "\n".join(links)})
            except Exception as e:
                return self.send_json({"success": False, "error": str(e)}, 500)

        if path in ("/", "/index.html"):
            tmpl_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
            if os.path.exists(tmpl_path):
                with open(tmpl_path, "r", encoding="utf-8") as f:
                    html_content = f.read()
                data = html_content.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            params = json.loads(body) if body else {}
        except Exception:
            params = {}

        if path == "/api/login":
            u = (params.get("username") or "").strip()
            p = (params.get("password") or "").strip()
            if u == CURRENT_CONFIG.get("username") and p == CURRENT_CONFIG.get("password"):
                token = secrets.token_hex(24)
                SESSIONS.add(token)
                cookie = f"relay_session={token}; Path=/; HttpOnly; Max-Age=2592000"
                return self.send_json({"success": True, "msg": "登录成功"}, cookie=cookie)
            return self.send_json({"success": False, "error": "用户名或密码错误"}, 401)

        if path == "/api/logout":
            return self.send_json({"success": True}, cookie="relay_session=deleted; Path=/; Max-Age=0")

        if not self.is_authenticated():
            return self.send_json({"error": "Unauthorized"}, 401)

        if path == "/api/nodes/add":
            raw_input = (params.get("socks5_str") or params.get("node_str") or "").strip()
            remark = (params.get("remark") or "").strip() or None
            group_name = (params.get("group") or DEFAULT_GROUP).strip()
            custom_port = params.get("port")
            if custom_port:
                try: custom_port = int(custom_port)
                except Exception: custom_port = None
            sni = (params.get("sni") or "").strip() or None

            parsed_node = NodeParser.parse(raw_input)
            if not parsed_node:
                return self.send_json({"success": False, "error": "无法识别此节点格式，支持 Socks5/VMess/VLESS/Trojan/SS/HTTP"}, 400)

            try:
                mgr = XuiManager()
                res = mgr.add_relay_node(parsed_node, remark=remark, custom_port=custom_port, sni=sni, group_name=group_name)
                return self.send_json({"success": True, "node": res})
            except Exception as e:
                return self.send_json({"success": False, "error": str(e)}, 500)

        if path == "/api/nodes/batch-add":
            batch_text = (params.get("batch_text") or "").strip()
            group_name = (params.get("group") or DEFAULT_GROUP).strip()
            sni = (params.get("sni") or "").strip() or None
            lines = [l.strip() for l in batch_text.splitlines() if l.strip()]
            if not lines:
                return self.send_json({"success": False, "error": "没有输入有效的节点行"}, 400)

            mgr = XuiManager()
            success_nodes = []
            errors = []

            for line in lines:
                parsed_node = NodeParser.parse(line)
                if not parsed_node:
                    errors.append(f"解析失败: {line[:30]}...")
                    continue
                try:
                    res = mgr.add_relay_node(parsed_node, sni=sni, group_name=group_name)
                    success_nodes.append(res)
                except Exception as e:
                    errors.append(f"添加失败: {e}")

            return self.send_json({
                "success": True,
                "total": len(lines),
                "succeeded": len(success_nodes),
                "nodes": success_nodes,
                "errors": errors
            })

        if path == "/api/nodes/set-group":
            node_id = params.get("id")
            group_name = (params.get("group") or DEFAULT_GROUP).strip()
            if not node_id:
                return self.send_json({"success": False, "error": "缺少节点ID"}, 400)
            mgr = XuiManager()
            mgr.set_node_group(int(node_id), group_name)
            return self.send_json({"success": True, "msg": "分组已更新"})

        if path == "/api/nodes/delete":
            node_id = params.get("id")
            if not node_id:
                return self.send_json({"success": False, "error": "缺少节点ID"}, 400)
            mgr = XuiManager()
            ok, msg = mgr.delete_node(int(node_id))
            return self.send_json({"success": ok, "msg": msg})

        # 分组管理接口
        if path == "/api/groups/save":
            name = (params.get("name") or "").strip()
            if not name:
                return self.send_json({"success": False, "error": "分组名称不能为空"}, 400)
            limit_gb = float(params.get("limit_gb") or 0)
            limit_bytes = int(limit_gb * 1073741824) if limit_gb > 0 else 0
            mgr = XuiManager()
            mgr.create_or_update_group(name, limit_bytes=limit_bytes)
            return self.send_json({"success": True, "msg": f"分组 [{name}] 已保存"})

        if path == "/api/groups/toggle-pause":
            name = (params.get("name") or "").strip()
            pause = bool(params.get("pause"))
            mgr = XuiManager()
            mgr.set_group_pause(name, pause=pause)
            status_text = "已暂停该组所有节点" if pause else "已恢复该组所有节点"
            return self.send_json({"success": True, "msg": f"分组 [{name}] {status_text}"})

        if path == "/api/groups/reset-traffic":
            name = (params.get("name") or "").strip()
            mgr = XuiManager()
            mgr.reset_group_traffic(name)
            return self.send_json({"success": True, "msg": f"分组 [{name}] 流量已清零并恢复开启"})

        if path == "/api/groups/delete":
            name = (params.get("name") or "").strip()
            mgr = XuiManager()
            ok, msg = mgr.delete_group(name)
            return self.send_json({"success": ok, "msg": msg})

        if path == "/api/nodes/test":
            raw_input = (params.get("node_str") or params.get("socks5_str") or "").strip()
            host = (params.get("host") or "").strip()
            port = int(params.get("port") or 0)
            user = str(params.get("user") or "")
            pwd = str(params.get("pass") or "")
            proto = (params.get("protocol") or "socks").strip()

            if raw_input:
                parsed_node = NodeParser.parse(raw_input)
                if parsed_node:
                    test_res = test_node_connectivity(parsed_node)
                    return self.send_json({"success": True, "result": test_res})

            node_data = {
                "protocol": proto,
                "host": host,
                "port": port,
                "user": user,
                "pass": pwd
            }
            test_res = test_node_connectivity(node_data)
            return self.send_json({"success": True, "result": test_res})

        if path == "/api/settings/update":
            new_u = (params.get("username") or "").strip()
            new_p = (params.get("password") or "").strip()
            new_sni = (params.get("default_sni") or "").strip()
            reset_token = params.get("reset_token")
            if new_u: CURRENT_CONFIG["username"] = new_u
            if new_p: CURRENT_CONFIG["password"] = new_p
            if new_sni: CURRENT_CONFIG["default_sni"] = new_sni
            if reset_token: CURRENT_CONFIG["sub_token"] = secrets.token_hex(16)
            save_config(CURRENT_CONFIG)
            return self.send_json({"success": True, "msg": "配置已更新"})

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

def run_server():
    cfg = CURRENT_CONFIG
    port = int(cfg.get("port", DEFAULT_PORT))
    listen = cfg.get("listen", "0.0.0.0")
    server = ThreadedHTTPServer((listen, port), RelayWebHandler)
    print(f"==================================================")
    print(f" x-ui 全协议中转管理 Web 系统 已启动")
    print(f" 访问地址: http://{cfg.get('server_ip', '127.0.0.1')}:{port}")
    print(f" 初始账号: {cfg.get('username')}")
    print(f" 初始密码: {cfg.get('password')}")
    print(f"==================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务已停止")
        server.server_close()

if __name__ == "__main__":
    run_server()
