#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
x-ui 全协议中转节点 Web 管理服务
支持将 Socks5 / VMess / VLESS / Trojan / Shadowsocks / HTTP 落地节点
一键封装为统一的 VLESS + Reality 落地中转节点，并提供现代化网页管理面板。
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
        "listen": "0.0.0.0"
    }

def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

CURRENT_CONFIG = load_config()

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
        """调用 Xray 核心生成真实配对的 X25519 密钥对"""
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
class NodeParser:
    @staticmethod
    def parse(raw: str):
        """
        支持智能解析：
        1. vmess://<base64>
        2. vless://<uuid>@<host>:<port>?...#remark
        3. trojan://<password>@<host>:<port>?...#remark
        4. ss://<base64>#remark 或 ss://method:pass@host:port#remark
        5. http://user:pass@host:port 或 http://host:port
        6. socks5://user:pass@host:port 或 ip:port:user:pass 或 ip:port
        """
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
            uuid_str = u.username
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
    """通用连通性测试：Socks5协议执行原生握手测试，其他协议执行TCP端口握手"""
    protocol = node_data.get("protocol", "tcp")
    host = node_data.get("host")
    port = int(node_data.get("port", 0))
    user = node_data.get("user", "")
    pwd = node_data.get("pass", "")

    if protocol == "socks":
        # 原生 Socks5 握手测试
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

    # 其他协议进行 TCP 握手探测
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

# ==================== x-ui 数据库管理 ====================
class XuiManager:
    def __init__(self, db_path=None):
        self.db_path = db_path or CURRENT_CONFIG.get("db_path", DEFAULT_DB_PATH)

    def get_connection(self):
        return sqlite3.connect(self.db_path)

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

    def list_relay_nodes(self):
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

        c.execute("SELECT * FROM inbounds ORDER BY id DESC;")
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

            vless_link = f"vless://{client_id}@{server_ip}:{port}?security=reality&encryption=none&pbk={pub_key}&headerType=none&fp=chrome&type=tcp&sni={sni}&sid={sid}#{urllib.parse.quote(remark)}"

            node_outbound_info = None
            if out_info:
                proto = out_info.get("protocol", "unknown")
                display = f"{proto.upper()} [{out_info.get('tag')}]"
                target_host = ""
                target_port = 0
                user_str = ""

                # 提取目标地址
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

    def add_relay_node(self, node_info, remark=None, custom_port=None, sni=None):
        """核心方法：一键添加中转节点 (支持全协议)"""
        outbound_tag = node_info["outbound_tag"]
        new_outbound = node_info["outbound"]
        host = node_info.get("host", "")
        remark = remark or node_info.get("remark") or host

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

            # 替换或添加 outbound
            outbounds = [o for o in outbounds if o.get("tag") != outbound_tag]
            outbounds.append(new_outbound)
            template["outbounds"] = outbounds

            # 插入精准路由规则
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

            conn.commit()
            conn.close()

            self.restart_xui()

            server_ip = CURRENT_CONFIG.get("server_ip", SERVER_IP)
            vless_link = f"vless://{client_id}@{server_ip}:{port}?security=reality&encryption=none&pbk={pub_key}&headerType=none&fp=chrome&type=tcp&sni={sni}&sid={sid}#{urllib.parse.quote(remark)}"

            return {
                "success": True,
                "port": port,
                "remark": remark,
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
            conn.commit()
            conn.close()

            self.restart_xui()
            return True, "删除成功并已重载配置"
        except Exception as e:
            conn.rollback()
            conn.close()
            return False, f"删除失败: {e}"

# ==================== Web Request Handler ====================
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class RelayWebHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def send_json(self, data, status=200, cookie=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def is_authenticated(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return False
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

        if path == "/api/qrcode":
            query = urllib.parse.parse_qs(parsed.query)
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

        if path == "/api/status":
            if not self.is_authenticated():
                return self.send_json({"error": "Unauthorized", "auth": False}, 401)
            return self.send_json({
                "auth": True,
                "server_ip": CURRENT_CONFIG.get("server_ip", SERVER_IP),
                "port": CURRENT_CONFIG.get("port", DEFAULT_PORT),
                "db_path": CURRENT_CONFIG.get("db_path", DEFAULT_DB_PATH),
                "default_sni": CURRENT_CONFIG.get("default_sni", DEFAULT_SNI)
            })

        if path == "/api/nodes":
            if not self.is_authenticated():
                return self.send_json({"error": "Unauthorized"}, 401)
            try:
                mgr = XuiManager()
                nodes = mgr.list_relay_nodes()
                return self.send_json({"success": True, "nodes": nodes})
            except Exception as e:
                return self.send_json({"success": False, "error": str(e)}, 500)

        if path == "/api/export":
            if not self.is_authenticated():
                return self.send_json({"error": "Unauthorized"}, 401)
            try:
                mgr = XuiManager()
                nodes = mgr.list_relay_nodes()
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
                res = mgr.add_relay_node(parsed_node, remark=remark, custom_port=custom_port, sni=sni)
                return self.send_json({"success": True, "node": res})
            except Exception as e:
                return self.send_json({"success": False, "error": str(e)}, 500)

        if path == "/api/nodes/batch-add":
            batch_text = (params.get("batch_text") or "").strip()
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
                    res = mgr.add_relay_node(parsed_node, sni=sni)
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

        if path == "/api/nodes/delete":
            node_id = params.get("id")
            if not node_id:
                return self.send_json({"success": False, "error": "缺少节点ID"}, 400)
            mgr = XuiManager()
            ok, msg = mgr.delete_node(int(node_id))
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
            if new_u: CURRENT_CONFIG["username"] = new_u
            if new_p: CURRENT_CONFIG["password"] = new_p
            if new_sni: CURRENT_CONFIG["default_sni"] = new_sni
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
