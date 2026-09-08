#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
x-ui 静态IP中转节点 Web 管理服务
支持单节点/批量导入 Socks5 静态IP，自动生成 VLESS+Reality 落地中转节点，并提供现代化网页管理界面。
"""

import os
import sys
import json
import uuid
import time
import socket
import sqlite3
import secrets
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

# 全局内存会话存储
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
    """获取本机外网公网IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
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
        """生成 X25519 密钥对"""
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

# ==================== Socks5 解析器 ====================
class Socks5Parser:
    @staticmethod
    def parse(line: str):
        """
        支持格式：
        1. 82.110.39.8:7610:user:pass
        2. user:pass@82.110.39.8:7610
        3. socks5://user:pass@82.110.39.8:7610
        4. socks5://82.110.39.8:7610
        5. 82.110.39.8:7610
        """
        line = line.strip()
        if not line:
            return None
        
        if line.startswith("socks5://"):
            line = line[9:]
        elif line.startswith("socks://"):
            line = line[8:]

        host = ""
        port = 0
        user = ""
        pwd = ""

        # Check user:pass@host:port
        if "@" in line:
            auth_part, host_part = line.split("@", 1)
            if ":" in auth_part:
                user, pwd = auth_part.split(":", 1)
            else:
                user = auth_part
            if ":" in host_part:
                h, p = host_part.split(":", 1)
                host = h
                port = int(p.split("/")[0])
            else:
                host = host_part
        else:
            parts = line.split(":")
            if len(parts) == 4:
                host = parts[0]
                port = int(parts[1])
                user = parts[2]
                pwd = parts[3]
            elif len(parts) == 2:
                host = parts[0]
                port = int(parts[1].split("/")[0])
            elif len(parts) == 3:
                host = parts[0]
                port = int(parts[1])
                user = parts[2]
            else:
                return None

        return {
            "host": host.strip(),
            "port": int(port),
            "user": user.strip(),
            "pass": pwd.strip()
        }

# ==================== Socks5 连通性测试 ====================
def test_socks5_connectivity(host, port, user="", pwd="", timeout=5):
    """原生 socket 测试 Socks5 连通性与真实出口公网IP"""
    start_time = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        # 1. 协商认证
        if user and pwd:
            s.sendall(b"\x05\x02\x00\x02") # 允许无需认证或用户名密码认证
            resp = s.recv(2)
            if len(resp) < 2 or resp[0] != 0x05:
                return {"ok": False, "error": "Socks5 handshake failed"}
            if resp[1] == 0x02: # 需要用户名密码
                u_b = user.encode()
                p_b = pwd.encode()
                auth_req = b"\x01" + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b
                s.sendall(auth_req)
                auth_resp = s.recv(2)
                if len(auth_resp) < 2 or auth_resp[1] != 0x00:
                    return {"ok": False, "error": "Socks5 auth failed (wrong username/pass)"}
            elif resp[1] != 0x00:
                return {"ok": False, "error": "No acceptable authentication methods"}
        else:
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
            if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
                return {"ok": False, "error": "Socks5 requires authentication"}

        # 2. 发起 CONNECT 请求至 api.ipify.org:80 (IPv4: 104.26.12.205 / 172.67.74.152)
        # 用域名连接
        domain = b"api.ipify.org"
        req = b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + (80).to_bytes(2, "big")
        s.sendall(req)
        connect_resp = s.recv(10)
        if len(connect_resp) < 4 or connect_resp[1] != 0x00:
            return {"ok": False, "error": f"Socks5 connect target failed: rep={connect_resp[1] if len(connect_resp)>1 else 'none'}"}

        # 3. 发送 HTTP 请求获取出口IP
        http_get = b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: curl/7.88.1\r\nConnection: close\r\n\r\n"
        s.sendall(http_get)
        http_resp = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            http_resp += chunk
        
        elapsed = int((time.time() - start_time) * 1000)
        s.close()

        # 解析出口IP
        content = http_resp.decode(errors="replace")
        exit_ip = ""
        if "\r\n\r\n" in content:
            body = content.split("\r\n\r\n", 1)[1].strip()
            exit_ip = body.splitlines()[0].strip() if body else ""
        return {
            "ok": True,
            "latency": elapsed,
            "exit_ip": exit_ip or host
        }
    except socket.timeout:
        return {"ok": False, "error": "Connection timed out"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        try:
            s.close()
        except Exception:
            pass

# ==================== x-ui 数据库与服务管理 ====================
class XuiManager:
    def __init__(self, db_path=None):
        self.db_path = db_path or CURRENT_CONFIG.get("db_path", DEFAULT_DB_PATH)

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def restart_xui(self):
        """重启 x-ui 使其编译最新 config.json 并生效"""
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
        """获取所有已占用的端口（包含数据库及系统占用）"""
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
        
        # 随机挑选 20000 ~ 60000
        import random
        for _ in range(100):
            p = random.randint(20000, 60000)
            if p not in used:
                # 检查操作系统中是否监听
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind(("0.0.0.0", p))
                    s.close()
                    return p
                except Exception:
                    used.add(p)
        raise Exception("无法在 20000-60000 范围找到空闲端口")

    def list_relay_nodes(self):
        """获取所有中转节点列表"""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # 读 template config 的 routing 和 outbounds
        template = self.get_template_config(c)
        rules = template.get("routing", {}).get("rules", [])
        outbounds = {o.get("tag"): o for o in template.get("outbounds", []) if o.get("tag")}

        # 建立 inboundTag -> outbound 映射
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
            
            # 解析 settings 与 stream_settings
            try:
                in_settings = json.loads(row["settings"])
            except Exception:
                in_settings = {}
            try:
                in_streams = json.loads(row["stream_settings"])
            except Exception:
                in_streams = {}

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

            # 构建 vless link
            vless_link = f"vless://{client_id}@{server_ip}:{port}?security=reality&encryption=none&pbk={pub_key}&headerType=none&fp=chrome&type=tcp&sni={sni}&sid={sid}#{urllib.parse.quote(remark)}"

            socks5_info = None
            if out_info and out_info.get("protocol") == "socks":
                servers = out_info.get("settings", {}).get("servers", [{}])
                if servers:
                    srv = servers[0]
                    users = srv.get("users", [{}])
                    u = users[0].get("user", "") if users else ""
                    p = users[0].get("pass", "") if users else ""
                    socks5_info = {
                        "host": srv.get("address", ""),
                        "port": srv.get("port", 0),
                        "user": u,
                        "pass": p,
                        "tag": out_info.get("tag", "")
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
                "is_relay": socks5_info is not None,
                "socks5": socks5_info
            })

        return nodes

    def add_relay_node(self, socks_data, remark=None, custom_port=None, sni=None):
        """
        核心方法：一键添加中转节点
        socks_data: dict {"host": ..., "port": ..., "user": ..., "pass": ...}
        """
        host = socks_data["host"]
        sport = socks_data["port"]
        user = socks_data.get("user", "")
        pwd = socks_data.get("pass", "")

        conn = self.get_connection()
        c = conn.cursor()

        try:
            # 1. 分配端口
            port = self.allocate_port(custom_port)
            inbound_tag = f"inbound-{port}"
            outbound_tag = f"socks5-{host}-{sport}"
            sni = sni or CURRENT_CONFIG.get("default_sni", DEFAULT_SNI)
            remark = remark or host

            # 2. 生成密钥、UUID、ShortID
            priv_key, pub_key = XrayHelper.generate_x25519()
            client_id = XrayHelper.generate_uuid()
            sid = XrayHelper.generate_short_id()

            # 3. 更新 xrayTemplateConfig (outbounds & routing)
            template = self.get_template_config(c)
            outbounds = template.get("outbounds", [])
            rules = template.get("routing", {}).get("rules", [])

            # 检查是否已存在同名 outboundTag，不存在则追加
            existing_outbound = None
            for o in outbounds:
                if o.get("tag") == outbound_tag:
                    existing_outbound = o
                    break

            if not existing_outbound:
                srv_obj = {"address": host, "port": int(sport)}
                if user or pwd:
                    srv_obj["users"] = [{"user": user, "pass": pwd}]
                new_outbound = {
                    "tag": outbound_tag,
                    "protocol": "socks",
                    "settings": {
                        "servers": [srv_obj]
                    }
                }
                outbounds.append(new_outbound)
                template["outbounds"] = outbounds

            # 在 rules 前部优先插入精准路由规则
            new_rule = {
                "type": "field",
                "inboundTag": [inbound_tag],
                "outboundTag": outbound_tag
            }
            # 移除冲突的旧规则（如果存在）
            rules = [r for r in rules if r.get("inboundTag") != [inbound_tag]]
            rules.insert(0, new_rule)
            template["routing"]["rules"] = rules

            self.save_template_config(c, template)

            # 4. 插入 inbounds 表
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

            # 5. 重启 x-ui
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
                "socks5": {
                    "host": host,
                    "port": sport,
                    "user": user,
                    "pass": pwd
                }
            }
        except Exception as e:
            conn.rollback()
            conn.close()
            raise e

    def delete_node(self, inbound_id):
        """一键级联删除中转节点"""
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

            # 清理 template config 规则
            template = self.get_template_config(c)
            rules = template.get("routing", {}).get("rules", [])
            outbounds = template.get("outbounds", [])

            # 找到关联的 outboundTag
            matched_outbounds = set()
            new_rules = []
            for r in rules:
                if inbound_tag in r.get("inboundTag", []):
                    matched_outbounds.add(r.get("outboundTag"))
                else:
                    new_rules.append(r)
            template["routing"]["rules"] = new_rules

            # 检查是否有其它 rule 引用这些 outboundTag，若没有则清理 outbound
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

            # 删除 inbounds 记录
            c.execute("DELETE FROM inbounds WHERE id=?;", (inbound_id,))
            conn.commit()
            conn.close()

            # 重启 x-ui
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

        # 静态文件或主页
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
            u = params.get("username", "").strip()
            p = params.get("password", "").strip()
            if u == CURRENT_CONFIG.get("username") and p == CURRENT_CONFIG.get("password"):
                token = secrets.token_hex(24)
                SESSIONS.add(token)
                cookie = f"relay_session={token}; Path=/; HttpOnly; Max-Age=2592000"
                return self.send_json({"success": True, "msg": "登录成功"}, cookie=cookie)
            return self.send_json({"success": False, "error": "用户名或密码错误"}, 401)

        if path == "/api/logout":
            return self.send_json({"success": True}, cookie="relay_session=deleted; Path=/; Max-Age=0")

        # 鉴权
        if not self.is_authenticated():
            return self.send_json({"error": "Unauthorized"}, 401)

        if path == "/api/nodes/add":
            raw_socks = (params.get("socks5_str") or "").strip()
            remark = (params.get("remark") or "").strip() or None
            custom_port = params.get("port")
            if custom_port:
                try:
                    custom_port = int(custom_port)
                except Exception:
                    custom_port = None
            sni = (params.get("sni") or "").strip() or None

            parsed_socks = Socks5Parser.parse(raw_socks)
            if not parsed_socks:
                return self.send_json({"success": False, "error": "无法解析Socks5地址格式，请检查输入"}, 400)

            try:
                mgr = XuiManager()
                res = mgr.add_relay_node(parsed_socks, remark=remark, custom_port=custom_port, sni=sni)
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
                parsed_socks = Socks5Parser.parse(line)
                if not parsed_socks:
                    errors.append(f"解析失败: {line}")
                    continue
                try:
                    res = mgr.add_relay_node(parsed_socks, sni=sni)
                    success_nodes.append(res)
                except Exception as e:
                    errors.append(f"{line} 添加失败: {e}")

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
            host = (params.get("host") or "").strip()
            port = int(params.get("port", 0))
            user = str(params.get("user") or "")
            pwd = str(params.get("pass") or "")
            if not host or not port:
                return self.send_json({"success": False, "error": "缺少主机或端口"}, 400)
            test_res = test_socks5_connectivity(host, port, user, pwd)
            return self.send_json({"success": True, "result": test_res})

        if path == "/api/settings/update":
            new_u = (params.get("username") or "").strip()
            new_p = (params.get("password") or "").strip()
            new_sni = (params.get("default_sni") or "").strip()
            if new_u:
                CURRENT_CONFIG["username"] = new_u
            if new_p:
                CURRENT_CONFIG["password"] = new_p
            if new_sni:
                CURRENT_CONFIG["default_sni"] = new_sni
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
    print(f" x-ui 静态IP中转管理 Web 系统 已启动")
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
