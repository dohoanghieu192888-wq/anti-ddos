#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ddos-panel — Panel web quản trị firewall chống DDoS + shield game proxy.

Chỉ dùng thư viện chuẩn của Python 3.8 (Ubuntu 20.04), không cần pip.

Cài đặt : setup-all.sh  (hoặc: install -m755 ddos-panel.py /usr/local/sbin/ddos-panel)
Chạy    : systemctl start ddos-panel
Mặc định nghe 127.0.0.1:8080 — truy cập qua SSH tunnel:
          ssh -L 8080:127.0.0.1:8080 user@VPS   rồi mở http://127.0.0.1:8080

Lệnh phụ:
  ddos-panel --init [--user admin] [--force]   tạo /etc/ddos/panel.json + in mật khẩu
  ddos-panel --hash '<mật khẩu>'               in hash để dán vào panel.json
"""

import base64
import hmac
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CONF_PATH = "/etc/ddos/panel.json"
PROXY_CONF = "/etc/ddos/game-proxy.conf"
NFT = shutil.which("nft") or "/usr/sbin/nft"
ITER = 120000
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
PORTSPEC_RE = re.compile(
    r"^(tcp|udp|both)\s+(\d{1,5})(?:-(\d{1,5}))?(?:=(\d{1,5})(?:-(\d{1,5}))?)?$"
)

SESSIONS = {}          # token -> expiry (epoch giây)
LOGIN_FAILS = {}       # ip -> [số lần, thời điểm]
CACHE = {}             # key -> (thời điểm, giá trị)


# ---------------------------------------------------------------- tiện ích
def h(text):
    return html.escape(str(text), quote=True)


def run(argv, timeout=60):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "không tìm thấy: " + argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "hết thời gian chờ"


def read_file(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def cached(key, ttl, fn):
    now = time.time()
    if key in CACHE and now - CACHE[key][0] < ttl:
        return CACHE[key][1]
    val = fn()
    CACHE[key] = (now, val)
    return val


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), ITER)
    return salt, base64.b64encode(dk).decode()


def check_password(password, conf):
    salt = conf.get("salt", "")
    _, want = hash_password(password, salt)
    return hmac.compare_digest(want, conf.get("hash", ""))


# ---------------------------------------------------------------- cấu hình
def load_conf():
    if not os.path.exists(CONF_PATH):
        return None
    try:
        with open(CONF_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save_conf(conf):
    os.makedirs(os.path.dirname(CONF_PATH), exist_ok=True)
    tmp = CONF_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(conf, fh, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF_PATH)


def init_conf(user="admin", force=False):
    if os.path.exists(CONF_PATH) and not force:
        print("Đã tồn tại " + CONF_PATH + " (dùng --force để ghi đè)")
        return 1
    pw = secrets.token_urlsafe(12)
    salt, digest = hash_password(pw)
    conf = {
        "user": user,
        "salt": salt,
        "hash": digest,
        "secret": secrets.token_hex(32),
        "bind": "127.0.0.1",
        "port": 8080,
        "session_hours": 12,
    }
    save_conf(conf)
    print("=== ddos-panel ===")
    print("File      : " + CONF_PATH)
    print("Tài khoản : " + user)
    print("Mật khẩu  : " + pw)
    print()
    print("Truy cập  : ssh -L 8080:127.0.0.1:8080 root@<IP-VPS>")
    print("            rồi mở http://127.0.0.1:8080")
    print("Đổi bind/port trong " + CONF_PATH)
    return 0


# ---------------------------------------------------------------- nftables
def nft_json(args):
    rc, out, _ = run([NFT, "-j"] + args, timeout=20)
    if rc != 0 or not out.strip():
        return {}
    try:
        return json.loads(out)
    except ValueError:
        return {}


def firewall_counters():
    """Trả về list (chain, nhãn, gói, byte) từ bảng inet filter + gamefilter."""

    def collect():
        rows = []
        for table in ("inet filter", "inet gamefilter"):
            fam, name = table.split()
            data = nft_json(["list", "table", fam, name])
            for item in data.get("nftables", []):
                rule = item.get("rule")
                if not rule:
                    continue
                packets = bytes_ = 0
                for expr in rule.get("expr", []):
                    if isinstance(expr, dict) and "counter" in expr:
                        packets = expr["counter"].get("packets", 0)
                        bytes_ = expr["counter"].get("bytes", 0)
                label = rule.get("comment") or _rule_label(rule)
                rows.append((name, rule.get("chain", "?"), label, packets, bytes_))
        return rows

    return cached("counters", 3, collect)


def _rule_label(rule):
    """Tạo nhãn ngắn cho rule không có comment (dựa vào nội dung)."""
    text = json.dumps(rule.get("expr", []), ensure_ascii=False)
    for key, label in (
        ("geo-block", "geo-block (IP ngoài VN)"),
        ("nft-input-drop", "input drop (log)"),
        ("nft-ssh-flood", "ssh flood"),
        ("limit", "rate-limit"),
        ("drop", "drop"),
        ("accept", "accept"),
    ):
        if key in text:
            return label
    return "-"


def set_count(table_family, table, name):
    def collect():
        data = nft_json(["list", "set", table_family, table, name])
        for item in data.get("nftables", []):
            st = item.get("set")
            if st:
                return len(st.get("elem", []))
        return 0

    return cached("set:%s:%s" % (table, name), 20, collect)


def set_elements(table_family, table, name, limit=60):
    data = nft_json(["list", "set", table_family, table, name])
    elems = []
    for item in data.get("nftables", []):
        st = item.get("set")
        if st:
            for e in st.get("elem", []):
                if isinstance(e, dict):
                    elems.append(str(e.get("val", e)))
                else:
                    elems.append(str(e))
    return elems[:limit], len(elems)


def nft_element(action, family, table, setname, element):
    return run([NFT, action, "element", family, table, setname, "{", element, "}"])


def service_state(name):
    rc, out, _ = run(["systemctl", "is-active", name], timeout=10)
    return "active" if rc == 0 and "active" in out else (out.strip() or "unknown")


def conntrack():
    cur = read_file("/proc/sys/net/netfilter/nf_conntrack_count", "?").strip()
    mx = read_file("/proc/sys/net/netfilter/nf_conntrack_max", "?").strip()
    return cur, mx


def loadavg():
    return read_file("/proc/loadavg", "?").strip()


def meminfo():
    info = {}
    for line in read_file("/proc/meminfo").splitlines():
        parts = line.split(":")
        if len(parts) == 2:
            info[parts[0]] = parts[1].strip()
    return info


def top_ips():
    def collect():
        rc, out, _ = run(["ss", "-tan"], timeout=10)
        counts = {}
        for line in out.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 5 or not cols[0].startswith("ESTAB"):
                continue
            ip = cols[4].rsplit(":", 1)[0]
            ip = ip.strip("[]")
            counts[ip] = counts.get(ip, 0) + 1
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return cached("topip", 5, collect)


# ---------------------------------------------------------------- proxy conf
def read_proxy_conf():
    """Đọc file cấu hình bash đơn giản -> dict."""
    data = {"PORTS": [], "ADMIN_IPS": [], "raw": ""}
    raw = read_file(PROXY_CONF)
    data["raw"] = raw
    if not raw:
        return data
    for m in re.finditer(r'^([A-Z_0-9]+)="([^"]*)"', raw, re.M):
        data[m.group(1)] = m.group(2)
    for key in ("PORTS", "ADMIN_IPS"):
        block = re.search(key + r"=\(\s*(.*?)\s*\)", raw, re.S)
        vals = []
        if block:
            vals = re.findall(r'"([^"]*)"', block.group(1))
        data[key] = [v for v in vals if v and not v.startswith("#")]
    return data


def valid_portspec(line):
    """Kiểm tra dòng 'proto cổng[-cổng][=cổng[-cổng]]' với dải 1-65535."""
    m = PORTSPEC_RE.match(line)
    if not m:
        return False
    nums = [int(g) for g in m.groups()[1:] if g]
    if any(n < 1 or n > 65535 for n in nums):
        return False
    if m.group(3) and int(m.group(2)) > int(m.group(3)):
        return False
    if m.group(5) and int(m.group(4)) > int(m.group(5)):
        return False
    return True


def write_proxy_conf(old, form):
    ports = [ln for ln in form.get("PORTS", "").splitlines() if ln.strip()]
    admins = [ln.strip() for ln in form.get("ADMIN_IPS", "").splitlines() if ln.strip()]
    for p in ports:
        if not valid_portspec(" ".join(p.split())):
            return False, "Dòng cổng không hợp lệ (cần 1-65535): " + p
    for a in admins:
        if not IPV4_RE.match(a):
            return False, "IP quản trị không hợp lệ: " + a
    win_ip = form.get("WIN_IP", "").strip()
    if not IPV4_RE.match(win_ip):
        return False, "WIN_IP không hợp lệ"
    mode = form.get("FORWARD_MODE", "proxy")
    if mode not in ("proxy", "dnat"):
        return False, "FORWARD_MODE không hợp lệ"

    def norm_ports(items):
        return "".join('  "%s"\n' % p.strip() for p in items)

    content = (
        "# TỰ SINH bởi ddos-panel — sửa qua panel hoặc sửa tay rồi chạy gen-proxy-rules\n"
        'WIN_IP="%s"\n' % win_ip
        + 'FORWARD_MODE="%s"\n' % mode
        + 'WAN_IF="%s"\n' % (form.get("WAN_IF") or "auto")
        + 'LAN_IF="%s"\n' % (form.get("LAN_IF") or "auto")
        + 'GEO_MODE="%s"\n' % ("vn-only" if form.get("GEO_MODE") == "vn-only" else "off")
        + 'ALLOW_V6="%s"\n' % ("yes" if form.get("ALLOW_V6") == "yes" else "no")
        + 'ADMIN_PORTS="%s"\n' % form.get("ADMIN_PORTS", "").strip()
        + 'UDP_PPS_PER_IP="%s"\n' % (re.sub(r"\D", "", form.get("UDP_PPS_PER_IP", "200")) or "200")
        + 'TCP_NEWCONN_PER_IP="%s"\n' % (re.sub(r"\D", "", form.get("TCP_NEWCONN_PER_IP", "30")) or "30")
        + 'TCP_CONN_PER_IP="%s"\n' % (re.sub(r"\D", "", form.get("TCP_CONN_PER_IP", "60")) or "60")
        + "PORTS=(\n" + norm_ports(ports) + ")\n"
        + "ADMIN_IPS=(\n" + norm_ports(admins) + ")\n"
        + 'GEOIP_FAIL_OPEN="%s"\n' % ("yes" if form.get("GEOIP_FAIL_OPEN") == "yes" else "no")
    )
    os.makedirs(os.path.dirname(PROXY_CONF), exist_ok=True)
    if old.get("raw"):
        with open(PROXY_CONF + ".bak", "w", encoding="utf-8") as fh:
            fh.write(old["raw"])
    with open(PROXY_CONF, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(PROXY_CONF, 0o640)
    return True, "Đã ghi " + PROXY_CONF


# ---------------------------------------------------------------- HTML
CSS = """
:root{--bg:#0f1419;--card:#181f27;--line:#26313d;--fg:#e6edf3;--muted:#8b98a5;
--green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
header{display:flex;flex-wrap:wrap;gap:14px;align-items:center;padding:14px 20px;
background:#11171d;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
header b{font-size:15px}header nav a{margin-right:14px;color:var(--muted)}
header nav a.on{color:var(--fg);font-weight:600}
main{padding:20px;max-width:1180px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.card h3{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.big{font-size:25px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.ok{color:var(--green)}.bad{color:var(--red)}.warn{color:var(--yellow)}
button,.btn{background:#21262d;color:var(--fg);border:1px solid var(--line);border-radius:7px;
padding:8px 14px;font:inherit;cursor:pointer}
button:hover,.btn:hover{background:#2d333b;text-decoration:none}
button.danger{border-color:#5c2b29;color:#ffb3ad}
button.primary{background:#238636;border-color:#2ea043;color:#fff}
input,textarea,select{width:100%;background:#0d1117;color:var(--fg);border:1px solid var(--line);
border-radius:7px;padding:9px 11px;font:inherit}
textarea{min-height:110px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
label{display:block;margin:12px 0 5px;color:var(--muted);font-size:12px;text-transform:uppercase}
pre{background:#0d1117;border:1px solid var(--line);border-radius:8px;padding:14px;
overflow:auto;font-size:12.5px;max-height:520px;margin:0}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.msg{padding:11px 14px;border-radius:8px;margin-bottom:16px;border:1px solid}
.msg.ok{border-color:#2ea04333;background:#2ea0431a;color:#8ee89a}
.msg.err{border-color:#f8514933;background:#f851491a;color:#ffb3ad}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
form.inline{display:inline}
"""

NAV = [("/", "Tổng quan"), ("/blocklist", "Chặn IP"), ("/proxy", "Shield / Proxy"),
       ("/rules", "Ruleset"), ("/logs", "Log")]


def page(title, body, active="", msg="", refresh=None, user=""):
    if not user:
        user = (load_conf() or {}).get("user", "")
    nav = "".join(
        '<a href="%s"%s>%s</a>' % (u, ' class="on"' if u == active else "", h(t))
        for u, t in NAV
    )
    meta = '<meta http-equiv="refresh" content="%d">' % refresh if refresh else ""
    banner = ""
    if msg:
        kind, text = msg
        banner = '<div class="msg %s">%s</div>' % (kind, h(text))
    return (
        "<!doctype html><html lang=\"vi\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>%s — DDoS Panel</title>%s<style>%s</style></head><body>"
        "<header><b>🛡 DDoS Panel</b><nav>%s</nav>"
        "<span class=\"muted\" style=\"margin-left:auto\">%s "
        "<a href=\"/logout\">Đăng xuất</a></span></header><main>%s%s</main></body></html>"
        % (h(title), meta, CSS, nav, h(user), banner, body)
    )


def login_page(error=""):
    body = (
        '<div style="max-width:380px;margin:9vh auto"><div class="card">'
        "<h3>Đăng nhập quản trị</h3>"
        + ('<div class="msg err">%s</div>' % h(error) if error else "")
        + '<form method="post" action="/login">'
        '<label>Tài khoản</label><input name="user" autofocus autocomplete="username">'
        '<label>Mật khẩu</label><input name="password" type="password" autocomplete="current-password">'
        '<div style="margin-top:16px"><button class="primary" style="width:100%">Đăng nhập</button></div>'
        "</form></div>"
        '<p class="muted" style="text-align:center;font-size:12px">'
        "Mặc định chỉ nghe 127.0.0.1 — dùng SSH tunnel:<br>"
        '<span class="mono">ssh -L 8080:127.0.0.1:8080 root@VPS</span></p></div>'
    )
    return (
        '<!doctype html><html lang="vi"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Đăng nhập — DDoS Panel</title><style>%s</style></head><body>%s</body></html>"
        % (CSS, body)
    )


def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0
    return str(n)


# ---------------------------------------------------------------- views
def view_dashboard(token):
    counters = firewall_counters()
    cur, mx = conntrack()
    mem = meminfo()
    conf = read_proxy_conf()
    geo = {
        "vn4": set_count("inet", "gamefilter", "vn4"),
        "vn6": set_count("inet", "gamefilter", "vn6"),
        "admin": set_count("inet", "gamefilter", "admin4"),
        "blackhole": set_count("inet", "filter", "blackhole_v4"),
        "whitelist": set_count("inet", "filter", "whitelist_v4"),
    }
    svc = {n: service_state(n) for n in
           ("nftables", "fail2ban", "ddos-panel", "ddos-geoip.timer")}

    def svc_row(name):
        st = svc.get(name, "?")
        cls = "ok" if st == "active" else "bad"
        return '<div class="row" style="justify-content:space-between">' \
               '<span class="mono">%s</span><span class="%s">%s</span></div>' % (h(name), cls, h(st))

    geo_mode = conf.get("GEO_MODE", "-")
    ports = conf.get("PORTS", [])
    total_pkt = sum(r[3] for r in counters)

    counts = "".join(
        '<div class="card"><h3>%s</h3><div class="big">%s</div>'
        '<div class="muted" style="font-size:12px">IP/CIDR</div></div>'
        % (h(label), h(val))
        for label, val in (
            ("Blocklist (blackhole)", geo["blackhole"]),
            ("IP Việt Nam (vn4)", geo["vn4"]),
            ("IP quản trị", geo["admin"]),
            ("Whitelist", geo["whitelist"]),
        )
    )

    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td class='n'>%s</td><td class='n'>%s</td></tr>"
        % (h(t), h(ch), h(lbl), format(p, ","), fmt_bytes(b))
        for t, ch, lbl, p, b in sorted(counters, key=lambda r: r[3], reverse=True)[:25]
        if p
    ) or "<tr><td colspan='5' class='muted'>Chưa có gói tin nào khớp</td></tr>"

    top = "".join(
        "<tr><td class='mono'>%s</td><td class='n'>%s</td></tr>" % (h(ip), n)
        for ip, n in top_ips()
    ) or "<tr><td colspan='2' class='muted'>Không có kết nối</td></tr>"

    emergency_on = any("emg_" in str(r[2]) or "emergency" in str(r[2]) for r in counters)

    body = """
<div class="grid">
  <div class="card"><h3>Tải hệ thống</h3><div class="big">%s</div>
    <div class="muted" style="font-size:12px">load average</div></div>
  <div class="card"><h3>Conntrack</h3><div class="big">%s</div>
    <div class="muted" style="font-size:12px">/ %s kết nối</div></div>
  <div class="card"><h3>RAM</h3><div class="big">%s</div>
    <div class="muted" style="font-size:12px">free / total</div></div>
  <div class="card"><h3>Chế độ bảo vệ</h3><div class="big %s">%s</div>
    <div class="muted" style="font-size:12px">khẩn cấp / bình thường</div></div>
</div>

<h3 style="margin:22px 0 10px">Bộ đếm chặn</h3>
<div class="grid">%s</div>

<h3 style="margin:22px 0 10px">Dịch vụ</h3>
<div class="card"><div class="grid">%s</div></div>

<h3 style="margin:22px 0 10px">Hành động nhanh</h3>
<div class="card"><div class="row">
  %s
  %s
  <form class="inline" method="post" action="/action">%s
    <button name="action" value="update_blocklist">Cập nhật blocklist</button></form>
  <form class="inline" method="post" action="/action">%s
    <button name="action" value="geoip_update">Cập nhật IP Việt Nam</button></form>
  <form class="inline" method="post" action="/action">%s
    <button name="action" value="reload_firewall">Nạp lại firewall</button></form>
</div></div>

<h3 style="margin:22px 0 10px">Shield game proxy</h3>
<div class="card">
  <div class="row" style="justify-content:space-between">
    <span>Windows: <b class="mono">%s</b> · chế độ <b>%s</b> ·
      GeoIP <b>%s</b></span>
    <a class="btn" href="/proxy">Cấu hình</a>
  </div>
  <div class="muted mono" style="margin-top:10px;font-size:12px">%s</div>
</div>

<h3 style="margin:22px 0 10px">Rule có lưu lượng (top 25) — tổng %s gói</h3>
<div class="card" style="padding:0;overflow:hidden">
<table><tr><th>Bảng</th><th>Chain</th><th>Rule</th><th class="n">Gói</th><th class="n">Byte</th></tr>
%s</table></div>

<h3 style="margin:22px 0 10px">Top IP đang kết nối</h3>
<div class="card" style="padding:0;overflow:hidden">
<table><tr><th>IP</th><th class="n">Kết nối</th></tr>%s</table></div>
""" % (
        h(loadavg()),
        h(cur), h(mx),
        h(mem.get("MemAvailable", "?")),
        "bad" if emergency_on else "ok",
        "KHẨN CẤP" if emergency_on else "Bình thường",
        counts,
        "".join(svc_row(n) for n in svc),
        ('<form class="inline" method="post" action="/action">%s'
         '<button class="danger" name="action" value="emergency_on">BẬT khẩn cấp</button></form>'
         % csrf_input(token)),
        ('<form class="inline" method="post" action="/action">%s'
         '<button class="primary" name="action" value="emergency_off">TẮT khẩn cấp</button></form>'
         % csrf_input(token)),
        csrf_input(token), csrf_input(token), csrf_input(token),
        h(conf.get("WIN_IP", "-")), h(conf.get("FORWARD_MODE", "-")), h(geo_mode),
        h(" · ".join(ports) if ports else "chưa có cổng nào"),
        format(total_pkt, ","), rows, top,
    )
    return page("Tổng quan", body, "/", refresh=15)


def csrf_input(token):
    return '<input type="hidden" name="csrf" value="%s">' % h(token)


def view_blocklist(token, msg=""):
    bh, _ = set_elements("inet", "filter", "blackhole_v4", 80)
    wl, wl_n = set_elements("inet", "filter", "whitelist_v4", 80)
    admins = read_proxy_conf().get("ADMIN_IPS", [])

    body = """
<div class="grid">
  <div class="card"><h3>Chặn IP / CIDR</h3>
    <form method="post" action="/action">%s
      <input type="hidden" name="action" value="block_ip">
      <input name="ip" placeholder="1.2.3.4 hoặc 1.2.3.0/24" required>
      <div style="margin-top:12px"><button class="danger" style="width:100%%">Chặn ngay</button></div>
    </form>
  </div>
  <div class="card"><h3>Bỏ chặn</h3>
    <form method="post" action="/action">%s
      <input type="hidden" name="action" value="unblock_ip">
      <input name="ip" placeholder="1.2.3.4" required>
      <div style="margin-top:12px"><button style="width:100%%">Bỏ chặn</button></div>
    </form>
  </div>
  <div class="card"><h3>Whitelist (không bao giờ chặn)</h3>
    <form method="post" action="/action">%s
      <input type="hidden" name="action" value="allow_ip">
      <input name="ip" placeholder="203.0.113.10" required>
      <div style="margin-top:12px"><button style="width:100%%">Thêm vào whitelist</button></div>
    </form>
  </div>
</div>

<h3 style="margin:22px 0 10px">Blocklist — hiển thị %d/%d mục</h3>
<div class="card"><div class="mono" style="line-height:1.9">%s</div></div>

<h3 style="margin:22px 0 10px">Whitelist — %d mục</h3>
<div class="card"><div class="mono" style="line-height:1.9">%s</div></div>

<h3 style="margin:22px 0 10px">IP quản trị (shield proxy)</h3>
<div class="card"><div class="mono">%s</div>
  <p class="muted" style="font-size:12px">Thêm/bớt ở trang <a href="/proxy">Shield / Proxy</a>.</p></div>
""" % (
        csrf_input(token), csrf_input(token), csrf_input(token),
        len(bh), set_count("inet", "filter", "blackhole_v4"),
        h(", ".join(bh)) if bh else '<span class="muted">(trống)</span>',
        wl_n, h(", ".join(wl)) if wl else '<span class="muted">(trống)</span>',
        h(", ".join(admins)) if admins else '<span class="muted">(trống)</span>',
    )
    return page("Chặn IP", body, "/blocklist", msg=msg)


def view_proxy(token, msg=""):
    c = read_proxy_conf()
    ports = "\n".join(c.get("PORTS", []))
    admins = "\n".join(c.get("ADMIN_IPS", []))

    def sel(name, value, options):
        return "".join(
            '<option value="%s"%s>%s</option>' % (h(v), " selected" if v == value else "", h(v))
            for v in options
        )

    body = """
<form method="post" action="/action">%s
<input type="hidden" name="action" value="save_proxy">
<div class="grid">
  <div class="card">
    <h3>Kết nối tới Windows</h3>
    <label>IP server Windows</label>
    <input name="WIN_IP" value="%s" placeholder="10.10.0.5">
    <label>Chế độ chuyển tiếp</label>
    <select name="FORWARD_MODE">%s</select>
    <p class="muted" style="font-size:12px">
      <b>proxy</b>: Windows thấy IP VPS (dễ, chạy mọi nơi).<br>
      <b>dnat</b>: giữ IP thật người chơi, Windows phải route reply về VPS.</p>
    <label>Cổng quản trị Windows (cách nhau dấu cách)</label>
    <input name="ADMIN_PORTS" value="%s" placeholder="3389">
  </div>
  <div class="card">
    <h3>Lọc quốc gia</h3>
    <label>GeoIP</label>
    <select name="GEO_MODE">%s</select>
    <label>IPv6</label>
    <select name="ALLOW_V6">%s</select>
    <label>Nếu chưa tải được danh sách IP Việt Nam</label>
    <select name="GEOIP_FAIL_OPEN">%s</select>
    <label>Card mạng (auto = tự phát hiện)</label>
    <div class="row">
      <input name="WAN_IF" value="%s" placeholder="auto" style="flex:1">
      <input name="LAN_IF" value="%s" placeholder="auto" style="flex:1">
    </div>
  </div>
</div>

<div class="grid" style="margin-top:14px">
  <div class="card">
    <h3>Giới hạn chống flood (mỗi IP)</h3>
    <label>UDP gói/giây</label>
    <input name="UDP_PPS_PER_IP" value="%s">
    <label>Kết nối TCP mới/giây</label>
    <input name="TCP_NEWCONN_PER_IP" value="%s">
    <label>Kết nối TCP đồng thời</label>
    <input name="TCP_CONN_PER_IP" value="%s">
  </div>
  <div class="card">
    <h3>Cổng game (mỗi dòng: proto cổng[=cổng_windows])</h3>
    <textarea name="PORTS" spellcheck="false">%s</textarea>
    <p class="muted" style="font-size:12px">Ví dụ: <span class="mono">both 7777</span>,
      <span class="mono">tcp 8080=80</span>, <span class="mono">both 27000-27030</span></p>
  </div>
  <div class="card">
    <h3>IP quản trị (mỗi dòng 1 IP/CIDR)</h3>
    <textarea name="ADMIN_IPS" spellcheck="false">%s</textarea>
    <p class="muted" style="font-size:12px">Chỉ các IP này vào được cổng quản trị và luôn
      được phép qua GeoIP.</p>
  </div>
</div>

<div class="card" style="margin-top:14px"><div class="row">
  <button class="primary" name="action" value="save_proxy">Lưu và áp dụng</button>
  <span class="muted">Ghi %s rồi chạy <span class="mono">gen-proxy-rules</span></span>
</div></div>
</form>
""" % (
        csrf_input(token),
        h(c.get("WIN_IP", "")),
        sel("FORWARD_MODE", c.get("FORWARD_MODE", "proxy"), ["proxy", "dnat"]),
        h(c.get("ADMIN_PORTS", "")),
        sel("GEO_MODE", c.get("GEO_MODE", "vn-only"), ["vn-only", "off"]),
        sel("ALLOW_V6", c.get("ALLOW_V6", "no"), ["no", "yes"]),
        sel("GEOIP_FAIL_OPEN", c.get("GEOIP_FAIL_OPEN", "no"), ["no", "yes"]),
        h(c.get("WAN_IF", "auto")), h(c.get("LAN_IF", "auto")),
        h(c.get("UDP_PPS_PER_IP", "200")), h(c.get("TCP_NEWCONN_PER_IP", "30")),
        h(c.get("TCP_CONN_PER_IP", "60")),
        h(ports), h(admins),
        h(PROXY_CONF),
    )
    return page("Shield / Proxy", body, "/proxy", msg=msg)


def view_rules(token):
    rc, out, err = run([NFT, "list", "ruleset"], timeout=20)
    text = out or err
    if len(text) > 60000:
        text = text[:60000] + "\n... (đã rút gọn)"
    body = """
<div class="card"><div class="row" style="justify-content:space-between">
  <span>Toàn bộ ruleset đang nạp</span>
  <form class="inline" method="post" action="/action">%s
    <button name="action" value="reload_firewall">Nạp lại /etc/nftables.conf</button></form>
</div></div>
<pre style="margin-top:14px">%s</pre>
""" % (csrf_input(token), h(text))
    return page("Ruleset", body, "/rules")


def view_logs(token):
    _, kernel, _ = run(["journalctl", "-k", "-n", "120", "--no-pager"], timeout=20)
    _, f2b, _ = run(["fail2ban-client", "status"], timeout=15)
    _, f2bjails, _ = run(["bash", "-lc",
                          "for j in sshd ddos-scanner recidive; do "
                          "fail2ban-client status $j 2>/dev/null; done"], timeout=20)
    body = """
<h3 style="margin:0 0 10px">fail2ban</h3>
<pre>%s

%s</pre>
<h3 style="margin:22px 0 10px">Kernel log (nftables drop)</h3>
<pre>%s</pre>
""" % (h(f2b or "(fail2ban không chạy)"), h(f2bjails), h(kernel))
    return page("Log", body, "/logs")


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "ddos-panel/1.0"

    # -------- helper
    def conf(self):
        return load_conf() or {}

    def client_ip(self):
        return self.client_address[0]

    def send_html(self, text, status=200, headers=None):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "frame-ancestors 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def cookies(self):
        raw = self.headers.get("Cookie", "")
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def session(self):
        tok = self.cookies().get("ddos_sess", "")
        exp = SESSIONS.get(tok)
        if not tok or not exp or exp < time.time():
            SESSIONS.pop(tok, None)
            return None
        return tok

    def flash(self, token, kind, text):
        # Thông báo 1 lần, lưu theo session
        SESSIONS.setdefault("msg:" + token, (time.time() + 20, kind, text))

    def take_flash(self, token):
        item = SESSIONS.get("msg:" + token)
        if item and item[0] > time.time():
            return item[1], item[2]
        return ""

    def csrf_ok(self, form, token):
        got = (form.get("csrf", [""])[0] or "")
        want = hmac.new(self.conf().get("secret", "").encode(), token.encode(),
                        hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(got, want)

    # -------- routing
    def do_GET(self):
        path = urlparse(self.path).path
        token = self.session()
        if path == "/login" or path == "/logout":
            self.redirect("/")
            return
        if not token:
            self.send_html(login_page())
            return
        kind, text = self.take_flash(token)
        msg = (kind, text) if kind else ""
        user = self.conf().get("user", "")
        try:
            if path == "/":
                self.send_html(view_dashboard(token))
            elif path == "/blocklist":
                self.send_html(view_blocklist(token, msg))
            elif path == "/proxy":
                self.send_html(view_proxy(token, msg))
            elif path == "/rules":
                self.send_html(view_rules(token))
            elif path == "/logs":
                self.send_html(view_logs(token))
            else:
                self.send_html(page("404", "<div class='card'>Không tìm thấy trang</div>",
                                    "", user=user), 404)
        except Exception as exc:  # noqa: BLE001 - panel phải luôn trả lời được
            self.send_html(page("Lỗi", "<div class='card'><pre>%s</pre></div>"
                                % h(repr(exc)), user=user), 500)

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            self.send_html("quá lớn", 413)
            return
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = parse_qs(raw, keep_blank_values=True)

        if path == "/login":
            self.handle_login(form)
            return

        token = self.session()
        if not token:
            self.send_html(login_page("Phiên đăng nhập đã hết hạn."), 401)
            return
        if not self.csrf_ok(form, token):
            self.send_html(login_page("CSRF token không hợp lệ."), 403)
            return

        action = form.get("action", [""])[0]
        kind, text, back = self.do_action(action, form, token)
        self.flash(token, kind, text)
        self.redirect(back)

    # -------- login
    def handle_login(self, form):
        ip = self.client_ip()
        fails = LOGIN_FAILS.get(ip, [0, 0])
        if fails[0] >= 8 and time.time() - fails[1] < 300:
            self.send_html(login_page("Quá nhiều lần thử. Chờ 5 phút."), 429)
            return
        user = form.get("user", [""])[0]
        pw = form.get("password", [""])[0]
        conf = self.conf()
        if user == conf.get("user") and check_password(pw, conf):
            LOGIN_FAILS.pop(ip, None)
            tok = secrets.token_urlsafe(32)
            hours = int(conf.get("session_hours", 12))
            SESSIONS[tok] = time.time() + hours * 3600
            self.redirect(
                "/",
                cookie="ddos_sess=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d"
                       % (tok, hours * 3600),
            )
        else:
            LOGIN_FAILS[ip] = [fails[0] + 1, time.time()]
            time.sleep(0.6)
            self.send_html(login_page("Sai tài khoản hoặc mật khẩu."), 401)

    # -------- actions
    def do_action(self, action, form, token):
        ip = (form.get("ip", [""])[0] or "").strip()
        if action == "block_ip":
            if not IPV4_RE.match(ip):
                return "err", "IP không hợp lệ", "/blocklist"
            rc, _, err = nft_element("add", "inet", "filter", "blackhole_v4", ip)
            CACHE.clear()
            if rc == 0:
                return "ok", "Đã chặn " + ip, "/blocklist"
            return "err", "Lỗi: " + err.strip(), "/blocklist"
        if action == "unblock_ip":
            if not IPV4_RE.match(ip):
                return "err", "IP không hợp lệ", "/blocklist"
            rc, _, err = nft_element("delete", "inet", "filter", "blackhole_v4", ip)
            CACHE.clear()
            if rc == 0:
                return "ok", "Đã bỏ chặn " + ip, "/blocklist"
            return "err", "Lỗi: " + err.strip(), "/blocklist"
        if action == "allow_ip":
            if not IPV4_RE.match(ip):
                return "err", "IP không hợp lệ", "/blocklist"
            rc, _, err = nft_element("add", "inet", "filter", "whitelist_v4", ip)
            nft_element("add", "inet", "gamefilter", "admin4", ip)
            CACHE.clear()
            if rc == 0:
                return "ok", "Đã whitelist " + ip, "/blocklist"
            return "err", "Lỗi: " + err.strip(), "/blocklist"
        if action == "emergency_on":
            rc, out, err = run(["/usr/local/sbin/ddos-emergency", "on"], timeout=60)
            CACHE.clear()
            if rc == 0:
                return "ok", "Đã BẬT chế độ khẩn cấp", "/"
            return "err", (err or out).strip(), "/"
        if action == "emergency_off":
            rc, out, err = run(["/usr/local/sbin/ddos-emergency", "off"], timeout=60)
            CACHE.clear()
            if rc == 0:
                return "ok", "Đã TẮT chế độ khẩn cấp", "/"
            return "err", (err or out).strip(), "/"
        if action == "update_blocklist":
            rc, out, err = run(["/usr/local/sbin/ddos-update-blocklist"], timeout=600)
            CACHE.clear()
            tail = (out or err).strip().splitlines()[-1:] or ["?"]
            return ("ok" if rc == 0 else "err", "Blocklist: " + tail[0], "/")
        if action == "geoip_update":
            rc, out, err = run(["/usr/local/sbin/geoip-vn-update"], timeout=600)
            CACHE.clear()
            tail = (out or err).strip().splitlines()[-1:] or ["?"]
            return ("ok" if rc == 0 else "err", "GeoIP: " + tail[0], "/")
        if action == "reload_firewall":
            rc, out, err = run([NFT, "-f", "/etc/nftables.conf"], timeout=60)
            CACHE.clear()
            return ("ok" if rc == 0 else "err",
                    "Đã nạp lại firewall" if rc == 0 else (err or out).strip()[:400], "/")
        if action == "save_proxy":
            old = read_proxy_conf()
            ok, text = write_proxy_conf(old, {k: v[0] for k, v in form.items()})
            if not ok:
                return "err", text, "/proxy"
            rc, out, err = run(["/usr/local/sbin/gen-proxy-rules"], timeout=120)
            CACHE.clear()
            if rc == 0:
                return "ok", text + " — đã áp dụng ruleset", "/proxy"
            return "err", "Đã lưu nhưng áp dụng lỗi: " + (err or out).strip()[:400], "/proxy"
        return "err", "Hành động không hỗ trợ: " + action, "/"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s %s\n" % (time.strftime("%H:%M:%S"),
                                           self.client_ip(), fmt % args))


# ---------------------------------------------------------------- main
def main(argv):
    if len(argv) > 1 and argv[1] == "--init":
        user = "admin"
        if "--user" in argv:
            user = argv[argv.index("--user") + 1]
        return init_conf(user, force="--force" in argv)
    if len(argv) > 2 and argv[1] == "--hash":
        salt, digest = hash_password(argv[2])
        print(json.dumps({"salt": salt, "hash": digest, "iterations": ITER}, indent=2))
        return 0
    if len(argv) > 1 and argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0

    conf = load_conf()
    if not conf:
        print("Chưa có %s — chạy: ddos-panel --init" % CONF_PATH, file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("Cảnh báo: panel cần quyền root để đọc/ghi nftables.", file=sys.stderr)

    bind = conf.get("bind", "127.0.0.1")
    port = int(conf.get("port", 8080))
    if bind not in ("127.0.0.1", "::1", "localhost"):
        print("CẢNH BÁO: panel đang nghe trên %s:%d (không phải loopback). "
              "Chỉ nên mở qua SSH tunnel hoặc firewall." % (bind, port), file=sys.stderr)

    srv = ThreadingHTTPServer((bind, port), Handler)
    print("ddos-panel đang chạy tại http://%s:%d (Ctrl+C để dừng)" % (bind, port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
