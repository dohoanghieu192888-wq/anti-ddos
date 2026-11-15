#!/usr/bin/env python3
import base64
import hashlib
import hmac
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

CONF = "/etc/ddos/panel.json"
PROXY = "/etc/ddos/game-proxy.conf"
NFT = shutil.which("nft") or "/usr/sbin/nft"
ITER = 120000
IPRE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
PORTRE = re.compile(r"^(tcp|udp|both)\s+(\d{1,5})(?:-(\d{1,5}))?(?:=(\d{1,5})(?:-(\d{1,5}))?)?$")
SESS = {}
FAILS = {}
CACHE = {}

CSS = """
:root{--bg:#0f1419;--card:#181f27;--line:#26313d;--fg:#e6edf3;--muted:#8b98a5;
--green:#3fb950;--red:#f85149;--blue:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
header{display:flex;flex-wrap:wrap;gap:14px;align-items:center;padding:14px 20px;
background:#11171d;border-bottom:1px solid var(--line)}
header b{font-size:15px}header nav a{margin-right:14px;color:var(--muted)}
header nav a.on{color:var(--fg);font-weight:600}
main{padding:20px;max-width:1180px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.card h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.big{font-size:25px;font-weight:600}h4{margin:22px 0 10px;font-size:14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-size:12px;text-transform:uppercase}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.ok{color:var(--green)}.bad{color:var(--red)}.muted{color:var(--muted)}
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
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
form.inline{display:inline}
"""

NAV = [("/", "Tổng quan"), ("/blocklist", "Chặn IP"), ("/proxy", "Shield / Proxy"),
       ("/rules", "Ruleset"), ("/logs", "Log")]


def h(v):
    return html.escape(str(v), quote=True)


def run(argv, timeout=60):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "không có " + argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "hết thời gian chờ"


def read(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
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


def load_conf():
    try:
        with open(CONF, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save_conf(conf):
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    with open(CONF, "w", encoding="utf-8") as fh:
        json.dump(conf, fh, indent=2)
    os.chmod(CONF, 0o600)


def pwhash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), ITER)
    return salt, base64.b64encode(key).decode()


def pwcheck(password, conf):
    return hmac.compare_digest(pwhash(password, conf.get("salt", ""))[1], conf.get("hash", ""))


def init_conf(user="admin", force=False):
    if os.path.exists(CONF) and not force:
        print("đã có " + CONF + " (dùng --force để ghi đè)")
        return 1
    pw = secrets.token_urlsafe(12)
    salt, digest = pwhash(pw)
    save_conf({"user": user, "salt": salt, "hash": digest,
               "secret": secrets.token_hex(32), "bind": "127.0.0.1",
               "port": 8080, "session_hours": 12})
    print("file       : " + CONF)
    print("tài khoản  : " + user)
    print("mật khẩu   : " + pw)
    print("truy cập   : ssh -L 8080:127.0.0.1:8080 root@<IP-VPS>")
    return 0


def nft_json(args):
    _, out, _ = run([NFT, "-j"] + args, timeout=20)
    try:
        return json.loads(out) if out.strip() else {}
    except ValueError:
        return {}


def label_of(rule):
    text = json.dumps(rule.get("expr", []))
    for key, name in (("geo-block", "geo-block"), ("nft-input-drop", "input drop"),
                      ("nft-ssh-flood", "ssh flood"), ("limit", "rate-limit"),
                      ("accept", "accept"), ("drop", "drop")):
        if key in text:
            return name
    return "-"


def counters():
    def collect():
        rows = []
        for fam, table in (("inet", "filter"), ("inet", "gamefilter")):
            for item in nft_json(["list", "table", fam, table]).get("nftables", []):
                rule = item.get("rule")
                if not rule:
                    continue
                pkt = byte = 0
                for expr in rule.get("expr", []):
                    if isinstance(expr, dict) and "counter" in expr:
                        pkt = expr["counter"].get("packets", 0)
                        byte = expr["counter"].get("bytes", 0)
                rows.append((table, rule.get("chain", "?"),
                             rule.get("comment") or label_of(rule), pkt, byte))
        return rows

    return cached("counters", 3, collect)


def set_count(fam, table, name):
    def collect():
        for item in nft_json(["list", "set", fam, table, name]).get("nftables", []):
            if "set" in item:
                return len(item["set"].get("elem", []))
        return 0

    return cached("set:" + table + name, 20, collect)


def set_items(fam, table, name, limit=80):
    elems = []
    for item in nft_json(["list", "set", fam, table, name]).get("nftables", []):
        for e in item.get("set", {}).get("elem", []):
            elems.append(str(e.get("val", e)) if isinstance(e, dict) else str(e))
    return elems[:limit], len(elems)


def elem_op(action, fam, table, name, element):
    return run([NFT, action, "element", fam, table, name, "{", element, "}"])


def active(name):
    rc, out, _ = run(["systemctl", "is-active", name], timeout=10)
    return "active" if rc == 0 else (out.strip() or "unknown")


def ct():
    return (read("/proc/sys/net/netfilter/nf_conntrack_count", "?").strip(),
            read("/proc/sys/net/netfilter/nf_conntrack_max", "?").strip())


def top_ips():
    def collect():
        _, out, _ = run(["ss", "-tan"], timeout=10)
        found = {}
        for line in out.splitlines()[1:]:
            cols = line.split()
            if len(cols) > 4 and cols[0].startswith("ESTAB"):
                ip = cols[4].rsplit(":", 1)[0].strip("[]")
                found[ip] = found.get(ip, 0) + 1
        return sorted(found.items(), key=lambda x: x[1], reverse=True)[:10]

    return cached("top", 5, collect)


def proxy_read():
    raw = read(PROXY)
    data = {"PORTS": [], "ADMIN_IPS": [], "raw": raw}
    for m in re.finditer(r'^([A-Z_0-9]+)="([^"]*)"', raw, re.M):
        data[m.group(1)] = m.group(2)
    for key in ("PORTS", "ADMIN_IPS"):
        block = re.search(key + r"=\(\s*(.*?)\s*\)", raw, re.S)
        data[key] = re.findall(r'"([^"]*)"', block.group(1)) if block else []
    return data


def portok(line):
    m = PORTRE.match(line)
    if not m:
        return False
    nums = [int(x) for x in m.groups()[1:] if x]
    if any(n < 1 or n > 65535 for n in nums):
        return False
    if m.group(3) and int(m.group(2)) > int(m.group(3)):
        return False
    if m.group(5) and int(m.group(4)) > int(m.group(5)):
        return False
    return True


def proxy_write(old, form):
    ports = [ln.strip() for ln in form.get("PORTS", "").splitlines() if ln.strip()]
    admins = [ln.strip() for ln in form.get("ADMIN_IPS", "").splitlines() if ln.strip()]
    for p in ports:
        if not portok(" ".join(p.split())):
            return False, "cổng không hợp lệ (1-65535): " + p
    for a in admins:
        if not IPRE.match(a):
            return False, "IP quản trị không hợp lệ: " + a
    win = form.get("WIN_IP", "").strip()
    if not IPRE.match(win):
        return False, "WIN_IP không hợp lệ"
    mode = form.get("FORWARD_MODE", "proxy")
    if mode not in ("proxy", "dnat"):
        return False, "FORWARD_MODE không hợp lệ"

    def arr(items):
        return "".join('  "%s"\n' % i for i in items)

    txt = (
        'WIN_IP="%s"\n' % win
        + "FORWARD_MODE=\"%s\"\n" % mode
        + 'WAN_IF="%s"\n' % (form.get("WAN_IF") or "auto")
        + 'LAN_IF="%s"\n' % (form.get("LAN_IF") or "auto")
        + 'GEO_MODE="%s"\n' % ("vn-only" if form.get("GEO_MODE") == "vn-only" else "off")
        + 'ALLOW_V6="%s"\n' % ("yes" if form.get("ALLOW_V6") == "yes" else "no")
        + 'ADMIN_PORTS="%s"\n' % form.get("ADMIN_PORTS", "").strip()
        + 'UDP_PPS_PER_IP="%s"\n' % (re.sub(r"\D", "", form.get("UDP_PPS_PER_IP", "200")) or "200")
        + 'TCP_NEWCONN_PER_IP="%s"\n' % (re.sub(r"\D", "", form.get("TCP_NEWCONN_PER_IP", "30")) or "30")
        + 'TCP_CONN_PER_IP="%s"\n' % (re.sub(r"\D", "", form.get("TCP_CONN_PER_IP", "60")) or "60")
        + "PORTS=(\n" + arr(ports) + ")\nADMIN_IPS=(\n" + arr(admins) + ")\n"
        + 'GEOIP_FAIL_OPEN="%s"\n' % ("yes" if form.get("GEOIP_FAIL_OPEN") == "yes" else "no")
    )
    os.makedirs(os.path.dirname(PROXY), exist_ok=True)
    with open(PROXY, "w", encoding="utf-8") as fh:
        fh.write(txt)
    os.chmod(PROXY, 0o640)
    return True, "đã lưu " + PROXY


def token_of(conf, token):
    return hmac.new(conf.get("secret", "").encode(), token.encode(), hashlib.sha256).hexdigest()[:32]


def field(conf, token):
    return '<input type="hidden" name="csrf" value="%s">' % h(token_of(conf, token))


def page(title, body, active_path="", msg="", refresh=None):
    conf = load_conf() or {}
    nav = "".join('<a href="%s"%s>%s</a>' % (u, ' class="on"' if u == active_path else "", h(t))
                  for u, t in NAV)
    meta = '<meta http-equiv="refresh" content="%d">' % refresh if refresh else ""
    banner = '<div class="msg %s">%s</div>' % (msg[0], h(msg[1])) if msg else ""
    return (
        '<!doctype html><html lang="vi"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>%s — DDoS Panel</title>%s<style>%s</style></head><body>'
        '<header><b>🛡 DDoS Panel</b><nav>%s</nav>'
        '<span class="muted" style="margin-left:auto">%s <a href="/logout">Đăng xuất</a></span>'
        "</header><main>%s%s</main></body></html>"
        % (h(title), meta, CSS, nav, h(conf.get("user", "")), banner, body)
    )


def login_page(error=""):
    body = (
        '<div style="max-width:380px;margin:9vh auto"><div class="card">'
        "<h3>Đăng nhập</h3>"
        + ('<div class="msg err">%s</div>' % h(error) if error else "")
        + '<form method="post" action="/login">'
        '<label>Tài khoản</label><input name="user" autofocus autocomplete="username">'
        '<label>Mật khẩu</label><input name="password" type="password" autocomplete="current-password">'
        '<div style="margin-top:16px"><button class="primary" style="width:100%">Đăng nhập</button></div>'
        "</form></div>"
        '<p class="muted" style="text-align:center;font-size:12px">'
        'ssh -L 8080:127.0.0.1:8080 root@VPS → http://127.0.0.1:8080</p></div>'
    )
    return ('<!doctype html><html lang="vi"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            "<title>Đăng nhập</title><style>%s</style></head><body>%s</body></html>" % (CSS, body))


def tail(text):
    lines = (text or "").strip().splitlines()
    return lines[-1] if lines else ""


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d B" % n) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return str(n)


def view_home(token):
    conf = load_conf() or {}
    pconf = proxy_read()
    rows = counters()
    cur, mx = ct()
    mem = read("/proc/meminfo")
    available = "-"
    for line in mem.splitlines():
        if line.startswith("MemAvailable:"):
            available = line.split()[1] + " kB"
    svc = [(n, active(n)) for n in ("nftables", "fail2ban", "ddos-panel", "ddos-geoip.timer")]
    emergency = any(r[1] == "emergency" and r[3] >= 0 for r in rows) or any(
        "emg_" in str(r[2]) for r in rows)
    gate = field(conf, token)
    cards = "".join(
        '<div class="card"><h3>%s</h3><div class="big">%s</div></div>' % (h(k), h(v))
        for k, v in (("Blocklist", set_count("inet", "filter", "blackhole_v4")),
                     ("IP Việt Nam", set_count("inet", "gamefilter", "vn4")),
                     ("Whitelist", set_count("inet", "filter", "whitelist_v4")),
                     ("IP quản trị", set_count("inet", "gamefilter", "admin4")))
    )
    rule_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td class='n'>%s</td><td class='n'>%s</td></tr>"
        % (h(t), h(c), h(lbl), format(p, ","), human(b))
        for t, c, lbl, p, b in sorted(rows, key=lambda r: r[3], reverse=True)[:25] if p
    ) or "<tr><td colspan='5' class='muted'>chưa có lưu lượng</td></tr>"
    top = "".join("<tr><td class='mono'>%s</td><td class='n'>%s</td></tr>" % (h(i), n)
                  for i, n in top_ips()) or "<tr><td colspan='2' class='muted'>trống</td></tr>"
    body = f"""
<div class="grid">
  <div class="card"><h3>Load</h3><div class="big">{h(read("/proc/loadavg").split(" ")[0])}</div></div>
  <div class="card"><h3>Conntrack</h3><div class="big">{h(cur)}</div>
    <div class="muted" style="font-size:12px">/ {h(mx)}</div></div>
  <div class="card"><h3>RAM trống</h3><div class="big">{h(available)}</div></div>
  <div class="card"><h3>Bảo vệ</h3><div class="big {'bad' if emergency else 'ok'}">
    {'KHẨN CẤP' if emergency else 'Bình thường'}</div></div>
</div>
<h4>Chặn</h4><div class="grid">{cards}</div>
<h4>Dịch vụ</h4><div class="card"><div class="grid">
{"".join('<div class="row" style="justify-content:space-between"><span class="mono">%s</span>'
         '<span class="%s">%s</span></div>' % (h(n), "ok" if s == "active" else "bad", h(s))
         for n, s in svc)}
</div></div>
<h4>Hành động</h4><div class="card"><div class="row">
<form class="inline" method="post" action="/action">{gate}
<button class="danger" name="action" value="emergency_on">BẬT khẩn cấp</button></form>
<form class="inline" method="post" action="/action">{gate}
<button class="primary" name="action" value="emergency_off">TẮT khẩn cấp</button></form>
<form class="inline" method="post" action="/action">{gate}
<button name="action" value="update_blocklist">Cập nhật blocklist</button></form>
<form class="inline" method="post" action="/action">{gate}
<button name="action" value="geoip_update">Cập nhật IP Việt Nam</button></form>
<form class="inline" method="post" action="/action">{gate}
<button name="action" value="reload_firewall">Nạp lại firewall</button></form>
</div></div>
<h4>Shield proxy</h4><div class="card"><div class="row" style="justify-content:space-between">
<span>windows <b class="mono">{h(pconf.get("WIN_IP", "-"))}</b> · mode <b>{h(pconf.get("FORWARD_MODE", "-"))}</b>
· geoip <b>{h(pconf.get("GEO_MODE", "-"))}</b></span><a class="btn" href="/proxy">Cấu hình</a></div>
<div class="muted mono" style="margin-top:10px;font-size:12px">{h(", ".join(pconf["PORTS"]) or "chưa có cổng")}</div>
</div>
<h4>Rule có lưu lượng</h4><div class="card" style="padding:0;overflow:hidden"><table>
<tr><th>Bảng</th><th>Chain</th><th>Rule</th><th class="n">Gói</th><th class="n">Byte</th></tr>
{rule_rows}</table></div>
<h4>Top IP</h4><div class="card" style="padding:0;overflow:hidden"><table>
<tr><th>IP</th><th class="n">Kết nối</th></tr>{top}</table></div>
"""
    return page("Tổng quan", body, "/", refresh=15)


def view_block(token, msg=""):
    conf = load_conf() or {}
    gate = field(conf, token)
    bh, bh_n = set_items("inet", "filter", "blackhole_v4")
    wl, wl_n = set_items("inet", "filter", "whitelist_v4")
    admins = proxy_read().get("ADMIN_IPS", [])
    body = f"""
<div class="grid">
  <div class="card"><h3>Chặn IP</h3><form method="post" action="/action">{gate}
    <input type="hidden" name="action" value="block_ip">
    <input name="ip" placeholder="1.2.3.4 hoặc 1.2.3.0/24" required>
    <div style="margin-top:12px"><button class="danger" style="width:100%">Chặn</button></div>
  </form></div>
  <div class="card"><h3>Bỏ chặn</h3><form method="post" action="/action">{gate}
    <input type="hidden" name="action" value="unblock_ip">
    <input name="ip" placeholder="1.2.3.4" required>
    <div style="margin-top:12px"><button style="width:100%">Bỏ chặn</button></div>
  </form></div>
  <div class="card"><h3>Whitelist</h3><form method="post" action="/action">{gate}
    <input type="hidden" name="action" value="allow_ip">
    <input name="ip" placeholder="203.0.113.10" required>
    <div style="margin-top:12px"><button style="width:100%">Thêm</button></div>
  </form></div>
</div>
<h4>Blocklist {len(bh)}/{bh_n}</h4>
<div class="card"><div class="mono">{h(", ".join(bh)) or "trống"}</div></div>
<h4>Whitelist {wl_n}</h4>
<div class="card"><div class="mono">{h(", ".join(wl)) or "trống"}</div></div>
<h4>IP quản trị</h4>
<div class="card"><div class="mono">{h(", ".join(admins)) or "trống"}</div></div>
"""
    return page("Chặn IP", body, "/blocklist", msg)


def view_proxy(token, msg=""):
    c = proxy_read()
    gate = field(load_conf() or {}, token)

    def opt(name, value, values):
        return "".join('<option value="%s"%s>%s</option>'
                       % (h(v), " selected" if v == value else "", h(v)) for v in values)

    body = f"""
<form method="post" action="/action">{gate}
<input type="hidden" name="action" value="save_proxy">
<div class="grid">
  <div class="card"><h3>Windows</h3>
    <label>IP server Windows</label><input name="WIN_IP" value="{h(c.get("WIN_IP", ""))}">
    <label>Chế độ</label><select name="FORWARD_MODE">
      {opt("FORWARD_MODE", c.get("FORWARD_MODE", "proxy"), ["proxy", "dnat"])}</select>
    <label>Cổng quản trị</label><input name="ADMIN_PORTS" value="{h(c.get("ADMIN_PORTS", ""))}">
  </div>
  <div class="card"><h3>Lọc quốc gia</h3>
    <label>GeoIP</label><select name="GEO_MODE">
      {opt("GEO_MODE", c.get("GEO_MODE", "vn-only"), ["vn-only", "off"])}</select>
    <label>IPv6</label><select name="ALLOW_V6">
      {opt("ALLOW_V6", c.get("ALLOW_V6", "no"), ["no", "yes"])}</select>
    <label>Khi thiếu dữ liệu GeoIP</label><select name="GEOIP_FAIL_OPEN">
      {opt("GEOIP_FAIL_OPEN", c.get("GEOIP_FAIL_OPEN", "no"), ["no", "yes"])}</select>
    <label>Card mạng</label>
    <div class="row"><input name="WAN_IF" value="{h(c.get("WAN_IF", "auto"))}" style="flex:1">
      <input name="LAN_IF" value="{h(c.get("LAN_IF", "auto"))}" style="flex:1"></div>
  </div>
  <div class="card"><h3>Giới hạn mỗi IP</h3>
    <label>UDP gói/giây</label><input name="UDP_PPS_PER_IP" value="{h(c.get("UDP_PPS_PER_IP", "200"))}">
    <label>TCP mới/giây</label><input name="TCP_NEWCONN_PER_IP" value="{h(c.get("TCP_NEWCONN_PER_IP", "30"))}">
    <label>TCP đồng thời</label><input name="TCP_CONN_PER_IP" value="{h(c.get("TCP_CONN_PER_IP", "60"))}">
  </div>
  <div class="card"><h3>Cổng game</h3>
    <textarea name="PORTS" spellcheck="false">{h(chr(10).join(c["PORTS"]))}</textarea>
    <p class="muted" style="font-size:12px">both 7777 · tcp 8080=80 · both 27000-27030</p>
  </div>
  <div class="card"><h3>IP quản trị</h3>
    <textarea name="ADMIN_IPS" spellcheck="false">{h(chr(10).join(c["ADMIN_IPS"]))}</textarea>
  </div>
</div>
<div class="card" style="margin-top:14px"><div class="row">
  <button class="primary">Lưu và áp dụng</button>
  <span class="muted mono">{h(PROXY)}</span></div></div>
</form>
"""
    return page("Shield / Proxy", body, "/proxy", msg)


def view_rules(token):
    _, out, err = run([NFT, "list", "ruleset"], timeout=20)
    text = (out or err)[:60000]
    body = f"""<div class="card"><div class="row" style="justify-content:space-between">
<span>ruleset hiện tại</span>
<form class="inline" method="post" action="/action">{field(load_conf() or {}, token)}
<button name="action" value="reload_firewall">Nạp lại</button></form></div></div>
<pre style="margin-top:14px">{h(text)}</pre>"""
    return page("Ruleset", body, "/rules")


def view_logs(token):
    _, kernel, _ = run(["journalctl", "-k", "-n", "120", "--no-pager"], timeout=20)
    _, f2b, _ = run(["fail2ban-client", "status"], timeout=15)
    _, jails, _ = run(["bash", "-lc", "for j in sshd ddos-scanner recidive; do "
                                        "fail2ban-client status $j 2>/dev/null; done"], timeout=20)
    body = f"<h4>fail2ban</h4><pre>{h(f2b or 'không chạy')}\n\n{h(jails)}</pre>" \
           f"<h4>Kernel log</h4><pre>{h(kernel)}</pre>"
    return page("Log", body, "/logs")


class App(BaseHTTPRequestHandler):
    server_version = "ddos-panel/1.0"

    def conf(self):
        return load_conf() or {}

    def send_html(self, text, status=200, headers=None):
        data = text.encode("utf-8")
        self.send_response(status)
        for key, value in (("Content-Type", "text/html; charset=utf-8"),
                           ("Content-Length", str(len(data))),
                           ("X-Frame-Options", "DENY"),
                           ("X-Content-Type-Options", "nosniff"),
                           ("Referrer-Policy", "no-referrer"),
                           ("Cache-Control", "no-store"),
                           ("Content-Security-Policy",
                            "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")):
            self.send_header(key, value)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, where, cookie=None):
        self.send_response(303)
        self.send_header("Location", where)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                if key.strip() == name:
                    return value.strip()
        return ""

    def session(self):
        tok = self.cookie("ddos_sess")
        if tok and SESS.get(tok, 0) > time.time():
            return tok
        SESS.pop(tok, None)
        return None

    def flash(self, token, kind, text):
        SESS["msg:" + token] = (time.time() + 20, kind, text)

    def take(self, token):
        item = SESS.get("msg:" + token)
        return (item[1], item[2]) if item and item[0] > time.time() else ""

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/login", "/logout"):
            self.redirect("/")
            return
        token = self.session()
        if not token:
            self.send_html(login_page())
            return
        msg = self.take(token)
        try:
            if path == "/":
                self.send_html(view_home(token))
            elif path == "/blocklist":
                self.send_html(view_block(token, msg))
            elif path == "/proxy":
                self.send_html(view_proxy(token, msg))
            elif path == "/rules":
                self.send_html(view_rules(token))
            elif path == "/logs":
                self.send_html(view_logs(token))
            else:
                self.send_html(page("404", '<div class="card">không tìm thấy</div>'), 404)
        except Exception as exc:
            self.send_html(page("Lỗi", "<pre>%s</pre>" % h(repr(exc))), 500)

    def do_POST(self):
        path = urlparse(self.path).path
        size = int(self.headers.get("Content-Length") or 0)
        if size > 1000000:
            self.send_html("quá lớn", 413)
            return
        form = parse_qs(self.rfile.read(size).decode("utf-8", "replace"), keep_blank_values=True)
        if path == "/login":
            self.login(form)
            return
        token = self.session()
        if not token:
            self.send_html(login_page("phiên đã hết hạn"), 401)
            return
        if not hmac.compare_digest(form.get("csrf", [""])[0], token_of(self.conf(), token)):
            self.send_html(login_page("csrf không hợp lệ"), 403)
            return
        kind, text, back = self.action(form.get("action", [""])[0], form)
        self.flash(token, kind, text)
        self.redirect(back)

    def login(self, form):
        ip = self.client_address[0]
        count, last = FAILS.get(ip, (0, 0))
        if count >= 8 and time.time() - last < 300:
            self.send_html(login_page("thử quá nhiều, chờ 5 phút"), 429)
            return
        if form.get("user", [""])[0] == self.conf().get("user") and \
                pwcheck(form.get("password", [""])[0], self.conf()):
            FAILS.pop(ip, None)
            token = secrets.token_urlsafe(32)
            hours = int(self.conf().get("session_hours", 12))
            SESS[token] = time.time() + hours * 3600
            self.redirect("/", "ddos_sess=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d"
                          % (token, hours * 3600))
        else:
            FAILS[ip] = (count + 1, time.time())
            time.sleep(0.6)
            self.send_html(login_page("sai tài khoản hoặc mật khẩu"), 401)

    def action(self, name, form):
        ip = form.get("ip", [""])[0].strip()
        if name in ("block_ip", "unblock_ip", "allow_ip"):
            if not IPRE.match(ip):
                return "err", "IP không hợp lệ", "/blocklist"
            if name == "allow_ip":
                rc, _, err = elem_op("add", "inet", "filter", "whitelist_v4", ip)
                elem_op("add", "inet", "gamefilter", "admin4", ip)
            else:
                verb = "add" if name == "block_ip" else "delete"
                rc, _, err = elem_op(verb, "inet", "filter", "blackhole_v4", ip)
            CACHE.clear()
            if rc == 0:
                return "ok", "cập nhật xong: " + ip, "/blocklist"
            return "err", err.strip(), "/blocklist"
        if name in ("emergency_on", "emergency_off"):
            rc, out, err = run(["/usr/local/sbin/ddos-emergency", name.split("_")[1]], timeout=60)
            CACHE.clear()
            return ("ok" if rc == 0 else "err", "khẩn cấp " + name.split("_")[1], "/")
        if name == "update_blocklist":
            rc, out, err = run(["/usr/local/sbin/ddos-update-blocklist"], timeout=600)
            CACHE.clear()
            return ("ok" if rc == 0 else "err", tail(out or err), "/")
        if name == "geoip_update":
            rc, out, err = run(["/usr/local/sbin/geoip-vn-update"], timeout=600)
            CACHE.clear()
            return ("ok" if rc == 0 else "err", tail(out or err), "/")
        if name == "reload_firewall":
            rc, out, err = run([NFT, "-f", "/etc/nftables.conf"], timeout=60)
            CACHE.clear()
            return ("ok" if rc == 0 else "err", "đã nạp lại" if rc == 0 else err.strip()[:400], "/")
        if name == "save_proxy":
            ok, text = proxy_write(proxy_read(), {k: v[0] for k, v in form.items()})
            if not ok:
                return "err", text, "/proxy"
            rc, out, err = run(["/usr/local/sbin/gen-proxy-rules"], timeout=120)
            CACHE.clear()
            if rc == 0:
                return "ok", text + ", đã áp dụng", "/proxy"
            return "err", "lưu xong nhưng áp dụng lỗi: " + (err or out).strip()[:400], "/proxy"
        return "err", "hành động lạ: " + name, "/"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s %s\n" % (time.strftime("%H:%M:%S"), self.client_address[0],
                                         fmt % args))


def main(argv):
    if len(argv) > 1 and argv[1] == "--init":
        user = argv[argv.index("--user") + 1] if "--user" in argv else "admin"
        return init_conf(user, force="--force" in argv)
    if len(argv) > 2 and argv[1] == "--hash":
        salt, digest = pwhash(argv[2])
        print(json.dumps({"salt": salt, "hash": digest}, indent=2))
        return 0
    if len(argv) > 1 and argv[1] in ("-h", "--help"):
        print("ddos-panel [--init [--user N] [--force]] [--hash PW]")
        return 0

    conf = load_conf()
    if not conf:
        print("chưa có " + CONF + ", chạy: ddos-panel --init", file=sys.stderr)
        return 2
    bind = conf.get("bind", "127.0.0.1")
    port = int(conf.get("port", 8080))
    if bind not in ("127.0.0.1", "localhost", "::1"):
        print("cảnh báo: nghe trên %s:%d, nên dùng SSH tunnel" % (bind, port), file=sys.stderr)
    srv = ThreadingHTTPServer((bind, port), App)
    print("ddos-panel: http://%s:%d" % (bind, port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
