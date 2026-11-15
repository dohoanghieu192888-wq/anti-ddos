# FireWall — Bộ chống DDoS cho Ubuntu 20.04 (nftables)

Bộ cấu hình hoàn chỉnh giúp server **Ubuntu 20.04 (kernel 5.4)** chịu được các đợt
tấn công DDoS tầng 3/4 (SYN flood, UDP flood, ICMP flood, port scan, kết nối rác)
và tầng 7 cơ bản (slowloris, request flood, brute-force SSH).

Toàn bộ dùng **nftables** (công cụ chuẩn của Ubuntu 20.04, nhanh hơn iptables khi
có hàng nghìn rule) + tuning kernel + fail2ban + rate-limit nginx (tuỳ chọn).

---

## ⚠️ Đọc trước: giới hạn thực tế

Không có firewall nào trên một server đơn lẻ chống được **DDoS volumetric**
(tấn công làm nghẽn đường truyền: 10–500 Gbps). Khi băng thông uplink của VPS bị
lấp đầy, gói tin không tới được kernel thì mọi rule đều vô nghĩa.

Bộ này giải quyết đúng phần nó làm được — **bảo vệ tài nguyên CPU/RAM/conntrack
của server** trước các đợt tấn công đốt tài nguyên (SYN flood, UDP amplification,
kết nối rác), tức là loại tấn công phổ biến và rẻ nhất.

Để chống tấn công volumetric, cần lớp phía trước:
- **Cloudflare** (proxy, bật "Under Attack Mode") — miễn phí cho web.
- Hoặc VPS có **upstream filtering / scrubbing** (OVH, Vultr, hetzner…).
- Hoặc dùng **anycast + nhiều node**.

Kiến trúc khuyến nghị: `Người dùng → Cloudflare → VPS (bộ firewall này) → app`.
Khi đó chỉ nên mở port 80/443 cho dải IP của Cloudflare và chặn IP gốc.

---

## Nội dung

| File | Mô tả |
|---|---|
| **`setup-all.sh`** | **Cài TẤT CẢ trong 1 lệnh (firewall + shield proxy + panel)** |
| `install.sh` | Cài riêng lớp firewall (chạy 1 lần) |
| `panel/ddos-panel.py` | Panel web quản trị (1 file Python, chỉ dùng stdlib) |
| `uninstall.sh` | Gỡ sạch, trả về mặc định |
| `nftables/ddos.nft` | Ruleset chính: chống SYN flood, scan, amplification, blocklist |
| `nftables/emergency-on.nft` / `emergency-off.nft` | Chế độ khẩn cấp khi đang bị tấn công |
| `sysctl/99-ddos-hardening.conf` | Tuning kernel (backlog, syncookies, conntrack, timeouts) |
| `sysctl/99-bbr.conf` | BBR + fq (tăng thông lượng, giảm bufferbloat) |
| `modprobe/nf_conntrack.conf` | Tăng hashsize bảng conntrack |
| `security/99-ddos-limits.conf` | Giới hạn file descriptor |
| `fail2ban/jail.local` | Auto-ban SSH brute-force + IP bị firewall drop |
| `fail2ban/filter.d/nft-input-drop.conf` | Filter đọc log drop của nftables |
| `nginx/*` | Rate limit tầng HTTP (nếu bạn chạy nginx) |
| `scripts/status.sh` | Xem trạng thái, bộ đếm, tải hệ thống |
| `scripts/emergency-mode.sh` | Bật/tắt chế độ khẩn cấp |
| `scripts/update-blocklist.sh` | Tải blocklist công khai (FireHOL, Spamhaus DROP) |
| `systemd/*` | Timer tự cập nhật blocklist mỗi ngày |
| `blocklist/whitelist.txt` | IP không bao giờ bị chặn |

**Module `game-proxy/`** — dùng VPS Ubuntu làm **trung gian chống DDoS cho server
Windows** (người chơi kết nối IP VPS, NAT về Windows, chỉ cho IP Việt Nam).
Xem [`game-proxy/README.md`](game-proxy/README.md).

---

## Cài đặt

Yêu cầu: Ubuntu 20.04 x86_64, quyền root, đã có phiên SSH dự phòng.

### Cách 1 — Một lệnh cho tất cả (khuyến nghị)

```bash
git clone <repo> && cd anti-ddos

# firewall + panel web
sudo bash setup-all.sh

# firewall + panel + shield game Windows (chỉ cho IP Việt Nam)
sudo bash setup-all.sh --with-proxy --win-ip 10.10.0.5
```

Kết thúc script in ra: địa chỉ panel, tài khoản/mật khẩu (lưu ở
`/root/ddos-panel-credentials.txt`) và tên đăng nhập SSH tunnel.

### Cách 2 — Cài từng lớp

```bash
cd FireWall   # hoặc anti-ddos
sudo bash install.sh                     # lớp 1: firewall chống DDoS
sudo bash game-proxy/install-proxy.sh    # lớp 2: shield proxy (tuỳ chọn)
```

Script sẽ: cài `nftables` + `fail2ban`, **kiểm tra cú pháp ruleset trước khi áp dụng**
(`nft -c -f`, sai là dừng, không thay đổi gì), backup cấu hình cũ vào
`/root/ddos-firewall-backup-<thời-gian>/`, nạp rule, áp sysctl, cấu hình fail2ban,
cài các lệnh `ddos-status`, `ddos-emergency`, `ddos-update-blocklist`.

> Sau khi cài, **mở terminal thứ hai** kiểm tra SSH/website vẫn vào được trước khi
> đóng phiên hiện tại. IP đang SSH được tự động thêm vào whitelist.

---

## Cấu hình cổng dịch vụ (bắt buộc kiểm tra)

Mặc định chỉ mở **22, 80, 443**. Sửa `/etc/nftables.d/ddos.nft` — tìm hai dòng
`tcp dport 22 ...` và `tcp dport { 80, 443 } ...`, thêm cổng mới ngay dưới:

```nft
tcp dport { 80, 443 } ct state new counter accept
tcp dport 8443 ct state new counter accept
tcp dport 53 counter accept
udp dport 53 counter accept
```

Áp dụng lại (không cần reboot):

```bash
sudo nft -c -f /etc/nftables.d/ddos.nft && sudo nft -f /etc/nftables.d/ddos.nft
```

Nếu bạn chạy **Docker**, chain `forward` đang có `policy drop` sẽ chặn container.
Đổi thành `policy accept;` trong `chain forward` của `ddos.nft`.

Nếu trước đây dùng **ufw**: installer sẽ hỏi tắt (hai bộ ruleset xung đột nhau).

---

## Chế độ khẩn cấp (khi đang bị tấn công)

Khi thấy load tăng vọt, `nft-input-drop` tăng nhanh, web chậm:

```bash
sudo ddos-emergency on      # ngưỡng rất chặt
sudo ddos-emergency status  # xem tình trạng
sudo ddos-emergency off     # hết tấn công thì tắt
```

Chế độ này: SYN ≤ 15/s mỗi IP, kết nối mới ≤ 25/s mỗi IP, web ≤ 20 kết nối
đồng thời mỗi IP, SSH ≤ 2 lần/phút, chặn toàn bộ UDP amplification. Traffic hợp lệ
cũng có thể bị chậm — chỉ dùng tạm thời.

---

## Blocklist tự động

```bash
sudo ddos-update-blocklist     # chạy ngay
systemctl list-timers | grep ddos
```

Nguồn: FireHOL level1/level2 + Spamhaus DROP/EDROP, khoảng vài chục nghìn dải IP
của các máy bị nhiễm/brute-force nổi tiếng. Tự cập nhật mỗi ngày qua systemd timer.

Muốn **không bao giờ** chặn IP nào (IP admin, monitoring, Cloudflare…), thêm vào
`/etc/ddos/whitelist.txt` rồi áp dụng:

```bash
echo "203.0.113.10" | sudo tee -a /etc/ddos/whitelist.txt
sudo nft add element inet filter whitelist_v4 { 203.0.113.10 }
```

---

## Kiểm tra & giám sát

```bash
sudo ddos-status                    # tổng quan: bộ đếm, conntrack, top IP, tải
sudo nft list table inet filter     # xem toàn bộ rule + counter
sudo nft list set inet filter blackhole_v4 | head
sudo conntrack -C                   # số kết nối đang track
sudo journalctl -k | grep nft-      # log các gói bị drop
dmesg -w | grep nft-                # theo dõi realtime
sudo fail2ban-client status sshd
```

Bộ đếm quan trọng cần xem:

| Counter | Ý nghĩa |
|---|---|
| `syn_v4` | SYN vượt 60/s từ 1 IP — đang bị SYN flood |
| `newconn_v4` | IP tạo > 25 kết nối mới/s — scan hoặc flood |
| `webconn_v4` | IP giữ > 60 kết nối web — slowloris |
| `ssh_v4` + `nft-ssh-flood` | Brute-force SSH |
| `blackhole_v4` | Gói từ IP trong blocklist |

---

## Nginx (tuỳ chọn)

Nếu có nginx, installer đã copy:
- `/etc/nginx/conf.d/00-ddos-http.conf` (zone rate-limit, tự include)
- `/etc/nginx/snippets/ddos-server.conf` (chống slowloris + limit_conn)

Thêm 1 dòng vào block `server { }` của site:

```nginx
include snippets/ddos-server.conf;
```

Rồi `sudo nginx -t && sudo systemctl reload nginx`.

---

## Cơ chế bảo vệ — giải thích ngắn

**Tầng 3/4 (`nftables/ddos.nft`)**

1. **Bảng `ddos_raw` (hook prerouting, priority raw)** — chạy *trước* conntrack,
   rẻ nhất: drop fragment IPv4, drop tổ hợp cờ TCP bất hợp lệ (FIN+SYN, SYN+RST,
   XMAS…), và drop SYN vượt 60/s mỗi IP. Nhờ vậy SYN flood không bao giờ vào tới
   SYN backlog hay bảng conntrack.
2. **`ct state invalid drop`** — chặn gói giả mạo / out-of-window / stray ACK.
3. **ICMP rate limit** — ping flood, smurf; vẫn cho ICMP lỗi + ICMPv6 ND cần thiết.
4. **Chặn cổng UDP khuếch đại** — chargen(19), NTP(123), NetBIOS(137), SNMP(161),
   LDAP(389), SSDP(1900), memcached(11211), mDNS(5353): các cổng bị lợi dụng để
  反射/amplification (hệ số khuếch đại 3–50000 lần).
5. **`meter newconn_v4`** — 1 IP tạo > 25 kết nối mới/s bị drop (chống scan/flood).
6. **`meter webconn_v4 { ip saddr ct count over 60 }`** — giới hạn số kết nối
   đồng thời *theo từng IP* (chống slowloris và flood giữ socket).
7. **SSH rate limit** 6 lần/phút mỗi IP + log để fail2ban ban.
8. **`policy drop`** — mặc định chặn tất cả, chỉ mở đúng cổng khai báo.
9. **Log có giới hạn** (`limit rate 20/minute log`) — tránh tự làm ngập đĩa khi bị flood.

**Kernel (`sysctl/99-ddos-hardening.conf`)**

| Thông số | Giá trị | Tác dụng |
|---|---|---|
| `tcp_syncookies` | 1 | Vẫn bắt tay TCP được khi backlog đầy (SYN flood) |
| `tcp_max_syn_backlog` | 65536 | Hàng đợi SYN lớn, chịu burst |
| `somaxconn` | 65535 | Hàng đợi accept lớn cho web server |
| `netdev_max_backlog` | 65536 | Chịu burst gói tin từ NIC |
| `nf_conntrack_max` | 1048576 | Bảng conntrack lớn, không bị "table full, dropping packet" |
| `nf_conntrack_tcp_timeout_*` | 20–3600s | Nhả entry nhanh khi bị flood |
| `tcp_max_orphans` / `max_tw_buckets` | 262k / 1.44M | Chống cạn socket rác |
| `rp_filter`, `accept_source_route=0` | | Chống giả mạo nguồn |
| `icmp_echo_ignore_broadcasts` | 1 | Chống smurf amplification |
| `tcp_congestion_control` | bbr | Thông lượng tốt hơn khi mạng mất gói |
| `file-max` / `nofile` | 2M / 65535 | Không hết file descriptor |

**fail2ban**: ban IP brute-force SSH và IP bị firewall drop ≥ 25 lần/phút;
tái phạm thì thời gian ban tăng gấp đôi (tối đa 7 ngày).

---

## Panel web (1 file, không cần pip/node)

Sau khi cài, panel chạy tại `http://127.0.0.1:8080` (chỉ loopback). Truy cập từ máy bạn:

```bash
ssh -L 8080:127.0.0.1:8080 root@<IP-VPS>
# rồi mở http://127.0.0.1:8080
```

Tài khoản/mật khẩu sinh ngẫu nhiên, xem `/root/ddos-panel-credentials.txt`.

| Trang | Chức năng |
|---|---|
| **Tổng quan** | load/RAM/conntrack, bộ đếm chặn, trạng thái dịch vụ, top IP, BẬT/TẮT khẩn cấp, cập nhật blocklist/GeoIP, nạp lại firewall |
| **Chặn IP** | chặn/bỏ chặn IP-CIDR, thêm whitelist, xem blocklist |
| **Shield / Proxy** | sửa IP Windows, chế độ proxy/dnat, danh sách cổng game, IP quản trị, giới hạn chống flood → lưu và áp dụng ngay |
| **Ruleset** | toàn bộ `nft list ruleset` |
| **Log** | fail2ban + kernel log (các gói bị drop) |

Bảo mật: đăng nhập bằng mật khẩu (PBKDF2-SHA256 120k vòng), session cookie
`HttpOnly; SameSite=Strict;` + CSRF token, giới hạn 8 lần đăng nhập sai/5 phút,
mặc định **chỉ nghe 127.0.0.1** nên phải qua SSH tunnel (không mở port ra Internet).

```bash
systemctl status ddos-panel
journalctl -u ddos-panel -n 30
# quên mật khẩu:
sudo /usr/local/sbin/ddos-panel --init --force && sudo systemctl restart ddos-panel
```

> Nếu muốn nghe ra ngoài, sửa `bind` trong `/etc/ddos/panel.json` sang `0.0.0.0`
> và **chỉ cho IP của bạn** vào port đó bằng `ADMIN_PORTS` trong shield proxy,
> hoặc luôn dùng SSH tunnel (an toàn hơn).

---

## Dùng VPS làm trung gian cho server game Windows

Xem [`game-proxy/README.md`](game-proxy/README.md). Tóm tắt:

```bash
sudo bash install.sh                     # lớp 1: chống DDoS
sudo bash game-proxy/install-proxy.sh    # lớp 2: NAT + chỉ cho IP Việt Nam
sudo proxy-status                        # kiểm tra
```

---

## Gỡ cài đặt

```bash
sudo bash uninstall.sh
```

Xoá bảng nftables, sysctl, script, timer, snippet nginx; giữ lại fail2ban (có in
hướng dẫn gỡ) và backup cấu hình cũ trong `/root/ddos-firewall-backup-*`.

---

## Sự cố thường gặp

**Tự khoá SSH ra ngoài**
Vào bằng VNC/console của nhà cung cấp:
```bash
sudo nft -f /etc/ddos/emergency-off.nft
sudo nft insert rule inet filter input ip saddr <IP-của-bạn> accept
sudo systemctl stop nftables     # tắt hẳn, rồi sửa lại ddos.nft
```

**`table full, dropping packet` trong dmesg** → tăng `nf_conntrack_max` hoặc giảm
timeout (đã đặt sẵn 1M; nếu vẫn gặp, tăng hashsize tương ứng trong
`/etc/modprobe.d/nf_conntrack.conf`).

**fail2ban không khởi động** → `sudo fail2ban-client -t`, xem
`journalctl -u fail2ban -n 50`. Nếu action `nftables` lỗi trên bản 0.11, giữ
`banaction = iptables-multiport` (mặc định trong `jail.local`).

**Website bị 429** → đó là rate limit của nginx (20 req/s mỗi IP). Tăng `rate=` trong
`/etc/nginx/conf.d/00-ddos-http.conf` hoặc `burst=` trong `ddos-server.conf`.

**Kiểm tra rule có thực sự chặn không**
```bash
sudo nft -a list chain inet filter input | grep -E 'syn_v4|newconn|webconn'
```

---

## Tóm tắt nhanh (cheat sheet)

```bash
sudo ddos-status                # đang bị gì?
sudo ddos-emergency on|off      # đang bị tấn công / hết
sudo ddos-update-blocklist      # cập nhật blacklist
sudo nft list ruleset           # toàn bộ firewall
sudo journalctl -k | grep nft   # log drop
```
