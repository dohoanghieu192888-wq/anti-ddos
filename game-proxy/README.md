# Game Proxy — VPS Ubuntu làm trung gian chống DDoS cho server Windows

Mô hình:

```
Người chơi (chỉ Việt Nam)  ──TCP/UDP──►  VPS Ubuntu (IP công khai, firewall chống DDoS)
                                            │  nftables NAT (kernel, không process nào chạy)
                                            ▼
                                     Server game Windows (IP ẩn)
```

- Người chơi kết nối **IP của VPS**, không bao giờ thấy IP Windows → IP thật được giấu.
- Toàn bộ traffic đi qua **NAT của kernel** (nftables), không phải proxy ứng dụng:
  tốc độ gần như trực tiếp, không cần cài gì thêm, chịu được hàng chục nghìn kết nối.
- **Chỉ IP Việt Nam** được vào cổng game, tất cả quốc gia khác bị drop ngay tại
  `prerouting priority -350` (trước cả conntrack → rất rẻ CPU).
- Cổng **tự map**: khai báo danh sách port trong 1 file, script sinh rule tự động;
  có thể map `8080` (VPS) → `80` (Windows), hỗ trợ dải cổng.

Kết hợp với firewall chính (`../install.sh`) là 2 lớp: chống SYN/UDP flood + blocklist
ở lớp ngoài, GeoIP + rate-limit theo IP ở lớp trong.

---

## Cài đặt

```bash
cd FireWall
sudo bash install.sh                 # lớp 1: firewall chống DDoS (nên chạy trước)
sudo bash game-proxy/install-proxy.sh  # lớp 2: NAT + GeoIP
```

Installer sẽ hỏi **IP của server Windows**, tự phát hiện card mạng, sinh ruleset,
tải danh sách IP Việt Nam và bật systemd (nạp lại GeoIP mỗi khi boot + cập nhật hằng ngày).

Cấu hình nằm ở `/etc/ddos/game-proxy.conf`.

---

## Cấu hình `/etc/ddos/game-proxy.conf`

```bash
WIN_IP="10.10.0.5"        # IP server Windows (để "" nếu game chạy trên chính VPS)
FORWARD_MODE="proxy"      # proxy (SNAT, ẩn IP người chơi) | dnat (giữ IP thật)

PORTS=(
  "tcp 80=80"             # VPS:80 -> Windows:80 (truy cập http://IP-VPS/)
  "tcp 8081=80"            # ví dụ đổi port public: VPS:8081 -> Windows:80
  "both 27015"
)

ADMIN_PORTS="3389"        # RDP: chỉ ADMIN_IPS vào được
ADMIN_IPS=( "203.0.113.10" )

GEO_MODE="vn-only"        # chặn mọi IP không phải Việt Nam
UDP_PPS_PER_IP="200"
TCP_NEWCONN_PER_IP="30"
TCP_CONN_PER_IP="60"
```

Sửa xong:

```bash
sudo gen-proxy-rules     # kiểm tra cú pháp (nft -c) rồi áp dụng
sudo proxy-status        # xem trạng thái
```

Không cần mở port bằng `ufw`/`iptables` gì thêm, và **không có process nào listen**
trên các cổng game — kernel NAT nhận và chuyển tiếp trực tiếp.

---

## Game chạy ngay trên VPS (không cần Windows)

```bash
WIN_IP=""                          # để trống nếu mọi cổng đều là local
PORTS=(
  "both 14445=local:7777"          # người chơi vào VPS:14445 -> game ở 7777
  "tcp  8080=127.0.0.1:80"         # hoặc viết 127.0.0.1:<cổng>
)
```

- Người chơi chỉ cần biết `IP-VPS:14445`; cổng thật `7777` **không mở ra ngoài**
  (firewall chỉ mở 22/80/443) nên không thể DDoS trực tiếp vào game.
- Game chỉ cần listen `0.0.0.0:7777` hoặc `127.0.0.1:7777`.
- Cơ chế: `dnat ip to 127.0.0.1:<cổng>` + `net.ipv4.conf.all.route_localnet=1`
  (installer bật sẵn), và cổng đích được mở ở INPUT qua chain `local_svc`.
- Đổi cổng công khai bao nhiêu cũng được (`14445`, `25565`, `30000`…), miễn là
  chưa trùng port khác đang dùng.

---

## Hai chế độ chuyển tiếp — chọn cái nào?

### `FORWARD_MODE="proxy"` (mặc định, dễ nhất)

VPS làm SNAT (masquerade). Windows trả lời về VPS, VPS chuyển cho người chơi.

- ✅ Chạy được với **mọi** IP Windows (public, private, khác nhà cung cấp, qua tunnel).
- ✅ Không cần đổi route trên Windows.
- ❌ Game server thấy **mọi người chơi là IP của VPS** → log/anti-cheat/ban theo IP
  trên Windows mất tác dụng; nếu game cần IP thật để xử lý thì dùng chế độ `dnat`.

### `FORWARD_MODE="dnat"` (giữ IP thật người chơi)

Chỉ DNAT, không SNAT → Windows thấy IP thật của người chơi.

Điều kiện: Windows phải gửi reply **ngược về VPS**, tức là:
- Windows nối chung dải private với VPS (cùng provider/VPC), hoặc
- Windows nối VPS bằng **WireGuard** và default gateway (hoặc route tới dải IP
  người chơi) trỏ về IP tunnel của VPS.

Ví dụ trên Windows (PowerShell, chạy Administrator), khi VPS là `10.66.0.1` qua WireGuard:

```powershell
route add 0.0.0.0 mask 0.0.0.0 10.66.0.1 metric 5
```

Nếu reply đi sai đường, người chơi sẽ kết nối được nhưng bị "timeout khi vào game"
(handshake xong, dữ liệu không về) — đó là dấu hiệu route chưa đúng, đổi về `proxy`.

---

## Việc phải làm trên máy Windows

1. **Windows Firewall**: cho phép IP của VPS vào các cổng game (không mở cho `Any`).
   ```powershell
   New-NetFirewallRule -DisplayName "GameProxy-VPS" -Direction Inbound `
     -Protocol Any -LocalPort 7777,27015,27000-27030 -RemoteAddress <IP_VPS> -Action Allow
   ```
2. Không cần mở port trên router cho IP người chơi nữa — chỉ VPS gọi tới.
3. Chế độ `proxy`: nếu game server có chức năng ban IP, hãy dùng ban theo tên/tài khoản.

---

## Cơ chế lọc

**GeoIP (chỉ Việt Nam)** — `table inet gamefilter`, hook `prerouting priority -350`:

```nft
tcp dport @game_ports jump geo_allow
udp dport @game_ports jump geo_allow

chain geo_allow {
    ip  saddr @admin4 return   # IP quản trị luôn được phép
    ip  saddr @vn4    return   # IP Việt Nam
    ip6 saddr @vn6    return   # (nếu bật IPv6)
    limit rate 10/minute log prefix "geo-block: " level info
    counter drop               # tất cả quốc gia khác
}
```

- Bộ `vn4` chứa ~1000+ dải CIDR của Việt Nam, tải từ ipdeny.com
  (dự phòng: `country-ip-blocks`), cache ở `/var/lib/ddos/vn.zone`.
- Cập nhật tự động hằng ngày (03:17) qua `ddos-geoip.timer`; lúc boot dùng cache nên
  game hoạt động ngay, không cần chờ mạng.
- IP Việt Nam thay đổi rất ít; nếu nhà mạng mới cấp dải IP mà danh sách chưa có,
  người chơi sẽ bị chặn — kiểm tra log `geo-block` và chạy `sudo geoip-vn-update`.

**Chống flood theo IP (trong cùng hook)**: giới hạn UDP pps, số kết nối TCP mới/giây,
và số kết nối TCP đồng thời cho từng IP nguồn (mặc định 200 pps / 30 conn/s / 60 conn).

**Lớp ngoài** (`install.sh`): SYN flood 60/s mỗi IP tại hook `raw`, blocklist
FireHOL/Spamhaus, giới hạn ICMP, chặn cổng UDP khuếch đại, fail2ban.

---

## Kiểm tra

```bash
sudo proxy-status                    # tổng quan: IP VN, NAT, bộ đếm, top IP
sudo nft list table inet gameproxy   # rule NAT
sudo nft list table inet gamefilter  # rule GeoIP
sudo nft list set inet gamefilter vn4 | head -5
sudo journalctl -k | grep geo-block  # IP nước ngoài bị chặn
sudo conntrack -L -p tcp --dport 7777 | head
```

Test từ máy ngoài Việt Nam (hoặc VPN nước ngoài): kết nối cổng game phải bị **timeout**,
và `proxy-status` hiện bộ đếm `geo-block` tăng.

Test từ Việt Nam: kết nối vào `IP_VPS:cổng` → vào game bình thường.

---

## Sự cố thường gặp

| Hiện tượng | Nguyên nhân / cách xử lý |
|---|---|
| Vào được nhưng bị treo/timeout khi chơi | `FORWARD_MODE="dnat"` nhưng Windows chưa route reply về VPS → đổi `proxy` hoặc sửa route |
| Người chơi Việt Nam vẫn bị chặn | Dải IP của nhà mạng chưa có trong danh sách → `sudo geoip-vn-update`; hoặc IP đó là VN nhưng qua VPN nước ngoài |
| Bị chặn hết sau khi reboot | `sudo geoip-vn-update --cache-only`; kiểm tra `systemctl status ddos-geoip-boot` |
| Không forward được gì | Thiếu rule trong chain `proxy_fwd` → chạy lại `sudo gen-proxy-rules` (script tự sinh và nạp chain này) |
| Thấy `conntrack: table full` | Tăng `net.netfilter.nf_conntrack_max` (đã đặt 1M ở `install.sh`) hoặc hạ `TCP_CONN_PER_IP` |
| Muốn tạm tắt lọc quốc gia | Đổi `GEO_MODE="off"` rồi `sudo gen-proxy-rules` |

---

## Gỡ

```bash
sudo nft delete table inet gameproxy
sudo nft delete table inet gamefilter
sudo systemctl disable --now ddos-geoip.timer ddos-geoip-boot.service
sudo rm -f /etc/systemd/system/ddos-geoip*.service /etc/systemd/system/ddos-geoip.timer \
           /etc/nftables.d/game-proxy.nft /etc/nftables.d/zz-proxy-forward.nft \
           /etc/sysctl.d/99-game-proxy.conf \
           /usr/local/sbin/gen-proxy-rules /usr/local/sbin/geoip-vn-update /usr/local/sbin/proxy-status
sudo systemctl daemon-reload
```
