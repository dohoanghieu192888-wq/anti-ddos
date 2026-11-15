#!/usr/bin/env bash
# =====================================================================
#  install-proxy.sh — biến VPS Ubuntu thành shield chống DDoS cho
#                     server game Windows (NAT + GeoIP Việt Nam)
#
#  Chạy:  sudo bash game-proxy/install-proxy.sh
#  Yêu cầu: đã cài firewall chính (bash install.sh) — nếu chưa, script vẫn
#           cài NAT nhưng sẽ cảnh báo.
# =====================================================================
set -Eeuo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="/etc/ddos/game-proxy.conf"

GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'
ok()   { echo "${GREEN}[ OK ]${NC} $*"; }
info() { echo "${YELLOW}[ .. ]${NC} $*"; }
warn() { echo "${YELLOW}[WARN]${NC} $*"; }
die()  { echo "${RED}[FAIL]${NC} $*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "Phải chạy bằng root: sudo bash game-proxy/install-proxy.sh"

# ---------------------------------------------------------------------
# 1. Cấu hình
# ---------------------------------------------------------------------
mkdir -p /etc/ddos /etc/nftables.d /var/lib/ddos

if [[ ! -f "$CONF" ]]; then
	info "Chưa có $CONF — tạo từ file mẫu"
	install -m 0640 "$REPO_DIR/game-proxy.conf.example" "$CONF"
	if [[ -t 0 ]]; then
		echo
		echo "Nhập IP của server Windows (game server)."
		echo "  - Cùng nhà cung cấp / mạng private : ví dụ 10.10.0.5"
		echo "  - Nối qua WireGuard / Tailscale     : ví dụ 10.66.0.2"
		read -r -p "WIN_IP: " win_ip
		if [[ "$win_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			sed -i "s|^WIN_IP=.*|WIN_IP=\"$win_ip\"|" "$CONF"
			ok "WIN_IP = $win_ip"
		else
			warn "IP không hợp lệ — giữ mặc định, hãy sửa $CONF rồi chạy lại"
		fi
	fi
else
	ok "Dùng cấu hình sẵn có: $CONF"
fi

# ---------------------------------------------------------------------
# 2. Gói cần thiết
# ---------------------------------------------------------------------
command -v nft >/dev/null || {
	info "Cài nftables..."
	DEBIAN_FRONTEND=noninteractive apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables curl ca-certificates
}
command -v curl >/dev/null || die "thiếu curl (apt-get install curl)"

# ---------------------------------------------------------------------
# 3. Bật IP forwarding
# ---------------------------------------------------------------------
info "Bật net.ipv4.ip_forward..."
cat >/etc/sysctl.d/99-game-proxy.conf <<'EOF'
# VPS làm trung gian NAT cho server game
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
# Giảm timeout để nhả kết nối nhanh khi bị flood (game nhiều kết nối ngắn)
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_udp_timeout = 30
EOF
sysctl -p /etc/sysctl.d/99-game-proxy.conf >/dev/null 2>&1 || true
ok "ip_forward = $(sysctl -n net.ipv4.ip_forward)"

# ---------------------------------------------------------------------
# 4. File include cho chain forward
# ---------------------------------------------------------------------
[[ -f /etc/ddos/forward-extra.rules ]] \
	|| printf '# Module mở rộng nạp rule vào chain forward\n' >/etc/ddos/forward-extra.rules

if ! nft list chain inet filter input >/dev/null 2>&1; then
	warn "Chưa thấy firewall chính (chain 'inet filter input')."
	warn "Nên chạy trước:  sudo bash install.sh   (chống SYN flood, blocklist...)"
fi

# ---------------------------------------------------------------------
# 5. Cài script + sinh rule
# ---------------------------------------------------------------------
info "Cài script..."
install -m 0755 "$REPO_DIR/scripts/gen-proxy-rules.sh"  /usr/local/sbin/gen-proxy-rules
install -m 0755 "$REPO_DIR/scripts/geoip-vn-update.sh"  /usr/local/sbin/geoip-vn-update
install -m 0755 "$REPO_DIR/scripts/proxy-status.sh"     /usr/local/sbin/proxy-status

info "Sinh và áp dụng rule NAT + GeoIP..."
/usr/local/sbin/gen-proxy-rules

info "Tải danh sách IP Việt Nam (lần đầu)..."
/usr/local/sbin/geoip-vn-update || warn "Chưa tải được GeoIP — sẽ tự thử lại theo timer"

# ---------------------------------------------------------------------
# 6. systemd (nạp geoip lúc boot + cập nhật hằng ngày)
# ---------------------------------------------------------------------
info "Cài systemd unit..."
install -m 0644 "$REPO_DIR/systemd/ddos-geoip-boot.service" /etc/systemd/system/ddos-geoip-boot.service
install -m 0644 "$REPO_DIR/systemd/ddos-geoip.service"      /etc/systemd/system/ddos-geoip.service
install -m 0644 "$REPO_DIR/systemd/ddos-geoip.timer"        /etc/systemd/system/ddos-geoip.timer
systemctl daemon-reload
systemctl enable ddos-geoip-boot.service >/dev/null 2>&1
systemctl enable --now ddos-geoip.timer  >/dev/null 2>&1 || true
ok "Đã bật ddos-geoip-boot.service + ddos-geoip.timer"

# ---------------------------------------------------------------------
# 7. Tổng kết
# ---------------------------------------------------------------------
VPS_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
# shellcheck disable=SC1090
source "$CONF"

echo
echo "=============================================================="
echo " HOÀN TẤT — VPS TRUNG GIAN CHỐNG DDOS"
echo "=============================================================="
echo " Người chơi kết nối : ${VPS_IP:-<IP-VPS>}  (thay vì IP Windows)"
echo " Server Windows     : $WIN_IP"
echo " Chế độ             : $FORWARD_MODE"
echo " Lọc quốc gia       : $GEO_MODE (chỉ Việt Nam)"
echo " Cổng mở            : ${PORTS[*]}"
echo
echo " VIỆC CẦN LÀM TRÊN MÁY WINDOWS:"
echo "  1. Mở Windows Firewall cho IP của VPS ($VPS_IP) trên các cổng game"
if [[ "$FORWARD_MODE" == "proxy" ]]; then
	echo "  2. Chế độ proxy: game server thấy mọi người chơi là $VPS_IP (mất IP thật)"
else
	echo "  2. Chế độ dnat: đặt default gateway của Windows về VPS để reply đi đúng đường"
fi
echo
echo " Lệnh quản lý:"
echo "   sudo proxy-status          # xem trạng thái, IP VN, bộ đếm chặn"
echo "   sudo gen-proxy-rules       # áp lại sau khi sửa $CONF"
echo "   sudo geoip-vn-update       # cập nhật danh sách IP Việt Nam ngay"
echo "=============================================================="
