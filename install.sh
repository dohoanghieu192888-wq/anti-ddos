#!/usr/bin/env bash
# =====================================================================
#  install.sh - Cài bộ firewall chống DDoS cho Ubuntu 20.04
#  Chạy:  sudo bash install.sh
#
#  Việc sẽ làm:
#    1. Cài nftables, fail2ban, curl
#    2. Nạp ruleset /etc/nftables.d/ddos.nft (có kiểm tra cú pháp trước)
#    3. Áp dụng sysctl tuning kernel
#    4. Cấu hình fail2ban
#    5. Cài script tiện ích + timer cập nhật blocklist
# =====================================================================
set -Eeuo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/ddos-firewall-backup-$STAMP"

GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'
ok()   { echo "${GREEN}[ OK ]${NC} $*"; }
info() { echo "${YELLOW}[ .. ]${NC} $*"; }
warn() { echo "${YELLOW}[WARN]${NC} $*"; }
die()  { echo "${RED}[FAIL]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------
# 0. Kiểm tra môi trường
# ---------------------------------------------------------------------
[[ ${EUID} -eq 0 ]] || die "Phải chạy bằng root: sudo bash install.sh"

if [[ -r /etc/os-release ]]; then
	. /etc/os-release
	info "Hệ điều hành: ${PRETTY_NAME:-unknown}"
	case "${VERSION_ID:-}" in
		20.04|22.04|24.04) ;;
		*) warn "Script được viết cho Ubuntu 20.04, vẫn tiếp tục trên ${VERSION_ID:-?}." ;;
	esac
fi

KEV="$(uname -r)"
info "Kernel: $KEV"

backup() {
	local src="$1"
	[[ -e "$src" ]] || return 0
	mkdir -p "$BACKUP_DIR"
	cp -a "$src" "$BACKUP_DIR/$(echo "$src" | tr '/' '_')"
	ok "Đã backup $src"
}

# ---------------------------------------------------------------------
# 1. Gói cần thiết
# ---------------------------------------------------------------------
info "Cập nhật apt và cài nftables, fail2ban, curl..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nftables fail2ban curl ca-certificates \
	|| die "apt-get install thất bại"
ok "Đã cài nftables $(nft --version | awk '{print $2}'), fail2ban"

# aggregate (tuỳ chọn): gộp các dải CIDR trùng nhau trong blocklist
if ! command -v aggregate >/dev/null; then
	apt-get install -y -qq aggregate >/dev/null 2>&1 || warn "Không cài được aggregate (không bắt buộc)"
fi

# ---------------------------------------------------------------------
# 2. Phát hiện ufw đang chạy (xung đột với ruleset riêng)
# ---------------------------------------------------------------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
	warn "ufw đang BẬT. Bộ ruleset này thay thế ufw và hai bên sẽ xung đột."
	if [[ -t 0 ]]; then
		read -r -p "Tắt ufw bây giờ? [y/N] " ans
		if [[ "${ans,,}" == y* ]]; then
			ufw --force disable >/dev/null && ok "Đã tắt ufw"
		else
			die "Hãy tắt ufw (ufw disable) rồi chạy lại."
		fi
	else
		die "Hãy chạy 'ufw disable' rồi chạy lại script."
	fi
fi

# ---------------------------------------------------------------------
# 3. Module kernel
# ---------------------------------------------------------------------
info "Nạp module nf_conntrack, tcp_bbr..."
modprobe nf_conntrack 2>/dev/null && ok "nf_conntrack" || warn "nf_conntrack không nạp được"
BBR_OK=0
if modprobe tcp_bbr 2>/dev/null; then BBR_OK=1; ok "tcp_bbr"; else warn "tcp_bbr không có, bỏ qua BBR"; fi
echo "nf_conntrack" >/etc/modules-load.d/ddos-netfilter.conf

# ---------------------------------------------------------------------
# 4. Ruleset nftables
# ---------------------------------------------------------------------
# File include cho chain forward (mặc định rỗng) - phải tồn tại trước khi check.
# Đặt ở /etc/ddos/ (KHÔNG phải /etc/nftables.d/*.nft) để không bị nạp như ruleset riêng.
mkdir -p /etc/nftables.d /etc/ddos
[[ -f /etc/ddos/forward-extra.rules ]] || printf '# Module mở rộng nạp rule vào chain forward (game proxy, VPN...)\n' >/etc/ddos/forward-extra.rules

info "Kiểm tra cú pháp ruleset..."
nft -c -f "$REPO_DIR/nftables/ddos.nft" || die "Ruleset có lỗi cú pháp - dừng lại (chưa thay đổi gì)"

backup /etc/nftables.conf

install -m 0644 "$REPO_DIR/nftables/ddos.nft"          /etc/nftables.d/ddos.nft
install -m 0644 "$REPO_DIR/nftables/emergency-on.nft"  /etc/ddos/emergency-on.nft
install -m 0644 "$REPO_DIR/nftables/emergency-off.nft" /etc/ddos/emergency-off.nft
install -m 0644 "$REPO_DIR/blocklist/whitelist.txt"    /etc/ddos/whitelist.txt

cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
# Nạp toàn bộ ruleset trong /etc/nftables.d/
# (ddos.nft tự xoá/tạo lại bảng của nó nên nạp lại nhiều lần vẫn an toàn)
include "/etc/nftables.d/*.nft"
EOF
chmod 0755 /etc/nftables.conf

nft -f /etc/nftables.conf || die "Nạp ruleset thất bại"
ok "Đã nạp ruleset nftables"

systemctl enable nftables >/dev/null 2>&1
systemctl restart nftables >/dev/null 2>&1 || systemctl start nftables >/dev/null 2>&1 || true
ok "nftables.service đã bật (tự khôi phục sau reboot)"

# ---------------------------------------------------------------------
# 5. Sysctl tuning
# ---------------------------------------------------------------------
info "Áp dụng sysctl tuning..."
backup /etc/sysctl.conf
mkdir -p /etc/modprobe.d /etc/security/limits.d
install -m 0644 "$REPO_DIR/modprobe/nf_conntrack.conf" /etc/modprobe.d/nf_conntrack.conf
install -m 0644 "$REPO_DIR/sysctl/99-ddos-hardening.conf" /etc/sysctl.d/99-ddos-hardening.conf
install -m 0644 "$REPO_DIR/security/99-ddos-limits.conf" /etc/security/limits.d/99-ddos-limits.conf

if [[ "$BBR_OK" == 1 ]]; then
	install -m 0644 "$REPO_DIR/sysctl/99-bbr.conf" /etc/sysctl.d/99-bbr.conf
else
	rm -f /etc/sysctl.d/99-bbr.conf
fi

sysctl --system >/dev/null 2>&1 || true
ok "sysctl: syncookies=$(sysctl -n net.ipv4.tcp_syncookies) somaxconn=$(sysctl -n net.core.somaxconn) cc=$(sysctl -n net.ipv4.tcp_congestion_control)"

# ---------------------------------------------------------------------
# 6. fail2ban
# ---------------------------------------------------------------------
info "Cấu hình fail2ban..."
backup /etc/fail2ban/jail.local
install -m 0644 "$REPO_DIR/fail2ban/jail.local" /etc/fail2ban/jail.local
install -m 0644 "$REPO_DIR/fail2ban/filter.d/nft-input-drop.conf" \
	/etc/fail2ban/filter.d/nft-input-drop.conf

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1 || warn "fail2ban restart lỗi - xem: journalctl -u fail2ban -n 50"
sleep 2
if fail2ban-client status >/dev/null 2>&1; then
	ok "fail2ban: $(fail2ban-client status | grep -oE 'Jail list:.*')"
else
	warn "fail2ban chưa sẵn sàng (kiểm tra: fail2ban-client status)"
fi

# ---------------------------------------------------------------------
# 7. Script tiện ích
# ---------------------------------------------------------------------
info "Cài script tiện ích..."
install -m 0755 "$REPO_DIR/scripts/update-blocklist.sh" /usr/local/sbin/ddos-update-blocklist
install -m 0755 "$REPO_DIR/scripts/emergency-mode.sh"   /usr/local/sbin/ddos-emergency
install -m 0755 "$REPO_DIR/scripts/status.sh"           /usr/local/sbin/ddos-status
install -m 0644 "$REPO_DIR/systemd/ddos-blocklist.service" /etc/systemd/system/ddos-blocklist.service
install -m 0644 "$REPO_DIR/systemd/ddos-blocklist.timer"   /etc/systemd/system/ddos-blocklist.timer
systemctl daemon-reload
systemctl enable ddos-blocklist.timer >/dev/null 2>&1
systemctl start ddos-blocklist.timer >/dev/null 2>&1 || true
ok "Đã cài: ddos-status, ddos-emergency, ddos-update-blocklist, timer cập nhật blocklist"

# ---------------------------------------------------------------------
# 8. Nginx (chỉ khi đã có nginx)
# ---------------------------------------------------------------------
if command -v nginx >/dev/null; then
	info "Phát hiện nginx - cài snippet rate limit..."
	backup /etc/nginx/conf.d/00-ddos-http.conf
	install -m 0644 "$REPO_DIR/nginx/00-ddos-http.conf" /etc/nginx/conf.d/00-ddos-http.conf
	mkdir -p /etc/nginx/snippets
	install -m 0644 "$REPO_DIR/nginx/ddos-server.conf" /etc/nginx/snippets/ddos-server.conf
	if nginx -t >/dev/null 2>&1; then
		systemctl reload nginx 2>/dev/null && ok "nginx đã reload"
	else
		warn "nginx -t báo lỗi - bỏ file /etc/nginx/conf.d/00-ddos-http.conf để khôi phục"
	fi
	warn "Nhớ thêm 'include snippets/ddos-server.conf;' vào block server{} trong /etc/nginx/sites-enabled/"
else
	info "Không có nginx - bỏ qua phần rate limit HTTP"
fi

# ---------------------------------------------------------------------
# 9. Whitelist IP đang SSH (tránh tự khoá mình)
# ---------------------------------------------------------------------
SSH_IP="${SSH_CONNECTION%% *}"
if [[ -n "${SSH_IP:-}" ]] && [[ "$SSH_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$SSH_IP" != 127.0.0.1 ]]; then
	echo "$SSH_IP" >>/etc/ddos/whitelist.txt
	nft add element inet filter whitelist_v4 "{ $SSH_IP }" 2>/dev/null || true
	ok "Đã whitelist IP SSH hiện tại: $SSH_IP"
fi

# ---------------------------------------------------------------------
# 10. Tổng kết
# ---------------------------------------------------------------------
echo
echo "=============================================================="
echo " HOÀN TẤT"
echo "=============================================================="
nft list table inet filter 2>/dev/null | head -20
echo "..."
echo
echo "Backup cấu hình cũ: $BACKUP_DIR"
echo
echo "Bước tiếp theo:"
echo "  1) Mở đúng cổng dịch vụ trong /etc/nftables.d/ddos.nft rồi: nft -f /etc/nftables.conf"
echo "  2) Xem trạng thái : sudo ddos-status"
echo "  3) Đang bị tấn công: sudo ddos-emergency on   (hết: off)"
echo "  4) Cập nhật blocklist ngay: sudo ddos-update-blocklist"
echo
echo "LƯU Ý: đang có phiên SSH, đừng đóng kết nối này cho tới khi mở terminal"
echo "       thứ hai kiểm tra lại truy cập."
echo "=============================================================="
