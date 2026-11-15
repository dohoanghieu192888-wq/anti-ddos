#!/usr/bin/env bash
# =====================================================================
#  setup-all.sh — CÀI TẤT CẢ TRONG 1 LỆNH
#
#    sudo bash setup-all.sh                     # firewall + panel
#    sudo bash setup-all.sh --with-proxy \
#         --win-ip 10.10.0.5                    # + shield game Windows
#    sudo bash setup-all.sh --with-proxy --win-ip 10.10.0.5 --panel-port 8080
#
#  Gồm:
#    1. Firewall nftables chống DDoS + sysctl tuning + fail2ban + blocklist
#    2. (tuỳ chọn) Shield game proxy: NAT VPS -> Windows, chỉ cho IP Việt Nam
#    3. Panel web quản trị (127.0.0.1:8080, truy cập qua SSH tunnel)
# =====================================================================
set -Eeuo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WITH_PROXY="ask"
WIN_IP=""
PANEL_PORT="8080"
PANEL_USER="admin"
PANEL_BIND="127.0.0.1"

GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'
ok()   { echo "${GREEN}[ OK ]${NC} $*"; }
step() { echo; echo "${YELLOW}==>${NC} $*"; }
warn() { echo "${YELLOW}[WARN]${NC} $*"; }
die()  { echo "${RED}[FAIL]${NC} $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
	case "$1" in
		--with-proxy) WITH_PROXY="yes" ;;
		--no-proxy)   WITH_PROXY="no" ;;
		--win-ip)     WIN_IP="${2:-}"; shift ;;
		--panel-port) PANEL_PORT="${2:-8080}"; shift ;;
		--panel-user) PANEL_USER="${2:-admin}"; shift ;;
		--panel-bind) PANEL_BIND="${2:-127.0.0.1}"; shift ;;
		-h|--help)
			sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
			exit 0 ;;
		*) die "tham số không hiểu: $1" ;;
	esac
	shift
done

[[ ${EUID} -eq 0 ]] || die "Phải chạy bằng root: sudo bash setup-all.sh"

if [[ -r /etc/os-release ]]; then
	. /etc/os-release
	echo "Hệ điều hành: ${PRETTY_NAME:-unknown}  (kernel $(uname -r))"
fi

# ---------------------------------------------------------------------
# 1. Firewall chống DDoS
# ---------------------------------------------------------------------
step "1/3  Cài firewall chống DDoS (nftables + sysctl + fail2ban)"
bash "$REPO_DIR/install.sh" || die "install.sh thất bại"
ok "Firewall xong"

# ---------------------------------------------------------------------
# 2. Shield game proxy (tuỳ chọn)
# ---------------------------------------------------------------------
step "2/3  Shield game proxy (VPS trung gian cho server Windows)"
if [[ "$WITH_PROXY" == "ask" ]]; then
	if [[ -t 0 ]]; then
		echo "Bạn có muốn dùng VPS này làm trung gian chống DDoS cho server game"
		echo "Windows không? (người chơi kết nối IP VPS, chỉ cho IP Việt Nam)"
		read -r -p "Cài shield proxy? [Y/n] " ans
		[[ "${ans,,}" == n* ]] && WITH_PROXY="no" || WITH_PROXY="yes"
	else
		WITH_PROXY="no"
	fi
fi

if [[ "$WITH_PROXY" == "yes" ]]; then
	mkdir -p /etc/ddos
	if [[ -z "$WIN_IP" ]]; then
		if [[ -t 0 ]]; then
			read -r -p "IP server Windows (ví dụ 10.10.0.5): " WIN_IP
		fi
	fi
	if [[ ! -f /etc/ddos/game-proxy.conf ]]; then
		install -m 0640 "$REPO_DIR/game-proxy/game-proxy.conf.example" /etc/ddos/game-proxy.conf
	fi
	if [[ -n "$WIN_IP" ]]; then
		[[ "$WIN_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "IP Windows không hợp lệ: $WIN_IP"
		sed -i "s|^WIN_IP=.*|WIN_IP=\"$WIN_IP\"|" /etc/ddos/game-proxy.conf
		ok "WIN_IP = $WIN_IP"
	fi
	# KHÔNG copy đè cấu hình đã có; install-proxy dùng lại file sẵn có
	bash "$REPO_DIR/game-proxy/install-proxy.sh" || warn "game-proxy cài chưa trọn vẹn"
	ok "Shield proxy xong"
else
	ok "Bỏ qua shield proxy"
fi

# ---------------------------------------------------------------------
# 3. Panel web
# ---------------------------------------------------------------------
step "3/3  Cài panel web quản trị"
command -v python3 >/dev/null || {
	info_pkg=1
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null 2>&1 || true
}

install -m 0755 "$REPO_DIR/panel/ddos-panel.py" /usr/local/sbin/ddos-panel
install -m 0644 "$REPO_DIR/panel/ddos-panel.service" /etc/systemd/system/ddos-panel.service

mkdir -p /etc/ddos
if [[ ! -f /etc/ddos/panel.json ]]; then
	/usr/bin/python3 /usr/local/sbin/ddos-panel --init --user "$PANEL_USER" \
		| tee /root/ddos-panel-credentials.txt
	# đổi bind/port theo tham số
	/usr/bin/python3 - "$PANEL_PORT" "$PANEL_BIND" <<'PY'
import json, sys
p = "/etc/ddos/panel.json"
c = json.load(open(p))
c["port"] = int(sys.argv[1]); c["bind"] = sys.argv[2]
json.dump(c, open(p, "w"), indent=2)
PY
	chmod 600 /root/ddos-panel-credentials.txt
else
	warn "Panel đã có /etc/ddos/panel.json — giữ nguyên tài khoản cũ"
	warn "Quên mật khẩu: ddos-panel --init --force  (rồi systemctl restart ddos-panel)"
fi

systemctl daemon-reload
systemctl enable ddos-panel >/dev/null 2>&1
systemctl restart ddos-panel
sleep 2
if systemctl is-active ddos-panel >/dev/null 2>&1; then
	ok "Panel đang chạy tại http://$PANEL_BIND:$PANEL_PORT"
else
	warn "Panel không chạy — xem: journalctl -u ddos-panel -n 30"
fi

# ---------------------------------------------------------------------
# Tổng kết
# ---------------------------------------------------------------------
VPS_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"

echo
echo "=============================================================="
echo " HOÀN TẤT"
echo "=============================================================="
echo " Firewall      : nftables + sysctl + fail2ban + blocklist"
[[ "$WITH_PROXY" == "yes" ]] && echo " Shield proxy  : bật (Windows: ${WIN_IP:-xem /etc/ddos/game-proxy.conf})"
echo " Panel web     : http://$PANEL_BIND:$PANEL_PORT"
echo " Tài khoản     : xem /root/ddos-panel-credentials.txt"
echo
echo " Truy cập panel từ máy bạn:"
echo "   ssh -L $PANEL_PORT:127.0.0.1:$PANEL_PORT root@${VPS_IP:-<IP-VPS>}"
echo "   rồi mở http://127.0.0.1:$PANEL_PORT"
echo
echo " Lệnh CLI (dùng song song với panel):"
echo "   sudo ddos-status        trạng thái firewall"
echo "   sudo ddos-emergency on  chế độ khẩn cấp"
[[ "$WITH_PROXY" == "yes" ]] && echo "   sudo proxy-status       trạng thái shield proxy"
echo "=============================================================="
