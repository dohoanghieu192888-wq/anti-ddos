#!/usr/bin/env bash
set -Eeuo pipefail

D=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONF=/etc/ddos/game-proxy.conf
G=$'\033[0;32m'; Y=$'\033[1;33m'; R=$'\033[0;31m'; N=$'\033[0m'
ok() { echo "${G}[ok]${N} $*"; }
info() { echo "${Y}[..]${N} $*"; }
warn() { echo "${Y}[!]${N} $*"; }
die() { echo "${R}[x]${N} $*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "cần root"
mkdir -p /etc/ddos /etc/nftables.d /var/lib/ddos

if [[ ! -f $CONF ]]; then
	install -m 0640 "$D/game-proxy.conf.example" "$CONF"
	if [[ -t 0 ]]; then
		echo "IP server Windows (để trống nếu game chạy ngay trên VPS này):"
		read -r -p "> " win_ip
		[[ $win_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] \
			&& sed -i "s|^WIN_IP=.*|WIN_IP=\"$win_ip\"|" "$CONF" && ok "WIN_IP=$win_ip" \
			|| warn "IP không hợp lệ, sửa $CONF rồi chạy lại"
	fi
else
	ok "dùng $CONF"
fi

command -v nft >/dev/null || {
	DEBIAN_FRONTEND=noninteractive apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables curl ca-certificates
}
command -v curl >/dev/null || die "thiếu curl"

info "bật ip_forward"
printf 'net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.forwarding = 1\nnet.ipv4.conf.all.route_localnet = 1\n' \
	>/etc/sysctl.d/99-game-proxy.conf
sysctl -p /etc/sysctl.d/99-game-proxy.conf >/dev/null 2>&1 || true
ok "ip_forward=$(sysctl -n net.ipv4.ip_forward)"

nft list chain inet filter input >/dev/null 2>&1 \
	|| warn "chưa cài firewall chính (bash install.sh)"

info "cài script"
install -m 0755 "$D/scripts/gen-proxy-rules.sh" /usr/local/sbin/gen-proxy-rules
install -m 0755 "$D/scripts/geoip-vn-update.sh" /usr/local/sbin/geoip-vn-update
install -m 0755 "$D/scripts/proxy-status.sh" /usr/local/sbin/proxy-status

info "sinh ruleset"
/usr/local/sbin/gen-proxy-rules

info "tải danh sách IP Việt Nam"
/usr/local/sbin/geoip-vn-update || warn "chưa tải được, timer sẽ thử lại"

info "cài systemd"
install -m 0644 "$D/systemd/ddos-geoip-boot.service" /etc/systemd/system/ddos-geoip-boot.service
install -m 0644 "$D/systemd/ddos-geoip.service" /etc/systemd/system/ddos-geoip.service
install -m 0644 "$D/systemd/ddos-geoip.timer" /etc/systemd/system/ddos-geoip.timer
systemctl daemon-reload
systemctl enable ddos-geoip-boot.service >/dev/null 2>&1
systemctl enable --now ddos-geoip.timer >/dev/null 2>&1 || true
ok "geoip boot + timer"

. "$CONF"
VPS_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
echo
printf 'players : %s\nwindows : %s\nmode    : %s\ngeoip   : %s\nports   : %s\n\n' \
	"${VPS_IP:-<IP-VPS>}" "$WIN_IP" "$FORWARD_MODE" "$GEO_MODE" "${PORTS[*]}"
echo "trên Windows: mở firewall cho IP ${VPS_IP:-VPS} trên các cổng game"
[[ $FORWARD_MODE == dnat ]] && echo "mode dnat: đặt default gateway của Windows về VPS"
echo "proxy-status | gen-proxy-rules | geoip-vn-update"
