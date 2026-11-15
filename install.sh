#!/usr/bin/env bash
set -Eeuo pipefail

D=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/root/ddos-backup-$STAMP"
G=$'\033[0;32m'; Y=$'\033[1;33m'; R=$'\033[0;31m'; N=$'\033[0m'

ok() { echo "${G}[ok]${N} $*"; }
info() { echo "${Y}[..]${N} $*"; }
warn() { echo "${Y}[!]${N} $*"; }
die() { echo "${R}[x]${N} $*" >&2; exit 1; }

backup() { [[ -e $1 ]] || return 0; mkdir -p "$BACKUP"; cp -a "$1" "$BACKUP/$(echo "$1" | tr / _)"; }

[[ ${EUID} -eq 0 ]] || die "chạy bằng root"
[[ -r $D/install.sh ]] || die "thiếu file nguồn"

info "cài gói cần thiết"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nftables fail2ban curl ca-certificates || die "apt-get lỗi"
command -v aggregate >/dev/null || apt-get install -y -qq aggregate >/dev/null 2>&1 || true
ok "nftables $(nft --version | awk '{print $2}')"

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
	if [[ -t 0 ]]; then
		read -r -p "ufw đang bật và sẽ xung đột. Tắt ufw? [y/N] " a
		[[ ${a,,} == y* ]] || die "hãy chạy: ufw disable"
		ufw --force disable >/dev/null
	else
		die "hãy chạy: ufw disable"
	fi
fi

info "nạp module"
modprobe nf_conntrack 2>/dev/null || warn "nf_conntrack"
echo nf_conntrack >/etc/modules-load.d/ddos-netfilter.conf
BBR=0
modprobe tcp_bbr 2>/dev/null && BBR=1 || warn "không có tcp_bbr, bỏ qua BBR"

mkdir -p /etc/nftables.d /etc/ddos /etc/modprobe.d /etc/security/limits.d
[[ -f /etc/ddos/forward-extra.rules ]] || : >/etc/ddos/forward-extra.rules

info "kiểm tra ruleset"
nft -c -f "$D/nftables/ddos.nft" || die "ruleset sai cú pháp, chưa thay đổi gì"

backup /etc/nftables.conf
install -m 0644 "$D/nftables/ddos.nft" /etc/nftables.d/ddos.nft
install -m 0644 "$D/nftables/emergency-on.nft" /etc/ddos/emergency-on.nft
install -m 0644 "$D/nftables/emergency-off.nft" /etc/ddos/emergency-off.nft
install -m 0644 "$D/blocklist/whitelist.txt" /etc/ddos/whitelist.txt

printf '#!/usr/sbin/nft -f\n\ninclude "/etc/nftables.d/*.nft"\n' >/etc/nftables.conf
chmod 0755 /etc/nftables.conf

nft -f /etc/nftables.conf || die "nạp ruleset thất bại"
systemctl enable nftables >/dev/null 2>&1
systemctl restart nftables >/dev/null 2>&1 || true
ok "ruleset đã nạp"

info "áp sysctl"
install -m 0644 "$D/modprobe/nf_conntrack.conf" /etc/modprobe.d/nf_conntrack.conf
install -m 0644 "$D/sysctl/99-ddos-hardening.conf" /etc/sysctl.d/99-ddos-hardening.conf
install -m 0644 "$D/security/99-ddos-limits.conf" /etc/security/limits.d/99-ddos-limits.conf
((BBR)) && install -m 0644 "$D/sysctl/99-bbr.conf" /etc/sysctl.d/99-bbr.conf || rm -f /etc/sysctl.d/99-bbr.conf
sysctl --system >/dev/null 2>&1 || true
ok "syncookies=$(sysctl -n net.ipv4.tcp_syncookies) somaxconn=$(sysctl -n net.core.somaxconn) cc=$(sysctl -n net.ipv4.tcp_congestion_control)"

info "cấu hình fail2ban"
backup /etc/fail2ban/jail.local
install -m 0644 "$D/fail2ban/jail.local" /etc/fail2ban/jail.local
install -m 0644 "$D/fail2ban/filter.d/nft-input-drop.conf" /etc/fail2ban/filter.d/nft-input-drop.conf
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1 || warn "fail2ban restart lỗi"
sleep 2
fail2ban-client status >/dev/null 2>&1 && ok "fail2ban chạy" || warn "fail2ban chưa sẵn sàng"

info "cài script"
install -m 0755 "$D/scripts/update-blocklist.sh" /usr/local/sbin/ddos-update-blocklist
install -m 0755 "$D/scripts/emergency-mode.sh" /usr/local/sbin/ddos-emergency
install -m 0755 "$D/scripts/status.sh" /usr/local/sbin/ddos-status
install -m 0644 "$D/systemd/ddos-blocklist.service" /etc/systemd/system/ddos-blocklist.service
install -m 0644 "$D/systemd/ddos-blocklist.timer" /etc/systemd/system/ddos-blocklist.timer
systemctl daemon-reload
systemctl enable --now ddos-blocklist.timer >/dev/null 2>&1 || true
ok "ddos-status, ddos-emergency, timer blocklist"

if command -v nginx >/dev/null; then
	info "cấu hình nginx"
	mkdir -p /etc/nginx/snippets
	backup /etc/nginx/conf.d/00-ddos-http.conf
	install -m 0644 "$D/nginx/00-ddos-http.conf" /etc/nginx/conf.d/00-ddos-http.conf
	install -m 0644 "$D/nginx/ddos-server.conf" /etc/nginx/snippets/ddos-server.conf
	nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null && ok "nginx reload" \
		|| warn "nginx -t lỗi, xoá /etc/nginx/conf.d/00-ddos-http.conf để khôi phục"
fi

SSH_IP=${SSH_CONNECTION:-}
SSH_IP=${SSH_IP%% *}
if [[ $SSH_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && $SSH_IP != 127.0.0.1 ]]; then
	echo "$SSH_IP" >>/etc/ddos/whitelist.txt
	nft add element inet filter whitelist_v4 "{ $SSH_IP }" 2>/dev/null || true
	ok "whitelist IP SSH: $SSH_IP"
fi

echo
echo "backup cấu hình cũ: $BACKUP"
echo "ddos-status | ddos-emergency on|off | ddos-update-blocklist"
