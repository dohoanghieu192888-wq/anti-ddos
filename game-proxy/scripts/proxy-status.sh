#!/usr/bin/env bash
set -uo pipefail

[[ ${EUID} -eq 0 ]] || { echo "cần root" >&2; exit 1; }

sec() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
n() { nft list set "$@" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | wc -l; }

sec "Cấu hình"
if [[ -r /etc/ddos/game-proxy.conf ]]; then
	. /etc/ddos/game-proxy.conf
	printf 'windows : %s\nmode    : %s\ngeoip   : %s\ncổng    : %s\nadmin   : %s\n' \
		"${WIN_IP:-?}" "${FORWARD_MODE:-?}" "${GEO_MODE:-?}" "${PORTS[*]:-?}" "${ADMIN_IPS[*]:-?}"
else
	echo "chưa có /etc/ddos/game-proxy.conf"
fi

sec "IP công khai"
ip -4 -o addr show scope global | awk '{print "  " $2 ": " $4}'

sec "Dữ liệu GeoIP"
printf '  vn4   : %s dải\n  vn6   : %s dải\n  admin : %s IP\n  cache : %s dải (%s)\n' \
	"$(n inet gamefilter vn4)" "$(n inet gamefilter vn6)" "$(n inet gamefilter admin4)" \
	"$(wc -l </var/lib/ddos/vn.zone 2>/dev/null || echo 0)" \
	"$(stat -c %y /var/lib/ddos/vn.zone 2>/dev/null | cut -d. -f1)"

sec "Bộ đếm"
nft list table inet gamefilter 2>/dev/null | grep 'counter packets' | sed 's/^[[:space:]]*//' | head -20

sec "NAT"
nft list table inet gameproxy 2>/dev/null | sed 's/^/  /' | head -30

sec "Kết nối"
printf '  conntrack: %s / %s\n' "$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?')" \
	"$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')"
ss -tan 2>/dev/null | awk 'NR>1 && $1=="ESTAB"{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

sec "Chặn gần đây"
journalctl -k -n 200 --no-pager 2>/dev/null | grep -E 'geo-block|admin-deny' | tail -10 || true
