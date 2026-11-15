#!/usr/bin/env bash
# =====================================================================
#  proxy-status.sh — xem trạng thái VPS trung gian chống DDoS
#    sudo proxy-status
# =====================================================================
set -uo pipefail
hdb() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
[[ ${EUID} -eq 0 ]] || { echo "Cần root (sudo)." >&2; exit 1; }

CONF="/etc/ddos/game-proxy.conf"

hdb "CẤU HÌNH"
if [[ -r "$CONF" ]]; then
	# shellcheck disable=SC1090
	source "$CONF" 2>/dev/null || true
	echo "Windows server : ${WIN_IP:-?}"
	echo "Chế độ         : ${FORWARD_MODE:-?}  (proxy = ẩn IP người chơi | dnat = giữ IP thật)"
	echo "GeoIP          : ${GEO_MODE:-?} ${ALLOW_V6:+(v6=${ALLOW_V6})}"
	echo "Cổng game      : ${PORTS[*]:-?}"
	echo "IP quản trị    : ${ADMIN_IPS[*]:-?}"
else
	echo "Chưa có $CONF"
fi

hdb "IP CÔNG KHAI CỦA VPS (người chơi kết nối vào đây)"
ip -4 -o addr show scope global | awk '{print "  " $2 ": " $4}'

hdb "DANH SÁCH IP VIỆT NAM ĐANG NẠP"
echo "  vn4: $(nft list set inet gamefilter vn4 2>/dev/null | grep -c ':') dòng"
echo "  vn6: $(nft list set inet gamefilter vn6 2>/dev/null | grep -c ':') dòng"
echo "  admin: $(nft list set inet gamefilter admin4 2>/dev/null | grep -c ':') IP"
echo "  cache: $(wc -l </var/lib/ddos/vn.zone 2>/dev/null || echo 0) dải (cập nhật: $(stat -c %y /var/lib/ddos/vn.zone 2>/dev/null | cut -d. -f1))"

hdb "BỘ ĐẾM CHẶN"
nft list table inet gamefilter 2>/dev/null | grep -E 'geo-block|admin-deny|counter packets' \
	| sed -E 's/^\s*//' | head -20

hdb "NAT ĐANG ÁP DỤNG"
nft list table inet gameproxy 2>/dev/null | sed 's/^/  /' | head -40

hdb "KẾT NỐI HIỆN TẠI TỚI CỔNG GAME"
ss -tan 2>/dev/null | awk 'NR>1 && $1=="ESTAB"' | wc -l | sed 's/^/  TCP established: /'
echo "  conntrack: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?') / $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')"

hdb "TOP 10 IP ĐANG KẾT NỐI NHIỀU NHẤT"
ss -tan 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

hdb "LOG CHẶN GẦN ĐÂY (geo-block / admin-deny)"
journalctl -k -n 200 --no-pager 2>/dev/null | grep -E 'geo-block|admin-deny' | tail -10 || echo "  (không có)"
