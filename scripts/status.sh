#!/usr/bin/env bash
# =====================================================================
#  status.sh - xem nhanh tình trạng firewall / tải hệ thống
#    sudo ddos-status
# =====================================================================
set -uo pipefail

line() { printf '%s\n' "--------------------------------------------------------------"; }
hdb() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

[[ ${EUID} -eq 0 ]] || { echo "Cần quyền root (sudo)." >&2; exit 1; }

hdb "BỘ ĐẾM CỦA FIREWALL (gói tin khớp rule)"
nft -a list table inet filter 2>/dev/null | grep -E 'counter packets' \
	| sed -E 's/^\s*//' | sed -E 's/^([a-z0-9 ]{0,60}).*(counter packets [0-9]+ bytes [0-9]+).*/\1 \2/' \
	| head -40

hdb "CONNTRACK"
if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
	echo "đang dùng : $(cat /proc/sys/net/netfilter/nf_conntrack_count)"
	echo "tối đa    : $(cat /proc/sys/net/netfilter/nf_conntrack_max)"
else
	echo "module nf_conntrack chưa nạp (hoặc không có netfilter)"
fi

hdb "BLOCKLIST"
echo "IPv4 bị chặn: $(nft list set inet filter blackhole_v4 2>/dev/null | grep -oE '^[^;]*' | tr ',' '\n' | wc -l) mục"
echo "Whitelist   : $(nft list set inet filter whitelist_v4 2>/dev/null | grep -c ',' || echo 0)"

hdb "CHẾ ĐỘ KHẨN CẤP"
if nft list chain inet filter emergency 2>/dev/null | grep -q 'tcp'; then
	echo "ĐANG BẬT (chain emergency có rule)"
else
	echo "tắt"
fi

hdb "TẢI HỆ THỐNG"
echo "loadavg   : $(cut -d' ' -f1-3 /proc/loadavg)"
echo "CPU       : $(grep -c ^processor /proc/cpuinfo) core"
free -h 2>/dev/null | sed 's/^/            /'
echo "TCP hiện tại: $(ss -s 2>/dev/null | grep -i '^TCP' || echo '?')"
echo
echo "Top 10 IP đang có nhiều kết nối nhất:"
ss -tan 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

hdb "FAIL2BAN"
if command -v fail2ban-client >/dev/null; then
	fail2ban-client status 2>/dev/null | sed 's/^/  /'
	for j in sshd ddos-scanner recidive; do
		fail2ban-client status "$j" 2>/dev/null | sed -n '2,4p' | sed 's/^/  /'
	done
else
	echo "fail2ban chưa cài"
fi

hdb "SYSCTL ĐANG ÁP DỤNG"
for k in net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog net.core.somaxconn \
	net.ipv4.tcp_congestion_control net.core.default_qdisc; do
	printf '  %-40s = %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo '?')"
done
line
