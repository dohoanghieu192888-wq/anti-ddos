#!/usr/bin/env bash
set -uo pipefail

[[ ${EUID} -eq 0 ]] || { echo "cần root" >&2; exit 1; }

sec() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ips() { nft list set inet filter "$1" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | wc -l; }
tcp_state() { nft list chain inet filter emergency 2>/dev/null | grep -q tcp && echo BẬT || echo tắt; }

sec "Bộ đếm firewall"
nft -a list table inet filter 2>/dev/null | grep 'counter packets' | sed 's/^[[:space:]]*//' | head -40

sec "Conntrack"
printf '%s / %s\n' "$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?')" \
	"$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')"

sec "Danh sách"
printf 'blackhole: %s\nwhitelist : %s\nkhẩn cấp  : %s\n' \
	"$(ips blackhole_v4)" "$(ips whitelist_v4)" "$(tcp_state)"

sec "Tải hệ thống"
printf 'load : %s\ncpu  : %s core\n' "$(cut -d' ' -f1-3 /proc/loadavg)" "$(grep -c ^processor /proc/cpuinfo)"
free -h 2>/dev/null | sed 's/^/       /'
ss -s 2>/dev/null | grep -i '^TCP'

sec "Top IP kết nối"
ss -tan 2>/dev/null | awk 'NR>1{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

sec "fail2ban"
if command -v fail2ban-client >/dev/null; then
	fail2ban-client status 2>/dev/null | sed 's/^/  /'
	for j in sshd ddos-scanner recidive; do
		fail2ban-client status "$j" 2>/dev/null | sed -n '2,3p' | sed 's/^/  /'
	done
else
	echo "  chưa cài"
fi

sec "sysctl"
for k in net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog net.core.somaxconn \
	net.ipv4.tcp_congestion_control net.core.default_qdisc; do
	printf '  %-38s %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo '?')"
done
