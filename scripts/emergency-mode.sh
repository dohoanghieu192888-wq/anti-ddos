#!/usr/bin/env bash
set -Eeuo pipefail

D=/etc/ddos
[[ ${EUID} -eq 0 ]] || { echo "cần root" >&2; exit 1; }
state() { nft list chain inet filter emergency 2>/dev/null | grep -q tcp && echo BẬT || echo tắt; }

case "${1:-status}" in
on)
	[[ -f $D/emergency-on.nft ]] || { echo "thiếu $D/emergency-on.nft" >&2; exit 1; }
	nft -c -f "$D/emergency-on.nft"
	nft -f "$D/emergency-on.nft"
	sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_established=600 || true
	echo "khẩn cấp: $(state)"
	;;
off)
	nft -f "$D/emergency-off.nft"
	sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_established=3600 || true
	echo "khẩn cấp: $(state)"
	;;
status)
	printf 'khẩn cấp: %s\nconntrack: %s / %s\n' "$(state)" \
		"$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?')" \
		"$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')"
	;;
*)
	echo "dùng: $0 {on|off|status}" >&2
	exit 1
	;;
esac
