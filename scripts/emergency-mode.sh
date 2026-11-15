#!/usr/bin/env bash
# =====================================================================
#  emergency-mode.sh - bật/tắt chế độ chống DDoS khẩn cấp
#    sudo ddos-emergency on      # đang bị tấn công
#    sudo ddos-emergency off     # hết tấn công
#    sudo ddos-emergency status
# =====================================================================
set -Eeuo pipefail

NFT_DIR="/etc/ddos"

[[ ${EUID} -eq 0 ]] || { echo "Cần quyền root (sudo)." >&2; exit 1; }
[[ -f "$NFT_DIR/emergency-on.nft" ]] || { echo "Thiếu $NFT_DIR/emergency-on.nft" >&2; exit 1; }

nft_ok() { nft list chain inet filter emergency >/dev/null 2>&1; }

status() {
	local rules
	rules=$(nft -a list chain inet filter emergency 2>/dev/null | grep -c '^\s*[a-z]' || true)
	if [[ "${rules:-0}" -gt 0 ]]; then
		echo "Trạng thái: ĐANG BẬT chế độ khẩn cấp ($rules dòng rule)"
	else
		echo "Trạng thái: tắt (chain emergency rỗng)"
	fi
	echo
	echo "--- Conntrack: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?') / $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')"
	echo "--- Số IP trong blocklist: $(nft list set inet filter blackhole_v4 2>/dev/null | grep -c 'elements' || echo 0)"
	echo "--- fail2ban:"
	fail2ban-client status 2>/dev/null | sed 's/^/    /' || echo "    (không chạy)"
}

case "${1:-status}" in
on)
	nft_ok || { echo "Chưa có chain 'emergency' - hãy nạp /etc/nftables.conf trước." >&2; exit 1; }
	nft -c -f "$NFT_DIR/emergency-on.nft"
	nft -f "$NFT_DIR/emergency-on.nft"
	# Giảm timeout conntrack để nhả tài nguyên nhanh hơn
	sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_established=600 2>/dev/null || true
	sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_time_wait=15 2>/dev/null || true
	echo "Đã BẬT chế độ khẩn cấp."
	echo "Nhớ tắt bằng: sudo ddos-emergency off"
	status
	;;
off)
	nft -f "$NFT_DIR/emergency-off.nft"
	sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_established=3600 2>/dev/null || true
	sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_time_wait=30 2>/dev/null || true
	echo "Đã TẮT chế độ khẩn cấp."
	;;
status) status ;;
*)
	echo "Dùng: $0 {on|off|status}" >&2
	exit 1
	;;
esac
