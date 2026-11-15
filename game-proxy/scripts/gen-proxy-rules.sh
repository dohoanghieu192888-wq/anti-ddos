#!/usr/bin/env bash
# =====================================================================
#  gen-proxy-rules.sh — sinh ruleset NAT + GeoIP từ /etc/ddos/game-proxy.conf
#    sudo gen-proxy-rules
#
#  Kết quả:
#    /etc/nftables.d/game-proxy.nft     (NAT + lọc GeoIP)
#    /etc/ddos/forward-extra.rules      (accept trong chain forward của ddos.nft)
# =====================================================================
set -Eeuo pipefail

CONF="/etc/ddos/game-proxy.conf"
OUT_NFT="/etc/nftables.d/game-proxy.nft"
OUT_FWD="/etc/ddos/forward-extra.rules"

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { log "LỖI: $*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "cần root (sudo)"
[[ -r "$CONF" ]] || die "không thấy $CONF"
# shellcheck disable=SC1090
source "$CONF"

[[ -n "${WIN_IP:-}" ]] || die "WIN_IP chưa được đặt trong $CONF"
[[ "${FORWARD_MODE:-proxy}" == "proxy" || "${FORWARD_MODE}" == "dnat" ]] \
	|| die "FORWARD_MODE phải là 'proxy' hoặc 'dnat'"
[[ ${#PORTS[@]} -gt 0 ]] || die "PORTS rỗng"

# --- Tự phát hiện card mạng -------------------------------------------
detect_wan() { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }
detect_lan() { ip -4 route get "$WIN_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }
[[ "$WAN_IF" == "auto" || -z "$WAN_IF" ]] && WAN_IF="$(detect_wan)"
[[ "$LAN_IF" == "auto" || -z "$LAN_IF" ]] && LAN_IF="$(detect_lan)"
WAN_IF="${WAN_IF:-eth0}"
LAN_IF="${LAN_IF:-$WAN_IF}"
log "WAN_IF=$WAN_IF  LAN_IF=$LAN_IF  WIN_IP=$WIN_IP  MODE=$FORWARD_MODE"

# --- Gom danh sách cổng ----------------------------------------------
declare -a VPS_PORTS=() DNAT_RULES=()
for spec in "${PORTS[@]}"; do
	# spec: "<proto> <cổng>[=<cổng_windows>]"
	read -r proto portspec <<<"$spec"
	case "${proto,,}" in
		tcp|udp|both) ;;
		*) die "proto không hợp lệ trong PORTS: '$spec'" ;;
	esac
	[[ "$portspec" =~ ^[0-9]{1,5}(-[0-9]{1,5})?(=[0-9]{1,5}(-[0-9]{1,5})?)?$ ]] \
		|| die "cổng không hợp lệ trong PORTS: '$spec'"

	vps="${portspec%%=*}"
	if [[ "$portspec" == *=* ]]; then dst="${portspec#*=}"; else dst=""; fi

	# Kiểm tra dải cổng hợp lệ 1-65535
	for num in ${vps//-/ } ${dst//-/ }; do
		((num >= 1 && num <= 65535)) || die "cổng ngoài dải 1-65535: '$spec'"
	done

	VPS_PORTS+=("$vps")

	# Đích: giữ nguyên cổng nếu không có "="
	if [[ -z "$dst" ]]; then target="$WIN_IP"; else target="$WIN_IP:$dst"; fi

	case "${proto,,}" in
		tcp)  DNAT_RULES+=("tcp dport $vps dnat ip to $target") ;;
		udp)  DNAT_RULES+=("udp dport $vps dnat ip to $target") ;;
		both) DNAT_RULES+=("tcp dport $vps dnat ip to $target")
		      DNAT_RULES+=("udp dport $vps dnat ip to $target") ;;
	esac
done

# Cổng quản trị cũng phải NAT về Windows (chỉ ADMIN_IPS vào được)
for ap in ${ADMIN_PORTS:-}; do
	[[ "$ap" =~ ^[0-9]{1,5}(-[0-9]{1,5})?$ ]] || continue
	DNAT_RULES+=("tcp dport $ap dnat ip to $WIN_IP")
	DNAT_RULES+=("udp dport $ap dnat ip to $WIN_IP")
done

# Bỏ trùng cổng, sắp xếp
mapfile -t VPS_PORTS < <(printf '%s\n' "${VPS_PORTS[@]}" | awk '!seen[$0]++')
join_list() { local IFS=", "; echo "$*"; }
GAME_PORTS_DECL="$(join_list "${VPS_PORTS[@]}")"
ADMIN_PORTS_DECL=""
if [[ -n "${ADMIN_PORTS:-}" ]]; then
	ADMIN_PORTS_DECL="${ADMIN_PORTS// /, }"
fi

# --- ADMIN_IPS (kèm IP đang SSH nếu có) ------------------------------
declare -a ADMINS=()
for a in "${ADMIN_IPS[@]:-}"; do [[ -n "$a" && "$a" != \#* ]] && ADMINS+=("$a"); done
SSH_IP="${SSH_CONNECTION:-}"
SSH_IP="${SSH_IP%% *}"
if [[ -n "${SSH_IP:-}" ]] && [[ "$SSH_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
	&& [[ "$SSH_IP" != "127.0.0.1" ]]; then
	ADMINS+=("$SSH_IP")
fi
ADMIN_DECL=""
[[ ${#ADMINS[@]} -gt 0 ]] && ADMIN_DECL="elements = { $(join_list "${ADMINS[@]}") };"

# --- Sinh file nft ---------------------------------------------------
{
	echo '#!/usr/sbin/nft -f'
	echo "# TỰ SINH bởi gen-proxy-rules — ĐỪNG SỬA TAY."
	echo "# Nguồn: $CONF   |   sinh lúc: $(date '+%F %T')"
	echo
	echo "# ---------------------------------------------------------------"
	echo "# Lọc GeoIP + chống flood, chạy TRƯỚC conntrack (priority -350)"
	echo "# ---------------------------------------------------------------"
	echo 'table inet gamefilter {}'
	echo 'delete table inet gamefilter'
	echo 'table inet gamefilter {'
	echo "	set vn4 { type ipv4_addr; flags interval; auto-merge; size 262144; }"
	echo "	set vn6 { type ipv6_addr; flags interval; auto-merge; size 65536; }"
	echo "	set admin4 { type ipv4_addr; flags interval; auto-merge; size 1024; ${ADMIN_DECL} }"
	echo "	set game_ports { type inet_service; flags interval; auto-merge; elements = { $GAME_PORTS_DECL }; }"
	if [[ -n "$ADMIN_PORTS_DECL" ]]; then
		echo "	set admin_ports { type inet_service; flags interval; auto-merge; elements = { $ADMIN_PORTS_DECL }; }"
	else
		echo "	set admin_ports { type inet_service; flags interval; auto-merge; }"
	fi
	echo
	echo '	chain prerouting {'
	echo '		type filter hook prerouting priority -350; policy accept;'
	echo '		# Chống flood UDP/TCP theo từng IP nguồn (cổng game)'
	echo "		ct state new tcp dport @game_ports meter g_tcp_new { ip saddr limit rate over ${TCP_NEWCONN_PER_IP:-30}/second burst 60 packets } counter drop"
	echo "		udp dport @game_ports meter g_udp { ip saddr limit rate over ${UDP_PPS_PER_IP:-200}/second burst 400 packets } counter drop"
	echo "		ct state new tcp dport @game_ports meter g_conn { ip saddr ct count over ${TCP_CONN_PER_IP:-60} } counter drop"
	echo
	if [[ "${GEO_MODE}" == "vn-only" ]]; then
		echo '		# Chỉ IP Việt Nam được vào cổng game'
		echo '		tcp dport @game_ports jump geo_allow'
		echo '		udp dport @game_ports jump geo_allow'
	else
		echo '		# GEO_MODE=off: không lọc theo quốc gia'
	fi
	if [[ -n "$ADMIN_PORTS_DECL" ]]; then
		echo '		# Cổng quản trị: chỉ ADMIN_IPS'
		echo '		tcp dport @admin_ports jump admin_allow'
	fi
	echo '	}'
	echo
	echo '	chain geo_allow {'
	echo '		ip saddr @admin4 return'
	echo '		ip saddr @vn4 return'
	echo '		ip6 saddr @vn6 return'
	echo '		limit rate 10/minute log prefix "geo-block: " level info'
	echo '		counter drop'
	echo '	}'
	echo
	echo '	chain admin_allow {'
	echo '		ip saddr @admin4 return'
	echo '		limit rate 5/minute log prefix "admin-deny: " level info'
	echo '		counter drop'
	echo '	}'
	echo '}'
	echo
	echo "# ---------------------------------------------------------------"
	echo "# NAT: người chơi -> IP VPS -> $WIN_IP"
	echo "# ---------------------------------------------------------------"
	echo 'table inet gameproxy {}'
	echo 'delete table inet gameproxy'
	echo 'table inet gameproxy {'
	echo '	chain prerouting {'
	echo '		type nat hook prerouting priority dstnat; policy accept;'
	for r in "${DNAT_RULES[@]}"; do echo "		$r"; done
	echo '	}'
	if [[ "${FORWARD_MODE}" == "proxy" ]]; then
		echo
		echo '	chain postrouting {'
		echo '		type nat hook postrouting priority srcnat; policy accept;'
		echo "		# SNAT: Windows thấy IP VPS (người chơi ẩn danh)"
		echo "		ip daddr $WIN_IP masquerade"
		echo '	}'
	fi
	echo '}'
} >"$OUT_NFT"

# --- File accept trong chain forward của ddos.nft --------------------
{
	echo '# TỰ SINH bởi gen-proxy-rules — được include trong chain forward của ddos.nft'
	echo '# (đặt ở /etc/ddos/ để không bị nạp như một ruleset riêng)'
	echo "# sinh lúc: $(date '+%F %T')"
	echo "iifname \"$WAN_IF\" ip daddr $WIN_IP counter accept"
	[[ "$LAN_IF" != "$WAN_IF" ]] && echo "oifname \"$LAN_IF\" ip daddr $WIN_IP counter accept"
} >"$OUT_FWD"

# --- Kiểm tra cú pháp rồi áp dụng ------------------------------------
nft -c -f "$OUT_NFT" || die "ruleset sinh ra bị lỗi cú pháp — không áp dụng"
nft -f "$OUT_NFT"
log "Đã áp dụng NAT + GeoIP cho ${#VPS_PORTS[@]} cổng: ${VPS_PORTS[*]}"

# Cho phép forward ngay ở runtime (file forward-extra.nft chỉ được đọc khi
# /etc/nftables.conf nạp lại — tức là lúc boot, nên ở đây thêm rule trực tiếp).
if nft list chain inet filter forward >/dev/null 2>&1; then
	if ! nft list chain inet filter forward | grep -q "ip daddr $WIN_IP"; then
		nft insert rule inet filter forward ip daddr "$WIN_IP" counter accept \
			&& log "Đã thêm rule forward accept cho $WIN_IP"
	fi
else
	log "CẢNH BÁO: chưa có chain 'inet filter forward' — hãy cài firewall chính (bash install.sh)"
fi
