#!/usr/bin/env bash
set -Eeuo pipefail

CONF=/etc/ddos/game-proxy.conf
OUT=/etc/nftables.d/game-proxy.nft
FWD=/etc/ddos/forward-extra.rules

die() { echo "lỗi: $*" >&2; exit 1; }
join() { local IFS=,; echo "$*"; }
det_if() { ip -4 route get "$1" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }

[[ ${EUID} -eq 0 ]] || die "cần root"
[[ -r $CONF ]] || die "thiếu $CONF"
. "$CONF"
[[ -n ${WIN_IP:-} ]] || die "WIN_IP chưa đặt"
[[ ${#PORTS[@]} -gt 0 ]] || die "PORTS rỗng"
case ${FORWARD_MODE:-proxy} in proxy|dnat) ;; *) die "FORWARD_MODE phải là proxy hoặc dnat" ;; esac

[[ ${WAN_IF:-auto} == auto || -z ${WAN_IF:-} ]] && WAN_IF=$(det_if 1.1.1.1)
[[ ${LAN_IF:-auto} == auto || -z ${LAN_IF:-} ]] && LAN_IF=$(det_if "$WIN_IP")
WAN_IF=${WAN_IF:-eth0}
LAN_IF=${LAN_IF:-$WAN_IF}

VPS_PORTS=()
RULES=()
for spec in "${PORTS[@]}"; do
	read -r proto portspec <<<"$spec"
	[[ $proto =~ ^(tcp|udp|both)$ ]] || die "proto sai: $spec"
	[[ $portspec =~ ^[0-9]{1,5}(-[0-9]{1,5})?(=[0-9]{1,5}(-[0-9]{1,5})?)?$ ]] || die "cổng sai: $spec"
	vps=${portspec%%=*}
	dst=""
	[[ $portspec == *=* ]] && dst=${portspec#*=}
	for n in ${vps//-/ } ${dst//-/ }; do
		((n >= 1 && n <= 65535)) || die "cổng ngoài 1-65535: $spec"
	done
	target=$WIN_IP
	[[ -n $dst ]] && target=$WIN_IP:$dst
	VPS_PORTS+=("$vps")
	case $proto in
	tcp) RULES+=("tcp dport $vps dnat ip to $target") ;;
	udp) RULES+=("udp dport $vps dnat ip to $target") ;;
	both)
		RULES+=("tcp dport $vps dnat ip to $target")
		RULES+=("udp dport $vps dnat ip to $target")
		;;
	esac
done

for ap in ${ADMIN_PORTS:-}; do
	[[ $ap =~ ^[0-9]{1,5}(-[0-9]{1,5})?$ ]] || continue
	RULES+=("tcp dport $ap dnat ip to $WIN_IP")
	RULES+=("udp dport $ap dnat ip to $WIN_IP")
done

mapfile -t VPS_PORTS < <(printf '%s\n' "${VPS_PORTS[@]}" | awk '!s[$0]++')

ADM=()
for a in "${ADMIN_IPS[@]:-}"; do
	[[ -n $a && $a != \#* ]] && ADM+=("$a")
done
sip=${SSH_CONNECTION:-}
sip=${sip%% *}
[[ $sip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && $sip != 127.0.0.1 ]] && ADM+=("$sip")

ADM_DECL=""
[[ ${#ADM[@]} -gt 0 ]] && ADM_DECL="elements = { $(join "${ADM[@]}"); };"
AP_DECL=""
[[ -n ${ADMIN_PORTS:-} ]] && AP_DECL="elements = { $(join ${ADMIN_PORTS// /, }); };"

GEO_JUMPS=""
[[ ${GEO_MODE:-vn-only} == vn-only ]] && GEO_JUMPS=$'tcp dport @game_ports jump geo_allow\n\t\tudp dport @game_ports jump geo_allow'

{
	cat <<EOF
#!/usr/sbin/nft -f

table inet gamefilter {}
delete table inet gamefilter

table inet gamefilter {
	set vn4 { type ipv4_addr; flags interval; auto-merge; size 262144; }
	set vn6 { type ipv6_addr; flags interval; auto-merge; size 65536; }
	set admin4 { type ipv4_addr; flags interval; auto-merge; size 1024; $ADM_DECL }
	set game_ports { type inet_service; flags interval; auto-merge; elements = { $(join "${VPS_PORTS[@]}") }; }
	set admin_ports { type inet_service; flags interval; auto-merge; $AP_DECL }

	chain prerouting {
		type filter hook prerouting priority -350; policy accept;

		ct state new tcp dport @game_ports meter g_tcp { ip saddr limit rate over ${TCP_NEWCONN_PER_IP:-30}/second burst 60 packets } counter drop
		udp dport @game_ports meter g_udp { ip saddr limit rate over ${UDP_PPS_PER_IP:-200}/second burst 400 packets } counter drop
		ct state new tcp dport @game_ports meter g_conn { ip saddr ct count over ${TCP_CONN_PER_IP:-60} } counter drop
		${GEO_JUMPS}
		tcp dport @admin_ports jump admin_allow
	}

	chain geo_allow {
		ip saddr @admin4 return
		ip saddr @vn4 return
		ip6 saddr @vn6 return
		limit rate 10/minute log prefix "geo-block: " level info
		counter drop
	}

	chain admin_allow {
		ip saddr @admin4 return
		limit rate 5/minute log prefix "admin-deny: " level info
		counter drop
	}
}

table inet gameproxy {}
delete table inet gameproxy

table inet gameproxy {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		$(printf '%s\n\t\t' "${RULES[@]}")
	}
EOF
	if [[ ${FORWARD_MODE:-proxy} == proxy ]]; then
		cat <<EOF

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip daddr $WIN_IP masquerade
	}
EOF
	fi
	echo "}"
} >"$OUT"

{
	printf 'iifname "%s" ip daddr %s counter accept\n' "$WAN_IF" "$WIN_IP"
	[[ $LAN_IF != "$WAN_IF" ]] && printf 'oifname "%s" ip daddr %s counter accept\n' "$LAN_IF" "$WIN_IP"
} >"$FWD"

nft -c -f "$OUT" || die "ruleset sinh ra sai cú pháp"
nft -f "$OUT"
echo "đã áp dụng NAT cho ${#VPS_PORTS[@]} cổng: ${VPS_PORTS[*]}"

if nft list chain inet filter forward >/dev/null 2>&1; then
	nft list chain inet filter forward | grep -q "ip daddr $WIN_IP" \
		|| nft insert rule inet filter forward ip daddr "$WIN_IP" counter accept
else
	echo "cảnh báo: chưa có chain 'inet filter forward' (cài install.sh trước)" >&2
fi
