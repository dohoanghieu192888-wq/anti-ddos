#!/usr/bin/env bash
# =====================================================================
#  geoip-vn-update.sh — tải danh sách IP Việt Nam và nạp vào nftables
#    sudo geoip-vn-update
#  Cache: /var/lib/ddos/vn.zone (+ vn6.zone) -> dùng được khi boot không
#         có mạng và khi nguồn tải lỗi.
# =====================================================================
set -Eeuo pipefail

CACHE_DIR="/var/lib/ddos"
V4_CACHE="$CACHE_DIR/vn.zone"
V6_CACHE="$CACHE_DIR/vn6.zone"
SET4="inet gamefilter vn4"
SET6="inet gamefilter vn6"
CHUNK=2000

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --cache-only: chỉ dùng cache trong /var/lib/ddos (dùng lúc boot)
CACHE_ONLY=0
[[ "${1:-}" == "--cache-only" ]] && CACHE_ONLY=1

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }

SRC4=(
	"https://www.ipdeny.com/ipblocks/data/aggregated/vn-aggregated.zone"
	"https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr"
)
SRC6=(
	"https://www.ipdeny.com/ipv6/ipaddresses/aggregated/vn-aggregated.zone"
	"https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/vn.cidr"
)

mkdir -p "$CACHE_DIR"

# fetch_list <output> <regex> <urls...>
fetch_list() {
	local out="$1" re="$2"; shift 2
	local url
	for url in "$@"; do
		if curl -fsSL --max-time 60 --retry 2 -A "ddos-geoip/1.0" "$url" \
			| grep -aoE "$re" | sort -u >"$TMP/list" && [[ -s "$TMP/list" ]]; then
			mv "$TMP/list" "$out"
			log "OK   $url ($(wc -l <"$out" | tr -d ' ') dải)"
			return 0
		fi
		log "BỎ QUA $url"
	done
	return 1
}

RE4='^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$'
RE6='^[0-9a-fA-F:]+(:[0-9a-fA-F:]*)*/[0-9]{1,3}$'

if [[ "$CACHE_ONLY" == 1 ]]; then
	log "Chế độ --cache-only: dùng cache $CACHE_DIR (dùng khi boot)"
else
	fetch_list "$TMP/v4.new" "$RE4" "${SRC4[@]}" || log "Không tải được IPv4 mới"
	fetch_list "$TMP/v6.new" "$RE6" "${SRC6[@]}" || log "Không tải được IPv6 mới"
fi

# Dùng bản mới nếu có, không thì dùng cache
for pair in "v4:$V4_CACHE:$SET4:vn4" "v6:$V6_CACHE:$SET6:vn6"; do
	IFS=: read -r tag cache set name <<<"$pair"
	new="$TMP/$tag.new"
	if [[ -s "$new" ]]; then
		mv "$new" "$cache"
	elif [[ -s "$cache" ]]; then
		log "Dùng cache $cache cho $tag"
	else
		log "CẢNH BÁO: không có dữ liệu $tag nào"
	fi

	[[ -s "$cache" ]] || continue
	nft list set $set >/dev/null 2>&1 || { log "CẢNH BÁO: chưa có set $set (chạy gen-proxy-rules)"; continue; }

	nft flush set $set
	split -l "$CHUNK" -d -a 4 "$cache" "$TMP/c_${tag}_"
	loaded=0
	for f in "$TMP"/c_"${tag}"_*; do
		{ printf 'add element %s { ' "$set"; paste -sd, "$f"; printf ' }\n'; } >"$f.nft"
		if nft -f "$f.nft" 2>/dev/null; then
			loaded=$((loaded + $(wc -l <"$f")))
		else
			log "CẢNH BÁO: bỏ qua 1 chunk $tag ($(wc -l <"$f") mục)"
		fi
	done
	log "Đã nạp $loaded dải $tag vào $set"
done

# Fail-open nếu cấu hình yêu cầu và không có dữ liệu VN
if [[ -r /etc/ddos/game-proxy.conf ]]; then
	# shellcheck disable=SC1091
	source /etc/ddos/game-proxy.conf || true
	if [[ "${GEOIP_FAIL_OPEN:-no}" == "yes" ]] \
		&& ! nft list set $SET4 | grep -q 'elements'; then
		log "GEOIP_FAIL_OPEN=yes và set rỗng -> thêm 0.0.0.0/0 (tạm cho qua hết)"
		nft add element $SET4 "{ 0.0.0.0/0 }" || true
	fi
fi

log "Hoàn tất"
