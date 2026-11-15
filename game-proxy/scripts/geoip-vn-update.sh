#!/usr/bin/env bash
set -Eeuo pipefail

CACHE=/var/lib/ddos
SET4="inet gamefilter vn4"
SET6="inet gamefilter vn6"
CHUNK=2000
CACHE_ONLY=0
[[ ${1:-} == --cache-only ]] && CACHE_ONLY=1

V4_URLS=(
	https://www.ipdeny.com/ipblocks/data/aggregated/vn-aggregated.zone
	https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr
)
V6_URLS=(
	https://www.ipdeny.com/ipv6/ipaddresses/aggregated/vn-aggregated.zone
	https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/vn.cidr
)

log() { printf '[%s] %s\n' "$(date '+%T')" "$*"; }
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$CACHE"

fetch() {
	local out=$1 re=$2 url
	shift 2
	for url in "$@"; do
		if curl -fsSL --max-time 60 --retry 2 -A ddos-geoip "$url" 2>/dev/null \
			| grep -aoE "$re" | sort -u >"$T/x" && [[ -s $T/x ]]; then
			mv "$T/x" "$out"
			log "ok $url"
			return 0
		fi
	done
	log "bỏ qua $out"
	return 1
}

RE4='^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$'
RE6='^[0-9a-fA-F:]+(:[0-9a-fA-F:]*)*/[0-9]{1,3}$'

if ((CACHE_ONLY)); then
	log "cache-only"
else
	fetch "$T/v4.new" "$RE4" "${V4_URLS[@]}" || true
	fetch "$T/v6.new" "$RE6" "${V6_URLS[@]}" || true
fi

load() {
	local set=$1 file=$2 tag=$3
	[[ -s $file ]] || { log "không có dữ liệu $tag"; return 1; }
	nft list set $set >/dev/null 2>&1 || { log "chưa có set $tag"; return 1; }
	nft flush set $set
	split -l "$CHUNK" -d -a 4 "$file" "$T/${tag}_"
	local loaded=0 f
	for f in "$T"/"${tag}"_*; do
		{ printf 'add element %s { ' "$set"; paste -sd, "$f"; printf ' }\n'; } >"$f.nft"
		nft -f "$f.nft" 2>/dev/null && loaded=$((loaded + $(wc -l <"$f")))
	done
	log "nạp $loaded dải $tag"
}

[[ -s $T/v4.new ]] && mv "$T/v4.new" "$CACHE/vn.zone"
[[ -s $T/v6.new ]] && mv "$T/v6.new" "$CACHE/vn6.zone"
[[ ${CACHE_ONLY} -eq 1 && ! -s $CACHE/vn.zone ]] && log "cache rỗng"

load "$SET4" "$CACHE/vn.zone" v4 || true
load "$SET6" "$CACHE/vn6.zone" v6 || true

if [[ -r /etc/ddos/game-proxy.conf ]]; then
	. /etc/ddos/game-proxy.conf || true
	if [[ ${GEOIP_FAIL_OPEN:-no} == yes ]] && ! nft list set $SET4 | grep -q elements; then
		log "fail-open: cho qua toàn bộ"
		nft add element $SET4 "{ 0.0.0.0/0 }" || true
	fi
fi
