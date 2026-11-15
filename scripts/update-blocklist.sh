#!/usr/bin/env bash
set -Eeuo pipefail

SET="inet filter blackhole_v4"
CHUNK=2000
URLS=(
	https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
	https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset
	https://www.spamhaus.org/drop/drop.txt
	https://www.spamhaus.org/drop/edrop.txt
)

log() { printf '[%s] %s\n' "$(date '+%T')" "$*"; }
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

command -v nft >/dev/null || { log "thiếu nftables"; exit 1; }

: >"$T/raw"
for u in "${URLS[@]}"; do
	curl -fsSL --max-time 60 --retry 2 -A ddos-blocklist "$u" >>"$T/raw" 2>/dev/null \
		&& log "ok $u" || log "bỏ qua $u"
done

grep -aE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' "$T/raw" \
	| grep -vE '^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
	| sort -u >"$T/v4"

if command -v aggregate >/dev/null; then
	aggregate -q <"$T/v4" >"$T/agg" 2>/dev/null && mv "$T/agg" "$T/v4"
fi

if [[ -s /etc/ddos/whitelist.txt ]]; then
	grep -aE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' /etc/ddos/whitelist.txt \
		| sort -u >"$T/wl"
	comm -23 "$T/v4" "$T/wl" >"$T/f"
else
	cp "$T/v4" "$T/f"
fi

total=$(wc -l <"$T/f")
((total > 0)) || { log "danh sách rỗng, giữ nguyên"; exit 1; }

nft flush set $SET
split -l "$CHUNK" -d -a 4 "$T/f" "$T/c_"
loaded=0
for f in "$T"/c_*; do
	{ printf 'add element %s { ' "$SET"; paste -sd, "$f"; printf ' }\n'; } >"$f.nft"
	nft -f "$f.nft" 2>/dev/null && loaded=$((loaded + $(wc -l <"$f")))
done

log "đã nạp $loaded/$total mục vào $SET"
