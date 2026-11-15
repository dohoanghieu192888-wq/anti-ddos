#!/usr/bin/env bash
# =====================================================================
#  update-blocklist.sh - tải blocklist công khai và nạp vào nftables
#  Chạy tự động mỗi ngày qua ddos-blocklist.timer
#  Chạy tay: sudo /usr/local/sbin/ddos-update-blocklist
# =====================================================================
set -Eeuo pipefail

NFT_SET4="inet filter blackhole_v4"
NFT_SET6="inet filter blackhole_v6"
CHUNK=2000
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { log "LỖI: $*" >&2; exit 1; }

command -v nft >/dev/null || die "chưa cài nftables"
command -v curl >/dev/null || die "chưa cài curl"

# Danh sách nguồn (có thể thêm/bớt)
SOURCES=(
	"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
	"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"
	"https://www.spamhaus.org/drop/drop.txt"
	"https://www.spamhaus.org/drop/edrop.txt"
)

RAW="$TMPDIR/raw.txt"
: >"$RAW"

for url in "${SOURCES[@]}"; do
	if curl -fsSL --max-time 60 --retry 2 -A "ddos-blocklist/1.0" "$url" >>"$RAW"; then
		log "OK   $url"
	else
		log "BỎ QUA (không tải được) $url"
	fi
done

# Chỉ giữ IP/CIDR hợp lệ, bỏ comment và rác
grep -aE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' "$RAW" \
	| grep -vE '^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
	| sort -u >"$TMPDIR/v4.txt" || true

# Bỏ các IP nằm trong whitelist (so khớp chính xác)
if [[ -s /etc/ddos/whitelist.txt ]]; then
	grep -aE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' /etc/ddos/whitelist.txt \
		| sort -u >"$TMPDIR/wl.txt" || true
	comm -23 "$TMPDIR/v4.txt" "$TMPDIR/wl.txt" >"$TMPDIR/v4f.txt" || cp "$TMPDIR/v4.txt" "$TMPDIR/v4f.txt"
else
	cp "$TMPDIR/v4.txt" "$TMPDIR/v4f.txt"
fi

# Gộp các dải trùng/chồng nhau nếu có công cụ aggregate
if command -v aggregate >/dev/null; then
	aggregate -q <"$TMPDIR/v4f.txt" >"$TMPDIR/v4agg.txt" 2>/dev/null \
		&& mv "$TMPDIR/v4agg.txt" "$TMPDIR/v4f.txt" \
		&& log "Đã gộp dải trùng bằng aggregate" || true
fi

COUNT=$(wc -l <"$TMPDIR/v4f.txt" | tr -d ' ')
log "Số mục sau khi lọc: $COUNT"
[[ "$COUNT" -gt 0 ]] || die "blocklist rỗng - giữ nguyên cấu hình cũ"

# Xoá blocklist cũ
nft flush set $NFT_SET4

# Nạp từng chunk riêng: một chunk lỗi (dải chồng nhau) không làm mất cả list
split -l "$CHUNK" -d -a 4 "$TMPDIR/v4f.txt" "$TMPDIR/chunk_"
LOADED=0
FAILED=0
for f in "$TMPDIR"/chunk_*; do
	printf 'add element %s { ' "$NFT_SET4" >"$f.nft"
	paste -sd, "$f" >>"$f.nft"
	printf ' }\n' >>"$f.nft"
	if nft -f "$f.nft" 2>/dev/null; then
		LOADED=$((LOADED + $(wc -l <"$f")))
	else
		FAILED=$((FAILED + $(wc -l <"$f")))
		log "CẢNH BÁO: bỏ qua 1 chunk ($(wc -l <"$f") mục) do lỗi dải chồng nhau"
	fi
done

log "Đã nạp $LOADED mục vào $NFT_SET4 (bỏ qua $FAILED)"
[[ "$LOADED" -gt 0 ]] || die "không nạp được mục nào"
log "Tổng số IP đang bị chặn: $(nft list set $NFT_SET4 | grep -c ':') dòng"
