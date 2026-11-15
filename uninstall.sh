#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "cần root" >&2; exit 1; }

nft delete table inet filter 2>/dev/null || true
nft delete table inet ddos_raw 2>/dev/null || true
nft delete table inet gameproxy 2>/dev/null || true
nft delete table inet gamefilter 2>/dev/null || true

systemctl disable --now ddos-panel ddos-geoip.timer ddos-geoip-boot.service ddos-blocklist.timer 2>/dev/null || true

rm -f /etc/nftables.d/ddos.nft /etc/nftables.d/game-proxy.nft /etc/nftables.d/zz-proxy-forward.nft \
	/etc/ddos/emergency-on.nft /etc/ddos/emergency-off.nft \
	/etc/ddos/whitelist.txt /etc/ddos/forward-extra.rules \
	/etc/ddos/game-proxy.conf /etc/ddos/panel.json \
	/etc/systemd/system/ddos-panel.service \
	/etc/systemd/system/ddos-geoip.service /etc/systemd/system/ddos-geoip.timer \
	/etc/systemd/system/ddos-geoip-boot.service \
	/etc/systemd/system/ddos-blocklist.service /etc/systemd/system/ddos-blocklist.timer \
	/etc/sysctl.d/99-ddos-hardening.conf /etc/sysctl.d/99-bbr.conf \
	/etc/sysctl.d/99-game-proxy.conf \
	/etc/modprobe.d/nf_conntrack.conf /etc/modules-load.d/ddos-netfilter.conf \
	/etc/security/limits.d/99-ddos-limits.conf \
	/etc/nginx/conf.d/00-ddos-http.conf /etc/nginx/snippets/ddos-server.conf \
	/usr/local/sbin/ddos-status /usr/local/sbin/ddos-emergency \
	/usr/local/sbin/ddos-update-blocklist /usr/local/sbin/gen-proxy-rules \
	/usr/local/sbin/geoip-vn-update /usr/local/sbin/proxy-status \
	/usr/local/sbin/ddos-panel
rm -rf /var/lib/ddos /etc/ddos

systemctl daemon-reload
printf '#!/usr/sbin/nft -f\n\nflush ruleset\n' >/etc/nftables.conf
chmod 0755 /etc/nftables.conf
sysctl --system >/dev/null 2>&1 || true
nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true

echo "đã gỡ. fail2ban giữ nguyên (/etc/fail2ban), ufw: ufw enable"
