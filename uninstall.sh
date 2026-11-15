#!/usr/bin/env bash
# =====================================================================
#  uninstall.sh - Gỡ bộ firewall chống DDoS, trả hệ thống về mặc định
#  Chạy: sudo bash uninstall.sh
# =====================================================================
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Cần root: sudo bash uninstall.sh" >&2; exit 1; }

echo "==> Xoá bảng nftables của bộ DDoS"
nft delete table inet filter   2>/dev/null || true
nft delete table inet ddos_raw 2>/dev/null || true

echo "==> Xoá file cấu hình"
rm -f /etc/nftables.d/ddos.nft \
	/etc/ddos/emergency-on.nft /etc/ddos/emergency-off.nft /etc/ddos/whitelist.txt
rmdir /etc/ddos 2>/dev/null || true
rm -f /etc/sysctl.d/99-ddos-hardening.conf /etc/sysctl.d/99-bbr.conf
rm -f /etc/modprobe.d/nf_conntrack.conf /etc/modules-load.d/ddos-netfilter.conf
rm -f /etc/security/limits.d/99-ddos-limits.conf
rm -f /usr/local/sbin/ddos-status /usr/local/sbin/ddos-emergency /usr/local/sbin/ddos-update-blocklist
rm -f /etc/nginx/conf.d/00-ddos-http.conf /etc/nginx/snippets/ddos-server.conf

echo "==> Tắt timer cập nhật blocklist"
systemctl disable --now ddos-blocklist.timer 2>/dev/null || true
rm -f /etc/systemd/system/ddos-blocklist.timer /etc/systemd/system/ddos-blocklist.service
systemctl daemon-reload

echo "==> Khôi phục /etc/nftables.conf"
cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
EOF
chmod 0755 /etc/nftables.conf

echo "==> Áp lại sysctl mặc định"
sysctl --system >/dev/null 2>&1 || true

if command -v nginx >/dev/null && nginx -t >/dev/null 2>&1; then
	systemctl reload nginx 2>/dev/null || true
fi

echo
echo "Đã gỡ. fail2ban vẫn được giữ lại (cấu hình /etc/fail2ban/jail.local)."
echo "Nếu muốn gỡ luôn: apt-get remove --purge fail2ban"
echo "Nếu trước đây dùng ufw: ufw enable"
