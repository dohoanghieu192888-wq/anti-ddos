#!/usr/bin/env bash
set -Eeuo pipefail

D=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROXY=ask
WIN_IP=""
P_PORT=8080
P_USER=admin
P_BIND=127.0.0.1
G=$'\033[0;32m'; Y=$'\033[1;33m'; N=$'\033[0m'

ok() { echo "${G}[ok]${N} $*"; }
step() { echo; echo "${Y}==>${N} $*"; }
warn() { echo "${Y}[!]${N} $*"; }
die() { echo "$*" >&2; exit 1; }

while (($#)); do
	case $1 in
	--with-proxy) PROXY=yes ;;
	--no-proxy) PROXY=no ;;
	--win-ip) WIN_IP=${2:-}; shift ;;
	--panel-port) P_PORT=${2:-8080}; shift ;;
	--panel-user) P_USER=${2:-admin}; shift ;;
	--panel-bind) P_BIND=${2:-127.0.0.1}; shift ;;
	-h | --help) sed -n '4,12p' "$0"; exit 0 ;;
	*) die "tham số lạ: $1" ;;
	esac
	shift
done

[[ ${EUID} -eq 0 ]] || die "chạy bằng root: sudo bash setup-all.sh"

step "1/3 firewall"
bash "$D/install.sh"

step "2/3 shield proxy"
if [[ $PROXY == ask ]]; then
	if [[ -t 0 ]]; then
		read -r -p "Dùng VPS làm shield cho server game Windows? [Y/n] " a
		[[ ${a,,} == n* ]] && PROXY=no || PROXY=yes
	else
		PROXY=no
	fi
fi

if [[ $PROXY == yes ]]; then
	mkdir -p /etc/ddos
	[[ -z $WIN_IP && -t 0 ]] && read -r -p "IP server Windows: " WIN_IP
	[[ -f /etc/ddos/game-proxy.conf ]] || install -m 0640 "$D/game-proxy/game-proxy.conf.example" /etc/ddos/game-proxy.conf
	if [[ -n $WIN_IP ]]; then
		[[ $WIN_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "IP Windows sai: $WIN_IP"
		sed -i "s|^WIN_IP=.*|WIN_IP=\"$WIN_IP\"|" /etc/ddos/game-proxy.conf
		ok "WIN_IP=$WIN_IP"
	fi
	bash "$D/game-proxy/install-proxy.sh" || warn "shield proxy chưa trọn vẹn"
else
	ok "bỏ qua shield proxy"
fi

step "3/3 panel"
command -v python3 >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3
install -m 0755 "$D/panel/ddos-panel.py" /usr/local/sbin/ddos-panel
install -m 0644 "$D/panel/ddos-panel.service" /etc/systemd/system/ddos-panel.service
mkdir -p /etc/ddos

if [[ ! -f /etc/ddos/panel.json ]]; then
	python3 /usr/local/sbin/ddos-panel --init --user "$P_USER" | tee /root/ddos-panel-credentials.txt
	python3 - "$P_PORT" "$P_BIND" <<'PY'
import json, sys
p = "/etc/ddos/panel.json"
c = json.load(open(p))
c["port"], c["bind"] = int(sys.argv[1]), sys.argv[2]
json.dump(c, open(p, "w"), indent=2)
PY
	chmod 600 /root/ddos-panel-credentials.txt
else
	warn "giữ tài khoản panel cũ (/etc/ddos/panel.json)"
fi

systemctl daemon-reload
systemctl enable ddos-panel >/dev/null 2>&1
systemctl restart ddos-panel
sleep 2
systemctl is-active ddos-panel >/dev/null 2>&1 && ok "panel http://$P_BIND:$P_PORT" \
	|| warn "panel lỗi: journalctl -u ddos-panel -n 30"

VPS_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
echo
echo "panel   : http://$P_BIND:$P_PORT  (tài khoản: /root/ddos-panel-credentials.txt)"
echo "truy cập: ssh -L $P_PORT:127.0.0.1:$P_PORT root@${VPS_IP:-<IP-VPS>}"
echo "cli     : ddos-status | ddos-emergency on|off | proxy-status"
