#!/usr/bin/env bash
# Mini hospital on the Linux Mint laptop. Run ONCE at home (needs internet to pull one image), then at the venue
# only start_lab.sh is needed (no internet).
#   sudo bash setup_linux.sh <WINDOWS_LAPTOP_IP>
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
WIN_IP="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SECRET_DIR=/etc/hassan

echo "== 1. Docker"
if ! command -v docker >/dev/null; then
  apt-get update && apt-get install -y docker.io docker-compose-v2 python3
fi
systemctl enable --now docker

echo "== 2. Bridge traffic must pass through iptables (so HASSAN's rules apply between containers)"
modprobe br_netfilter
sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
echo br_netfilter > /etc/modules-load.d/hassan.conf
echo "net.bridge.bridge-nf-call-iptables=1" > /etc/sysctl.d/90-hassan.conf

echo "== 3. Pull the image and start the lab (no ports published)"
cd "$HERE"
docker compose pull
docker compose up -d

echo "== 4. The lab may only talk to itself (never the venue network or the internet)"
iptables -C DOCKER-USER -s 172.30.0.0/24 ! -d 172.30.0.0/24 -j DROP 2>/dev/null \
  || iptables -I DOCKER-USER -s 172.30.0.0/24 ! -d 172.30.0.0/24 -j DROP

echo "== 5. Signing key (shared with the Windows laptop by USB, never by chat or e-mail)"
install -d -m 700 "$SECRET_DIR"
(cd "$HERE/../../.." && HASSAN_SECRET_DIR="$SECRET_DIR" python3 -c "from qacrs.booth import secure; secure.load_secret('plan_key')")
chmod 600 "$SECRET_DIR/plan_key"
echo "   copy $SECRET_DIR/plan_key to a USB stick, then on Windows to %USERPROFILE%\\.hassan\\plan_key"

echo "== 6. Only the Windows laptop may reach the agent port"
if [[ -n "$WIN_IP" ]] && command -v ufw >/dev/null; then
  ufw allow from "$WIN_IP" to any port 8900 proto tcp
  ufw --force enable
fi
echo "done. Next: sudo bash $HERE/start_lab.sh <THIS_LAPTOP_LAN_IP>"
