#!/usr/bin/env bash
# Start the mini hospital and the HASSAN agent (Linux Mint laptop, at the venue).
#   sudo bash start_lab.sh <THIS_LAPTOP_LAN_IP>          e.g. 192.168.1.50
#   sudo bash start_lab.sh <IP> --dry-run                 print rules only (rehearsal)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
IP="${1:?usage: start_lab.sh LAN_IP (see: ip -4 addr)}"
MODE="--apply"; [[ "${2:-}" == "--dry-run" ]] && MODE=""
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" && docker compose up -d
modprobe br_netfilter && sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
iptables -C DOCKER-USER -s 172.30.0.0/24 ! -d 172.30.0.0/24 -j DROP 2>/dev/null \
  || iptables -I DOCKER-USER -s 172.30.0.0/24 ! -d 172.30.0.0/24 -j DROP
cd "$HERE/../../.."            # backend/
HASSAN_SECRET_DIR=/etc/hassan exec python3 -m qacrs.booth.agent --bind "$IP" --port 8900 $MODE
