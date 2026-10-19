#!/usr/bin/env bash
# ACRS Box (Raspberry Pi 5 prototype): start the engine + interface offline and open it full screen (kiosk).
#   bash backend/qacrs/booth/start_box.sh            # kiosk on the attached screen
# Needs: python3 (+numpy), chromium. Binds to 127.0.0.1 only; nothing is exposed on the network.
set -euo pipefail
cd "$(dirname "$0")/../.."                       # -> backend
mkdir -p "$HOME/.hassan" && chmod 700 "$HOME/.hassan"
python3 -m qacrs.booth.server --port 8800 --auto-budget &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
for i in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:8800/ && break; sleep 0.5; done
BROWSER=$(command -v chromium-browser || command -v chromium || echo chromium)
"$BROWSER" --kiosk --incognito --noerrdialogs --disable-infobars --no-first-run --check-for-update-interval=31536000 \
  --overscroll-history-navigation=0 "http://127.0.0.1:8800/?kiosk=1"
