#!/bin/sh
# Called by run.sh only after a healthy tunnel workload; uses existing captures.
set -eu
OUT=${1:?results directory}
ADDRESS=${2:?bdx address}
event() { printf '{"time":"%s","event":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$OUT/events.jsonl"; }
event stop_both_entry_https_transports
START=$(date +%s)
for entry in entry1 entry2; do
  docker exec "bb-lab-$entry-1" /bin/sh -c 'kill -TERM "$(cat /lab/run/$NODE/transport.pid)"'
done
docker exec bb-lab-client-1 /lab/probe-linux fetch "http://$ADDRESS:8080" >> "$OUT/outage-requests.jsonl" 2>&1 || true
ELAPSED=$(($(date +%s)-START))
if [ "$ELAPSED" -lt 30 ]; then sleep "$((30-ELAPSED))"; fi
event restart_both_entry_https_transports
for entry in entry1 entry2; do
  docker exec -d "bb-lab-$entry-1" /bin/sh -c '
    BRIDGE_TOKEN=$(cat /lab/run/certs/token); export BRIDGE_TOKEN
    exec belnet-bridge udp-server -listen :443 -cert /lab/run/certs/entry.crt -key /lab/run/certs/entry.key -target "$NODE_IP:1090" >> /lab/run/$NODE/transport.log 2>&1
  '
done
RECOVERED=no
for attempt in 1 2 3 4 5 6 7 8; do
  if docker exec bb-lab-client-1 /lab/probe-linux fetch "http://$ADDRESS:8080" >> "$OUT/recovery-requests.jsonl" 2>&1; then
    RECOVERED=yes
    break
  fi
  sleep 2
done
event "recovery_http_$RECOVERED"
printf 'recovery_http_ok=%s\n' "$RECOVERED" >> "$OUT/manifest.txt"
