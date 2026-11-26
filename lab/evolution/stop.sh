#!/bin/sh
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
OUT=${1:-results/$(date -u +%Y%m%dT%H%M%SZ)-snapshot}
mkdir -p "$OUT"
for node in train validation test; do
  docker stop -t 3 "bb-evolution-capture-$node" >/dev/null 2>&1 || true
  docker logs "bb-evolution-capture-$node" > "$OUT/$node-capture.log" 2>&1 || true
  docker logs "bb-evolution-$node-1" > "$OUT/$node-belnet.log" 2>&1 || true
  cp "run/$node/wire.pcap" "$OUT/$node.pcap"
  for entry in 1 2; do
    [ ! -f "run/$node/entry$entry-transport.log" ] || cp "run/$node/entry$entry-transport.log" "$OUT/$node-entry$entry-transport.log"
  done
done
cp run/service-http.log "$OUT/service-http.log"
for n in 1 2; do cp "../run/entry$n/evolution-transport.log" "$OUT/entry$n-server.log"; done
if docker compose version >/dev/null 2>&1; then docker compose -f compose.yml stop; else docker-compose -f compose.yml stop; fi
echo "$OUT"
