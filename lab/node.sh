#!/bin/sh
set -eu
NODE=${NODE:?}
ROLE=${ROLE:?}
NODE_IP=${NODE_IP:?}
DATA=/lab/run/$NODE
BOOT=/lab/run
if [ -s /lab/run/fixtures/ready ]; then BOOT=/lab/run/fixtures; fi
mkdir -p "$DATA"
if [ "$NODE" != seed ]; then
  while [ ! -s /lab/run/seed/self.signed ]; do sleep 1; done
fi
if [ "$NODE" = entry1 ]; then
  /lab/probe-linux udp-echo > "$DATA/benign-udp.log" 2>&1 &
fi
if [ "$ROLE" != relay ]; then
  for peer in seed entry1 entry2 relay1 relay2 relay3; do
    while [ ! -s "/lab/run/$peer/self.signed" ]; do sleep 1; done
  done
fi
# Offline fixtures avoid external bootstrap and preserve original signed RCs.
mkdir -p "$DATA/nodedb/0"
for peer in seed entry1 entry2 relay1 relay2 relay3; do
  if [ -s "$BOOT/$peer/self.signed" ]; then
    cp "$BOOT/$peer/self.signed" "$DATA/nodedb/0/$peer.signed"
  fi
done
cat > "$DATA/belnet.ini" <<EOF
[router]
data-dir=$DATA
netid=bb-lab
block-bogons=false
nickname=$NODE
worker-threads=1
[logging]
level=${BB_LOG_LEVEL:-info}
type=print
[api]
enabled=true
bind=tcp://127.0.0.1:1190
[bind]
outbound=$NODE_IP:0
EOF
if [ "$ROLE" = relay ]; then
  cat >> "$DATA/belnet.ini" <<EOF
inbound=$NODE_IP:1090
[network]
type=null
[beldexd]
enabled=false
rpc=ipc:///lab/unused-beldexd.sock
EOF
else
  cat >> "$DATA/belnet.ini" <<EOF
[network]
type=tun
ifname=bbtun0
ifaddr=10.250.0.1/16
reachable=true
keyfile=$DATA/service.private
hops=${BB_HOPS:-3}
paths=3
EOF
  cat >> "$DATA/belnet.ini" <<EOF
[paths]
unique-range-size=32
[dns]
bind=127.3.2.1:53
upstream=
EOF
fi
ALL_READY=1
for peer in seed entry1 entry2 relay1 relay2 relay3; do
  if [ ! -s "$BOOT/$peer/self.signed" ]; then ALL_READY=0; fi
done
if [ "$ROLE" = relay ] && [ "$ALL_READY" = 1 ]; then
  echo '[bootstrap]' >> "$DATA/belnet.ini"
  for peer in seed entry1 entry2 relay1 relay2 relay3; do
    echo "add-node=$BOOT/$peer/self.signed" >> "$DATA/belnet.ini"
  done
elif [ "$NODE" = seed ] || [ "$ROLE" != relay ]; then
  cat >> "$DATA/belnet.ini" <<EOF
[bootstrap]
seed-node=true
EOF
else
  cat >> "$DATA/belnet.ini" <<EOF
[bootstrap]
add-node=/lab/run/seed/self.signed
EOF
fi
# TLS transport terminates inside the actual entry relay's network namespace.
if [ "$NODE" = entry1 ] || [ "$NODE" = entry2 ]; then
  BRIDGE_TOKEN=$(cat /lab/run/certs/token)
  export BRIDGE_TOKEN
  belnet-bridge udp-server -listen :443 -cert /lab/run/certs/entry.crt \
    -key /lab/run/certs/entry.key -target "$NODE_IP:1090" \
    > "$DATA/transport.log" 2>&1 &
  echo $! > "$DATA/transport.pid"
fi
if [ "$NODE" = service ]; then
  /lab/probe-linux serve > "$DATA/http.log" 2>&1 &
fi
if [ "$NODE" = client ]; then
  case "${MODE:-control}" in
    control|dpi) ;;
    filter|tunnel|dpi-tunnel)
      if [ "$MODE" = tunnel ] || [ "$MODE" = dpi-tunnel ]; then
        BRIDGE_TOKEN=$(cat /lab/run/certs/token)
        export BRIDGE_TOKEN
        belnet-bridge udp-client -listen 127.0.0.1:2091 -url wss://10.88.0.11/ws \
          -ca /lab/run/certs/ca.crt > "$DATA/entry1-transport.log" 2>&1 &
        belnet-bridge udp-client -listen 127.0.0.1:2092 -url wss://10.88.0.12/ws \
          -ca /lab/run/certs/ca.crt > "$DATA/entry2-transport.log" 2>&1 &
      fi
      ;;
    *) echo "Unknown MODE: $MODE" >&2; exit 2 ;;
  esac
  # A host-native utility applies rules inside this same namespace. This avoids
  # unsupported netfilter syscalls when the release runs under QEMU on ARM.
  while [ ! -s /lab/run/client/firewall.ready ]; do sleep 1; done
fi
if [ "$ROLE" = relay ]; then
  exec belnet -r "$DATA/belnet.ini"
else
  exec belnet "$DATA/belnet.ini"
fi
