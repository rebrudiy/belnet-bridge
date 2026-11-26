#!/bin/sh
set -eu
DATA=/lab/evolution/run/${NODE:?}
mkdir -p "$DATA/nodedb/0"
for peer in seed entry1 entry2 relay1 relay2 relay3; do
  cp "/lab/run/fixtures/$peer/self.signed" "$DATA/nodedb/0/$peer.signed"
done
cat > "$DATA/belnet.ini" <<EOF
[router]
data-dir=$DATA
netid=bb-lab
block-bogons=false
nickname=evolution-$NODE
worker-threads=1
[logging]
level=info
type=print
[api]
enabled=true
bind=tcp://127.0.0.1:1190
[bind]
outbound=${NODE_IP:?}:0
[network]
type=tun
ifname=bbtun0
ifaddr=10.251.0.1/16
reachable=true
keyfile=$DATA/service.private
hops=3
paths=3
[paths]
unique-range-size=32
[dns]
bind=127.3.2.1:53
upstream=
[bootstrap]
seed-node=true
EOF
while [ ! -s "$DATA/start.ready" ]; do sleep 1; done
BRIDGE_TOKEN=$(cat /lab/run/certs/token)
export BRIDGE_TOKEN
for n in 1 2; do
  case "$n" in 1) entry=10.88.0.11 ;; 2) entry=10.88.0.12 ;; esac
  belnet-bridge udp-client -listen "127.0.0.1:209$n" -url "wss://$entry/ws" \
    -ca /lab/run/certs/ca.crt -lab-control "127.0.0.1:219$n" \
    -lab-observe-dir "$DATA/observations-entry$n" > "$DATA/entry$n-transport.log" 2>&1 &
done
while [ ! -s "$DATA/firewall.ready" ]; do sleep 1; done
exec belnet "$DATA/belnet.ini"
