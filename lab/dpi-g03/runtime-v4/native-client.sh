#!/bin/sh
set -eu
: "${G03_CLIENT_IP:?}"
mkdir -p /group/data/nodedb/0
for peer in seed entry1 entry2 relay1 relay2 relay3; do cp "/prep/fixtures/$peer/self.signed" "/group/data/nodedb/0/$peer.signed"; done
while [ ! -f /group/start-native ]; do sleep 0.1; done
BRIDGE_TOKEN=$(cat /prep/private/bridge-token); export BRIDGE_TOKEN
for n in 1 2; do
 case "$n" in 1) entry=10.88.0.11;; 2) entry=10.88.0.12;; esac
 /bridge udp-stream-client -listen "127.0.0.1:209$n" -upstream "127.0.0.1:1909$n" -max-queue-age 100ms -lab-control "127.0.0.1:219$n" > "/group/adapter$n.log" 2>&1 &
 echo $! > "/group/adapter$n.pid"
 iptables -t nat -A OUTPUT -p udp -d "$entry" --dport 1090 -j DNAT --to-destination "127.0.0.1:209$n"
done
iptables -A OUTPUT -o eth0 -p udp --dport 1090 -j DROP
cat > /group/data/belnet.ini <<CONF
[router]
data-dir=/group/data
netid=bb-lab
block-bogons=false
nickname=g03-native
worker-threads=1
[logging]
level=info
type=print
[api]
enabled=true
bind=tcp://127.0.0.1:1190
[bind]
outbound=$G03_CLIENT_IP:0
[network]
type=tun
ifname=bbtun0
ifaddr=10.253.0.1/16
reachable=true
keyfile=/group/data/service.private
hops=3
paths=3
[paths]
unique-range-size=32
[dns]
bind=127.3.2.1:53
upstream=
[bootstrap]
seed-node=true
CONF
exec belnet /group/data/belnet.ini > /group/belnet.log 2>&1
