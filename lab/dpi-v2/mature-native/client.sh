#!/bin/sh
set -eu
data=/lab/dpi-v2/run/mature-native/client
mkdir -p "$data/nodedb/0"
for peer in seed entry1 entry2 relay1 relay2 relay3; do cp "/lab/run/fixtures/$peer/self.signed" "$data/nodedb/0/$peer.signed"; done
/mature/sing-box run -c /work/private/client.json > /work/client-singbox.log 2>&1 &
echo $! > /work/client-singbox.pid
for n in 1 2; do
 case "$n" in 1) entry=10.88.0.11;; 2) entry=10.88.0.12;; esac
 iptables -t nat -A OUTPUT -p udp -d "$entry" --dport 1090 -j DNAT --to-destination "127.0.0.1:1909$n"
done
iptables -A OUTPUT -o eth0 -p udp --dport 1090 -j DROP
cat > "$data/belnet.ini" <<CONF
[router]
data-dir=$data
netid=bb-lab
block-bogons=false
nickname=mature-native
worker-threads=1
[logging]
level=info
type=print
[api]
enabled=true
bind=tcp://127.0.0.1:1190
[bind]
outbound=10.88.0.41:0
[network]
type=tun
ifname=bbtun0
ifaddr=10.252.0.1/16
reachable=true
keyfile=$data/service.private
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
exec belnet "$data/belnet.ini" > "$data/belnet.log" 2>&1
