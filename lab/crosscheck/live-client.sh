#!/bin/sh
set -eu
kind=${KIND:?}
data=/lab/crosscheck/run/$kind-client
mkdir -p "$data/nodedb/0"
for peer in seed entry1 entry2 relay1 relay2 relay3; do cp "/lab/run/fixtures/$peer/self.signed" "$data/nodedb/0/$peer.signed"; done
if [ "$kind" = claude ]; then
  ip tuntap add dev bb0 mode tun
  ip link set bb0 up mtu 1500
  rm -f "$data/addr"
  /bin/sh /lab/crosscheck/proxy-claude.sh
  for i in $(seq 1 60); do [ -s "$data/addr" ] && ip -4 addr show dev bb0 | grep -q "inet 10.77." && break; sleep 1; done
  test -s "$data/addr"
  bind_ip=$(cut -d/ -f1 "$data/addr")
  for entry in 10.88.0.11 10.88.0.12; do iptables -A OUTPUT -o bb0 -p udp -d "$entry" --dport 1090 -j ACCEPT; done
  iptables -A OUTPUT -o bb0 -p udp --dport 1090 -j DROP
else
  bind_ip=${NODE_IP:?}
  BRIDGE_TOKEN=$(cat /lab/run/certs/token); export BRIDGE_TOKEN
  for n in 1 2; do
    case "$n" in 1) entry=10.88.0.11;; 2) entry=10.88.0.12;; esac
    /lab/crosscheck/bin/our-transport udp-client -listen "127.0.0.1:209$n" -url "wss://$entry/ws" -ca /lab/run/certs/ca.crt -profile /lab/crosscheck/run/frozen-profile.json -lab-control "127.0.0.1:219$n" > "$data/entry$n.log" 2>&1 &
    echo $! > "$data/entry$n.pid"
    iptables -t nat -A OUTPUT -p udp -d "$entry" --dport 1090 -j DNAT --to-destination "127.0.0.1:209$n"
  done
fi
iptables -A OUTPUT -o eth0 -p udp --dport 1090 -j DROP
cat > "$data/belnet.ini" <<CONF
[router]
data-dir=$data
netid=bb-lab
block-bogons=false
nickname=cross-$kind
worker-threads=1
[logging]
level=info
type=print
[api]
enabled=true
bind=tcp://127.0.0.1:1190
[bind]
outbound=$bind_ip:0
[network]
type=tun
ifname=bbtun0
ifaddr=10.251.0.1/16
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
