#!/bin/sh
set -eu
for n in 1 2; do
  case "$n" in 1) entry=10.88.0.11 ;; 2) entry=10.88.0.12 ;; esac
  iptables -t nat -A OUTPUT -p udp -d "$entry" --dport 1090 -j DNAT --to-destination "127.0.0.1:209$n"
done
iptables -A OUTPUT -p udp -d 127.0.0.1 -m multiport --dports 2091,2092 -j ACCEPT
# Direct attempts to all other relay IWP sockets fail closed.
iptables -A OUTPUT -o eth0 -p udp --dport 1090 -j DROP
echo ready > "/lab/evolution/run/${1:?}/firewall.ready"
