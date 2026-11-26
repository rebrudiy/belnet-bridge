#!/bin/sh
set -eu
case "$1" in
 dpi|dpi-tunnel)
  # Post-DNAT local proxy traffic is not traffic leaving the client.
  iptables -I OUTPUT -o eth0 ! -d 127.0.0.0/8 -j NFQUEUE --queue-num 42
  ;;
esac
case "$1" in
 control|dpi)
  # strict-connect also purges intermediate RCs; enforce two first hops here.
  iptables -A OUTPUT -o eth0 -p udp -d 10.88.0.11 --dport 1090 -j ACCEPT
  iptables -A OUTPUT -o eth0 -p udp -d 10.88.0.12 --dport 1090 -j ACCEPT
  iptables -A OUTPUT -o eth0 -p udp --dport 1090 -j DROP
  ;;
 filter) iptables -A OUTPUT -o eth0 -p udp -j DROP ;;
 tunnel|dpi-tunnel)
  iptables -t nat -A OUTPUT -p udp -d 10.88.0.11 --dport 1090 -j DNAT --to-destination 127.0.0.1:2091
  iptables -t nat -A OUTPUT -p udp -d 10.88.0.12 --dport 1090 -j DNAT --to-destination 127.0.0.1:2092
  iptables -A OUTPUT -p udp -d 127.0.0.1 -m multiport --dports 2091,2092 -j ACCEPT
  if [ "$1" = tunnel ]; then
    iptables -A OUTPUT -o eth0 -p udp -j DROP
  else
    iptables -A OUTPUT -o eth0 -p udp -d 10.88.0.11 --dport 1090 -j ACCEPT
    iptables -A OUTPUT -o eth0 -p udp -d 10.88.0.12 --dport 1090 -j ACCEPT
    iptables -A OUTPUT -o eth0 -p udp --dport 1090 -j DROP
  fi
  ;;
 *) exit 2;;
esac
echo ready > /lab/run/client/firewall.ready
