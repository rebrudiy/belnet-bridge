#!/usr/bin/env bash
# Censored client: everything except TLS to the bridge is dropped on eth0
# (a crude stand-in for DPI that blocks BelNet's UDP), then BelNet runs
# through the bridge.
set -euo pipefail
: "${BRIDGE_IP:?}" "${BRIDGE_TOKEN:?}"
GW=$(ip route | awk '/^default/ {print $3}')

if [ "${CENSOR:-1}" = 1 ]; then
  iptables -A OUTPUT -o eth0 -p tcp -d "$BRIDGE_IP" --dport 443 -j ACCEPT
  iptables -A OUTPUT -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -o eth0 -j DROP
  echo "censor: only TCP $BRIDGE_IP:443 allowed out of eth0"
fi

ip tuntap add dev bb0 mode tun
ip link set bb0 up mtu 1400
belnet-bridge client -url "wss://$BRIDGE_IP/ws" -insecure -tun bb0 -addr-file /run/bb.addr &
for _ in $(seq 1 30); do [ -s /run/bb.addr ] && break; sleep 1; done
read -r ADDR TUNGW < /run/bb.addr
ip addr add "$ADDR" dev bb0
ip route add "$BRIDGE_IP" via "$GW" dev eth0 2>/dev/null || true
ip route replace default via "$TUNGW" dev bb0
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "tunnel up: $ADDR via $TUNGW"

curl -fsS -m 10 -o /dev/null -w "internet via bridge: HTTP %{http_code}\n" https://github.com || echo "internet via bridge: FAILED"

if [ "${RUN_BELNET:-1}" = 1 ]; then
  belnet -g >/dev/null 2>&1 || true
  belnet-bootstrap || echo "belnet-bootstrap failed"
  exec belnet
fi
wait
