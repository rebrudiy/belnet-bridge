#!/usr/bin/env bash
# Bridge server: TUN + NAT, self-signed TLS, cover website on every other path.
set -euo pipefail
ip tuntap add dev bb0 mode tun
ip addr add 10.77.0.1/24 dev bb0
ip link set bb0 up mtu 1400
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=bridge.example" \
  -keyout /tmp/key.pem -out /tmp/cert.pem 2>/dev/null
exec belnet-bridge server -listen :443 -cert /tmp/cert.pem -key /tmp/key.pem -tun bb0
