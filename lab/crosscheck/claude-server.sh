#!/bin/sh
set -eu
ip tuntap add dev bb0 mode tun
ip addr add 10.77.0.1/24 dev bb0
ip link set bb0 up mtu 1500
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE
BRIDGE_TOKEN=$(cat /lab/run/certs/token);export BRIDGE_TOKEN
export BB_CROSS_MODEL=/lab/crosscheck/run/final-attacker.json
export BB_CROSS_OUTPUT=/lab/crosscheck/run/claude-server/decisions.jsonl
export BB_CROSS_TRIAL_FILE=/lab/crosscheck/run/claude-trial.json
mkdir -p /lab/crosscheck/run/claude-server
exec /lab/crosscheck/bin/claude-transport server -listen :443 -cert /lab/run/certs/entry.crt -key /lab/run/certs/entry.key -tun bb0 -mtu 1500 -pad -egress-allow 10.88.0.0/24 -lease-file /lab/crosscheck/run/claude-server/leases.json > /lab/crosscheck/run/claude-server/transport.log 2>&1
