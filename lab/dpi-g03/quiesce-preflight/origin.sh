#!/bin/sh
set -eu
ip addr add 10.88.0.11/32 dev lo
if [ "$CASE" = ordinary ]; then
 /controls/bench-server -listen 10.88.0.11:443 -cert /work/cert/cert.pem -key /work/cert/key.pem -role diagnostic > /work/origin.log 2>&1 &
else
 BRIDGE_TOKEN=$(cat /prep/private/bridge-token); export BRIDGE_TOKEN
 /work/udp echo > /work/echo.log 2>&1 &
 /bridge udp-stream-server -listen 127.0.0.1:21992 -target 127.0.0.1:12092 > /work/framer-server.log 2>&1 &
 openssl s_server -accept 127.0.0.1:18445 -cert /prep/private/entry1.crt -key /prep/private/entry1.key -www -tls1_3 > /work/decoy.log 2>&1 &
 /mature/sing-box run -c /work/server.json > /work/server-core.log 2>&1 &
fi
touch /work/origin-started
sleep 120
