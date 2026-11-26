#!/bin/sh
set -eu
ip route add 10.88.0.11/32 via 172.30.93.3 dev eth0
/proxy -listen 127.0.0.1:8080 -control 127.0.0.1:8091 -config /work/proxy.json > /work/proxy.jsonl 2> /work/proxy-stderr.log &
echo $! > /work/proxy.pid
if [ "$CASE" = reality ]; then
 BRIDGE_TOKEN=$(cat /prep/private/bridge-token); export BRIDGE_TOKEN
 /mature/sing-box run -c /work/client.json > /work/client-core.log 2>&1 &
 /bridge udp-stream-client -listen 127.0.0.1:2093 -upstream 127.0.0.1:19093 -max-queue-age 100ms > /work/framer-client.log 2>&1 &
fi
touch /work/client-started
sleep 120
