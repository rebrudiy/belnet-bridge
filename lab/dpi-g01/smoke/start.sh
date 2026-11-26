#!/bin/sh
set -eu
BRIDGE_TOKEN=$(cat /prep/private/bridge-token); export BRIDGE_TOKEN
openssl s_server -accept 127.0.0.1:18444 -cert /prep/private/entry1.crt -key /prep/private/entry1.key -www -tls1_3 > /work/decoy.log 2>&1 &
/work/bin/check echo > /work/echo.jsonl 2>&1 &
/bridge udp-stream-server -listen 127.0.0.1:21990 -target 127.0.0.1:12090 -lab-control 127.0.0.1:2291 > /work/server.log 2>&1 &
echo $! > /work/server.pid
/bridge udp-stream-client -listen 127.0.0.1:2091 -upstream 127.0.0.1:19091 -lab-control 127.0.0.1:2191 > /work/client.log 2>&1 &
echo $! > /work/client.pid
BRIDGE_TOKEN="smoke-invalid-$BRIDGE_TOKEN" /bridge udp-stream-client -listen 127.0.0.1:2092 -upstream 127.0.0.1:19091 -lab-control 127.0.0.1:2192 > /work/bad-client.log 2>&1 &
echo $! > /work/bad.pid
/mature/sing-box run -c /work/private/server.json > /work/server-core.log 2>&1 &
tcpdump -U -i lo -w /work/outer.pcap tcp port 19444 > /work/capture.log 2>&1 &
capture=$!
i=0
while ! grep -q 'listening on lo' /work/capture.log; do
 i=$((i+1)); if [ "$i" -ge 50 ]; then break; fi
 sleep 0.1
done
sleep 0.4
set +e
/work/bin/check probe > /work/probe-stdout.json 2> /work/probe-stderr.log
status=$?
kill -INT "$capture" 2>/dev/null
wait "$capture"
exit "$status"
