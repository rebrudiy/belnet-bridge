#!/bin/sh
set -eu
ip addr add 10.88.0.11/32 dev lo
BRIDGE_TOKEN=$(cat /prep/private/bridge-token); export BRIDGE_TOKEN
openssl s_server -accept 127.0.0.1:18445 -cert /prep/private/entry1.crt -key /prep/private/entry1.key -www -tls1_3 > /work/decoy.log 2>&1 &
/work/bin/check echo > /work/echo.jsonl 2>&1 &
/work/bin/connect-proxy -listen 127.0.0.1:8080 -config /work/private/proxy.json > /work/proxy.jsonl 2> /work/proxy-stderr.log &
proxy=$!
/bridge udp-stream-server -listen 127.0.0.1:21992 -target 127.0.0.1:12092 -lab-control 127.0.0.1:2293 > /work/server.log 2>&1 &
echo $! > /work/server.pid
/bridge udp-stream-client -listen 127.0.0.1:2093 -upstream 127.0.0.1:19093 -max-queue-age 100ms -lab-control 127.0.0.1:2193 > /work/client.log 2>&1 &
echo $! > /work/client.pid
BRIDGE_TOKEN="preflight-invalid-$BRIDGE_TOKEN" /bridge udp-stream-client -listen 127.0.0.1:2094 -upstream 127.0.0.1:19093 -max-queue-age 100ms > /work/bad-client.log 2>&1 &
/bridge udp-stream-client -listen 127.0.0.1:2095 -upstream 127.0.0.1:19094 -max-queue-age 100ms > /work/forbidden-client.log 2>&1 &
/mature/sing-box run -c /work/private/server.json > /work/server-core.log 2>&1 &
/mature/sing-box run -c /work/private/client.json > /work/client-core.log 2>&1 &
core=$!
tcpdump -U -i lo -s 0 -w /work/outer.pcap tcp port 19445 > /work/capture.log 2>&1 &
capture=$!
i=0
while ! grep -q 'listening on lo' /work/capture.log; do
 i=$((i+1)); if [ "$i" -ge 30 ]; then echo 'capture-not-ready' >&2; exit 2; fi
 sleep 0.1
done
set +e
/work/bin/check probe > /work/probe-stdout.json 2> /work/probe-stderr.log
status=$?
kill -TERM "$core" 2>/dev/null
wait "$core"
kill -TERM "$proxy" 2>/dev/null
wait "$proxy"
kill -INT "$capture" 2>/dev/null
wait "$capture"
exit "$status"
