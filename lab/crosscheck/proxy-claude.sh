#!/bin/sh
set -eu
data=/lab/crosscheck/run/claude-client
BRIDGE_TOKEN=$(cat /lab/run/certs/token);export BRIDGE_TOKEN
pin=$(openssl x509 -in /lab/run/certs/entry.crt -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -binary | openssl base64 -A)
/lab/crosscheck/bin/claude-transport client -url wss://10.88.0.50/ws -tun bb0 -mtu 1500 -pad -utls -sni entry1 -pin "$pin" -session-file "$data/session" -addr-file "$data/addr" -on-connect "/bin/sh /lab/crosscheck/claude-hook.sh" >> "$data/transport.log" 2>&1 &
echo $! > "$data/transport.pid"
