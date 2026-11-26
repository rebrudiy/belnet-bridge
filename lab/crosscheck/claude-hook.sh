#!/bin/sh
set -eu
ip addr replace "$ADDR" dev bb0
ip link set bb0 up mtu "$MTU"
for peer in 10.88.0.10 10.88.0.11 10.88.0.12 10.88.0.13 10.88.0.14 10.88.0.15; do ip route replace "$peer/32" via "$GW" dev bb0; done
