#!/bin/sh
set -eu
ip route add 10.88.0.11/32 via 10.179.61.11
exec tail -f /dev/null
