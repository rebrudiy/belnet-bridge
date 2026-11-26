#!/bin/sh
set -eu
ip addr add 10.88.0.11/32 dev lo
exec /work/bin/helper serve -private /work/private -ready /work/server-ready.json
