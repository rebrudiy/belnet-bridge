#!/bin/sh
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
OUT="$REPO/out/dpi-v2/mature"
VERSION=1.14.4
ARCHIVE="sing-box-$VERSION-linux-arm64.tar.gz"
EXPECTED=436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26
mkdir -p "$OUT/bin"
if [ ! -f "$OUT/$ARCHIVE" ] || [ "$(shasum -a 256 "$OUT/$ARCHIVE" | cut -d ' ' -f 1)" != "$EXPECTED" ]; then
 curl -4 -fsSL --retry 2 --connect-timeout 15 --max-time 180 "https://github.com/SagerNet/sing-box/releases/download/v$VERSION/$ARCHIVE" -o "$OUT/$ARCHIVE"
fi
[ "$(shasum -a 256 "$OUT/$ARCHIVE" | cut -d ' ' -f 1)" = "$EXPECTED" ]
tar -xzf "$OUT/$ARCHIVE" -C "$OUT/bin" --strip-components=1
cd "$REPO"
go run lab/dpi-v2/mature/probe.go cert "$OUT"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$OUT/bin/probe" lab/dpi-v2/mature/probe.go
python3 lab/dpi-v2/mature/make-configs.py "$OUT"
