#!/usr/bin/env bash
set -euo pipefail

task_root=$(cd "$(dirname "$0")" && pwd)
image_tag=${BB_SOURCE_IMAGE:-belnet-bridge:source-testnet}
evidence_prefix=${BB_SOURCE_EVIDENCE_PREFIX:-runtime}
test -s "$task_root/bin/belnet"
test -s "$task_root/bin/belnet-bridge"
mkdir -p "$task_root/lib"
find "$task_root/cmake/external" \( -type f -o -type l \) -name '*.so*' -exec cp -a {} "$task_root/lib/" \;
docker build --platform linux/arm64 -t "$image_tag" -f "$task_root/Dockerfile.runtime" "$task_root"
docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' "$image_tag" > "$task_root/$evidence_prefix-image.txt"
docker run --rm --platform linux/arm64 "$image_tag" belnet --version > "$task_root/$evidence_prefix-version.txt"
docker run --rm --platform linux/arm64 "$image_tag" belnet-bridge udp-client -help > "$task_root/$evidence_prefix-transport-help.txt" 2>&1 || test "$?" = 1
