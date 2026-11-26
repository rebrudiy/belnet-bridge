#!/usr/bin/env bash
set -euo pipefail

task_root=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$task_root/../../vendor/belnet" && pwd)
test -s "$task_root/bin/belnet"
cp "$task_root/bin/belnet" "$task_root/bin/belnet.unmodified"
cp "$task_root/belnet.sha256" "$task_root/belnet.unmodified.sha256"

docker run --name bb-source-build-patched --platform linux/arm64 \
  --cpus 2 --memory 1500m \
  -v "$source_root:/src:ro" -v "$task_root:/out" \
  -v "$task_root/outbound_message_handler.cpp:/src/llarp/router/outbound_message_handler.cpp:ro" \
  belnet-build:arm64 bash /out/compile.sh

BB_SOURCE_IMAGE=belnet-bridge:source-testnet-patched BB_SOURCE_EVIDENCE_PREFIX=runtime-patched bash "$task_root/package.sh"
