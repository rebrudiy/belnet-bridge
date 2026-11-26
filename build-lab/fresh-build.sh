#!/usr/bin/env bash
set -euo pipefail
umask 077

task_root=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$task_root/.." && pwd)
variant=${1:-unmodified}
if [ "$#" -gt 1 ]; then echo 'usage: fresh-build.sh [unmodified|queuefix]' >&2; exit 2; fi
case "$variant" in unmodified|queuefix) ;; *) echo 'variant must be unmodified or queuefix' >&2; exit 2;; esac
for tool in docker git go awk patch; do command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }; done
hash_file() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}
source_root=$(cd "${BB_SOURCE_DIR:-$task_root/../../vendor/belnet}" && pwd)
test "$(git -C "$source_root" rev-parse HEAD)" = 480aafb3c68ac359f0711b2cbd8a07be661703c0
test -z "$(git -C "$source_root" status --porcelain)" || { echo 'BelNet checkout must be clean' >&2; exit 1; }
git -C "$source_root" submodule status --recursive | awk 'substr($0,1,1) != " " {bad=1} END {exit bad}'

mkdir -p "$task_root/reproductions"
out=$(mktemp -d "$task_root/reproductions/$(date -u +%Y%m%dT%H%M%SZ)-$variant.XXXXXX")
run_id=$(basename "$out")
builder_image="belnet-build:repro-$run_id"
runtime_image=${BB_FRESH_IMAGE:-belnet-bridge:repro-$run_id}
container_name="bb-source-repro-$run_id"
for image_tag in "$builder_image" "$runtime_image"; do
  if docker image inspect "$image_tag" >/dev/null 2>&1; then
    echo "Refusing to overwrite existing image $image_tag" >&2; exit 1
  fi
done
memory=${BB_FRESH_MEMORY:-1500m}
cpus=${BB_FRESH_CPUS:-1}
printf 'Output: %s\nRuntime image: %s\n' "$out" "$runtime_image"
printf 'variant=%s\nplatform=linux/arm64\ntestnet=ON\nmemory=%s\ncpus=%s\nextra_swap=0\n' "$variant" "$memory" "$cpus" > "$out/manifest.txt"
git -C "$source_root" rev-parse HEAD > "$out/source.commit"
git -C "$source_root" status --porcelain > "$out/base-source.status"
git -C "$source_root" submodule status --recursive > "$out/source.submodules"
cp "$task_root/Dockerfile.builder" "$task_root/Dockerfile.runtime" "$task_root/.dockerignore" "$out/"
cp "$task_root/compile-fresh.sh" "$task_root/endpoint-flags.awk" "$out/"

set --
if [ "$variant" = queuefix ]; then
  patch_hash=$(hash_file "$task_root/queue-wakeup.patch" | awk '{print $1}')
  test "$patch_hash" = 83f1339d42e96c30d814a29ec8505c4d3285a5bddf46266a2b0a3d728623bfe6
  mkdir -p "$out/overlay/llarp/router"
  cp "$source_root/llarp/router/outbound_message_handler.cpp" "$out/overlay/llarp/router/"
  patch -t -p1 -d "$out/overlay" < "$task_root/queue-wakeup.patch" > "$out/patch.log"
  cp "$task_root/queue-wakeup.patch" "$out/"
  printf 'patch_sha256=%s\n' "$patch_hash" >> "$out/manifest.txt"
  set -- -v "$out/overlay/llarp/router/outbound_message_handler.cpp:/src/llarp/router/outbound_message_handler.cpp:ro"
fi

mkdir -p "$out/bin"
(cd "$repo_root"; GOWORK=off GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$out/bin/belnet-bridge" .)
go version -m "$out/bin/belnet-bridge" > "$out/transport-build-info.txt"
docker build --platform linux/arm64 -t "$builder_image" -f "$out/Dockerfile.builder" "$out" > "$out/builder.log" 2>&1
docker image inspect "$builder_image" --format '{{.Id}} {{.Os}}/{{.Architecture}}' > "$out/builder-image.txt"
docker run --name "$container_name" --platform linux/arm64 --cpus "$cpus" \
  --memory "$memory" --memory-swap "$memory" --network none \
  -e "BB_SOURCE_VARIANT=$variant" \
  -v "$source_root:/src:ro" -v "$out:/out" -v "$out:/recipe:ro" \
  "$@" "$builder_image" bash /recipe/compile-fresh.sh > "$out/build.log" 2>&1
docker inspect "$container_name" > "$out/build-container.json"
if docker image inspect "$runtime_image" >/dev/null 2>&1; then
  echo "Refusing to overwrite existing image $runtime_image" >&2; exit 1
fi
docker build --platform linux/arm64 --build-arg "BUILDER_IMAGE=$builder_image" \
  -t "$runtime_image" -f "$out/Dockerfile.runtime" "$out" > "$out/package.log" 2>&1
docker image inspect "$runtime_image" --format '{{.Id}} {{.Os}}/{{.Architecture}}' > "$out/runtime-image.txt"
docker run --rm --platform linux/arm64 --network none --entrypoint /bin/bash "$runtime_image" -c '
  set -eu
  uname -m
  belnet --version
  sha256sum /usr/local/bin/belnet /usr/local/bin/belnet-bridge
  ldd /usr/local/bin/belnet
  for tool in dig openssl ip iptables tcpdump curl; do command -v "$tool"; done
' > "$out/runtime-validation.txt" 2>&1
if awk '/not found/ {bad=1} END {exit bad}' "$out/runtime-validation.txt"; then
  printf 'build_complete=yes\n' >> "$out/manifest.txt"
else
  echo 'Unresolved runtime dependency; see runtime-validation.txt' >&2; exit 1
fi
printf 'Built %s\nEvidence: %s\n' "$runtime_image" "$out"
