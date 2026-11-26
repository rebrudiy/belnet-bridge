#!/bin/sh
# Private native BelNet lab; no mainnet or real national-censor claim.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
MODE=${1:-control}
case "$MODE" in control|filter|tunnel|dpi|dpi-tunnel) ;; *) echo 'usage: ./lab/run.sh control|filter|tunnel|dpi|dpi-tunnel' >&2; exit 2;; esac
export BB_MODE=$MODE
export BB_IMAGE=${BB_IMAGE:-belnet-bridge:native}
export BB_PLATFORM=${BB_PLATFORM:-linux/amd64}
BB_CAPTURE_IMAGE=${BB_CAPTURE_IMAGE:-belnet-bridge:lab-capture}
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) CAPTURE_PLATFORM=linux/arm64 ;;
  *) CAPTURE_PLATFORM=linux/amd64 ;;
esac
if ! docker image inspect "$BB_CAPTURE_IMAGE" >/dev/null 2>&1; then
  docker build --platform "$CAPTURE_PLATFORM" -t "$BB_CAPTURE_IMAGE" -f Dockerfile.capture .
fi
if docker compose version >/dev/null 2>&1; then
  compose() { docker compose -f compose.yml "$@"; }
else
  compose() { docker-compose -f compose.yml "$@"; }
fi
mkdir -p run/certs results
chmod 700 run run/certs
if [ ! -s run/certs/entry.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 7 -keyout run/certs/ca.key \
    -out run/certs/ca.crt -subj /CN=BB-Lab-Private-CA >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -keyout run/certs/entry.key -out run/certs/entry.csr \
    -subj /CN=bb-lab-entry >/dev/null 2>&1
  cat > run/certs/entry.ext <<EXT
subjectAltName=IP:10.88.0.11,IP:10.88.0.12,DNS:entry1,DNS:entry2
extendedKeyUsage=serverAuth
EXT
  openssl x509 -req -in run/certs/entry.csr -CA run/certs/ca.crt -CAkey run/certs/ca.key \
    -CAcreateserial -days 7 -out run/certs/entry.crt -extfile run/certs/entry.ext >/dev/null 2>&1
  openssl rand -hex 32 > run/certs/token
  chmod 600 run/certs/*.key run/certs/token
fi
ARCH=${BB_PLATFORM#linux/}
GOWORK=off GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -o probe-linux ./cmd/probe
case "$MODE" in
 dpi|dpi-tunnel)
  CAPTURE_ARCH=${CAPTURE_PLATFORM#linux/}
  GOWORK=off GOOS=linux GOARCH=$CAPTURE_ARCH CGO_ENABLED=0 go build -o iwp-censor-linux ../cmd/iwp-censor
  ;;
esac
for node in seed entry1 entry2 relay1 relay2 relay3 client service; do
  docker rm -f "bb-lab-capture-$node" >/dev/null 2>&1 || true
done
docker rm -f bb-lab-censor >/dev/null 2>&1 || true
compose stop client service
rm -f run/client/firewall.ready run/client/censor.ready
rm -f run/client/profiles.dat run/service/profiles.dat
# Two phases generate signed relay fixtures, then start the full private topology.
compose up -d seed entry1 entry2 relay1 relay2 relay3
n=0
while :; do
  ready=yes
  for peer in seed entry1 entry2 relay1 relay2 relay3; do
    [ -s "run/$peer/self.signed" ] || ready=no
  done
  [ "$ready" = yes ] && break
  n=$((n+1)); [ "$n" -lt 90 ] || { echo 'relay fixture startup timed out' >&2; exit 1; }
  sleep 1
done
mkdir -p run/fixtures
for peer in seed entry1 entry2 relay1 relay2 relay3; do
  mkdir -p "run/fixtures/$peer"
  cp "run/$peer/self.signed" "run/fixtures/$peer/self.signed"
done
echo ready > run/fixtures/ready
: > run/public-identities.txt
for peer in seed entry1 entry2 relay1 relay2 relay3; do
  GOWORK=off go run ./cmd/probe rc-key "run/fixtures/$peer/self.signed" >> run/public-identities.txt
done
compose up -d --force-recreate seed entry1 entry2 relay1 relay2 relay3
compose up -d --force-recreate client service
case "$MODE" in
 dpi|dpi-tunnel)
  docker run -d --platform "$CAPTURE_PLATFORM" --name bb-lab-censor \
    --network container:bb-lab-client-1 --cap-add NET_ADMIN -v "$PWD:/lab" \
    --entrypoint /lab/iwp-censor-linux "$BB_CAPTURE_IMAGE" \
    -queue 42 -identities /lab/run/public-identities.txt -ready-file /lab/run/client/censor.ready >/dev/null
  n=0
  while [ ! -s run/client/censor.ready ]; do
    n=$((n+1)); [ "$n" -lt 20 ] || { docker logs bb-lab-censor; exit 1; }
    sleep 1
  done
  ;;
esac
docker run --rm --platform "$CAPTURE_PLATFORM" --network container:bb-lab-client-1 \
  --cap-add NET_ADMIN -v "$PWD:/lab" --entrypoint /bin/sh "$BB_CAPTURE_IMAGE" /lab/firewall.sh "$MODE"
for node in seed entry1 entry2 relay1 relay2 relay3 client service; do
  docker run -d --platform "$CAPTURE_PLATFORM" --name "bb-lab-capture-$node" \
    --network "container:bb-lab-$node-1" --cap-add NET_RAW --cap-add NET_ADMIN \
    -v "$PWD/run/$node:/capture" --entrypoint tcpdump "$BB_CAPTURE_IMAGE" \
    -U -i eth0 -w /capture/eth0.pcap >/dev/null
done
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="results/$STAMP-$MODE"
mkdir -p "$OUT"
printf 'mode=%s\nimage=%s\nplatform=%s\nstarted=%s\nnetid=bb-lab\nhops=3\nnetwork=private-lab-no-mainnet\n' "$MODE" "$BB_IMAGE" "$BB_PLATFORM" "$STAMP" > "$OUT/manifest.txt"
docker image inspect "$BB_IMAGE" --format '{{.Id}}' >> "$OUT/manifest.txt"
docker exec bb-lab-client-1 belnet --version >> "$OUT/manifest.txt" 2>&1 || true
docker exec bb-lab-client-1 sha256sum /usr/local/bin/belnet /usr/local/bin/belnet-bridge /lab/probe-linux > "$OUT/binary-sha256.txt"
case "$MODE" in
 dpi|dpi-tunnel)
  docker exec bb-lab-client-1 sha256sum /lab/iwp-censor-linux >> "$OUT/binary-sha256.txt"
  ;;
esac
cp run/public-identities.txt "$OUT/public-identities.txt"
case "$MODE" in
 dpi|dpi-tunnel)
  docker exec bb-lab-client-1 /lab/probe-linux udp-check 10.88.0.11:1099 > "$OUT/benign-udp.jsonl"
  docker exec bb-lab-client-1 curl --silent --show-error --cacert /lab/run/certs/ca.crt \
    --output /lab/run/client/benign-https-body.txt --write-out '%{http_code}\n' https://10.88.0.11/ws > "$OUT/benign-https-status.txt"
  cp run/client/benign-https-body.txt "$OUT/benign-https-body.txt"
  ;;
esac
# Blocked control has a finite failure window. Healthy cases retry while native paths warm.
if [ "$MODE" = filter ] || [ "$MODE" = dpi ]; then ATTEMPTS=3; else ATTEMPTS=${BB_ATTEMPTS:-24}; fi
ok=no
attempt=0
while [ "$attempt" -lt "$ATTEMPTS" ]; do
  attempt=$((attempt+1))
  ADDRESS=$(docker exec bb-lab-service-1 dig @127.3.2.1 localhost.bdx CNAME +short 2>/dev/null | tr -d '\r' | rg '^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}\.bdx\.$' | head -n 1 | sed 's/\.$//')
  if [ -n "$ADDRESS" ]; then
    if docker exec bb-lab-client-1 /lab/probe-linux fetch "http://$ADDRESS:8080" >> "$OUT/requests.jsonl" 2>&1; then
      ok=yes
      break
    fi
  fi
  sleep 2
done
# Measure a small fixed workload after the first successful response.
if [ "$ok" = yes ]; then
  sample=0
  while [ "$sample" -lt "${BB_SAMPLES:-10}" ]; do
    sample=$((sample+1))
    docker exec bb-lab-client-1 /lab/probe-linux fetch "http://$ADDRESS:8080" >> "$OUT/steady-requests.jsonl" 2>&1 || true
    sleep 1
  done
fi
if [ "$ok" = yes ] && { [ "$MODE" = tunnel ] || [ "$MODE" = dpi-tunnel ]; } && [ "${BB_RECOVERY:-1}" = 1 ]; then
  ./recovery.sh "$OUT" "$ADDRESS"
fi
case "$MODE" in
 dpi|dpi-tunnel)
  docker stop -t 3 bb-lab-censor >/dev/null
  docker logs bb-lab-censor > "$OUT/censor.log" 2>&1
  ;;
esac
# Native capture helpers share each existing node's namespace; they route no traffic.
for node in seed entry1 entry2 relay1 relay2 relay3 client service; do
  docker stop -t 3 "bb-lab-capture-$node" >/dev/null
  docker logs "bb-lab-capture-$node" > "$OUT/$node-capture.log" 2>&1
  docker logs "bb-lab-$node-1" > "$OUT/$node.log" 2>&1
  cp "run/$node/eth0.pcap" "$OUT/$node.pcap"
done
docker run --rm --platform "$CAPTURE_PLATFORM" --network container:bb-lab-client-1 \
  --cap-add NET_ADMIN --entrypoint iptables-save "$BB_CAPTURE_IMAGE" > "$OUT/client-firewall.txt"
docker run --rm --platform "$CAPTURE_PLATFORM" --network container:bb-lab-client-1 \
  --cap-add NET_ADMIN --entrypoint iptables "$BB_CAPTURE_IMAGE" -t nat -nvL OUTPUT > "$OUT/client-nat-counters.txt"
docker run --rm --platform "$CAPTURE_PLATFORM" --network container:bb-lab-client-1 \
  --cap-add NET_ADMIN --entrypoint iptables "$BB_CAPTURE_IMAGE" -nvL OUTPUT > "$OUT/client-filter-counters.txt"
cp run/service/http.log "$OUT/service-http.log"
for node in client entry1 entry2; do
  for file in run/$node/*transport.log; do [ ! -f "$file" ] || cp "$file" "$OUT/$node-$(basename "$file")"; done
done
printf 'http_ok=%s\nattempts=%s\n' "$ok" "$attempt" >> "$OUT/manifest.txt"
GOWORK=off go run ./cmd/probe report "$OUT" > "$OUT/summary.json"
printf 'Artifacts: %s/%s\nHTTP proof: %s\n' "$PWD" "$OUT" "$ok"
if [ "$MODE" = filter ] || [ "$MODE" = dpi ]; then
  [ "$ok" = no ] || { echo 'Unexpected filter bypass' >&2; exit 1; }
else
  [ "$ok" = yes ] || exit 1
fi
