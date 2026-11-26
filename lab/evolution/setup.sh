#!/bin/sh
# Starts only the private BelNet experiment; never touches the host firewall.
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
LAB=$(CDPATH='' cd .. && pwd)
CAPTURE_IMAGE=${BB_CAPTURE_IMAGE:-belnet-bridge:lab-capture}
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) CAPTURE_PLATFORM=linux/arm64; HELPER_ARCH=arm64 ;;
  *) CAPTURE_PLATFORM=linux/amd64; HELPER_ARCH=amd64 ;;
esac
HELPER_ARCH=${BB_GOARCH:-$HELPER_ARCH}
if ! docker image inspect "$CAPTURE_IMAGE" >/dev/null 2>&1; then
  docker build --platform "$CAPTURE_PLATFORM" -t "$CAPTURE_IMAGE" - < "$LAB/Dockerfile.capture"
fi
if docker compose version >/dev/null 2>&1; then
  base() { docker compose -f "$LAB/compose.yml" "$@"; }
  evolve() { docker compose -f compose.yml "$@"; }
else
  base() { docker-compose -f "$LAB/compose.yml" "$@"; }
  evolve() { docker-compose -f compose.yml "$@"; }
fi
mkdir -p run results
chmod 700 run
GOWORK=off GOOS=linux GOARCH=$HELPER_ARCH CGO_ENABLED=0 go build -o evo-probe-linux ./cmd/probe
# The ordinary lab prepares its private CA and relay fixtures on first use.
if [ ! -s "$LAB/run/certs/token" ] || [ ! -s "$LAB/run/fixtures/ready" ]; then
  echo 'Run ./lab/run.sh control once to prepare the private CA and signed relay fixtures.' >&2
  exit 1
fi
evolve stop >/dev/null 2>&1 || true
base stop service >/dev/null 2>&1 || true
python3 - <<'PY'
from pathlib import Path
from datetime import datetime,timezone
root=Path('run');archive=root/'archive'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
for name in ('train','validation','test','service'):
    p=root/name
    if p.exists():
        archive.mkdir(parents=True,exist_ok=True)
        p.rename(archive/name)
PY
rm -f "$LAB/run/service/profiles.dat"
base up -d --force-recreate seed entry1 entry2 relay1 relay2 relay3
# On this private release the mesh can take over a minute to establish. Start
# clients only after all six relays have observed links with the other five.
mesh_ready=no
for attempt in $(seq 1 180); do
  mesh_ready=yes
  for peer in seed entry1 entry2 relay1 relay2 relay3; do
    count=$(docker logs "bb-lab-$peer-1" 2>&1 | sed -n 's/.*session with router \[\([^]]*\)\].*/\1/p' | sort -u | wc -l | tr -d ' ')
    [ "$count" -ge 5 ] || mesh_ready=no
  done
  [ "$mesh_ready" = yes ] && break
  if [ $((attempt % 15)) -eq 0 ]; then echo "Waiting for the native relay mesh: ${attempt}s"; fi
  sleep 1
done
[ "$mesh_ready" = yes ] || { echo 'native relay mesh did not become ready' >&2; exit 1; }
base up -d --force-recreate service
for n in 1 2; do
  ready=no
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if docker exec "bb-lab-entry$n-1" /bin/sh -c 'curl --silent --fail --max-time 1 --cacert /lab/run/certs/ca.crt "https://$NODE_IP/ws" >/dev/null'; then ready=yes; break; fi
    sleep 1
  done
  [ "$ready" = yes ] || { echo "entry$n transport failed to start" >&2; exit 1; }
  docker exec "bb-lab-entry$n-1" /bin/sh -c 'kill -TERM "$(cat /lab/run/$NODE/transport.pid)"'
  sleep 1
  docker exec -d "bb-lab-entry$n-1" /bin/sh -c '
    BRIDGE_TOKEN=$(cat /lab/run/certs/token); export BRIDGE_TOKEN
    exec belnet-bridge udp-server -listen :443 -target "$NODE_IP:1090" \
      -cert /lab/run/certs/entry.crt -key /lab/run/certs/entry.key \
      -lab-control 127.0.0.1:2290 > /lab/run/$NODE/evolution-transport.log 2>&1
  '
  ready=no
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if docker exec "bb-lab-entry$n-1" /lab/evolution/evo-probe-linux admin GET http://127.0.0.1:2290/decisions >/dev/null 2>&1; then ready=yes; break; fi
    sleep 1
  done
  [ "$ready" = yes ] || { echo "entry$n lab control failed to start" >&2; exit 1; }
done
docker exec -d bb-lab-service-1 /bin/sh -c 'exec /lab/evolution/evo-probe-linux serve > /lab/evolution/run/service-http.log 2>&1'
for node in train validation test; do
  mkdir -p "run/$node"
  rm -f "run/$node/firewall.ready" "run/$node/start.ready" "run/$node/profiles.dat"
  docker rm -f "bb-evolution-capture-$node" >/dev/null 2>&1 || true
done
evolve up -d --force-recreate
for node in train validation test; do
  docker run --rm --platform "$CAPTURE_PLATFORM" --network "container:bb-evolution-$node-1" \
    --cap-add NET_ADMIN -v "$LAB:/lab" --entrypoint /bin/sh "$CAPTURE_IMAGE" /lab/evolution/firewall.sh "$node"
  docker run -d --platform "$CAPTURE_PLATFORM" --name "bb-evolution-capture-$node" \
    --network "container:bb-evolution-$node-1" --cap-add NET_RAW --cap-add NET_ADMIN \
    -v "$PWD/run/$node:/capture" --entrypoint tcpdump "$CAPTURE_IMAGE" \
    -U -i eth0 -w /capture/wire.pcap >/dev/null
done
echo 'Evolution clients started; use the experiment driver to warm real paths and collect trials.'
