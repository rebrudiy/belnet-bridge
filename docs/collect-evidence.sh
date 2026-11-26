#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo 'usage: sh docs/collect-evidence.sh CONTROL_DIR DPI_DIR DPI_TUNNEL_DIR NEW_OUTPUT_DIR' >&2
  exit 2
fi

collector_repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
collector_output=$4
if [ -e "$collector_output" ]; then
  echo 'output path already exists; choose a new evidence directory' >&2
  exit 2
fi

check_run() {
  collector_mode=$1
  collector_source=$(CDPATH='' cd -- "$2" && pwd -P)
  case "$collector_source" in
    "$collector_repo"/lab/results/*) ;;
    *) echo 'source must be a directory under this repository lab/results' >&2; exit 2 ;;
  esac
  if ! rg -qx "mode=$collector_mode" "$collector_source/manifest.txt"; then
    echo "manifest does not match expected mode: $collector_mode" >&2
    exit 2
  fi
  for collector_required in manifest.txt summary.json requests.jsonl; do
    if [ ! -f "$collector_source/$collector_required" ]; then
      echo "missing $collector_mode artifact: $collector_required" >&2
      exit 2
    fi
  done
  for collector_participant in client entry1 entry2 relay1 relay2 relay3 seed service; do
    if [ ! -f "$collector_source/$collector_participant.pcap" ]; then
      echo "missing $collector_mode capture: $collector_participant" >&2
      exit 2
    fi
    if [ ! -f "$collector_source/$collector_participant-capture.log" ]; then
      echo "missing $collector_mode capture log: $collector_participant" >&2
      exit 2
    fi
  done
  case "$collector_mode" in
    control|dpi-tunnel)
      if [ ! -f "$collector_source/steady-requests.jsonl" ]; then
        echo "missing $collector_mode steady request records" >&2
        exit 2
      fi
      ;;
  esac
  case "$collector_mode" in
    dpi|dpi-tunnel)
      for collector_required in binary-sha256.txt public-identities.txt censor.log benign-udp.jsonl benign-https-status.txt; do
        if [ ! -f "$collector_source/$collector_required" ]; then
          echo "missing $collector_mode classifier/control evidence: $collector_required" >&2
          exit 2
        fi
      done
      ;;
  esac
}

check_run control "$1"
check_run dpi "$2"
check_run dpi-tunnel "$3"
mkdir -p -- "$collector_output"
collector_output=$(CDPATH='' cd -- "$collector_output" && pwd -P)

copy_run() {
  collector_mode=$1
  collector_source=$(CDPATH='' cd -- "$2" && pwd -P)
  mkdir -- "$collector_output/$collector_mode"
  for collector_artifact in \
    manifest.txt summary.json requests.jsonl steady-requests.jsonl events.jsonl \
    recovery-requests.jsonl outage-requests.jsonl binary-sha256.txt public-identities.txt \
    analysis-source-sha256.txt independent-audit.json TEARDOWN.md \
    teardown-client-entry1-transport.log teardown-client-entry2-transport.log \
    client-firewall.txt client-filter-counters.txt client-nat-counters.txt \
    benign-udp.jsonl benign-https-status.txt benign-https-body.txt censor.log \
    client.log client-entry1-transport.log client-entry2-transport.log \
    entry1.log entry2.log entry1-transport.log entry2-transport.log \
    relay1.log relay2.log relay3.log seed.log service.log service-http.log \
    client-capture.log entry1-capture.log entry2-capture.log relay1-capture.log \
    relay2-capture.log relay3-capture.log seed-capture.log service-capture.log \
    client.pcap entry1.pcap entry2.pcap relay1.pcap relay2.pcap relay3.pcap seed.pcap service.pcap; do
    if [ -f "$collector_source/$collector_artifact" ]; then
      cp -- "$collector_source/$collector_artifact" "$collector_output/$collector_mode/$collector_artifact"
    fi
  done
}

copy_run control "$1"
copy_run dpi "$2"
copy_run dpi-tunnel "$3"

{
  printf '# Evidence collection\n\n'
  printf 'Created UTC: %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Sources: `%s`, `%s`, `%s`.\n\n' "$1" "$2" "$3"
  printf 'Explicit artifact allowlist only; lab/run and key/configuration files are not copied.\n'
  printf 'This helper does not decide whether a run is final or validate its scientific claims.\n'
  printf 'Review logs and captures before distributing the bundle.\n'
} > "$collector_output/README.md"

(
  cd -- "$collector_output"
  if command -v sha256sum >/dev/null 2>&1; then
    find control dpi dpi-tunnel -type f -exec sha256sum {} \;
  else
    find control dpi dpi-tunnel -type f -exec shasum -a 256 {} \;
  fi
) > "$collector_output/SHA256SUMS"
printf 'Collected evidence: %s\n' "$collector_output"
