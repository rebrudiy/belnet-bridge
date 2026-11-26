#!/usr/bin/env python3
"""Isolated functional baseline; no real BelNet or censorship claim."""
import copy
import base64
import json
import pathlib
import secrets
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = ROOT / 'out/dpi-v2/mature'
SUFFIX = str(time.time_ns())
NETWORK = 'mature-' + SUFFIX
SERVER = NETWORK + '-server'
CLIENT = NETWORK + '-client'
CAPTURE = NETWORK + '-capture'
IMAGE = 'debian:bookworm-slim'
created = []


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=60).stdout.strip()


def probe(sizes=None):
    args = ['docker', 'exec']
    if sizes:
        args += ['-e', 'MATURE_PROBE_SIZES=' + sizes]
    args += [CLIENT, '/work/bin/probe', 'probe', '127.0.0.1:19090', '21900']
    return json.loads(run(*args))


def restart_with(config):
    (OUT / 'client.json').write_text(json.dumps(config, indent=2) + '\n')
    run('docker', 'restart', CLIENT)
    time.sleep(0.5)


try:
    (OUT / 'echo.jsonl').write_text('')
    run('docker', 'network', 'create', '--internal', NETWORK)
    run('docker', 'run', '-d', '--name', SERVER, '--network', NETWORK,
        '--network-alias', 'mature-server', '-v', f'{OUT}:/work', IMAGE, 'sh', '-c',
        '/work/bin/probe serve > /work/decoy.log 2>&1 & exec /work/bin/sing-box run -c /work/server.json')
    created.append(SERVER)
    address = json.loads(run('docker', 'inspect', SERVER))[0]['NetworkSettings']['Networks'][NETWORK]['IPAddress']
    config = json.loads((OUT / 'client.json').read_text())
    config['outbounds'][0]['server'] = address
    (OUT / 'client.json').write_text(json.dumps(config, indent=2) + '\n')
    run('docker', 'run', '-d', '--name', CLIENT, '--network', NETWORK, '-v', f'{OUT}:/work',
        IMAGE, '/work/bin/sing-box', 'run', '-c', '/work/client.json')
    created.append(CLIENT)
    time.sleep(0.7)
    capture = subprocess.run(['docker', 'run', '-d', '--name', CAPTURE,
        '--network', 'container:' + CLIENT, '-v', f'{OUT}:/work', 'belnet-bridge:evolution-refactored',
        'tcpdump', '-U', '-i', 'eth0', '-w', '/work/transport.pcap', 'tcp', 'port', '19443'],
        text=True, capture_output=True, timeout=30)
    if capture.returncode == 0:
        created.append(CAPTURE)
        time.sleep(0.3)
    report = {'transport': 'sing-box 1.14.4 VLESS/REALITY/Vision/XUDP', 'server_ip': address,
              'isolated_network': NETWORK, 'real_belnet': False, 'censorship_test': False}
    report['initial'] = probe()
    if CAPTURE in created:
        # Let libpcap's capture-buffer timeout drain before signalling tcpdump.
        time.sleep(1.2)
        run('docker', 'stop', '--signal', 'SIGINT', CAPTURE, check=False)
    peers_before = [json.loads(line)['peer'] for line in (OUT / 'echo.jsonl').read_text().splitlines()]
    restart_with(config)
    report['after_client_restart_same_local_source'] = probe('128')
    peers_after = [json.loads(line)['peer'] for line in (OUT / 'echo.jsonl').read_text().splitlines()]
    report['native_udp_source_before'] = peers_before[-1] if peers_before else None
    report['native_udp_source_after'] = peers_after[-1] if peers_after else None
    report['native_udp_source_preserved'] = report['native_udp_source_before'] == report['native_udp_source_after']
    redirected = copy.deepcopy(config)
    redirected['inbounds'][0]['override_address'] = '192.0.2.123'
    redirected['inbounds'][0]['override_port'] = 5555
    restart_with(redirected)
    report['arbitrary_udp_destination_forced_to_local_1090'] = probe('128')
    bad = copy.deepcopy(config)
    bad['outbounds'][0]['uuid'] = '00000000-0000-4000-8000-000000000000'
    restart_with(bad)
    report['wrong_uuid'] = probe('128')
    bad = copy.deepcopy(config)
    bad['outbounds'][0]['tls']['reality']['short_id'] = 'deadbeef'
    restart_with(bad)
    report['wrong_reality_short_id'] = probe('128')
    bad = copy.deepcopy(config)
    bad['outbounds'][0]['tls']['reality']['public_key'] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
    restart_with(bad)
    report['wrong_server_public_key'] = probe('128')
    restart_with(config)
    report['restored'] = probe('128')
    (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
finally:
    for name in created:
        logs = subprocess.run(['docker', 'logs', name], capture_output=True, text=True, timeout=30)
        (OUT / (name.rsplit('-', 1)[-1] + '.log')).write_text(logs.stdout + logs.stderr)
    for name in reversed(created):
        run('docker', 'rm', '-f', name, check=False)
    run('docker', 'network', 'rm', NETWORK, check=False)
    archive = OUT / 'runs' / SUFFIX
    archive.mkdir(parents=True, exist_ok=True)
    for path in OUT.iterdir():
        if path.is_file() and path.suffix in ('.json', '.jsonl', '.log', '.pcap'):
            shutil.copy2(path, archive / path.name)
