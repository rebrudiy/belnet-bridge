#!/usr/bin/env python3
"""Generate private-lab configs. Output contains test-only credentials."""
import json
import pathlib
import secrets
import subprocess
import sys
import uuid

out = pathlib.Path(sys.argv[1]).resolve()
image = 'debian:bookworm-slim'
keys = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '-v', f'{out}/bin:/bin-mature:ro', image, '/bin-mature/sing-box', 'generate', 'reality-keypair'], text=True)
private = next(line.split(':', 1)[1].strip() for line in keys.splitlines() if line.lower().startswith('private'))
public = next(line.split(':', 1)[1].strip() for line in keys.splitlines() if line.lower().startswith('public'))
user = str(uuid.uuid4())
short = secrets.token_hex(4)
server = {
 'log': {'level': 'debug', 'timestamp': True},
 'inbounds': [{'type': 'vless', 'tag': 'belnet-only', 'listen': '0.0.0.0', 'listen_port': 19443,
  'users': [{'name': 'lab', 'uuid': user, 'flow': 'xtls-rprx-vision'}],
  'tls': {'enabled': True, 'server_name': 'decoy.test', 'reality': {'enabled': True,
   'handshake': {'server': '127.0.0.1', 'server_port': 18443},
   'private_key': private, 'short_id': [short]}}}],
 'outbounds': [{'type': 'direct', 'tag': 'local-belnet'}],
 'route': {'rules': [
  {'inbound': ['belnet-only'], 'network': 'udp', 'action': 'route',
   'override_address': '127.0.0.1', 'override_port': 1090, 'outbound': 'local-belnet'},
  {'action': 'reject'}]}}
client = {
 'log': {'level': 'debug', 'timestamp': True},
 'inbounds': [{'type': 'direct', 'tag': 'local-udp', 'listen': '127.0.0.1', 'listen_port': 19090,
  'network': 'udp', 'override_address': '127.0.0.1', 'override_port': 1090, 'udp_timeout': '5m'}],
 'outbounds': [{'type': 'vless', 'tag': 'transport', 'server': 'mature-server', 'server_port': 19443,
  'uuid': user, 'flow': 'xtls-rprx-vision', 'packet_encoding': 'xudp',
  'tls': {'enabled': True, 'server_name': 'decoy.test', 'utls': {'enabled': True, 'fingerprint': 'chrome'},
   'reality': {'enabled': True, 'public_key': public, 'short_id': short}}}],
 'route': {'final': 'transport'}}
for name, value in [('server', server), ('client', client)]:
 (out / f'{name}.json').write_text(json.dumps(value, indent=2)+'\n')
 (out / f'{name}.json').chmod(0o600)
(out / 'credentials.json').write_text(json.dumps({'uuid': user, 'public_key': public, 'short_id': short}, indent=2)+'\n')
(out / 'credentials.json').chmod(0o600)
