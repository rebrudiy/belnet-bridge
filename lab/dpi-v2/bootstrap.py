#!/usr/bin/env python3
"""Start only the authorized isolated native testnet; never touches host routes."""
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / 'lab'
ENV = dict(os.environ, BB_IMAGE='belnet-bridge:dpi-v2', BB_PLATFORM='linux/arm64')

def call(args):
    p = subprocess.run(args, cwd=ROOT, env=ENV, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(p.stderr)
    return p.stdout

def main():
    relays = ['seed', 'entry1', 'entry2', 'relay1', 'relay2', 'relay3']
    run = LAB/'dpi-v2/run'; run.mkdir(parents=True,exist_ok=True)
    if (run/'client').exists():
        raise RuntimeError('Refusing to overwrite an existing run/client; archive first')
    call(['docker-compose','-f','lab/compose.yml','up','-d',*relays])
    time.sleep(5)
    for node in relays:
        (LAB/'run/fixtures'/node).mkdir(parents=True,exist_ok=True)
        shutil.copyfile(LAB/'run'/node/'self.signed',LAB/'run/fixtures'/node/'self.signed')
    call(['docker-compose','-f','lab/compose.yml','restart',*relays])
    time.sleep(5)
    for node in ['entry1','entry2']:
        address={'entry1':'10.88.0.11','entry2':'10.88.0.12'}[node]
        script='kill -TERM "$(cat /lab/run/'+node+'/transport.pid)"; BRIDGE_TOKEN=$(cat /lab/run/certs/token); export BRIDGE_TOKEN; exec belnet-bridge udp-server -listen :443 -target '+address+':1090 -cert /lab/run/certs/entry.crt -key /lab/run/certs/entry.key -lab-control 127.0.0.1:2290 > /lab/dpi-v2/run/'+node+'-transport.log 2>&1'
        call(['docker','exec','-d','bb-lab-'+node+'-1','/bin/sh','-c',script])
    call(['docker-compose','-f','lab/compose.yml','up','-d','service'])
    call(['docker','exec','-d','bb-lab-service-1','/bin/sh','-c','exec /lab/evolution/evo-probe-linux serve > /lab/dpi-v2/run/service-http.log 2>&1'])
    call(['docker','run','-d','--name','bb-dpi-v2-client','--network','bb-lab_private','--ip','10.88.0.40','--cap-add','NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv4.conf.all.route_localnet=1','--sysctl','net.ipv4.conf.lo.route_localnet=1','--sysctl','net.ipv4.conf.all.accept_local=1','--sysctl','net.ipv4.conf.lo.accept_local=1','--sysctl','net.ipv4.conf.all.rp_filter=0','--sysctl','net.ipv4.conf.lo.rp_filter=0','-v',str(LAB)+':/lab','--entrypoint','/bin/sh','belnet-bridge:dpi-v2','/lab/dpi-v2/client.sh'])
    print('Started native relays/service and isolated v2/v3 client; readiness still requires nonce fetch.')

if __name__ == '__main__':main()
