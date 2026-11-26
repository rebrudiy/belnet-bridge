#!/usr/bin/env python3
"""New client identity after a full server process restart; retain first run."""
import json
import subprocess
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
LAB=ROOT/'lab'
RUN=LAB/'dpi-v2/run'

def call(args):
    p=subprocess.run(args,capture_output=True,text=True,check=True)
    return p.stdout

def main():
    data='round-client-recovered'
    if (RUN/data).exists():raise RuntimeError('recovered client evidence already exists')
    (RUN/'first-client-inspect.json').write_text(call(['docker','inspect','bb-dpi-v2-client']))
    call(['docker','stop','-t','3','bb-dpi-v2-client']);call(['docker','rm','bb-dpi-v2-client'])
    for n in (1,2):
        node='entry%d'%n
        processes=call(['docker','exec','bb-lab-'+node+'-1','ps','-eo','pid,comm,args'])
        for line in processes.splitlines()[1:]:
            fields=line.split(None,2)
            if len(fields)==3 and fields[1]=='belnet-bridge' and ' udp-server ' in fields[2]:call(['docker','exec','bb-lab-'+node+'-1','kill','-TERM',fields[0]])
        time.sleep(.2)
        script='BRIDGE_TOKEN=$(cat /lab/run/certs/token); export BRIDGE_TOKEN; echo $$ > /lab/dpi-v2/run/'+node+'-server.pid; exec /lab/dpi-v2/bin/belnet-bridge udp-server -listen :443 -target 10.88.0.1'+str(n)+':1090 -cert /lab/run/certs/entry.crt -key /lab/run/certs/entry.key -lab-control 127.0.0.1:2290 > /lab/dpi-v2/run/'+node+'-round-recovered-transport.log 2>&1'
        call(['docker','exec','-d','bb-lab-'+node+'-1','/bin/sh','-c',script])
    call(['docker','run','-d','--name','bb-dpi-v2-client','--network','bb-lab_private','--ip','10.88.0.40','--cap-add','NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv4.conf.all.route_localnet=1','--sysctl','net.ipv4.conf.lo.route_localnet=1','--sysctl','net.ipv4.conf.all.accept_local=1','--sysctl','net.ipv4.conf.lo.accept_local=1','--sysctl','net.ipv4.conf.all.rp_filter=0','--sysctl','net.ipv4.conf.lo.rp_filter=0','-e','BB_DATA_DIR=/lab/dpi-v2/run/'+data,'-v',str(LAB)+':/lab','--entrypoint','/bin/sh','belnet-bridge:dpi-v2','/lab/dpi-v2/client.sh'])
    print('New round client started; first run kept unchanged.')

if __name__=='__main__':main()
