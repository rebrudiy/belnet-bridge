#!/usr/bin/env python3
"""Fresh isolated client identity for an explicitly labelled recovery check."""
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
LAB=ROOT/'lab';RUN=LAB/'dpi-v2/run'

def call(args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout

def reset(name):
    if not re.fullmatch(r'post-[a-z0-9-]{1,48}',name):raise RuntimeError('invalid lab-only name')
    if (RUN/name).exists():raise RuntimeError('recovery evidence already exists')
    (RUN/(name+'-previous-inspect.json')).write_text(call(['docker','inspect','bb-dpi-v2-client']))
    call(['docker','stop','-t','3','bb-dpi-v2-client']);call(['docker','rm','bb-dpi-v2-client'])
    call(['docker','run','-d','--name','bb-dpi-v2-client','--network','bb-lab_private','--ip','10.88.0.40','--cap-add','NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv4.conf.all.route_localnet=1','--sysctl','net.ipv4.conf.lo.route_localnet=1','--sysctl','net.ipv4.conf.all.accept_local=1','--sysctl','net.ipv4.conf.lo.accept_local=1','--sysctl','net.ipv4.conf.all.rp_filter=0','--sysctl','net.ipv4.conf.lo.rp_filter=0','-e','BB_DATA_DIR=/lab/dpi-v2/run/'+name,'-v',str(LAB)+':/lab','--entrypoint','/bin/sh','belnet-bridge:dpi-v2','/lab/dpi-v2/client.sh'])
    print('Started fresh client '+name+'; previous failed session remains archived.')

if __name__=='__main__':reset(sys.argv[1])
