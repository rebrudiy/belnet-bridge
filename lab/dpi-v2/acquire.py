#!/usr/bin/env python3
"""Acquire fresh native BelNet trials, retaining failed/incomplete attempts."""
import datetime
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'out/dpi-v2/native'
PROBE = '/lab/evolution/evo-probe-linux'
PROFILE = json.loads((ROOT/'lab/crosscheck/run/frozen-profile.json').read_text())
CELL = {'name':'v3-paired-random','min_size':384,'max_size':1536,'interval_ms':12,'jitter_ms':18}
URL = 'http://f3839udf9nsefrp3ug8zotg37jh6zcwejrps6hmdt4xstrpfupdy.bdx:8081'

def save(name,data):
    p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
    temp=p.with_suffix('.tmp');temp.write_text(json.dumps(data,indent=2)+'\n');temp.replace(p)

def admin(n,method,path,data=None):
    return call('bb-dpi-v2-client',[PROBE,'admin',method,'http://127.0.0.1:219%d/'%n+path],data)

def call(container,args,data=None):
    p=subprocess.run(['docker','exec','-i',container]+args,input=None if data is None else json.dumps(data).encode(),capture_output=True,timeout=40)
    if p.returncode:raise RuntimeError(p.stderr.decode())
    return json.loads(p.stdout)

def fetch(size):return call('bb-dpi-v2-client',[PROBE,'fetch',URL,str(size)])

def main():
    if (OUT/'trials.json').exists():raise RuntimeError('Refusing to overwrite measured trials')
    save('policy-frozen.json',{'v2':PROFILE,'v3':CELL,'groups_per_candidate':12,'whole_group_splits':'6 train / 3 validation / 3 test','selected_before_acquisition':True,'capture_seconds':6.2})
    trials=[]
    for kind in ['v2','v3']:
        for i in range(12):
            group='%s-native-%02d'%(kind,i)
            split='train' if i<6 else 'validation' if i<9 else 'test'
            epoch={'id':group,'group_id':group,'split':split,'class':'belnet','profile':PROFILE}
            if kind=='v3':epoch['cells']=CELL
            row={'id':group,'split':split,'kind':kind,'started':datetime.datetime.now(datetime.timezone.utc).isoformat()}
            try:
                for n in (1,2):admin(n,'POST','epoch',epoch)
                started=time.monotonic()
                row['proofs']=[fetch([1024,4096,16384][i%3])]
                if time.monotonic()-started<3:time.sleep(3-(time.monotonic()-started))
                row['proofs'].append(fetch([4096,16384,1024][i%3]))
                if time.monotonic()-started<6.2:time.sleep(6.2-(time.monotonic()-started))
                row['states']=[admin(n,'GET','state') for n in (1,2)]
            except Exception as e:row['error']=str(e)
            trials.append(row);save('trials.json',trials)
            print(group,split,[p.get('ok') for p in row.get('proofs',[])],row.get('error',''),flush=True)
    save('status.json',{'status':'complete','trials':len(trials)})

if __name__=='__main__':main()
