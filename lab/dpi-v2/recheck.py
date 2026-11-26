#!/usr/bin/env python3
"""Cold checks after the continuous-session failure; original failures remain."""
import json
import subprocess
import time
import acquire as a

OUT=a.ROOT/'out/dpi-v2/rechecks'

def save(name,data):
    OUT.mkdir(parents=True,exist_ok=True);(OUT/name).write_text(json.dumps(data,indent=2)+'\n')

def reset(name):
    subprocess.run(['python3',str(a.ROOT/'lab/dpi-v2/reset-native.py'),name],check=True,capture_output=True)
    errors=[]
    for _ in range(20):
        try:a.admin(1,'GET','state');break
        except Exception as e:errors.append(str(e));time.sleep(.25)
    return errors

def main():
    if (OUT/'trials.json').exists():raise RuntimeError('Refusing to overwrite recheck evidence')
    plan=json.loads((a.ROOT/'out/dpi-v2/rounds/plan.json').read_text())['candidates']
    rows=[]
    for number in [14,15]:
        p=plan[number-1]['policy'];name='post-r%02d'%number
        row={'round':number,'fresh_native_identity':True,'group_id':name,'policy':p,'reason':'continuous native path failure after long-pause round; cold diagnostic, not replacement of original failure'}
        row['control_start_errors']=reset(name)
        row['baseline_warmup']=a.fetch(1024)
        epoch={'id':name,'group_id':name,'split':'test','class':'belnet','profile':a.PROFILE,'cells':p}
        for n in (1,2):a.admin(n,'POST','epoch',epoch)
        started=time.monotonic();row['proofs']=[a.fetch(4096),a.fetch(16384)]
        if time.monotonic()-started<6.2:time.sleep(6.2-(time.monotonic()-started))
        row['states']=[a.admin(n,'GET','state') for n in (1,2)]
        rows.append(row);save('trials.json',rows)
        print(name,'warmup',row['baseline_warmup']['ok'],'proofs',[p['ok'] for p in row['proofs']],flush=True)

if __name__=='__main__':main()
