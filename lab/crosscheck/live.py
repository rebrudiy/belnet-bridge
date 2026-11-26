#!/usr/bin/env python3
"""Fixed cross-test acquisition; never fits a model or selects a profile."""
import datetime
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / 'lab/crosscheck/run'
OUT = ROOT / 'out/crosscheck/live'
PROBE = '/lab/evolution/evo-probe-linux'
ENDPOINT = 'http://f3839udf9nsefrp3ug8zotg37jh6zcwejrps6hmdt4xstrpfupdy.bdx:8081'
MODEL = json.loads((RUN / 'final-attacker.json').read_text())
PROFILE = json.loads((RUN / 'frozen-profile.json').read_text())
SIZES = [1024, 4096, 16384, 1024, 4096, 16384, 1024, 4096]


def save(name, value):
    target = OUT / name
    temp = target.with_suffix(target.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(target)


def call(container, args, payload=None):
    cmd = ['docker', 'exec', '-i', container] + args
    data = json.dumps(payload).encode() if payload is not None else None
    p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35)
    if p.returncode:
        with (OUT / 'infrastructure-errors.jsonl').open('a') as f:
            f.write(json.dumps({'time':now(), 'container':container, 'args':args, 'error':p.stderr.decode()})+'\n')
        raise RuntimeError(container + ': ' + p.stderr.decode())
    return p.stdout.decode()


def admin(container, method, url, payload=None):
    return json.loads(call(container, [PROBE, 'admin', method, url], payload))


def fetch(kind, size):
    return json.loads(call('bb-cross-'+kind+'-client', [PROBE, 'fetch', ENDPOINT, str(size)]))


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def claude_decisions(trial):
    p = RUN / 'claude-server/decisions.jsonl'
    return [x for x in (json.loads(line) for line in p.read_text().splitlines()) if x['trial_id']==trial]


def rotate_claude(trial, mode):
    p = RUN / 'claude-trial.json'
    temp=p.with_suffix('.tmp');temp.write_text(json.dumps({'id':trial,'mode':mode})+'\n');temp.replace(p)
    log=RUN/'claude-client/transport.log'
    count=log.read_text().count('connected: tunnel address')
    call('bb-cross-claude-client', ['/bin/sh','-c','kill -TERM "$(cat /lab/crosscheck/run/claude-client/transport.pid)"'])
    time.sleep(.2)
    call('bb-cross-claude-client', ['/bin/sh','/lab/crosscheck/proxy-claude.sh'])
    deadline=time.monotonic()+12
    while time.monotonic()<deadline:
        if log.read_text().count('connected: tunnel address')>count:return
        time.sleep(.05)
    raise RuntimeError('Claude TLS connection did not become ready')


def our_states():
    return [admin('bb-cross-ours-client','GET','http://127.0.0.1:219%d/state'%n) for n in (1,2)]


def rotate_ours(trial):
    request={'id':trial,'group_id':trial,'split':'test','class':'belnet','profile':PROFILE}
    for n in (1,2):admin('bb-cross-ours-client','POST','http://127.0.0.1:219%d/epoch'%n,request)
    deadline=time.monotonic()+12
    while time.monotonic()<deadline:
        states=our_states()
        if all(s['epoch']==trial and s['connected'] for s in states):return
        time.sleep(.05)
    raise RuntimeError('Both first-node TLS connections did not become ready')


def install_ours(enforce):
    for n in (1,2):
        a=admin('bb-lab-entry%d-1'%n,'POST','http://127.0.0.1:2290/model',{'model':MODEL,'enforce':enforce})
        assert a['model_sha256']=='4136d0ec8d2780b3efc707eb328dc006229c1b86264a4f4e49522dd2f4531aa8'


def collect(kind, trial):
    if kind=='claude':return claude_decisions(trial)
    ids={x['session_id'] for s in our_states() for x in s['observations']}
    found=[]
    for n in (1,2):
        rows=admin('bb-lab-entry%d-1'%n,'GET','http://127.0.0.1:2290/decisions')['decisions']
        found += [x for x in rows if x['session_id'] in ids]
    return found


def main():
    save('status.json',{'status':'warming','started':now()})
    for kind in ('ours','claude'):
        warmed=False
        for i in range(8):
            proof=fetch(kind,256);save('warmup-%s-%02d.json'%(kind,i),proof)
            print('warmup',kind,i,proof['ok'],flush=True)
            if proof['ok']:warmed=True;break
            time.sleep(1)
        if not warmed:raise RuntimeError(kind+' failed warmup; no measured sessions acquired')
    save('status.json',{'status':'measuring','started':now()})
    all_trials=[]
    for mode,count in (('shadow',8),('enforce',2)):
        install_ours(mode=='enforce')
        for kind in ('ours','claude'):
            for i in range(count):
                trial='%s-%s-%02d'%(kind,mode,i+1)
                row={'id':trial,'kind':kind,'mode':mode,'started':now(),'body_bytes':SIZES[i]}
                try:
                    if kind=='ours':rotate_ours(trial)
                    else:rotate_claude(trial,mode)
                    reference=time.monotonic()
                    row['proof']=fetch(kind,SIZES[i])
                    remaining=reference+2.6-time.monotonic()
                    if remaining>0:time.sleep(remaining)
                    row['decisions']=collect(kind,trial)
                    if mode=='enforce':
                        row['after_window_proof']=fetch(kind,4096)
                        time.sleep(.3)
                        row['decisions']=collect(kind,trial)
                    row['complete_flows']=sum(x.get('complete',False) for x in row['decisions'])
                    row['flagged_flows']=sum(x.get('complete',False) and x['blocked'] for x in row['decisions'])
                    row['enforced_flows']=sum(x.get('enforced',False) for x in row['decisions'])
                    row['complete_group']=row['complete_flows']>=(2 if kind=='ours' else 1)
                except Exception as e:
                    row['error']=str(e)
                row['finished']=now();save(trial+'.json',row);all_trials.append(row)
                with (OUT/'trials.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
                print(trial,'proof',row.get('proof',{}).get('ok'),'flagged',row.get('flagged_flows'),'complete',row.get('complete_flows'),'enforced',row.get('enforced_flows'),'error',row.get('error'),flush=True)
    save('trials.json',all_trials)
    save('status.json',{'status':'complete','finished':now(),'trial_count':len(all_trials)})


if __name__=='__main__':
    try:main()
    except Exception as e:
        save('status.json',{'status':'failed','finished':now(),'error':str(e)})
        raise
