#!/usr/bin/env python3
"""Live private-lab enforcement, separating detection from application outcome."""
import argparse
import json
from pathlib import Path
import subprocess
import time
import acquire as a

OUT=a.ROOT/'out/dpi-v2/enforcement'

def save(name,data):
    OUT.mkdir(parents=True,exist_ok=True)
    p=OUT/name;temp=p.with_suffix('.tmp');temp.write_text(json.dumps(data,indent=2)+'\n');temp.replace(p)

def server(n,data):return a.call('bb-lab-entry%d-1'%n,[a.PROBE,'admin','POST','http://127.0.0.1:2290/model'],data)
def decisions(n):return a.call('bb-lab-entry%d-1'%n,[a.PROBE,'admin','GET','http://127.0.0.1:2290/decisions'])

def firewall(n,action):
    args=['docker','exec','bb-lab-entry%d-1'%n,'iptables',action,'INPUT']
    if action=='-I':args.append('1')
    args+=['-s','10.88.0.40','-p','tcp','--dport','443','-j','REJECT','--reject-with','tcp-reset']
    subprocess.run(args,check=True,capture_output=True)
    return args

def run(mode,policy):
    target=OUT/(mode+'.json')
    if target.exists():raise RuntimeError('Refusing to overwrite live evidence')
    cells=json.loads((a.ROOT/'out/dpi-v2/rounds/plan.json').read_text())['candidates'][-1]['policy']
    model=None if mode=='classical' else json.loads(Path(policy).read_text())
    row={'mode':mode,'policy_path':str(policy),'cells':cells,'cooldown_seconds':30,'firewall_scope':'private entry namespace, client10.88.0.40 TCP443 only','before_decisions':{str(n):len(decisions(n)['decisions']) for n in (1,2)}}
    row['before_install_proof']=a.fetch(1024)
    if not row['before_install_proof'].get('ok'):
        row['status']='inconclusive: native application baseline unavailable'
        save(mode+'.json',row)
        print(mode,row['status'],flush=True)
        return
    installed=[]
    try:
        row['install']=[server(n,{'model':model,'enforce':mode=='forest','cooldown_seconds':30 if mode=='forest' else 0}) for n in (1,2)]
        epoch={'id':mode+'-enforce','group_id':mode+'-enforce','split':'test','class':'belnet','profile':a.PROFILE,'cells':cells}
        for n in (1,2):a.admin(n,'POST','epoch',epoch)
        started=time.monotonic();row['before_window_proof']=a.fetch(1024)
        if time.monotonic()-started<2.4:time.sleep(2.4-(time.monotonic()-started))
        row['states_at_verdict']=[a.admin(n,'GET','state') for n in (1,2)]
        if mode=='classical':
            observations=[o for s in row['states_at_verdict'] for o in s['observations']]
            save('classical-input.json',observations)
            command=[str(a.ROOT/'out/dpi-v2/classical/classical'),'evaluate','-policy',str(policy),'-input',str(OUT/'classical-input.json'),'-split','test','-output',str(OUT/'classical-verdict.json')]
            subprocess.run(command,check=True,capture_output=True)
            verdict=json.loads((OUT/'classical-verdict.json').read_text())
            last=max(x['round'] for x in verdict['rounds'])
            hits={d['session_id'] for d in verdict['decisions'] if d['round']==last and d['detected']}
            row['detected_entries']=[];row['firewall_commands']=[]
            for n,state in enumerate(row['states_at_verdict'],1):
                if any(o['session_id'] in hits for o in state['observations']):
                    row['firewall_commands'].append(firewall(n,'-I'));installed.append(n);row['detected_entries'].append(n)
            row['rule_decision']=verdict['rounds'][-1]
        blocked_at=time.monotonic()
        row['after_window_proof']=a.fetch(4096)
        row['states_during_block']=[a.admin(n,'GET','state') for n in (1,2)]
        row['decisions_after']={str(n):decisions(n)['decisions'][row['before_decisions'][str(n)]:] for n in (1,2)}
        # Keep the declared rule-based deny active for a measured30 seconds.
        if mode=='classical' and installed and time.monotonic()-blocked_at<30:
            time.sleep(30-(time.monotonic()-blocked_at))
        row['enforcement_elapsed_seconds']=time.monotonic()-blocked_at
    except Exception as e:row['error']=str(e)
    finally:
        for n in installed:
            try:firewall(n,'-D')
            except Exception as e:row.setdefault('cleanup_errors',[]).append(str(e))
        row['restore']=[server(n,{'model':None,'enforce':False,'cooldown_seconds':0}) for n in (1,2)]
        row['after_restore_proof']=a.fetch(1024)
        save(mode+'.json',row)
    print(mode,{k:row.get(k) for k in ['detected_entries','before_window_proof','after_window_proof','after_restore_proof','error']},flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['classical','forest']);p.add_argument('policy');args=p.parse_args();run(args.mode,Path(args.policy).resolve())
