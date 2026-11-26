#!/usr/bin/env python3
"""15 distinct declared transport hypotheses, retaining every measured outcome.

These are engineering experiments, not 15 promised successful improvements.
Policies and split assignments are frozen before acquisition. Test outcomes are
not used to select later policies. Classical adaptive rules are fit separately.
"""
import copy
import json
import time
import acquire as a

OUT=a.ROOT/'out/dpi-v2/rounds'
BASE={'name':'r01-fixed','min_size':768,'max_size':768,'interval_ms':20,'jitter_ms':0}

def plan():
    variants=[]
    def add(name,why,**fields):
        p=copy.deepcopy(BASE);p.update(fields);p['name']=name
        variants.append({'round':len(variants)+1,'policy':p,'hypothesis':why})
    add('r01-fixed','Replace input-driven v2 timing with paired fixed polling cells.')
    add('r02-uniform','Remove one dominant cell length.',min_size=384,max_size=1536)
    add('r03-wide','Expand size entropy beyond a narrow cell band.',min_size=256,max_size=4096)
    add('r04-mixture','Use a multimodal size distribution instead of uniform lengths.',min_size=256,max_size=4096,size_mode='mixture')
    add('r05-jitter','Remove a strict inter-poll time grid.',min_size=384,max_size=1536,interval_ms=8,jitter_ms=24)
    add('r06-tail','Change bounded-uniform gaps to capped exponential gaps.',min_size=384,max_size=1536,interval_ms=6,jitter_ms=18,delay_mode='exponential')
    add('r07-pipeline2','Break strict one-up/one-down turns with two outstanding cells.',min_size=384,max_size=1536,burst_cells=2)
    add('r08-pipeline4','Test four-cell directional bursts and higher bandwidth cost.',min_size=384,max_size=1536,burst_cells=4)
    add('r09-pipeline8','Test a larger bounded pipeline; watch queue and bandwidth limits.',min_size=384,max_size=1536,burst_cells=8)
    add('r10-asymmetry','Break exact request/reply size pairing.',min_size=384,max_size=1536,reply_min_size=512,reply_max_size=3072)
    add('r11-downskew','Break directional byte balance with smaller replies.',min_size=1024,max_size=3072,reply_min_size=256,reply_max_size=768)
    add('r12-shortpause','Break continuous polling with declared short idle gaps.',min_size=384,max_size=1536,pause_every=16,pause_ms=250)
    add('r13-longpause','Test long idle gaps and their real UDP latency/disconnect cost.',min_size=384,max_size=1536,pause_every=8,pause_ms=700)
    add('r14-ratecoupled','Couple poll duration to encrypted cell bytes rather than independent clocks.',min_size=256,max_size=4096,interval_ms=4,jitter_ms=8,rate_bytes_per_second=48000)
    add('r15-combined','Combine size mixture, asymmetric replies, burst and irregular gaps; not a proof of HTTPS mimicry.',min_size=256,max_size=4096,size_mode='mixture',delay_mode='exponential',interval_ms=8,jitter_ms=20,burst_cells=2,reply_min_size=384,reply_max_size=2048,pause_every=24,pause_ms=120,rate_bytes_per_second=64000)
    return variants

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    if (OUT/'trials.json').exists():raise RuntimeError('Refusing to overwrite round evidence')
    candidates=plan();(OUT/'plan.json').write_text(json.dumps({'candidates':candidates,'groups_per_candidate':4,'split':['train','train','validation','test'],'seconds':5.2,'test_not_for_selection':True},indent=2)+'\n')
    rows=[]
    for candidate in candidates:
        for i,split in enumerate(['train','train','validation','test']):
            name=candidate['policy']['name'];group=name+'-g%d'%i
            epoch={'id':group,'group_id':group,'split':split,'class':'belnet','profile':a.PROFILE,'cells':candidate['policy']}
            row={'id':group,'kind':name,'round':candidate['round'],'split':split,'policy':candidate['policy']}
            try:
                for n in (1,2):a.admin(n,'POST','epoch',epoch)
                started=time.monotonic();row['proofs']=[a.fetch([1024,4096,16384,8192][i])]
                if time.monotonic()-started<3:time.sleep(3-(time.monotonic()-started))
                row['proofs'].append(a.fetch(4096))
                if time.monotonic()-started<5.2:time.sleep(5.2-(time.monotonic()-started))
                row['states']=[a.admin(n,'GET','state') for n in (1,2)]
            except Exception as e:row['error']=str(e)
            rows.append(row);temp=OUT/'trials.tmp';temp.write_text(json.dumps(rows,indent=2)+'\n');temp.replace(OUT/'trials.json')
            print(group,split,[p.get('ok') for p in row.get('proofs',[])],row.get('error',''),flush=True)
    (OUT/'status.json').write_text(json.dumps({'status':'complete','rounds':15,'groups':len(rows)})+'\n')

if __name__=='__main__':main()
