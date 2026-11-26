from pathlib import Path
import json,statistics,math
ROOT=Path(__file__).resolve().parents[3]
base=ROOT/'lab/evolution/results/full-15-queuefix-20261119'
train=json.loads((base/'final-training.json').read_text());validation=json.loads((base/'benign-validation.json').read_text())
cohorts={'benign_training':[o for o in train if o['class']=='benign'],'belnet_training':[o for o in train if o['class']=='belnet'],'frozen_profile_training':[o for o in train if o['class']=='belnet' and o['profile']=='w15-c02'],'benign_validation':validation}
def dist(a):
 b=sorted(a)
 if not b:return {'n':0}
 def q(v):
  p=v*(len(b)-1);lo=int(p);hi=min(lo+1,len(b)-1);return b[lo]+(b[hi]-b[lo])*(p-lo)
 return {'n':len(b),'min':b[0],'p25':q(.25),'median':q(.5),'p75':q(.75),'max':b[-1],'mean':sum(b)/len(b)}
report={}
for name,observations in cohorts.items():
 rows=[]
 for o in observations:
  ev=o['events'];suffix=ev[6:];ups=[(i,e) for i,e in enumerate(suffix) if e['direction']==1];used=set();matches=[];adj=[]
  for i,e in ups:
   for j in range(i+1,min(i+9,len(suffix))):
    d=suffix[j];delta=d['at_micros']-e['at_micros']
    if j not in used and d['direction']==-1 and d['bytes']==e['bytes']-4 and 0<=delta<=50000:
     matches.append(delta/1000);used.add(j);break
   if i+1<len(suffix):
    d=suffix[i+1];delta=d['at_micros']-e['at_micros']
    if d['direction']==-1 and d['bytes']==e['bytes']-4 and 0<=delta<=50000:adj.append(delta/1000)
  rows.append({'session_id':o['session_id'],'ups':len(ups),'pairs':len(matches),'match_fraction':len(matches)/len(ups) if ups else None,'adjacent_pair_fraction':len(adj)/len(ups) if ups else None,'paired_gap_ms':matches})
 report[name]={'flows':len(rows),'up_records_after_first6':sum(r['ups'] for r in rows),'matched_echo_signature_pairs':sum(r['pairs'] for r in rows),'flow_match_fraction':dist([r['match_fraction'] for r in rows if r['match_fraction'] is not None]),'flow_adjacent_pair_fraction':dist([r['adjacent_pair_fraction'] for r in rows if r['adjacent_pair_fraction'] is not None]),'matched_pair_gap_ms':dist([g for r in rows for g in r['paired_gap_ms']]),'sessions':rows}
report['method']={'drop_initial_encrypted_records':6,'pair_condition':'client_to_server TLS record followed within next8 records and50ms by unused server_to_client record of length up_length-4; greedily pair','why_delta4':'WebSocket client masking adds4bytes compared with server frame when equal payload and oneTLSrecord perWSmessage; TLSfragmentation/coalescing can invalidate signature','limitations':['Not proof of plaintext equality; only ciphertext-record metadata pairing.','First6 discarded records are a heuristic; encrypted handshake boundary is not known.','Not a production traffic classifier or evasion result.','Training and benign calibration only; no final/cross test observations used.']}
out=ROOT/'out/dpi-next/diagnostic/echo-pairs.json';out.write_text(json.dumps(report,indent=2)+'\n')
for n in cohorts: print(n,{k:v for k,v in report[n].items() if k!='sessions'})
