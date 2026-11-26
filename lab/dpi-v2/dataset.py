#!/usr/bin/env python3
"""Join only eligible observations; never relabel unsuccessful real visits."""
import copy
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'out/dpi-v2'

def main():
    data=[];late=[];excluded=[]
    if (OUT/'real/frozen-20261119/observations.json').exists():data.extend(json.loads((OUT/'real/frozen-20261119/observations.json').read_text()))
    # A CAPTCHA/failed video is not successful search/playback, but its valid
    # public browser TLS flows are still ordinary benign traffic for DPI FPR.
    failure_path=OUT/'real/frozen-20261119/access-failure-observations.json'
    if failure_path.exists():
        for o in json.loads(failure_path.read_text()):
            o['profile']='real-access-failure/'+o['profile'];data.append(o)
    if (OUT/'real/frozen-20261119/late-observations.json').exists():
        for o in json.loads((OUT/'real/frozen-20261119/late-observations.json').read_text()):
            o['capture_window_start_micros']=o.pop('window_offset_micros',0)
            late.append(o)
    for folder,pattern in [('controls-final','fresh-local-*.json')]:
        for p in sorted((ROOT/'lab/dpi-v2/run'/folder).glob(pattern)):
            r=json.loads(p.read_text())
            if r.get('eligible'):data.append(r['observation'])
            else:excluded.append({'file':str(p.relative_to(ROOT)),'reason':'incomplete_local_control'})
            full=r.get('full_observation');start=2000000
            if full and full['events'] and full['events'][-1]['at_micros']>=start+2000000:
                o=copy.deepcopy(full);o['session_id']+='-late2s';o['capture_window_start_micros']=start
                o['events']=[dict(e,at_micros=e['at_micros']-start) for e in full['events'] if start<=e['at_micros']<start+2000000][:64]
                if o['events']:late.append(o)
    for name in ['native','rounds']:
        p=OUT/name/'trials.json'
        if not p.exists():continue
        for row in json.loads(p.read_text()):
            for state in row.get('states',[]):
                ready={x['session_id']:x['ready'] for x in state['connections']}
                for obs in state['observations']:
                    if ready.get(obs['session_id']):data.append(obs)
                    else:excluded.append({'session_id':obs['session_id'],'reason':'incomplete_native_prefix'})
                for full in state.get('full_observations',[]):
                    events=full['events']
                    # A later application-only window: require traffic past its
                    # end, avoiding a short tail being counted as eligible.
                    start=3000000
                    if not events or events[-1]['at_micros']<start+2000000:continue
                    window=[dict(e,at_micros=e['at_micros']-start) for e in events if start<=e['at_micros']<start+2000000][:64]
                    if not window:continue
                    o=copy.deepcopy(full);o['session_id']+='-late3s';o['events']=window;o['capture_window_start_micros']=start;late.append(o)
    seen={};groups={}
    for o in data:
        if o['session_id'] in seen:raise RuntimeError('Duplicate session '+o['session_id'])
        seen[o['session_id']]=True
        g=o['group_id'];split=o['split']
        if g in groups and groups[g]!=split:raise RuntimeError('Group split leakage '+g)
        groups[g]=split
    (OUT/'dataset.json').write_text(json.dumps(data,indent=2)+'\n')
    (OUT/'late-dataset.json').write_text(json.dumps(late,indent=2)+'\n')
    (OUT/'exclusions.json').write_text(json.dumps(excluded,indent=2)+'\n')
    # Preliminary controls remain available for diagnosis. They are not reused
    # as a fresh final holdout after fixing the request-metadata mismatch.
    diagnostic=[]
    for folder in ['controls','controls-late','controls-matched']:
        for p in sorted((ROOT/'lab/dpi-v2/run'/folder).glob('*.json')):
            r=json.loads(p.read_text())
            if 'observation' in r:diagnostic.append(r)
    (OUT/'diagnostic-controls.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
    print('eligible',len(data),'groups',len(groups),'late',len(late),'excluded',len(excluded))

if __name__=='__main__':main()
