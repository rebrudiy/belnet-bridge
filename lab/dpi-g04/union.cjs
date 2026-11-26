'use strict';
// Metadata-only union. Source reports remain immutable, with per-collector origins.
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const read=p=>JSON.parse(fs.readFileSync(p));
function need(ok,message){if(!ok)throw Error(message);}
function save(p,x){fs.writeFileSync(p,JSON.stringify(x,null,2)+'\n',{flag:'wx',mode:0o600});}
function union(a){
 const base=read(a.projection),baseIndex=read(a.index),master=read(a.master),manifest=read(a.extraction);
 need(base.stage==='B1'&&base.observer_schema===6&&baseIndex.stage==='B1','Header development projection/index required');
 need(manifest.complete&&manifest.global_integrity&&manifest.integrity_errors.length===0&&manifest.input_master_sha256===hash(a.master)&&manifest.adaptive_round===master.adaptive_round,'Verified completed round extraction required');
 need(master.experiment_role==='candidate-development'&&[3,6].includes(master.groups.length)&&manifest.groups.length===master.groups.length,'Finite adaptive groups required');
 need(hash(manifest.observer_index.path)===manifest.observer_index.sha256,'Round index changed');
 const nextIndex=read(manifest.observer_index.path),sha=hash(a.master),groups=[...base.groups],seen=new Set(groups.map(g=>g.group_id));
 for(const g of master.groups){need(!seen.has(g.group_id)&&g.scope==='primary'&&g.class==='belnet'&&['train','validation'].includes(g.split),'New development positive required');seen.add(g.group_id);groups.push(Object.fromEntries([...['group_id','source_workload_id','scope','transport','client_stack','split','class','profile'].map(k=>[k,g[k]]),['collector_freeze_sha256',sha]]));}
 const out=path.resolve(a.output);need(!fs.existsSync(out),'Refusing overwrite');fs.mkdirSync(out,{recursive:true,mode:0o700});
 const collectors=[...(base.collectors||[])];need(collectors.length>0&&!collectors.some(c=>c.sha256===sha),'Fresh explicit collector required');collectors.push({path:path.resolve(a.master),sha256:sha});
 const projection={...base,groups,collectors,frozen_at:new Date().toISOString(),supplemental_extraction:{path:path.resolve(a.extraction),sha256:hash(a.extraction)}};
 const absolute=(index,file)=>index.reports.map(r=>({...r,path:path.resolve(path.dirname(file),r.path),longflow_path:path.resolve(path.dirname(file),r.longflow_path)}));
 const index={schema:4,stage:'B1',coverage_errors:[...(baseIndex.coverage_errors||[]),...(nextIndex.coverage_errors||[])],reports:[...absolute(baseIndex,path.resolve(a.index)),...absolute(nextIndex,manifest.observer_index.path)]};
 save(out+'/projection.json',projection);save(out+'/index.json',index);
 const initial=read(a.policy),policy={...initial,freeze_sha256:hash(out+'/projection.json'),policy_frozen_at:new Date().toISOString(),parameters_origin:{path:path.resolve(a.policy),sha256:hash(a.policy),parameters_frozen_at:initial.policy_frozen_at,numerical_parameters_unchanged:true}};
 // Evaluation reuses fixed initial numbers; this new serialization binds their
 // application to the enlarged declared cohort and is not a new fit.
 save(out+'/fixed-initial-policy.json',policy);
 save(out+'/UNION.json',{created_at:new Date().toISOString(),groups:groups.length,base_projection:{path:path.resolve(a.projection),sha256:hash(a.projection)},round_master:{path:path.resolve(a.master),sha256:sha},round_extraction:{path:path.resolve(a.extraction),sha256:hash(a.extraction)},rules_or_thresholds_changed:false,private_test_values_read:false});
 return{directory:out,groups:groups.length,projection:out+'/projection.json',index:out+'/index.json',policy:out+'/fixed-initial-policy.json'};
}
if(require.main===module){try{const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i].slice(2)]=process.argv[i+1];console.log(JSON.stringify(union(a)));}catch(e){console.error(e.stack);process.exitCode=1;}}
module.exports={union};
