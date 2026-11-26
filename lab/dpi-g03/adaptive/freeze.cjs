'use strict';
// Supplemental development metadata only. Traffic uses the unchanged v5 collector.
const fs=require('fs'),path=require('path'),cp=require('child_process');
const {hash}=require('./prepare.cjs');
const {validateLedger}=require('../iterations/index.cjs');
const {validate}=require('../runtime-v5/freeze.cjs');
const ROOT=path.resolve(__dirname,'../../..');
function need(ok,message){if(!ok)throw Error(message);}
function ref(r){need(r?.path&&/^[a-f0-9]{64}$/.test(r.sha256),'Pinned artifact reference required');need(hash(path.resolve(ROOT,r.path))===r.sha256,'Artifact drift: '+r.path);return path.resolve(ROOT,r.path);}
function requireRelease(release){
  need(release.schema==='g03-root-conservative-analysis-release/v1'&&release.stage==='B1'&&release.analysis_input_allowed===true&&release.raw_acquisition_complete===true&&release.terminal_completed===true&&release.expected_groups===71&&release.observed_groups===71&&release.groups?.length===71&&release.private_test_values_read===false,'Complete original71 raw-acquisition release required');
}
function preflight(plan,prep,release,baseline,ledger){
  requireRelease(release);
  need(release.frozen_collector_sha256===release.collector_freeze?.sha256&&baseline.stage==='B1'&&baseline.groups?.length===71,'Baseline collector mismatch');
  need(new Set(release.groups.map(g=>g.group_id)).size===71&&release.groups.every(g=>baseline.groups.some(b=>b.group_id===g.group_id)),'Release inventory differs from baseline');
  need(prep.adaptive_candidate_only===true&&prep.adapter_source_provenance?.source_sha256&&prep.baseline_preparation?.sha256===baseline.prepared.sha256,'Candidate must clone the original verified preparation');
  need(plan.schema==='belnet-adaptive-native-plan/v1'&&Number.isInteger(plan.cycle)&&plan.cycle>=1&&plan.cycle<=15&&plan.experiment_role==='candidate-development'&&plan.real_traffic_started===false&&plan.test_rows===0,'Explicit pending adaptive development round required');
  need(ledger.cycles?.[plan.cycle-1]?.state==='in_progress','Round must be causally in progress in the validated ledger');
  need(Number.isFinite(Date.parse(release.completion_finished_utc))&&Date.parse(ledger.cycles[plan.cycle-1].hypothesis?.selected_at)>Date.parse(release.completion_finished_utc),'Round hypothesis must follow completed baseline acquisition');
  need([3,6].includes(plan.groups?.length)&&plan.resource_limits?.max_active_native===1&&plan.resource_limits.max_active_groups===1,'Exactly3or6 singleton native deployments required');
  need(Object.keys(plan.stages||{}).join(',')==='B1'&&JSON.stringify(plan.stages.B1.order)===JSON.stringify(plan.groups.map(g=>g.group_id))&&JSON.stringify(plan.stages.B1.batches)===JSON.stringify(plan.groups.map(g=>[g.group_id])),'Exact finite singleton order required');
  const ids=new Set(),nonces=new Set(),oldNonces=new Set(baseline.groups.flatMap(g=>[g.nonce,g.initial_nonce,...g.warmup_nonces]));
  for(const g of plan.groups){
    need(!ids.has(g.group_id)&&/^[-a-z0-9]{1,80}$/.test(g.group_id),'Unique bounded group ID required');ids.add(g.group_id);
    need(g.class==='belnet'&&g.transport==='reality'&&g.scope==='primary'&&g.experiment_role==='candidate-development'&&['train','validation'].includes(g.split)&&['rpc','download','upload'].includes(g.family)&&g.fresh_native_identity_required===true&&g.workload_duration_seconds===45&&g.measured_seconds===80&&g.prefix_grace_seconds===2,'Candidate group contract mismatch');
    need(Number.isSafeInteger(g.seed_int)&&g.seed_int>=1&&g.seed_int<2**48&&g.seed_hex===g.seed_int.toString(16).padStart(16,'0'),'Actual frozen48-bit workload seed required');
    need(g.warmup_nonces?.length===3,'All initial/warmup/main attempts must remain declared');
    for(const n of [g.nonce,g.initial_nonce,...g.warmup_nonces]){need(/^[a-f0-9]{64}$/.test(n)&&!nonces.has(n)&&!oldNonces.has(n),'Fresh disjoint nonce required');nonces.add(n);}
  }
  need(new Set(plan.groups.map(g=>g.split)).size===2,'Both development splits required');
  for(const family of ['rpc','download','upload'])need(plan.groups.filter(g=>g.family===family).length===plan.groups.length/3,'All3 application families required');
  need(plan.candidate?.elf?.sha256===prep.adapter.sha256,'Selected ELF differs from the planned candidate');
}
function freeze({planPath,prepPath,releasePath,ledgerPath,output,runID}){
  planPath=path.resolve(planPath);prepPath=path.resolve(prepPath);releasePath=path.resolve(releasePath);ledgerPath=path.resolve(ledgerPath);output=path.resolve(output);
  need(!fs.existsSync(output)&&!fs.existsSync(output+'-source'),'Refusing overwrite');
  const release=JSON.parse(fs.readFileSync(releasePath));
  requireRelease(release);
  const plan=JSON.parse(fs.readFileSync(planPath)),prep=JSON.parse(fs.readFileSync(prepPath)),ledger=JSON.parse(fs.readFileSync(ledgerPath));
  // This validates the real baseline/prior-row evidence, including semantic deltas.
  const baselinePath=ref(release.collector_freeze),baseline=JSON.parse(fs.readFileSync(baselinePath));
  need(release.auditor_sha256===hash(path.join(ROOT,'lab/dpi-g03/review-analysis-r4.cjs')),'Unknown or changed baseline analysis auditor');
  need(typeof runID==='string'&&/^[-a-z0-9]{1,80}$/.test(runID),'Explicit bounded run ID required');
  preflight(plan,prep,release,baseline,ledger);
  validateLedger(ledger,{root:ROOT});
  const pinned=[planPath,prepPath,releasePath,ledgerPath,baselinePath,__filename];
  for(const r of Object.values(plan.candidate))pinned.push(ref(r));
  const source=JSON.parse(fs.readFileSync(ref(plan.candidate.source_manifest)));
  need(source.kind==='source_manifest'&&Array.isArray(source.files),'Compiled source manifest required');
  const declared={};for(const f of source.files){ref(f);need(f.logical_path&&!declared[f.logical_path],'Unique logical source paths required');declared[f.logical_path]=f.sha256;pinned.push(path.resolve(ROOT,f.path));}
  need(JSON.stringify(Object.entries(declared).sort())===JSON.stringify(Object.entries(prep.adapter_source_provenance.source_sha256).sort()),'Planned source differs from tested preparation');
  const staging=output+'-template';need(!fs.existsSync(staging),'Template already exists');fs.mkdirSync(staging,{recursive:true});
  const templatePath=path.join(staging,'template.json');
  cp.execFileSync(process.execPath,[path.join(ROOT,'lab/dpi-g03/runtime-v5/freeze.cjs'),'--stage','B1','--assignments',planPath,'--prepared',prepPath,'--output',templatePath,'--run-id',runID],{cwd:ROOT,stdio:'pipe'});
  const f=JSON.parse(fs.readFileSync(templatePath));
  f.adaptive_round=plan.cycle;f.experiment_role='candidate-development';f.adaptive_baseline_release={path:releasePath,sha256:hash(releasePath)};f.collector_template={path:templatePath,sha256:hash(templatePath),traffic_started:false};
  for(const g of f.groups){g.adaptive_round=plan.cycle;g.max_queue_age_micros=100000;g.application_budget_bytes_per_direction=4194304;}
  const archive=output+'-source';fs.cpSync(f.source_archive,archive,{recursive:true});f.source_archive=archive;
  pinned.push(templatePath);for(const p of pinned){f.files_sha256[p]=hash(p);const local=path.relative(ROOT,p);if(!local.startsWith('..')&&/\.(?:cjs|json|md|go|mod|sum)$/.test(local)){const dest=path.join(archive,local);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(p,dest);}}
  fs.writeFileSync(output,JSON.stringify(f,null,2)+'\n',{flag:'wx',mode:0o600});validate(output);
  return{freeze:output,sha256:hash(output),adaptive_round:f.adaptive_round,groups:f.groups.length,real_traffic_started:false};
}
if(require.main===module){try{const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i].slice(2)]=process.argv[i+1];console.log(JSON.stringify(freeze({planPath:a.plan,prepPath:a.prepared,releasePath:a.release,ledgerPath:a.ledger,output:a.output,runID:a['run-id']})));}catch(e){console.error(e.stack);process.exitCode=1;}}
module.exports={preflight,freeze};
