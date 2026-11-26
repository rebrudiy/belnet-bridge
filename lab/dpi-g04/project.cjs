'use strict';
// Bind a declared posthoc extraction to its raw acquisition and exact classifier.
// Opaque report bytes are hashed, never JSON-round-tripped through JavaScript.
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const {preflight}=require('../dpi-g03/adaptive/project.cjs');
const ROOT=path.resolve(__dirname,'../..');
const hash=raw=>crypto.createHash('sha256').update(raw).digest('hex');
function need(ok,message){if(!ok)throw Error(message);}
function bytes(file){return fs.readFileSync(path.resolve(file));}
function verified(file,expected){const raw=bytes(file);need(hash(raw)===expected,'Artifact changed: '+file);return raw;}
function write(file,value){fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});}
function project(a){
  const masterPath=path.resolve(a.master),masterRaw=bytes(masterPath),auditRaw=bytes(a.audit);
  const original=preflight({masterRaw,auditRaw,masterPath,auditorSHA:hash(bytes(path.join(ROOT,'lab/dpi-g03/review-analysis-r4.cjs')))});
  const extractionRaw=bytes(a.extraction),extraction=JSON.parse(extractionRaw);
  need(extraction.schema==='g04-header-extraction/v1'&&extraction.complete===true&&extraction.global_integrity===true&&extraction.groups?.length===71&&extraction.integrity_errors?.length===0&&extraction.errors?.length===0,'Complete integrity-verified71 extraction required');
  need(extraction.input_master_sha256===hash(masterRaw)&&extraction.root_release_sha256===hash(auditRaw)&&extraction.private_test_values_read===false,'Extraction lineage mismatch');
  verified(extraction.declaration.path,extraction.declaration.sha256);
  verified(extraction.observer_index.path,extraction.observer_index.sha256);
  const toolingRaw=bytes(a.tooling),tool=JSON.parse(toolingRaw);
  need(tool.version==='g04-header-ensemble-v1'&&tool.analysis_contract==='r4-worst-case-benign-fp-v1','Header classifier required');
  const observerRaw=bytes(path.join(ROOT,'lab/dpi-g04/observer/tooling/TOOLING.json')),longRaw=bytes(path.join(ROOT,'lab/dpi-g04/longflow/tooling/TOOLING.json'));
  const observer=JSON.parse(observerRaw),long=JSON.parse(longRaw);
  need(hash(observerRaw)===tool.observer_descriptor_sha256&&hash(longRaw)===tool.longflow_descriptor_sha256&&observer.coverage_semantics_sha256===tool.coverage_semantics_sha256&&long.feature_definitions_sha256===tool.longflow_definitions_sha256,'Header extractor/classifier disagreement');
  for(const descriptor of [tool,observer,long])for(const [file,sha]of Object.entries(descriptor.source_sha256))verified(path.join(ROOT,file),sha);
  for(const b of [tool.binary.ensemble,tool.score_engine,observer.binary.observer,long.binary.longflow])verified(path.join(ROOT,b.versioned_path),b.sha256);
  const seen=new Set();
  for(const group of extraction.groups){
    need(!seen.has(group.group_id)&&original.master.groups.some(g=>g.group_id===group.group_id&&g.split===group.split)&&group.finished===true&&group.raw_input_before_verified===true&&group.raw_input_after_verified===true&&group.errors?.length===0,'Missing/mismatched extracted group');seen.add(group.group_id);
    const dir=path.join(path.dirname(path.resolve(a.extraction)),group.group_id);
    for(const [name,file]of [['observer','windows.json'],['longflow','longflow.json']]){need(group.outputs?.[name]?.path===file,'Unexpected report path');verified(path.join(dir,file),group.outputs[name].sha256);}
  }
  const f=original.master,now=new Date().toISOString(),projection={schema:4,stage:'B1',stage_a_viability:'proceed',frozen_at:now,analysis_contract:tool.analysis_contract,collector_freeze_sha256:hash(masterRaw),collectors:[{path:masterPath,sha256:hash(masterRaw)}],extraction_manifest:{path:path.resolve(a.extraction),sha256:hash(extractionRaw)},measured_seconds:80,capture_seconds:82,prefix_grace_seconds:2,window_offsets_seconds:f.window_offsets_seconds,window_seconds:2,cooldown_seconds:30,capture_cap_bytes:f.pcap_cap_bytes,group_fpr_budget:.05,direct_flow_fpr_budget:.05,definitions_sha256:tool.definitions_sha256,window_definitions_sha256:tool.window_definitions_sha256,longflow_definitions_sha256:tool.longflow_definitions_sha256,ordering_semantics_sha256:tool.ordering_semantics_sha256,coverage_semantics_sha256:tool.coverage_semantics_sha256,observer_schema:6,longflow_extractor_sha256:long.binary.longflow.sha256,ensemble_binary_sha256:tool.binary.ensemble.sha256,score_engine_sha256:tool.score_engine.sha256,observer_sha256:observer.binary.observer.sha256,observer_version:observer.version,groups:f.groups.map(g=>Object.fromEntries([...['group_id','source_workload_id','scope','transport','client_stack','split','class','profile'].map(k=>[k,g[k]]),['collector_freeze_sha256',hash(masterRaw)]]))};
  const out=path.resolve(a.output);need(!fs.existsSync(out),'Refusing overwrite');fs.mkdirSync(out,{recursive:true,mode:0o700});
  write(path.join(out,'projection.json'),projection);
  write(path.join(out,'INPUTS.json'),{schema:'g04-header-policy-inputs/v1',created_at:now,posthoc_development:true,test_values_read:false,classifier_fitting_performed:false,master_sha256:hash(masterRaw),root_release_sha256:hash(auditRaw),extraction_sha256:hash(extractionRaw),tooling_sha256:hash(toolingRaw),index:extraction.observer_index,projection_sha256:hash(bytes(path.join(out,'projection.json'))),projector_sha256:hash(bytes(__filename))});
  return{projection:path.join(out,'projection.json'),index:extraction.observer_index.path,actual_input_reports_verified:71,classifier_fitting_performed:false};
}
if(require.main===module){try{const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i].slice(2)]=process.argv[i+1];console.log(JSON.stringify(project(a)));}catch(e){console.error(e.stack);process.exitCode=1;}}
module.exports={project};
