'use strict';
// No module-load I/O. This is a sequencing/provenance gate, not a filesystem
// sandbox or an attestation that an arbitrary policy trainer obeyed its inputs.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {utcNanoseconds}=require('./time.cjs');
const receipts=new WeakMap(),SHA=/^[0-9a-f]{64}$/,NONCE=/^[0-9a-f]{64}$/,MAX_SEED=(1n<<48n)-1n;
class GateError extends Error{constructor(code){super(code);this.name='GateError';this.code=code;}}
const fail=code=>{throw new GateError(code);};
function canonicalJSON(value){
 if(value===null||typeof value==='string'||typeof value==='boolean')return JSON.stringify(value);
 if(typeof value==='number'){if(!Number.isFinite(value))fail('NON_JSON_VALUE');return JSON.stringify(value);}
 if(Array.isArray(value))return '['+value.map(canonicalJSON).join(',')+']';
 if(value&&Object.getPrototypeOf(value)===Object.prototype)return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonicalJSON(value[k])).join(',')+'}';
 fail('NON_JSON_VALUE');
}
const sha256Bytes=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const sha256Canonical=value=>sha256Bytes(Buffer.from(canonicalJSON(value)));
const plain=x=>!!x&&Object.getPrototypeOf(x)===Object.prototype;
const strictUTC=x=>{try{return utcNanoseconds(x);}catch{fail('INVALID_UTC_TIMESTAMP');}};
function sameSet(actual,expected,code){if(actual.length!==expected.length||new Set(actual).size!==actual.length||actual.some(x=>!expected.includes(x)))fail(code);}
function idList(ids,count,code){if(!Array.isArray(ids)||ids.length!==count||new Set(ids).size!==count||ids.some(x=>typeof x!=='string'||x.length===0))fail(code);}
function descriptor(d,code){if(!plain(d)||typeof d.path!=='string'||!d.path||!SHA.test(d.sha256||''))fail(code);}
function readBytes(filename,io){let b;try{b=io.readFileSync(filename);}catch{fail('ARTIFACT_READ_FAILED');}if(!Buffer.isBuffer(b)&&!(b instanceof Uint8Array))fail('READER_MUST_RETURN_BYTES');return Buffer.from(b);}
function verifyBytes(d,io){const b=readBytes(d.path,io);if(sha256Bytes(b)!==d.sha256)fail('ARTIFACT_SHA256_MISMATCH');return b;}
function parseJSON(bytes){try{return JSON.parse(bytes.toString('utf8'));}catch{fail('ARTIFACT_JSON_INVALID');}}
function privateAliases(vault,publicFiles,io){
 const lexical=path.resolve(vault.path);if(publicFiles.some(d=>path.resolve(d.path)===lexical))fail('PUBLIC_ARTIFACT_ALIASES_VAULT');
 // stat/realpath inspect identity only, never vault bytes. Reject accidental
 // symlink/hardlink policy aliases before any content read.
 let vr,vs;try{vr=io.realpathSync(vault.path);vs=io.statSync(vault.path);}catch{fail('VAULT_METADATA_UNAVAILABLE');}
 if(!vs.isFile())fail('VAULT_NOT_REGULAR_FILE');
 for(const d of publicFiles){let real,stat;try{real=io.realpathSync(d.path);stat=io.statSync(d.path);}catch{fail('PUBLIC_ARTIFACT_METADATA_UNAVAILABLE');}if(real===vr||(stat.dev===vs.dev&&stat.ino===vs.ino))fail('PUBLIC_ARTIFACT_ALIASES_VAULT');if(!stat.isFile())fail('PUBLIC_ARTIFACT_NOT_REGULAR_FILE');}
}
function checkCompletedAudit(audit,ids,{supplement=false}={}){
 if(!plain(audit)||!Array.isArray(audit.groups))fail('B1_COMPLETION_AUDIT_REQUIRED');
 if(audit.groups.some(g=>!plain(g)))fail('B1_GROUP_NOT_COMPLETED_PRIMARY');
 sameSet(audit.groups.map(g=>g.group_id),ids,'INCOMPLETE_OR_UNEXPECTED_B1_COHORT');
 let latest=null;const splitByID=new Map();
 for(const g of audit.groups){
  if(!plain(g)||!['train','validation'].includes(g.split)||g.completed!==true||!['primary',...(supplement?['candidate-development']:[])].includes(g.scope)||g.qualification===true||g.incomplete===true||g.capped===true||(g.phase!==undefined&&!['B1',...(supplement?['candidate-response']:[])].includes(g.phase))||/^q(?:-|$)/i.test(g.group_id))fail('B1_GROUP_NOT_COMPLETED_PRIMARY');
  const t=strictUTC(g.capture_ended_utc);if(latest===null||t>latest)latest=t;splitByID.set(g.group_id,g.split);
 }
 return {latest,splitByID};
}
function seed(value){if(!Number.isSafeInteger(value)||value<1||BigInt(value)>MAX_SEED)fail('SEED_OUT_OF_48BIT_RANGE');return value;}
function nonceValues(row){if(!NONCE.test(row.nonce||'')||!NONCE.test(row.initial_nonce||'')||!Array.isArray(row.warmup_nonces)||row.warmup_nonces.length!==3||row.warmup_nonces.some(x=>!NONCE.test(x||'')))fail('INVALID_64HEX_NONCES');return [row.nonce,row.initial_nonce,...row.warmup_nonces];}
function checkAssignmentRows(spec){
 if(!Array.isArray(spec.assignments))fail('ASSIGNMENTS_REQUIRED');
 if(spec.assignments.some(r=>!plain(r)))fail('ASSIGNMENT_METADATA_INVALID');
 const expected=[...spec.expectedB1IDs,...spec.expectedTestIDs];sameSet(spec.assignments.map(r=>r.group_id),expected,'UNKNOWN_OR_MISSING_ASSIGNMENT_GROUP');
 const sourceSplits=new Map(),openSeeds=new Map(),openNonces=[];
 for(const r of spec.assignments){
  if(!plain(r)||r.scope!=='primary'||typeof r.source_workload_id!=='string'||!r.source_workload_id)fail('ASSIGNMENT_METADATA_INVALID');
  const isTest=spec.expectedTestIDs.includes(r.group_id);
  if(isTest){
   if(r.split!=='test'||r.seed_int!==null||r.seed_hex!==null||r.nonce!==null||r.initial_nonce!==null||!Array.isArray(r.warmup_nonces)||r.warmup_nonces.length!==3||r.warmup_nonces.some(x=>x!==null)||r.sealed_seed_ref!==r.source_workload_id||r.sealed_nonce_ref!==r.group_id)fail('TEST_ROW_NOT_EXPLICITLY_SEALED_NULL');
  }else{
   if(!['train','validation'].includes(r.split))fail('B1_ASSIGNMENT_SPLIT_INVALID');seed(r.seed_int);if(r.seed_hex!==r.seed_int.toString(16).padStart(16,'0'))fail('OPEN_SEED_HEX_MISMATCH');openNonces.push(...nonceValues(r));
   if(openSeeds.has(r.source_workload_id)&&openSeeds.get(r.source_workload_id)!==r.seed_int)fail('SOURCE_WORKLOAD_SEED_MISMATCH');openSeeds.set(r.source_workload_id,r.seed_int);
  }
  if(sourceSplits.has(r.source_workload_id)&&sourceSplits.get(r.source_workload_id)!==r.split)fail('SOURCE_WORKLOAD_CROSSES_SPLITS');sourceSplits.set(r.source_workload_id,r.split);
 }
 if(new Set(openNonces).size!==openNonces.length)fail('DUPLICATE_OPEN_NONCE');
 return {openNonces,sourceSplits};
}
function checkInitial(spec){
 if(!plain(spec))fail('GATE_SPEC_REQUIRED');idList(spec.expectedB1IDs,71,'EXPECTED_71_B1_IDS_REQUIRED');idList(spec.expectedTestIDs,25,'EXPECTED_25_TEST_IDS_REQUIRED');
 if(spec.expectedB1IDs.some(x=>!/^b-(train|validation)-/.test(x))||spec.expectedTestIDs.some(x=>!/^b-test-/.test(x)))fail('NONPRIMARY_OR_QUALIFICATION_ID');
 const supplements=spec.expectedSupplementIDs||[];if(!Array.isArray(supplements)||![0,6].includes(supplements.length)||new Set(supplements).size!==supplements.length||supplements.some(x=>typeof x!=='string'||!x||/^q(?:-|$)|^b-test-/i.test(x)||spec.expectedB1IDs.includes(x)||spec.expectedTestIDs.includes(x)))fail('INVALID_EXPLICIT_SUPPLEMENT_IDS');
 const allIDs=[...spec.expectedB1IDs,...spec.expectedTestIDs,...supplements];if(new Set(allIDs).size!==allIDs.length)fail('COHORT_ID_COLLISION');
 const b1=checkCompletedAudit(spec.b1Audit,spec.expectedB1IDs),assignments=checkAssignmentRows(spec);
 for(const r of spec.assignments)if(r.split!=='test'&&r.split!==b1.splitByID.get(r.group_id))fail('ASSIGNMENT_AUDIT_SPLIT_MISMATCH');
 let latest=b1.latest,supplementAudit=null;
 if(supplements.length){supplementAudit=checkCompletedAudit(spec.supplementAudit,supplements,{supplement:true});if(supplementAudit.latest>latest)latest=supplementAudit.latest;for(const g of spec.supplementAudit.groups){if(typeof g.source_workload_id!=='string'||!g.source_workload_id)fail('SUPPLEMENT_SOURCE_ID_REQUIRED');if(assignments.sourceSplits.get(g.source_workload_id)==='test')fail('SUPPLEMENT_USES_TEST_WORKLOAD_SOURCE');}}
 else if(spec.supplementAudit?.groups?.length)fail('UNDECLARED_SUPPLEMENT_AUDIT');
 descriptor(spec.primaryPolicy,'PRIMARY_POLICY_DESCRIPTOR_REQUIRED');descriptor(spec.projection,'PROJECTION_DESCRIPTOR_REQUIRED');descriptor(spec.collector,'COLLECTOR_DESCRIPTOR_REQUIRED');descriptor(spec.vault,'VAULT_COMMITMENT_REQUIRED');
 const auxiliary=spec.auxiliaryPolicy;
 if(auxiliary!==undefined&&(!plain(auxiliary)||typeof auxiliary.enabled!=='boolean'))fail('AUXILIARY_REQUIRES_EXPLICIT_ENABLE');
 if(auxiliary?.enabled){descriptor(auxiliary,'ENABLED_AUXILIARY_POLICY_MISSING');descriptor(spec.auxiliaryProjection,'ENABLED_AUXILIARY_PROJECTION_MISSING');}
 const sources=spec.supplementCollectors||[];if(!Array.isArray(sources))fail('SUPPLEMENT_COLLECTORS_INVALID');
 const supplementBindings=new Map();for(const d of sources){descriptor(d,'SUPPLEMENT_COLLECTOR_DESCRIPTOR_REQUIRED');if(!Array.isArray(d.group_ids)||d.group_ids.length===0)fail('SUPPLEMENT_SOURCE_GROUPS_REQUIRED');for(const id of d.group_ids){if(!supplements.includes(id)||supplementBindings.has(id))fail('UNDECLARED_OR_DUPLICATE_SUPPLEMENT_BINDING');supplementBindings.set(id,d.sha256);}}
 if(supplementBindings.size!==supplements.length)fail('SUPPLEMENT_SOURCE_BINDINGS_INCOMPLETE');
 const freeze=spec.b2Freeze;if(!plain(freeze))fail('B2_FREEZE_REQUIRED');const b2Time=strictUTC(freeze.frozen_at);
 const required={primary_policy_sha256:spec.primaryPolicy.sha256,projection_sha256:spec.projection.sha256,collector_sha256:spec.collector.sha256,vault_sha256:spec.vault.sha256,b1_audit_sha256:sha256Canonical(spec.b1Audit),assignments_sha256:sha256Canonical(spec.assignments)};
 for(const[k,v]of Object.entries(required))if(freeze[k]!==v)fail('B2_FREEZE_BINDING_MISMATCH');
 if(auxiliary?.enabled){if(freeze.auxiliary_policy_sha256!==auxiliary.sha256||freeze.auxiliary_projection_sha256!==spec.auxiliaryProjection.sha256)fail('AUXILIARY_FREEZE_BINDING_MISMATCH');}
 else for(const key of ['auxiliary_policy_sha256','auxiliary_projection_sha256','auxiliary_feature_definitions_sha256','auxiliary_library_source_sha256','auxiliary_ordering_semantics_sha256','auxiliary_coverage_semantics_sha256'])if(freeze[key]!==undefined&&freeze[key]!==null)fail('UNENABLED_AUXILIARY_BOUND_IN_FREEZE');
 if(supplements.length){if(freeze.supplement_audit_sha256!==sha256Canonical(spec.supplementAudit))fail('SUPPLEMENT_AUDIT_FREEZE_MISMATCH');const hashes=[...new Set(sources.map(s=>s.sha256))].sort();if(!Array.isArray(freeze.supplement_collector_sha256)||canonicalJSON([...freeze.supplement_collector_sha256].sort())!==canonicalJSON(hashes))fail('SUPPLEMENT_SOURCE_FREEZE_MISMATCH');}
 else {if(sources.length||(freeze.supplement_collector_sha256?.length))fail('UNDECLARED_SUPPLEMENT_SOURCE');if(freeze.supplement_audit_sha256!==undefined&&freeze.supplement_audit_sha256!==null)fail('UNDECLARED_SUPPLEMENT_AUDIT');}
 return {b1,supplementAudit,supplements,latest,b2Time,supplementBindings};
}
function checkPolicy(policy,spec,context,projectionSHA=spec.projection.sha256){
 if(!plain(policy))fail('POLICY_JSON_OBJECT_REQUIRED');
 if(policy.freeze_sha256!==projectionSHA)fail('POLICY_PROJECTION_SHA256_MISMATCH');
 if(typeof policy.policy_frozen_at!=='string')fail('POLICY_FROZEN_AT_REQUIRED');
 const last=strictUTC(policy.last_development_capture_ended_utc),frozen=strictUTC(policy.policy_frozen_at);
 if(last<context.latest)fail('POLICY_OMITS_LATEST_B1_OR_SUPPLEMENT_CAPTURE');
 if(frozen<=last||frozen<=context.latest)fail('POLICY_FROZEN_TOO_EARLY');
 if(context.b2Time<=frozen)fail('B2_FREEZE_NOT_AFTER_FINAL_POLICY');
 const train=policy.calibration?.train?.groups,validation=policy.calibration?.validation?.groups;
 const base={train:0,validation:0},extra={train:0,validation:0};for(const v of context.b1.splitByID.values())base[v]++;for(const v of context.supplementAudit?.splitByID.values()||[])extra[v]++;
 if(!Number.isSafeInteger(train)||!Number.isSafeInteger(validation)||train<base.train||validation<base.validation||train>base.train+extra.train||validation>base.validation+extra.validation)fail('POLICY_CALIBRATION_MISSING_71_B1_GROUPS');
 return {policy_frozen_at:policy.policy_frozen_at,last_development_capture_ended_utc:policy.last_development_capture_ended_utc,calibration_groups:train+validation};
}
function checkProjection(projection,spec,context,reference=null){
 if(!plain(projection)||projection.collector_freeze_sha256!==spec.collector.sha256||!Array.isArray(projection.groups))fail('PROJECTION_COLLECTOR_BINDING_INVALID');
 if(projection.groups.some(g=>!plain(g)))fail('PROJECTION_GROUP_METADATA_INVALID');
 const allIDs=[...spec.expectedB1IDs,...context.supplements];sameSet(projection.groups.map(g=>g.group_id),allIDs,'PROJECTION_MISSING_B1_OR_UNDECLARED_GROUP');
 const sourceSplits=new Map();
 for(const g of projection.groups){
  const supplemental=context.supplements.includes(g.group_id),split=(supplemental?context.supplementAudit:context.b1).splitByID.get(g.group_id);
  if(!plain(g)||g.split!==split||!['primary',...(supplemental?['candidate-development']:[])].includes(g.scope)||typeof g.source_workload_id!=='string'||!g.source_workload_id)fail('PROJECTION_GROUP_METADATA_INVALID');
  const expectedRow=supplemental?spec.supplementAudit.groups.find(x=>x.group_id===g.group_id):spec.assignments.find(x=>x.group_id===g.group_id);
  if(expectedRow.class!==undefined&&g.class!==expectedRow.class)fail('PROJECTION_GROUP_CLASS_MISMATCH');
  const expectedSource=supplemental?spec.supplementAudit.groups.find(x=>x.group_id===g.group_id).source_workload_id:spec.assignments.find(x=>x.group_id===g.group_id).source_workload_id;
  if(g.source_workload_id!==expectedSource)fail('PROJECTION_WORKLOAD_SOURCE_MISMATCH');
  const binding=g.collector_freeze_sha256||projection.collector_freeze_sha256,expected=supplemental?context.supplementBindings.get(g.group_id):spec.collector.sha256;
  if(binding!==expected)fail('PROJECTION_GROUP_COLLECTOR_BINDING_MISMATCH');
  if(sourceSplits.has(g.source_workload_id)&&sourceSplits.get(g.source_workload_id)!==g.split)fail('PROJECTION_SOURCE_CROSSES_SPLITS');sourceSplits.set(g.source_workload_id,g.split);
 }
 if(reference){
  const groups=new Map(reference.groups.map(g=>[g.group_id,g]));
  for(const g of projection.groups){const ref=groups.get(g.group_id);if(typeof g.class!=='string'||!g.class||g.class!==ref.class||g.split!==ref.split||g.source_workload_id!==ref.source_workload_id||g.scope!==ref.scope||(g.collector_freeze_sha256||projection.collector_freeze_sha256)!==(ref.collector_freeze_sha256||reference.collector_freeze_sha256))fail('AUXILIARY_PROJECTION_GROUP_MISMATCH');}
 }
}
function auxiliarySemantics(policy,projection,freeze){
 const keys=['feature_definitions_sha256','library_source_sha256','ordering_semantics_sha256'];
 if(policy.coverage_semantics_sha256!==undefined||projection.coverage_semantics_sha256!==undefined)keys.push('coverage_semantics_sha256');
 else if(freeze.auxiliary_coverage_semantics_sha256!==undefined&&freeze.auxiliary_coverage_semantics_sha256!==null)fail('AUXILIARY_COVERAGE_BINDING_WITHOUT_METADATA');
 const result={};
 for(const key of keys){if(!SHA.test(policy[key]||'')||!SHA.test(projection[key]||'')||policy[key]!==projection[key])fail('AUXILIARY_SEMANTICS_MISMATCH');if(freeze['auxiliary_'+key]!==policy[key])fail('AUXILIARY_SEMANTICS_FREEZE_MISMATCH');result[key]=policy[key];}
 return result;
}
function validateSpec(spec,io){
 const context=checkInitial(spec),checkedAt=io.nowUTC();if(context.b2Time>strictUTC(checkedAt))fail('B2_FREEZE_IS_IN_FUTURE');
 const files=[spec.primaryPolicy,spec.projection,spec.collector,...(spec.auxiliaryPolicy?.enabled?[spec.auxiliaryPolicy,spec.auxiliaryProjection]:[]),...(spec.supplementCollectors||[])];
 privateAliases(spec.vault,files,io);
 const primary=parseJSON(verifyBytes(spec.primaryPolicy,io));const primaryMeta=checkPolicy(primary,spec,context);
 const projection=parseJSON(verifyBytes(spec.projection,io));verifyBytes(spec.collector,io);
 checkProjection(projection,spec,context);
 for(const d of spec.supplementCollectors||[])verifyBytes(d,io);
 let auxiliaryMeta=null;
 if(spec.auxiliaryPolicy?.enabled){
  const auxProjection=parseJSON(verifyBytes(spec.auxiliaryProjection,io));checkProjection(auxProjection,spec,context,projection);
  const auxPolicy=parseJSON(verifyBytes(spec.auxiliaryPolicy,io));auxiliaryMeta={...checkPolicy(auxPolicy,spec,context,spec.auxiliaryProjection.sha256),projection_sha256:spec.auxiliaryProjection.sha256,semantics:auxiliarySemantics(auxPolicy,auxProjection,spec.b2Freeze)};
 }
 return {checked_at_utc:checkedAt,primary:primaryMeta,auxiliary:auxiliaryMeta,latest_development_capture_ns:context.latest.toString()};
}
function ioOptions(options){return {readFileSync:options.readFileSync||fs.readFileSync,realpathSync:options.realpathSync||fs.realpathSync,statSync:options.statSync||fs.statSync,nowUTC:options.nowUTC||(()=>new Date().toISOString())};}
function deepFreeze(x){if(x&&typeof x==='object'){for(const v of Object.values(x))deepFreeze(v);Object.freeze(x);}return x;}
function validateBeforeUnseal(spec,options={}){
 // Clone once: mutable caller objects cannot replace policy bindings/null rows
 // between validation and resolution.
 const snapshot=JSON.parse(canonicalJSON(spec)),validated=validateSpec(snapshot,ioOptions(options));
 const receipt=deepFreeze({schema:'g03-b2-gate-receipt-v2',b1_groups:71,test_groups:25,supplement_groups:(snapshot.expectedSupplementIDs||[]).length,primary_policy_sha256:snapshot.primaryPolicy.sha256,projection_sha256:snapshot.projection.sha256,auxiliary_projection_sha256:snapshot.auxiliaryPolicy?.enabled?snapshot.auxiliaryProjection.sha256:null,collector_sha256:snapshot.collector.sha256,vault_sha256:snapshot.vault.sha256,b2_frozen_at:snapshot.b2Freeze.frozen_at,validation:validated});
 receipts.set(receipt,{spec:snapshot,used:false});return receipt;
}
function resolveCommittedTestRows(receipt,options={}){
 const plan=receipts.get(receipt);if(!plan||plan.used)fail('VALID_SINGLE_USE_RECEIPT_REQUIRED');plan.used=true;
 const io=ioOptions(options),spec=plan.spec;validateSpec(spec,io); // recheck public files immediately before the one private read
 const unsealStarted=io.nowUTC();if(strictUTC(unsealStarted)<strictUTC(spec.b2Freeze.frozen_at))fail('UNSEAL_CLOCK_PRECEDES_B2_FREEZE');
 const raw=readBytes(spec.vault.path,io);if(sha256Bytes(raw)!==spec.vault.sha256)fail('VAULT_COMMITMENT_SHA256_MISMATCH');
 // This is the first JSON decode of the committed vault, after byte SHA check.
 const vault=parseJSON(raw);if(!plain(vault))fail('VAULT_OBJECT_REQUIRED');sameSet(Object.keys(vault),spec.expectedTestIDs,'VAULT_UNKNOWN_OR_MISSING_TEST_GROUP');
 const resolved=JSON.parse(canonicalJSON(spec.assignments)),bySource=new Map(),seenNonces=new Set();
 for(const r of resolved)if(r.split!=='test')for(const n of nonceValues(r))seenNonces.add(n);
 for(const r of resolved){if(r.split!=='test')continue;const value=vault[r.group_id];if(!plain(value))fail('VAULT_ROW_INVALID');sameSet(Object.keys(value),['seed_int','nonce','initial_nonce','warmup_nonces'],'VAULT_ROW_FIELDS_INVALID');seed(value.seed_int);
  if(bySource.has(r.source_workload_id)&&bySource.get(r.source_workload_id)!==value.seed_int)fail('VAULT_SOURCE_WORKLOAD_SEED_MISMATCH');bySource.set(r.source_workload_id,value.seed_int);
  for(const n of nonceValues(value)){if(seenNonces.has(n))fail('VAULT_NONCE_COLLISION');seenNonces.add(n);}
  r.seed_int=value.seed_int;r.seed_hex=value.seed_int.toString(16).padStart(16,'0');r.nonce=value.nonce;r.initial_nonce=value.initial_nonce;r.warmup_nonces=[...value.warmup_nonces];
 }
 return {assignments:resolved,resolvedTestRows:resolved.filter(r=>r.split==='test'),audit:{schema:'g03-b2-unseal-audit-v1',receipt,unseal_started_utc:unsealStarted,unseal_finished_utc:io.nowUTC(),committed_vault_sha256:spec.vault.sha256,vault_bytes:raw.length,resolved_test_groups:25,source_workloads:bySource.size,vault_modified:false,only_null_test_fields_filled:true}};
}
module.exports={GateError,canonicalJSON,sha256Bytes,sha256Canonical,utcNanoseconds,validateBeforeUnseal,resolveCommittedTestRows};
