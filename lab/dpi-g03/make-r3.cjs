"use strict";
const fs=require("node:fs"),crypto=require("node:crypto");
const {validate}=require("./make-assignments.cjs");
const sha=raw=>crypto.createHash("sha256").update(raw).digest("hex");
function derive(mode,source,master,extraPlans=[],fresh=()=>crypto.randomBytes(32).toString("hex")){
 if(!["qualification","b1"].includes(mode))throw Error("explicit_R3_mode_required");
 validate(source);
 if(master.stage!=="B1"||!/^[a-f0-9]{64}$/.test(master.test_seeds_commitment?.sha256||""))throw Error("existing_test_commitment_required");
 const used=new Set([source,...extraPlans].flatMap(p=>(p.groups||[]).filter(g=>g.split!=="test").flatMap(g=>[g.nonce,g.initial_nonce,...(g.warmup_nonces||[])])).filter(Boolean));
 function nonce(){const n=fresh();if(!/^[a-f0-9]{64}$/.test(n)||used.has(n))throw Error("fresh_nonce_collision_or_invalid");used.add(n);return n;}
 function refresh(group){return {...structuredClone(group),nonce:nonce(),initial_nonce:nonce(),warmup_nonces:[nonce(),nonce(),nonce()]};}
 const shutdown={immediate_mode:true,min_postquiesce_drain_micros:500000,stats_observation_budget_ms:2500,required_identical_healthy_stats:2,stats_semantics:"SIGUSR1 reports counters; it does not flush kernel capture. Final LAST statistics still must reconcile."};
 if(mode==="qualification"){
  const selected=[["b-train-native-download-1","q-native-download"],["b-train-public-google","q-chrome-google"],["b-train-long-idle-2","q-go-idle"]];
  const groups=selected.map(([id,qid])=>{const g=source.groups.find(g=>g.group_id===id);if(!g||g.split!=="train")throw Error("qualification_source_missing");return {...refresh(g),qualification_source_group_id:id,group_id:qid,source_workload_id:"q-r3-"+g.source_workload_id,scope:"diagnostic",split:"development"};});
  const order=groups.map(g=>g.group_id);
  return {schema:"belnet-g03-qualification/v1",revision:"R3",stage:"Q",test_vault_required:false,detector_fitting_allowed:false,purpose:"One80s heavy-native-DOWNLOAD/ChromeGoogle/GoIdle capture qualification; excluded from B1/B2",primary_seconds:80,capture_seconds:82,prefix_grace_seconds:2,window_offsets_seconds:source.window_offsets_seconds,window_seconds:2,resource_limits:source.resource_limits,capture_shutdown:shutdown,stages:{Q:{splits:["development"],count:3,order,batches:[order]}},groups};
 }
 const result=structuredClone(source);result.groups=result.groups.map(g=>g.split==="test"?g:refresh(g));
 result.revision={id:"R3",physical_acquisition:"All71 train/validation groups are new; prior15 and24 stopped groups remain collector development, never calibration",changed:"355 fresh CSPRNG nonces; capture immediate-mode/statistics shutdown revision",unchanged:"All workload source seeds, source partitions, groups/batches and25 sealed test rows"};
 result.capture_shutdown=shutdown;result.seeds.test_seed_commitment_sha256=master.test_seeds_commitment.sha256;
 result.seeds.train_validation_nonces="R3 CSPRNG355 unique values, disjoint from supplied public prior plans; pinned before acquisition";
 validate(result);return result;
}
if(require.main===module){
 const [mode,sourcePath,masterPath,output,...previous]=process.argv.slice(2);if(!output)throw Error("usage: node make-r3.cjs qualification|b1 SOURCE R2_MASTER NEW_OUTPUT [PREVIOUS_PUBLIC_PLANS...]");
 const sourceRaw=fs.readFileSync(sourcePath),masterRaw=fs.readFileSync(masterPath),extra=previous.map(p=>JSON.parse(fs.readFileSync(p)));
 const result=derive(mode,JSON.parse(sourceRaw),JSON.parse(masterRaw),extra);
 result.lineage={created_utc:new Date().toISOString(),source_assignments_sha256:sha(sourceRaw),parent_collector_sha256:sha(masterRaw),generator_sha256:sha(fs.readFileSync(__filename)),prior_public_plans:previous.map(p=>({path:p,sha256:sha(fs.readFileSync(p))})),private_test_values_read:false};
 fs.writeFileSync(output,JSON.stringify(result,null,2)+"\n",{flag:"wx",mode:0o644});
 console.log(JSON.stringify({output,mode,sha256:sha(fs.readFileSync(output)),groups:result.groups.length,test_values_read:false}));
}
module.exports={derive};
