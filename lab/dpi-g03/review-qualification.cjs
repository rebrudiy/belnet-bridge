"use strict";
// Independent acquisition checks for the finite diagnostic Q batch; never fits.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const { inspectPCAP, pinLocation } = require("./review-checkpoint.cjs");
const sha = raw => crypto.createHash("sha256").update(raw).digest("hex");
function audit(run, freezePath) {
 const inputs = [], read = p => {const raw=fs.readFileSync(p);inputs.push({path:path.resolve(p),sha256:sha(raw),bytes:raw.length});return raw;};
 const frozenRaw=read(freezePath),f=JSON.parse(frozenRaw),freezeSHA=sha(frozenRaw);
 if(f.schema!=="belnet-g03-collector/v2"||f.stage!=="Q"||f.test_seeds_commitment!==null||f.groups?.length!==3||f.groups.some(g=>g.split!=="development"||g.scope!=="diagnostic"||!/^q-/.test(g.group_id)))throw Error("finite_diagnostic_Q_only_no_test_or_calibration");
 const errors=[],pins=[];
 if(f.measured_seconds!==80||f.capture_seconds!==82||f.quiesce_after_seconds!==82||f.quiesce_drain_micros!==500000)errors.push("frozen_Q_timing_mismatch");
 for(const [relative,expected]of Object.entries(f.files_sha256)){
  const loc=pinLocation(f,relative);try{const actual=sha(read(loc.filename));pins.push({path:relative,kind:loc.kind,expected,actual,matches:expected===actual});if(actual!==expected)errors.push("pin_mismatch:"+relative);}catch(e){errors.push("pin_read_failure:"+relative+":"+e.message);}
 }
 const groups=[];
 for(const g of f.groups){
  const dir=path.join(run,g.group_id),issues=[];
  const r=JSON.parse(read(path.join(dir,"result.json"))),o=JSON.parse(read(path.join(dir,"windows.json"))),l=JSON.parse(read(path.join(dir,"longflow.json")));
  const pcap=inspectPCAP(read(path.join(dir,"outer.pcap"))),outer=r.captures.filter(c=>/-capture$/.test(c.name));
  if(!isDeepStrictEqual(g,r.group))issues.push("assignment_mismatch");
  if(r.errors?.length)issues.push(...r.errors.map(e=>"collector:"+e));
  if(outer.length!==1)issues.push("outer_capture_count");
  const c=outer[0];
  if(!c||c.captured!==pcap.packets||c.bytes!==pcap.bytes||c.received_by_filter!==pcap.packets||c.dropped_by_kernel!==0||c.capped||c.forced_cleanup||c.code!==0||c.signal||pcap.truncated_packets)issues.push("outer_capture_accounting_or_lifecycle");
  if(o.schema!==4||o.version!=="g03-observer-v2"||l.schema!==2||l.version!=="g03-longflow-v2")issues.push("report_schema_or_version");
  if(o.pcap_sha256!==pcap.sha256||l.pcap_sha256!==pcap.sha256)issues.push("report_raw_binding");
  if(o.ordering_semantics_sha256!==l.ordering_semantics_sha256)issues.push("ordering_contract_mismatch");
  for(const report of [o,l])if(report.metadata?.freeze_sha256!==freezeSHA||report.metadata?.group_id!==g.group_id||report.metadata?.split!=="development"||report.metadata?.measurement_start_unix_micros!==r.measurement_start?.unix_micros)issues.push("report_frozen_metadata_mismatch");
  if(!o.coverage_complete||!l.source_observer_coverage_complete||l.collector_flow_censored||l.collector_omitted_flow_records)issues.push("observer_or_longflow_coverage");
  for(const name of ["observer_process","longflow_process"])if(r[name]?.code!==0||r[name]?.signal)issues.push(name+"_failed");
  const start=r.measurement_start?.unix_micros,q=r.quiesce,drain=r.drain_end?.unix_micros,end=r.capture_end?.unix_micros;
  if(!Number.isSafeInteger(start)||!Number.isSafeInteger(q?.started_unix_micros)||!Number.isSafeInteger(q?.finished_unix_micros)||!Number.isSafeInteger(drain)||!Number.isSafeInteger(end)||q.started_unix_micros-start<82_000_000||drain-q.finished_unix_micros<500_000||end<drain||r.capture_start?.unix_micros>start||q.result!=="ok"||q.process_code!==0)issues.push("VM_horizon_quiesce_or_drain");
  if(g.client_stack==="chrome"&&(!r.browser_acquisition_complete||r.browser?.code!==0||r.browser?.signal||r.browser_teardown?.result!=="exited"||r.browser_teardown?.signals?.length||r.browser_teardown?.errors?.length))issues.push("browser_acquisition_or_teardown");
  let nativeFinal=null;
  if(g.class==="belnet"){
   const snap=r.snapshots.find(s=>s.label==="t81000");nativeFinal=snap?{started:snap.clock?.unix_micros,finished:snap.snapshot_finished?.unix_micros}:null;
   if(!snap||!Number.isSafeInteger(nativeFinal.started)||!Number.isSafeInteger(nativeFinal.finished)||nativeFinal.started<start+80_000_000||nativeFinal.finished>=q.started_unix_micros)issues.push("native_postprimary_snapshot_unverified");
  }
  groups.push({group_id:g.group_id,qualified:issues.length===0,errors:issues,outer:pcap,observer_coverage:o.coverage_complete,longflow_coverage:l.source_observer_coverage_complete,flow_count:o.flows.length,masked_windows:o.windows.filter(w=>w.ordering_ambiguous).length,quiesce_offset_micros:q.started_unix_micros-start,drain_micros:drain-q.finished_unix_micros,native_final_snapshot:nativeFinal,browser_teardown_ms:r.browser_teardown?.elapsed_ms??null,observer_issues:[...new Set(o.flows.flatMap(f=>f.issues||[]))]});
 }
 const auditorSHA=sha(read(__filename));
 return {schema:"g03-independent-Q-audit/v1",checked_utc:new Date().toISOString(),auditor_sha256:auditorSHA,stage:"Q",qualified:errors.length===0&&groups.every(g=>g.qualified),errors,pins,groups,inputs,detector_fitting_allowed:false,limitations:["Diagnostic development acquisition only; excluded from B1/B2 denominators", "No classifier scoring, native operation attribution, FPR or realISP proof", "Independent raw PCAP structure/hash/count/time/source checks; TCP/TLS semantic coverage comes from pinned reporters", "Auxiliary loopback UDP filter counters have separate semantics; this audit qualifies upstream TCP443 only"]};
}
if(require.main===module){const [run,freeze,out]=process.argv.slice(2);if(!run||!freeze||!out)throw Error("usage: node review-qualification.cjs RUN FREEZE NEW_OUTPUT");const r=audit(run,freeze);fs.writeFileSync(out,JSON.stringify(r,null,2)+"\n",{flag:"wx",mode:0o600});console.log(JSON.stringify({qualified:r.qualified,pins:r.pins.length,errors:r.errors,groups:r.groups.map(g=>({id:g.group_id,qualified:g.qualified,errors:g.errors,packets:g.outer.packets}))}));process.exitCode=r.qualified?0:2;}
module.exports={audit};
