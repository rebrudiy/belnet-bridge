'use strict';
// Passive native-only checkpoint audit. Never loads assignments/test seeds,
// starts processes, fits a policy or modifies acquisition files.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const patterns={
 established_session_timeout:/\bsession to .+ timed out/i,
 pending_session_timeout:/pending session at .+ timed out/i,
 outbound_establish_timeout:/Session establish attempt to .+ timed out/i,
 fully_closed_callback:/Session to .+ fully closed/i,
 path_build_failed:/path build .* failed|path build failed/i,
 native_decrypt_error:/failed to decrypt|decrypt error/i,
 no_first_hop_candidate:/has no first hop candidate/i,
 session_established:/session with router .+ established/i,
};
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const micros=phase=>Number(phase?.unix_micros);
const offsetSeed=(main,offset)=>Number(((BigInt(main)-1n+BigInt(offset))%((1n<<48n)-1n))+1n);
const safeTime=n=>Number.isFinite(n)&&n>0?n:null;
function discoverNativeDirs(names,{qualification=false}={}){return names.filter(n=>/^b-(train|validation)-native-[a-z0-9-]+$/.test(n)||(qualification&&n==='q-native-rpc')).sort();}
function phaseScope(start,end,second){if(!Number.isFinite(second))return 'unknown_timestamp';if(second>=start&&second+1e6<=end)return 'definitely_inside_primary';if(second<end&&second+1e6>start)return 'possibly_inside_primary';return 'outside_primary';}
function censusLogs(log,start,end){
 const counts=Object.fromEntries(Object.keys(patterns).map(k=>[k,{total:0,primary_certain:0,primary_possible:0,distinct_endpoints:[]}])) ,events=[];
 for(const [index,raw]of log.split('\n').entries()){
  const line=raw.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'');const ts=line.match(/^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\]/);const second=ts?Date.parse(ts[1].replace(' ','T')+'Z')*1000:NaN,scope=phaseScope(start,end,second);
  for(const[kind,re]of Object.entries(patterns)){if(!re.test(line))continue;const endpoint=line.match(/\b10\.88\.0\.\d+:1090\b/)?.[0]||null;const c=counts[kind];c.total++;if(scope==='definitely_inside_primary')c.primary_certain++;if(scope==='definitely_inside_primary'||scope==='possibly_inside_primary')c.primary_possible++;if(endpoint&&!c.distinct_endpoints.includes(endpoint))c.distinct_endpoints.push(endpoint);events.push({line:index+1,kind,scope,utc_second:ts?.[1]||null,endpoint,text:line});}
 }
 return {counts,events,scope:'Canonical belnet.log only; duplicated container stdout is not counted',limits:['Second-resolution timestamps provide certain/possible bounds','Pending and outbound establishment messages may describe the same attempt; never add them as independent established disconnects','Message census is not a complete protocol transition or independent user-disconnect count']};
}
function expectedOperations(group){return [
 {label:'initial',nonce:group.initial_nonce,seed:offsetSeed(group.seed_int,8999),family:'rpc',duration_ms:1000},
 ...[0,1,2].map(i=>({label:'warmup-'+i,nonce:group.warmup_nonces[i],seed:offsetSeed(group.seed_int,9000+i),family:'rpc',duration_ms:1000})),
 {label:'main',nonce:group.nonce,seed:group.seed_int,family:group.family,duration_ms:45000},
 ];}
function joinOperation(expected,attempt,serviceRows,primaryStart,primaryEnd){
 const client=attempt?.data?.workload||{},matches=serviceRows.filter(x=>x.role==='native-application'&&x.workload?.nonce===expected.nonce),server=matches.length===1?matches[0].workload:null;
 const fields={family:client.family===expected.family,seed:client.seed===expected.seed,nonce:typeof expected.nonce==='string'&&/^[0-9a-f]{64}$/.test(expected.nonce)&&client.nonce===expected.nonce};
 const serverFields=server?{family:server.family===expected.family,seed:server.seed===expected.seed,nonce:server.nonce===expected.nonce,duration:server.requested_duration_ms===expected.duration_ms}:null;
 const countPairs=[['sent_messages','up_messages'],['received_messages','down_messages'],['sent_bytes','up_bytes'],['received_bytes','down_bytes']];
 const comparisons=Object.fromEntries(countPairs.map(([a,b])=>[a+'_vs_'+b,{client:client[a]??null,server:server?.[b]??null,equal:!!server&&Number.isSafeInteger(client[a])&&Number.isSafeInteger(server[b])&&client[a]>=0&&client[a]===server[b]}]));
 const uniqueJoin=matches.length===1,metadataMatch=Object.values(fields).every(Boolean)&&serverFields&&Object.values(serverFields).every(Boolean),countsExact=Object.values(comparisons).every(x=>x.equal);
 const clientStart=safeTime(client.started_unix_micros),clientEnd=safeTime(client.finished_unix_micros),serverStart=safeTime(server?.started_unix_micros),serverEnd=safeTime(server?.finished_unix_micros);
 const intervalsValid=!!clientStart&&!!clientEnd&&clientEnd>=clientStart&&!!serverStart&&!!serverEnd&&serverEnd>=serverStart;
 const cleanClient=client.invalid_messages===0&&Array.isArray(client.errors)&&client.errors.length===0&&!attempt?.data?.error;
 const proof=uniqueJoin&&metadataMatch&&countsExact&&intervalsValid&&cleanClient&&attempt?.code===0;
 const times={client_started_unix_micros:clientStart,client_finished_unix_micros:clientEnd,server_started_unix_micros:serverStart,server_finished_unix_micros:serverEnd,client_duration_ms:clientStart&&clientEnd?(clientEnd-clientStart)/1000:null,server_duration_ms:serverStart&&serverEnd?(serverEnd-serverStart)/1000:null,server_underrun_ms:serverStart&&serverEnd?Math.max(0,expected.duration_ms-(serverEnd-serverStart)/1000):null,client_end_offset_ms:clientEnd?(clientEnd-primaryStart)/1000:null,server_end_offset_ms:serverEnd?(serverEnd-primaryStart)/1000:null,whole_operation_inside_primary:intervalsValid&&Math.min(clientStart,serverStart)>=primaryStart&&Math.max(clientEnd,serverEnd)<=primaryEnd};
 return {label:expected.label,expected,attempt_present:!!attempt,client_exit_code:attempt?.code??null,client_error:attempt?.data?.error||null,client_errors:client.errors||[],client_invalid_messages:client.invalid_messages??null,service_nonce_matches:matches.length,client_fields_match:fields,server_fields_match:serverFields,counts:comparisons,unique_nonce_count_and_metadata_proof:!!proof,client_completed_duration:client.completed_duration===true,server_completed_duration:server?.completed_duration??null,duration_flags_disagree:!!server&&client.completed_duration!==server.completed_duration,server_error_kind:server?.error_kind||null,strict_both_endpoints_duration_complete:proof&&client.completed_duration===true&&server.completed_duration===true,times,client_rpc_verified:client.rpc_verified??null,unanswered_RPC_requests:expected.family==='rpc'&&Number.isSafeInteger(client.sent_messages)&&Number.isSafeInteger(client.received_messages)?Math.max(0,client.sent_messages-client.received_messages):null,client_download_integrity:expected.family==='download'?{verified_chunks_reported:client.download_pattern_verified_messages??null,received_sha256:client.download_received_sha256||null,status:client.integrity_status||null,invalid_messages:client.invalid_messages??null,scope:'Instrumented client reports pattern verification and received SHA; this auditor does not rehash absent raw application bytes'}:null};
}
function parseProcStats(stdout){return stdout.split('\n').flatMap(line=>{const m=line.match(/^(\d+) \((.*)\) (.+)$/);if(!m)return [];const f=m[3].trim().split(/\s+/);return f.length>19?[{pid:Number(m[1]),name:m[2],state:f[0],starttick:f[19]}]:[];});}
function snapshotBounds(snapshot){
 const begin=snapshot.clock?.unix_micros,end=snapshot.snapshot_finished?.unix_micros;
 if(!Number.isFinite(end))return {available:false,valid:null,scope:'Legacy snapshot has no recorded VM end bound'};
 const states=[...(snapshot.clients||[]),...(snapshot.servers||[])].map(x=>x.snapshot_unix_micros);
 return {available:true,begin_unix_micros:begin,end_unix_micros:end,valid:Number.isFinite(begin)&&end>=begin&&states.length===4&&states.every(x=>Number.isFinite(x)&&x>=begin&&x<=end),endpoint_state_timestamps:states};
}
function auditProcesses(snapshots,adapterPIDs){
 const rows=snapshots.map(s=>({label:s.label,at_unix_micros:s.clock?.unix_micros,snapshot_finished_unix_micros:s.snapshot_finished?.unix_micros??null,VM_bounds:snapshotBounds(s),command_ok:s.native_process?.code===0,native_executable:(s.native_process?.stdout||'').split('\n').find(l=>l==='/usr/local/bin/belnet')||null,processes:parseProcStats(s.native_process?.stdout||'')}));
 const valid=rows.length>0&&rows.every(x=>x.command_ok&&x.native_executable==='/usr/local/bin/belnet'&&x.processes.length===3&&x.processes.every(p=>p.state!=='Z'));
 const identities=[0,1,2].map(i=>({role:i===0?'native':'adapter'+i,identities:[...new Set(rows.map(r=>r.processes[i]?r.processes[i].pid+':'+r.processes[i].starttick:null))]}));
 return {samples:rows,VM_bounds_complete_and_valid:rows.length>0&&rows.every(r=>r.VM_bounds.valid===true),continuous_at_samples:valid&&identities.every(x=>x.identities.length===1&&!x.identities.includes(null)),identities,adapter_pid_files_match:valid&&rows.every(r=>r.processes[1].pid===adapterPIDs[0]&&r.processes[2].pid===adapterPIDs[1]),scope:'PID/starttick equality at saved checkpoints only; no assertion about every instant or process lifetime after last sample'};
}
function parseFirewall(stdout){
 const lines=stdout.split('\n');const drop=lines.find(l=>/^-?\[\d+:\d+\] -A OUTPUT -o eth0 -p udp -m udp --dport 1090 -j DROP$/.test(l));
 const match=drop?.match(/^\[(\d+):(\d+)\]/);
 const dnat=[1,2].map(i=>lines.some(l=>new RegExp(' -A OUTPUT -d 10\\.88\\.0\\.'+(10+i)+'/32 -p udp -m udp --dport 1090 -j DNAT --to-destination 127\\.0\\.0\\.1:209'+i+'$').test(l)));
 return {drop_rule_present:!!drop,drop_packets:match?Number(match[1]):null,drop_bytes:match?Number(match[2]):null,entry1_DNAT_present:dnat[0],entry2_DNAT_present:dnat[1]};
}
const counters=['up_bytes','down_bytes','up_datagrams','down_datagrams','expired_datagrams','expired_bytes','failed_write_datagrams','failed_write_bytes','local_queue_dropped','receiver_queue_dropped'];
const compactConn=c=>c?Object.fromEntries(['id','session_hash','udp_tuple','connected','opened_unix_micros','closed_unix_micros','max_queue_wait_micros','max_blocked_write_micros',...counters].filter(k=>c[k]!==undefined).map(k=>[k,c[k]])):null;
function auditStreams(snapshots){
 const entries=[];
 for(let entry=0;entry<2;entry++){
  const clientSID=[...new Set(snapshots.flatMap(s=>(s.clients?.[entry]?.connections||[]).map(c=>c.session_hash)).filter(Boolean))];
  const sid=clientSID.length===1?clientSID[0]:null,observations=snapshots.map(s=>{const clientState=s.clients?.[entry]||{},serverState=s.servers?.[entry]||{};const clients=(clientState.connections||[]).filter(c=>clientSID.includes(c.session_hash)),servers=(serverState.connections||[]).filter(c=>clientSID.includes(c.session_hash));return {label:s.label,client_state_at:clientState.snapshot_unix_micros,server_state_at:serverState.snapshot_unix_micros,metadata_truncated:clientState.metadata_truncated!==false||serverState.metadata_truncated!==false,client:clients.map(compactConn),server:servers.map(compactConn),client_disconnect_events:(clientState.disconnects||[]).filter(e=>!e.session_hash||clientSID.includes(e.session_hash)),server_disconnect_events:(serverState.disconnects||[]).filter(e=>!e.session_hash||clientSID.includes(e.session_hash))};});
  const all=observations.flatMap(o=>[...o.client,...o.server]),clientIDs=[...new Set(observations.flatMap(o=>o.client.map(c=>c.id+':'+c.opened_unix_micros)))],serverIDs=[...new Set(observations.flatMap(o=>o.server.map(c=>c.id+':'+c.opened_unix_micros)))],serverTuples=[...new Set(observations.flatMap(o=>o.server.map(c=>c.udp_tuple)))];
  const historical=[...new Set(snapshots.flatMap(s=>(s.servers?.[entry]?.connections||[]).filter(c=>!clientSID.includes(c.session_hash)).map(c=>c.session_hash)))];
  const last=observations.at(-1),lastClient=last?.client.at(-1),lastServer=last?.server.at(-1);
  const monotonic=observations.every((o,i)=>i===0||counters.every(k=>o.client[0]?.[k]===undefined||observations[i-1].client[0]?.[k]===undefined||o.client[0][k]>=observations[i-1].client[0][k]));
  entries.push({entry:entry+1,current_client_SIDs:clientSID,current_SID:sid,observations,excluded_historical_server_SIDs:historical,client_stream_identities:clientIDs,server_stream_identities:serverIDs,receiver_UDP_tuples:serverTuples,continuous_at_samples:!!sid&&observations.length>0&&observations.every(o=>!o.metadata_truncated&&o.client.length===1&&o.server.length===1&&o.client[0].connected===true&&o.server[0].connected===true)&&clientIDs.length===1&&serverIDs.length===1&&serverTuples.length===1,client_counters_monotonic:monotonic,last_client:lastClient||null,last_server:lastServer||null,last_client_server_counters_equal:!!lastClient&&!!lastServer&&['up_bytes','down_bytes','up_datagrams','down_datagrams'].every(k=>lastClient[k]===lastServer[k]),current_stream_closed_records:new Set(all.filter(c=>c.closed_unix_micros).map(c=>c.session_hash+':'+c.id+':'+c.opened_unix_micros)).size});
 }
 return {entries,scope:'Current client SID filters persistent server state. Counters use only latest matching sample, never sum cumulative snapshots or previous groups.',continuous_at_samples:entries.every(e=>e.continuous_at_samples),latest_client_totals:Object.fromEntries(counters.map(k=>[k,entries.reduce((n,e)=>n+(e.last_client?.[k]||0),0)]))};
}
function pcapRecordCount(b){
 if(b.length<24)throw Error('truncated PCAP global header');const magic=b.readUInt32LE(0);if(magic!==0xa1b2c3d4)throw Error('unsupported PCAP endian/time format');if(b.readUInt16LE(4)!==2||b.readUInt16LE(6)!==4||b.readUInt32LE(16)===0)throw Error('invalid PCAP version/snaplen');if(b.readUInt32LE(20)!==1)throw Error('leak PCAP must be Ethernet');let packets=0;for(let at=24;at<b.length;){if(at+16>b.length)throw Error('truncated PCAP packet header');const cap=b.readUInt32LE(at+8);at+=16;if(at+cap>b.length)throw Error('truncated PCAP packet body');at+=cap;packets++;}return packets;
}
function captureSummary(capture){return {name:capture.name,captured:capture.captured,received_by_filter:capture.received_by_filter,dropped_by_kernel:capture.dropped_by_kernel,capped:capture.capped,incomplete:capture.incomplete,accounting_status:capture.capture_accounting_status||'unknown_missing_status',coverage_claim:!capture.incomplete&&!capture.capped&&capture.capture_accounting_status==='reconciled_complete'?'metadata_reconciled':'UNKNOWN_NOT_PROMOTED_TO_PASS'};}
function udpWindowCounts(snapshots,start){
 const latest=snapshots.at(-1),states=latest?.clients||[],clocks=states.map(s=>s.snapshot_unix_micros).filter(Number.isFinite),coverageEnd=clocks.length===2?Math.min(...clocks):null;
 const events=states.flatMap(s=>{const ids=new Set((s.connections||[]).map(c=>c.session_hash));return(s.packet_events||[]).filter(e=>ids.has(e.session_hash));});
 return [0,8,16,24,32,40,48,56,64,72,78].map(offset=>{const lo=start+offset*1e6,hi=lo+2e6,rows=events.filter(e=>e.at_unix_micros>=lo&&e.at_unix_micros<hi);return{offset_seconds:offset,up_datagrams_observed:rows.filter(e=>e.direction===1).length,down_datagrams_observed:rows.filter(e=>e.direction===-1).length,up_bytes_observed:rows.filter(e=>e.direction===1).reduce((n,e)=>n+e.bytes,0),down_bytes_observed:rows.filter(e=>e.direction===-1).reduce((n,e)=>n+e.bytes,0),state_evidence_covers_entire_window:coverageEnd!==null&&hi<=coverageEnd,sampled_state_end_unix_micros:coverageEnd,scope:'Latest client event metadata only; coverage ends at minimum actual state timestamp without extrapolation'}});
}
function audit(directory,{qualification=false}={}){
 const inputs={},read=file=>{const absolute=path.join(directory,file),bytes=fs.readFileSync(absolute);inputs[absolute]=sha(bytes);return bytes;};
 const collector=qualification?'../../runtime-v2/collect.cjs':'../../runtime/collect.cjs';
 if(fs.existsSync(path.resolve(directory,collector)))read(collector);
 const serviceLog=qualification?'bb-g03-service.log':'service.log';
 const serviceRaw=read(serviceLog).toString(),serviceRows=[],serviceParseErrors=[];
 serviceRaw.split('\n').forEach((line,i)=>{if(!line.trim())return;try{serviceRows.push(JSON.parse(line));}catch(e){serviceParseErrors.push({line:i+1,error:e.message});}});
 const names=discoverNativeDirs(fs.readdirSync(directory),{qualification}),groups=[],notCompleted=[];
 for(const id of names){
  if(!fs.existsSync(path.join(directory,id,'result.json'))){notCompleted.push({id,status:'no completed result; descriptors not read, excluded attempts denominator'});continue;}
  const result=JSON.parse(read(id+'/result.json'));if(!['train','validation'].includes(result.group?.split)&&!(qualification&&id==='q-native-rpc'&&result.group?.split==='development'))throw Error('Refuse sealed/test group');if(result.group?.stratum!=='native'||result.group?.class!=='belnet')throw Error('Not a native positive');
  const start=micros(result.measurement_start),end=start+80e6,expected=expectedOperations(result.group),operations=expected.map(e=>joinOperation(e,result.workloads.find(w=>w.label===e.label),serviceRows,start,end));
  const processes=auditProcesses(result.snapshots,[1,2].map(n=>Number(read(id+'/adapter'+n+'.pid').toString().trim()))),streams=auditStreams(result.snapshots),firewall=result.snapshots.map(s=>({label:s.label,command_ok:s.native_firewall?.code===0,...parseFirewall(s.native_firewall?.stdout||'')}));
  const rawLeak=read(id+'/native-raw-udp.pcap'),leakPackets=pcapRecordCount(rawLeak),captures=result.captures.map(captureSummary),logs=censusLogs(read(id+'/belnet.log').toString(),start,end);
  // Raw outer bytes are hashed as evidence only: no TLS feature extraction,
  // model fitting or test policy reads occur in this audit.
  read(id+'/outer.pcap');read(id+'/observer-meta.json');
  groups.push({id,split:result.group.split,family:result.group.family,scope:'Completed native checkpoint only; separate initial failure, nonce evidence, sampled continuity and capture UNKNOWN',primary_start_unix_micros:start,primary_end_unix_micros:end,recorded_measurement_end_unix_micros:micros(result.measurement_end),recorded_end_offset_ms:(micros(result.measurement_end)-start)/1000,operations,processes,streams,firewall:{snapshots:firewall,rules_present_every_sample:firewall.length>0&&firewall.every(f=>f.command_ok&&f.drop_rule_present&&f.entry1_DNAT_present&&f.entry2_DNAT_present),final_drop_packets:firewall.at(-1)?.drop_packets,note:'DROP counters are attempted raw packets blocked before eth0, not proof that all native connection attempts succeeded'},raw_UDP_leak:{pcap_bytes:rawLeak.length,saved_packets:leakPackets,observed_zero_packets:leakPackets===0,scope:'Native eth0 udp port1090 only; captured0 is an observation, not blanket absence of BelNet errors'},udp_primary_windows:udpWindowCounts(result.snapshots,start),captures,native_log_census:logs});
 }
 const ops=groups.flatMap(g=>g.operations),nonceCounts=new Map();for(const op of ops)nonceCounts.set(op.expected.nonce,(nonceCounts.get(op.expected.nonce)||0)+1);for(const op of ops){op.expected_nonce_reused=nonceCounts.get(op.expected.nonce)!==1;if(op.expected_nonce_reused){op.unique_nonce_count_and_metadata_proof=false;op.strict_both_endpoints_duration_complete=false;}}return{schema:'g03-native-checkpoint-audit-v2',qualification_opt_in:qualification,service_log:serviceLog,run_directory:path.resolve(directory),read_only:true,no_sealed_test_seed_files_read:true,completed_native_groups:groups.length,not_completed_directories:notCompleted,summary:{attempts:ops.length,all_expected_nonces_unique:ops.every(o=>!o.expected_nonce_reused),initial_DNS_failures:ops.filter(o=>o.label==='initial'&&o.client_exit_code!==0&&/connection refused/.test(o.client_error||'')).length,unique_nonce_exact_count_metadata_proofs:ops.filter(o=>o.unique_nonce_count_and_metadata_proof).length,client_duration_completed:ops.filter(o=>o.client_completed_duration).length,server_duration_completed:ops.filter(o=>o.server_completed_duration===true).length,duration_flag_disagreements:ops.filter(o=>o.duration_flags_disagree).length,proof_with_both_duration_flags_complete:ops.filter(o=>o.strict_both_endpoints_duration_complete).length,all_sampled_PID_and_SID_continuous:groups.every(g=>g.processes.continuous_at_samples&&g.streams.continuous_at_samples),raw_UDP_leak_packets:groups.reduce((n,g)=>n+g.raw_UDP_leak.saved_packets,0),capture_status:'UNKNOWN_RETAINED; no full coverage or DPI evasion PASS',independent_user_disconnects:'not inferred from message counts',native_log_counts:Object.fromEntries(Object.keys(patterns).map(k=>[k,groups.reduce((n,g)=>n+g.native_log_census.counts[k].total,0)]))},groups,service_parse_errors:serviceParseErrors,input_sha256:inputs,limits:['Only selected completed native checkpoint groups; not the full B1/B2 cohort','Initial DNS refusal is retained as failed attempt, not silently dropped','Unique nonce/exact counters prove bounded recorded application delivery, not Internet/ISP indistinguishability','Server/client clocks are Linux VM UTC; process/log samples are not continuous tracing','No all-BelNet-errors-absent claim; pending/outbound/first-hop failures are explicit','Capture metadata UNKNOWN is not upgraded; windows without sufficient state timestamps remain UNKNOWN despite application success']};
}
if(require.main===module){if(!process.argv[2])throw Error('Use stopped RUN_DIR');process.stdout.write(JSON.stringify(audit(path.resolve(process.argv[2]),{qualification:process.argv.includes('--qualification')}),null,2)+'\n');}
module.exports={discoverNativeDirs,phaseScope,censusLogs,expectedOperations,joinOperation,parseProcStats,snapshotBounds,auditProcesses,parseFirewall,auditStreams,pcapRecordCount,captureSummary,udpWindowCounts,audit};
