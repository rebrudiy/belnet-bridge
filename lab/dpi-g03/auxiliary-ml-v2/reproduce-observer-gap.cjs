// Synthetic-only: demonstrate why consumers validate physical primary payload
// handshakes independently of sampled windows. No network, capture or fitting.
const fs=require('fs'),path=require('path'),cp=require('child_process');
const base='lab/dpi-g03/auxiliary-ml-v2/tooling/coverage-regression';fs.mkdirSync(base,{recursive:true});
const parts=[];const head=Buffer.alloc(24);head.writeUInt32LE(0xa1b23c4d);head.writeUInt16LE(2,4);head.writeUInt16LE(4,6);head.writeUInt32LE(262144,16);head.writeUInt32LE(1,20);parts.push(head);
const epoch=1700000000;
function record(kind){const r=Buffer.alloc(26);r[0]=kind;r[1]=3;r[2]=3;r.writeUInt16BE(21,3);return r;}
function tcp(offset,port,d,seq,flags,payload=Buffer.alloc(0)){
 const b=Buffer.alloc(54+payload.length);b.writeUInt16BE(0x0800,12);b[14]=0x45;b.writeUInt16BE(40+payload.length,16);b[23]=6;
 Buffer.from(d===1?[10,0,0,1,10,0,0,2]:[10,0,0,2,10,0,0,1]).copy(b,26);
 b.writeUInt16BE(d===1?port:443,34);b.writeUInt16BE(d===1?443:port,36);b.writeUInt32BE(seq,38);b[46]=0x50;b[47]=flags;payload.copy(b,54);
 const h=Buffer.alloc(16);h.writeUInt32LE(epoch+Math.floor(offset));h.writeUInt32LE(Math.round((offset%1)*1e9),4);h.writeUInt32LE(b.length,8);h.writeUInt32LE(b.length,12);parts.push(h,b);
}
tcp(0,30000,1,100,2);tcp(.001,30000,-1,400,18);tcp(1,30000,1,101,24,record(23));
tcp(3,30001,1,200,2);tcp(3.001,30001,1,201,24,record(22));tcp(4,30001,-1,0,20);
const pcap=path.join(base,'synthetic.pcap');fs.writeFileSync(pcap,Buffer.concat(parts));
const start=new Date(epoch*1000).toISOString(),end=new Date((epoch+82)*1000).toISOString();
const meta={group_id:'synthetic-short-hello-gap',split:'train',class:'benign',profile:'synthetic-only',scope:'primary',source_workload_id:'synthetic-only',transport:'ordinary-tls',client_stack:'fixture',server_ports:[443],capture_started_utc:start,capture_ended_utc:end,capture_cap_bytes:268435456,capture_cap_hit:false,packets_dropped:0,freeze_sha256:'c'.repeat(64),measured_seconds:80,measurement_start_unix_micros:epoch*1e6,prefix_grace_seconds:2,window_offsets_seconds:[0,8,16,24,32,40,48,56,64,72,78]};
const metadata=path.join(base,'meta.json'),output=path.join(base,'observer.json');fs.writeFileSync(metadata,JSON.stringify(meta,null,2)+'\n');
const manifest=JSON.parse(fs.readFileSync('lab/dpi-g03/observer-v3/tooling/TOOLING.json'));
cp.execFileSync(path.resolve(manifest.binary.observer.versioned_path),['-pcap',pcap,'-meta',metadata,'-out',output]);
const r=JSON.parse(fs.readFileSync(output));const failed=r.flows.find(f=>f.five_tuple.client_port===30001);
const findings={synthetic_only:true,observer_binary_sha256:manifest.binary.observer.sha256,observer_coverage_complete:r.coverage_complete,failed_flow_primary:failed.primary_scope,failed_flow_raw_payload:failed.raw_tcp_payload_bytes_including_retransmits,failed_flow_issues:failed.issues,failed_flow_window_statuses:failed.windows.map(w=>w.status),conclusion:'V3 consumer must independently reject primary payload without complete captured handshake even between sampled windows. Frozen observer retained unchanged.'};
fs.writeFileSync(path.join(base,'findings.json'),JSON.stringify(findings,null,2)+'\n');console.log(JSON.stringify(findings,null,2));
if(!r.coverage_complete || !failed.primary_scope || failed.raw_tcp_payload_bytes_including_retransmits!==26 || !failed.issues.includes('missing_syn_ack'))process.exitCode=1;
// If the prospective V4 tool is ready, prove the same bytes become UNKNOWN.
const fixedManifestPath='lab/dpi-g03/observer-v4/tooling/TOOLING.json';
if(fs.existsSync(fixedManifestPath)){
 const fixedManifest=JSON.parse(fs.readFileSync(fixedManifestPath));
 const fixedOutput=path.join(base,'observer-v4.json');
 cp.execFileSync(path.resolve(fixedManifest.binary.observer.versioned_path),['-pcap',pcap,'-meta',metadata,'-out',fixedOutput]);
 const fixed=JSON.parse(fs.readFileSync(fixedOutput));
 const comparison={synthetic_only:true,same_pcap_sha256:r.pcap_sha256===fixed.pcap_sha256,old_version:r.version,new_version:fixed.version,new_binary_sha256:fixedManifest.binary.observer.sha256,old_coverage_complete:r.coverage_complete,new_coverage_complete:fixed.coverage_complete,new_global_reasons:fixed.global_coverage_reasons,counter_values_equal:JSON.stringify(r.counters)===JSON.stringify(fixed.counters),same_coverage_contract:r.coverage_semantics_sha256===fixed.coverage_semantics_sha256,same_ordering_contract:r.ordering_semantics_sha256===fixed.ordering_semantics_sha256};
 fs.writeFileSync(path.join(base,'v4-comparison.json'),JSON.stringify(comparison,null,2)+'\n');
 if(fixed.coverage_complete || !fixed.global_coverage_reasons.includes('primary_payload_with_missing_handshake') || !comparison.same_pcap_sha256 || !comparison.counter_values_equal)process.exitCode=1;
}
