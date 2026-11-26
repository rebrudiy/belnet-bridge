"use strict";
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),crypto=require('node:crypto');
const {Capture}=require('../../dpi-g02/runtime/capture.cjs');
const {exec}=require('../../dpi-g02/runtime/common.cjs');
const {wireSummary}=require('./wire.cjs');
const ROOT=path.resolve(__dirname,'../../..'),hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const save=(p,v)=>fs.writeFileSync(p,JSON.stringify(v,null,2)+'\n',{mode:0o600});
const wait=ms=>new Promise(r=>setTimeout(r,ms));
async function main(){
 const id=process.argv[2];if(!/^[a-z0-9-]{1,24}$/.test(id||''))throw Error('explicit_new_dev_id_required');
 const prefix='bb-g03-quiesce-'+id,network=prefix,run=path.join(ROOT,'out/dpi-g03/quiesce-preflight',id);
 if(fs.existsSync(run))throw Error('refusing_existing_attempt');fs.mkdirSync(run,{recursive:true,mode:0o700});
 const prep=JSON.parse(fs.readFileSync(path.join(ROOT,'lab/dpi-g01/run/prepared-a/preparation.json'))),image=prep.runtime_image;
 const controls=path.join(ROOT,'out/dpi-g03/tooling/v2/bin'),adapter=path.join(ROOT,'lab/dpi-g02/bin/belnet-bridge-a2-v1');
 const tooling=JSON.parse(fs.readFileSync(path.join(ROOT,'lab/dpi-g03/quiesce-proxy/TOOLING.json'))),proxy=tooling.binary.path;
 if(hash(proxy)!==tooling.binary.sha256)throw Error('proxy_binary_drift');
 const existing=JSON.parse((await exec(['docker','network','inspect',...(await exec(['docker','network','ls','-q'])).stdout.trim().split(/\s+/)])).stdout);
 if(existing.some(n=>(n.IPAM?.Config||[]).some(c=>c.Subnet==='172.30.93.0/24')))throw Error('reserved_subnet_already_used');
 const build=await exec(['env','GOWORK=off','GOPROXY=off','GOOS=linux','GOARCH=arm64','CGO_ENABLED=0','go','build','-trimpath','-o',path.join(run,'udp'),path.join(__dirname,'udp.go')],{timeout:60000});save(path.join(run,'build.json'),build);
 const cases=['ordinary','reality'];
 for(const kind of cases){
  const dir=path.join(run,kind);fs.mkdirSync(dir,{mode:0o700});
  fs.copyFileSync(path.join(run,'udp'),path.join(dir,'udp'));
  const cert=await exec(['docker','run','--rm','--network','none','-v',dir+':/work','-v',controls+':/controls:ro',image,'/controls/bench-cert','-directory','/work/cert','-hosts','bench-entry1.test']);
  save(path.join(dir,'cert.json'),JSON.parse(cert.stdout));
  const server=JSON.parse(fs.readFileSync(path.join(prep.directory,'private/entry1.json'))),client=JSON.parse(fs.readFileSync(path.join(prep.directory,'private/client.json')));
  server.inbounds[0].listen='10.88.0.11';server.inbounds[0].listen_port=443;server.inbounds[0].tls.reality.handshake.server_port=18445;
  server.route.rules[0].port=[21992];server.route.rules[0].override_port=21992;
  client.inbounds=[{type:'direct',tag:'valid-target',listen:'127.0.0.1',listen_port:19093,network:'tcp',override_address:'127.0.0.1',override_port:21992}];
  const ob=client.outbounds[0];ob.server='decoy.test';ob.server_port=443;ob.detour='observer-connect';
  client.outbounds=[ob,{type:'http',tag:'observer-connect',server:'127.0.0.1',server_port:8080}];
  client.route.rules=[{inbound:['valid-target'],network:'tcp',action:'route',outbound:ob.tag},{action:'reject'}];
  save(path.join(dir,'server.json'),server);save(path.join(dir,'client.json'),client);
  save(path.join(dir,'proxy.json'),{group_id:'DEV-QUIESCE-'+kind,public_authorities:[],lab_mappings:{[kind==='ordinary'?'bench-entry1.test:443':'decoy.test:443']:'10.88.0.11:443'},max_connections:8,dial_timeout_ms:2000,max_tunnel_ms:30000});
 }
 const pins={};for(const f of ['run.cjs','wire.cjs','udp.go','origin.sh','client.sh'])pins[path.relative(ROOT,path.join(__dirname,f))]=hash(path.join(__dirname,f));
 for(const f of [proxy,adapter,prep.sing_box.path,...prep.sing_box.libraries.map(x=>x.path),path.join(controls,'bench-client'),path.join(controls,'bench-server'),path.join(ROOT,'lab/dpi-g02/runtime/capture.cjs'),path.join(ROOT,'lab/dpi-g02/runtime/common.cjs'),path.join(ROOT,'lab/dpi-g03/review-checkpoint.cjs'),path.join(run,'udp')])pins[path.relative(ROOT,f)]=hash(f);
 for(const kind of cases)for(const f of ['server.json','client.json','proxy.json','cert/cert.pem','cert/key.pem'])pins[path.relative(ROOT,path.join(run,kind,f))]=hash(path.join(run,kind,f));
 const frozen={schema:'g03-quiesce-dev-preflight/v1',frozen_at:new Date().toISOString(),run_id:id,dev_only:true,native_belnet:false,excluded_from_B:true,image,network:{name:network,internal:true,subnet:'172.30.93.0/24',client:'172.30.93.2',origin:'172.30.93.3',origin_alias:'10.88.0.11/32 on owned loopback only',client_route:'10.88.0.11/32 via172.30.93.3 on ownedeth0 only'},plan:{cases,startup_seconds:3,active_seconds:5,drain_ms:500,capture_cap_bytes:16*1024*1024,capture:'proxy eth0 TCP443 ciphertext',application_durations:{ordinary:20,reality:8},expected_postquiesce:'application interruptions/denied reconnects retained',retry_until_success:false},pins};
 save(path.join(run,'freeze.json'),frozen);
 const owned=[],captures=[];let created=false;const results=[];
 try{
  save(path.join(run,'network-create.json'),await exec(['docker','network','create','--internal','--subnet','172.30.93.0/24',network]));created=true;
  for(const kind of cases){
   const dir=path.join(run,kind),origin=prefix+'-'+kind+'-origin',client=prefix+'-'+kind+'-client';
   const mounts=['-v',dir+':/work','-v',controls+':/controls:ro','-v',proxy+':/proxy:ro','-v',adapter+':/bridge:ro','-v',prep.directory+':/prep:ro','-v',prep.sing_box.directory+':/mature:ro','-v',__dirname+':/scripts:ro'];
   for(const [name,ip,script]of [[origin,'172.30.93.3','origin.sh'],[client,'172.30.93.2','client.sh']]){
    owned.push(name);save(path.join(dir,script+'.launch.json'),await exec(['docker','run','-d','--name',name,'--network',network,'--ip',ip,'--cap-add','NET_ADMIN','--cpus','1','--memory','512m','-e','CASE='+kind,...mounts,'--entrypoint','/bin/sh',image,'/scripts/'+script]));
   }
   await wait(3000);
   const result={kind,errors:[]};
   result.before=await exec(['docker','exec',client,'curl','-fsS','--max-time','2','http://127.0.0.1:8091/state']);
   const capName=prefix+'-'+kind+'-capture';owned.push(capName);
   const capture=new Capture({name:capName,network:client,image,directory:dir,file:'outer.pcap',iface:'eth0',filter:['tcp','port','443'],maxBytes:16*1024*1024});captures.push(capture);await capture.ready();
   const pin=JSON.parse(fs.readFileSync(path.join(dir,'cert.json'))).spki_sha256_base64;
   const argv=kind==='ordinary'?['/controls/bench-client','-url','wss://bench-entry1.test/ws','-family','rpc','-seed','9173','-duration','20s','-proxy','http://127.0.0.1:8080','-spki',pin,'-nonce','a'.repeat(64)]:['/work/udp','traffic'];
   const child=cp.spawn('docker',['exec',client,...argv],{stdio:['ignore','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);const finished=new Promise(resolve=>{child.once('close',(code,signal)=>resolve({code,signal}));child.once('error',e=>resolve({code:null,error:e.message}));});
   result.launched_utc=new Date().toISOString();await wait(5000);
   result.quiesce=await exec(['docker','exec',client,'curl','-fsS','--max-time','5','-X','POST','http://127.0.0.1:8091/quiesce']);
   await wait(500);
   result.after_drain=await exec(['docker','exec',client,'curl','-fsS','--max-time','2','http://127.0.0.1:8091/state']);
   result.new_connect=await exec(['docker','exec',client,'curl','--noproxy','','-x','http://127.0.0.1:8080','--proxytunnel','-sS','-o','/dev/null','-w','%{http_connect}','--max-time','2','https://'+(kind==='ordinary'?'bench-entry1.test':'decoy.test')+'/'],{allowFailure:true});
   await capture.stop();result.capture=capture.result();
   result.proxy_still_alive=await exec(['docker','exec',client,'sh','-c','kill -0 "$(cat /work/proxy.pid)"']);
   let timer;result.application=await Promise.race([finished,new Promise(resolve=>{timer=setTimeout(()=>resolve({timeout:true}),12000);})]);clearTimeout(timer);
   if(result.application.timeout){child.kill('SIGKILL');result.errors.push('application_watchdog');}
   fs.writeFileSync(path.join(dir,'application-stdout.json'),stdout);fs.writeFileSync(path.join(dir,'application-stderr.log'),stderr);
   const logs=fs.readFileSync(path.join(dir,'proxy.jsonl'),'utf8').trim().split('\n').filter(Boolean).map(x=>JSON.parse(x));
   result.proxy_events=logs;result.wire=wireSummary(fs.readFileSync(path.join(dir,'outer.pcap')));
   result.quiesce_data=JSON.parse(result.quiesce.stdout);result.state_data=JSON.parse(result.after_drain.stdout);
   const accepted=logs.filter(x=>x.accepted);result.accepted_tunnels=accepted.length;
   result.proxy_payload={up:accepted.reduce((n,e)=>n+e.up_bytes,0),down:accepted.reduce((n,e)=>n+e.down_bytes,0)};
   result.wire_payload={up:result.wire.flows.filter(f=>f.dst.endsWith(':443')).reduce((n,f)=>n+f.unique_payload,0),down:result.wire.flows.filter(f=>f.src.endsWith(':443')).reduce((n,f)=>n+f.unique_payload,0)};
   result.packet_count_join=result.capture.captured===result.wire.packets;
   result.packet_accounting_match=result.packet_count_join&&result.capture.captured===result.capture.received_by_filter&&result.capture.dropped_by_kernel===0;
   result.payload_join=result.proxy_payload.up===result.wire_payload.up&&result.proxy_payload.down===result.wire_payload.down;
   if(!result.packet_accounting_match)result.errors.push('packet_accounting_unknown');
   if(!result.payload_join)result.errors.push('proxy_vs_wire_payload_unknown');
   if(result.capture.incomplete||result.capture.forced_cleanup||result.capture.capped)result.errors.push('capture_incomplete');
   if(result.quiesce_data.result!=='ok'||!result.state_data.quiesced||!result.state_data.shutdown_completed||result.quiesce_data.accepted_tunnels_closed<1)result.errors.push('active_quiesce_unverified');
   if(result.new_connect.stdout.trim()!=='503')result.errors.push('new_CONNECT_not_denied');
   if(!accepted.length||!result.proxy_payload.up||!result.proxy_payload.down)result.errors.push('no_duplex_tunnel_evidence');
   if(result.wire.issues.length||result.wire.flows.some(f=>!f.syn||f.gaps))result.errors.push('wire_inventory_or_sequence_incomplete');
   if(kind==='ordinary'){let a;try{a=JSON.parse(stdout);}catch{}if(!(a?.workload?.rpc_verified>0))result.errors.push('ordinary_RPC_unverified');result.application_summary=a;}
   else{let a;try{a=JSON.parse(stdout);}catch{}if(!(a?.exact>0))result.errors.push('framed_UDP_echo_unverified');result.application_summary=a;}
   result.qualified=result.errors.length===0;save(path.join(dir,'result.json'),result);results.push(result);
   for(const name of [capName,client,origin])save(path.join(dir,name+'.cleanup.json'),await exec(['docker','rm','-f',name],{allowFailure:true}));
  }
 }catch(e){save(path.join(run,'runner-error.json'),{error:e.message,stack:e.stack});process.exitCode=1;}
 finally{
  for(const c of captures)await c.stop().catch(()=>{});
  for(const name of owned){const logs=await exec(['docker','logs',name],{allowFailure:true});if(logs.code===0)save(path.join(run,name+'.logs.json'),logs);await exec(['docker','rm','-f',name],{allowFailure:true});}
  if(created)save(path.join(run,'network-cleanup.json'),await exec(['docker','network','rm',network],{allowFailure:true}));
  const summary={schema:frozen.schema,dev_only:true,native_belnet:false,excluded_from_B:true,freeze_sha256:hash(path.join(run,'freeze.json')),results:results.map(r=>({kind:r.kind,qualified:r.qualified,errors:r.errors,packet_accounting_match:r.packet_accounting_match,payload_join:r.payload_join,proxy_payload:r.proxy_payload,wire_payload:r.wire_payload,captured:r.capture.captured,received:r.capture.received_by_filter,application:r.application_summary})),completed:results.length,qualified:results.length===2&&results.every(r=>r.qualified),limitations:['Two finite private development cases; no BelNet/native payload or realISP proof','Post-quiesce application interruption is intended; capture accounting UNKNOWN stays UNKNOWN','No reroll or changes to frozenB1 data or helper']};save(path.join(run,'summary.json'),summary);console.log(JSON.stringify({run,completed:summary.completed,qualified:summary.qualified,results:summary.results.map(({application,...rest})=>rest)}));
  if(!summary.qualified && !process.exitCode)process.exitCode=2;
 }
}
main().catch(e=>{console.error(e);process.exitCode=1;});
