'use strict';
const fs=require('fs'),path=require('path'),cp=require('child_process'),crypto=require('crypto');
const ROOT=path.resolve(__dirname,'../../..');
const hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const save=(p,x)=>{fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,JSON.stringify(x,null,2)+'\n',{mode:0o600});};
function call(argv,{cwd=ROOT,timeout=30000,allowFailure=false}={}){const p=cp.spawnSync(argv[0],argv.slice(1),{cwd,timeout,encoding:'utf8',maxBuffer:16*1024*1024});const r={code:p.status,signal:p.signal,stdout:p.stdout||'',stderr:p.stderr||'',error:p.error?.message};if((r.code!==0||r.error)&&!allowFailure)throw Object.assign(Error(argv.slice(0,3).join(' ')+': '+r.stderr.slice(-1200)),{result:r});return r;}
function sources(){const d={};for(const base of [__dirname,path.join(ROOT,'lab/dpi-g03/controls')]){function walk(p){for(const x of fs.readdirSync(p,{withFileTypes:true})){const q=path.join(p,x.name);if(x.isDirectory())walk(q);else d[path.relative(ROOT,q)]=hash(q);}}walk(base);}return d;}
function main(){
 const id=process.argv[2];if(!id||!/^[a-z0-9-]{1,32}$/.test(id))throw Error('Explicit new dev run ID required');
 const run=path.join(ROOT,'lab/dpi-g03/run/preflight-'+id),out=path.join(ROOT,'out/dpi-g03/preflight',id),name='bb-g03-preflight-'+id;
 if(fs.existsSync(run)||fs.existsSync(out))throw Error('Refusing to reroll/reuse attempted run');
 fs.mkdirSync(path.join(run,'private'),{recursive:true,mode:0o700});fs.mkdirSync(path.join(run,'bin'));fs.mkdirSync(out,{recursive:true});
 const prepPath=path.join(ROOT,'lab/dpi-g01/run/prepared-a/preparation.json'),prep=JSON.parse(fs.readFileSync(prepPath));
 const adapter=path.join(ROOT,'lab/dpi-g02/bin/belnet-bridge-a2-v1');let launched=false;
 try{
  for(const [p,h]of Object.entries(prep.assets_sha256))if(hash(path.join(prep.directory,p))!==h)throw Error('Prepared lineage hash changed');
  if(hash(prep.sing_box.path)!==prep.sing_box.sha256)throw Error('Core hash changed');
  const server=JSON.parse(fs.readFileSync(path.join(prep.directory,'private/entry1.json'))),client=JSON.parse(fs.readFileSync(path.join(prep.directory,'private/client.json')));
  server.inbounds[0].listen='10.88.0.11';server.inbounds[0].listen_port=19445;server.inbounds[0].tls.reality.handshake.server_port=18445;
  server.route.rules[0].port=[21992];server.route.rules[0].override_port=21992;
  client.inbounds=[{type:'direct',tag:'valid-target',listen:'127.0.0.1',listen_port:19093,network:'tcp',override_address:'127.0.0.1',override_port:21992},{type:'direct',tag:'forbidden-target',listen:'127.0.0.1',listen_port:19094,network:'tcp',override_address:'127.0.0.1',override_port:21993}];
  const outbound=client.outbounds[0];outbound.server='decoy.test';outbound.server_port=19445;outbound.detour='observer-connect';
  client.outbounds=[outbound,{type:'http',tag:'observer-connect',server:'127.0.0.1',server_port:8080}];
  client.route.rules=[{inbound:['valid-target','forbidden-target'],network:'tcp',action:'route',outbound:outbound.tag},{action:'reject'}];
  save(path.join(run,'private/server.json'),server);save(path.join(run,'private/client.json'),client);
  save(path.join(run,'private/proxy.json'),{group_id:'DEV-EXCLUDED-B-'+id,public_authorities:[],lab_mappings:{'decoy.test:19445':'10.88.0.11:19445'},max_connections:16,dial_timeout_ms:2000,max_tunnel_ms:55000});
  const builds=[];for(const [cwd,argv]of [[__dirname,['go','build','-trimpath','-o',path.join(run,'bin/check'),'./cmd/check']],[path.join(ROOT,'lab/dpi-g03/controls'),['go','build','-trimpath','-o',path.join(run,'bin/connect-proxy'),'./cmd/connect-proxy']]])builds.push(call(['env','GOWORK=off','GOPROXY=off','GOOS=linux','GOARCH=arm64','CGO_ENABLED=0',...argv],{cwd,timeout:60000}));
  save(path.join(out,'build.json'),builds);
  const checks=[];for(const which of ['client','server'])checks.push({which,...call(['docker','run','--rm','--network','none','-v',run+':/work:ro','-v',prep.sing_box.directory+':/mature:ro',prep.runtime_image,'/mature/sing-box','check','-c','/work/private/'+which+'.json'])});save(path.join(out,'offline-configchecks.json'),checks);
  const manifest={schema:'g03-connect-reality-dev-preflight-v1',frozen_at:new Date().toISOString(),dev_only:true,excluded_from_B:true,native_belnet:false,run_id:id,container:name,network:'none, alias10.88.0.11/32 on own loopback only; no existing network changes',runtime_image:prep.runtime_image,core:prep.sing_box,adapter:{path:adapter,sha256:hash(adapter),max_queue_age:'100ms'},prepared_lineage:{descriptor:prepPath,sha256:hash(prepPath)},helpers:{check:hash(path.join(run,'bin/check')),proxy:hash(path.join(run,'bin/connect-proxy'))},config_sha256:Object.fromEntries(['server','client','proxy'].map(x=>[x,hash(path.join(run,'private/'+x+'.json'))])),source_sha256:sources(),ports:{proxy:8080,REALITY:19445,decoy:18445,framer:21992,forbidden_destination:21993,UDP_echo:12092,UDP_valid:2093,UDP_invalid_token:2094,UDP_forbidden_target:2095},plan:{startup_seconds:3,valid_sizes:[0,1,1200],datagram_timeout_seconds:5,negative_timeout_seconds:1,invalid_token_no_new_UDP_state:true,forbidden_target_no_new_UDP_state:true,max_wire_seconds:60,retry_until_success:false,core_restarts:0,warmups:0,capture:'lo TCP19445 ciphertext only; excludes plaintext token21992',capture_cap_bytes:67108864},limitations:['No actual BelNet/native nonce proof','Private local decoy not public camouflage','Non443 DEV port excluded all B dataset/splits']};
  save(path.join(run,'freeze.json'),manifest);save(path.join(out,'freeze.json'),manifest);
  const argv=['docker','run','-d','--name',name,'--network','none','--cap-add','NET_ADMIN','--cpus','1','--memory','512m','-v',run+':/work','-v',prep.directory+':/prep:ro','-v',prep.sing_box.directory+':/mature:ro','-v',adapter+':/bridge:ro','-v',__dirname+':/preflight:ro','--entrypoint','/bin/sh',prep.runtime_image,'/preflight/start.sh'];save(path.join(out,'launch-command.json'),argv);const start=call(argv);launched=true;save(path.join(out,'launch.json'),start);
  const waited=call(['docker','wait',name],{timeout:60000,allowFailure:true});save(path.join(out,'wait.json'),waited);
  if(waited.error||waited.code!==0){call(['docker','kill',name],{allowFailure:true});throw Error('Bounded docker wait failed');}
  const inspect=JSON.parse(call(['docker','inspect',name]).stdout)[0];save(path.join(out,'runtime.json'),{state:inspect.State,network_mode:inspect.HostConfig.NetworkMode,image:inspect.Image,freeze_precedes_start:Date.parse(manifest.frozen_at)<=Date.parse(inspect.State.StartedAt)});
 }catch(e){save(path.join(out,'runner-error.json'),{error:e.message,result:e.result});process.exitCode=1;}
 finally{
  if(launched){const logs=call(['docker','logs',name],{allowFailure:true});save(path.join(out,'container-logs.json'),logs);const cleanup=call(['docker','rm','-f',name],{allowFailure:true});save(path.join(out,'cleanup.json'),cleanup);}
  for(const f of fs.readdirSync(run)){const p=path.join(run,f);if(fs.statSync(p).isFile()&&!['freeze.json'].includes(f))fs.copyFileSync(p,path.join(out,f));}
  console.log(JSON.stringify({out,run,launched,result:fs.existsSync(path.join(out,'result.json'))?JSON.parse(fs.readFileSync(path.join(out,'result.json'))):null}));
 }
}
main();
