'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),os=require('os'),path=require('path');
const {matchedWarmupURL,matchedInitialURL,parseWarmupNonces,awaitStartBarrier}=require('./browser.cjs');
test('Warmups use unique64hex nonces and main+9000+i seeds',()=>{
 const base='https://decoy.test/bench?family=download&seed=0000000000000041&duration_ms=45000&nonce='+'f'.repeat(64);
 const steps=[0,1,2].map(i=>matchedWarmupURL(base,i));
 assert.equal(new Set(steps.map(x=>x.nonce)).size,3);
 for(let i=0;i<3;i++){const u=new URL(steps[i].url);assert.match(steps[i].nonce,/^[0-9a-f]{64}$/);assert.notEqual(steps[i].nonce,'f'.repeat(64));assert.equal(steps[i].seed,65+9000+i);assert.equal(u.searchParams.get('seed').length,16);assert.equal(u.searchParams.get('duration_ms'),'1000');assert.equal(u.searchParams.get('family'),'rpc');}
 assert.throws(()=>matchedWarmupURL(base,3),/step/);
 assert.throws(()=>matchedWarmupURL(base.replace('0000000000000041','0001000000000000'),0),/range/);
});
test('Barrier waits for explicit file; timeout never implies release',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'g03-browser-barrier-'));const file=path.join(dir,'start.json');
 try{let released=false;const waiting=awaitStartBarrier(file,{timeoutMS:500,pollMS:5}).then(x=>{released=true;return x;});await new Promise(r=>setTimeout(r,20));assert.equal(released,false);fs.writeFileSync(file,'{}');const got=await waiting;assert.equal(got.file,file);assert.equal(got.clock_scope,'host_lifecycle_only_not_VM');fs.unlinkSync(file);await assert.rejects(awaitStartBarrier(file,{timeoutMS:15,pollMS:5}),/timed out/);await assert.rejects(awaitStartBarrier(file,{isAlive:()=>false}),/Chrome exited/);}finally{fs.rmSync(dir,{recursive:true,force:true});}
});

test('Frozen warmup nonce assignment is exact and validated before launch',()=>{
 const main='a'.repeat(64),values=['1','2','3'].map(x=>x.repeat(64));
 const parsed=parseWarmupNonces(JSON.stringify(values),main);assert.deepEqual(parsed,values);
 const base='https://decoy.test/bench?family=rpc&seed=0000000000000041&duration_ms=45000&nonce='+main;
 for(let i=0;i<3;i++){const got=matchedWarmupURL(base,i,parsed[i]);assert.equal(got.nonce,values[i]);assert.equal(new URL(got.url).searchParams.get('nonce'),values[i]);assert.equal(got.nonce_source,'frozen_env');}
 assert.equal(parseWarmupNonces(undefined,main),null);
 for(const invalid of ['oops','[]',JSON.stringify([main,...values.slice(0,2)]),JSON.stringify([values[0],values[0],values[2]]),JSON.stringify(['short',...values.slice(1)])])assert.throws(()=>parseWarmupNonces(invalid,main),/G03_WARMUP_NONCES/);
});

test('Matched initial RPC starts atzero with seedmain+8999 and its own nonce',()=>{
 const nonce='f'.repeat(64),base='https://decoy.test/bench?family=download&seed=0000000000000041&duration_ms=45000&nonce='+nonce;
 const initial=matchedInitialURL(base);assert.equal(initial.seed,65+8999);assert.equal(initial.scheduled_ms,0);assert.match(initial.nonce,/^[a-f0-9]{64}$/);assert.notEqual(initial.nonce,nonce);const all=[initial.nonce,...[0,1,2].map(i=>matchedWarmupURL(base,i).nonce),nonce];assert.equal(new Set(all).size,5);
 const frozen=matchedInitialURL(base,'4'.repeat(64));assert.equal(frozen.nonce,'4'.repeat(64));assert.equal(frozen.nonce_source,'frozen_env');const u=new URL(frozen.url);assert.equal(u.searchParams.get('family'),'rpc');assert.equal(u.searchParams.get('duration_ms'),'1000');assert.equal(u.searchParams.get('seed').length,16);
 assert.throws(()=>matchedInitialURL(base,'short'),/initial nonce/);assert.throws(()=>matchedInitialURL(base,nonce),/initial nonce/);
});

test('Initial/warmup seed offsets wrap across maximum48-bit positive seed',()=>{
 const base='https://decoy.test/bench?family=rpc&seed=0000ffffffffffff&duration_ms=45000&nonce='+'e'.repeat(64);
 assert.equal(matchedInitialURL(base).seed,8999);
 for(let i=0;i<3;i++){const got=matchedWarmupURL(base,i);assert.equal(got.seed,9000+i);assert.equal(new URL(got.url).searchParams.get('seed'),(9000+i).toString(16).padStart(16,'0'));}
 const near=base.replace('0000ffffffffffff','0000fffffffffffe');assert.equal(matchedInitialURL(near).seed,8998);assert.equal(matchedWarmupURL(near,2).seed,9001);
});
