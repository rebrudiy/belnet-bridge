"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {makeAssignments}=require("./make-assignments.cjs"),{revise}=require("./make-r2-assignments.cjs");
const freeze={stage:"B1",test_seeds_commitment:{sha256:"a".repeat(64)}};
test("R2 preserves all source plans, batches and test rows, replacing only development nonces",()=>{
 const original=makeAssignments();let n=0;
 const r=revise(original,freeze,{},()=> (++n).toString(16).padStart(64,"0"));
 assert.equal(n,355);assert.deepEqual(r.stages,original.stages);
 for(let i=0;i<original.groups.length;i++){
  const a=original.groups[i],b=r.groups[i];
  if(a.split==="test"){assert.deepEqual(b,a);continue;}
  const {nonce:an,initial_nonce:ai,warmup_nonces:aw,...ac}=a;
  const {nonce:bn,initial_nonce:bi,warmup_nonces:bw,...bc}=b;
  assert.deepEqual(bc,ac);assert.notEqual(an,bn);assert.notEqual(ai,bi);assert.notDeepEqual(aw,bw);
 }
 assert.equal(r.seeds.test_seed_commitment_sha256,freeze.test_seeds_commitment.sha256);
});
test("old nonce reuse and new collisions fail instead of retrying",()=>{
 const original=makeAssignments();assert.throws(()=>revise(original,freeze,{},()=>original.groups.find(g=>g.split!=="test").nonce),/fresh_nonce_invalid_or_collision/);
 assert.throws(()=>revise(original,freeze,{},()=>"1".repeat(64)),/fresh_nonce_invalid_or_collision/);
});
test("missing original test commitment is rejected",()=>{
 assert.throws(()=>revise(makeAssignments(),{stage:"B1"},{},()=>"1".repeat(64)),/existing_B1_test_commitment_required/);
});
