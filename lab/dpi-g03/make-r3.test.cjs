"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {makeAssignments}=require("./make-assignments.cjs"),{derive}=require("./make-r3.cjs");
const master={stage:"B1",test_seeds_commitment:{sha256:"a".repeat(64)}};
const fresh=()=>{let n=0;return()=> (++n).toString(16).padStart(64,"0");};
test("Q stresses native download with exactly3 diagnostic groups and no test scope",()=>{
 const r=derive("qualification",makeAssignments(),master,[],fresh());assert.equal(r.groups.length,3);assert.equal(r.groups[0].family,"download");assert.equal(r.groups[0].group_id,"q-native-download");assert.ok(r.groups.every(g=>g.scope==="diagnostic"&&g.split==="development"));assert.equal(r.test_vault_required,false);assert.equal(r.detector_fitting_allowed,false);assert.deepEqual(Object.keys(r.stages),["Q"]);
});
test("fresh71 nonces preserve every source plan and sealed test row",()=>{
 const plan=makeAssignments(),r=derive("b1",plan,master,[],fresh());assert.deepEqual(r.stages,plan.stages);
 const strip=g=>Object.fromEntries(Object.entries(g).filter(([k])=>!["nonce","initial_nonce","warmup_nonces"].includes(k)));
 for(let i=0;i<96;i++){if(plan.groups[i].split==="test")assert.deepEqual(r.groups[i],plan.groups[i]);else{assert.deepEqual(strip(r.groups[i]),strip(plan.groups[i]));assert.notEqual(r.groups[i].nonce,plan.groups[i].nonce);}}
 assert.equal(r.seeds.test_seed_commitment_sha256,master.test_seeds_commitment.sha256);
});
test("old or duplicate nonces and missing commitment fail without rerolls",()=>{
 const plan=makeAssignments();assert.throws(()=>derive("qualification",plan,master,[],()=>plan.groups[0].nonce),/collision/);assert.throws(()=>derive("b1",plan,master,[],()=>"1".repeat(64)),/collision/);assert.throws(()=>derive("b1",plan,{stage:"B1"},[],fresh()),/commitment/);
});
