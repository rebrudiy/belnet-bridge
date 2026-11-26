'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {initialPolicyRef}=require('./extract-round.cjs');
test('Frozen repository-relative policy reference normalizes without reading policy',()=>{const p='out/dpi-g04/iterations/r01/policy.json',sha='a'.repeat(64);assert.deepEqual(initialPolicyRef({path:p,sha256:sha}),{path:path.resolve(__dirname,'../..',p),sha256:sha,source_declared_path:p});});
test('Policy reference still rejects test/vault/traversal and invalid SHA',()=>{for(const p of ['out/b-test-native/policy.json','private/vault.json','../outside/policy.json'])assert.throws(()=>initialPolicyRef({path:p,sha256:'a'.repeat(64)}));assert.throws(()=>initialPolicyRef({path:'out/policy.json',sha256:'bad'}));});
