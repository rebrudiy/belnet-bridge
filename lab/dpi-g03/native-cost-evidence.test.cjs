'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {operation,build,verifySource} = require('./native-cost-evidence.cjs');
function proof() {
  return {label:'main',expected:{nonce:'a'.repeat(64)},attempt_present:true,client_exit_code:0,
    service_nonce_matches:1,expected_nonce_reused:false,unique_nonce_count_and_metadata_proof:true,
    strict_both_endpoints_duration_complete:true,
    counts:Object.fromEntries(['sent_messages_vs_up_messages','received_messages_vs_down_messages',
      'sent_bytes_vs_up_bytes','received_bytes_vs_down_bytes'].map(k=>[k,{client:10,server:10,equal:true}]))};
}
test('Verified byte counts preserve both directions, not just one',()=>{
  const x=operation(proof());assert.equal(x.status,'success');assert.equal(x.client_bytes,20);
  assert.equal(x.server_bytes,20);assert.equal(x.service_nonce,'a'.repeat(64));
});
test('Exit0 and completed duration cannot hide unmatched message or byte counts',()=>{
  for(const field of ['sent_messages_vs_up_messages','received_bytes_vs_down_bytes']){
    const p=proof();p.counts[field].server=9; // Deliberately stale producer boolean.
    const x=operation(p);assert.equal(x.status,'failed');assert.match(x.error,/counts_not_exact/);
    assert.equal(x.service_nonce,null);
  }
});
test('Incomplete duration and duplicate service nonce remain failures',()=>{
  for(const field of ['strict_both_endpoints_duration_complete','service_nonce_matches']){
    const p=proof();p[field]=field==='service_nonce_matches'?2:false;
    assert.equal(operation(p).status,'failed');
  }
});
test('Four arbitrary counters cannot replace the four required direction counters',()=>{
  const p=proof();p.counts.unrelated={...p.counts.sent_messages_vs_up_messages};
  delete p.counts.sent_messages_vs_up_messages;
  const x=operation(p);assert.equal(x.status,'failed');assert.match(x.error,/counts_not_exact/);
});
test('Cold failures retain errors and missing server counts as null',()=>{
  const p=proof();p.client_exit_code=1;p.client_error='DNS refused';p.unique_nonce_count_and_metadata_proof=false;
  p.strict_both_endpoints_duration_complete=false;
  for(const x of Object.values(p.counts)){x.client=0;x.server=null;x.equal=false;}
  const x=operation(p);assert.equal(x.status,'failed');assert.equal(x.server_bytes,null);
  assert.match(x.error,/DNS refused/);
});
test('Malformed attempts and empty purported successes are rejected',()=>{
  const p=proof();p.attempt_present=false;assert.throws(()=>operation(p),/attempt_missing/);
  const q=proof();for(const x of Object.values(q.counts))x.client=x.server=0;
  assert.throws(()=>operation(q),/empty_success/);
});
test('Manifest schema and sealed paths reject before filesystem reads',()=>{
  assert.throws(()=>build({}),/input_schema/);
  assert.throws(()=>build({schema:'native-ledger-inputs/v1',freeze:{path:'test-vault/no-file',sha256:'a'.repeat(64)}}),/test_artifact_forbidden/);
});
test('Source binding rejects empty, renamed, duplicate or wrong-hash manifests before reading files',()=>{
  const h='a'.repeat(64),expected={'a.go':h,'b.go':h};
  const valid={kind:'source_manifest',files:[{logical_path:'a.go',sha256:h},{logical_path:'b.go',sha256:h}]};
  let reads=0;verifySource(valid,expected,()=>reads++);assert.equal(reads,2);
  for(const files of [[],[valid.files[0]],
    [valid.files[0],{logical_path:'wrong.go',sha256:h}],
    [valid.files[0],valid.files[0]],
    [valid.files[0],{logical_path:'b.go',sha256:'b'.repeat(64)}]]){
    reads=0;assert.throws(()=>verifySource({...valid,files},expected,()=>reads++),/wrapper_source_/);
    assert.equal(reads,0);
  }
});
