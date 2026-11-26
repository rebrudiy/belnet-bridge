"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {summarizeSegments,parseWire}=require("./review-wire.cjs");
const tls=Buffer.from([23,3,3,0,3,0xaa,0xbb,0xcc]);
const segment=(offset,data,ordinal=1)=>({offset,data,ordinal,at_micros:1});
test("out-of-order TCP bytes reassemble without sorting capture timestamps",()=>{
 const r=summarizeSegments([segment(4,tls.subarray(4),1),segment(0,tls.subarray(0,4),2)]);
 assert.equal(r.unique_bytes,8);assert.equal(r.tls_records,1);assert.equal(r.tls_issue,null);assert.deepEqual(r.sequence_gaps,[]);
});
test("retransmission overlap is counted and conflicting ciphertext never looks complete",()=>{
 const same=summarizeSegments([segment(0,tls),segment(4,tls.subarray(4),2)]);
 assert.equal(same.unique_bytes,8);assert.equal(same.overlapping_bytes,4);assert.equal(same.conflicting_segments,0);
 const bad=Buffer.from(tls.subarray(4));bad[1]^=1;
 const r=summarizeSegments([segment(0,tls),segment(4,bad,2)]);
 assert.equal(r.conflicting_segments,1);assert.match(r.tls_issue,/incomplete_or_conflicting/);
});
test("sequence holes, truncated TLS and implausible extents remain explicit",()=>{
 assert.deepEqual(summarizeSegments([segment(0,tls.subarray(0,3)),segment(4,tls.subarray(4),2)]).sequence_gaps,[[3,4]]);
 assert.equal(summarizeSegments([segment(0,tls.subarray(0,7))]).tls_issue,"partial_TLS_body");
 assert.throws(()=>summarizeSegments([segment(2**32-1,Buffer.from([1]))]),/exceeds_capture_bound/);
});
function fixture(link){
 const ip=link===276?20:link===113?16:14,proto=link===276?0:link===113?14:12;
 const head=Buffer.alloc(24);Buffer.from("d4c3b2a1","hex").copy(head);head.writeUInt16LE(2,4);head.writeUInt16LE(4,6);head.writeUInt32LE(65535,16);head.writeUInt32LE(link,20);
 const packet=(seq,data,syn)=>{const p=Buffer.alloc(ip+40+data.length);p.writeUInt16BE(0x0800,proto);p[ip]=0x45;p.writeUInt16BE(40+data.length,ip+2);p[ip+9]=6;Buffer.from([10,0,0,1,10,0,0,2]).copy(p,ip+12);const t=ip+20;p.writeUInt16BE(4000,t);p.writeUInt16BE(443,t+2);p.writeUInt32BE(seq,t+4);p[t+12]=0x50;p[t+13]=syn?2:16;data.copy(p,t+20);const h=Buffer.alloc(16);h.writeUInt32LE(1,0);h.writeUInt32LE(ordinal++,4);h.writeUInt32LE(p.length,8);h.writeUInt32LE(p.length,12);return Buffer.concat([h,p]);};
 let ordinal=0;return Buffer.concat([head,packet(0xfffffff8,Buffer.alloc(0),true),packet(0xfffffff9,tls.subarray(0,7),false),packet(0,tls.subarray(7),false)]);
}
test("Ethernet, SLL1 and SLL2 retain identical TLS bytes and TCP wrap semantics",()=>{
 const rows=[1,113,276].map(link=>parseWire(fixture(link)));
 for(const r of rows){assert.equal(r.capture.packets,3);assert.equal(r.streams.length,1);assert.equal(r.streams[0].unique_bytes,8);assert.equal(r.streams[0].tls_records,1);assert.equal(r.streams[0].syn_captured,true);assert.deepEqual(r.issues,[]);}
 assert.equal(new Set(rows.map(r=>r.streams[0].ciphertext_sha256)).size,1);
});
