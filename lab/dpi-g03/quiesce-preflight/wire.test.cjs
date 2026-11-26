"use strict";
const test=require('node:test'),assert=require('node:assert/strict');
const {wireSummary}=require('./wire.cjs');
function fixture(){
 const head=Buffer.alloc(24);Buffer.from('d4c3b2a1','hex').copy(head);head.writeUInt32LE(65535,16);head.writeUInt32LE(1,20);
 const packet=(seq,n,syn=false)=>{const p=Buffer.alloc(54+n);p.writeUInt16BE(0x800,12);p[14]=0x45;p.writeUInt16BE(40+n,16);p[23]=6;Buffer.from([1,2,3,4,5,6,7,8]).copy(p,26);p.writeUInt16BE(4000,34);p.writeUInt16BE(443,36);p.writeUInt32BE(seq,38);p[46]=0x50;p[47]=syn?2:16;const h=Buffer.alloc(16);h.writeUInt32LE(p.length,8);h.writeUInt32LE(p.length,12);return Buffer.concat([h,p]);};
 return {head,packet};
}
test('counts duplicate TCP ranges once, retaining observed retransmission bytes',()=>{const {head,packet}=fixture();const r=wireSummary(Buffer.concat([head,packet(100,0,true),packet(101,10),packet(106,5)]));assert.equal(r.packets,3);assert.equal(r.flows[0].unique_payload,10);assert.equal(r.flows[0].wire_payload,15);assert.equal(r.flows[0].retransmitted_or_overlap_bytes,5);assert.equal(r.flows[0].gaps,0);});
test('sequence wrap is relative to observed SYN and missing bytes remain explicit',()=>{const {head,packet}=fixture();const r=wireSummary(Buffer.concat([head,packet(0xfffffff0,0,true),packet(0xfffffff1,15),packet(0,4),packet(8,3)]));assert.equal(r.flows[0].unique_payload,22);assert.equal(r.flows[0].gaps,1);});
