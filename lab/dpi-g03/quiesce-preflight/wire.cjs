"use strict";
const { inspectPCAP } = require("../review-checkpoint.cjs");
function wireSummary(raw) {
 const info=inspectPCAP(raw),little=["d4c3b2a1","4d3cb2a1"].includes(raw.subarray(0,4).toString("hex"));
 const u32=at=>little?raw.readUInt32LE(at):raw.readUInt32BE(at);
 if(u32(20)!==1)throw Error("Ethernet_only_preflight_parser");
 let at=24;const streams=new Map(),issues=[];
 while(at<raw.length){const size=u32(at+8),p=raw.subarray(at+16,at+16+size);at+=16+size;
  if(p.length<34||p.readUInt16BE(12)!==0x800)continue;
  const ihl=(p[14]&15)*4,total=p.readUInt16BE(16),t=14+ihl;
  if(p[23]!==6)continue;
  if(ihl<20||t+20>p.length||14+total>p.length){issues.push("short_TCP_or_IP");continue;}
  if(p.readUInt16BE(20)&0x3fff){issues.push("fragmented_IP");continue;}
  const ip=n=>[...p.subarray(n,n+4)].join('.');
  const src=ip(26)+":"+p.readUInt16BE(t),dst=ip(30)+":"+p.readUInt16BE(t+2);
  const key=src+">"+dst,header=(p[t+12]>>4)*4,n=total-ihl-header;
  if(header<20||n<0){issues.push("bad_TCP_header");continue;}
  if(!streams.has(key))streams.set(key,{src,dst,base:null,syn:false,segments:[],wire_payload:0});
  const s=streams.get(key),seq=p.readUInt32BE(t+4),syn=!!(p[t+13]&2);
  if(s.base===null)s.base=(seq+(syn?1:0))>>>0;
  s.syn||=syn;
  if(n>0){const begin=((seq+(syn?1:0))-s.base)>>>0;s.segments.push([begin,begin+n]);s.wire_payload+=n;}
 }
 const flows=[];
 for(const s of streams.values()){
  s.segments.sort((a,b)=>a[0]-b[0]);let high=0,unique=0,gaps=0;
  for(const [a,b]of s.segments){if(a>high)gaps++;if(b>high)unique+=b-Math.max(a,high);high=Math.max(high,b);}
  flows.push({src:s.src,dst:s.dst,syn:s.syn,wire_payload:s.wire_payload,unique_payload:unique,retransmitted_or_overlap_bytes:s.wire_payload-unique,gaps});
 }
 return {...info,flows,issues};
}
module.exports={wireSummary};
