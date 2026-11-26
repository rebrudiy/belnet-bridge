'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const{golden,pcapCount,select}=require('./run.cjs');
test('Predeclared selection is buffered whenbothqualify, otherwiseonlypass ornone',()=>{assert.equal(select([{id:'buffered16',qualified:true},{id:'immediate64',qualified:true}]),'buffered16');assert.equal(select([{id:'buffered16',qualified:false},{id:'immediate64',qualified:true}]),'immediate64');assert.equal(select([{id:'buffered16',qualified:false},{id:'immediate64',qualified:false}]),null);});
test('Independent periodic golden is fixed before either livecase',()=>assert.equal(golden(),'f4880c0c720e714910e28f2a004ab79462f8f30788d73947083381ce94304662'));
test('Rawcount rejects truncated packet bodies',()=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'g03-stress-count-'));try{const file=path.join(dir,'fixture.pcap'),b=Buffer.alloc(40);b.writeUInt32LE(0xa1b2c3d4);b.writeUInt32LE(1,20);b.writeUInt32LE(50,32);fs.writeFileSync(file,b);assert.throws(()=>pcapCount(file),/Truncated PCAP packet body/);}finally{fs.rmSync(dir,{recursive:true,force:true});}});
