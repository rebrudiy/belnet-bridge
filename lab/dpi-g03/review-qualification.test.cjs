"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os");
const {audit}=require("./review-qualification.cjs");
const original=path.join(__dirname,"run/q-r2-20261119"),freeze=path.join(__dirname,"run/freeze-q-r2.json");
test("primary/test data cannot enter the Q-only audit before any artifact read",()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"belnet-Q-guard-"));
 try{const p=path.join(dir,"freeze.json");fs.writeFileSync(p,JSON.stringify({schema:"belnet-g03-collector/v2",stage:"B1",groups:[]}));assert.throws(()=>audit("/nonexistent",p),/finite_diagnostic_Q_only/);}finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test("Q regression: counter mismatch and forced browser lifecycle cannot qualify",{skip:!fs.existsSync(freeze)},()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"belnet-Q-corruption-"));
 try{
  const f=JSON.parse(fs.readFileSync(freeze)),records=new Map();
  for(const g of f.groups){
   const target=path.join(dir,g.group_id),source=path.join(original,g.group_id);fs.mkdirSync(target);
   for(const file of ["windows.json","longflow.json","outer.pcap"])fs.symlinkSync(path.join(source,file),path.join(target,file));
   const raw=fs.readFileSync(path.join(source,"result.json"));records.set(g.group_id,raw);fs.writeFileSync(path.join(target,"result.json"),raw);
  }
  const native=f.groups.find(g=>g.class==="belnet").group_id,nativeFile=path.join(dir,native,"result.json"),r=JSON.parse(records.get(native));
  r.captures.find(c=>/-capture$/.test(c.name)).received_by_filter++;
  fs.writeFileSync(nativeFile,JSON.stringify(r));
  let out=audit(dir,freeze);assert.equal(out.qualified,false);assert.ok(out.groups.find(g=>g.group_id===native).errors.includes("outer_capture_accounting_or_lifecycle"));
  fs.writeFileSync(nativeFile,records.get(native));
  const chrome=f.groups.find(g=>g.client_stack==="chrome").group_id,chromeFile=path.join(dir,chrome,"result.json"),browser=JSON.parse(records.get(chrome));
  browser.browser_teardown.signals=["SIGTERM"];fs.writeFileSync(chromeFile,JSON.stringify(browser));
  out=audit(dir,freeze);assert.equal(out.qualified,false);assert.ok(out.groups.find(g=>g.group_id===chrome).errors.includes("browser_acquisition_or_teardown"));
  fs.writeFileSync(chromeFile,records.get(chrome));
  const early=JSON.parse(records.get(native));early.quiesce.started_unix_micros=early.measurement_start.unix_micros+79_000_000;
  fs.writeFileSync(nativeFile,JSON.stringify(early));out=audit(dir,freeze);
  assert.equal(out.qualified,false);assert.ok(out.groups.find(g=>g.group_id===native).errors.includes("VM_horizon_quiesce_or_drain"));
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
