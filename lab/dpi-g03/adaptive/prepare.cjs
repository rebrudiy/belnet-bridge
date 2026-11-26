'use strict';
// Local artifact preparation. Does not launch containers or select a candidate.
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function relativeFile(name) {
  if (typeof name !== 'string' || !name || path.isAbsolute(name) || name.split(/[\\/]/).some(p => !p || p === '..' || p === '.')) throw Error('Unsafe relative artifact path');
  return name;
}
function checked(file, expected) {
  if (!/^[a-f0-9]{64}$/.test(expected || '') || hash(file) !== expected) throw Error('Artifact SHA mismatch: ' + file);
}
function copyTree(from, to) {
  fs.mkdirSync(to, {recursive: true});
  for (const e of fs.readdirSync(from, {withFileTypes: true})) {
    const a = path.join(from, e.name), b = path.join(to, e.name);
    if (e.isDirectory()) copyTree(a,b);
    else if (e.isFile()) { fs.copyFileSync(a,b); fs.chmodSync(b, fs.statSync(a).mode & 0o777); }
    else throw Error('Prepared assets must be regular files/directories');
  }
}
function inventory(dir) {
  const out = {};
  function walk(p) { for (const e of fs.readdirSync(p,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))) { const f=path.join(p,e.name);if(e.isDirectory())walk(f);else if(e.isFile())out[path.relative(dir,f)]=hash(f);else throw Error('Unsupported asset type'); } }
  walk(dir); return out;
}
function successfulTests(row) {
  if (!row?.log || !row.sha256) throw Error('Candidate needs pinned actual test log');
  checked(row.log,row.sha256);
  const events = fs.readFileSync(row.log,'utf8').trim().split('\n').filter(Boolean).map(l=>JSON.parse(l));
  const packages=new Map();
  for(const e of events){
    if(typeof e.Action==='string'&&e.Action.endsWith('fail'))throw Error('Candidate tests failed');
    if(!e.Package)continue;
    packages.set(e.Package,e.Action==='pass'&&!e.Test);
  }
  if(!packages.size||[...packages.values()].some(done=>!done))throw Error('Every started test package must finish successfully');
}
function linuxARM64ELF(file){
  const b=fs.readFileSync(file);
  if(b.length<64||!b.subarray(0,4).equals(Buffer.from([0x7f,69,76,70]))||b[4]!==2||b[5]!==1||b.readUInt16LE(18)!==183||![2,3].includes(b.readUInt16LE(16))||b.readUInt16LE(52)!==64)throw Error('Candidate must be LinuxARM64 ELF64');
  const offset=b.readBigUInt64LE(32),count=b.readUInt16LE(56),size=b.readUInt16LE(54);
  if(!count||count>256||size!==56||offset>BigInt(b.length)||offset+BigInt(count*size)>BigInt(b.length))throw Error('Invalid ELF program table');
  let load=false;
  for(let i=0;i<count;i++){const p=Number(offset)+i*size;if(b.readUInt32LE(p)!==1)continue;load=true;const start=b.readBigUInt64LE(p+8),bytes=b.readBigUInt64LE(p+32);if(start>BigInt(b.length)||start+bytes>BigInt(b.length))throw Error('Truncated ELF load segment');}
  if(!load)throw Error('ELF has no load segment');
}
function prepare({basePreparation,candidateManifest,sourceDirectory,directory}) {
  directory=path.resolve(directory);
  if(fs.existsSync(directory))throw Error('Refusing overwrite');
  const base=JSON.parse(fs.readFileSync(basePreparation)), candidateBytes=fs.readFileSync(candidateManifest), candidate=JSON.parse(candidateBytes);
  if(base.adaptive_candidate_only)throw Error('Use the original baseline preparation, not another candidate tree');
  if(candidate.build?.GOOS!=='linux'||candidate.build?.GOARCH!=='arm64'||!Array.isArray(candidate.build.command)||!candidate.build.command.length)throw Error('Explicit LinuxARM64 candidate build required');
  if(!candidate.source_sha256?.['go.mod']||!candidate.source_sha256?.['go.sum'])throw Error('Full compiled source/module pins required');
  checked(candidate.candidate?.path,candidate.candidate?.sha256);linuxARM64ELF(candidate.candidate.path);successfulTests(candidate.tests?.candidate);
  const actualSources=inventory(sourceDirectory);
  const compiled=Object.keys(actualSources).filter(n=>n==='go.mod'||n==='go.sum'||(n.endsWith('.go')&&!n.endsWith('_test.go')));
  if(!compiled.some(n=>n.endsWith('.go'))||compiled.some(n=>candidate.source_sha256[n]!==actualSources[n]))throw Error('Compiled Go source census missing or incomplete');
  for(const [name,sha]of Object.entries(candidate.source_sha256)){relativeFile(name);if(['CANDIDATE.json','tests.jsonl','preparation-tool.cjs'].includes(name))throw Error('Reserved source archive name');checked(path.join(sourceDirectory,name),sha);}
  const baselineCensus=inventory(base.directory),descriptorRelative=path.relative(base.directory,path.resolve(basePreparation));
  if(!descriptorRelative.startsWith('..')&&!path.isAbsolute(descriptorRelative))delete baselineCensus[descriptorRelative];
  if(JSON.stringify(Object.entries(baselineCensus).sort())!==JSON.stringify(Object.entries(base.assets_sha256).sort()))throw Error('Baseline contains unlisted or missing assets');
  for(const [name,sha]of Object.entries(base.assets_sha256))checked(path.join(base.directory,relativeFile(name)),sha);
  // Verify everything before creating an output: rejected candidates leave no
  // partial descriptor that could accidentally be acquired.
  copyTree(base.directory,directory);
  for(const [name,sha]of Object.entries(base.assets_sha256))checked(path.join(directory,name),sha);
  fs.rmSync(path.join(directory,'preparation.json'),{force:true});
  if(!descriptorRelative.startsWith('..')&&!path.isAbsolute(descriptorRelative))fs.rmSync(path.join(directory,descriptorRelative),{force:true});
  const sourceOut=path.join(directory,'selected-adapter-source');fs.mkdirSync(sourceOut);
  for(const name of Object.keys(candidate.source_sha256)){const dest=path.join(sourceOut,name);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(sourceDirectory,name),dest);checked(dest,candidate.source_sha256[name]);}
  const adapter=path.join(directory,'bin','selected-adapter');fs.copyFileSync(candidate.candidate.path,adapter);fs.chmodSync(adapter,0o755);
  checked(adapter,candidate.candidate.sha256);
  fs.writeFileSync(path.join(sourceOut,'CANDIDATE.json'),candidateBytes);
  fs.copyFileSync(candidate.tests.candidate.log,path.join(sourceOut,'tests.jsonl'));
  checked(path.join(sourceOut,'tests.jsonl'),candidate.tests.candidate.sha256);
  fs.copyFileSync(__filename,path.join(sourceOut,'preparation-tool.cjs'));
  const result={...base,directory,prepared_at:new Date().toISOString(),adapter:{path:adapter,sha256:hash(adapter)},adapter_source_provenance:{candidate_manifest_sha256:crypto.createHash('sha256').update(candidateBytes).digest('hex'),source_root:'selected-adapter-source',source_sha256:candidate.source_sha256,build:candidate.build,tests_log:'selected-adapter-source/tests.jsonl',tests_sha256:candidate.tests.candidate.sha256,preparation_tool_sha256:hash(path.join(sourceOut,'preparation-tool.cjs'))},baseline_preparation:{path:path.resolve(basePreparation),sha256:hash(basePreparation)},adaptive_candidate_only:true};
  result.assets_sha256=inventory(directory);
  fs.writeFileSync(path.join(directory,'preparation.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
  return {path:path.join(directory,'preparation.json'),sha256:hash(path.join(directory,'preparation.json')),adapter_sha256:result.adapter.sha256};
}
if(require.main===module){try{const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i].slice(2)]=process.argv[i+1];console.log(JSON.stringify(prepare({basePreparation:a.base,candidateManifest:a.candidate,sourceDirectory:a.source,directory:a.output})));}catch(e){console.error(e.stack);process.exitCode=1;}}
module.exports={prepare,hash,successfulTests,relativeFile,linuxARM64ELF};
