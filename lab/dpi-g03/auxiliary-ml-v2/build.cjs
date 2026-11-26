// Synthetic preparation only. No Docker, traffic, cohort/test reads or real fit.
const fs=require('fs'),path=require('path'),crypto=require('crypto'),cp=require('child_process');
const root=process.cwd(),dir=path.relative(root,__dirname),out=path.join(dir,'tooling');
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const run=(args,env={})=>cp.execFileSync('go',args,{cwd:root,env:{...process.env,...env},encoding:'utf8'});
const oldPath='out/dpi-g03/auxiliary-ml/tooling/TOOLING.json',oldBytes=fs.readFileSync(oldPath),old=JSON.parse(oldBytes);
for(const [file,expected]of Object.entries(old.source_sha256))if(digest(fs.readFileSync(file))!==expected)throw Error('Protected auxiliary V1 source changed: '+file);
for(const row of Object.values(old.binary))if(digest(fs.readFileSync(row.versioned_path))!==row.sha256)throw Error('Protected auxiliary V1 ELF changed');
for(const [file,expected]of Object.entries(old.readonly_library_source.files))if(digest(fs.readFileSync(file))!==expected)throw Error('Pinned ML library changed: '+file);
fs.mkdirSync(out,{recursive:true});
fs.writeFileSync(path.join(out,'race-test.log'),run(['test','-race','-count=1','-v','./'+dir]));
fs.writeFileSync(path.join(out,'vet.log'),run(['vet','./'+dir]));
const source={},archive={},library={};fs.mkdirSync(path.join(out,'source-archive'),{recursive:true});
for(const file of fs.readdirSync(dir).filter(f=>/\.(go|cjs|md|json)$/.test(f)).sort()){
 const original=path.join(dir,file),bytes=fs.readFileSync(original);source[original]=digest(bytes);archive[file]=digest(bytes);fs.writeFileSync(path.join(out,'source-archive',file),bytes);
}
fs.mkdirSync(path.join(out,'library-source-archive'),{recursive:true});
for(const file of Object.keys(old.readonly_library_source.files)){
 const bytes=fs.readFileSync(file);library[file]=digest(bytes);fs.writeFileSync(path.join(out,'library-source-archive',path.basename(file)),bytes);
}
const binary={};for(const os of ['darwin','linux']){
 const dest=path.join(out,`auxiliary-${os}-arm64`);run(['build','-trimpath','-o',dest,'./'+dir],{GOOS:os,GOARCH:'arm64',CGO_ENABLED:'0'});
 const sha=digest(fs.readFileSync(dest)),versioned=path.join(out,`auxiliary-ml-v2-${os}-arm64-${sha.slice(0,12)}`),staged=versioned+'.tmp';
 fs.copyFileSync(dest,staged);fs.chmodSync(staged,0o755);fs.renameSync(staged,versioned);
 binary[os==='darwin'?'auxiliary':'auxiliary-linux-arm64']={sha256:sha,versioned_path:versioned};
}
const catalogFile=path.join(out,'catalog.json');cp.execFileSync(path.resolve(binary.auxiliary.versioned_path),['catalog','-out',catalogFile]);
const catalog=JSON.parse(fs.readFileSync(catalogFile));
for(const name of ['EXAMPLE-B1-freeze.json','EXAMPLE-B2-freeze.json','EXAMPLE-data-release.json']){
 const example=JSON.parse(fs.readFileSync(path.join('out/dpi-g03/auxiliary-ml/tooling',name)));
 if(name!=='EXAMPLE-data-release.json'){
  example.observer_version='g03-observer-v4';example.coverage_semantics_sha256=catalog.contract.coverage_semantics_sha256;
  example.observer_sha256=JSON.parse(fs.readFileSync('lab/dpi-g03/observer-v4/tooling/TOOLING.json')).binary.observer.sha256;
  example.auxiliary_binary_sha256=binary.auxiliary.sha256;example.feature_definitions_sha256=catalog.definitions_sha256;
 }
 fs.writeFileSync(path.join(out,name),JSON.stringify(example,null,2)+'\n');
}
cp.execFileSync('node',[path.join(dir,'reproduce-observer-gap.cjs')]);
const descriptor={schema:1,role:'auxiliary-ml',version:'g03-auxiliary-ml-v2',created_at:new Date().toISOString(),status:'PREPARATION_ONLY_SYNTHETIC_VERIFIED_ACTUAL_DATA_READ_AND_FIT_GATED',
 real_R2_Q_R3_test_data_read:false,actual_data_fit_performed:false,test_seeds_read:false,new_traffic_or_Docker:false,
 coverage_semantics_sha256:catalog.contract.coverage_semantics_sha256,ordering_semantics_sha256:catalog.contract.ordering_semantics_sha256,
 feature_definitions_sha256:catalog.definitions_sha256,feature_count:catalog.contract.feature_names.length,hyperparameters:catalog.contract.hyperparameters,
 source_sha256:source,source_archive_sha256:archive,source_archive_aggregate_sha256:digest(JSON.stringify(archive)),
 readonly_library_source:old.readonly_library_source,library_source_archive_sha256:library,
 previous_descriptor_sha256:'d79079de4fcd886ec7282b8f689256c704ccaef86fb552abcfc0d73225bbee39',previous_descriptor_archive:'lab/dpi-g03/auxiliary-ml-v2/tooling/history/d79079de4fcd886ec7282b8f689256c704ccaef86fb552abcfc0d73225bbee39',
 protected_V1_descriptor_sha256:digest(oldBytes),protected_V1_source_sha256:old.source_sha256,protected_V1_binary:old.binary,
 binary,checks:{race:'PASS race-test.log',vet:'PASS vet.log',tests:fs.readFileSync(path.join(out,'race-test.log'),'utf8').split('\n').filter(l=>l.startsWith('--- PASS: ')).map(l=>l.split(' ')[2]),
 actual_primary_inventory_Group_Decision_threshold_measure:'PASS includes between-window SYN; grace excluded; no fake windows',
 zero_anchor_waiver:'PASS pinned nonvacuous SYN/raw0 case only; payload/ACK-only/noSYN UNKNOWN',
 directflow_and_group_joint_budget:'PASS with highfanout and unsupported actualflows; conditional supported FPR separate',
 majority_unsupported_actual_flows:'PASS aggregate INCONCLUSIVE',
 release_before_any_index_IO:'PASS',final_policy_before_B2_index_IO:'PASS',
 frozen_observer_sampling_gap:'REPRODUCED_SYNTHETIC; independent primary-payload handshake validator rejects'},
 synthetic_observer_gap:'tooling/coverage-regression/findings.json',go_version:run(['version']).trim()};
fs.writeFileSync(path.join(out,'TOOLING.json'),JSON.stringify(descriptor,null,2)+'\n');
console.log(JSON.stringify({manifest:path.join(out,'TOOLING.json'),features_sha:catalog.definitions_sha256,tests:descriptor.checks.tests.length,binary},null,2));
