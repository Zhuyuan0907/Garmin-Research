#!/usr/bin/env python3
"""Generate a separate bounded public input closure, never mutate aa-proto."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'native/aa-input'
STAGE=ROOT/'staging/android-auto-input-host-v1'
OLD=ROOT/'staging/android-auto-proto-host-v1'
NP=OLD/'tools/nanopb-0.4.9.1'
PROTOC=OLD/'tools/protoc-21.12/bin/protoc'
SRC=ROOT/'sources/android-auto/aasdk-046b3b381595509d0939fa84b14a90978f46ff63/aasdk_proto'
ARCHIVE=ROOT/'sources/android-auto/aasdk-046b3b381595509d0939fa84b14a90978f46ff63.zip'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    prior=json.loads((ROOT/'evidence/android-auto-control-host-v1.json').read_text())
    for name,pin in prior['source_sha256'].items():assert sha(ROOT/name)==pin,name
    for d in [BASE/'schema',BASE/'generated',STAGE,STAGE/'python']:d.mkdir(parents=True,exist_ok=True)
    closure=set();todo=['InputEventIndicationMessage.proto']
    while todo:
        name=todo.pop()
        if name in closure:continue
        assert re.fullmatch(r'[A-Za-z0-9]+\.proto',name),name
        closure.add(name);todo+=re.findall(r'import\s+"([^"]+)"',(SRC/name).read_text())
    assert sha(ARCHIVE)=='ff439a3e206edaff6c3cfa2eb458a911ddcf677e86695c0c7785377235add0e9'
    with zipfile.ZipFile(ARCHIVE) as z:
        for name in sorted(closure):
            body=(SRC/name).read_bytes()
            assert body==z.read('aasdk-046b3b381595509d0939fa84b14a90978f46ff63/aasdk_proto/'+name),name
            (BASE/'schema'/name).write_bytes(body)
    env=dict(os.environ);env['PATH']=str(PROTOC.parent)+os.pathsep+env.get('PATH','');env['PYTHONDONTWRITEBYTECODE']='1'
    receipts=[]
    def run(argv):
        p=subprocess.run(argv,cwd=ROOT,env=env,text=True,capture_output=True,timeout=60)
        receipts.append(dict(argv=argv,exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr))
        assert p.returncode==0,receipts[-1]
    run([str(PROTOC),'--version'])
    names=[str(BASE/'schema'/name) for name in sorted(closure)]
    run([str(PROTOC),'-I'+str(BASE/'schema'),'--python_out='+str(STAGE/'python')]+names)
    run([str(PROTOC),'-I'+str(BASE/'schema'),'--plugin=protoc-gen-nanopb='+str(NP/'generator/protoc-gen-nanopb'),
         '--nanopb_out=-f'+str(BASE/'bounded.options')+':'+str(BASE/'generated')]+names)
    for name,pin in prior['source_sha256'].items():assert sha(ROOT/name)==pin,name
    files=[BASE/'bounded.options',Path(__file__).resolve()]+list((BASE/'schema').glob('*.proto'))+list((BASE/'generated').glob('*.pb.*'))+list((STAGE/'python').glob('*.py'))
    old=json.loads((OLD/'build.json').read_text())
    # Bind the unmodified generator inputs already verified by control43.
    for name in prior['source_sha256']:
        if name.startswith('staging/android-auto-proto-host-v1/tools/') or name.startswith('native/aa-proto/runtime/'):
            files.append(ROOT/name)
    manifest=dict(schema='android-auto-input-build-v1',pass_=True,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        schema_count=len(closure),c_sources=[str(p.relative_to(ROOT)) for p in sorted((BASE/'generated').glob('*.pb.c'))],
        include_dirs=['native/aa-input','native/aa-input/generated']+old['include_dirs'],
        source_sha256={str(p.relative_to(ROOT)):sha(p) for p in sorted(set(files))},
        actual_generation_receipts=receipts,prior_control43_source_pins_unchanged=True,
        device_IO=False,native_guest_executed=False)
    manifest['pass']=manifest.pop('pass_')
    (STAGE/'build.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(dict(pass_=True,schemas=len(closure),manifest=str((STAGE/'build.json').relative_to(ROOT)),sha256=sha(STAGE/'build.json'))))
if __name__=='__main__':main()
