#!/usr/bin/env python3
"""Build only official OpenH264 software decoder/common and our Linux ABI."""
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'staging/android-auto-h264-host-v1'
SOURCE=STAGE/'openh264-1a0073f0322c8b74cbcb75ca1bb1c3d19d75538d'
BASE=ROOT/'native/aa-h264'
ARCHIVE=STAGE/'openh264-1a0073f0322c8b74cbcb75ca1bb1c3d19d75538d.tar.gz'
PIN='3e021e6046dcd79f70fa7842896a85cb2205575ea6170db023c4318fafcb0040'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    assert sha(ARCHIVE)==PIN
    # Exact archive bytes for every selected compilation source/header.
    sources=sorted((SOURCE/'codec/common/src').glob('*.cpp'))
    sources+=sorted((SOURCE/'codec/decoder/core/src').glob('*.cpp'))
    sources+=sorted((SOURCE/'codec/decoder/plus/src').glob('*.cpp'))
    headers=sorted((SOURCE/'codec').rglob('*.h'))+[SOURCE/'build/platform-gnu-chain.mk']
    pins={}
    with tarfile.open(ARCHIVE) as archive:
        for p in sources+headers:
            member='openh264-1a0073f0322c8b74cbcb75ca1bb1c3d19d75538d/'+str(p.relative_to(SOURCE))
            assert archive.extractfile(member).read()==p.read_bytes(),member
            pins[str(p.relative_to(ROOT))]=sha(p)
    includes=[SOURCE/'codec/api/wels',SOURCE/'codec/common/inc',SOURCE/'codec/decoder/core/inc',SOURCE/'codec/decoder/plus/inc',BASE]
    receipts=[]
    def run(argv):
        start=time.monotonic()
        r=subprocess.run([str(a) for a in argv],cwd=ROOT,text=True,capture_output=True,timeout=120)
        record={'argv':[str(a) for a in argv],'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'elapsed_seconds':time.monotonic()-start}
        assert r.returncode==0,record
        return record
    receipts.append(run(['g++','--version']))
    builds=[]
    for name,flags in [('ordinary',['-O2']),('asan-ubsan',['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        out=STAGE/name;out.mkdir(exist_ok=True)
        argvbase=['g++','-std=c++11','-pthread','-fPIC','-fno-strict-aliasing']+flags+['-I'+str(p) for p in includes]
        commands=[argvbase+['-c',str(p),'-o',str(out/(p.stem+'.o'))] for p in sources]
        with ThreadPoolExecutor(max_workers=3) as pool:
            receipts.extend(pool.map(run,commands))
        receipts.append(run(argvbase+['-Wall','-Wextra','-Werror','-c',str(BASE/'h264.cpp'),'-o',str(out/'aa_h264.o')]))
        objects=[out/(p.stem+'.o') for p in sources]+[out/'aa_h264.o']
        library=out/'libaa_h264.a'
        receipts.append(run(['ar','rcs',str(library)]+objects))
        shared=out/'libaa-h264-host.so'
        receipts.append(run(['g++','-shared','-Wl,--no-undefined','-Wl,--whole-archive',str(library),'-Wl,--no-whole-archive','-pthread']+
                            (['-fsanitize=address,undefined'] if name=='asan-ubsan' else [])+['-o',str(shared)]))
        builds.append({'name':name,'library':str(library.relative_to(ROOT)),'library_sha256':sha(library),
                       'shared_library':str(shared.relative_to(ROOT)),'shared_library_sha256':sha(shared),
                       'link_flags':['-pthread'],'sanitize_flags':flags if name=='asan-ubsan' else [],'object_count':len(objects)})
        for p in objects:p.unlink()
    proof={'schema':'android-auto-h264-host-build-v1','pass':True,
           'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'source':json.loads((STAGE/'source.json').read_text()),'source_sha256':pins,
           'wrapper_sha256':{str(p.relative_to(ROOT)):sha(p) for p in [BASE/'h264.h',BASE/'h264.cpp',Path(__file__).resolve()]},
           'include_dirs':[str(BASE.relative_to(ROOT)),str((SOURCE/'codec/api/wels').relative_to(ROOT))],
           'builds':builds,'actual_compile_receipts':receipts,'upstream_cpp_count':len(sources),
           'assembly_compiled':False,'encoder_compiled':False,'decoder_threads':0,
           'ordinary_linux_host_only':True,'device_IO':False,'native_guest_executed':False,'ARM_crosscompile':False}
    path=STAGE/'build.json';path.write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'pass':True,'upstream_cpp_count':len(sources),'builds':builds,'manifest':str(path.relative_to(ROOT)),'manifest_sha256':sha(path)},indent=2))
if __name__=='__main__':main()
