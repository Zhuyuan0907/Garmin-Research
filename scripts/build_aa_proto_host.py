#!/usr/bin/env python3
"""Generate bounded nanopb C/Python from pinned public schemas; Linux host only."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'native/aa-proto'
STAGE=ROOT/'staging/android-auto-proto-host-v1'
TOOLS=STAGE/'tools'
NP=TOOLS/'nanopb-0.4.9.1'
PROTOC=TOOLS/'protoc-21.12/bin/protoc'
SRC=ROOT/'sources/android-auto/aasdk-046b3b381595509d0939fa84b14a90978f46ff63/aasdk_proto'
TOP=['ServiceDiscoveryRequestMessage','ServiceDiscoveryResponseMessage','ChannelOpenRequestMessage',
 'ChannelOpenResponseMessage','PingRequestMessage','PingResponseMessage','AVChannelSetupRequestMessage',
 'AVChannelSetupResponseMessage','AVChannelStartIndicationMessage','AVChannelStopIndicationMessage',
 'AVMediaAckIndicationMessage','BindingRequestMessage','BindingResponseMessage','VideoFocusRequestMessage',
 'VideoFocusIndicationMessage','AudioFocusRequestMessage','AudioFocusResponseMessage','ShutdownRequestMessage','ShutdownResponseMessage']

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    for d in [BASE,BASE/'schema',BASE/'generated',BASE/'runtime']:
        d.mkdir(exist_ok=True)
    receipts=[]
    def run(argv,env=None):
        before=datetime.datetime.now(datetime.timezone.utc).isoformat()
        r=subprocess.run(argv,cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        receipts.append({'argv':argv,'started_utc':before,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        if r.returncode:raise RuntimeError('host generation command failed: '+r.stderr)
        return r
    closure=set();todo=[n+'.proto' for n in TOP]
    while todo:
        name=todo.pop()
        if name in closure:continue
        closure.add(name);todo+=re.findall(r'import\s+"([^"]+)"',(SRC/name).read_text())
    srcpins={}
    archive=ROOT/'sources/android-auto/aasdk-046b3b381595509d0939fa84b14a90978f46ff63.zip'
    if sha(archive)!='ff439a3e206edaff6c3cfa2eb458a911ddcf677e86695c0c7785377235add0e9':raise RuntimeError('aasdk archive changed')
    with zipfile.ZipFile(archive) as z:
        for name in sorted(closure):
            body=(SRC/name).read_bytes()
            if body!=z.read('aasdk-046b3b381595509d0939fa84b14a90978f46ff63/aasdk_proto/'+name):raise RuntimeError('schema drift '+name)
            (BASE/'schema'/name).write_bytes(body)
            srcpins[name]={'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body)}
    npmeta=json.loads((STAGE/'upstream-tools.json').read_text())['nanopb']
    for name in ['pb.h','pb_common.h','pb_common.c','pb_encode.h','pb_encode.c','pb_decode.h','pb_decode.c','LICENSE.txt']:
        if sha(NP/name)!=npmeta['selected_files'][name]['sha256']:raise RuntimeError('nanopb source drift '+name)
        (BASE/'runtime'/name).write_bytes((NP/name).read_bytes())
    env=dict(os.environ);env['PATH']=str(PROTOC.parent)+os.pathsep+env.get('PATH','');env['PYTHONDONTWRITEBYTECODE']='1'
    run([str(PROTOC),'--version'],env)
    run([str(PROTOC),'-I'+str(NP/'generator/proto'),'-I'+str(TOOLS/'protoc-21.12/include'),
         '--python_out='+str(NP/'generator/proto'),str(NP/'generator/proto/nanopb.proto')],env)
    py=STAGE/'python';py.mkdir(exist_ok=True)
    names=sorted(closure)
    run([str(PROTOC),'-I'+str(BASE/'schema'),'--python_out='+str(py),
         '--descriptor_set_out='+str(STAGE/'schema.desc'),'--include_imports']+
         [str(BASE/'schema'/n) for n in names],env)
    run([str(PROTOC),'-I'+str(BASE/'schema'),
         '--plugin=protoc-gen-nanopb='+str(NP/'generator/protoc-gen-nanopb'),
         '--nanopb_out=-f'+str(BASE/'bounded.options')+':'+str(BASE/'generated')]+
         [str(BASE/'schema'/n) for n in names],env)
    if len(list((BASE/'generated').glob('*.pb.h')))!=len(closure):
        raise RuntimeError('generated import closure incomplete')
    api='''/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_PROTO_H
#define AA_PROTO_H
#include "runtime/pb.h"
#include "runtime/pb_encode.h"
#include "runtime/pb_decode.h"
'''
    api+=''.join('#include "generated/'+name+'.pb.h"\n' for name in TOP)
    api+='''/* Generated API: f1x_aasdk_proto_messages_TYPE / _init_zero /
 * _init_default / _fields. _fields expands to const pb_msgdesc_t*.
 * pb_decode may modify output before failure: discard failed output.
 * No callbacks or heap fields. Build with PB_VALIDATE_UTF8=1 and never
 * PB_ENABLE_MALLOC. Required/default/unknown-field policy is in README. */
#endif
'''
    (BASE/'proto.h').write_text(api)
    c_sources=sorted(str(p.relative_to(ROOT)) for p in (BASE/'generated').glob('*.pb.c'))
    c_sources+=['native/aa-proto/runtime/pb_common.c','native/aa-proto/runtime/pb_encode.c','native/aa-proto/runtime/pb_decode.c']
    manifest={'schema':'android-auto-proto-host-build-v1','success':True,
      'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'aasdk_commit':'046b3b381595509d0939fa84b14a90978f46ff63','aasdk_archive_sha256':sha(archive),
      'root_messages':TOP,'schema_source_pins':srcpins,'nanopb_tools':json.loads((STAGE/'upstream-tools.json').read_text()),
      'include_dirs':['native/aa-proto','native/aa-proto/generated','native/aa-proto/runtime'],
      'compile_defines':['PB_VALIDATE_UTF8=1'],'forbidden_define':'PB_ENABLE_MALLOC',
      'c_sources':c_sources,'generated_header_count':len(list((BASE/'generated').glob('*.pb.h'))),
      'actual_generation_receipts':receipts,
      'files':{str(p.relative_to(ROOT)):{'sha256':sha(p),'bytes':p.stat().st_size}
        for p in [BASE/'proto.h',BASE/'bounded.options']+sorted((BASE/'generated').glob('*'))+sorted((BASE/'runtime').glob('*'))},
      'prior_setup_observations':[
        {'tool_chunk_id':'57018a','exit_code':1,'operation':'generator --help before local protoc PATH setup','reason':'protoc not on PATH; subsequently generated nanopb_pb2 with local protoc.'},
        {'tool_chunk_id':'e6a21b','exit_code':2,'operation':'own builder text creation','reason':'nested triple quotes caused Python SyntaxError before execution; replaced with apply_patch.'}],
      'scope':{'ordinary_host_generation_only':True,'Garmin_original_code_read_or_executed':False,
        'ARM_crosscompile_or_guest':False,'device_io':False,'Pixel_compatibility_proven':False}}
    (STAGE/'build.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'success':True,'schema_count':len(closure),'c_sources':len(c_sources),
      'include':'native/aa-proto/proto.h','manifest':'staging/android-auto-proto-host-v1/build.json',
      'manifest_sha256':sha(STAGE/'build.json')},indent=2))
if __name__=='__main__':main()
