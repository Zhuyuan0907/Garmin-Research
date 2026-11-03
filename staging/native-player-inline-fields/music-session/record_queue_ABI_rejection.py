#!/usr/bin/env python3
"""Pure original-opcode rejection of v1's native ABI; no emulator/device."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[3];OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
im=NativeImage();rows=[]
expected={0x270458:'ffb5',0x27045a:'85b0',0x27045e:'1098',0x270460:'0f9f',
  0x270462:'0e9e',0x27049a:'0898',0x27049c:'6946',0x27049e:'c1c1',
  0x2704a4:'0659',0x2704a8:'2b00',0x2704ac:'f549',0x2704ae:'069a',
  0x2704b0:'a930',0x2704b2:'b047',0x277c6a:'ffb5',0x277c70:'83b0',
  0x277c76:'0e9e',0x277c78:'0f00',0x277cb2:'0599',0x277cb6:'0173',
  0x277cb8:'0699',0x277cbc:'4173',0x277cd0:'0d9a',0x277cd2:'0c99'}
for a,b in expected.items():
    assert im.read(a,2).hex()==b,(hex(a),b)
    i=im.instructions(a,a+2)[0]
    rows.append(dict(PC=hex(a),opcode_hex=b,instruction=i.mnemonic+' '+i.op_str))
assert im.word(0x270884)==0xffff
v1=OUT/'verification.json';qualification=OUT/'v1-native-ABI-qualification.json'
d=dict(all_native_ABI_passed=False,v1_compile_and15_HOST_groups_retained=True,
    v1_HOST_test_scope='state logic using the same incorrect native callback ABI in mock and guard',
    v1_native_queue_execution=False,v1_unusable_for_actual2704B2_binding=True,
    exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')),
    source_sha256={str(p.relative_to(ROOT)):sha(p)for p in [Path(__file__).resolve(),ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',v1,qualification,OUT/'music_session_guard.c',OUT/'music_session_guard.h',OUT/'host_session_controls.c']},
    original_opcode_assertions=rows,assertion_count=len(rows)+1,
    literal=dict(PC='0x2704AC',literal_address='0x270884',bytes_hex=im.read(0x270884,4).hex(),value=65535),
    original_public_register_frame=dict(push_bytes=36,locals_bytes=20,total_bytes=56,
        saved_r1_kind='+0x18',saved_r3_params='+0x20',entry_stack_args_at_current_sp=['length+0x38','metadata+0x3C','force+0x40']),
    actual_native_lower_callback=dict(r0='list=record+1A8',r1='key=FFFF',r2='kind',r3='flags',
        stack_args=['params pointer','length','metadata pointer'],
        original_stack_write='27049E STM {r0=params,r6=length,r7=metadata}',
        lower_frame_bytes=48,lower_reads=dict(params='277CD2 sp+30',length='277CD0 sp+34',metadata='277C76 sp+38',kind='277CB2 sp+14',flags='277CB8 sp+18')),
    rejected_v1_callback=dict(r0='list',r1='kind (wrong)',r2='flags (wrong)',r3='params (wrong)',stack_args=['length(wrong)','metadata(wrong)','last(wrong)']),
    next_candidate='NEW v2 sources/profile only; never rewrite v1 record',
    flags=dict(static_only=True,no_guest=True,no_VM=True,no_device=True,no_old_edits=True,no_physical_candidate=True))
p=OUT/'v1-native-ABI-rejection-evidence.json'
with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
print(json.dumps(dict(path=str(p.relative_to(ROOT)),sha256=sha(p),assertions=d['assertion_count'],all_native_ABI_passed=False)))
