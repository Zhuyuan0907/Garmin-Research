#!/usr/bin/env python3
"""One original-instruction kind5 producer fixture, plus saved-window audit.

This intentionally stops at the typed allocator entry. No callback is replaced,
no external function is made to return, and no IMG/device is opened.
"""
from pathlib import Path
import hashlib
import json
import struct
import capstone
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import *

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent

def digest(b):
    return hashlib.sha256(b).hexdigest()

def put(name, value):
    p = HERE / name
    assert not p.exists(), str(p)
    p.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')

def saved_windows():
    bindings = json.loads((HERE/'input-bindings.json').read_bytes())
    result = []
    for pin in bindings['files']:
        p = ROOT/pin['path']
        b = p.read_bytes()
        assert len(b) == pin['bytes'] and digest(b) == pin['sha256'], str(p)
        assert p.stat().st_mode & 0o777 == 0o444
        if p.name.startswith('windows-'):
            result.extend((pin['path'], w) for w in json.loads(b)['windows'])
    for p in sorted(HERE.glob('windows-*.json')):
        result.extend((str(p.relative_to(ROOT)), w) for w in json.loads(p.read_bytes())['windows'])
    return result

def code_fragment(windows, start, end, mode='Thumb'):
    assert end > start
    hits = [(path,w) for path,w in windows if int(w['runtime_start'],0)<=start
            and end<=int(w['runtime_start'],0)+w['bytes']]
    assert hits, (hex(start),hex(end))
    payloads=[]
    for path,w in hits:
        raw=bytes.fromhex(w['raw_hex']); assert digest(raw)==w['sha256']
        off=start-int(w['runtime_start'],0);payloads.append(raw[off:off+end-start])
    assert all(b==payloads[0] for b in payloads)
    b=payloads[0]
    cs=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB if mode=='Thumb' else capstone.CS_MODE_ARM)
    rows=[dict(address=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
          for i in cs.disasm(b,start)]
    return dict(start=hex(start),end_exclusive=hex(end),raw_hex=b.hex(),sha256=digest(b),
                source_paths=[path for path,w in hits],instructions=rows)

def main():
    ws=saved_windows()
    producer=code_fragment(ws,0x1109f8,0x110a38)
    # Resolve every later static witness before entering the sole guest.
    for start,end in [(0x110d24,0x110d28),(0x10ee80,0x10ee98),
                      (0x358fdc,0x35902c),(0x3987f6,0x398806),
                      (0x398880,0x39888a),(0x10e886,0x10e8ec),
                      (0x10ea0c,0x10ea12),(0x1105d0,0x1105da),
                      (0x11068e,0x1106a2),(0x1106ae,0x1106ba),
                      (0x1103de,0x1103ec),(0x10c60c,0x10c65c),
                      (0x10f198,0x10f1b2),(0x110f9e,0x110fbe)]:
        code_fragment(ws,start,end)
    assert next(r for r in producer['instructions'] if r['address']=='0x110a10')['bytes']=='e080'
    assert next(r for r in producer['instructions'] if r['address']=='0x110a34')['bytes']=='b9f1fafe'
    raw=bytes.fromhex(producer['raw_hex'])
    # Distinct, synthetic RAM frame. Candidate 1500 is an opaque field value;
    # no decoded real token, actual metadata, live date or allocation is claimed.
    stack=0x02001000;payload=0x02010000;context=0x02012000
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    u.mem_map(0x110000,0x2000);u.mem_map(0x2ca000,0x1000)
    u.mem_map(0x02000000,0x20000)
    u.mem_write(0x1109f8,raw)
    literal=code_fragment(ws,0x110d24,0x110d28)
    assert bytes.fromhex(literal['raw_hex'])==struct.pack('<I',0x101a)
    u.mem_write(0x110d24,bytes.fromhex(literal['raw_hex']))
    original=bytes((i*37+11)&255 for i in range(512))
    u.mem_write(payload,original)
    u.mem_write(payload+2,struct.pack('<H',2))
    initial=bytes(u.mem_read(payload,512))
    u.mem_write(context+0x2c,struct.pack('<II',0x12345678,0x9abcdef0))
    u.mem_write(stack+0x64,struct.pack('<I',1500))
    u.mem_write(stack+0x160,struct.pack('<I',0x8d))
    u.mem_write(stack+0x170,b'\x03')
    u.mem_write(stack+0x1a8,struct.pack('<I',context))
    u.mem_write(stack+0x9c,struct.pack('<I',0xa5a5a5a5))
    u.reg_write(UC_ARM_REG_CPSR,0x3f)
    u.reg_write(UC_ARM_REG_SP,stack);u.reg_write(UC_ARM_REG_R4,payload)
    trace=[];stopped=[]
    def hook(uc,a,size,_):
        if a==0x2ca82c:
            stopped.append(a);uc.emu_stop();return
        assert 0x1109f8<=a<0x110a38, ('unexpected true code frontier',hex(a))
        trace.append(dict(address=hex(a),bytes=bytes(uc.mem_read(a,size)).hex()))
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(0x1109f9,0,count=100)
    assert stopped==[0x2ca82c]
    actual=bytes(u.mem_read(payload,512));expected=bytearray(initial)
    expected[0]=0x8d&63;expected[1]=0x03|0xa0
    expected[6:8]=struct.pack('<H',1500)
    expected[8:16]=struct.pack('<II',0x12345678,0x9abcdef0)
    assert actual==bytes(expected)
    registers=dict(type=hex(u.reg_read(UC_ARM_REG_R0)),payload_pointer=hex(u.reg_read(UC_ARM_REG_R1)),
                   length=u.reg_read(UC_ARM_REG_R2),out_pointer=hex(u.reg_read(UC_ARM_REG_R3)),
                   link_register=hex(u.reg_read(UC_ARM_REG_LR)))
    assert registers==dict(type='0x101a',payload_pointer=hex(payload),length=416,
                           out_pointer=hex(stack+0x9c),link_register='0x110a39')
    assert actual[1]>>5==5
    result=dict(schema='original-kind5-payload-producer-fixture/v1',completed_cases=1,
                completed_original_instructions=len(trace),entry='0x1109f8',stop='0x2ca82c',
                stop_before_typed_allocation=True,unknown_callback_returns_faked=False,
                original_control_and_stores_executed=True,synthetic_frame=True,
                fixture=dict(selected_candidate_field_value=1500,source_value_is_fixture=True,
                             descriptor_count=2,payload_bytes=512,opaque_pair=['0x12345678','0x9abcdef0']),
                output_fields=dict(kind=5,field0=actual[0],field6=struct.unpack_from('<H',actual,6)[0]),
                allocator_entry_registers=registers,preserved_bytes_outside_explicit_stores=True,
                initial_payload_sha256=digest(initial),actual_payload_sha256=digest(actual),
                trace=trace,IMG_reads=0,MAIN_reads=0,device_reads=0,
                decoder_provider_allocator_mapload_renderer_not_executed=True,
                actual_IMG_admission=False,renderer_proven=False,v3_fixed=False)
    put('producer-cpu-proof.json',result)
    fragments=[
        dict(name='source12_field4_store_and_original25_parser',fragments=[code_fragment(ws,0x10ee80,0x10ee98),code_fragment(ws,0x358fdc,0x35902c),code_fragment(ws,0x3987f6,0x398806),code_fragment(ws,0x398880,0x39888a)]),
        dict(name='provider_exact_match_and_max_field4',fragments=[code_fragment(ws,0x10e886,0x10e8ec),code_fragment(ws,0x10ea0c,0x10ea12)]),
        dict(name='caller_running_min_and_kind5_typed_commit',fragments=[code_fragment(ws,0x1105d0,0x1105da),code_fragment(ws,0x11068e,0x1106a2),code_fragment(ws,0x1106ae,0x1106ba),producer,literal]),
        dict(name='true12byte_source_table_supply',fragments=[code_fragment(ws,0x1103de,0x1103ec),code_fragment(ws,0x10c60c,0x10c65c)]),
        dict(name='original_consumer_kind5_and_field6_min',fragments=[code_fragment(ws,0x10f198,0x10f1b2),code_fragment(ws,0x110f9e,0x110fbe)])]
    put('five-exact-witnesses.json',dict(schema='kind5-producer-five-witnesses/v1',witnesses=fragments))
    # The first 64 bytes and remaining 416 are separate exact DATA reads.
    a=json.loads((HERE/'windows-format.json').read_bytes())['windows'][0]
    b=json.loads((HERE/'windows-fieldmap.json').read_bytes())['windows'][0]
    descriptors=struct.unpack('<120I',bytes.fromhex(a['raw_hex'])+bytes.fromhex(b['raw_hex']))
    routing=[dict(decoder_bit=i,field_word_offset=4*(v>>5),output_bit=v&31)
             for i,v in enumerate(descriptors) if v>>5==1]
    assert sorted(v['output_bit'] for v in routing)==list(range(13))
    put('source-field-routing.json',dict(schema='source25-field4-bit-routing/v1',
         table_runtime='0xb9dce4',descriptor_words=120,target_word_offset=4,routing=routing,
         normalization=dict(instruction_start='0x398880',bit12_set_becomes_zero=True),
         text_format_or_sscanf=False,actual_25byte_source_token_not_read=True))
    print(json.dumps(dict(completed_cases=1,completed_original_instructions=len(trace),stop='0x2ca82c',
                          five_witnesses=5,IMG_bytes=0,new_MAIN_bytes=json.loads((HERE/'read-ledger.json').read_bytes())['bytes'])))

if __name__=='__main__':
    main()
