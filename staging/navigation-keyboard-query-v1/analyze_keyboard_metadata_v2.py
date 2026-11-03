#!/usr/bin/env python3
"""Bounded static dispatch proof of stock keyboard metadata; no query execution."""
import datetime as dt
import hashlib
import json
import struct
import sys
from pathlib import Path
ROOT=Path('/root/garmin')
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from analyze_sdp_activation import BRANCHES,describe
from capstone.arm import ARM_OP_IMM
OUT=Path(__file__).resolve().parent

def bounded(im,start,end,switches,limit=1600):
    pending=[start]; seen=set(); rows=[]; exits=[]
    while pending and len(seen)<limit:
        a=pending.pop()
        while start<=a<end and a not in seen and len(seen)<limit:
            ins=next(im.md.disasm(im.read(a,4),a,count=1),None)
            if ins is None:
                exits.append(dict(address=hex(a),reason='undecodable'));break
            seen.add(a); row=describe(im,ins);rows.append(row)
            if a in switches:
                assert ins.mnemonic=='add' and ins.op_str=='pc, r3'
                row['resolved_static_switch_targets']=[hex(t) for t in switches[a]]
                pending.extend(switches[a]);break
            if ins.mnemonic=='bx' or (ins.mnemonic=='pop' and 'pc' in ins.op_str):break
            if ins.mnemonic in BRANCHES:
                if ins.operands[0].type!=ARM_OP_IMM:
                    exits.append(dict(address=hex(a),reason='indirect branch'));break
                target=ins.operands[0].imm
                if start<=target<end:pending.append(target)
                else:exits.append(dict(address=hex(a),target=hex(target),reason='external branch'))
                if ins.mnemonic=='b':break
            if ins.mnemonic in ('add','mov') and ins.reg_name(ins.operands[0].reg)=='pc':
                exits.append(dict(address=hex(a),reason='unresolved computed PC'));break
            a+=ins.size
    return dict(instructions=sorted(rows,key=lambda r:int(r['address'],16)),unresolved_exits=exits,instruction_limit_reached=len(seen)>=limit)

def main():
    im=NativeImage();checks=[]
    def require(name,cond):
        checks.append(dict(name=name,passed=bool(cond)));assert cond,name
    name_table=0xad1c10
    require('stock_code_page_tag6',im.word(name_table+6*4)==0xc7da82 and im.read(0xc7da82,20)=='code_page\0'.encode('utf-16le'))
    expected1=[('lsls','r3, r0, #1'),('add','r3, pc'),('ldrh','r3, [r3, #4]'),('lsls','r3, r3, #1'),('add','pc, r3')]
    require('tag_start_switch_original_opcode_sequence',[(i.mnemonic,i.op_str) for i in im.instructions(0x4c7e38,0x4c7e42)]==expected1)
    start_offsets=struct.unpack('<23H',im.read(0x4c7e42,46));start_targets=[0x4c7e44+2*n for n in start_offsets]
    require('tag6_start_text_accumulator_dispatch',start_targets[6]==0x4c7e70)
    require('tag_close_switch_original_opcode_sequence',[(i.mnemonic,i.op_str) for i in im.instructions(0x4c793c,0x4c7944)]==[('adr','r3, #4'),('ldrb','r3, [r3, r1]'),('adds','r3, r3, r3'),('add','pc, r3')])
    close_offsets=list(im.read(0x4c7944,14));close_targets=[0x4c7946+2*n for n in close_offsets]
    require('tag6_close_numeric_field_dispatch',close_targets[6]==0x4c7a76)
    require('parser_callback_literal_addresses', [im.word(a) for a in [0x4c8e30,0x4c8e34,0x4c8e38]]==[0x4c78d1,0x4c790f,0x4c7da5])
    fs=bounded(im,0x4c7da4,0x4c8b48,{0x4c7e40:start_targets})
    fc=bounded(im,0x4c790e,0x4c7cae,{0x4c7942:close_targets})
    require('start_dispatch_reaches_text_clear',[r for r in fs['instructions'] if r['address']=='0x4c7e76' and r.get('direct_call')=='0x3928e6'])
    require('close_dispatch_reaches_numeric_conversion',[r for r in fc['instructions'] if r['address']=='0x4c7a8c' and r.get('direct_call')=='0x2734da'])
    require('close_dispatch_stores_16_bit_object_offset48',[r for r in fc['instructions'] if r['address']=='0x4c7a92' and r['instruction']=='strh r0, [r4, #8]'])
    require('decimal_base10_original_wrapper',[(i.mnemonic,i.op_str) for i in im.instructions(0x2734da,0x2734e0)]==[('movs','r2, #0xa'),('movs','r1, #0'),('b','#0x2733ce')])
    require('finite_CFG_limits_not_reached',not fs['instruction_limit_reached'] and not fc['instruction_limit_reached'])
    result=dict(all_passed=True,checked_utc=dt.datetime.now(dt.timezone.utc).isoformat(),stock_MAIN_sha256=EXPECTED,
      source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
      scope='Bounded static analysis of original keyboard metadata callbacks, verified inline switches and code_page integer store; no UI input, keyboard character generation, map lookup or address search executed.',
      checks=checks,keyboard_code_page=950,code_page_tag_index=6,
      code_page_destination=dict(object_relative_offset='0x48',size=2,meaning='numeric keyboard header code_page; downstream consumer not traced'),
      parser_callbacks=[dict(literal=hex(a),pointer=hex(im.word(a))) for a in [0x4c8e30,0x4c8e34,0x4c8e38]],
      start_switch=dict(pc='0x4c7e40',table='0x4c7e42',target_PC_base='0x4c7e44',rows=[dict(index=n,halfword_offset=o,target=hex(t)) for n,(o,t) in enumerate(zip(start_offsets,start_targets))]),
      close_switch=dict(pc='0x4c7942',table='0x4c7944',target_PC_base='0x4c7946',rows=[dict(index=n,byte_offset=o,target=hex(t)) for n,(o,t) in enumerate(zip(close_offsets,close_targets))]),
      bounded_functions={'0x4c7da4':fs,'0x4c790e':fc},
      findings=['Original stock parser distinguishes code_page as tag6 and stores its decimal value as a 16-bit field at object+0x48.',
       'Taiwan KBD file header950 is metadata actually parsed by firmware, but does not establish the output character encoding or the map query encoding.',
       'No evidence here justifies changing zh_TW.kbd header to65001.'],
      cross_code_page_conversion_verified=False,device_search_verified=False,firmware_modified=False,device_IO=False,guest_execution=False,
      limitations=['Bounded CFG includes statically possible paths, not measured live reachability.','Other computed PC exits, if present, remain unresolved.','Downstream keyboard-to-search conversion and map lookup are outside this scope.'])
    target=OUT/'keyboard-metadata-dispatch-proof-v2.json'
    with target.open('x') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(all_passed=True,checks=len(checks),start_instructions=len(fs['instructions']),close_instructions=len(fc['instructions']),unresolved_exits=len(fs['unresolved_exits'])+len(fc['unresolved_exits']),evidence=str(target.relative_to(ROOT)))))
if __name__=='__main__':main()
