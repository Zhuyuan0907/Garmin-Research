#!/usr/bin/env python3
"""Trace conditional ARM display backend into the original SGA library.

Exact backup bytes only. No live RAM or pixel output. Conditional BL/BLX
instructions are calls, not branches into the callee's CFG. Unknown computed
PC exits are recorded rather than silently called complete.
"""
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import (ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC,
    ARM_REG_LR, ARM_CC_AL, ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX,
    ARM_INS_POP, ARM_INS_LDR)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage


def sha(blob):return hashlib.sha256(blob).hexdigest()
def require(test,reason):
    if not test:raise ValueError(reason)


def arm_cfg(image,start,limit=2500):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM);md.detail=True
    queue=deque([start]);seen={};exits=[];returns=[]
    while queue and len(seen)<limit:
        address=queue.popleft()
        if address in seen:continue
        if not start<=address<start+0x3000 or address%4:
            exits.append({'target':hex(address),'reason':'Outside bounded local range'})
            continue
        i=next(md.disasm(image.read(address,4),address,count=1),None)
        if i is None:
            exits.append({'address':hex(address),'reason':'Undecodable'})
            continue
        row={'address':hex(address),'instruction':i.mnemonic+' '+i.op_str}
        seen[address]=row
        if i.id==ARM_INS_LDR and i.operands[-1].type==ARM_OP_MEM:
            operand=i.operands[-1]
            if operand.mem.base==ARM_REG_PC:
                literal=address+8+operand.mem.disp
                row.update(literal_address=hex(literal),literal_value=hex(image.word(literal)))
        if i.id in (ARM_INS_BL,ARM_INS_BLX):
            if i.operands[0].type==ARM_OP_IMM:
                row.update(direct_call=hex(i.operands[0].imm),
                           callee_instruction_set='Thumb' if i.id==ARM_INS_BLX else 'ARM')
            else:row['indirect_call']=True
        elif i.id==ARM_INS_B:
            require(i.operands[0].type==ARM_OP_IMM,'Expected direct ARM branch')
            queue.append(i.operands[0].imm)
            if i.cc==ARM_CC_AL:continue
        elif i.id==ARM_INS_BX:
            if i.operands[0].reg==ARM_REG_LR:
                returns.append(hex(address))
            else:exits.append({'address':hex(address),'reason':'Computed BX'})
            if i.cc==ARM_CC_AL:continue
        elif i.id==ARM_INS_POP and any(o.type==ARM_OP_REG and o.reg==ARM_REG_PC for o in i.operands):
            returns.append(hex(address))
            if i.cc==ARM_CC_AL:continue
        elif ARM_REG_PC in i.regs_access()[1]:
            exits.append({'address':hex(address),'reason':'Computed PC needs analysis'})
            if i.cc==ARM_CC_AL:continue
        queue.append(address+4)
    return {'entry':hex(start),'instructions':[seen[a] for a in sorted(seen)],
            'returns':returns,'unresolved_exits':exits,
            'instruction_limit_reached':bool(queue),'callees_not_recursively_executed':True}


def main():
    stock=NativeImage();image=RuntimeImage(stock)
    functions={hex(a):arm_cfg(image,a) for a in
               (0x44de688,0x44de780,0x44dea44,0x6f3bec,0x6f5ce8,0x6f63e0,0x6f63f4,0x6f9054)}
    # Incomplete functions remain explicit; this is not a whole-backend proof.
    require(all(not f['instruction_limit_reached'] for f in functions.values()),
            'Instruction bound exceeded')
    for entry in ('0x44de688','0x44dea44','0x6f5ce8','0x6f63e0','0x6f9054'):
        require(not functions[entry]['unresolved_exits'],'Unexpected unresolved local CFG: '+entry)
    veneers=[]
    for entry,target in [(0x448c838,0x6f3bec),(0x448c840,0x6f4b40),
                         (0x448c848,0x6f63f4),(0x448c788,0x3732c8),
                         (0x448c928,0x3009a1),(0x448c930,0x3008b1)]:
        require(image.word(entry)==0xe51ff004 and image.word(entry+4)==target,
                'Exact display veneer changed')
        veneers.append({'ARM_veneer':hex(entry),'target_word':hex(target),
                        'file_load_address':hex(stock.runtime_to_load(entry,8))})
    draw={int(i['address'],16):i for i in functions['0x44dea44']['instructions']}
    require(draw[0x44deb5c]['direct_call']=='0x448c848','Display SGA submission differs')
    require(draw[0x44deb0c]['instruction']=='mov ip, #4' and
            draw[0x44deb10]['instruction']=='strh ip, [sp, #0x26]',
            'Original surface format field differs')
    bpp_fn=functions['0x6f5ce8']['instructions']
    bpp_table=int(next(i['literal_value'] for i in bpp_fn if 'literal_value' in i),16)
    type_fn=functions['0x6f63e0']['instructions']
    type_table=int(next(i['literal_value'] for i in type_fn if 'literal_value' in i),16)
    require(image.read(bpp_table,8)[4]==2,'Native format4 is not two-byte pixels')
    require(image.read(0x6f9054,4)==bytes.fromhex('1eff2fe1'),
            'Expected exact native no-op fallback')
    deps={Path(__file__).resolve(),ROOT/'evidence/firmware-analysis/main_02bd.bin'}
    for module in list(sys.modules.values()):
        name=getattr(module,'__file__',None)
        if name and Path(name).resolve().parent==ROOT/'scripts' and name.endswith('.py'):
            deps.add(Path(name).resolve())
    output={'updated_utc':datetime.now(timezone.utc).isoformat(),
        'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted(deps)},
        'functions':functions,'ARM_veneers':veneers,
        'conditional_display_backend':{'init':'0x044de688','parent':'0x044de780',
            'submit':'0x044dea44','control_struct_pointer':'0x05432c28',
            'init_once_flag_offset':6,'SGA_context_offset':'0x3c',
            'SGA_manager_init':'0x6f4b40','SGA_context_create':'0x6f3bec',
            'SGA_submit':'0x6f63f4','live_conditional_activation_or_control_structure_read':False},
        'surface_descriptor_static_ABI':{'built_on_submit_stack':True,
            'primary_data_pointer_offset':0,'secondary_data_pointer_offset':4,
            'width_u16_offset':8,'height_u16_offset':10,'stride_u16_offset':12,
            'format_flags_u16_offset':14,'built_format_low3':4,
            'built_stride':'width*2 truncated to16 bits by original AND/store',
            'bpp_getter':'0x6f5ce8','bpp_table':hex(bpp_table),
            'bpp_table_bytes':list(image.read(bpp_table,8)),
            'format4_bytes_per_pixel':2,'type_getter':'0x6f63e0',
            'type_table':hex(type_table),'type_table_bytes':list(image.read(type_table,8)),
            'specific_RGB_layout_or_framebuffer_present_verified':False},
        'SGA_submit_arguments':{'R0':'source surface descriptor',
            'R1':'source rectangle of four16-bit values',
            'R2':'destination surface descriptor built on stack',
            'R3':'destination rectangle built on stack',
            'stack0':'0 selecting default options in SGA body',
            'stack1':'0x10000 fixed-point scale passed by original caller',
            'real_SGA_operation_completion_or_pixel_output_verified':False},
        'software_flag_branch_warning':{'surface_flag_mask':'0x200',
            'when_both_source_and_destination_have_flag_calls':'0x6f9054',
            'exact_6f9054_body':'BX LR',
            'is_not_evidence_of_working_software_blit':True},
        'all_assertions_passed':True,'device_io':False,'firmware_modified':False,
        'native_Android_Auto_running':False,'device_install_candidate':False,
        'limits':'Native conditional display caller/SGA veneers and surface parameter construction are statically linked. Bpp tables prove two-byte storage forformat4, not a named RGB bit layout or actual pixel presentation. Some larger CFGs may retain explicitly reported unresolved exits; direct calls are not recursively proven. Original both-flags fallback is a no-op and cannot be advertised as a software renderer. No live control pointers, conditional activation, physical register, display, phone, H264, App installation or clock/heap benchmark.'}
    path=ROOT/'evidence/firmware-analysis/native-display-path-static.json'
    path.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'functions':len(functions),
        'function_instruction_counts':{k:len(f['instructions']) for k,f in functions.items()},
        'unresolved_exits':{k:f['unresolved_exits'] for k,f in functions.items() if f['unresolved_exits']},
        'format4_bytes_per_pixel':2,'device_io':False}))


if __name__=='__main__':main()
