#!/usr/bin/env python3
"""Bound an instruction-pattern host search; never infer whole firmware absence.

MOVS81/LSL21 identifies one Thumb construction of10200000, not every possible
base/address path. Record only each anchor's straight-line prefix until branch,
call/return; data-flow does not cross joins or resolve indirect/controller ABI.
"""
from datetime import datetime,timezone
import hashlib,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
from capstone.arm import (ARM_OP_REG,ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC,
                          ARM_INS_B,ARM_INS_BL,ARM_INS_BLX,ARM_INS_BX)
from analyze_native_sections import NativeImage,ROOT,EXPECTED

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    stock=NativeImage();md=stock.md
    def read(address,n):return stock.read(stock.runtime_to_load(address,n),n)
    anchors=[];regions=[]
    for region in stock.copies:
        if region['runtime_start'] in (0xf00000,0xffff0000):continue
        regions.append({k:region[k] for k in ('runtime_start','runtime_end','conditional')})
        blob=stock.read(region['load_start'],region['size']);start=region['runtime_start']
        for n in range(0,len(blob)-4,2):
            first=blob[n]|(blob[n+1]<<8);second=blob[n+2]|(blob[n+3]<<8)
            if first&0xf8ff==0x2081 and second&0xffc0==0x0540 and (second>>3)&7==(first>>8)&7:
                anchors.append(start+n)
    candidates=[]
    for address in anchors:
        constants={};rows=[];accesses=[];reason='72-byte bound reached'
        for i in md.disasm(read(address,72),address):
            row={'address':hex(i.address),'instruction':i.mnemonic+' '+i.op_str};rows.append(row)
            if i.id in (ARM_INS_B,ARM_INS_BL,ARM_INS_BLX,ARM_INS_BX) or ARM_REG_PC in i.regs_access()[1]:
                reason='Stopped before branch/call/return; no control-flow join inference';break
            for op in i.operands:
                if op.type!=ARM_OP_MEM or op.mem.base not in constants:continue
                index=0
                if op.mem.index:
                    if op.shift.value:continue
                    if op.mem.index not in constants:continue
                    index=constants[op.mem.index]
                target=constants[op.mem.base]+op.mem.disp+index
                if 0x10200000<=target<0x10200400:
                    accesses.append({'instruction':hex(i.address),'operation':i.mnemonic,
                        'effective_address':hex(target),'offset':target-0x10200000})
            value=None
            if len(i.operands)>=2 and i.operands[0].type==ARM_OP_REG:
                dst=i.operands[0].reg
                if i.mnemonic in ('mov','movs'):
                    op=i.operands[1];value=op.imm if op.type==ARM_OP_IMM else constants.get(op.reg)
                elif i.mnemonic in ('lsl','lsls') and len(i.operands)==3:
                    src,shift=i.operands[1:]
                    if src.type==ARM_OP_REG and shift.type==ARM_OP_IMM and src.reg in constants:
                        value=(constants[src.reg]<<shift.imm)&0xffffffff
                elif i.mnemonic in ('add','adds'):
                    if len(i.operands)==2:
                        base=constants.get(dst);op=i.operands[1]
                    else:
                        base=constants.get(i.operands[1].reg);op=i.operands[2]
                    addition=op.imm if op.type==ARM_OP_IMM else constants.get(op.reg)
                    if base is not None and addition is not None:value=(base+addition)&0xffffffff
                elif i.mnemonic=='ldr' and i.operands[1].type==ARM_OP_MEM and i.operands[1].mem.base==ARM_REG_PC:
                    literal=((i.address+4)&~3)+i.operands[1].mem.disp
                    try:value=int.from_bytes(read(literal,4),'little')
                    except ValueError:pass
            for written in i.regs_access()[1]:constants.pop(written,None)
            if value is not None:constants[dst]=value
        assert rows[0]['instruction'].startswith('movs') and rows[1]['instruction'].startswith('lsls')
        candidates.append({'anchor':hex(address),'instructions':rows,
          'resolved_straight_line_USB_accesses':accesses,'stop_reason':reason,
          'instruction_pattern_not_confirmed_function_entry':True})
    raw=read(0x6f058c,4);assert int.from_bytes(raw,'little')==0x10200080
    arm=Cs(CS_ARCH_ARM,CS_MODE_ARM)
    excluded=[{'address':hex(i.address),'instruction':i.mnemonic+' '+i.op_str}
              for i in arm.disasm(read(0x6f0588,16),0x6f0588)]
    assert [i['instruction'].split()[0] for i in excluded]==['lsls','eorne','clzne','bx']
    assert excluded[-1]['instruction']=='bx lr'
    deps=[Path(__file__),ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',
          ROOT/'sources/native-usb/musb_regs.h',ROOT/'sources/native-usb/source-snapshots.json']
    output={'updated_utc':datetime.now(timezone.utc).isoformat(),
      'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
      'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},
      'scanned_startup_backed_regions':regions,'Thumb_base_construction_pattern':'MOVS81 then LSL21',
      'anchor_count':len(anchors),'candidates':candidates,
      'DEVCTL_offset60_in_resolved_straight_line_prefixes':[
        x for c in candidates for x in c['resolved_straight_line_USB_accesses'] if x['offset']==0x60],
      'excluded_raw_word_candidate':{'address':'0x6f058c','raw_word':'0x10200080',
        'actual_role':'ARM EORNE instruction in saturating/fixed-point helper, not a MMIO pointer',
        'bounded_original_instructions':excluded,'original_bytes_sha256':hashlib.sha256(read(0x6f0588,16)).hexdigest()},
      'all_assertions_passed':True,'register_names_from_MUSB_are_inference':True,
      'device_io':False,'firmware_modified':False,'device_install_candidate':False,
      'actual_host_driver_registration_VBUS_or_AOA_verified':False,
      'scope':'Specific instruction-shape scan of startup-backed regions, including conditional code. '
        'Fifteen Thumb MOVS81/LSL21 anchors and only straight-line prefixes until control flow. '
        'No exhaustive address/ARM/register/indirect/embedded-module search and no whole-driver '
        'absence claim. No offset60 in these prefixes is not proof DEVCTL/host absent. Raw word '
        '10200080 at6F058C positively excluded as an ARM instruction. Primary MUSB names remain '
        'comparison inference, not hardware/controller/host/VBUS or current phone evidence.'}
    name='evidence/firmware-analysis/native-usb-host-candidates.json'
    (ROOT/name).write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'evidence':name,'anchors':len(anchors),'excluded_raw_word_candidate':True,
      'DEVCTL_prefix_hits':len(output['DEVCTL_offset60_in_resolved_straight_line_prefixes']),'device_io':False}))
if __name__=='__main__':main()
