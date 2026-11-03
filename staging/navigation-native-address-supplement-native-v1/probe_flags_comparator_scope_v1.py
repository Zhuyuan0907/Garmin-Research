#!/usr/bin/env python3
"""New bounded flags8 descriptor fragment and static comparator call sites.

This does not execute house lookup/comparison or reread old/full map cases.
"""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *


def sha(raw): return hashlib.sha256(raw).hexdigest()


def main():
    output = HERE/'flags8-comparator-bounded-proof-v1.json'
    if output.exists(): raise ValueError('Refuse overwrite terminal proof')
    image = NativeImage()
    def rd(address,count):
        try: address = image.runtime_to_load(address,count)
        except ValueError: pass
        return image.read(address,count)
    code = rd(0x00173000,4096)
    if rd(0x00173C72,8).hex() != '0498c008c00701d0':
        raise ValueError('Original bit3 descriptor fragment changed')
    cases = []
    for rawflags in [0,8,5,6,13,14,40]:
        u = Uc(UC_ARCH_ARM,UC_MODE_THUMB)
        u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        u.mem_map(0x00173000,4096)
        u.mem_write(0x00173000,code)
        u.mem_protect(0x00173000,4096,UC_PROT_READ|UC_PROT_EXEC)
        u.mem_map(0x09010000,4096)
        sp = 0x09010800
        u.mem_write(sp+0x10,struct.pack('<I',rawflags))
        u.mem_write(sp+0x38,struct.pack('<I',0))
        trace,stopped = [],[]
        def observe(uc,pc,size,_):
            if pc == 0x00173C8E:
                stopped.append(True)
                uc.emu_stop()
                return
            if not 0x00173C72 <= pc < 0x00173C8E:
                raise ValueError('Fragment exceeded assigned flags scope')
            trace.append(dict(pc=hex(pc),opcode_hex=bytes(uc.mem_read(pc,size)).hex()))
        u.hook_add(UC_HOOK_CODE,observe)
        u.reg_write(UC_ARM_REG_CPSR,0x3f)
        u.reg_write(UC_ARM_REG_SP,sp)
        u.emu_start(0x00173C73,0x00173C90,count=100,timeout=100000)
        result = struct.unpack('<I',u.mem_read(sp+0x38,4))[0]
        expected = (0x40 if rawflags&8 else 0)|(0x80 if rawflags&7 else 0)
        if stopped != [True] or result != expected:
            raise ValueError('Original flag mapping differs')
        cases.append(dict(explicit_synthetic_record_out04=rawflags,initial_descriptor_flags=0,
            actual_original_descriptor_flags=result,actual_fragment_trace=trace))
    md = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    ranges = [
        (0x00173C3E,0x50,'Parent low3bits select child table; child out04 bit3 becomes descriptor flag0x40 and nonzero low3bits sets0x80'),
        (0x00173CAC,0x0E,'Child table level plus2 and descriptor flags combine into output descriptor byte9'),
        (0x044B1594,0x84,'Per-record text match callback: native record/getter followed by strlen/string matcher or SRT comparison helper'),
        (0x044B1EA2,0x48,'Per-record comparator callback: native getter followed by original1ACA74 through veneer'),
        (0x044B1F18,0x3A,'Selector chooses CP950/CP936 branch according to query attributes and current child table'),
        (0x044B1F68,0x64,'Selector chooses callbacks from original native descriptor flags and invokes binary or linear range search'),
        (0x044B1FF4,0x1C,'Exact callback/encoding literals; not Thumb instructions'),
        (0x044B1FCE,0x26,'After reading selected record, out04 bit5 and context byte0x168 control expansion'),
    ]
    fragments = []
    for address,count,purpose in ranges:
        raw = rd(address,count)
        fragments.append(dict(runtime=hex(address),bytes=count,sha256=sha(raw),hex=raw.hex(),purpose=purpose,
            instructions=[] if address == 0x044B1FF4 else [dict(pc=hex(i.address),opcode_hex=i.bytes.hex(),
                instruction=i.mnemonic+' '+i.op_str) for i in md.disasm(raw,address)]))
    veneers = []
    for address,target,description in [
        (0x0448ED08,0x001ACA75,'original comparator used by044B1EA2'),
        (0x0448EB78,0x001ACED1,'alternate SRT comparison helper used by044B1594'),
        (0x0448EEB8,0x0030C9B5,'range-search helper; exact algorithm not executed here'),
        (0x0448FFA0,0x0035B571,'strlen'),
        (0x0448F6F8,0x00523259,'alternate string matcher')]:
        raw = rd(address,8)
        if raw[:4] != bytes.fromhex('04f01fe5') or struct.unpack_from('<I',raw,4)[0] != target:
            raise ValueError('Original comparator veneer target changed')
        veneers.append(dict(runtime=hex(address),hex=raw.hex(),target=hex(target),description=description))
    result = dict(schema='AP-flags8-comparator-bounded/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=sha(Path(__file__).read_bytes()),stock_MAIN_sha256=EXPECTED,
        new_original_fragment_case_count=len(cases),all_fragment_checks_passed=True,cases=cases,
        fragment_entry='0x00173C72',fragment_stop_before='0x00173C8E',function_hooks=[],
        original_RX_page_sha256=sha(code),static_original_fragments=fragments,static_veneers=veneers,
        observed_flag8_dataflow='The decoded child out+04 bit3 becomes0x40 in descriptor flags; nonzero low3 child level also sets0x80. This establishes the transformation, not its semantic name.',
        comparator_static_path='044B1EA2→044B153A native record/text getter→0448ED08 ARM veneer→1ACA74; 044B1EEA selects callbacks and either range helper30C9B4 or linear044B1508.',
        original_comparator_executed=False,complete_house_query_or_UI_executed=False,
        native_numeric_order_of93_records_verified=False,device_IO=False,IMG_bytes_read=0,stock_map_or_DB_modified=False,
        old_closed_cases_replayed=False,full_Taiwan_address_update=False,installable=False,
        limits=['Only the newly selected flag-bit transformation runs; stack/decoded-record flag inputs are explicit synthetic fixtures.',
            'Flag8 maps to descriptor0x40; no name such as house/intersection is established. Level5/6 or out04 upper-bit full lifecycle remains unverified.',
            'Comparator entry/caller and alternate callback selection are statically located, but metadata/getter/SRT state and actual house-search path are not reconstructed here.',
            'Numeric insertion preserves observed source order but does not prove the original comparator, full query or hardware result; a device acceptance check remains necessary.',
            'No old reader, label or sort suites, nationwide records, USB, service or installation operations.'])
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(output.relative_to(ROOT)),proof_sha256=sha(output.read_bytes()),
        new_flag_cases=len(cases),all_passed=True,flags8_descriptor=64,comparator_static_entry='0x1ACA74',
        actual_house_query_verified=False),ensure_ascii=False))


if __name__ == '__main__': main()
