#!/usr/bin/env python3
"""One finite ARM1176 fixture group for original FE67E byte getter only."""
from pathlib import Path
import hashlib
import json
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.arm_const import UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR

HERE=Path(__file__).resolve().parent
CAPTURE=HERE/'windows-first.json'
ENTRY=0xfe67e;END=0xfe68c;LITERAL=0xfe7d0;TABLE=0xf00114;STOP=0x90000000


def stat(p):
    s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def main():
    before=stat(CAPTURE);blob=CAPTURE.read_bytes();d=json.loads(blob)
    w=next(w for w in d['windows']if w['name']=='dynamic_map_slot_getter')
    assert int(w['runtime_start'],16)==ENTRY
    code=bytes.fromhex(w['raw_hex'])[:END-ENTRY]
    assert code.hex()=='632802d25349085c7047ff207047'
    literal=next(i for i in w['instructions']if i['address']=='0xfe682')
    assert int(literal['literal_address'],16)==LITERAL and int(literal['literal_value'],16)==TABLE
    fixtures=[('mapped_slot_nonzero',2,0x63,True),('last_valid_slot',98,0x64,True),
              ('first_invalid_slot_unmapped_table',99,0xff,False),
              ('unsigned_negative_index_unmapped_table',0xffffffff,0xff,False)]
    results=[]
    for name,index,expected,map_table in fixtures:
        u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        u.mem_map(0xfe000,0x1000,UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC)
        u.mem_write(ENTRY,code);u.mem_write(LITERAL,struct.pack('<I',TABLE))
        u.mem_protect(0xfe000,0x1000,UC_PROT_READ|UC_PROT_EXEC)
        table=bytearray([0xa5]*99)
        if map_table:
            table[index]=expected
            u.mem_map(0xf00000,0x1000,UC_PROT_READ|UC_PROT_WRITE)
            u.mem_write(TABLE,bytes(table));u.mem_protect(0xf00000,0x1000,UC_PROT_READ)
        u.mem_map(STOP,0x1000,UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC)
        u.mem_write(STOP,b'\x00\xbe');u.mem_protect(STOP,0x1000,UC_PROT_READ|UC_PROT_EXEC)
        trace=[]
        def observe(cpu,address,size,data):
            assert ENTRY<=address<END,hex(address)
            trace.append(hex(address))
            assert len(trace)<=8
        u.hook_add(UC_HOOK_CODE,observe)
        u.reg_write(UC_ARM_REG_CPSR,0x33)
        u.reg_write(UC_ARM_REG_R0,index)
        u.reg_write(UC_ARM_REG_LR,STOP|1)
        u.emu_start(ENTRY|1,STOP,count=32)
        actual=u.reg_read(UC_ARM_REG_R0);pc=u.reg_read(UC_ARM_REG_PC)
        assert actual==expected and pc==STOP,(name,actual,hex(pc))
        if map_table:assert u.mem_read(TABLE,len(table))==table
        results.append(dict(name=name,input_index=index,expected=expected,actual=actual,
                            table_mapped=map_table,table_and_code_readonly=True,
                            actual_original_instruction_trace=trace,
                            stopped_after_original_BX_LR=True))
    assert stat(CAPTURE)==before
    out=HERE/'slot-getter-cpu-proof.json';assert not out.exists()
    result=dict(schema='bounded-original-slot-getter-CPU-fixture/v1',
                source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                input_capture_sha256=hashlib.sha256(blob).hexdigest(),input_capture_stat_before=before,
                input_capture_stat_after=stat(CAPTURE),MAIN_SHA_inherited=d['MAIN_SHA_inherited'],
                exact_original_entry=hex(ENTRY),exact_original_code_hex=code.hex(),
                exact_original_PC_literal_address=hex(LITERAL),exact_original_PC_literal_value=hex(TABLE),
                CPU='ARM1176 / original Thumb instructions',fixtures=results,
                instruction_semantics_or_return_hooks=[],code_hook='Read-only instruction observer only',
                stop_point='Original BX LR to fixture sentinel; no getter return substituted',
                synthetic_fixture_scope='99-slot byte mapping table only; values63/64 correspond to compared values in110308 caller, not a proved AP file binding',
                actual_map_or_driver_descriptor_tested=False,
                geometry_or_block_size_tested=False,AP_admission_or_rendering_proved=False,
                no_MAIN_IMG_USB_device_or_old_CPU_suite_opened=True)
    out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(fixture_group_count=1,fixtures=len(results),all_passed=True,
                          actual_CPU_getter_return_preserved=True,AP_binding=False,
                          proof_sha256=hashlib.sha256(out.read_bytes()).hexdigest())))


if __name__=='__main__':main()
