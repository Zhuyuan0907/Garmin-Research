#!/usr/bin/env python3
"""One original parameter case ending at the registered SD block-read entry.

No unknown call returns, storage bytes, MMIO or DMA are simulated. The fixture
selects the documented non-cache branch; its live selection remains unknown.
"""
from pathlib import Path
import hashlib
import json
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import *

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent

def sha(b): return hashlib.sha256(b).hexdigest()

def put(name, value):
    p = HERE/name
    assert not p.exists(), str(p)
    p.write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n')

def main():
    pins = json.loads((HERE/'input-bindings.json').read_bytes())
    for p in pins['files']:
        path = ROOT/p['path']; b = path.read_bytes(); s = path.stat()
        assert sha(b) == p['sha256'] and len(b) == p['bytes']
        assert [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns] == p['stat']
    oldpath = ROOT/'staging/navigation-native-ap-mount-registry-binding-v1/windows-type1read.json'
    old = json.loads(oldpath.read_bytes())
    adapter = next(w for w in old['windows'] if w['name']=='type1_real_read_callback')
    assert adapter['runtime_start']=='0x3a132c'
    assert sha(bytes.fromhex(adapter['raw_hex']))==adapter['sha256']
    current = json.loads((HERE/'windows-callbacks.json').read_bytes())
    dispatch = next(w for w in current['windows'] if w['name']=='registered_partition_read_dispatch')
    endpoint = next(w for w in current['windows'] if w['name']=='sd_block_read_entry')
    for w in [dispatch,endpoint]: assert sha(bytes.fromhex(w['raw_hex']))==w['sha256']
    # The ops target comes from original literal/store bytes, not a fake backend.
    setup = next(w for w in current['windows'] if w['name']=='lower_table_setup')
    by = {i['address']:i for i in setup['instructions']}
    assert by['0x3feb3e']['literal_value']=='0x3fea37'
    assert by['0x3feb40']['bytes']=='e066'
    provider = next(w for w in current['windows'] if w['name']=='raw_storage_provider')
    byp = {i['address']:i for i in provider['instructions']}
    assert byp['0x1d84d6']['literal_value']=='0x225b19'
    assert byp['0x1d84d8']['bytes']=='2160'
    assert by['0x3feb8c']['bytes']=='e068' and by['0x3feb8e']['bytes']=='e860'
    drive=0x08000000; geometry=0x08001000; extent=0x08002000
    dest=0x08003000; stack=0x0800f000; context=0x02cea340; part=0x02cea4d0
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    u.mem_map(0x3a1000,0x1000);u.mem_map(0x3fe000,0x1000)
    u.mem_map(0x225000,0x1000);u.mem_map(0x08000000,0x10000)
    u.mem_map(0x02cea000,0x1000)
    u.mem_write(0x3a132c,bytes.fromhex(adapter['raw_hex']))
    u.mem_write(0x3fea36,bytes.fromhex(dispatch['raw_hex']))
    u.mem_write(0x225b18,bytes.fromhex(endpoint['raw_hex']))
    def w32(a,v): u.mem_write(a,struct.pack('<I',v))
    u.mem_write(drive+1,b'\0');w32(drive+0x20,context+0x64)
    u.mem_write(geometry+6,struct.pack('<H',9))
    u.mem_write(context+0x64,struct.pack('<H',9));w32(context+0x68,0x40004)
    w32(context+0x6c,0x3fea37)
    # Explicit non-cache fixture, allowed by original 3FEB8C..96 branch.
    w32(context+0x8c,0x225b19);u.mem_write(context,b'\0')
    u.mem_write(context+0xa1,b'\1')
    w32(part,0x800);w32(part+4,0x40004)
    u.mem_write(part+8,b'\1');u.mem_write(part+0xa,b'\0')
    w32(extent+4,0x40000);w32(extent+8,8)
    w32(stack+8,geometry);w32(stack+0xc,drive);w32(stack+0x24,dest)
    sentinel=bytes((i*37+11)&255 for i in range(8192))
    u.mem_write(dest,sentinel)
    u.reg_write(UC_ARM_REG_CPSR,0x3f);u.reg_write(UC_ARM_REG_SP,stack)
    u.reg_write(UC_ARM_REG_R0,8192);u.reg_write(UC_ARM_REG_R4,extent)
    u.reg_write(UC_ARM_REG_R6,0x1e);u.reg_write(UC_ARM_REG_R7,0x20)
    u.reg_write(UC_ARM_REG_LR,0x10001)
    trace=[];stops=[];states=[]
    def regs():
        return {f'r{i}':u.reg_read(globals()[f'UC_ARM_REG_R{i}']) for i in range(4)}
    def hook(uc,a,size,_):
        if a==0x225b18:
            stops.append(a);states.append(dict(at=hex(a),registers=regs()))
            uc.emu_stop();return
        assert 0x3a1456<=a<=0x3a147e or 0x3fea36<=a<0x3feabe, hex(a)
        if a in [0x3a147e,0x3feab6]:states.append(dict(at=hex(a),registers=regs()))
        trace.append(dict(address=hex(a),bytes=bytes(uc.mem_read(a,size)).hex()))
    u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x3a1457,0,count=128)
    assert stops==[0x225b18]
    assert states[0]['registers']==dict(r0=0,r1=0x40002,r2=6,r3=dest)
    assert states[-1]['registers']==dict(r0=0,r1=0x40802,r2=2,r3=dest)
    assert u.reg_read(UC_ARM_REG_LR)==0x3feab9
    assert bytes(u.mem_read(dest,len(sentinel)))==sentinel
    assert struct.unpack('<I',u.mem_read(stack+0x10,4))[0]==6
    result=dict(schema='production-lower-block-read-original-parameter-fixture/v1',
        all_assigned_case_checks_passed=True,completed_cases=1,
        completed_original_instructions=len(trace),entry='0x3a1456',stop='0x225b18',
        original_function_entry_not_run=True,adapter_frame_mid_function_fixture=True,
        fixture=dict(drive=True,ops_record=True,partition_inventory=True,
            sector_exponent=9,remaining_bytes=8192,extent_first_sector=0x40000,
            extent_total_sectors=8,relative_sector=2,partition_sectors=0x40004,
            partition_start_sector=0x800,noncache_branch_explicitly_selected=True),
        callback_target_original_registration_proven=True,
        callback_entry_is_original_SD_block_interface_not_MMIO_driver=True,
        original_extent_min_and_partition_min_executed=True,states=states,
        final_sector=0x40802,final_sector_byte_position_under_fixture=0x40802*512,
        fixture_position_above_128MiB=True,no_board_capacity_value_verified=True,
        live_drive_mapping_and_cache_choice_unknown=True,trace=trace,
        stop_before_SD_callback_body=True,unknown_function_returns_faked=False,
        hooks_only_stop_and_observe=True,destination_8192_bytes_untouched=True,
        requested_io_not_executed=True,IMG_reads=0,MAIN_reads_during_guest=0,
        device_IO=False,MMIO_DMA_executed=False,original_mount_or_renderer_executed=False,
        actual_IMG_admission=False,AP_renderer_root_cause_established=False,v3_fixed=False)
    put('read-binding-cpu-proof.json',result)
    print(json.dumps(dict(completed_cases=1,instructions=len(trace),stop='0x225b18',
        requested_final_sector=hex(0x40802),requested_sector_count=2,IMG_bytes=0,
        lower_SD_callback_body_not_executed=True)))

if __name__=='__main__':main()
