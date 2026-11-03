#!/usr/bin/env python3
"""Isolated actual Unicorn hook ordering; not a controller/font endpoint proof."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_CPSR,UC_ARM_REG_R0,UC_ARM_REG_R1
from analyze_native_sections import NativeImage
ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'staging/native-player-controller-gir-integration/cache-hook-micro-v3'
PC=0x263fce;BASE=0x34fa3bc;TARGET=BASE+4;PAGE=BASE&~4095
def main():
    assert unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247)
    STAGE.mkdir(parents=True,exist_ok=True)
    source=Path(__file__).resolve();snapshot=STAGE/'source-at-run.py'
    assert not snapshot.exists();snapshot.write_bytes(source.read_bytes())
    stock=NativeImage();opcode=stock.read(PC,2);assert opcode==bytes.fromhex('4160')
    assert any(z['runtime_start']<=PAGE and PAGE+4096<=z['runtime_end']for z in stock.zeros)
    cases=[]
    for mode in ['native_invalid_mapping_only','read_before_native_invalid_mapping','verified_zero_mapping_declared_before_emulation']:
        uc=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_THUMB)
        uc.mem_map(PC&~4095,4096);uc.mem_write(PC,opcode);uc.mem_protect(PC&~4095,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        uc.reg_write(UC_ARM_REG_CPSR,0x1ff);uc.reg_write(UC_ARM_REG_R0,BASE);uc.reg_write(UC_ARM_REG_R1,0x18000)
        if mode=='verified_zero_mapping_declared_before_emulation':
            uc.mem_map(PAGE,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        events=[];observed_error=None
        def invalid(vm,access,address,size,value,data):
            assert address==TARGET and size==4
            events.append(dict(event='native_unmapped_callback',address=hex(address),access=access))
            vm.mem_map(PAGE,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE);return True
        def write(vm,access,address,size,value,data):
            assert address==TARGET and size==4 and value==0x18000 and vm.reg_read(UC_ARM_REG_PC)==PC
            events.append(dict(event='CPU_write_callback',address=hex(address),size=size,value=value,
                target_already_mapped=any(lo<=TARGET and TARGET+3<=hi for lo,hi,_ in vm.mem_regions())))
            if mode=='native_invalid_mapping_only':return
            try:
                before=bytes(vm.mem_read(address,size));events.append(dict(event='host_before_read',before_hex=before.hex()))
            except unicorn.UcError as error:
                events.append(dict(event='host_before_read_UcError',errno=error.errno,message=str(error)));raise
        uc.hook_add(unicorn.UC_HOOK_MEM_WRITE_UNMAPPED,invalid)
        uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,write,begin=PAGE,end=PAGE+4095)
        try:uc.emu_start(PC|1,PC+2,count=1)
        except unicorn.UcError as error:observed_error=dict(errno=error.errno,message=str(error))
        actual=bytes(uc.mem_read(TARGET,4)).hex()
        if mode=='read_before_native_invalid_mapping':
            assert observed_error and observed_error['errno']==unicorn.UC_ERR_READ_UNMAPPED
            assert events[0]['event']=='CPU_write_callback'and not events[0]['target_already_mapped']
        else:assert observed_error is None and actual=='00800100'
        cases.append(dict(mode=mode,passed=True,events=events,observed_error=observed_error,native_stored_bytes_hex=actual))
        print(json.dumps(dict(mode=mode,observed_error=observed_error,native_stored_bytes_hex=actual)),flush=True)
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,case_count=3,cases=cases,
        source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest(),
            str(snapshot.relative_to(ROOT)):hashlib.sha256(snapshot.read_bytes()).hexdigest(),
            'evidence/firmware-analysis/main_02bd.bin':hashlib.sha256((ROOT/'evidence/firmware-analysis/main_02bd.bin').read_bytes()).hexdigest()},
        original_single_instruction_PC=hex(PC),original_opcode_hex=opcode.hex(),registers_and_mapping_are_explicit_micro_fixtures=True,
        native_controller_allocator_or_fonts_endpoint_not_executed=True,old85428_underlying_UcError_was_not_captured=True,
        old_failure_cause_is_inference_from_matching_PC_and_source_not_retroactive_observation=True,device_io=False,sounds_emitted=False)
    with (STAGE/'hook-order-controls.json').open('x')as out:json.dump(result,out,ensure_ascii=False,indent=2);out.write('\n')
    print(json.dumps(dict(all_passed=True,case_count=3,before_read_fault=cases[1]['observed_error'],device_io=False)))
if __name__=='__main__':main()
