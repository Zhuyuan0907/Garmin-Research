#!/usr/bin/env python3
"""Extend frozen heap/settings run with original first-owner lazy VFP.

Normal kernel context restores still run and disable FPEXC. Undefined entry
uses declared virtual banked CPU/stack inputs; the original handler enables
and retries, never a host float result or a host rewrite of FP ownership.
"""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_C1_C0_2,UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_CPSR
import probe_native_heap_settings_boot as boot
from probe_native_lazy_vfp import LazyVFPState,OWNER,TRAPSTACK,TRAPBYTES
from emulate_native_vpm_filesystem import REGS,RETURN,require

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'staging/native-player-settings-vfp-context/runtime'

class LazySettingsVM(boot.HeapSettingsVM):
    last_VM=None
    def __init__(self,stock,build):
        self.fp_extra_ranges=[];self.lazy=None
        super().__init__(stock,build)
        provenance=next((r for r in stock.zeros if r['runtime_start']<=OWNER and OWNER+4<=r['runtime_end']),None)
        require(provenance is not None,'FP owner lacks exact original BSS-zero field provenance')
        page=OWNER&~4095
        if not any(lo<=page and page+4095<=hi for lo,hi,_ in self.uc.mem_regions()):
            self.uc.mem_map(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        require(self.word(OWNER)==0,'FP owner already live; refusing reset')
        require(not any(lo<=TRAPSTACK+TRAPBYTES-1 and TRAPSTACK<=hi for lo,hi,_ in self.uc.mem_regions()),
                'Declared undefined stack overlaps previous storage')
        self.uc.mem_map(TRAPSTACK,TRAPBYTES,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.mem_write(TRAPSTACK,b'\xa5'*TRAPBYTES)
        self.fp_extra_ranges=[(TRAPSTACK+32,TRAPSTACK+TRAPBYTES-32)]
        self.zones[page]=4096;self.zones[TRAPSTACK+32]=TRAPBYTES-64
        # Coprocessor access is a declared virtual startup input. This is
        # separate from FPEXC: only original restore/handler change its enable.
        self.uc.reg_write(UC_ARM_REG_C1_C0_2,0xf00000)
        require(self.uc.reg_read(UC_ARM_REG_C1_C0_2)==0xf00000,'Virtual CP10/11 input not actually set')
        self.lazy=LazyVFPState(self.uc,stock,lambda:self.running_task or self.word(0xf09090),
            lambda task,n:task in self.native_TCBs and bool(self.declared_storage(task,n)),TRAPSTACK+TRAPBYTES-32)
        self.virtual_fp_inputs=dict(CPACR='0xf00000',CPACR_is_explicit_virtual_startup_input=True,
            original_FP_boot20ED68_not_executed=True,original_FP_exit_listener_not_registered=True,
            owner_zero_field_provenance=provenance,undefined_stack=hex(TRAPSTACK),undefined_stack_bytes=TRAPBYTES,
            first_or_same_task_only=True,multi_task_FP_context_exchange_not_admitted=True)
        type(self).last_VM=self

    def declared_storage(self,pointer,length):
        value=super().declared_storage(pointer,length)
        if value:return value
        if any(lo<=pointer and pointer+length<=hi for lo,hi in getattr(self,'fp_extra_ranges',[])):
            return 'declared_guarded_architectural_undefined_stack_input'
        return None

    def observe(self,uc,address,size,data):
        if self.lazy is not None:self.lazy.observe(uc,address,size,data)
        return super().observe(uc,address,size,data)

    def journal_zone_write(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        if not self.zone_active or pc not in [0x20ebe0,0x20ec78]:
            return super().journal_zone_write(uc,access,address,size,value,data)
        require(self.lazy is not None and self.lazy.active and
                uc.reg_read(UC_ARM_REG_CPSR)&0x3f==0x1b and size==4,
                'Original handler push lacks exact active ARM undefined frame')
        row=self.lazy.active;top=self.lazy.stack_top
        if pc==0x20ebe0:
            opcode=0xe92d101f
            writes={top-24+4*n:int(row['before']['GP15'][r],16) for n,r in enumerate([0,1,2,3,4,12])}
        else:
            opcode=0xe92d4020
            writes={top-32:int(row['before']['GP15'][5],16),top-28:int(row['before']['PC'],16)+4}
        raw=struct.pack('<I',opcode)
        require(self.stock.read(pc,4)==raw and bytes(uc.mem_read(pc,4))==raw and
                address in writes and value==writes[address],
                'Original handler push opcode/address/register payload differs')
        zone=self.zone_rows[TRAPSTACK+32]
        require(int(zone['start'],16)<=address and address+size<=int(zone['start'],16)+zone['bytes'],
                'Original handler push crossed its declared undefined stack')
        zone['stores'].append(dict(PC=hex(pc),address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),phase=self.phase,
            running_task=hex(self.running_task),Thumb=False,
            original_instruction='push '+('{r0,r1,r2,r3,r4,ip}' if pc==0x20ebe0 else '{r5,lr}'),
            opcode_hex=raw.hex(),exact_original_architectural_frame_store=True))

    def kernel_invoke(self,address,args=(),stack=None):
        require(self.kernel_active,'Original native kernel inventory absent')
        self.returned=False;self.idle_endpoint=False
        if stack is None:stack=self.word(0xf09090)
        for register,value in zip(REGS,args):self.uc.reg_write(register,value)
        self.uc.reg_write(UC_ARM_REG_SP,stack);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        current=address;quanta=0
        while quanta<24:
            try:self.uc.emu_start(current,RETURN+2,count=3000000,timeout=15000000)
            except unicorn.UcError as error:
                current=self.lazy.enter(error)
                print(json.dumps(dict(phase='original_lazy_VFP',fault=self.lazy.rows[-1]['before'],
                    instruction=self.lazy.rows[-1]['original_instruction'])),flush=True)
                continue
            if self.returned or self.idle_endpoint:break
            quanta+=1;pc=self.uc.reg_read(UC_ARM_REG_PC);thumb=bool(self.uc.reg_read(UC_ARM_REG_CPSR)&32)
            current=pc|1 if thumb else pc&~1
            print(json.dumps(dict(phase='resume_same_native_kernel_work',API=hex(address),PC=hex(pc),
                quantum=quanta,original_function_not_reentered=True)),flush=True)
        require((self.returned or self.idle_endpoint) and self.lazy.active is None,
                'Original kernel work failed to reach actual endpoint or complete its lazy-VFP handler')
        value=self.uc.reg_read(REGS[0])
        self.kernel_calls.append(dict(entry=hex(address),arguments=[hex(n) for n in args],
            original_return_endpoint_reached=self.returned,idle_sentinel_reached=self.idle_endpoint,
            current_after=hex(self.word(0xf09090)),result=hex(value)))
        return value

    def verify_extra_zones(self):
        rows=super().verify_extra_zones()
        require(self.lazy.active is None and self.lazy.rows and
                all(row['original_handler_entered'] and row['original_exception_return_seen'] and
                    row['original_opcode_retry_reached'] and not row['host_wrote_FP_enable_or_context'] for row in self.lazy.rows),
                'Original lazy VFP rows incomplete')
        require(bytes(self.uc.mem_read(TRAPSTACK,32))==b'\xa5'*32 and
                bytes(self.uc.mem_read(TRAPSTACK+TRAPBYTES-32,32))==b'\xa5'*32,
                'Original handler crossed undefined-stack canary')
        require(self.word(OWNER)==self.controller and self.word(self.controller+28)==0,
                'First-owner FP scope changed actual controller/metadata provenance')
        return rows


def main():
    require(not (STAGE/'native-lazy-vfp-state.json').exists(),'Preserve prior lazy-VFP evidence')
    STAGE.mkdir(exist_ok=True)
    # Select only a new observer. The frozen driver and every guest byte stay
    # intact; terminal metadata separately attributes driver and new runner.
    boot.HeapSettingsVM=LazySettingsVM;boot.STAGE=STAGE
    try:boot.main()
    finally:
        vm=LazySettingsVM.last_VM
        if vm is not None:
            record=dict(updated_utc=datetime.now(timezone.utc).isoformat(),
                runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                helper_sha256=hashlib.sha256((ROOT/'scripts/probe_native_lazy_vfp.py').read_bytes()).hexdigest(),
                driver_sha256=hashlib.sha256((ROOT/'scripts/probe_native_heap_settings_boot.py').read_bytes()).hexdigest(),
                virtual_inputs=vm.virtual_fp_inputs,original_lazy_handler_rows=vm.lazy.rows,
                active_handler=vm.lazy.active,actual_final_registers=vm.lazy.snapshot(),
                device_io=False,sounds_emitted=False,physical_CPU_exception_or_full_boot_verified=False)
            with (STAGE/'native-lazy-vfp-state.json').open('x') as handle:
                json.dump(record,handle,ensure_ascii=False,indent=2);handle.write('\n')

if __name__=='__main__':main()
