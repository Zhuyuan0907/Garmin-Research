#!/usr/bin/env python3
"""Development: original5D2F7C mutex/registration bootstrap, offline only."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP
from analyze_native_sections import ROOT,NativeImage
from probe_native_pool_clock import PoolClockVM
from probe_native_player_mainmenu import BUILD
from emulate_native_vpm_filesystem import REGS,require

STAGE=ROOT/'staging/native-player-gui-bootstrap'
MUTEX=0x34a59a8

class BootstrapVM(PoolClockVM):
    def __init__(self,stock,build):
        self.gui_bootstrap_entries=[]
        super().__init__(stock,build)
        require(any(r['runtime_start']<=0x34a5000 and 0x34a6000<=r['runtime_end']for r in stock.zeros),
            'GUI bootstrap mutex not inside original zero-fill BSS')
        if not any(lo<=0x34a5000<=hi for lo,hi,_ in self.uc.mem_regions()):
            self.uc.mem_map(0x34a5000,0x1000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)

    def observe(self,uc,address,size,data):
        if address in [0x5d2f7c,0x3103d8,0x3008a0,0x3896f8,0x2c0a1e,0x2c0e9a,0x5d2130,0x5d2232,
            0x351bd0,0x351be2,0x310400,0x31040c]:
            self.gui_bootstrap_entries.append(dict(entry=hex(address),arguments=[hex(uc.reg_read(r))for r in REGS],
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1)))
        return super().observe(uc,address,size,data)

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(exist_ok=True);source=Path(__file__).resolve();vm=BootstrapVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        full_scoped_final_guards_passed=False,source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest())
    try:
        result['load']=vm.load()
        result['mutex_words_before']=[hex(vm.word(MUTEX+4*n))for n in range(7)]
        result['phase']='before_original_gui_mutex_registration_bootstrap';print(json.dumps(dict(phase=result['phase'])),flush=True)
        value=vm.invoke(0x5d2f7d,())
        result.update(bootstrap_returned=hex(value),mutex_words_after=[hex(vm.word(MUTEX+4*n))for n in range(7)])
        require(vm.word(MUTEX)==0xc1b5dc,'Original bootstrap did not construct C++ mutex vtable')
        result['completed']=True
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        vm.verify_descriptor_guards();result['allocation_descriptor_guards_intact']=True
    except Exception as error:
        result.update(completed=False,error=str(error),invalid_accesses=vm.invalid_accesses,recent=list(vm.recent),
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(original_bootstrap_entries=vm.gui_bootstrap_entries,native_fatal_entries=vm.native_fatal_entries,
        conditional_writes=vm.conditional_region_writes,mutex_inventory={hex(p):n for p,n in vm.mutexes.items()},
        audio_requests=vm.audio,real_kernel_thread_owner_boot_order_and_event_delivery_verified=False)
    (STAGE/'gui-bootstrap-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','bootstrap_returned','mutex_words_after']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
