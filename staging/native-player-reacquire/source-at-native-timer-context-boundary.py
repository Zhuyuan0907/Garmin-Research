#!/usr/bin/env python3
"""Restore original timer TCB as condition constructor owner; offline probe."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP
from analyze_native_sections import ROOT,NativeImage
from probe_native_dispatcher_reacquire import ReacquireVM
from probe_native_player_mainmenu import BUILD
from emulate_native_vpm_filesystem import REGS,require

class TimerOwnerVM(ReacquireVM):
    def __init__(self,stock,build):
        self.timer_task=0;self.original_timer_initialization=None;self.native_condition_owner_transfers=[]
        super().__init__(stock,build)
        require(any(r['runtime_start']<=0x2d22000 and 0x2d23000<=r['runtime_end']for r in stock.zeros),
            'Original timer descriptor/stack outside startup zero BSS')
        if not any(lo<=0x2d22000 and 0x2d22fff<=hi for lo,hi,_ in self.uc.mem_regions()):
            self.uc.mem_map(0x2d22000,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)

    def initialize_native_timer_owner(self):
        require(self.owner_thread is not None and self.timer_task==0,'Current fixture absent or timer configured twice')
        self.uc.mem_write(0x2d226f4,b'\xa5'*320) # Explicit input stack canaries, not real free RAM.
        self.invoke(0xf6e49,())
        descriptor=struct.unpack('<5I',self.uc.mem_read(0x2d226e0,20))
        require(descriptor==(0x353d79,0,0x2d22834,1<<16,0),'Original timer descriptor differs')
        self.invoke(0x353d3d,());self.timer_task=self.word(0xf090a0)
        require(self.timer_task==(0x2d22834-108)&~7 and self.timer_task!=self.owner_thread and
            self.word(0xf09090)==self.owner_thread,'Original timer builder did not make distinct expected TCB')
        self.original_timer_initialization=dict(original_descriptor_initializer='0xf6e48',
            original_timer_initializer='0x353d3c',original_kernel_builder='0x358bf8',
            original_descriptor_words=[hex(n)for n in descriptor],native_timer_TCB=hex(self.timer_task),
            current_thread_fixture=hex(self.owner_thread),F090A0_distinct_from_F09090=True,
            timer_priority=int.from_bytes(self.uc.mem_read(self.timer_task+17,1),'little'),
            timer_ready_state=int.from_bytes(self.uc.mem_read(self.timer_task+22,1),'little'),
            timer_saved_context=hex(self.word(self.timer_task+12)),
            timer_stack_leading24_canaries_unchanged=bytes(self.uc.mem_read(0x2d226f4,24))==b'\xa5'*24,
            timer_boot_event_post_or_real_clock_interrupt_verified=False,
            host_seeded_timer_owner_pointer=False)
        return self.timer_task

    def observe(self,uc,address,size,data):
        if address==0x3ec57e and self.timer_task and self.active_condition is not None:
            ptr=int(self.active_condition['pointer'],16)
            self.native_condition_owner_transfers.append(dict(condition=hex(ptr),
                original_transfer='0x300ae4',native_owner_after_transfer=hex(self.word(ptr+8)),
                original_timer_TCB=hex(self.timer_task),owner_matches_timer=self.word(ptr+8)==self.timer_task,
                current_thread_fixture=hex(self.owner_thread),real_event_delivery_verified=False))
        return super().observe(uc,address,size,data)

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    stage=ROOT/'staging/native-player-reacquire';source=Path(__file__).resolve()
    vm=TimerOwnerVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),full_scoped_final_guards_passed=False)
    try:
        result['load']=vm.load();vm.configure_thread_fixture();result['phase']='before_original_timer_owner_initialization'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        vm.initialize_native_timer_owner();vm.invoke(0x5d2f7d,())
        result['phase']='before_original_singleton_with_distinct_native_timer_owner'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        value=vm.invoke(0x5d2131,());result.update(completed=True,singleton=hex(value),original_singleton_returned=True)
    except Exception as error:
        result.update(completed=False,error=str(error),original_singleton_returned=False,
            original_return_endpoint_reached=vm.returned,recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(
                ['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(original_timer_initialization=vm.original_timer_initialization,
        native_condition_owner_transfers=vm.native_condition_owner_transfers,
        native_fatal_entries=vm.native_fatal_entries,native_mutex_operations=vm.native_mutex_runs,
        native_condition_waits=vm.native_condition_waits,native_full_releases=vm.native_full_releases,
        native_lower_wait_operations=vm.native_lower_wait_operations,native_condition_constructor_runs=vm.condition_constructor_runs,
        active_wait=vm.active_wait,active_lower_wait=vm.active_lower_wait,
        native_mutex_inventory={hex(p):n for p,n in vm.mutexes.items()},
        wake_boundary_fixtures=vm.wake_boundaries,audio_requests=vm.audio,
        actual_worker_wake_timer_block_unblock_scheduler_controller_foreground_or_device_App_verified=False)
    (stage/'native-timer-owner-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','singleton']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
