#!/usr/bin/env python3
"""Integrate original GUI dispatcher wait with original kernel event/context paths."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR
from analyze_native_sections import ROOT, NativeImage
from emulate_native_kernel_context import RoundtripVM
from probe_native_kernel_context import POST, RESTORE, STAGE
from probe_native_player_mainmenu import BUILD
from emulate_native_vpm_filesystem import REGS, require

class DispatcherKernelVM(RoundtripVM):
    def __init__(self,stock,build):
        self.native_all_task_insertions=[];self.native_TCBs=set()
        super().__init__(stock,build)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.observe_original_task_list,begin=0xf0908c,end=0xf0908f)

    def observe_original_task_list(self,uc,access,address,size,value,data):
        require(address==0xf0908c and size==4 and value and self.declared_storage(value,108),
            'Original task-list insertion outside declared full native TCB storage')
        self.native_all_task_insertions.append(dict(native_store_PC=hex(uc.reg_read(UC_ARM_REG_PC)),TCB=hex(value)))
        self.native_TCBs.add(value)

    def observe(self,uc,address,size,data):
        if self.kernel_active and address==POST:
            target=uc.reg_read(REGS[0])
            self.kernel_events.append(dict(entry=hex(address),current=hex(self.word(0xf09090)),
                arguments=[hex(uc.reg_read(r))for r in REGS],original_post_entry_reached=True,
                target_original_native_TCB_insertion_observed=target in self.native_TCBs))
            require(target in self.native_TCBs,'GUI event post target lacks observed original kernel TCB creation')
            self.visits[address]+=1;return
        if self.kernel_active and address==RESTORE:
            current=self.word(0xf09090);frame=self.word(current+12)
            require(current in self.native_TCBs,'GUI context restore target lacks original kernel TCB creation')
            row=dict(current=hex(current),saved_context=hex(frame),saved_PC=hex(self.word(frame+4)),
                context_format=bytes(uc.mem_read(current+23,1))[0],original_restore_entry_reached=True,
                original_task_resume_destination_reached=False,python_CPU_context_restore=False)
            self.kernel_restores.append(row);self.pending_restore=row;self.visits[address]+=1
            if self.native_condition_waits:self.native_condition_waits[-1]['context_restore_boundary_reached']=True
            return
        value=super().observe(uc,address,size,data)
        if address==0x300a14 and self.active_lower_wait is not None:
            self.active_lower_wait.update(same_fictional_constructor_owner_and_current_thread=False,
                observed_condition_owner_equals_current_thread=self.word(int(self.active_lower_wait['condition'],16)+8)==self.word(0xf09090))
        return value

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    source=Path(__file__);vm=DispatcherKernelVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        full_scoped_final_guards_passed=False,device_io=False,sounds_emitted=False)
    try:
        result['load']=vm.load()
        vm.uc.reg_write(UC_ARM_REG_CPSR,(vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        result['kernel_inventory']=vm.configure_native_kernel_inventory()
        vm.kernel_invoke(POST,(vm.timer_task,0x10))
        require(vm.returned and vm.word(0xf09090)==vm.controller,'Timer bootstrap did not restore controller')
        vm.kernel_invoke(0x5d2f7d,())
        require(vm.returned,'Original GUI diagnostic/mutex bootstrap did not return')
        result['phase']='original_singleton_with_native_kernel_timer_and_context'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        value=vm.kernel_invoke(0x5d2131,())
        result.update(completed=bool(vm.returned),singleton=hex(value)if vm.returned else None,
            original_singleton_returned=bool(vm.returned),idle_sentinel_reached=vm.idle_endpoint,
            original_wait_returned=bool(vm.native_condition_waits and vm.native_condition_waits[-1]['original_wait_returned']))
        if not vm.returned:result['error']='Original singleton remained blocked; original kernel restored declared idle sentinel'
    except Exception as error:
        result.update(completed=False,error=str(error),original_singleton_returned=False,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(
                ['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,
        native_all_task_insertions=vm.native_all_task_insertions,known_native_TCBs=[hex(n)for n in sorted(vm.native_TCBs)],
        kernel_events=vm.kernel_events,kernel_restores=vm.kernel_restores,kernel_calls=vm.kernel_calls,
        original_task_resume_destinations=vm.dispatch_destinations,native_condition_waits=vm.native_condition_waits,
        native_condition_owner_transfers=vm.native_condition_owner_transfers,native_full_releases=vm.native_full_releases,
        native_lower_wait_operations=vm.native_lower_wait_operations,current=hex(vm.word(0xf09090)),
        audio_requests=vm.audio,real_IRQ_or_foreground_device_App_direct_phone_music_or_safe_lifetime_verified=False)
    (STAGE/'dispatcher-native-kernel-context-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','singleton','idle_sentinel_reached']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
