#!/usr/bin/env python3
"""Original dispatcher with native C++ mutex ownership; scheduler still open."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_R4
from analyze_native_sections import ROOT,NativeImage
from probe_native_mutex_owner import OwnerVM
from probe_native_player_mainmenu import BUILD
from emulate_native_vpm_filesystem import REGS,require,RETURN

class DispatcherOwnerVM(OwnerVM):
    def __init__(self,stock,build):
        self.native_condition_waits=[]
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        caller=uc.reg_read(UC_ARM_REG_LR)&~1
        if self.owner_thread is not None and address==0x3ec5c6:
            cond,mutex,deadline,kind=[uc.reg_read(r)for r in REGS]
            self.native_condition_waits.append(dict(original_entry=hex(address),native_caller=hex(caller),
                condition=hex(cond),mutex=hex(mutex),native_argument=hex(deadline),native_kind=kind,
                semaphore_owner_before=hex(self.word(mutex+8)),fixture_thread=hex(self.owner_thread),
                native_owner_gate_passed=False,original_wait_returned=False,real_kernel_wait_verified=False))
        if address==0x3ec5ea and self.native_condition_waits:
            row=self.native_condition_waits[-1]
            require(self.word(int(row['mutex'],16)+8)==uc.reg_read(UC_ARM_REG_R4),
                'Original wait owner gate task identity differs')
            row['native_owner_gate_passed']=True
        if self.owner_thread is not None and address in [0x3009a0,0x3008b0]:
            ptr=uc.reg_read(REGS[0]);cpp=caller==(0x310408 if address==0x3009a0 else 0x310414)
            aux=(address==0x3009a0 and caller==0x3ec61c and self.native_condition_waits and
                ptr==int(self.native_condition_waits[-1]['condition'],16)+28)
            if cpp or aux:
                require(self.declared_storage(ptr,24),'Native C++/condition semaphore outside owned storage')
                if cpp:require(self.word(ptr-4)==0xc1b5dc and self.word(ptr+16)==0x31041c,
                    'Original C++ mutex vtable or native diagnostic tag differs')
                if ptr not in self.native_semaphores:self.register_native_semaphore(ptr)
                require(self.native_lock_run is None and self.word(0xf09090)==self.owner_thread,
                    'Unexpected nested original C++/condition mutex scope')
                row=dict(original_entry=hex(address),pointer=hex(ptr),native_caller=hex(caller),
                    operation='lock'if address==0x3009a0 else'unlock',
                    before_words=[hex(self.word(ptr+4*n))for n in range(6)],fixture_thread=hex(self.owner_thread),
                    native_body_returned=False,semaphore_fields_written_by_original_only=True,
                    real_kernel_scheduler_verified=False,scope='original_Cpp_mutex'if cpp else'original_condition_auxiliary_lock')
                self.native_mutex_runs.append(row);self.native_lock_run=row;self.visits[address]+=1;return
        if address==0x358ec4 and self.native_condition_waits:
            self.native_condition_waits[-1]['context_restore_boundary_reached']=True
            raise ValueError('Native condition wait reached kernel context restore beyond single-thread fixture scope')
        return super().observe(uc,address,size,data)

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    stage=ROOT/'staging/native-player-mutex-owner';source=Path(__file__).resolve()
    vm=DispatcherOwnerVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),full_scoped_final_guards_passed=False)
    try:
        result['load']=vm.load();vm.configure_thread_fixture();vm.invoke(0x5d2f7d,())
        result['phase']='before_original_singleton_with_native_mutex_owner'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        value=vm.invoke(0x5d2131,())
        result.update(completed=True,singleton=hex(value),original_singleton_returned=True)
    except Exception as error:
        result.update(completed=False,error=str(error),original_singleton_returned=False,
            recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(
                ['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(original_bootstrap_entries=vm.gui_bootstrap_entries,native_fatal_entries=vm.native_fatal_entries,
        native_mutex_operations=vm.native_mutex_runs,native_condition_waits=vm.native_condition_waits,
        native_condition_constructor_runs=vm.condition_constructor_runs,
        retained_condition_tokens=list(vm.dispatcher_condition_tokens.values()),
        original_thread_fixture_inventory=vm.fixture_thread_inventory,
        active_native_mutex_operation=vm.native_lock_run,mutex_inventory={hex(p):n for p,n in vm.mutexes.items()},
        wake_boundary_fixtures=getattr(vm,'wake_boundaries',[]),audio_requests=vm.audio,
        original_controller_root_foreground_safe_lifetime_or_device_App_verified=False)
    (stage/'dispatcher-native-owner-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','singleton']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
