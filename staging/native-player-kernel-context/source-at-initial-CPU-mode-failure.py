#!/usr/bin/env python3
"""Execute original normal-context event save/restore in the loaded-player VM."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, struct, sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP
from analyze_native_sections import ROOT, NativeImage
from probe_native_condition_timer_owner import TimerOwnerVM
from probe_native_player_mainmenu import BUILD
from emulate_native_vpm_filesystem import REGS, RETURN, require

CODE = 0x09400000
DESCRIPTORS = CODE + 0x800
CONTROLLER_STACK = 0x09500000
IDLE_STACK = 0x09505000
STACK_BYTES = 16384
POST = 0x2fcf44
WAIT = 0x2fd035
RESTORE = 0x358ec4
STAGE = ROOT / 'staging/native-player-kernel-context'

class KernelContextVM(TimerOwnerVM):
    def __init__(self, stock, build):
        self.kernel_active = False
        self.controller = self.idle = 0
        self.kernel_events = []; self.kernel_restores = []; self.kernel_calls = []
        self.idle_endpoint = False
        self.synthetic_stack_ranges = []
        super().__init__(stock, build)
        for base, size in [(CODE,4096),(CONTROLLER_STACK,STACK_BYTES),(IDLE_STACK,STACK_BYTES)]:
            require(not any(lo <= base + size - 1 and base <= hi for lo,hi,_ in self.uc.mem_regions()),
                    'Synthetic kernel input mapping overlaps existing VM')
            self.uc.mem_map(base, size)
        self.uc.mem_write(CODE, struct.pack('<2I',0xeafffffe,0xe12fff1e))
        for base in [CONTROLLER_STACK, IDLE_STACK]:
            self.uc.mem_write(base,b'\xa5'*STACK_BYTES)
            self.synthetic_stack_ranges.append((base,base+STACK_BYTES))

    def declared_storage(self, pointer, length):
        value = super().declared_storage(pointer,length)
        if value: return value
        if any(lo <= pointer and pointer+length <= hi for lo,hi in self.synthetic_stack_ranges):
            return 'explicit_synthetic_kernel_stack_input'
        return None

    def configure_native_kernel_inventory(self):
        require(self.owner_thread is None and not any(self.mutexes.values()),'Kernel configured with active locks')
        before = {hex(a):self.word(a) for a in [0xf0908c,0xf09090,0xf09094,0xf090a0]}
        for n,entry,stack,priority in [(0,CODE,IDLE_STACK,240),(1,CODE+4,CONTROLLER_STACK,16)]:
            desc=DESCRIPTORS+n*32
            self.uc.mem_write(desc,struct.pack('<5I',entry,0,stack+STACK_BYTES,priority<<16,0))
            tcb=self.invoke(0x358bf9,(desc,))
            require(tcb==((stack+STACK_BYTES-108)&~7),'Original kernel TCB placement differs')
            if n==0:self.idle=tcb
            else:self.controller=tcb
        # Explicit initial ready membership, not a recovered full boot path.
        # All TCB fields/context frames above were constructed by original358BF8.
        self.put(0xf09090,self.controller);self.put(self.controller,self.idle);self.put(self.idle,0)
        self.uc.mem_write(self.controller+22,b'\x01');self.uc.mem_write(self.idle+22,b'\x01')
        self.put(0xf09094,0)
        self.owner_thread=self.controller
        self.kernel_active=True
        self.initialize_native_timer_owner()
        self.kernel_inventory=dict(original_global_words_before=before,
            original_TCB_builder='0x358bf8',controller=hex(self.controller),idle=hex(self.idle),
            timer=hex(self.timer_task),initial_controller_idle_ready_membership_is_fixture=True,
            original_all_task_list_preserved=True,original_MAIN_instructions_patched=False,
            construction_bookkeeping_not_replaced=True,real_boot_or_physical_task_inventory_verified=False)
        return self.kernel_inventory

    def kernel_invoke(self,address,args=(),stack=None):
        require(self.kernel_active,'Original kernel inventory absent')
        self.returned=False;self.idle_endpoint=False
        if stack is None:stack=self.word(0xf09090)
        for reg,value in zip(REGS,args):self.uc.reg_write(reg,value)
        self.uc.reg_write(UC_ARM_REG_SP,stack);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        self.uc.emu_start(address,RETURN+2,count=3000000,timeout=15000000)
        require(self.returned or self.idle_endpoint,'Kernel call did not reach original return or declared idle sentinel')
        result=self.uc.reg_read(REGS[0])
        row=dict(entry=hex(address),arguments=[hex(n)for n in args],original_return_endpoint_reached=self.returned,
            idle_sentinel_reached=self.idle_endpoint,current_after=hex(self.word(0xf09090)),result=hex(result))
        self.kernel_calls.append(row)
        return result

    def observe(self,uc,address,size,data):
        if self.kernel_active:
            if address==CODE:
                require(self.word(0xf09090)==self.idle,'Idle sentinel reached on another task')
                self.idle_endpoint=True;uc.emu_stop();return
            if address in [POST,WAIT&~1]:
                self.kernel_events.append(dict(entry=hex(address),current=hex(self.word(0xf09090)),
                    arguments=[hex(uc.reg_read(r))for r in REGS],original_body_executed=True))
            if address==POST:
                require(uc.reg_read(REGS[0]) in [self.timer_task,self.controller,self.idle],
                    'Original post target outside current scoped kernel tasks')
                self.visits[address]+=1
                return # Execute original post body, bypass only PageVM ret0 boundary.
            if address==RESTORE:
                current=self.word(0xf09090);frame=self.word(current+12)
                require(current in [self.timer_task,self.controller,self.idle],
                    'Original context restore target outside scoped native tasks')
                self.kernel_restores.append(dict(current=hex(current),saved_context=hex(frame),
                    saved_PC=hex(self.word(frame+4)),context_format=bytes(uc.mem_read(current+23,1))[0],
                    original_body_executed=True,python_CPU_context_restore=False))
                self.visits[address]+=1
                return # Execute original context restore; no PC/register/owner replacement.
        return super().observe(uc,address,size,data)

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    vm=KernelContextVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        source_sha256_before_run=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        full_scoped_final_guards_passed=False)
    try:
        result['load']=vm.load();result['phase']='configure_original_kernel_inventory'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        result['inventory']=vm.configure_native_kernel_inventory()
        result['phase']='original_timer_boot_post_context_switch'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        value=vm.kernel_invoke(POST,(vm.timer_task,0x10))
        require(vm.returned and vm.word(0xf09090)==vm.controller and
            bytes(vm.uc.mem_read(vm.timer_task+22,1))==b'\x02','Timer did not block and restore original controller')
        result.update(completed=True,original_timer_post_return=hex(value))
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(
                ['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(original_timer_initialization=vm.original_timer_initialization,
        kernel_events=vm.kernel_events,kernel_restores=vm.kernel_restores,kernel_calls=vm.kernel_calls,
        native_backend_initializations=vm.backend_initializations,native_fatal_entries=vm.native_fatal_entries,
        current=hex(vm.word(0xf09090)),timer=hex(vm.timer_task),controller=hex(vm.controller),idle=hex(vm.idle),
        audio_requests=vm.audio,actual_dispatcher_foreground_device_App_or_direct_phone_audio_verified=False)
    (STAGE/'original-kernel-context-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','original_timer_post_return']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
