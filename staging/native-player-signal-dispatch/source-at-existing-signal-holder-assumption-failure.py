#!/usr/bin/env python3
"""Native signal publication reaches its callback on the Dispatcher stack.

This stops BEFORE the original MainMenu callback body. Background and idle
continuations remain resident; no UI, rendering, cleanup or device proof.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_CPSR,UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_LR
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from emulate_native_task_runtime_full import FullTaskVM,sha
from probe_native_kernel_context import POST,WAIT
from probe_native_player_mainmenu import BUILD
from emulate_native_player_menu_selection import DATABASE
from emulate_native_vpm_filesystem import REGS,RETURN,require

STAGE=ROOT/'staging/native-player-signal-dispatch'
PROOF=ROOT/'evidence/firmware-analysis/native-signal-dispatch-emulation.json'

class SignalVM(FullTaskVM):
    def __init__(self,stock,build):
        self.signal_chain=[];self.stop_before_callback=False;self.callback_endpoint=False
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        if self.kernel_active and address in [0x4b571c,0x5d28fe,0x37bce4,0x52353c,0x609338,0x574760,0x405340]:
            self.signal_chain.append(dict(entry=hex(address),running_task=hex(self.running_task),
                ready_head=hex(self.word(0xf09090)),SP=hex(uc.reg_read(UC_ARM_REG_SP)),
                LR=hex(uc.reg_read(UC_ARM_REG_LR)),arguments=[hex(uc.reg_read(r))for r in REGS],
                host_replaced_callback_or_queue=False))
        if address==0x405340 and self.stop_before_callback:
            self.callback_endpoint=True;uc.emu_stop();return
        return super().observe(uc,address,size,data)

    def invoke_to_callback(self):
        require(self.running_task==self.controller and self.word(0xf09090)==self.controller,
            'Signal yield must originate in current native controller')
        self.returned=False;self.idle_endpoint=False;self.callback_endpoint=False
        self.uc.reg_write(UC_ARM_REG_SP,self.controller);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        self.uc.emu_start(WAIT,RETURN+2,count=3000000,timeout=15000000)
        require(self.callback_endpoint and not self.returned and not self.idle_endpoint,
            'Original signal worker did not reach declared callback boundary')

    def signal_inventory(self,signal):
        raw=bytes(self.uc.mem_read(signal,0x38));begin,end,cap=struct.unpack_from('<3I',raw,4)
        require(self.word(signal)==0xc1b59c and begin<=end<=cap and (end-begin)%4==0 and cap-begin<4096,
            'Native signal vtable/vector bounds differ')
        require((begin==end==cap==0) or self.declared_storage(begin,cap-begin),
            'Native signal vector is outside live guarded storage')
        entries=[]
        for p in range(begin,end,4):
            holder=self.word(p);require(self.declared_storage(holder,8),'Callback holder is not live guarded storage')
            entries.append(dict(pointer=hex(holder),vtable=hex(self.word(holder)),callback=hex(self.word(holder+4))))
        return dict(signal=hex(signal),raw56_hex=raw.hex(),vector=[hex(n)for n in [begin,end,cap]],entries=entries,
            recursive_mutex_owner=hex(self.word(signal+0x1c+28+8)),
            recursive_mutex_depth=int.from_bytes(self.uc.mem_read(signal+0x1c+28+20,2),'little'))

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(exist_ok=True);require(not PROOF.exists(),'Keep completed proof immutable')
    source=Path(__file__).resolve();source_sha=hashlib.sha256(source.read_bytes()).hexdigest()
    build=json.loads((ROOT/BUILD).read_text());vm=SignalVM(NativeImage(),build)
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=source_sha,
        device_io=False,sounds_emitted=False,full_scoped_final_guards_passed=False)
    cases=[]
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        result['load']=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480));dbsha=sha(DATABASE)
        vm.uc.reg_write(UC_ARM_REG_CPSR,(vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        result['kernel_inventory']=vm.configure_native_kernel_inventory();vm.kernel_invoke(POST,(vm.timer_task,16))
        vm.kernel_invoke(0x5d2f7d,());dispatcher_object=vm.kernel_invoke(0x5d2131,())
        require(vm.returned and dispatcher_object==0x8800520,'Original singleton did not return')
        prior_inventory=vm.verify_singleton_inventory();prior_memory=vm.verify_memory(voice,exports,dbsha)
        record('prior_native_singleton_inventory_and_memory_guards_reproduce',inventory=prior_inventory,memory=prior_memory)
        result['phase']='original_controller_WAIT_drains_workers_then_native_idle_POST_resumes_wait'
        vm.kernel_invoke(WAIT)
        require(vm.idle_endpoint and vm.running_task==vm.idle and not any(vm.task_mutex_ops.values()),
            'Original background continuations did not drain to idle')
        wait_frame=vm.word(vm.controller+12);require(vm.word(wait_frame+4)==0x2fd0ac,'Controller current wait PC differs')
        background_inventory=vm.native_task_inventory();restore_count=len(vm.kernel_restores)
        post_result=vm.kernel_invoke(POST,(vm.controller,1),stack=vm.idle)
        require(vm.returned and not vm.idle_endpoint and vm.running_task==vm.controller and
            vm.word(0xf09090)==vm.controller and vm.uc.reg_read(UC_ARM_REG_SP)==vm.controller and
            vm.uc.reg_read(UC_ARM_REG_PC)==RETURN and post_result==1 and
            len(vm.kernel_restores)==restore_count+1 and
            vm.kernel_restores[-1]['saved_context']==hex(wait_frame) and
            vm.kernel_restores[-1]['saved_PC']=='0x2fd0ac' and
            vm.kernel_restores[-1]['original_task_resume_destination_reached'],
            'Original idle POST did not restore and return current controller wait')
        record('background_continuations_drain_and_idle_original_POST_restores_current_controller_wait',
            background_inventory=background_inventory,event_API_stimulus=1,native_restores=vm.kernel_restores,
            original_controller_WAIT_return=post_result,idle_POST_continuation_still_resident=True,
            host_wrote_ready_links_mailbox_or_saved_context=False)
        signal=dispatcher_object+0x464;before=vm.signal_inventory(signal)
        require(not before['entries'],'Expected original signal to have no prior callback holders')
        vm.kernel_invoke(0x4b571d,(signal,0x405341));require(vm.returned and vm.running_task==vm.controller,
            'Original registration did not return in controller')
        after=vm.signal_inventory(signal)
        require(len(after['entries'])==1 and after['entries'][0]['vtable']=='0xc1b584' and
            after['entries'][0]['callback']=='0x405341','Native callback registration differs')
        vm.kernel_invoke(0x5d28ff,(dispatcher_object,signal));require(vm.returned and vm.running_task==vm.controller,
            'Original signal publication did not return in controller')
        record('original_signal_register_and_publish_API_create_native_holder_and_queue_record',
            original_signal_before=before,original_signal_after=after,queue_producer_chain=vm.signal_chain)
        result['phase']='original_Dispatcher_consumes_signal_and_reaches_callback_before_body'
        vm.stop_before_callback=True;vm.invoke_to_callback()
        dispatch=vm.word(dispatcher_object+0xaa8)
        require(vm.running_task==dispatch and vm.word(0xf09090)==dispatch and
            vm.uc.reg_read(UC_ARM_REG_PC)==0x405340 and
            0x8801024<=vm.uc.reg_read(UC_ARM_REG_SP)<dispatch,
            'Callback was not reached on actual original Dispatcher stack')
        required=[0x52353c,0x609338,0x574760,0x405340]
        actual=[int(row['entry'],16)for row in vm.signal_chain]
        require(all(a in actual for a in required),'Incomplete original callback vtable/adapter chain')
        for address in required:
            require(all(row['running_task']==hex(dispatch)for row in vm.signal_chain if int(row['entry'],16)==address),
                'Callback chain was not executed by Dispatcher')
        memory=vm.verify_memory(voice,exports,dbsha);inventory=vm.native_task_inventory()
        record('native_queue_consumer_signal_vtables_and_adapter_reach_controller_callback_with_memory_guards',
            signal_chain=vm.signal_chain,current_inventory=inventory,signal=vm.signal_inventory(signal),memory=memory,
            callback_body_executed=False,foreground_or_cleanup_verified=False)
        paths={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',source}
        paths.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                p=Path(filename).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):paths.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
            source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
            all_passed=True,case_count=len(cases),cases=cases,device_io=False,sounds_emitted=False,
            full_scoped_nonmutating_memory_and_original_signal_dispatch_verified=True,
            callback_body_foreground_device_App_direct_music_or_safe_cleanup_verified=False,
            original_MAIN_patch_bytes=0,host_wrote_owner_context_ready_or_fake_callback=False,
            limits='Explicit native event1 stimulus from declared idle fixture restores controller original2FD0AC WAIT and leaves idle POST continuation resident. Original signal APIs build holder, publish native8-byte record and original Dispatcher consumes through signal/vtables/adapter to405340 before its body. All full scoped memory guards pass here; initial kernel inventory, service/FS/heap/IRQ and idle/API stimulus remain fixtures. No MainMenu callback body, root/frame/visibility/rendering/touch/physical App, phone direct music, accepted package or task quiescence/safe cleanup proof.')
        PROOF.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        result.update(completed=True,full_scoped_final_guards_passed=True,complete_proof=str(PROOF.relative_to(ROOT)),
            complete_proof_sha256=sha(str(PROOF.relative_to(ROOT))))
        print(json.dumps(dict(full_scoped_signal_dispatch_guards_passed=True,groups=len(cases),exact_dependencies=len(paths))),flush=True)
    except Exception as error:
        result.update(completed=False,error=str(error));print(json.dumps(dict(phase=result.get('phase'),error=str(error))),flush=True)
    try:inventory=vm.native_task_inventory()if vm.native_TCBs else None
    except Exception as error:inventory=dict(snapshot_error=str(error))
    result.update(cases=cases,recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,
        native_inventory=inventory,signal_chain=vm.signal_chain,native_restores=vm.kernel_restores,
        native_mutex_operations=vm.native_mutex_runs,
        pending_mutex_operations={hex(t):v for t,v in vm.task_mutex_ops.items()if v},
        registers={n:hex(vm.uc.reg_read(r))for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))},
        audio_requests=vm.audio)
    (STAGE/'signal-dispatch-terminal-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    vm.db.close()
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
