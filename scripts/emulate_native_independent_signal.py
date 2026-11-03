#!/usr/bin/env python3
"""Independent original Signal publishes a callback on native Dispatcher.

The stock cleanup Signal is retained unchanged. This uses explicit native
allocator/constructor/API inputs and stops before the MainMenu callback body.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_CPSR,UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_LR
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_signal_dispatch import SignalVM
from emulate_native_task_runtime_full import sha
from probe_native_kernel_context import POST,WAIT
from probe_native_player_mainmenu import BUILD
from emulate_native_player_menu_selection import DATABASE
from emulate_native_vpm_filesystem import REGS,RETURN,require

STAGE=ROOT/'staging/native-player-independent-signal'
PROOF=ROOT/'evidence/firmware-analysis/native-independent-signal-emulation.json'

class IndependentSignalVM(SignalVM):
    def signal_inventory(self,signal):
        require(self.declared_storage(signal,80),'Original Signal object outside live storage')
        raw=bytes(self.uc.mem_read(signal,80));words=struct.unpack('<20I',raw)
        require(words[0]==0xc1b59c and words[7]==0xc1b5c4 and words[18]==0x46c2c8,
            'Original Signal type/recursive native tag differs')
        vectors=[]
        for offset in [4,16]:
            begin,end,cap=struct.unpack_from('<3I',raw,offset)
            require(begin<=end<=cap and (end-begin)%4==0 and cap-begin<4096,
                'Native Signal vector bounds differ')
            require((begin==end==cap==0)or self.declared_storage(begin,cap-begin),'Signal vector backing not live')
            entries=[]
            for p in range(begin,end,4):
                holder=self.word(p);vtable=self.word(holder)
                length={0xc1b584:8,0xc1b56c:16}.get(vtable)
                require(length is not None and self.declared_storage(holder,length),'Unknown callback type/lifetime')
                entry=dict(pointer=hex(holder),vtable=hex(vtable),bytes=length,
                    raw_hex=bytes(self.uc.mem_read(holder,length)).hex())
                if length==8:entry.update(kind='free_function',function=hex(self.word(holder+4)))
                else:entry.update(kind='member_function',object=hex(self.word(holder+4)),
                    encoded_function=hex(self.word(holder+8)),encoded_adjustment=hex(self.word(holder+12)))
                entries.append(entry)
            vectors.append(dict(offset=offset,bounds=[hex(v)for v in [begin,end,cap]],entries=entries))
        return dict(signal=hex(signal),raw80_hex=raw.hex(),vectors=vectors,
            native_mutex=hex(signal+56),native_mutex_raw24_hex=bytes(self.uc.mem_read(signal+56,24)).hex())

    def timed_thread_inventory(self,thread):
        frame=self.word(thread+12);words=struct.unpack('<13I',self.uc.mem_read(frame,52));node=words[11]+4
        require(self.word(frame+4)==0x353c64 and self.uc.mem_read(thread+22,1)[0]==8 and
            self.declared_storage(frame,52)and self.declared_storage(node,20),
            'Original timed Thread saved frame/state/node backing differs')
        raw=bytes(self.uc.mem_read(node,20));nextnode,target,deadline,type_word,parameter=struct.unpack('<5I',raw)
        require(self.word(0xf0909c)==node and nextnode==0 and target==thread and raw[12]==2,
            'Original Thread timed-node list/target/kind differs')
        return dict(thread=hex(thread),frame=hex(frame),saved_frame13_words=[hex(n)for n in words],
            node=hex(node),raw20_hex=raw.hex(),deadline=deadline,type_byte=raw[12],
            type_word_padding_not_interpreted=hex(type_word),type_specific_parameter_observed=hex(parameter),current_clock=self.word(0xf09098),
            virtual_clock_is_fixture=True,physical_timer_IRQ_verified=False)

    def callback_endpoint_inventory(self,D,S,before_timed,idle_frame):
        dispatch=self.word(D+0xaa8);thread=next(t for t in self.native_TCBs if t not in [self.controller,self.idle,self.timer_task,dispatch])
        inventory=self.native_task_inventory()
        require(inventory['all_tasks']==[hex(t)for t in [thread,dispatch,self.timer_task,self.controller,self.idle]] and
            inventory['ready']==[hex(dispatch),hex(self.idle)],'Callback native ALL/ready inventory differs')
        for t,state,priority in [(thread,8,92),(dispatch,1,92),(self.timer_task,2,1),(self.controller,2,16),(self.idle,1,240)]:
            require(self.declared_storage(t,108)and self.uc.mem_read(t+22,1)[0]==state and
                self.uc.mem_read(t+16,1)[0]==self.uc.mem_read(t+17,1)[0]==priority,'Endpoint task state/priority/live backing differs')
            for offset in [56,80]:
                require(self.word(t+offset+8)==self.word(t+offset+12)==0 and
                    int.from_bytes(self.uc.mem_read(t+offset+20,2),'little')==0,'Native task internal semaphore still owned/queued')
        signal_mutex=S+56;Dmutex=D+0xaec;condition=self.timer_task and int(self.native_condition_waits[0]['condition'],16)
        for p,owner,nextptr,prev,depth,tag in [(signal_mutex,dispatch,Dmutex,dispatch+32,1,0x46c2c8),
                (Dmutex,dispatch,0,signal_mutex,0,0x31041c),(condition,self.timer_task,0,self.timer_task+32,0,self.word(condition+16))]:
            values=struct.unpack('<6I',self.uc.mem_read(p,24))
            require(values[:5]==(nextptr,prev,owner,0,tag)and values[5]&0xffff==depth,
                'Callback native owned semaphore links/owner/waiter/tag/depth differ '+hex(p))
        require(self.word(dispatch+32)==signal_mutex and self.word(self.timer_task+32)==condition and
            all(self.word(t+32)==0 for t in [self.controller,thread,self.idle]),'Endpoint per-task owned heads differ')
        require({p:n for p,n in self.mutexes.items()if n}=={signal_mutex:2,Dmutex:1},'Callback ordinary recursion counters differ')
        require(not any(self.task_mutex_ops.values())and not any(self.task_waits.values())and
            not any(self.task_releases.values())and not any(self.task_lower_waits.values()),'Callback unresolved native mutex continuation')
        sp=self.uc.reg_read(UC_ARM_REG_SP);lr=self.uc.reg_read(UC_ARM_REG_LR)
        require(sp==0x8804f78 and lr==0x60935d and self.running_task==dispatch and self.word(0xf09090)==dispatch,
            'Actual Dispatcher callback SP/LR/task differs')
        require([self.word(p)for p in [0x8804f9c,0x8804f88,0x8804f78]]==[D+0xae8,S+28,S+28] and
            [self.word(0x8804fa0),self.word(0x8804fa4)]==[S,0],'Original live signal RAII cells/8-byte worker record differ')
        require(self.uc.mem_read(dispatch+18,1)[0]==self.uc.mem_read(dispatch+21,1)[0] and
            self.word(dispatch+4)&2==0,'Native queue read/write cursors or event2 consume differ')
        timed=self.timed_thread_inventory(thread)
        require(timed==before_timed,'Original background Thread timed node/context/clock changed during independent signal dispatch')
        require(self.word(self.idle+12)==idle_frame and self.word(idle_frame+4)==0x2fd016 and
            self.word(idle_frame)&31==31 and self.declared_storage(idle_frame,52),'Idle POST original continuation no longer live')
        ctl_frame=self.word(self.controller+12)
        require(self.word(ctl_frame+4)==0x2fd0ac and self.word(ctl_frame)&31==31 and self.declared_storage(ctl_frame,52),
            'Controller current WAIT continuation differs')
        return dict(native_inventory=inventory,owned_semaphores={hex(p):bytes(self.uc.mem_read(p,24)).hex()for p in [signal_mutex,Dmutex,condition]},
            timed_thread=timed,active_Dispatcher_SP=hex(sp),active_Dispatcher_LR=hex(lr),
            active_Dispatcher_old_saved_frame_is_consumed_not_resumable=True,
            controller_wait_frame=hex(ctl_frame),idle_POST_frame=hex(idle_frame),idle_POST_PC='0x2fd016',
            actual_queue_record=[hex(S),0],queue_event2_consumed=True,resident_signal_mutex_acquisitions=2,
            resident_Dispatcher_mutex_acquisitions=1,safe_cleanup_or_task_exit_verified=False)

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(exist_ok=True);require(not PROOF.exists(),'Keep completed proof immutable')
    source=Path(__file__).resolve();build=json.loads((ROOT/BUILD).read_text());vm=IndependentSignalVM(NativeImage(),build)
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        device_io=False,sounds_emitted=False,full_scoped_final_guards_passed=False);cases=[]
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        result['load']=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480));dbsha=sha(DATABASE)
        vm.uc.reg_write(UC_ARM_REG_CPSR,(vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        result['kernel_inventory']=vm.configure_native_kernel_inventory();vm.kernel_invoke(POST,(vm.timer_task,16))
        vm.kernel_invoke(0x5d2f7d,());D=vm.kernel_invoke(0x5d2131,())
        require(vm.returned and D==0x8800520,'Original singleton return differs')
        record('prior_original_singleton_task_inventory_and_full_memory_guards_reproduce',
            native_inventory=vm.verify_singleton_inventory(),memory=vm.verify_memory(voice,exports,dbsha))
        result['phase']='original_background_WAIT_and_idle_POST_controller_return'
        vm.kernel_invoke(WAIT);require(vm.idle_endpoint and vm.running_task==vm.idle and not any(vm.task_mutex_ops.values()),
            'Original background continuations did not drain')
        frame=vm.word(vm.controller+12);require(vm.word(frame+4)==0x2fd0ac,'Controller current WAIT savedPC differs')
        start=len(vm.kernel_restores);value=vm.kernel_invoke(POST,(vm.controller,1),stack=vm.idle)
        require(vm.returned and value==1 and vm.running_task==vm.controller and vm.uc.reg_read(UC_ARM_REG_SP)==vm.controller and
            len(vm.kernel_restores)==start+1 and vm.kernel_restores[-1]['saved_context']==hex(frame)and
            vm.kernel_restores[-1]['saved_PC']=='0x2fd0ac'and vm.kernel_restores[-1]['original_task_resume_destination_reached'],
            'Original idle POST did not resume exact current controller WAIT')
        idle_frame=vm.word(vm.idle+12);thread=vm.word(D+0x4ba4+0)
        thread_task=next(t for t in vm.native_TCBs if t not in [vm.controller,vm.idle,vm.timer_task,vm.word(D+0xaa8)])
        require(thread and vm.declared_storage(thread,12)and vm.word(thread+8)==thread_task,
            'Original Thread object/live native TCB link differs')
        before_timed=vm.timed_thread_inventory(thread_task)
        record('native_background_drain_and_original_idle_POST_restore_controller_with_live_timed_Thread',
            native_restores=vm.kernel_restores,timed_thread=before_timed,idle_POST_frame=hex(idle_frame),
            retained_original_Thread_object=hex(thread),host_context_ready_or_owner_rewritten=False)
        result['phase']='construct_original_independent_Signal80_and_register_callback'
        retained=vm.signal_inventory(D+0x464);retained_thread=vm.word(D+0x4ba4)
        S=vm.kernel_invoke(0x3954cc,(80,));require(vm.returned and S!=0 and S%8==0 and vm.declared_storage(S,80),
            'Explicit aligned native allocator service did not provide live80-byte backing')
        vm.kernel_invoke(0x57458d,(S,));require(vm.returned,'Original Signal ctor did not return')
        empty=vm.signal_inventory(S)
        expected=[0xc1b59c,0,0,0,0,0,0,0xc1b5c4,0,0,0,0,0x31041c,0,0,0,0,0,0x46c2c8,0]
        require(bytes(vm.uc.mem_read(S,80))==struct.pack('<20I',*expected),'Whole original independent Signal constructor image differs')
        vm.kernel_invoke(0x4b571d,(S,0x405341));registered=vm.signal_inventory(S)
        require(vm.returned and len(registered['vectors'][0]['entries'])==1 and not registered['vectors'][1]['entries'] and
            registered['vectors'][0]['entries'][0]['vtable']=='0xc1b584'and
            registered['vectors'][0]['entries'][0]['function']=='0x405341','Original free-function holder registration differs')
        vm.kernel_invoke(0x5d28ff,(D,S));require(vm.returned and vm.running_task==vm.controller,'Original queue API did not return')
        record('independent_original_Signal_constructor_register_and_queue_preserve_cleanup_signal',
            signal_before=empty,signal_registered=registered,retained_original_cleanup_signal=retained,
            allocator_lower_service_is_fixture=True,host_wrote_signal_vtable_vector_or_native_mutex=False)
        result['phase']='original_Dispatcher_reaches_MainMenu_callback_before_body'
        vm.stop_before_callback=True;vm.invoke_to_callback()
        required=[0x52353c,0x609338,0x574760,0x405340];actual=[int(r['entry'],16)for r in vm.signal_chain]
        require(all(a in actual for a in required)and vm.uc.reg_read(UC_ARM_REG_PC)==0x405340,'Missing original Signal callback adapter path')
        require(vm.signal_inventory(D+0x464)==retained and vm.word(D+0x4ba4)==retained_thread,
            'Independent Signal modified original cleanup holder/Thread pointer')
        endpoint=vm.callback_endpoint_inventory(D,S,before_timed,idle_frame);memory=vm.verify_memory(voice,exports,dbsha)
        record('native_callback_entry_and_complete_live_owned_timed_queue_frame_memory_guards_pass',
            endpoint=endpoint,memory=memory,signal_chain=vm.signal_chain,signal=vm.signal_inventory(S),
            callback_body_executed=False,original_cleanup_signal_and_Thread_unchanged=True)
        paths={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',source}
        paths.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                p=Path(filename).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):paths.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,all_passed=True,case_count=len(cases),cases=cases,
            source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
            original_MAIN_patch_bytes=0,host_wrote_signal_callback_ready_owner_or_saved_context=False,
            full_scoped_memory_and_native_callback_endpoint_inventory_guards_passed=True,
            original_MainMenu_callback_body_foreground_device_App_direct_music_or_safe_cleanup_verified=False,
            emulator_binding_version=unicorn.__version__,emulator_native_version=list(unicorn.uc_version()),device_io=False,sounds_emitted=False,
            limits='Explicit lower aligned heap allocator service, original80-byte Signal constructor, register and queue API create an independent resident Signal and callback. Original Dispatcher consumes native event2 and executes signal/vtables/free-function adapter into405340 before body. Exact native ALL/ready/state/priority/live storage, recursive owned semaphore links/depth, live RAII/queue record/cursors/event2, Thread timed node/context and idlePOST/controllerWAIT saved frames plus whole code/voice/privateAPI/GUI/DB/storage/descriptor/stack guards pass. Current Dispatcher saved frame is consumed, not treated as resumable. Original cleanup Signal/member holder and Thread pointer remain unchanged. System/initial-ready/descriptors/idle/API event1 and lower heap/IRQ/filesystem/clock inputs are fixtures. No callback completion/MainMenu foreground/rendering/touch/hardware App/directphone music/accepted package/task exit/safe cleanup proof.')
        PROOF.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        result.update(completed=True,full_scoped_final_guards_passed=True,complete_proof=str(PROOF.relative_to(ROOT)),complete_proof_sha256=sha(str(PROOF.relative_to(ROOT))))
        print(json.dumps(dict(all_passed=True,groups=len(cases),dependencies=len(paths),callback_before_body=True)),flush=True)
    except Exception as error:
        result.update(completed=False,error=str(error));print(json.dumps(dict(phase=result.get('phase'),error=str(error))),flush=True)
    try:inventory=vm.native_task_inventory()if vm.native_TCBs else None
    except Exception as error:inventory=dict(snapshot_error=str(error))
    result.update(cases=cases,recent=list(vm.recent),native_inventory=inventory,signal_chain=vm.signal_chain,
        native_restores=vm.kernel_restores,native_mutex_operations=vm.native_mutex_runs,
        pending_mutex_operations={hex(t):rows for t,rows in vm.task_mutex_ops.items()if rows},
        invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,
        registers={n:hex(vm.uc.reg_read(r))for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))},
        audio_requests=vm.audio)
    (STAGE/'independent-signal-terminal-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');vm.db.close()
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
