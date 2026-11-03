#!/usr/bin/env python3
"""Whole-memory guards for original GUI condition return; no task cleanup.

This is a new proof namespace.  Resident native mutex ownership and suspended
background continuations are verified as they stand, never swept to satisfy
the old generic loader cleanup predicate.  Then yield the controller through
its original event wait to observe the next actual background dependency.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_CPSR,UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_LR
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_task_mutex import NativeTaskMutexVM
from probe_native_kernel_context import POST,WAIT,CONTROLLER_STACK,IDLE_STACK,CODE,DESCRIPTORS
from probe_native_player_mainmenu import BUILD
from emulate_native_player_menu_selection import DATABASE
from emulate_native_vpm_filesystem import REGS,RETURN,require

STAGE=ROOT/'staging/native-player-task-runtime-full'
PROOF=ROOT/'evidence/firmware-analysis/native-task-runtime-full-emulation.json'

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()

class FullTaskVM(NativeTaskMutexVM):
    def __init__(self,stock,build):
        self.GUI_stack_canaries=[]
        self.active_GUI_stack_fill=None
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        if address==0x358bf8 and self.kernel_active:
            caller=uc.reg_read(UC_ARM_REG_LR)&~1
            if caller in [0x5d2220,0x261dec]:
                desc=uc.reg_read(REGS[0]);top=self.word(desc+8);bottom=top-16384
                require(self.declared_storage(bottom,16384),'Original GUI stack outside live guarded allocation')
                self.GUI_stack_canaries.append(dict(descriptor=hex(desc),bottom=hex(bottom),top=hex(top),
                    leading64_before_hex=bytes(uc.mem_read(bottom,64)).hex(),
                    captured_before_original_TCB_builder=True,host_poisoned_original_GUI_stack=False))
        if address==0x3794f0 and (uc.reg_read(UC_ARM_REG_LR)&~1)==0xf6f48:
            bottom,length,byte=[uc.reg_read(r)for r in REGS[:3]]
            rows=[row for row in self.GUI_stack_canaries if int(row['bottom'],16)==bottom]
            if rows:
                require(len(rows)==1 and length==16384 and byte==255 and self.active_GUI_stack_fill is None,
                    'Original GUI stack fill caller/range/pattern differs')
                row=rows[0];self.active_GUI_stack_fill=row
                row.update(original_stack_fill_entry='0x3794f0',native_caller='0xf6f48',
                    original_stack_fill_bytes=length,original_stack_fill_byte=byte,
                    original_stack_fill_body_returned=False,host_filled_GUI_stack=False)
        if address==0xf6f48 and self.active_GUI_stack_fill is not None:
            row=self.active_GUI_stack_fill;bottom=int(row['bottom'],16)
            require(bytes(uc.mem_read(bottom,16384))==b'\xff'*16384,
                'Whole original3794F0 GUI stack fill differs')
            row.update(original_stack_fill_body_returned=True,whole16384_native_fill_verified=True,
                leading64_after_native_fill_hex=bytes(uc.mem_read(bottom,64)).hex())
            self.active_GUI_stack_fill=None
        return super().observe(uc,address,size,data)

    def native_task_inventory(self):
        known=self.native_TCBs
        def linked(head,next_offset,previous_offset=None,previous_head=None):
            nodes=[];previous=previous_head;p=self.word(head)
            while p:
                require(p in known and p not in nodes and len(nodes)<16,'Native task list unknown/cyclic')
                if previous_offset is not None:
                    require(self.word(p+previous_offset)==previous,'Native task previous link mismatch')
                nodes.append(p);previous=p+next_offset;p=self.word(p+next_offset)
            return nodes
        all_tasks=linked(0xf0908c,40,44,0xf0908c)
        ready=linked(0xf09090,0)
        rows=[]
        for t in all_tasks:
            rows.append(dict(TCB=hex(t),raw108_hex=bytes(self.uc.mem_read(t,108)).hex(),
                base_priority=self.uc.mem_read(t+16,1)[0],effective_priority=self.uc.mem_read(t+17,1)[0],
                state=self.uc.mem_read(t+22,1)[0],context_format=self.uc.mem_read(t+23,1)[0],
                saved_frame=hex(self.word(t+12)),owned_mutex_head=hex(self.word(t+32)),
                saved_frame13_words=[hex(v)for v in struct.unpack('<13I',self.uc.mem_read(self.word(t+12),52))]))
        return dict(all_tasks=[hex(t)for t in all_tasks],ready=[hex(t)for t in ready],tasks=rows)

    def verify_singleton_inventory(self):
        data=self.native_task_inventory()
        dispatch,thread=sorted(t for t in self.native_TCBs if t not in [self.controller,self.idle,self.timer_task])
        require(data['all_tasks']==[hex(n)for n in [thread,dispatch,self.timer_task,self.controller,self.idle]],
            'Whole original ALL-task list order differs')
        require(data['ready']==[hex(n)for n in [self.controller,thread,dispatch,self.idle]],
            'Whole original ready list equal-priority FIFO order differs')
        global_mutex=0x34a59ac;wait=self.native_condition_waits[0]
        condition=int(wait['condition'],16);user_mutex=int(wait['mutex'],16);aux=condition+28
        expected_owned={self.controller:0,dispatch:global_mutex,thread:0,self.timer_task:condition,self.idle:0}
        expected_priorities={self.controller:16,dispatch:92,thread:92,self.timer_task:1,self.idle:240}
        for t,head in expected_owned.items():
            require(self.declared_storage(t,108),'Native TCB backing no longer live and declared')
            require(self.word(t+32)==head,'Native task owned-mutex head differs '+hex(t))
            require(self.uc.mem_read(t+22,1)[0]==(2 if t==self.timer_task else 1) and
                self.uc.mem_read(t+16,1)[0]==self.uc.mem_read(t+17,1)[0]==expected_priorities[t],
                'Native task state/base/effective priority differs')
            require(self.word(t+24)==((5 if t in [dispatch,thread] else 0)<<28)|0x0ed1a247,
                'Native TCB flags/header magic differs')
            for offset in [56,80]:
                require(self.word(t+offset+8)==self.word(t+offset+12)==0 and
                    int.from_bytes(self.uc.mem_read(t+offset+20,2),'little')==0,
                    'Unexpected owned or queued native task internal semaphore')
        for ptr,owner in [(global_mutex,dispatch),(condition,self.timer_task)]:
            require(self.word(ptr)==0 and self.word(ptr+4)==owner+32 and self.word(ptr+8)==owner and self.word(ptr+12)==0 and
                int.from_bytes(self.uc.mem_read(ptr+20,2),'little')==0,'Resident owned mutex fields/list links differ '+hex(ptr))
        require(self.word(user_mutex+8)==0 and self.word(aux+8)==0,'Released user/auxiliary mutex still owned')
        require({p:n for p,n in self.mutexes.items()if n}=={global_mutex:1},'Counter inventory disagrees with native resident global ownership')
        require(self.dispatcher_condition_tokens[condition]['explicit_retained_bootstrap_token']==1 and
            self.dispatcher_condition_tokens[condition]['native_owner']==hex(self.timer_task),'Explicit retained native condition token differs')
        require(not any(self.task_waits.values()) and not any(self.task_releases.values()) and not any(self.task_lower_waits.values()),
            'Returned controller leaves incomplete condition/release/lower wait')
        require(len(self.task_mutex_ops[dispatch])==len(self.task_mutex_ops[thread])==1 and
            self.task_mutex_ops[dispatch][0]['operation']=='lock' and self.task_mutex_ops[thread][0]['operation']=='unlock',
            'Resident worker continuation inventory differs')
        expected_frames=[(dispatch,0x300d98,0x8804f1c,{2:self.controller,3:global_mutex,4:dispatch,5:0x8804f50,11:0x8804f50,12:0x3009f1}),
            (thread,0x358ebc,0x8809254,{2:thread,11:0x8809288,12:0x300911})]
        for t,pc,frame,fields in expected_frames:
            require(self.word(t+12)==frame and self.word(frame+4)==pc and
                self.uc.mem_read(t+23,1)[0]==0 and self.word(frame)&31==31,
                'Resident native worker context frame/PC/system mode differs '+hex(t))
            words=struct.unpack('<13I',self.uc.mem_read(frame,52))
            require(words[0]&0xbf==0xbf and all(words[n]==value for n,value in fields.items()) and
                self.declared_storage(frame,52),'Resident frame Thumb/IRQ mask/registers/live backing differs')
        require(self.word(0x8804f50+4)==0,'Transferred dispatcher mutex waiter marker was not cleared by original fullrelease')
        data.update(native_owned_mutex_heads={hex(t):hex(v)for t,v in expected_owned.items()},
            semaphores={hex(p):bytes(self.uc.mem_read(p,24)).hex()for p in [global_mutex,condition,user_mutex,aux]},
            pending_mutex_operations={hex(t):rows for t,rows in self.task_mutex_ops.items()if rows},
            resident_dispatcher_marker_cleared=True,whole_native_ready_ALL_and_owned_list_checked=True,
            tasks_and_condition_token_remain_resident=True,task_quiescence_or_safe_unload_verified=False)
        return data

    def verify_memory(self,voice,exports,dbsha):
        require(not self.invalid_accesses and not self.native_fatal_entries and not self.audio,'Runtime fault or unexpected audio request')
        oldram=struct.unpack_from('<I',(ROOT/self.build['original_binary']).read_bytes(),4)[0]
        require(bytes(self.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(self.uc.mem_read(STUBS,480))==exports,
            'Whole original voice RAM or40 exports changed')
        tables={}
        for table,names in [('app_component_api',self.build['private_api']),('player_component_api',self.build['player_api'])]:
            values=list(struct.unpack('<'+str(len(names))+'I',self.uc.mem_read(self.symbol(table),4*len(names))))
            require(values==[self.symbol(n)for n in names],'Whole compiled private/player API table changed')
            tables[table]=[hex(v)for v in values]
        require(bytes(self.uc.mem_read(self.build['extension_base'],0x10000))==self.extension_code,'Whole RX extension code changed')
        for address,raw in self.initial_regions.items():
            require(bytes(self.uc.mem_read(address,len(raw)))==raw,'Whole original initialized code/GUI region changed '+hex(address))
        for address,raw in self.code_images:
            require(bytes(self.uc.mem_read(address,len(raw)))==raw,'Whole original code image changed '+hex(address))
        require(not self.conditional_region_writes,'Kernel singleton bootstrap unexpectedly mutated declared GUI initialized region')
        for ptr,entry in self.raw_allocations.items():self.verify_guard(ptr,entry)
        for entry in self.handles.values():
            p,n=entry['pointer'],entry['length']
            require(bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(p+n,32))==b'\xa5'*32,
                'Whole opaque allocation canary changed')
        self.verify_storage_guards();self.verify_descriptor_guards();self.verify_closed_files()
        for bottom in [CONTROLLER_STACK,IDLE_STACK]:
            require(bytes(self.uc.mem_read(bottom,64))==b'\xa5'*64,'Synthetic stack leading64 canary changed')
        require(bytes(self.uc.mem_read(0x2d226f4,24))==b'\xa5'*24,'Native timer stack leading24 canary changed')
        for row in self.GUI_stack_canaries:
            require(row.get('whole16384_native_fill_verified') and
                bytes(self.uc.mem_read(int(row['bottom'],16),64)).hex()==row['leading64_after_native_fill_hex'],
                'Original GUI stack crossed its observed leading64 boundary')
        require(len(self.GUI_stack_canaries)==2,'Missing both original GUI stack boundary snapshots')
        require(bytes(self.uc.mem_read(CODE,8))==struct.pack('<2I',0xeafffffe,0xe12fff1e),'Declared synthetic code sentinels changed')
        require(sha(DATABASE)==dbsha and not self.statements and
            list(self.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))==self.database_before,
            'Readonly backup or in-memory baseline DB changed')
        return dict(original_voice_RAM_and40_exports_unchanged=True,private12_and_player2_API_tables=tables,
            whole_initialized_regions_checked=[dict(address=hex(a),bytes=len(raw))for a,raw in self.initial_regions.items()],
            whole_original_code_images_checked=[dict(address=hex(a),bytes=len(raw))for a,raw in self.code_images],
            whole_RX_extension_code_unchanged=True,all_allocation_storage_descriptor_and_stack_boundaries_intact=True,
            original_GUI_stack_canary_inputs=self.GUI_stack_canaries,backup_and_inmemory_DB_unchanged=True,
            native_closed_file_inventory_verified=True,guest_memory_or_counters_rewritten_by_guard=False,
            outer=self.summarize(),outer_region_module_tasks_and_mutex_tokens_remain_resident=True,
            outer_cleanup_task_quiescence_or_safe_unload_verified=False)

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(exist_ok=True);require(not PROOF.exists(),'Keep completed positive proof immutable')
    build=json.loads((ROOT/BUILD).read_text());vm=FullTaskVM(NativeImage(),build);cases=[]
    source_sha=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();dbsha=sha(DATABASE)
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        vm.uc.reg_write(UC_ARM_REG_CPSR,(vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        kernel=vm.configure_native_kernel_inventory();vm.kernel_invoke(POST,(vm.timer_task,0x10))
        vm.kernel_invoke(0x5d2f7d,());value=vm.kernel_invoke(0x5d2131,())
        require(vm.returned and value==0x8800520 and vm.running_task==vm.controller and
            vm.word(0xf09090)==vm.controller and vm.uc.reg_read(UC_ARM_REG_SP)==vm.controller and vm.uc.reg_read(UC_ARM_REG_PC)==RETURN,
            'Original singleton did not return through originating controller frame')
        require(len(vm.kernel_restores)==7 and all(r['original_task_resume_destination_reached']for r in vm.kernel_restores) and
            vm.native_condition_waits[0]['original_wait_returned'] and vm.native_condition_waits[0]['native_reacquisition_verified'] and
            vm.condition_notifications[0]['original_broadcast_returned'],'Native condition/broadcast/reacquisition restore completion missing')
        record('original_GUI_workers_notify_and_handoff_mutex_then_singleton_returns_originating_controller',
            singleton=hex(value),kernel_restores=vm.kernel_restores,condition_waits=vm.native_condition_waits,
            condition_broadcasts=vm.condition_notifications,full_releases=vm.native_full_releases,
            native_mutex_operations=vm.native_mutex_runs,original_MAIN_patch_bytes=0,host_context_restore_or_fakewake=False)
        inventory=vm.verify_singleton_inventory()
        record('exact_native_task_ready_ALL_owned_mutex_lists_and_resident_background_frames_match',inventory=inventory)
        snapshot=vm.verify_memory(voice,exports,dbsha)
        record('whole_code_voice_private_API_GUI_region_DB_allocation_descriptor_and_stack_guards_pass_without_cleanup',snapshot=snapshot)
        paths={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve()}
        paths.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                p=Path(filename).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):paths.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
            all_passed=True,case_count=len(cases),cases=cases,load=load,kernel_inventory=kernel,
            original_condition_wait_broadcast_reacquisition_and_singleton_return_verified=True,
            full_scoped_nonmutating_memory_and_native_inventory_guards_passed=True,
            native_mutex_owner_waiter_priority_context_restores_written_by_original_only=True,
            tasks_two_background_mutex_continuations_condition_token_and_module_remain_resident=True,
            physical_kernel_IRQ_GUI_foreground_App_direct_phone_music_or_safe_cleanup_verified=False,
            emulator_binding_version=unicorn.__version__,emulator_native_version=list(unicorn.uc_version()),
            device_io=False,sounds_emitted=False,
            limits='Loaded54976-byte EMULATION-ONLY player remains unchanged. Original native TCB construction, post/context and two original GUI workers run native contention, broadcast marker/event8 and ordinary-mutex handoff, returning original singleton through controller. Whole code/voice40/private12/player2/initialized GUI regions/DB/allocation/storage/descriptor/stack and exact native ALL/ready/owned/task frame guards pass without mutating counters or running old generic cleanup. Controller/idle descriptors/stacks, initial system mode and ready membership, explicit timer boot event, filesystem/settings/heap/IRQ service inputs remain fixtures. Dispatcher owns global mutex but its lock continuation remains suspended; Thread unlock continuation remains suspended. Outer region/module/tasks/condition token stay resident; no task quiescence, cleanup, foreground/touch/display, real IRQ clock/boot, accepted VPM, device App or direct-phone music proof. Subsequent original controller wait/background progress is separate development evidence.')
        PROOF.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(full_scoped_pre_background_guards_passed=True,groups=len(cases),exact_dependencies=len(paths))),flush=True)
    except Exception as error:
        path=STAGE/'focused-task-runtime-full-failure.json'
        require(not path.exists(),'Preserve previous terminal failure before rerun')
        try:native_inventory=vm.native_task_inventory()if vm.native_TCBs else None
        except Exception as snapshot_error:native_inventory=dict(snapshot_error=str(snapshot_error))
        path.write_text(json.dumps(dict(error=str(error),source_sha256_before_run=source_sha,completed_cases=cases,
            full_scoped_final_guards_passed=False,recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            native_fatal_entries=vm.native_fatal_entries,conditional_writes=vm.conditional_region_writes,
            native_task_descriptors=vm.native_task_descriptors,kernel_restores=vm.kernel_restores,
            GUI_stack_canary_observations=[dict(row,current_leading64_hex=bytes(vm.uc.mem_read(int(row['bottom'],16),64)).hex())
                for row in vm.GUI_stack_canaries],
            native_inventory=native_inventory,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))},
            device_io=False,sounds_emitted=False),ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases),full_scoped_final_guards_passed=False)),flush=True)
        vm.db.close();sys.exit(1)
    # Advance the original saved continuations using an actual controller wait.
    # No fabricated event, priority, ready link or worker entry is supplied.
    development=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=source_sha,
        prior_complete_proof=str(PROOF.relative_to(ROOT)),prior_complete_proof_sha256=sha(str(PROOF.relative_to(ROOT))),
        full_scoped_pre_background_guards_passed=True,full_scoped_background_final_guards_passed=False,
        device_io=False,sounds_emitted=False)
    try:
        vm.kernel_invoke(WAIT)
        development.update(original_controller_wait_returned=vm.returned,idle_sentinel_reached=vm.idle_endpoint,
            reached_declared_native_endpoint=True)
    except Exception as error:
        development.update(reached_declared_native_endpoint=False,error=str(error))
    try:background_inventory=vm.native_task_inventory()
    except Exception as snapshot_error:background_inventory=dict(snapshot_error=str(snapshot_error))
    development.update(recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,
        running_task=hex(vm.running_task),ready_head=hex(vm.word(0xf09090)),kernel_restores=vm.kernel_restores,
        native_mutex_operations=vm.native_mutex_runs,native_condition_waits=vm.native_condition_waits,
        pending_mutex_operations={hex(t):rows for t,rows in vm.task_mutex_ops.items()if rows},
        current_native_inventory=background_inventory,audio_requests=vm.audio,
        registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    (STAGE/'post-guard-background-development-probe.json').write_text(json.dumps(development,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(phase='original_controller_wait_and_background_resume',
        reached_declared_native_endpoint=development['reached_declared_native_endpoint'],error=development.get('error'),
        running_task=development['running_task'],full_scoped_background_final_guards_passed=False)),flush=True)
    vm.db.close()

if __name__=='__main__':main()
