#!/usr/bin/env python3
"""Stock heap/list/settings boot on declared native kernel and storage inputs.

Original list/heap constructors and all scoped raw mutex bodies execute. The
heap extent, NOR, boot descriptors/ready inventory and opaque translation are
explicit offline inputs; this is not a physical allocator or accepted App.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_CPSR
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_mainmenu_native_settings_journal import JournalSettingsVM
from probe_mainmenu_native_settings_prep import INIT,COND
from emulate_native_task_runtime_full import sha
from probe_native_kernel_context import POST,WAIT
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_selection import DATABASE
from emulate_native_vpm_filesystem import REGS,RETURN,require

STAGE=ROOT/'staging/native-player-heap-settings-boot'
BUFFER=0x18301000
EXTENT=INPUT+0x1000
WORK=0x3a7f170
LISTS={0x2d226b4:'exit_list',0x148e680:'settings_list'}
HEAP_STATIC='staging/native-player-mainmenu-native-prep/heap-static/mainmenu-native-heap-mutex-preflight.json'
SETTINGS_STATIC='staging/native-player-mainmenu-native-prep/mutex-static/mainmenu-native-settings-mutex-preflight.json'


class HeapSettingsVM(JournalSettingsVM):
    def __init__(self,stock,build):
        self.heap_raw_shapes={}
        self.list_constructors=[];self.active_list=None
        self.scoped_raw_ops=[];self.zone_active=False;self.zone_rows={}
        self.listener_registrations=[];self.internal_tags={}
        self.phase='initial_boot'
        super().__init__(stock,build)
        review=json.loads((ROOT/HEAP_STATIC).read_text())
        require(review['assertions_passed'] and review['static_only'],'Need exact reviewed heap call table')
        for p,s in review['source_sha256'].items():require(sha(p)==s,'Heap review source changed '+p)
        for row in review['raw_mutex_calls']+review['listener_mutex_calls']:
            key=(int(row['entry'],16),int(row['continuation'],16),int(row['pointer'],16))
            require(key not in self.heap_raw_shapes,'Duplicate exact raw shape')
            self.heap_raw_shapes[key]=dict(row,tag_value=int(row['tag'],16))
        settings=json.loads((ROOT/SETTINGS_STATIC).read_text())
        for p,s in settings['source_sha256'].items():require(sha(p)==s,'Settings review source changed '+p)
        self.RAW_CALLS={}
        for row in settings['raw_mutex_calls']:
            self.RAW_CALLS[int(row['entry'],16),int(row['continuation'],16)]=dict(row,
                pointer=int(row['pointer'],16),tag=int(row['tag'],16))
        for pointer in [0x3a7f150,0x3a7f170]:
            require(self.declared_storage(pointer,96),'Heap workspace/listener storage outside original BSS')
            page=pointer&~4095
            if not any(lo<=page and page+4095<=hi for lo,hi,_ in self.uc.mem_regions()):
                self.uc.mem_map(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        require(not any(lo<=BUFFER+12287 and BUFFER-4096<=hi for lo,hi,_ in self.uc.mem_regions()),
                'Declared heap input mapping overlaps old experiment')
        self.uc.mem_map(BUFFER-4096,16384,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.mem_write(BUFFER-4096,b'\xa5'*16384)
        self.uc.mem_write(BUFFER,b'\xcc'*8192)
        self.uc.mem_write(EXTENT-32,b'\xa5'*72)
        self.uc.mem_write(EXTENT,struct.pack('<2I',BUFFER,8192))
        self.synthetic_heap_ranges=[(BUFFER,BUFFER+8192),(EXTENT,EXTENT+8)]
        self.zones={0x3a7f150:128,0x2d226b4:64,0x148e680:0x2c4,BUFFER:8192}
        for start,length in self.zones.items():
            self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.journal_zone_write,begin=start,end=start+length-1)

    def declared_storage(self,pointer,length):
        value=super().declared_storage(pointer,length)
        if value:return value
        if any(lo<=pointer and pointer+length<=hi for lo,hi in getattr(self,'synthetic_heap_ranges',[])):
            return 'explicit_guarded_heap_extent_input'
        return None

    def begin_mutable_scope(self):
        if self.mutable_bank_before is None:return super().begin_mutable_scope()
        require(self.mutable_journal_active and self.phase=='settings','Unexpected second initialized-data journal start')

    def begin_extra_zones(self,inventory,timed):
        require(not self.zone_active,'Heap/settings zones already started')
        for row in inventory['tasks']:
            task=int(row['TCB'],16)
            require(self.declared_storage(task,108),'TCB journal lacks native live backing')
            self.zones[task]=108
            for offset in [56,80]:self.internal_tags[task+offset]=self.word(task+offset+16)
            if task!=self.controller:
                frame=int(row['saved_frame'],16)
                require(self.declared_storage(frame,52),'Background frame journal lacks live backing')
                self.zones[frame]=52
        self.zones[int(timed['node'],16)]=20
        starts=sorted(self.zones)
        require(all(a+self.zones[a]<=b for a,b in zip(starts,starts[1:])),
                'Declared CPU write journals overlap')
        old_starts={0x3a7f150,0x2d226b4,0x148e680,BUFFER}
        for start in starts:
            if start not in old_starts:
                self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.journal_zone_write,
                    begin=start,end=start+self.zones[start]-1)
        for start,length in self.zones.items():
            self.zone_rows[start]=dict(start=hex(start),bytes=length,
                before_hex=bytes(self.uc.mem_read(start,length)).hex(),stores=[])
        self.zone_active=True
        self.begin_mutable_scope()

    def journal_zone_write(self,uc,access,address,size,value,data):
        if not self.zone_active:return
        zone=next((row for start,row in self.zone_rows.items()if start<=address and address+size<=start+row['bytes']),None)
        require(zone is not None and size in [1,2,4],'Heap/settings write crossed a declared zone')
        pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)
        opcode=self.stock.read(pc,4);instructions=list(self.store_disassemblers[thumb].disasm(opcode,pc,count=1))
        require(len(instructions)==1,'No original store instruction at heap writer')
        instruction=instructions[0]
        require(bytes(uc.mem_read(pc,instruction.size))==opcode[:instruction.size] and
                instruction.mnemonic.startswith(('str','stm','swp')),'Heap writer not an unchanged original store opcode')
        require(len(zone['stores'])<20000,'Heap/settings write journal exhausted')
        zone['stores'].append(dict(PC=hex(pc),address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),phase=self.phase,
            running_task=hex(self.running_task),Thumb=thumb,
            original_instruction=instruction.mnemonic+' '+instruction.op_str,opcode_hex=opcode[:instruction.size].hex()))

    def verify_extra_zones(self):
        result=[]
        for start,row in self.zone_rows.items():
            expected=bytearray.fromhex(row['before_hex'])
            for store in row['stores']:
                offset=int(store['address'],16)-start;size=store['size']
                require(expected[offset:offset+size].hex()==store['before_hex'],'Zone journal missed an intervening net host mutation')
                expected[offset:offset+size]=int(store['value']).to_bytes(size,'little')
            actual=bytes(self.uc.mem_read(start,row['bytes']))
            require(actual==bytes(expected),'Whole heap/settings zone differs outside original CPU write history')
            result.append(dict(row,after_sha256=hashlib.sha256(actual).hexdigest(),whole_net_zone_matches_original_stores=True))
        require(bytes(self.uc.mem_read(BUFFER-4096,4096))==b'\xa5'*4096 and
                bytes(self.uc.mem_read(BUFFER+8192,4096))==b'\xa5'*4096,'Heap extent crossed leading/trailing guard page')
        require(bytes(self.uc.mem_read(EXTENT,8))==struct.pack('<2I',BUFFER,8192) and
                bytes(self.uc.mem_read(EXTENT-32,32))==b'\xa5'*32 and
                bytes(self.uc.mem_read(EXTENT+8,32))==b'\xa5'*32,'Declared extent descriptor or guards changed')
        return result

    def exact_raw(self,uc,address,caller,pointer,shape):
        task=self.running_task
        require(task==self.controller==self.word(0xf09090) and self.declared_storage(pointer,24),
                'Scoped heap/list raw semaphore actor/storage differs')
        require(self.word(pointer+16)==shape['tag_value'] and self.uc.mem_read(pointer+22,1)[0]==0,
                'Scoped heap/list/internal semaphore tag/class differs')
        if pointer not in self.native_semaphores:self.register_native_semaphore(pointer)
        require(not self.native_semaphores[pointer]['retained_condition_token'],'Raw heap lock is a retained token')
        row=dict(original_entry=hex(address),pointer=hex(pointer),native_caller=hex(caller),
            operation='lock'if address==0x3009a0 else'unlock',scope='exact_heap_list_or_current_internal',
            running_task=hex(task),entry_SP=hex(uc.reg_read(UC_ARM_REG_SP)),entry_LR=hex(uc.reg_read(UC_ARM_REG_LR)),
            before_words=[hex(self.word(pointer+4*n))for n in range(6)],native_body_returned=False,
            semaphore_fields_written_by_original_only=True,host_CPU_context_restore=False,reviewed_shape=shape)
        self.native_mutex_runs.append(row);self.scoped_raw_ops.append(row)
        self.task_mutex_ops[task].append(row);self.visits[address]+=1

    def observe(self,uc,address,size,data):
        caller=uc.reg_read(UC_ARM_REG_LR)&~1
        if self.kernel_active and address in [0x388be6,0x388bf8]:
            require(self.phase=='heap_ctor' and self.running_task==self.controller and
                    uc.reg_read(REGS[0])==0,'Original heap listener registration did not return success')
            self.listener_registrations.append(dict(native_return=hex(address),result=0,
                node=hex(0x3a7f150 if address==0x388be6 else 0x3a7f160)))
        if self.kernel_active and self.active_list and address==int(self.active_list['native_caller'],16):
            row=self.active_list;pointer=int(row['pointer'],16)
            require(row['native_initializer_observed'] and self.word(pointer)==0 and
                    bytes(uc.mem_read(pointer+4,24))==struct.pack('<6I',0,0,0,0,0x3cc660,0),
                    'Original list ctor whole head/backend result differs')
            row['original_constructor_returned']=True;self.list_constructors.append(row);self.active_list=None
        if self.kernel_active and address==0x3cc57c:
            pointer=uc.reg_read(REGS[0])
            require(pointer in LISTS and self.active_list is None and self.running_task==self.controller,
                    'Original list ctor outside explicit instance/actor')
            require(self.declared_storage(pointer,28) and bytes(uc.mem_read(pointer,28))==b'\0'*28,
                    'Refusing to reset existing nonempty or initialized list')
            require((pointer==0x2d226b4 and caller==RETURN) or (pointer==0x148e680 and caller==0x2cbd8e),
                    'Original list ctor caller differs')
            self.active_list=dict(pointer=hex(pointer),backend=hex(pointer+4),native_caller=hex(caller),
                before_hex=bytes(uc.mem_read(pointer,28)).hex(),native_initializer_observed=False,
                original_constructor_returned=False,host_seeded_tag_or_head=False)
        if self.kernel_active and address==0x3008a0 and caller in [0x3cc58a,0x388bd0]:
            pointer=uc.reg_read(REGS[0])
            if caller==0x3cc58a:
                require(self.active_list and pointer==int(self.active_list['backend'],16),'Original list native backend differs')
                self.active_list['native_initializer_observed']=True
            else:require(pointer==WORK+28 and self.phase=='heap_ctor','Original heap ctor native backend differs')
            storage=self.declared_storage(pointer,24)
            require(storage and self.active_backend is None,'Native heap/list init storage or nesting differs')
            row=dict(original_entry='0x3008a0',pointer=hex(pointer),native_caller=hex(caller),bytes=24,
                storage_boundary=storage,before_hex=bytes(uc.mem_read(pointer,24)).hex(),native_zero_writes=[],
                original_body_executed=False,host_seeded_backend_bytes=False)
            self.backend_initializations.append(row);self.active_backend=row;self.visits[address]+=1
            return
        if self.kernel_active and address in [0x3009a0,0x3008b0]:
            pointer=uc.reg_read(REGS[0]);shape=self.heap_raw_shapes.get((address,caller,pointer))
            if caller in [0x1c0618,0x1c0634]:
                require((address,caller)in [(0x3009a0,0x1c0618),(0x3008b0,0x1c0634)] and
                        pointer==self.running_task+56 and self.running_task in self.native_TCBs,
                        'Internal semaphore lacks exact actual current-TCB+56 provenance')
                require(pointer in self.internal_tags,'Internal semaphore has no pre-operation native tag snapshot')
                shape=dict(tag_value=self.internal_tags[pointer],pointer='actual_native_current_TCB+56',classification_byte=0,
                    tag_from_actual_preoperation_TCB=True)
            if shape:
                self.exact_raw(uc,address,caller,pointer,shape)
                return
        return super().observe(uc,address,size,data)

    def verify_heap(self,cold=False):
        require(self.word(WORK+4)==BUFFER+4096 and self.word(WORK+0x18)==BUFFER and
                [self.word(WORK+o)for o in [0x50,0x54,0x58]]==[8192,4096,4096],
                'Original single-extent heap metadata differs')
        require(self.word(BUFFER)==27 and self.word(BUFFER+0x78)==BUFFER+0x7c and
                [self.word(BUFFER+4096),self.word(BUFFER+4100)]==[0,4096],
                'Original private prefix/free header differs')
        nodes=[];p=self.word(0x2d226b4)
        while p:
            require(p in [0x3a7f150,0x3a7f160] and p not in [r['pointer']for r in nodes],
                    'New heap exit-list listener chain differs')
            words=struct.unpack('<4I',self.uc.mem_read(p,16))
            nodes.append(dict(pointer=p,words=[hex(v)for v in words]));p=words[0]
        require([r['pointer']for r in nodes]==[0x3a7f150,0x3a7f160] and
                nodes[0]['words'][1:]==['0x1000000','0x388b57','0x0'] and
                nodes[1]['words'][1:]==['0x3000000','0x388b37','0x0'],'Two original heap listeners differ')
        ops=[r for r in self.backend_initializations if r['native_caller']=='0x388bd0']
        require(len(ops)==1 and ops[0]['original_body_executed'] and len(ops[0]['native_zero_writes'])==6 and
                self.word(WORK+44)==0x388d00,'Original heap native init/retag not complete')
        require([r['native_return'] for r in self.listener_registrations]==['0x388be6','0x388bf8'],
                'Missing both original successful listener registration returns')
        expected_buffer=bytearray(b'\0'*4096+b'\xcc'*4096)
        for offset,value in [(0,27),(0x78,BUFFER+0x7c),(4096,0),(4100,4096)]:
            struct.pack_into('<I',expected_buffer,offset,value)
        require(bytes(self.uc.mem_read(BUFFER,8192))==bytes(expected_buffer),
                'Whole declared extent differs from native prefix/free-page recipe')
        if cold:
            expected_work=bytearray(96)
            for offset,value in [(4,BUFFER+4096),(0x18,BUFFER),(0x2c,0x388d00),
                                 (0x50,8192),(0x54,4096),(0x58,4096)]:
                struct.pack_into('<I',expected_work,offset,value)
            require(bytes(self.uc.mem_read(WORK,96))==bytes(expected_work),
                    'Whole cold native heap workspace differs from exact one-extent recipe')
        require(not any(self.task_mutex_ops.values()) and not any(self.mutexes.values()),'Heap ctor returned with an ordinary lock')
        return dict(workspace96_hex=bytes(self.uc.mem_read(WORK,96)).hex(),listeners=nodes,
            native_initializer=ops[0],declared_extent=[hex(BUFFER),8192],original_prefix_reserve_bytes=4096,
            whole_extent_matches_original_recipe=True,whole_cold_workspace_recipe_checked=cold,
            listener_registration_returns=self.listener_registrations,native_real_device_allocator_verified=False)

    def verify_native_endpoint(self,gui_condition,before,timed):
        require(self.returned and self.running_task==self.controller==self.word(0xf09090) and
                self.uc.reg_read(UC_ARM_REG_PC)==RETURN and self.uc.reg_read(UC_ARM_REG_SP)==self.controller,
                'Native settings failed to return on the actual controller stack')
        require(len(self.settings_init_rows)==5,'Missing original five settings initializer bodies')
        for caller,(pointer,tag) in INIT.items():
            rows=[r for r in self.settings_init_rows if r['native_caller']==hex(caller)]
            require(len(rows)==1 and rows[0]['original_body_executed'] and len(rows[0]['native_zero_writes'])==6,
                    'Original settings initializer six stores incomplete')
            uses=[r for r in self.settings_raw_mutex_operations if r['pointer']==hex(pointer)]
            expected=struct.pack('<6I',*[int(v,16) for v in uses[-1]['after_words']]) if uses else struct.pack('<6I',0,0,0,0,tag,0)
            require(bytes(self.uc.mem_read(pointer,24))==expected and
                    self.word(pointer+8)==self.word(pointer+12)==0 and self.word(pointer+16)==tag and
                    self.word(pointer+20)==0,'Released native settings semaphore differs from its actual epilogue')
        expected={COND:(gui_condition,self.timer_task+32,self.timer_task,0,0x2cbf8c,0),
            gui_condition:(0,COND,self.timer_task,0,0x6048e8,0),COND+28:(0,0,0,0,0x2cbf8c,0)}
        for pointer,words in expected.items():
            require(bytes(self.uc.mem_read(pointer,24))==struct.pack('<6I',*words),
                    'Native two-condition retained Timer chain differs '+hex(pointer))
        require(self.word(COND+24)==self.native_condition_magic and
                set(self.dispatcher_condition_tokens)=={COND,gui_condition},'Native condition token inventory differs')
        ctors=[r for r in self.condition_constructor_runs if r['pointer']==hex(COND)]
        transfers=[r for r in self.native_condition_owner_transfers if r['condition']==hex(COND)]
        locks=[r for r in self.native_mutex_runs if r['pointer']==hex(COND) and r['scope']=='condition_constructor']
        require(len(ctors)==len(transfers)==len(locks)==1 and ctors[0]['native_constructor_returned'] and
                ctors[0]['original_mutex_lock_and_owner_store_executed'] and locks[0]['native_body_returned'] and
                locks[0]['native_owner']==hex(self.controller) and transfers[0]['owner_matches_timer'] and
                self.native_semaphores[COND]['retained_condition_token'],
                'Original second condition constructor/lock/Timer transfer incomplete')
        pending=[self.task_mutex_ops,self.task_waits,self.task_releases,self.task_lower_waits,self.task_notifications]
        require(not any(any(values.values()) for values in pending) and not self.task_constructors and
                self.active_backend is None and self.active_list is None and not any(self.mutexes.values()),
                'Native endpoint has an unresolved operation or ordinary lock')
        require(all(r['native_body_returned'] for r in self.scoped_raw_ops+self.settings_raw_mutex_operations),
                'Scoped native raw mutex operation failed to reach its original epilogue')
        require(len(self.list_constructors)==2 and {int(r['pointer'],16) for r in self.list_constructors}==set(LISTS) and
                all(r['original_constructor_returned'] for r in self.list_constructors),
                'Original exit/settings list constructors did not both return')
        require(bytes(self.uc.mem_read(0x148e680,28))==struct.pack('<7I',0,0,0,0,0,0x3cc660,0),
                'Original unused settings list head/backend differs')
        for pointer in [WORK+28,0x2d226b8]:
            uses=[r for r in self.scoped_raw_ops if r['pointer']==hex(pointer)]
            tag=0x388d00 if pointer==WORK+28 else 0x3cc660
            expected_raw=struct.pack('<6I',*[int(v,16) for v in uses[-1]['after_words']]) if uses else struct.pack('<6I',0,0,0,0,tag,0)
            require(bytes(self.uc.mem_read(pointer,24))==expected_raw and self.word(pointer+8)==self.word(pointer+12)==0 and
                    self.word(pointer+16)==tag and self.word(pointer+20)==0,
                    'Heap/list released backend differs from its observed native epilogue')
        after=self.native_task_inventory()
        require(after['all_tasks']==before['all_tasks'] and after['ready']==before['ready'],
                'Settings changed native ALL/ready membership')
        resident=[]
        for old,new in zip(before['tasks'],after['tasks']):
            task=int(old['TCB'],16);raw=bytearray.fromhex(old['raw108_hex'])
            require(task in self.native_TCBs and self.declared_storage(task,108),'Missing original native TCB lifetime')
            if task==self.timer_task:struct.pack_into('<I',raw,32,COND)
            for offset in [56,80]:
                pointer=task+offset
                uses=[r for r in self.scoped_raw_ops if r['pointer']==hex(pointer)]
                if uses:
                    require(task==self.controller and offset==56,'Unexpected internal semaphore use')
                    expected_raw=struct.pack('<6I',*[int(v,16) for v in uses[-1]['after_words']])
                    require(bytes(self.uc.mem_read(pointer,24))==expected_raw,'Whole internal semaphore differs from its native epilogue')
                    raw[offset:offset+8]=expected_raw[:8]
                require(self.word(pointer+8)==self.word(pointer+12)==0 and self.word(pointer+20)==0 and
                        self.word(pointer+16)==self.internal_tags[pointer],
                        'Native internal semaphore owner/waiter/depth/tag differs')
            require(bytes(raw)==bytes.fromhex(new['raw108_hex']),
                    'Whole native TCB changed outside exact retained head/internal stale links '+old['TCB'])
            require(self.word(task+32)==(COND if task==self.timer_task else 0),
                    'Final native task owned head differs')
            if task!=self.controller:
                require(old['saved_frame']==new['saved_frame'] and
                        old['saved_frame13_words']==new['saved_frame13_words'],
                        'Resident background original frame changed '+old['TCB'])
                resident.append(dict(TCB=old['TCB'],frame=new['saved_frame'],raw13=new['saved_frame13_words']))
        thread=int(timed['thread'],16)
        require(self.timed_thread_inventory(thread)==timed,'Original timed Thread node/context/virtual clock changed')
        owned=set()
        for task in self.native_TCBs:
            pointer=self.word(task+32);prev=task+32
            while pointer:
                require(pointer in self.native_semaphores and pointer not in owned and len(owned)<16 and
                        self.word(pointer+4)==prev and self.word(prev)==pointer and self.word(pointer+8)==task and
                        self.word(pointer+12)==0,'Native retained owned semaphore chain malformed')
                owned.add(pointer);prev=pointer;pointer=self.word(pointer)
        require(owned=={COND,gui_condition} and
                {p for p in self.native_semaphores if self.word(p+8)}==owned,
                'Registered native semaphore owners disagree with exact owned chains')
        require(not self.condition_bootstrap_tokens,'Inherited fake settings constructor lock was used')
        return dict(native_inventory=after,whole_TCB108_compared_with_exact_native_deltas=True,
            resident_four_frames=resident,timed_thread=timed,controller_old_WAIT_frame_consumed=True,
            actual_controller_SP=hex(self.uc.reg_read(UC_ARM_REG_SP)),condition_constructor=ctors[0],
            native_token_lock=locks[0],native_Timer_transfer=transfers[0],
            original_lists=self.list_constructors,inherited_settings_ret0_lock_used=False,
            real_allocator_release_or_physical_device_boot_verified=False)


def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    target=STAGE/'heap-settings-terminal-probe.json';require(not target.exists(),'Preserve prior terminal artifacts')
    source=Path(__file__).resolve();build=json.loads((ROOT/BUILD).read_text());vm=HeapSettingsVM(NativeImage(),build)
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),device_io=False,sounds_emitted=False,
        full_scoped_final_guards_passed=False)
    try:
        result['phase']='load_and_native_singleton';print(json.dumps(dict(phase=result['phase'])),flush=True)
        result['load']=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480));dbsha=sha(DATABASE)
        vm.uc.reg_write(UC_ARM_REG_CPSR,(vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        result['kernel']=vm.configure_native_kernel_inventory();vm.kernel_invoke(POST,(vm.timer_task,16))
        vm.kernel_invoke(0x5d2f7d,());D=vm.kernel_invoke(0x5d2131,())
        require(vm.returned and D==0x8800520,'Original singleton did not return')
        result['prior_inventory']=vm.verify_singleton_inventory();result['prior_memory']=vm.verify_memory(voice,exports,dbsha)
        vm.kernel_invoke(WAIT);require(vm.idle_endpoint and vm.running_task==vm.idle,'Original background failed to drain')
        vm.kernel_invoke(POST,(vm.controller,1),stack=vm.idle);require(vm.returned and vm.running_task==vm.controller,'Idle POST failed')
        result['before_native_prep']=vm.native_task_inventory()
        gui_condition=int(vm.native_condition_waits[0]['condition'],16)
        thread=next(t for t in vm.native_TCBs if t not in [vm.controller,vm.idle,vm.timer_task,vm.word(D+0xaa8)])
        timed=vm.timed_thread_inventory(thread);result['before_timed_thread']=timed
        vm.begin_extra_zones(result['before_native_prep'],timed);vm.phase='exit_list_ctor';result['phase']=vm.phase
        print(json.dumps(dict(phase=vm.phase)),flush=True)
        require(bytes(vm.uc.mem_read(WORK,96))==b'\0'*96,'Native heap workspace is already in use; refusing reset')
        vm.kernel_invoke(0x3cc57d,(0x2d226b4,));require(vm.returned and vm.active_list is None,'Exit list ctor did not return')
        vm.phase='heap_ctor';result['phase']=vm.phase;print(json.dumps(dict(phase=vm.phase)),flush=True)
        result['heap_return']=hex(vm.kernel_invoke(0x388b6d,(EXTENT,1,0,0)))
        require(vm.returned,'Original heap ctor failed to return');result['heap_inventory']=vm.verify_heap(cold=True)
        result['phase']='settings';vm.phase='settings';print(json.dumps(dict(phase=vm.phase)),flush=True)
        result['settings_return']=hex(vm.kernel_invoke(0x2cbd17,()))
        require(vm.returned and vm.running_task==vm.controller,'Original settings did not return')
        result['settings_initializer_returned']=True
        result['heap_after_settings']=vm.verify_heap()
        result['settings_native_endpoint']=vm.verify_native_endpoint(gui_condition,result['before_native_prep'],timed)
        result['initialized_data_journal']=vm.verify_mutable_scope();result['extra_zones']=vm.verify_extra_zones()
        result['memory']=vm.verify_memory(voice,exports,dbsha)
        result.update(completed=True,full_scoped_final_guards_passed=True,
            settings_native_final_inventory_verified=True,foreground_or_device_App_verified=False)
        print(json.dumps(dict(completed=True,settings_returned=True)),flush=True)
    except Exception as error:
        result.update(completed=False,error=str(error));print(json.dumps(dict(phase=result.get('phase'),error=str(error))),flush=True)
    try: inventory=vm.native_task_inventory()if vm.native_TCBs else None
    except Exception as error: inventory=dict(snapshot_error=str(error))
    result.update(native_inventory=inventory,recent=list(vm.recent),backend_initializations=vm.backend_initializations,
        list_constructors=vm.list_constructors,listener_registrations=vm.listener_registrations,native_mutex_operations=vm.native_mutex_runs,
        condition_constructor_runs=vm.condition_constructor_runs,native_owner_transfers=vm.native_condition_owner_transfers,
        native_restores=vm.kernel_restores,pending_raw_ops={hex(t):v for t,v in vm.task_mutex_ops.items()if v},
        journal_zones=vm.zone_rows,initialized_CPU_store_journal=vm.mutable_cpu_stores,
        invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,
        registers={n:hex(vm.uc.reg_read(r))for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');vm.db.close()
    if not result.get('completed'):sys.exit(1)


if __name__=='__main__':main()
