"""New narrow Dispatcher observer; guest instructions and old journals remain.

Root calls init_dispatcher_actor_observer() after its existing constructor.
When dispatcher_body_active, root calls observe_dispatcher_actor(...) before
super().observe(...), returning immediately only when this returns True.
True skips an inherited hook, never execution of the original instruction.

This source is a static integration candidate. No emulator run is performed by
its producer/review. Allocation providers, FP exchanges, full manager/page
memory, BSS mapping, kernel scheduling and all older journals remain root's
separately declared and guarded responsibilities.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                              UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R6,
                              UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_PC,
                              UC_ARM_REG_CPSR)

_ROOT=Path(__file__).resolve().parents[3]
_SHAPE_PATH=_ROOT/'staging/native-player-dispatcher-fp/gui-static/dispatcher_actor_shapes.py'
_SHAPE_SHA='8275e21abb736367660d7bf0bec2ec57a7cc838d07f61c2d2322c9ad4f852fbf'
if hashlib.sha256(_SHAPE_PATH.read_bytes()).hexdigest()!=_SHAPE_SHA:
    raise RuntimeError('Frozen Dispatcher shape helper changed')
_SPEC=importlib.util.spec_from_file_location('garmin_frozen_dispatcher_actor_shapes',_SHAPE_PATH)
shape=importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(shape)

_REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
_FUNCTIONS=(0x393A2C,0x392DE4,0x38D4BE,0x38D456,0x38D480,
            0x390142,0x394596,0x1C0600,0x1C0624)
_RAW=dict(shape._MANAGER_RAW)
_INIT_CONTINUATIONS=(0x38D470,0x392EFA)
_CLOCK_CONTINUATIONS=(0x38D912,0x38D91E)


def require(test,message):
    if not test:
        raise RuntimeError('Dispatcher actor observer: '+message)


class DispatcherActorObserverMixin:
    def init_dispatcher_actor_observer(self):
        require(not hasattr(self,'dispatcher_actor_state'),'Observer initialized twice')
        required=('native_mutex_runs','task_mutex_ops','native_semaphores','backend_initializations',
                  'active_backend','raw_allocations','native_TCBs','internal_tags','store_disassemblers')
        require(all(hasattr(self,name) for name in required),'Existing native parent ledger missing')
        self.dispatcher_actor_state=dict(callback_entered=False,callback_returned=False,
            frames={p:[] for p in _FUNCTIONS},frame_history=[],initializers=[],raw_ops=[],
            raw_returns_pending=[],clock_reads=[],clock_pending=None,manager_allocator=None,
            manager_published=False,cleanup=None,cleanup_registrations=[],zones={},zone_hooks=[])
        # Do not read/map/init original BSS here. Existing mapping is root's input.
        self.dispatcher_actor_state['head_hook']=self.uc.hook_add(UC_HOOK_MEM_WRITE,
            self.journal_dispatcher_actor_write,begin=shape.CLEANUP_HEAD,end=shape.CLEANUP_HEAD+3)

    def _da_actor(self,uc):
        require(self.dispatcher_body_active and self.dispatcher_task==shape.DISPATCHER,
                'Missing declared actual body/task')
        require(self.running_task==self.dispatcher_task==self.word(0xF09090)
                and self.dispatcher_task in self.native_TCBs,'Actual running/current/native task differs')
        require(self.pending_restore is None,'Original restore destination has not been attributed by parent')
        require(bool(uc.reg_read(UC_ARM_REG_CPSR)&32),'Reviewed actor boundary is not Thumb')
        sp=uc.reg_read(UC_ARM_REG_SP)
        require(sp%4==0 and sp<=self.dispatcher_callback_SP<=self.dispatcher_task,
                'Body SP is outside captured callback stack')
        require(self.declared_storage(sp,self.dispatcher_task-sp), 'Body stack has no live original backing')
        return sp

    def _da_opcode(self,uc,address,length=2):
        expected=self.stock.read(address,length)
        require(bytes(uc.mem_read(address,length))==expected,'Original MAIN opcode differs '+hex(address))
        return expected.hex()

    def _da_original_call(self,uc,target,lr):
        high=lr&~1;low=high-4
        require(lr&1,'Expected an original Thumb caller')
        opcode=self.stock.read(low,4)
        instructions=list(self.store_disassemblers[True].disasm(opcode,low,count=1))
        require(len(instructions)==1 and instructions[0].size==4 and
                instructions[0].mnemonic in ('bl','blx') and
                instructions[0].op_str=='#'+hex(target) and
                bytes(uc.mem_read(low,4))==opcode,'Caller is not exact original MAIN BL/BLX')
        return dict(call=hex(low),opcode_hex=opcode.hex(),instruction=instructions[0].mnemonic+' '+instructions[0].op_str)

    def _da_frame(self,function):
        rows=self.dispatcher_actor_state['frames'][function]
        require(rows,'Missing actual containing-function entry '+hex(function))
        return rows[-1]

    def _da_live_raw(self,pointer,length,exact_length=None):
        matches=[(p,row) for p,row in self.raw_allocations.items() if not row['freed']
                 and p<=pointer and pointer+length<=p+row['length']]
        require(len(matches)==1,'Storage lacks one live raw allocation')
        base,row=matches[0]
        if exact_length is not None:
            require(base==pointer and row['length']==exact_length,'Original allocation size/base differs')
        require(self.declared_storage(pointer,length),'Live original allocation is not declared')
        self.verify_guard(base,row)
        return dict(pointer=hex(base),length=row['length'],service=row.get('service'),freed=False)

    def _da_add_zone(self,address,length,kind,already_hooked=False):
        zones=self.dispatcher_actor_state['zones']
        if address in zones:
            require(zones[address]['bytes']==length and zones[address]['kind']==kind,'Zone reused with different shape')
            return zones[address]
        require(all(address+length<=p or p+row['bytes']<=address for p,row in zones.items()),
                'New exact actor journal overlaps another actor zone')
        row=dict(start=hex(address),bytes=length,kind=kind,
                 before_hex=bytes(self.uc.mem_read(address,length)).hex(),stores=[])
        zones[address]=row
        if not already_hooked:
            self.dispatcher_actor_state['zone_hooks'].append(self.uc.hook_add(UC_HOOK_MEM_WRITE,
                self.journal_dispatcher_actor_write,begin=address,end=address+length-1))
        return row

    def _da_cleanup_inventory(self,head):
        nodes={};live=set();pointer=head
        while pointer:
            require(pointer%4==0 and pointer not in nodes and len(nodes)<4096,'Cleanup chain cyclic/unbounded')
            self._da_live_raw(pointer,16,16)
            raw=bytes(self.uc.mem_read(pointer,16));words=list(struct.unpack('<4I',raw))
            nodes[pointer]=words;live.add(pointer);pointer=words[0]
        require(shape.cleanup_reachable(head,nodes,live)==list(nodes),'Cleanup inventory order differs')
        return nodes,live

    def journal_dispatcher_actor_write(self,uc,access,address,size,value,data):
        if not getattr(self,'dispatcher_body_active',False):
            return
        state=self.dispatcher_actor_state
        zones=[row for start,row in state['zones'].items() if start<=address and address+size<=start+row['bytes']]
        require(len(zones)==1 and size in (1,2,4),'Write outside exact declared actor zone')
        row=zones[0];pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)
        # Mixed-mode native raw bodies perform ARM stores too; this is not an
        # actor-entry Thumb check. Readyhead may transiently change in kernel.
        require(self.running_task==self.dispatcher_task==shape.DISPATCHER,'Actor-zone CPU writer changed task')
        opcode,instruction,load=self.original_store(pc,thumb)
        store=dict(PC=hex(pc),load_PC=hex(load),address=hex(address),size=size,
            value=value&((1<<(8*size))-1),before_hex=bytes(uc.mem_read(address,size)).hex(),
            opcode_hex=opcode.hex(),instruction=instruction,running_task=hex(self.running_task),Thumb=thumb)
        if row['kind']=='raw_backend':
            pointer=int(row['start'],16)
            init=next((r for r in state['initializers'] if int(r['pointer'],16)==pointer),None)
            if pc in range(0x3008A2,0x3008AE,2):
                require(init is not None and self.active_backend is init and
                        address==pointer+2*(pc-0x3008A2) and size==4 and value==0,
                        'Native actor initializer store differs')
            elif init is not None and pc==init['reviewed_shape']['tag_store_PC']:
                require(init.get('actual_native_continuation_seen') and not init.get('native_tag_store_seen')
                        and address==pointer+16 and size==4 and value==init['reviewed_shape']['tag'],
                        'Original post-init tag store differs')
                init.update(native_tag_store_seen=True,native_tag_store=store)
            else:
                require(0x300800<=pc<0x300E00 and self.task_mutex_ops[self.dispatcher_task],
                        'Backend write lacks active original native raw operation')
        elif row['kind']=='clock_result':
            index=0 if pc==0x38D918 else 1
            require(pc in (0x38D918,0x38D91E) and len(state['clock_reads'])>index,
                    'Clock result has an unreviewed writer')
            clock=state['clock_reads'][index]
            require(clock['original_getter_returned'] and not clock.get('actual_result_store_journaled')
                    and size==4 and value==0 and address==self.manager_object+(0x378 if index==0 else 0x37C)
                    and uc.reg_read(UC_ARM_REG_R6)==self.manager_object+0x340,
                    'Native clock result store address/register/value/order differs')
            clock.update(actual_result_store_journaled=True,actual_result_store=store)
        else:
            cleanup=state['cleanup']
            require(cleanup is not None and row['kind'] in ('cleanup_head','cleanup_new_node'),
                    'Existing cleanup nodes are immutable in this append scope')
            index=len(cleanup['native_stores']);node=cleanup.get('node')
            require(node is not None,'Cleanup store precedes actual allocator return')
            expected=shape.cleanup_registration_shape(node,cleanup['actual_oldhead'])['ordered_native_stores']
            require(index<len(expected) and dict(PC=pc,address=address,size=size,value=value)==expected[index],
                    'Cleanup writer/address/value/order differs')
            if index>=3:
                require(cleanup.get('actual_head_getter_seen'),'Cleanup link write precedes original head read')
            cleanup['native_stores'].append(dict(PC=pc,address=address,size=size,value=value,
                before_hex=store['before_hex'],opcode_hex=store['opcode_hex']))
        row['stores'].append(store)

    def _da_begin_raw(self,uc,reviewed_shape):
        sp=self._da_actor(uc);pointer=uc.reg_read(UC_ARM_REG_R0)
        event=dict(scope=shape.SCOPE,actor=self.running_task,current=self.word(0xF09090),
                   Thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32),entry=reviewed_shape['entry'],
                   LR=uc.reg_read(UC_ARM_REG_LR),entry_SP=sp,pointer=pointer,
                   tag=self.word(pointer+16),classification_byte=uc.mem_read(pointer+22,1)[0])
        shape.check_event_shape(reviewed_shape,event)
        self._da_opcode(uc,reviewed_shape['entry']);self._da_opcode(uc,reviewed_shape['continuation']-4,4)
        require(self.declared_storage(pointer,24),'Raw backend24 has no declared native storage')
        if pointer==shape.REGISTRY_SEM or pointer==(getattr(self,'manager_object',0) or 0)+0xE04:
            inits=[r for r in self.dispatcher_actor_state['initializers'] if int(r['pointer'],16)==pointer]
            require(len(inits)==1 and inits[0].get('native_tag_store_seen'),'New raw backend has not executed native init/tag')
        if pointer not in self.native_semaphores:
            self.register_native_semaphore(pointer)
        require(not self.native_semaphores[pointer]['retained_condition_token'],'Raw backend is a retained condition token')
        self._da_add_zone(pointer,24,'raw_backend')
        row=dict(original_entry=hex(reviewed_shape['entry']),pointer=hex(pointer),
            native_caller=hex(reviewed_shape['continuation']),operation='lock' if reviewed_shape['entry']==0x3009A0 else 'unlock',
            scope='dispatcher_manager_or_current_internal',running_task=hex(self.running_task),
            entry_SP=hex(sp),entry_LR=hex(uc.reg_read(UC_ARM_REG_LR)),
            before_words=[hex(self.word(pointer+4*n)) for n in range(6)],native_body_returned=False,
            semaphore_fields_written_by_original_only=True,host_CPU_context_restore=False,
            actual_caller_continuation_seen=False,reviewed_shape=reviewed_shape)
        self.native_mutex_runs.append(row);self.task_mutex_ops[self.running_task].append(row)
        self.dispatcher_actor_state['raw_ops'].append(row)
        self.dispatcher_actor_state['raw_returns_pending'].append(row)
        self.visits[reviewed_shape['entry']]+=1

    def observe_dispatcher_actor(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):
            return False
        state=self.dispatcher_actor_state;lr=uc.reg_read(UC_ARM_REG_LR);caller=lr&~1
        if address==0x405340:
            sp=self._da_actor(uc)
            require(not state['callback_entered'] and sp==self.dispatcher_callback_SP and lr==0x60935D,
                    'Actual callback entry repeated or frame/LR differs')
            self._da_opcode(uc,address)
            state.update(callback_entered=True,callback_SP=hex(sp),callback_LR=hex(lr),
                         original_manager_cache_before=hex(self.word(0xF2CD0C)))
            require(self.word(0xF2CD0C)==0,'This new constructor scope requires actual cold manager cache')
        require(state['callback_entered'],'Body observer active before actual callback entry')
        # Capture returns before entering a second reviewed function at that PC.
        for function,frames in state['frames'].items():
            if frames and address==(frames[-1]['LR']&~1):
                frame=frames[-1];sp=self._da_actor(uc)
                require(sp==frame['SP'],'Containing native function actual return SP differs')
                frame.update(returned=True,result=hex(uc.reg_read(UC_ARM_REG_R0)))
                frames.pop()
        for row in list(state['raw_returns_pending']):
            if address==int(row['native_caller'],16):
                sp=self._da_actor(uc)
                require(row['native_body_returned'] and row.get('original_return_branch_reached')
                        and sp==int(row['entry_SP'],16) and uc.reg_read(UC_ARM_REG_R0)==row['original_return'],
                        'Native pending epilogue/actual caller SP/result incomplete')
                if row['operation']=='lock':
                    require(row['original_return']==0 and self.word(int(row['pointer'],16)+8)==self.dispatcher_task,
                            'Original actor raw lock did not acquire current native ownership')
                row.update(actual_caller_continuation_seen=True,actual_return_SP=hex(sp),
                           actual_return_r0=uc.reg_read(UC_ARM_REG_R0))
                state['raw_returns_pending'].remove(row)
        for row in state['initializers']:
            reviewed=row['reviewed_shape']
            if address==reviewed['continuation'] and not row.get('actual_native_continuation_seen'):
                sp=self._da_actor(uc)
                require(row['original_body_executed'] and self.active_backend is None
                        and sp==reviewed['entry_SP'] and uc.reg_read(UC_ARM_REG_R0)==int(row['pointer'],16)
                        and bytes(uc.mem_read(int(row['pointer'],16),24))==bytes(24),
                        'Native sixzero body/actual continuation differs')
                expected=[dict(PC=hex(pc),address=hex(int(row['pointer'],16)+4*i),size=4,value=0)
                          for i,pc in enumerate(reviewed['native_zero_store_PCs'])]
                require(row['native_zero_writes']==expected,'Parent native initializer six stores/order differ')
                row.update(actual_native_continuation_seen=True,actual_return_SP=hex(sp))
        if address in _FUNCTIONS:
            sp=self._da_actor(uc);call=self._da_original_call(uc,address,lr)
            self._da_opcode(uc,address)
            frame=dict(entry=hex(address),SP=sp,LR=lr,returned=False,original_call=call)
            if address==0x38D456:
                frame['actual_once_before']=self.word(0xF2CBF4)
            if address==0x392DE4:
                manager=uc.reg_read(UC_ARM_REG_R0);allocation=state['manager_allocator']
                require(allocation and allocation.get('actual_return_seen') and allocation['pointer']==manager,
                        'Manager ctor does not originate in observed original getter allocation')
                self._da_live_raw(manager,0xE50,0xE50)
                require(getattr(self,'manager_object',None) in (None,0,manager),'Manager pointer changed')
                self.manager_object=manager
            state['frames'][address].append(frame);state['frame_history'].append(frame)
        if address==0x3954CC and caller==0x393A3E:
            sp=self._da_actor(uc);getter=self._da_frame(0x393A2C)
            require(uc.reg_read(UC_ARM_REG_R0)==0xE50 and sp==getter['SP']-16 and state['manager_allocator'] is None,
                    'Original manager allocation call differs')
            self._da_original_call(uc,address,lr)
            state['manager_allocator']=dict(request=0xE50,SP=sp,LR=lr,actual_return_seen=False)
        if address==0x393A3E:
            row=state['manager_allocator'];sp=self._da_actor(uc);pointer=uc.reg_read(UC_ARM_REG_R0)
            require(row and not row['actual_return_seen'] and sp==row['SP'] and pointer!=0,
                    'Manager allocation actual return missing/null')
            self._da_live_raw(pointer,0xE50,0xE50)
            row.update(actual_return_seen=True,pointer=pointer)
        if address==0x393A48:
            self._da_actor(uc)
            require(self.manager_object and self.word(0xF2CD0C)==self.manager_object,
                    'Original manager native cache publication differs')
            state['manager_published']=True
        if address==0x3008A0 and caller in _INIT_CONTINUATIONS:
            function=0x38D456 if caller==0x38D470 else 0x392DE4
            frame=self._da_frame(function)
            reviewed=shape.manager_init_shape(caller,getattr(self,'manager_object',0),frame['SP'])
            sp=self._da_actor(uc);pointer=uc.reg_read(UC_ARM_REG_R0)
            # Initializer tag is a future native post-return store, not an
            # observed entry value. Do not feed expected tag as a guest fact.
            entry_shape={key:value for key,value in reviewed.items() if key!='tag'}
            shape.check_event_shape(entry_shape,dict(scope=shape.SCOPE,actor=self.running_task,current=self.word(0xF09090),
                Thumb=True,entry=address,LR=lr,entry_SP=sp,pointer=pointer))
            self._da_opcode(uc,address);self._da_original_call(uc,address,lr)
            storage=self.declared_storage(pointer,24)
            require(storage and self.active_backend is None and not any(r['pointer']==hex(pointer) for r in state['initializers']),
                    'Native manager initializer storage/nesting/repetition differs')
            if caller==0x38D470:
                require(frame['actual_once_before']==0 and self.word(0xF2CBF4)==1
                        and bytes(uc.mem_read(pointer,24))==bytes(24),'Native cold once/backend result differs')
            else:
                self._da_live_raw(self.manager_object,0xE50,0xE50)
            self._da_add_zone(pointer,24,'raw_backend')
            row=dict(original_entry=hex(address),pointer=hex(pointer),native_caller=hex(caller),bytes=24,
                storage_boundary=storage,before_hex=bytes(uc.mem_read(pointer,24)).hex(),native_zero_writes=[],
                original_body_executed=False,host_seeded_backend_bytes=False,running_task=hex(self.running_task),
                reviewed_shape=reviewed)
            self.backend_initializations.append(row);state['initializers'].append(row);self.active_backend=row
            self.visits[address]+=1
            return True
        if (address,caller) in _RAW:
            function,delta,instance=_RAW[address,caller]
            reviewed=shape.manager_raw_shape(address,caller,getattr(self,'manager_object',0),self._da_frame(function)['SP'])
            self._da_begin_raw(uc,reviewed)
            return True
        if (address,caller) in ((0x3009A0,0x1C0618),(0x3008B0,0x1C0634)):
            function=0x1C0600 if address==0x3009A0 else 0x1C0624
            pointer=self.dispatcher_task+56
            require(pointer in self.internal_tags,'Missing actual pre-operation internal native tag snapshot')
            reviewed=shape.current_internal_shape(address,caller,self._da_frame(function)['SP'],self.internal_tags[pointer])
            self._da_begin_raw(uc,reviewed)
            return True
        if address==0x353A9C:
            sp=self._da_actor(uc)
            reviewed=shape.clock_shape(caller,self._da_frame(0x38D4BE)['SP'],self.word(0xF09098))
            shape.check_event_shape(reviewed,dict(scope=shape.SCOPE,actor=self.running_task,current=self.word(0xF09090),
                Thumb=True,entry=address,LR=lr,entry_SP=sp))
            require(state['clock_pending'] is None,'Nested clock read')
            self._da_opcode(uc,address,6);self._da_original_call(uc,address,lr)
            self._da_add_zone(self.manager_object+0x378,8,'clock_result')
            row=dict(reviewed_shape=reviewed,original_getter_returned=False,result_store_seen=False)
            state['clock_reads'].append(row);state['clock_pending']=row;self.visits[address]+=1
            return True  # Only bypass inherited ControllerVM host+20; native getter executes.
        if address in _CLOCK_CONTINUATIONS:
            row=state['clock_pending'];sp=self._da_actor(uc)
            require(row and row['reviewed_shape']['continuation']==address and sp==row['reviewed_shape']['entry_SP']
                    and uc.reg_read(UC_ARM_REG_R0)==self.word(0xF09098)==0,
                    'Original fixedclock getter actual return differs')
            require(uc.reg_read(UC_ARM_REG_R4)==self.manager_object,'Clock target is not actualmanager')
            row.update(original_getter_returned=True,actual_return_SP=hex(sp));state['clock_pending']=None
        if address in (0x38D91A,0x38D920):
            index=0 if address==0x38D91A else 1
            require(len(state['clock_reads'])>index,'Clock result store before getter')
            row=state['clock_reads'][index]
            offset=0x378 if index==0 else 0x37C
            require(row['original_getter_returned'] and row.get('actual_result_store_journaled')
                    and self.word(self.manager_object+offset)==0
                    and uc.reg_read(UC_ARM_REG_R6)==self.manager_object+0x340,
                    'Native clock result store effective target/value differs')
            row.update(result_store_seen=True,result_address=hex(self.manager_object+offset),
                       original_store_PC=hex(0x38D918 if index==0 else 0x38D91E))
        if address==0x3896F8:
            sp=self._da_actor(uc)
            require(lr==0x38D4B5 and [uc.reg_read(r) for r in _REGS[:3]]==[0x34F9B40,0x20DC53,0xC7F980]
                    and sp==self._da_frame(0x38D480)['SP']-16 and state['cleanup'] is None,
                    'Original manager cleanup registration arguments/frame differ')
            self._da_original_call(uc,address,lr);self._da_opcode(uc,address)
            oldhead=self.word(shape.CLEANUP_HEAD);nodes,live=self._da_cleanup_inventory(oldhead)
            self._da_add_zone(shape.CLEANUP_HEAD,4,'cleanup_head',already_hooked=True)
            for p in nodes:self._da_add_zone(p,16,'cleanup_existing_node')
            state['cleanup']=dict(entry_SP=sp,LR=lr,actual_oldhead=oldhead,before_nodes=nodes,
                live_before=sorted(live),native_stores=[],allocator_entered=False,actual_head_getter_seen=False)
        cleanup=state['cleanup']
        if address==0x39544C and caller==0x389706:
            sp=self._da_actor(uc)
            require(cleanup and not cleanup['allocator_entered'] and sp==cleanup['entry_SP']-32
                    and uc.reg_read(UC_ARM_REG_R0)==16,'Cleanup original16 allocation request differs')
            self._da_original_call(uc,address,lr);cleanup['allocator_entered']=True
        if address==0x389706:
            sp=self._da_actor(uc);node=uc.reg_read(UC_ARM_REG_R0)
            require(cleanup and cleanup['allocator_entered'] and sp==cleanup['entry_SP']-32 and node!=0,
                    'Cleanup original allocator return missing/null')
            self._da_live_raw(node,16,16)
            require(node not in cleanup['live_before'],'Cleanup allocator reused an existing live node')
            cleanup['node']=node;self._da_add_zone(node,16,'cleanup_new_node')
        if address==0x38971A:
            self._da_actor(uc)
            require(cleanup and cleanup.get('node')==uc.reg_read(UC_ARM_REG_R4)
                    and uc.reg_read(UC_ARM_REG_R0)==shape.CLEANUP_HEAD
                    and self.word(shape.CLEANUP_HEAD)==cleanup['actual_oldhead'],
                    'Original cleanup getter/actual oldhead changed before link')
            cleanup['actual_head_getter_seen']=True
        if address==0x38D4B4:
            sp=self._da_actor(uc)
            require(cleanup and sp==cleanup['entry_SP'] and uc.reg_read(UC_ARM_REG_R0)==0,
                    'Original cleanup registration did not return0 at actualcaller')
            afterhead=self.word(shape.CLEANUP_HEAD);nodes,live=self._da_cleanup_inventory(afterhead)
            reviewed=shape.cleanup_registration_shape(cleanup['node'],cleanup['actual_oldhead'])
            shape.check_cleanup_linkage(reviewed,cleanup['before_nodes'],nodes,set(cleanup['live_before']),
                live,afterhead,cleanup['native_stores'])
            cleanup.update(original_registration_returned=True,after_head=hex(afterhead),
                after_nodes=nodes,live_after=sorted(live),reviewed_shape=reviewed)
            state['cleanup_registrations'].append(cleanup);state['cleanup']=None
        if address==0x60935C:
            sp=self._da_actor(uc)
            require(sp==self.dispatcher_callback_SP and not state['callback_returned'],
                    'Native callback return frame differs/repeated')
            state['callback_returned']=True
        return False

    def verify_dispatcher_actor_observer(self):
        state=self.dispatcher_actor_state
        require(state['callback_entered'] and state['callback_returned'] and state['manager_published'],
                'Callback/manager native completion absent')
        require(not state['raw_returns_pending'] and state['clock_pending'] is None and state['cleanup'] is None,
                'Actor native continuation is still pending')
        require(all(not rows for rows in state['frames'].values()),'Containing native function remains active')
        require(len(state['initializers'])==2 and all(r['original_body_executed'] and
                r.get('actual_native_continuation_seen') and r.get('native_tag_store_seen') for r in state['initializers']),
                'Both original native initializer/tag continuations incomplete')
        require(state['raw_ops'] and all(r['native_body_returned'] and r['actual_caller_continuation_seen']
                for r in state['raw_ops']),'Actor raw native pending returns incomplete')
        require(len(state['clock_reads'])==2 and all(r['original_getter_returned'] and r['result_store_seen']
                for r in state['clock_reads']) and self.word(0xF09098)==0,'Fixed nativeclock read/store scope incomplete')
        require(len(state['cleanup_registrations'])==1,'Original cleanup registration count differs')
        for start,row in state['zones'].items():
            expected=bytearray.fromhex(row['before_hex'])
            for store in row['stores']:
                offset=int(store['address'],16)-start;length=store['size']
                require(expected[offset:offset+length].hex()==store['before_hex'],'Actor zone journal omitted intervening write')
                expected[offset:offset+length]=store['value'].to_bytes(length,'little')
            actual=bytes(self.uc.mem_read(start,row['bytes']))
            require(actual==bytes(expected),'Whole exact actor zone differs from chronological CPU journal')
            row.update(whole_zone_replayed=True,after_sha256=hashlib.sha256(actual).hexdigest())
        for init in state['initializers']:
            pointer=int(init['pointer'],16)
            require(self.word(pointer+16)==init['reviewed_shape']['tag'] and self.uc.mem_read(pointer+22,1)[0]==0,
                    'Final native raw tag/class differs')
            require(self.word(pointer+8)==0 and self.word(pointer+12)==0
                    and int.from_bytes(self.uc.mem_read(pointer+20,2),'little')==0,
                    'Final actor manager raw backend retains owner/waiter/depth')
        return self.snapshot_dispatcher_actor_observer()

    def snapshot_dispatcher_actor_observer(self):
        # Exclude runtime hook IDs; normalize integer dictionary keys to JSON.
        state={key:value for key,value in self.dispatcher_actor_state.items() if key not in ('zone_hooks','head_hook')}
        return json.loads(json.dumps(state))
