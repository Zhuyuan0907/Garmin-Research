"""Exact current-Dispatcher 395520 -> 353A9C native read-only clock prefix.

No VM is created or executed by this module. Parent mappings, native raw
epilogues, FP and all existing journals remain intact. The new observer only
bypasses the inherited clock hook for one captured native caller; original
instructions execute. Subsequent unreviewed allocator entries stop.
"""
from pathlib import Path
import hashlib, importlib.util, json, struct
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_PC, UC_ARM_REG_CPSR)

ROOT=Path(__file__).resolve().parents[3]
PARENT=ROOT/'staging/native-player-inline-fields/gui-static/inline_fields_observer.py'
PARENT_SHA='f8ef74225acadc6a8e9ec13791baf9103a5227e66c1532ce177d2226e6a8c681'
if hashlib.sha256(PARENT.read_bytes()).hexdigest()!=PARENT_SHA:
    raise RuntimeError('Frozen inline-field observer changed')
spec=importlib.util.spec_from_file_location('garmin_clock_caller_frozen_inline',PARENT)
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
require=parent.require
DISPATCHER=0x8804FB8
CLOCK=0x353A9C
CLOCK_WORD=0xF09098
CLOCK_RETURN=0x39552C
GETTER_OPS=((0x353A9C,'0149'),(0x353A9E,'0868'),(0x353AA0,'7047'))
ALLOC_RETURNS={0x395534:48,0x395544:8}
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)


def clock_caller_shapes(SFS_entry_SP):
    require(type(SFS_entry_SP) is int and SFS_entry_SP>=224 and SFS_entry_SP%4==0,
            'Invalid actual SFS native entry SP')
    wrapper=SFS_entry_SP-72
    constructor=wrapper-24
    clock=constructor-128
    return dict(SFS_entry=0x26DCE8,SFS_entry_SP=SFS_entry_SP,
        wrapper_entry=0x39578E,wrapper_call=0x26DD5C,wrapper_LR=0x26DD61,
        wrapper_entry_SP=wrapper,wrapper_body_SP=constructor,wrapper_push_bytes=24,
        constructor_entry=0x395520,constructor_call=0x3957B2,constructor_LR=0x3957B7,
        constructor_entry_SP=constructor,constructor_push_bytes=36,constructor_local_bytes=92,
        clock_entry=CLOCK,clock_call=0x395528,clock_LR=CLOCK_RETURN|1,
        clock_entry_SP=clock,clock_return=CLOCK_RETURN,clock_word=CLOCK_WORD,
        clock_result_store_PC=CLOCK_RETURN,clock_result_address=clock+0x3C,
        clock_result_size=4,clock_result_value=0,clock_host_write_allowed=False)


def check_clock_actor(shape,event):
    require(event['actor']==event['current']==DISPATCHER and event['Thumb'] is True,
            'Clock caller actor/current/mode differs')
    require(event['entry']==CLOCK and event['LR']==shape['clock_LR']
            and event['SP']==shape['clock_entry_SP'] and event['clock_word']==0,
            'Clock caller native entry/LR/SP/fixed input differs')


def check_clock_result_store(shape,event):
    require(event['actor']==event['current']==DISPATCHER and event['Thumb'] is True,
            'Clock result store actor/current/mode differs')
    require(event['actual_return_seen'] and
            (event['PC'],event['address'],event['size'],event['value'],event['SP'])==
            (CLOCK_RETURN,shape['clock_result_address'],4,0,shape['clock_entry_SP']),
            'Clock result store lacks exact actual return/tuple/SP')


def clock_bank_input_shape(copy,bank_start,bank_size,journal_active,raw):
    require(copy and copy['runtime_start']==bank_start==0xF00000
            and copy['load_start']==0xCB1980 and copy['size']==bank_size==467532,
            'Clock input lacks exact original initialized-copy bank provenance')
    require(journal_active is True and bank_start<=CLOCK_WORD and
            CLOCK_WORD+4<=bank_start+bank_size and raw==bytes(4),
            'Clock fixed0 input lacks existing whole initialized-bank journal/beforeimage')
    return dict(storage_class='original_initialized_data_copy',bank_start=hex(bank_start),
        bank_bytes=bank_size,load_start=hex(copy['load_start']),
        clock_address=hex(CLOCK_WORD),clock_load_address=hex(copy['load_start']+CLOCK_WORD-bank_start),
        inherited_whole_bank_journal_required=True,new_mapping_or_BSS_zero_assumption=False)


class ClockCallerDispatcherActorObserverMixin(parent.InlineFieldDispatcherActorObserverMixin):
    def init_dispatcher_actor_observer(self):
        super().init_dispatcher_actor_observer()
        require(not hasattr(self,'clock_caller_state') and hasattr(self,'body_zones'),
                'Clock observer repeated or original whole-stack ledger missing')
        self.clock_caller_state=dict(inputs=None,wrapper=None,constructor=None,
            clock_reads=[],pending=None,result_stores=[],clock_prefix_complete=False,
            clock_write_attempts=[],unreviewed_allocator_boundaries=[],
            whole_395520_function_complete=False,full_scoped_guards_passed=False,
            full_dispatcher_body_or_foreground_verified=False)
        self.clock_caller_hooks=[self.uc.hook_add(UC_HOOK_MEM_WRITE,
            self.journal_clock_word_write,begin=CLOCK_WORD,end=CLOCK_WORD+3)]

    def capture_dispatcher_settings_inputs(self):
        result=super().capture_dispatcher_settings_inputs();state=self.clock_caller_state
        require(state['inputs'] is None,'Clock input capture repeated')
        raw=bytes(self.uc.mem_read(CLOCK_WORD,4))
        bank=next((r for r in self.stock.copies if r['runtime_start']==0xF00000),None)
        provenance=clock_bank_input_shape(bank,self.mutable_bank_start,self.mutable_bank_size,
            self.mutable_journal_active and self.mutable_bank_before is not None,raw)
        state['inputs']=dict(address=hex(CLOCK_WORD),bytes=4,before_hex=raw.hex(),
            captured_running_task=hex(self.running_task),captured_current=hex(self.word(0xF09090)),
            initialized_data_bank_provenance=provenance,
            host_clock_seeded_or_reset=False,physical_clock_or_tick_verified=False)
        return dict(result,clock_caller_inputs=json.loads(json.dumps(state['inputs'])))

    def _cc_zone(self,address,n):
        matches=[r for low,r in self.body_zones.items() if low<=address and address+n<=low+r['bytes']]
        require(len(matches)==1,'Clock frame lacks one existing whole-native-stack journal')
        return matches[0]

    def _cc_begin_frame(self,uc,pc,SP,push_registers,local_bytes,LR,shape):
        n=4*len(push_registers);low=SP-n;zone=self._cc_zone(low,n)
        require(self.declared_storage(SP-n-local_bytes,n+local_bytes),
                'Clock containing-frame stack has no live declared backing')
        return dict(entry=hex(pc),SP=SP,LR=LR,entry_arguments=[uc.reg_read(r) for r in REGS],
            source_call=self._da_original_call(uc,pc,LR),original_entry_opcode=self._da_opcode(uc,pc),
            stack_start=hex(SP-n-local_bytes),stack_bytes=n+local_bytes,
            actual_stack_before_hex=bytes(uc.mem_read(SP-n-local_bytes,n+local_bytes)).hex(),
            push_start=hex(low),push_bytes=n,push_before_hex=bytes(uc.mem_read(low,n)).hex(),
            actual_push_values=[uc.reg_read(r) for r in push_registers],
            whole_stack_journal_start=zone['start'],whole_stack_event_index=len(zone['stores']),
            push_events=[],native_push_complete=False,source_shape=shape,
            frame_host_seeded=False,actual_containing_function_return_seen=False)

    def _cc_finish_push(self,uc,row):
        low=int(row['push_start'],16);n=row['push_bytes'];zone=self._cc_zone(low,n)
        events=zone['stores'][row['whole_stack_event_index']:]
        require(not row['native_push_complete'] and len(events)==n//4,
                'Native clock containing PUSH event count/repetition differs')
        expected=bytearray.fromhex(row['push_before_hex'])
        for index,event in enumerate(events):
            require(event['PC']==row['entry'] and event['Thumb'] and event['processor_mode']==31
                    and event['running_task']==hex(DISPATCHER) and event['opcode_hex']==row['original_entry_opcode']
                    and (int(event['address'],16),event['size'],event['value'])==
                    (low+4*index,4,row['actual_push_values'][index]),
                    'Native clock containing PUSH source/value/actor/span differs')
            offset=4*index
            require(event['before_hex']==expected[offset:offset+4].hex(),'Clock containing PUSH beforeimage differs')
            expected[offset:offset+4]=event['value'].to_bytes(4,'little')
        require(bytes(uc.mem_read(low,n))==expected,'Clock containing PUSH differs from whole native stack history')
        row.update(push_events=json.loads(json.dumps(events)),native_push_complete=True,
                   push_after_hex=expected.hex(),actual_after_push_SP=hex(uc.reg_read(UC_ARM_REG_SP)))

    def journal_clock_word_write(self,uc,access,address,size,value,data):
        if not getattr(self,'dispatcher_body_active',False):return
        self.clock_caller_state['clock_write_attempts'].append(dict(PC=hex(uc.reg_read(UC_ARM_REG_PC)),
            address=hex(address),size=size,value=value,before_hex=bytes(uc.mem_read(address,size)).hex(),
            running_task=hex(self.running_task),admitted=False))
        require(False,'Read-only fixed clock input has an unreviewed write attempt')

    def journal_clock_result_write(self,uc,access,address,size,value,data):
        if not getattr(self,'dispatcher_body_active',False):return
        state=self.clock_caller_state;row=state['pending']
        require(row and row['actual_return_seen'] and not row['result_store_seen'],
                'Clock result cell writer lacks one pending original returned getter')
        shape=row['shape'];sp=self._da_actor(uc);pc=uc.reg_read(UC_ARM_REG_PC)
        event=dict(actor=self.running_task,current=self.word(0xF09090),Thumb=True,
            actual_return_seen=row['actual_return_seen'],PC=pc,address=address,size=size,
            value=value,SP=sp)
        check_clock_result_store(shape,event)
        require([uc.reg_read(r) for r in REGS]==[0,CLOCK_WORD,row['entry_arguments'][2],row['entry_arguments'][3]]
                and uc.reg_read(UC_ARM_REG_LR)==shape['clock_LR'],
                'Native clock result-store registers/LR differ')
        opcode,instruction,load=self.original_store(pc,True)
        require(opcode.hex()=='0f90' and load==pc and
                bytes(uc.mem_read(address,4)).hex()==row['result_before_hex'],
                'Original clock result opcode/beforeimage differs')
        store=dict(PC=hex(pc),load_PC=hex(load),Thumb=True,address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),opcode_hex=opcode.hex(),
            original_instruction=instruction,running_task=hex(self.running_task))
        state['result_stores'].append(store);row.update(result_store_seen=True,result_store=store)
        # Root's existing whole-D stack hook records this CPU store once.

    def observe_dispatcher_actor(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):return False
        state=self.clock_caller_state;lr=uc.reg_read(UC_ARM_REG_LR);caller=lr&~1
        if address==0x39578E and caller==0x26DD60:
            require(state['inputs'] and state['wrapper'] is None,'Clock wrapper before capture or repeated')
            sfs=self._ss_frame(0x26DCE8);shape=clock_caller_shapes(sfs['SP']);sp=self._da_actor(uc)
            require(sfs['LR']==0x26DE5D and sfs['arguments'][0]=='0x3aaed08'
                    and sp==shape['wrapper_entry_SP'] and lr==shape['wrapper_LR']
                    and [uc.reg_read(r) for r in REGS]==[sp+0x28,sp+0x10,0xEA60,1],
                    'Clock wrapper lacks exact native SFS caller/SP/arguments')
            state['wrapper']=self._cc_begin_frame(uc,address,sp,
                (UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_LR),0,lr,shape)
        wrapper=state['wrapper']
        if address==0x395790 and wrapper and not wrapper['native_push_complete']:
            require(self._da_actor(uc)==wrapper['SP']-24,'Native wrapper PUSH actual SP differs')
            self._cc_finish_push(uc,wrapper)
        if address==0x395520 and caller==0x3957B6:
            require(wrapper and wrapper['native_push_complete'] and state['constructor'] is None,
                    'Clock constructor lacks original wrapper or repeated')
            shape=wrapper['source_shape'];sp=self._da_actor(uc)
            manager=self.manager_object
            self._da_live_raw(manager,0xE50,0xE50)
            require(self.dispatcher_actor_state['manager_published'] and self.word(0xF2CD0C)==manager,
                    'Clock descriptor does not originate in actual published native manager')
            require(sp==shape['constructor_entry_SP'] and lr==shape['constructor_LR']
                    and [uc.reg_read(r) for r in REGS]==[wrapper['entry_arguments'][0],manager+0xE34,
                        wrapper['entry_arguments'][1],wrapper['entry_arguments'][2]]
                    and self.word(sp)==wrapper['entry_arguments'][3]==1,
                    'Clock constructor exact wrapper argument/SP/fifth-input binding differs')
            fifth=next((r for r in reversed(self._cc_zone(sp,4)['stores']) if r['address']==hex(sp)),None)
            require(fifth and fifth['PC']=='0x3957b0' and fifth['opcode_hex']=='0097'
                    and fifth['size']==4 and fifth['value']==1 and fifth['running_task']==hex(DISPATCHER),
                    'Clock fifth input lacks actual original caller STRr7,[SP]')
            require(self._da_opcode(uc,0x223A08,6)=='014940187047' and self.stock.word(0x223A10)==0xE34,
                    'Manager E34 accessor original bytes/literal differ')
            row=self._cc_begin_frame(uc,address,sp,
                (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,
                 UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_LR),92,lr,shape)
            row.update(native_stack_fifth_input=self.word(sp),native_fifth_input_store=json.loads(json.dumps(fifth)),
                manager=hex(manager),manager_E34_binding=hex(manager+0xE34),local_SUB_seen=False)
            state['constructor']=row
        constructor=state['constructor']
        if address==0x395522 and constructor and not constructor['native_push_complete']:
            require(self._da_actor(uc)==constructor['SP']-36,'Native constructor PUSH actual SP differs')
            self._cc_finish_push(uc,constructor);require(self._da_opcode(uc,address)=='97b0','Original SUBsp,#5C differs')
        if address==0x395524 and constructor and not constructor['local_SUB_seen']:
            require(constructor['native_push_complete'] and self._da_actor(uc)==constructor['SP']-128,
                    'Native constructor SUB actual SP differs')
            constructor['local_SUB_seen']=True
        if address==CLOCK and caller==CLOCK_RETURN:
            require(constructor and constructor['native_push_complete'] and constructor['local_SUB_seen']
                    and not state['clock_reads'] and state['pending'] is None,
                    'Clock getter lacks real original containing-function entry/prologue')
            shape=constructor['source_shape'];sp=self._da_actor(uc)
            check_clock_actor(shape,dict(actor=self.running_task,current=self.word(0xF09090),Thumb=True,
                entry=address,LR=lr,SP=sp,clock_word=self.word(CLOCK_WORD)))
            require([uc.reg_read(r) for r in REGS]==constructor['entry_arguments']
                    and uc.reg_read(UC_ARM_REG_R4)==0xEA60 and uc.reg_read(UC_ARM_REG_R5)==1,
                    'Native constructor clock call argument/fifth-input registers differ')
            source_call=self._da_original_call(uc,CLOCK,lr)
            require(source_call['call']=='0x395528' and source_call['opcode_hex']=='bef7b8fa'
                    and self._da_opcode(uc,CLOCK,6)=='014908687047'
                    and self.stock.word(0x353AA4)==CLOCK_WORD,
                    'Original direct clock call/getter/literal differs')
            before=bytes(uc.mem_read(CLOCK_WORD,4));target=shape['clock_result_address']
            require(before.hex()==state['inputs']['before_hex'],'Clock input changed before native getter')
            row=dict(shape=shape,entry_arguments=[uc.reg_read(r) for r in REGS],entry_SP=sp,LR=lr,
                source_call=source_call,clock_before_hex=before.hex(),instructions_seen=[],
                original_return_branch_seen=False,actual_return_seen=False,result_store_seen=False,
                result_before_hex=bytes(uc.mem_read(target,4)).hex(),host_return_supplied=False,
                guest_context_restored_by_host=False)
            state['clock_reads'].append(row);state['pending']=row
            self.clock_caller_hooks.append(self.uc.hook_add(UC_HOOK_MEM_WRITE,
                self.journal_clock_result_write,begin=target,end=target+3))
        row=state['pending']
        if address in (pc for pc,_ in GETTER_OPS) and row and not row['actual_return_seen']:
            sp=self._da_actor(uc);index=len(row['instructions_seen'])
            require(index<3 and GETTER_OPS[index][0]==address and
                    self._da_opcode(uc,address)==GETTER_OPS[index][1] and
                    sp==row['entry_SP'] and lr==row['LR'],
                    'Native three-instruction clock getter sequence/SP/LR differs')
            args=[uc.reg_read(r) for r in REGS];expected=list(row['entry_arguments'])
            if index>=1:expected[1]=CLOCK_WORD
            if index>=2:expected[0]=0
            require(args==expected and self.word(CLOCK_WORD)==0,'Original clock instruction register/input effect differs')
            row['instructions_seen'].append(address)
            if index==2:row['original_return_branch_seen']=True
            if address==CLOCK:return True  # Bypass old manager frame/host+20 only; native instruction executes.
        if address==CLOCK_RETURN and constructor:
            row=state['pending'];sp=self._da_actor(uc)
            require(row and not row['actual_return_seen'] and row['original_return_branch_seen']
                    and row['instructions_seen']==[pc for pc,_ in GETTER_OPS]
                    and sp==row['entry_SP'] and lr==row['LR']
                    and [uc.reg_read(r) for r in REGS]==[0,CLOCK_WORD,row['entry_arguments'][2],row['entry_arguments'][3]]
                    and bytes(uc.mem_read(CLOCK_WORD,4)).hex()==row['clock_before_hex'],
                    'Original clock actual return/frame/register/readonly ledger differs')
            require(self._da_opcode(uc,address)=='0f90','Original clock result STRr0,[SP,#3C] differs')
            row.update(actual_return_seen=True,actual_return_SP=hex(sp),
                actual_return_arguments=[hex(uc.reg_read(r)) for r in REGS])
        if address==0x39552E and constructor and state['pending']:
            row=state['pending'];sp=self._da_actor(uc)
            require(row['actual_return_seen'] and row['result_store_seen'] and
                    sp==row['entry_SP'] and self.word(row['shape']['clock_result_address'])==0,
                    'Native clock caller result store not observed before next instruction')
            row.update(clock_prefix_complete=True);state['clock_prefix_complete']=True;state['pending']=None
        if constructor and address==0x3954CC and caller in ALLOC_RETURNS:
            sp=self._da_actor(uc,thumb=False);requested=uc.reg_read(UC_ARM_REG_R0)
            boundary=dict(entry=hex(address),native_caller=hex(caller),LR=hex(lr),SP=hex(sp),
                requested_bytes=requested,running_task=hex(self.running_task),
                original_call=self._da_original_call(uc,address,lr),original_gate_opcode=self._da_opcode(uc,address,8),
                host_allocator_return_allowed=False,admitted=False)
            state['unreviewed_allocator_boundaries'].append(boundary)
            require(state['clock_prefix_complete'] and sp==constructor['SP']-128
                    and requested==ALLOC_RETURNS[caller],'Unreviewed allocator also differs from bounded caller shape')
            require(False,'Original timer-object allocator caller requires separate native/provider scope '+hex(caller))
        if constructor and address in ALLOC_RETURNS:
            state['unreviewed_allocator_boundaries'].append(dict(entry=hex(address),kind='unreviewed actual allocation return',admitted=False))
            require(False,'Unreviewed timer-object allocation return is not admitted')
        # Old manager clock callers, native raw epilogues and every other scope remain unchanged.
        return super().observe_dispatcher_actor(uc,address,size,data)

    def snapshot_dispatcher_actor_observer(self):
        result=super().snapshot_dispatcher_actor_observer()
        result['clock_caller_observer']=json.loads(json.dumps(self.clock_caller_state))
        return result

    def verify_dispatcher_actor_observer(self):
        super().verify_dispatcher_actor_observer();state=self.clock_caller_state
        require(state['inputs'] and state['wrapper'] and state['constructor']
                and state['wrapper']['native_push_complete'] and state['constructor']['native_push_complete']
                and state['clock_prefix_complete'] and state['pending'] is None
                and len(state['clock_reads'])==1 and len(state['result_stores'])==1
                and not state['clock_write_attempts'] and not state['unreviewed_allocator_boundaries']
                and self.word(CLOCK_WORD)==0,'Native clock caller prefix or old guards incomplete')
        state['full_scoped_guards_passed']=True
        return self.snapshot_dispatcher_actor_observer()
