"""V3 exact pending native allocation entries bypass inherited fixture providers.

All frozen V2 veneer/thunk, V1 input/constructor/raw/descriptor/whole-TCB guards
run first. Only the three reviewed entry gates skip subsequent inherited
observe providers. No guest memory, register, hook table or return is supplied.
"""
from pathlib import Path
import hashlib,importlib.util,json
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_LR,UC_ARM_REG_CPSR
ROOT=Path(__file__).resolve().parents[3]
PARENT=Path(__file__).resolve().parent/'native_allocation_observer_v2.py'
PARENT_SHA='c6b9aee523f3be43234f66a422c898bb9b83e9645af83434e38fc06611b7a3f3'
if hashlib.sha256(PARENT.read_bytes()).hexdigest()!=PARENT_SHA:raise RuntimeError('Frozen V2 native allocation helper changed')
spec=importlib.util.spec_from_file_location('garmin_native_allocation_frozen_v2',PARENT)
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
require=parent.require
D=0x8804FB8
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
PROVIDER_GATES={0x2DC954:'38b5',0x388804:'70b5',0x388E92:'70b5'}
FORBIDDEN_PENDING_PROVIDER_GATES=(0x3954CC,0x3954D8,0x3954E4,0x39544C,0x2DC982,
  0x2DC9AE,0x386F04,0x386F14,0x3954F0,0x38853C,0x3887A2,0x388AF4,0x388B22)


def reject_unknown_pending_provider(entry):
    require(entry not in FORBIDDEN_PENDING_PROVIDER_GATES,
            'Pending original48/8 allocation reached an unreviewed inherited allocation/free/provider entry')


def validate_native_provider_gate(shape,entry,event):
    """Pure admission predicate; observed values, never a guest configuration."""
    require(entry in PROVIDER_GATES,'Unreviewed native allocator provider gate')
    require((shape['request'],shape['continuation'],shape['LR']) in
            [(48,0x395534,0x395535),(8,0x395544,0x395545)],
            'Native provider gate is outside original48/8 caller scope')
    require(event['actor']==event['current']==D and event['Thumb'] is True
            and event['opcode']==PROVIDER_GATES[entry] and event['PC']==entry,
            'Native provider gate actor/current/mode/opcode differs')
    require(event['pending_original_allocation'] is True and event['original_cold_recipe_verified'] is True
            and event['actual_five_thunk_instructions_seen'] is True
            and event['actual_original_tail_branch_seen'] is True
            and event['native2DC954_entry_seen'] is True and event['gate_already_seen'] is False,
            'Native provider gate lacks unique actual pending thunk/constructor provenance')
    frame=event['frame']
    require(frame['entry']==hex(entry) and frame['actual_task']==hex(D) and frame['Thumb'] is True
            and frame['SP']==event['SP'] and frame['LR']==event['LR'] and frame['arguments']==event['arguments']
            and frame['original_entry_opcode']==event['opcode'] and frame['returned'] is False
            and frame['host_context_or_return_supplied'] is False,
            'Native provider gate lacks actual original containing-function frame')
    if entry==0x2DC954:
        require(event['SP']==shape['B'] and event['LR']==shape['LR']
                and event['arguments']==[shape['request'],0,8,shape['LR']]
                and not event['lower_return_seen'] and event['native_handle'] is None
                and event['raw_operations_completed']==0,
                'Native2DC954 provider bypass entry/frame/effective arguments differ')
    else:
        require(event['lower_return_seen'] is True and event['native_handle'] is not None
                and event['query_return_seen'] is False and event['arguments'][0]==event['native_handle']
                and event['raw_operations_completed']==(2 if entry==0x388804 else 3),
                'Native query/validator lacks genuine earlier lower/raw returns')
        if entry==0x388804:
            require(event['SP']==shape['query_entry_SP'] and event['LR']==0x2DC96B,
                    'Native388804 original query caller/frame differs')
        else:
            require(event['SP']==shape['validator_entry_SP'] and event['LR']==0x38881B
                    and event['arguments'][1]==0x2DC96B and event['query_PUSH_verified'] is True,
                    'Native388E92 original validator caller/query PUSH/arguments differ')


class NativeAllocationDispatcherActorObserverMixin(parent.NativeAllocationDispatcherActorObserverMixin):
    def init_dispatcher_actor_observer(self):
        super().init_dispatcher_actor_observer()
        self.native_provider_gate_state=dict(entries=[],
          exact_provider_gates=[hex(p)for p in PROVIDER_GATES],
          inherited_hook_tables_modified=False,guest_memory_or_register_or_return_supplied=False,
          native48_8_success_verified=False,full_Dispatcher_or_foreground_verified=False)

    def observe_dispatcher_actor(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):return False
        allocation=self.native_allocation_state['pending']
        if allocation is not None:reject_unknown_pending_provider(address)
        candidate=allocation is not None and address in PROVIDER_GATES
        # This first executes every frozen V2 and V1 shape/frame/input/raw guard.
        handled=super().observe_dispatcher_actor(uc,address,size,data)
        if not candidate:return handled
        require(self.native_allocation_state['pending'] is allocation,
                'Original provider gate pending allocation changed during parent observation')
        chain=self.native_allocation_thunk_state['current'];state=self.native_provider_gate_state
        require(chain is not None and chain['shape']==allocation['shape'],
                'Original provider gate lacks same actual veneer/thunk allocation chain')
        frame=self._na_frame(address)
        require(self.native_allocation_state['frame_history'][-1] is frame,
                'Original provider gate must immediately follow exact newly captured frame')
        index=len(self.native_allocation_state['allocations'])-1
        raw=allocation['raw_operations']
        event=dict(actor=self.running_task,current=self.word(0xF09090),
          Thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32),PC=address,opcode=self._da_opcode(uc,address),
          SP=self._da_actor(uc),LR=uc.reg_read(UC_ARM_REG_LR),arguments=[uc.reg_read(r)for r in REGS],
          pending_original_allocation=True,original_cold_recipe_verified=self.native_allocation_state['cold_recipe_verified'],
          actual_five_thunk_instructions_seen=[int(r['PC'],16)for r in chain['thunk_instructions_seen']]
            ==[pc for pc,_ in parent.THUNK_INSTRUCTIONS],
          actual_original_tail_branch_seen=chain['original_tail_branch_seen'],
          native2DC954_entry_seen=chain['native2DC954_entry_seen'],
          gate_already_seen=any(e['allocation_index']==index and e['entry']==hex(address)for e in state['entries']),
          frame=dict(frame),lower_return_seen=allocation['lower_return_seen'],
          query_return_seen=allocation['query_return_seen'],native_handle=allocation['native_handle'],
          raw_operations_completed=sum(r['native_body_returned']and r['actual_caller_continuation_seen']for r in raw),
          query_PUSH_verified=self._na_frame(0x388804)['original_push_verified']if address==0x388E92 else False)
        validate_native_provider_gate(allocation['shape'],address,event)
        state['entries'].append(dict(allocation_index=index,entry=hex(address),SP=hex(event['SP']),LR=hex(event['LR']),
          actual_arguments=[hex(r)for r in event['arguments']],original_opcode=event['opcode'],
          actual_before_frame_hex=frame['actual_frame_before_hex'],actual_task=hex(D),
          raw_original_caller_returns_before_entry=event['raw_operations_completed'],
          original_instruction_executes=True,inherited_provider_skipped=True,
          guest_memory_or_register_or_return_supplied=False))
        return True  # Root skips inherited host provider; unchanged original PUSH executes.

    def verify_native_allocation_prefix(self):
        result=super().verify_native_allocation_prefix();state=self.native_provider_gate_state
        require([(r['allocation_index'],r['entry'])for r in state['entries']]
                ==[(i,hex(p))for i in range(2)for p in PROVIDER_GATES],
                'Original48/8 native provider gate histories incomplete or reordered')
        state['native48_8_success_verified']=True
        return dict(result,native_allocator_provider_gate_observer=json.loads(json.dumps(state)))

    def snapshot_dispatcher_actor_observer(self):
        result=super().snapshot_dispatcher_actor_observer()
        result['native_allocator_provider_gate_observer']=json.loads(json.dumps(self.native_provider_gate_state));return result
