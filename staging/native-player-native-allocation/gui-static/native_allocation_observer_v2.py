"""V2: exact original ARM allocator veneer -> Thumb thunk bypass.

The frozen V1 public fixture, original ctor/whole-stack journals and native
malloc/raw guards are inherited. Only the exact pending48/8 Thumb-thunk gate
skips the inherited SelectionPlayerVM host allocation hook. Guest instructions
and all unknown guards remain; this module does not instantiate or run a VM.
"""
from pathlib import Path
import hashlib,importlib.util,json
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R12,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_CPSR
ROOT=Path(__file__).resolve().parents[3]
PARENT=Path(__file__).resolve().parent/'native_allocation_observer.py'
PARENT_SHA='f072a33b6505e21aa515a02d3e668f458d5842b6c4082debdd56ac60f1c181e8'
if hashlib.sha256(PARENT.read_bytes()).hexdigest()!=PARENT_SHA:raise RuntimeError('Frozen V1 native allocation helper changed')
spec=importlib.util.spec_from_file_location('garmin_native_public_heap_frozen_v1',PARENT)
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
require=parent.require
D=0x8804FB8;FLAGS=0xF070B0;THUNK=0x2DC9EA
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
THUNK_INSTRUCTIONS=((0x2DC9EA,'3849'),(0x2DC9EC,'0822'),(0x2DC9EE,'0968'),(0x2DC9F0,'7346'),(0x2DC9F2,'afe7'))


def validate_native_thunk_shape(shape,entry_arguments,index,event):
    require(type(index)is int and 0<=index<len(THUNK_INSTRUCTIONS),'Unknown native thunk instruction')
    require(event['actor']==event['current']==D and event['Thumb'] is True
            and event['PC']==THUNK_INSTRUCTIONS[index][0] and event['opcode']==THUNK_INSTRUCTIONS[index][1],
            'Native thunk actor/current/mode/instruction order differs')
    require(event['SP']==shape['B'] and event['LR']==shape['LR'] and event['R12']==THUNK|1
            and event['flags_word']==0 and event['veneer_BX_seen'] is True,
            'Native thunk lacks actual ARM veneer target/SP/LR/initialized flag provenance')
    expected=list(entry_arguments)
    if index>=1:expected[1]=FLAGS
    if index>=2:expected[2]=8
    if index>=3:expected[1]=0
    if index>=4:expected[3]=shape['LR']
    require(event['arguments']==expected,'Original native thunk register effects differ')


class NativeAllocationDispatcherActorObserverMixin(parent.NativeAllocationDispatcherActorObserverMixin):
    def init_dispatcher_actor_observer(self):
        super().init_dispatcher_actor_observer()
        self.native_allocation_thunk_state=dict(chains=[],current=None,
          original_thunk_bypass_scope='only captured actualD395530/395540 pending allocations',
          host_allocator_hook_used_in_V2_scope=False,full_Dispatcher_or_foreground_verified=False)

    def observe_dispatcher_actor(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):return False
        state=self.native_allocation_thunk_state;lr=uc.reg_read(UC_ARM_REG_LR);caller=lr&~1
        if address==0x3954CC and caller in (0x395534,0x395544):
            require(state['current'] is None,'Original malloc veneer/thunk reentered')
            handled=super().observe_dispatcher_actor(uc,address,size,data)
            require(handled is True and self.native_allocation_state['pending'],
                    'V2 veneer admission requires existing V1 exact native pending row')
            pending=self.native_allocation_state['pending'];row=dict(shape=dict(pending['shape']),
              original_entry_arguments=list(pending['entry_arguments']),veneer_LDR_seen=True,
              veneer_BX_seen=False,thunk_instructions_seen=[],thunk_entry_bypass_seen=False,
              original_tail_branch_seen=False,native2DC954_entry_seen=False,
              actual_original_caller_return_seen=False,host_CPU_or_return_or_allocation_supplied=False)
            state['chains'].append(row);state['current']=row;return True
        row=state['current'];pending=self.native_allocation_state['pending']
        if row and address==0x3954D0:
            shape=row['shape'];sp=self._da_actor(uc,False)
            require(pending and not row['veneer_BX_seen'] and sp==shape['B'] and lr==shape['LR']
                    and uc.reg_read(UC_ARM_REG_R12)==THUNK|1
                    and [uc.reg_read(r)for r in REGS]==row['original_entry_arguments']
                    and self._da_opcode(uc,address,4)=='1cff2fe1'
                    and self.stock.word(0x3954D4)==THUNK|1,
                    'V2 actual ARM LDRtarget/BXr12/SP/LR/arguments differ')
            row.update(veneer_BX_seen=True,actual_R12=hex(uc.reg_read(UC_ARM_REG_R12)),
              original_BX_opcode='1cff2fe1',original_veneer_literal='0x2dc9eb')
        if row and address in (pc for pc,_ in THUNK_INSTRUCTIONS):
            require(pending and not row['native2DC954_entry_seen'],'Original thunk after allocation progressed or pending lost')
            index=len(row['thunk_instructions_seen']);sp=self._da_actor(uc)
            opcode=self._da_opcode(uc,address)
            validate_native_thunk_shape(row['shape'],row['original_entry_arguments'],index,
              dict(actor=self.running_task,current=self.word(0xF09090),Thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32),
                PC=address,opcode=opcode,SP=sp,LR=lr,R12=uc.reg_read(UC_ARM_REG_R12),flags_word=self.word(FLAGS),
                veneer_BX_seen=row['veneer_BX_seen'],arguments=[uc.reg_read(r)for r in REGS]))
            require(self.stock.word(0x2DCACC)==FLAGS,'Original thunk literal differs')
            row['thunk_instructions_seen'].append(dict(PC=hex(address),opcode_hex=opcode,SP=hex(sp),LR=hex(lr),
              arguments=[hex(uc.reg_read(r))for r in REGS],actual_task=hex(self.running_task),Thumb=True))
            if address==THUNK:
                row['thunk_entry_bypass_seen']=True
                return True  # Original LDR executes; only inherited host fixture gate is bypassed.
            if address==0x2DC9F2:row['original_tail_branch_seen']=True
        if row and address==0x2DC954:
            require(pending and row['thunk_entry_bypass_seen'] and row['original_tail_branch_seen']
                    and [int(r['PC'],16)for r in row['thunk_instructions_seen']]==[pc for pc,_ in THUNK_INSTRUCTIONS]
                    and self._da_actor(uc)==row['shape']['B']
                    and [uc.reg_read(r)for r in REGS]==[row['shape']['request'],0,8,row['shape']['LR']],
                    'Native2DC954 entry lacks actual original five-instruction thunk and four effective arguments')
            row['native2DC954_entry_seen']=True
        handled=super().observe_dispatcher_actor(uc,address,size,data)
        if row and address==row['shape']['continuation']:
            allocation=self.native_allocation_state['allocations'][-1]
            require(allocation['actual_original_caller_return_seen'] and row['native2DC954_entry_seen'],
                    'V2 original48/8 continuation lacks genuine lower/raw/query/prefix returns')
            row.update(actual_original_caller_return_seen=True,native_pointer=hex(allocation['native_pointer']),
              native_handle=hex(allocation['native_handle']),actual_original_return_SP=allocation['actual_original_return_SP'])
            state['current']=None
        return handled

    def verify_native_allocation_prefix(self):
        result=super().verify_native_allocation_prefix();state=self.native_allocation_thunk_state
        require(len(state['chains'])==2 and state['current'] is None
                and all(r['actual_original_caller_return_seen'] and r['native2DC954_entry_seen']
                  and r['thunk_entry_bypass_seen'] and r['original_tail_branch_seen']for r in state['chains']),
                'V2 exact original allocator thunk/return scopes incomplete')
        return dict(result,native_allocator_thunk_observer=json.loads(json.dumps(state)))

    def snapshot_dispatcher_actor_observer(self):
        result=super().snapshot_dispatcher_actor_observer()
        result['native_allocator_thunk_observer']=json.loads(json.dumps(self.native_allocation_thunk_state));return result
