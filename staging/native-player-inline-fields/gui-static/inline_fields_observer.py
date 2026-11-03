"""Two exact native inline9-byte constructors; no guest mutation/execution.

Frozen parent owns every mapping/hook/page journal and all existing actor,
native epilogue, FP, GIR/font/cache/unknown-callback boundaries.
"""
from pathlib import Path
import hashlib,importlib.util,json
from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
    UC_ARM_REG_R3,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_PC)
ROOT=Path(__file__).resolve().parents[3]
PARENT=ROOT/'staging/native-player-global-subobject/gui-static/global_subobject_observer_v2.py'
PARENT_SHA='e1a25494f632d73b5154d0be6546fc1d8eed5fcee4f57fc1b7c6c20976205dd3'
if hashlib.sha256(PARENT.read_bytes()).hexdigest()!=PARENT_SHA:
    raise RuntimeError('Frozen global subobject v2 observer changed')
spec=importlib.util.spec_from_file_location('garmin_inline_fields_frozen_global_v2',PARENT)
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
require=parent.require
PAGE=0x3AAF000
BASE=0x3AAED08
VENEER=0x462FA4
LEAF=0x44F76CE
LEAF_END=0x44F76D8
LEAF_LOAD=0xE1B29A
LEAF_OPS=((0x44F76CE,'0022'),(0x44F76D0,'0260'),(0x44F76D2,'4260'),
          (0x44F76D4,'0272'),(0x44F76D6,'7047'))
CALLS={0x26DD04:(0x26DD00,BASE+0xB14),0x26DD0C:(0x26DD08,BASE+0xB20)}
STORE_SHAPES={0x44F76D0:(0,4,'0260'),0x44F76D2:(4,4,'4260'),0x44F76D4:(8,1,'0272')}
GAPS=((BASE+0xB11,3),(BASE+0xB1D,3),(BASE+0xB29,3))
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)

def inline_field_call_shape(continuation,SFS_entry_SP):
    require(continuation in CALLS,'Unreviewed original SFS inline caller')
    require(isinstance(SFS_entry_SP,int) and SFS_entry_SP>=72 and SFS_entry_SP%4==0,
            'Invalid captured SFS frame SP')
    call,target=CALLS[continuation]
    return dict(call=call,continuation=continuation,LR=continuation|1,entry_SP=SFS_entry_SP-72,
        veneer=VENEER,leaf=LEAF,leaf_load=LEAF_LOAD,target=target,bytes=9,entry_R1=0xB14)

def inline_field_store_shape(continuation,pc,SFS_entry_SP):
    call=inline_field_call_shape(continuation,SFS_entry_SP)
    require(pc in STORE_SHAPES,'Unreviewed inline field store PC')
    offset,n,opcode=STORE_SHAPES[pc]
    return dict(PC=pc,load_PC=LEAF_LOAD+pc-LEAF,Thumb=True,address=call['target']+offset,
        size=n,value=0,opcode_hex=opcode,SP=call['entry_SP'],R0=call['target'],R1=0xB14,R2=0)

def inline_field_observes_leaf(address,continuation,has_pending):
    return LEAF<=address<LEAF_END and (continuation in CALLS or has_pending)

class InlineFieldDispatcherActorObserverMixin(parent.GlobalSubobjectDispatcherActorObserverMixin):
    def init_dispatcher_actor_observer(self):
        super().init_dispatcher_actor_observer()
        require(not hasattr(self,'inline_fields_state'),'Inline field observer initialized twice')
        self.inline_fields_state=dict(inputs=None,operations=[],pending=None,stores=[],
            both_actual_returns_seen=False,full_scoped_guards_passed=False)

    def capture_dispatcher_settings_inputs(self):
        result=super().capture_dispatcher_settings_inputs();state=self.inline_fields_state
        require(state['inputs'] is None,'Inline field capture repeated')
        page=self.settings_actor_state['zones'][PAGE];regions=[];gaps=[]
        for target in (BASE+0xB14,BASE+0xB20):
            raw=bytes(self.uc.mem_read(target,9));offset=target-PAGE
            require(self.declared_storage(target,9) and raw.hex()==page['before_hex'][2*offset:2*(offset+9)],
                    'Inline field input differs from actual whole-page beforeimage')
            regions.append(dict(start=hex(target),bytes=9,before_hex=raw.hex()))
        for target,n in GAPS:
            raw=bytes(self.uc.mem_read(target,n));offset=target-PAGE
            require(raw.hex()==page['before_hex'][2*offset:2*(offset+n)],'Padding input differs from page beforeimage')
            gaps.append(dict(start=hex(target),bytes=n,before_hex=raw.hex()))
        state['inputs']=dict(fields=regions,padding=gaps,whole_page_start=hex(PAGE),
            whole_page_before_sha256=hashlib.sha256(bytes.fromhex(page['before_hex'])).hexdigest(),
            original_current=hex(self.word(0xF09090)),captured_running_task=hex(self.running_task),
            actual_mapped_bytes_reset=False,host_seeded_scalar_or_backend=False,physical_beforeRAM_proven=False)
        return dict(result,inline_fields_inputs=json.loads(json.dumps(state['inputs'])))

    def _if_opcode(self,uc,pc,n):
        load=self.stock.runtime_to_load(pc,n)
        require(load==LEAF_LOAD+pc-LEAF,'Inline original startup-copy mapping differs')
        op=self.stock.read(load,n)
        require(bytes(uc.mem_read(pc,n))==op,'Inline original copied instruction changed')
        return op

    def _if_padding(self,uc):
        for row in self.inline_fields_state['inputs']['padding']:
            require(bytes(uc.mem_read(int(row['start'],16),row['bytes'])).hex()==row['before_hex'],
                    'Original inline constructors changed excluded padding')

    def journal_settings_actor_write(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        if pc not in STORE_SHAPES:return super().journal_settings_actor_write(uc,access,address,size,value,data)
        state=self.inline_fields_state;row=state['pending']
        require(row and row['leaf_entry_seen'] and not row['actual_return_seen'],
                'Inline store lacks exact original active caller/leaf')
        index=len(row['stores']);require(index<3 and pc==list(STORE_SHAPES)[index],
                'Original inline store order/repetition differs')
        shape=inline_field_store_shape(row['continuation'],pc,row['SFS_entry_SP'])
        sp=self._da_actor(uc);opcode,instruction,load=self.original_store(pc,True)
        value&=(1<<(size*8))-1
        require((address,size,value,sp)==(shape['address'],shape['size'],0,shape['SP'])
                and opcode.hex()==shape['opcode_hex'] and load==shape['load_PC']
                and row['instructions_seen'][-1]==pc,
                'Exact original inline store tuple/SP/copy opcode differs')
        actual=[uc.reg_read(r) for r in REGS]
        require(actual==[shape['R0'],shape['R1'],0,row['entry_arguments'][3]]
                and uc.reg_read(UC_ARM_REG_LR)==row['LR'],'Inline native register binding differs')
        expected=bytearray.fromhex(row['before_hex'])
        for store in row['stores']:
            i=int(store['address'],16)-row['target'];n=store['size']
            require(expected[i:i+n].hex()==store['before_hex'],'Inline9 before/value history has a gap')
            expected[i:i+n]=store['value'].to_bytes(n,'little')
        require(bytes(uc.mem_read(row['target'],9))==expected,'Inline9 field was changed outside exact stores')
        store=dict(PC=hex(pc),load_PC=hex(load),Thumb=True,address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),opcode_hex=opcode.hex(),original_instruction=instruction,
            running_task=hex(self.running_task))
        row['stores'].append(store);state['stores'].append(store)
        self.settings_actor_state['zones'][PAGE]['stores'].append(dict(store))

    def observe_dispatcher_actor(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):return False
        state=self.inline_fields_state
        require(state['inputs'] is not None,'Root must capture inherited inline inputs before body')
        lr=uc.reg_read(UC_ARM_REG_LR);caller=lr&~1
        if address==VENEER and caller in CALLS:
            sfs=self._ss_frame(0x26DCE8);shape=inline_field_call_shape(caller,sfs['SP'])
            sp=self._da_actor(uc,thumb=False);args=[uc.reg_read(r) for r in REGS]
            require(state['pending'] is None and len(state['operations'])<2
                    and caller==list(CALLS)[len(state['operations'])]
                    and sp==shape['entry_SP'] and lr==shape['LR'] and args[:2]==[shape['target'],0xB14],
                    'Original SFS inline veneer caller/argument/SP/order differs')
            require(sfs['arguments'][0]==hex(BASE) and sfs['LR']==0x26DE5D,
                    'Inline fields lack captured original global SFS constructor provenance')
            self._da_original_call(uc,VENEER,lr);self._da_opcode(uc,VENEER,8)
            require(self.stock.word(VENEER+4)==LEAF|1,'Inline native ARM veneer target differs')
            raw=bytes(uc.mem_read(shape['target'],9));input_row=state['inputs']['fields'][len(state['operations'])]
            require(raw.hex()==input_row['before_hex'],'Inline field changed before its native constructor entry')
            row=dict(continuation=caller,LR=lr,entry_SP=sp,SFS_entry_SP=sfs['SP'],target=shape['target'],
                before_hex=raw.hex(),entry_arguments=args,reviewed_shape=shape,original_ARM_veneer_seen=True,
                leaf_entry_seen=False,instructions_seen=[],stores=[],original_return_branch_seen=False,
                actual_return_seen=False,host_return_supplied=False,guest_context_restored_by_host=False)
            state['operations'].append(row);state['pending']=row
        if inline_field_observes_leaf(address,caller,state['pending'] is not None):
            row=state['pending'];sp=self._da_actor(uc)
            require(row and row['original_ARM_veneer_seen'] and lr==row['LR'] and sp==row['entry_SP'],
                    'Copied inline leaf lacks exact native ARM veneer/frame')
            index=len(row['instructions_seen'])
            require(index<5 and address==LEAF_OPS[index][0] and self._if_opcode(uc,address,2).hex()==LEAF_OPS[index][1],
                    'Original five-instruction leaf sequence/opcode differs')
            args=[uc.reg_read(r) for r in REGS]
            require(args[0]==row['target'] and args[1]==0xB14 and args[3]==row['entry_arguments'][3],
                    'Native inline leaf clobbered original preserved arguments')
            if address==LEAF:
                require(args==row['entry_arguments'] and not row['leaf_entry_seen'],'Native inline leaf entry register preservation differs')
                self._if_opcode(uc,LEAF,10);row['leaf_entry_seen']=True
            else:require(args[2]==0,'Original MOVS r2,0 did not execute before inline stores/return')
            row['instructions_seen'].append(address)
            if address==LEAF+8:
                require(len(row['stores'])==3,'Inline BXLR reached before all three native stores')
                row['original_return_branch_seen']=True
        if address in CALLS:
            row=state['pending'];sp=self._da_actor(uc);args=[uc.reg_read(r) for r in REGS]
            require(row and row['continuation']==address and row['original_return_branch_seen']
                    and row['instructions_seen']==[pc for pc,_ in LEAF_OPS] and len(row['stores'])==3
                    and sp==row['entry_SP'] and lr==row['LR']
                    and args==[row['target'],0xB14,0,row['entry_arguments'][3]],
                    'Original inline actual caller return/SP/register ledger incomplete')
            actual=bytes(uc.mem_read(row['target'],9))
            require(actual==bytes(9),'Original inline stores did not produce their exact9-byte result')
            self._if_padding(uc)
            row.update(actual_return_seen=True,actual_return_SP=hex(sp),actual_return_arguments=[hex(v) for v in args],
                after_hex=actual.hex(),after_sha256=hashlib.sha256(actual).hexdigest())
            state['pending']=None
            if len(state['operations'])==2:state['both_actual_returns_seen']=True
        # Native code remains executable; frozen parents observe all older scopes.
        return super().observe_dispatcher_actor(uc,address,size,data)

    def snapshot_dispatcher_actor_observer(self):
        result=super().snapshot_dispatcher_actor_observer()
        result['inline_fields_observer']=json.loads(json.dumps(self.inline_fields_state))
        return result

    def verify_dispatcher_actor_observer(self):
        super().verify_dispatcher_actor_observer();state=self.inline_fields_state
        require(state['inputs'] and state['pending'] is None and len(state['operations'])==2
                and len(state['stores'])==6 and state['both_actual_returns_seen']
                and all(r['actual_return_seen'] for r in state['operations']),
                'Original inline two-call/six-store/actual-return closure incomplete')
        self._if_padding(self.uc)
        state['full_scoped_guards_passed']=True
        return self.snapshot_dispatcher_actor_observer()
