"""Exact original global3AAF844 constructor observer; no guest mutations.

The frozen settings observer owns the page hook and all older raw/native
epilogues. This subclass admits three stores and original frame/once witnesses.
The following container/allocator path remains outside this admission.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct
from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
    UC_ARM_REG_R4,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_PC,UC_ARM_REG_CPSR)
ROOT=Path(__file__).resolve().parents[3]
PARENT=ROOT/'staging/native-player-settings-scope/gui-static/settings_actor_observer.py'
PARENT_SHA='009cee2eee03684a2a95a70d92cada3e9dba94795bfc4a0270dc74262bd32513'
if hashlib.sha256(PARENT.read_bytes()).hexdigest()!=PARENT_SHA:
    raise RuntimeError('Frozen settings observer changed')
spec=importlib.util.spec_from_file_location('garmin_global_subobject_frozen_settings',PARENT)
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
require=parent.require
OBJECT=0x3AAF844
PAGE=0x3AAF000
SFS=0x3AAED08
OUTER_ONCE=0xF701FC
INNER_ONCE=0xF701F8
FRAMES={0x114612:(0x1152D2,24),0x11EAB2:(0x114630,80),0x26DE3C:(0x11EABA,8)}
STORES={0x26DE42:(OBJECT,0xC035F8,'r4','r0','2060'),
        0x26DE6C:(OBJECT+4,SFS,'r4','r0','6060'),
        0x11EABE:(OBJECT,0xC12D50,'r0','r1','0160')}
REGS={'r0':UC_ARM_REG_R0,'r1':UC_ARM_REG_R1,'r4':UC_ARM_REG_R4}

def global_subobject_frame_shape(function,continuation,function_SP):
    """Pure data shape; the native function entry SP must be captured."""
    require(function in FRAMES and continuation==FRAMES[function][0],
            'Unreviewed global subobject containing-function/caller')
    require(isinstance(function_SP,int) and function_SP>=80 and function_SP%4==0,
            'Invalid native global subobject frame input')
    return dict(function=function,continuation=continuation,LR=continuation|1,
        entry_SP=function_SP,body_SP=function_SP-FRAMES[function][1],object=OBJECT)

def global_subobject_store_shape(pc,base_SP,derived_SP):
    require(pc in STORES,'Unreviewed global object writer')
    require(all(isinstance(v,int) and v>=80 and v%4==0 for v in [base_SP,derived_SP]),
            'Invalid captured global constructor frame input')
    target,value,destination,source,opcode=STORES[pc]
    return dict(PC=pc,address=target,size=4,value=value,Thumb=True,
        SP=derived_SP-80 if pc==0x11EABE else base_SP-8,
        destination_register=destination,source_register=source,opcode_hex=opcode)

class GlobalSubobjectDispatcherActorObserverMixin(parent.SettingsDispatcherActorObserverMixin):
    def init_dispatcher_actor_observer(self):
        super().init_dispatcher_actor_observer()
        require(not hasattr(self,'global_subobject_state'),'Global observer initialized twice')
        self.global_subobject_state=dict(inputs=None,frames={p:[] for p in FRAMES},
            frame_history=[],stores=[],once_calls=[],once_pending=None,
            SFS_native_return=None,base_native_return=None,derived_native_return=None,
            three_store_prefix_complete=False,full_scoped_guards_passed=False,
            container_scope_admitted=False)

    def capture_dispatcher_settings_inputs(self):
        result=super().capture_dispatcher_settings_inputs()
        state=self.global_subobject_state
        require(state['inputs'] is None,'Global input capture repeated')
        page=self.settings_actor_state['zones'][PAGE]
        actual=bytes(self.uc.mem_read(OBJECT,8));offset=OBJECT-PAGE
        require(actual.hex()==page['before_hex'][offset*2:(offset+8)*2]
                and self.declared_storage(OBJECT,8),'Global object differs from actual whole-page beforeimage')
        provenance=[r for r in self.stock.zeros if r['runtime_start']<=OBJECT and OBJECT+8<=r['runtime_end']]
        require(len(provenance)==1,'Global object lacks exact original startup-zero provenance')
        flags={hex(p):self.word(p) for p in (OUTER_ONCE,INNER_ONCE)}
        require(all(v==0 for v in flags.values()),
                'This fresh-cold global constructor scope requires captured original once flags0')
        state['inputs']=dict(start=hex(OBJECT),bytes=8,before_hex=actual.hex(),
            whole_page_start=hex(PAGE),whole_page_before_sha256=hashlib.sha256(bytes.fromhex(page['before_hex'])).hexdigest(),
            startup_zero_provenance=provenance[0],captured_once_words=flags,
            captured_current=hex(self.word(0xF09090)),captured_running_task=hex(self.running_task),
            original_global_literal=dict(PC='0x11462a',literal='0x114688',value='0x3aaf844'),
            host_seeded_or_reset=False,physical_beforeRAM_proven=False,
            storage_is_MainMenu_heap_subobject=False,storage_is_old551C804=False)
        return dict(result,global_subobject_inputs=json.loads(json.dumps(state['inputs'])))

    def _gs_frame(self,function):
        rows=self.global_subobject_state['frames'][function]
        require(rows,'Missing captured global containing-function '+hex(function))
        return rows[-1]

    def _gs_expected_object(self):
        state=self.global_subobject_state;expected=bytearray.fromhex(state['inputs']['before_hex'])
        for row in state['stores']:
            low=int(row['address'],16)-OBJECT
            require(expected[low:low+4].hex()==row['before_hex'], 'Global before/value journal has a gap')
            expected[low:low+4]=row['value'].to_bytes(4,'little')
        return bytes(expected)

    def journal_settings_actor_write(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        if pc not in STORES:return super().journal_settings_actor_write(uc,access,address,size,value,data)
        state=self.global_subobject_state
        require(state['inputs'] is not None and len(state['stores'])<3,
                'Global exact writer lacks input or reused object sequence')
        require(pc==[0x26DE42,0x26DE6C,0x11EABE][len(state['stores'])],
                'Global base/derived store order differs')
        base=self._gs_frame(0x26DE3C) if pc!=0x11EABE else state['base_native_return']
        derived=self._gs_frame(0x11EAB2)
        require(base is not None,'Derived vtable writer lacks actual native base return')
        shape=global_subobject_store_shape(pc,base['SP'],derived['SP'])
        sp=self._da_actor(uc);opcode,instruction,load=self.original_store(pc,True)
        value&=0xFFFFFFFF
        require((address,size,value,sp)==(shape['address'],4,shape['value'],shape['SP'])
                and opcode.hex()==shape['opcode_hex'] and load==pc,
                'Exact global original store tuple/SP/opcode differs')
        require(uc.reg_read(REGS[shape['destination_register']])==OBJECT
                and uc.reg_read(REGS[shape['source_register']])==value,
                'Global native source/destination register binding differs')
        require(bytes(uc.mem_read(OBJECT,8))==self._gs_expected_object(),
                'Global object contains an unjournaled intervening write')
        if pc==0x26DE42:
            require(self.word(OUTER_ONCE)==1 and derived['original_outer_once_call_completed'],
                    'Global base initialization lacks original outer once transition')
        elif pc==0x26DE6C:
            returned=state['SFS_native_return']
            require(returned and returned['actual_return_r0']==SFS and
                    not self.settings_actor_state['frames'][0x26DCE8] and self.word(INNER_ONCE)==1,
                    'Global base pointer store precedes actual native SFS return/once transition')
        else:
            require(state['base_native_return'] and state['base_native_return']['returned']
                    and state['base_native_return']['actual_return_r0']==OBJECT,
                    'Derived vtable store precedes actual original base return')
        row=dict(PC=hex(pc),load_PC=hex(load),Thumb=True,address=hex(address),size=4,value=value,
            before_hex=bytes(uc.mem_read(address,4)).hex(),opcode_hex=opcode.hex(),original_instruction=instruction,
            running_task=hex(self.running_task))
        state['stores'].append(row)
        self.settings_actor_state['zones'][PAGE]['stores'].append(dict(row))
        if len(state['stores'])==3:state['three_store_prefix_complete']=True

    def observe_dispatcher_actor(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):return False
        state=self.global_subobject_state
        require(state['inputs'] is not None,'Root must capture inherited settings/global inputs before body')
        lr=uc.reg_read(UC_ARM_REG_LR);caller=lr&~1
        for function,rows in state['frames'].items():
            if rows and address==(rows[-1]['LR']&~1):
                frame=rows[-1];sp=self._da_actor(uc);result=uc.reg_read(UC_ARM_REG_R0)
                require(sp==frame['SP'],'Original global containing-function return SP differs')
                if function in (0x26DE3C,0x11EAB2):require(result==OBJECT,'Native global constructor returned a different object')
                if function==0x26DE3C:
                    require(len(state['stores'])==2 and state['SFS_native_return'] and not state['once_pending'],
                            'Original global base return lacks two native stores/SFS/once closure')
                if function==0x11EAB2:require(state['three_store_prefix_complete'],'Original derived return precedes three exact stores')
                frame.update(returned=True,actual_return_SP=hex(sp),actual_return_r0=result)
                rows.pop()
                if function==0x26DE3C:state['base_native_return']=frame
                if function==0x11EAB2:state['derived_native_return']=frame
        if address in FRAMES:
            sp=self._da_actor(uc);shape=global_subobject_frame_shape(address,caller,sp)
            require(not state['frames'][address],'Global containing function reentered')
            self._da_opcode(uc,address);original_call=self._da_original_call(uc,address,lr)
            args=[uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
            if address==0x114612:
                page=self._ss_frame(0x40434C)
                require(sp<page['SP']-2664 and self.word(OUTER_ONCE)==0,
                        'Native global getter lacks live MainMenu/fresh actual once input')
                property_input=self._da_live_raw(args[1],4)
                extra=dict(actual_property_argument=hex(args[1]),live_property_input_allocation=property_input,
                    original_outer_once_before=self.word(OUTER_ONCE))
            elif address==0x11EAB2:
                outer=self._gs_frame(0x114612)
                require(sp==outer['SP']-24 and args[0]==OBJECT and self.word(OUTER_ONCE)==1
                        and state['once_calls'] and state['once_calls'][-1]['pointer']==hex(OUTER_ONCE)
                        and state['once_calls'][-1].get('actual_return_seen'),
                        'Derived global ctor lacks exact native getter object/once/frame provenance')
                require(self.stock.word(0x114688)==OBJECT,'Native global object literal differs')
                extra=dict(original_outer_once_call_completed=True,whole8_before_hex=bytes(uc.mem_read(OBJECT,8)).hex())
                require(extra['whole8_before_hex']==state['inputs']['before_hex'],'Global input changed before native ctor')
            else:
                derived=self._gs_frame(0x11EAB2)
                require(sp==derived['SP']-80 and args[0]==OBJECT and self.word(INNER_ONCE)==0,
                        'Native global base ctor object/frame/inner once differs')
                extra=dict(original_inner_once_before=self.word(INNER_ONCE))
            frame=dict(entry=hex(address),SP=sp,LR=lr,shape=shape,arguments=[hex(v) for v in args],
                original_call=original_call,returned=False,**extra)
            state['frames'][address].append(frame);state['frame_history'].append(frame)
        if address==0x385448 and caller in (0x114626,0x26DE52):
            function,pointer=(0x114612,OUTER_ONCE) if caller==0x114626 else (0x26DE3C,INNER_ONCE)
            frame=self._gs_frame(function);sp=self._da_actor(uc)
            require(sp==frame['shape']['body_SP'] and uc.reg_read(UC_ARM_REG_R0)==pointer
                    and self.word(pointer)==0 and state['once_pending'] is None,
                    'Global native once input/frame differs')
            call=self._da_original_call(uc,address,lr);self._da_opcode(uc,address)
            row=dict(pointer=hex(pointer),native_caller=hex(caller),function=hex(function),entry_SP=sp,
                actual_before_word=0,original_call=call,actual_return_seen=False)
            state['once_calls'].append(row);state['once_pending']=row
        if address in (0x114626,0x26DE52):
            row=state['once_pending'];sp=self._da_actor(uc)
            require(row and int(row['native_caller'],16)==address and sp==row['entry_SP']
                    and uc.reg_read(UC_ARM_REG_R0)==1 and self.word(int(row['pointer'],16))==1,
                    'Original native once did not return/transition0 to1')
            writes=[w for w in self.mutable_cpu_stores if w['PC']=='0x385450'
                    and w['address']==row['pointer'] and w['running_task']==hex(self.dispatcher_task)]
            require(len(writes)==1 and writes[0]['before_hex']=='00000000'
                    and writes[0]['size']==4 and writes[0]['value']==1,
                    'Global native once lacks original whole-bank CPU store evidence')
            row.update(actual_return_seen=True,actual_return_SP=hex(sp),actual_return_r0=1,
                original_CPU_store=json.loads(json.dumps(writes[0])))
            state['once_pending']=None
        if address==0x26DE5C:
            base=self._gs_frame(0x26DE3C);sfs=self._ss_frame(0x26DCE8);sp=self._da_actor(uc)
            require(sp==base['SP']-8==sfs['SP'] and uc.reg_read(UC_ARM_REG_R0)==SFS,
                    'Original global base nested SFS did not return with actual object/frame')
            state['SFS_native_return']=dict(actual_continuation=hex(address),actual_return_SP=hex(sp),
                actual_return_r0=SFS,containing_entry_SP=hex(sfs['SP']),original_native_return=True)
        # Never bypass settings/decoder/native epilogue or unknown-page consumers.
        return super().observe_dispatcher_actor(uc,address,size,data)

    def snapshot_dispatcher_actor_observer(self):
        result=super().snapshot_dispatcher_actor_observer()
        result['global_subobject_observer']=json.loads(json.dumps(self.global_subobject_state))
        return result

    def verify_dispatcher_actor_observer(self):
        super().verify_dispatcher_actor_observer()
        state=self.global_subobject_state
        require(state['inputs'] and state['three_store_prefix_complete'] and len(state['stores'])==3
                and all(not rows for rows in state['frames'].values()) and not state['once_pending']
                and len(state['once_calls'])==2 and all(r['actual_return_seen'] for r in state['once_calls'])
                and state['base_native_return'] and state['derived_native_return'],
                'Global original frame/once/three-store closure incomplete')
        actual=bytes(self.uc.mem_read(OBJECT,8));require(actual==self._gs_expected_object(),
                'Whole global base8 differs from its exact original store history')
        state.update(whole8_replayed=True,after_sha256=hashlib.sha256(actual).hexdigest(),
            full_scoped_guards_passed=True)
        return self.snapshot_dispatcher_actor_observer()
