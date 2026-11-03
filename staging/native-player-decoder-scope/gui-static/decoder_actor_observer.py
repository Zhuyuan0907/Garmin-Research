"""Exact Dispatcher decoder/slot observer; no guest mutation or runner.

Root maps two stock zero-range pages only when unmapped, preserves old bytes,
and retains its whole-page/TCB/FP/initialized-data journals. This class extends
the frozen manager observer without replacing native epilogue consumers.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
    UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_LR,UC_ARM_REG_SP,
    UC_ARM_REG_PC,UC_ARM_REG_CPSR)

ROOT=Path(__file__).resolve().parents[3]
PARENT=ROOT/'staging/native-player-dispatcher-native-body/gui-static/dispatcher_actor_observer.py'
PARENT_SHA='a323501d1af12aae3d4ed87822165b8ed6fea849fe767ba9ed08fdda0281ac5c'
if hashlib.sha256(PARENT.read_bytes()).hexdigest()!=PARENT_SHA:
    raise RuntimeError('Frozen a323 Dispatcher observer changed')
spec=importlib.util.spec_from_file_location('garmin_decoder_frozen_actor_parent',PARENT)
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
require=parent.require
DECODER=0x2D1654C
SLOT=0x2D1F9D0
BACKEND=SLOT+4
CALLBACKS=0x2D1FA30
FUNCTIONS=(0x39720C,0x396B3E,0x36944A,0x369438,0x3697B8,0x3697CC)
RAW={(0x3009A0,0x396B4E):(0x396B3E,24,DECODER),
     (0x3008B0,0x396BA2):(0x396B3E,24,DECODER),
     (0x3009A0,0x36945C):(0x36944A,16,BACKEND),
     (0x3008B0,0x3697CA):(0x3697B8,8,BACKEND)}

def raw_shape(entry,continuation,function_SP):
    """Pure shape helper: captured containing-function SP is an input."""
    require((entry,continuation) in RAW,'Unreviewed decoder raw pair')
    function,delta,pointer=RAW[entry,continuation]
    require(isinstance(function_SP,int) and function_SP%4==0,'Unaligned frame input')
    return dict(entry=entry,continuation=continuation,LR=continuation|1,
        function=function,entry_SP=function_SP-delta,pointer=pointer,
        operation='lock' if entry==0x3009A0 else 'unlock')

class DecoderDispatcherActorObserverMixin(parent.DispatcherActorObserverMixin):
    def init_dispatcher_actor_observer(self):
        super().init_dispatcher_actor_observer()
        require(not hasattr(self,'decoder_actor_state'),'Decoder observer initialized twice')
        self.decoder_actor_state=dict(inputs=None,zones={},hooks=[],
            frames={p:[] for p in FUNCTIONS},frame_history=[],raw_ops=[],raw_returns_pending=[],
            status_writes=[],unknown_boundaries=[],full_scoped_guards_passed=False)

    def _decoder_provenance(self,pointer,length):
        ranges=[r for r in self.stock.zeros if r['runtime_start']<=pointer
                and pointer+length<=r['runtime_end']]
        require(len(ranges)==1 and self.declared_storage(pointer,length),
                'Decoder input lacks exact original startup-zero range')
        initializers=[json.loads(json.dumps(r)) for r in self.backend_initializations
                      if int(r['pointer'],16)==pointer and r.get('original_body_executed')]
        return dict(storage=self.declared_storage(pointer,length),startup_zero_range=ranges[0],
            captured_native_initializer_rows=initializers,
            native_constructor_execution_inferred_from_zero_bytes=False,
            original_decoder_constructor=dict(entry='0x39799e',call='0x3979a2',
                continuation='0x3979a6',tag_store='0x3979aa',tag='0x3979c0',
                tag_ascii='&decoder_smphr',conditional_hardware_function='0x396d6e'))

    def capture_decoder_inputs(self):
        """Pure reads after the full cold prefix, before body/queue execution."""
        state=self.decoder_actor_state
        require(state['inputs'] is None and not self.dispatcher_body_active,
                'Capture inputs exactly once before actual body')
        rows=[]
        for pointer,n,kind in [(DECODER,24,'decoder_backend24'),
                               (SLOT,32,'slot0_record32'),(CALLBACKS,24,'callback_table24')]:
            provenance=self._decoder_provenance(pointer,n)
            require(any(lo<=pointer and pointer+n-1<=hi for lo,hi,_ in self.uc.mem_regions()),
                    'Root must declare the unmapped original-zero input page first')
            raw=bytes(self.uc.mem_read(pointer,n))
            row=dict(start=hex(pointer),bytes=n,kind=kind,before_hex=raw.hex(),stores=[],
                     input_provenance=provenance)
            state['zones'][pointer]=row;rows.append(json.loads(json.dumps(row)))
            state['hooks'].append(self.uc.hook_add(UC_HOOK_MEM_WRITE,
                self.journal_decoder_actor_write,begin=pointer,end=pointer+n-1))
        decoder=bytes.fromhex(rows[0]['before_hex']);slot=bytes.fromhex(rows[1]['before_hex'])
        state['inputs']=dict(rows=rows,decoder_words=[hex(v) for v in struct.unpack('<6I',decoder)],
            decoder_owner=hex(int.from_bytes(decoder[8:12],'little')),
            decoder_tag=hex(int.from_bytes(decoder[16:20],'little')),decoder_class=decoder[22],
            slot_words=[hex(v) for v in struct.unpack('<8I',slot)],
            slot_owner=hex(int.from_bytes(slot[12:16],'little')),
            slot_tag=hex(int.from_bytes(slot[20:24],'little')),slot_class=slot[26],
            callback_words=[hex(v) for v in struct.unpack('<6I',bytes.fromhex(rows[2]['before_hex']))],
            original_current=hex(self.word(0xF09090)),captured_running_task=hex(self.running_task),
            host_seeded_or_reset_bytes=False,native_decoder_ctor_observed=False,
            admission='Actual captured startup-zero input; not a native constructor completion claim')
        # This candidate admits this exact cold-zero input, not any initialized
        # object guessed from its tag. Unknown nonzero input remains evidence.
        require(decoder==bytes(24) and slot==bytes(32),
                'Nonzero decoder/slot input needs separately observed native initialization provenance')
        return json.loads(json.dumps(state['inputs']))

    def _decoder_frame(self,function):
        frames=self.decoder_actor_state['frames'][function]
        require(frames,'Decoder raw lacks captured containing-function entry '+hex(function))
        return frames[-1]

    def _decoder_boundary(self,address,reason):
        self.decoder_actor_state['unknown_boundaries'].append(dict(PC=hex(address),reason=reason,
            running_task=hex(self.running_task),SP=hex(self.uc.reg_read(UC_ARM_REG_SP))))
        raise RuntimeError('Decoder native boundary: '+reason)

    def journal_decoder_actor_write(self,uc,access,address,size,value,data):
        state=self.decoder_actor_state
        # Hooks start at capture, so pre-body writes are rejected as well.
        require(self.dispatcher_body_active,'Decoder input changed before actual body')
        self._da_actor(uc)
        matches=[r for p,r in state['zones'].items() if p<=address and address+size<=p+r['bytes']]
        require(len(matches)==1 and size in (1,2,4),'Decoder write crosses exact input zone')
        row=matches[0];pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)
        opcode,instruction,load=self.original_store(pc,thumb)
        value&=(1<<(8*size))-1
        if row['kind']=='callback_table24':
            self._decoder_boundary(pc,'Unreviewed original callback table writer')
        if address>=SLOT+28 and row['kind']=='slot0_record32':
            frame=self._decoder_frame(0x36944A if pc==0x36945E else 0x3697B8)
            expected=1 if pc==0x36945E else 0
            require(pc in (0x36945E,0x3697C2) and address==SLOT+28 and size==1 and value==expected
                    and (uc.reg_read(UC_ARM_REG_R4)==SLOT if pc==0x36945E else uc.reg_read(UC_ARM_REG_R0)==SLOT),
                    'Slot status writer/value/register binding differs')
            require(self.word(BACKEND+8)==self.dispatcher_task,'Slot status write lacks native Dispatcher ownership')
            state['status_writes'].append(dict(PC=hex(pc),value=value,function_entry_SP=hex(frame['SP'])))
        else:
            base=DECODER if row['kind']=='decoder_backend24' else BACKEND
            require(base<=address and address+size<=base+24 and 0x300800<=pc<0x300E00,
                    'Decoder/backend write is outside original bounded raw body')
            pending=self.task_mutex_ops[self.dispatcher_task]
            require(pending and pending[-1] in state['raw_ops'],
                    'Raw writer lacks active exact decoder/slot native pending operation')
            # A nested slot operation legitimately adjusts the still-owned
            # decoder's list links. Other backend fields require own operation.
            pointer=int(pending[-1]['pointer'],16)
            require(pointer==base or (base==DECODER and pointer==BACKEND
                    and address+size<=DECODER+8 and self.word(DECODER+8)==self.dispatcher_task),
                    'Native raw store has no own-backend or owned-list-link provenance')
        row['stores'].append(dict(PC=hex(pc),load_PC=hex(load),address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),opcode_hex=opcode.hex(),
            original_instruction=instruction,Thumb=thumb,running_task=hex(self.running_task)))

    def _decoder_begin_raw(self,uc,entry,continuation):
        state=self.decoder_actor_state;function,_,_=RAW[entry,continuation]
        reviewed=raw_shape(entry,continuation,self._decoder_frame(function)['SP'])
        sp=self._da_actor(uc);pointer=uc.reg_read(UC_ARM_REG_R0)
        require(pointer==reviewed['pointer'] and sp==reviewed['entry_SP']
                and uc.reg_read(UC_ARM_REG_LR)==reviewed['LR'],'Decoder raw pointer/SP/LR differs')
        require(self.word(pointer+16)==0 and uc.mem_read(pointer+22,1)[0]==0,
                'Captured zero-input tag/class changed outside original raw body')
        self._da_opcode(uc,entry);self._da_original_call(uc,entry,reviewed['LR'])
        if pointer not in self.native_semaphores:self.register_native_semaphore(pointer)
        require(not self.native_semaphores[pointer]['retained_condition_token'],
                'Decoder raw unexpectedly became a retained condition token')
        if reviewed['operation']=='unlock':
            require(self.word(pointer+8)==self.dispatcher_task,'Decoder unlock lacks originating native ownership')
        row=dict(original_entry=hex(entry),pointer=hex(pointer),native_caller=hex(continuation),
            operation=reviewed['operation'],scope='exact_Dispatcher_decoder_or_slot0',
            running_task=hex(self.running_task),entry_SP=hex(sp),entry_LR=hex(reviewed['LR']),
            before_words=[hex(self.word(pointer+4*n)) for n in range(6)],native_body_returned=False,
            semaphore_fields_written_by_original_only=True,host_CPU_context_restore=False,
            actual_caller_continuation_seen=False,reviewed_shape=reviewed)
        self.native_mutex_runs.append(row);self.task_mutex_ops[self.running_task].append(row)
        state['raw_ops'].append(row);state['raw_returns_pending'].append(row);self.visits[entry]+=1

    def observe_dispatcher_actor(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):return False
        state=self.decoder_actor_state
        require(state['inputs'] is not None,'Root must capture_decoder_inputs before body')
        if address in (0x396D6E,0x39799E):
            self._decoder_boundary(address,'Hardware/decoder constructor path is not admitted by cold-zero query scope')
        lr=uc.reg_read(UC_ARM_REG_LR);caller=lr&~1
        for row in list(state['raw_returns_pending']):
            if address==int(row['native_caller'],16):
                sp=self._da_actor(uc);pointer=int(row['pointer'],16)
                require(row['native_body_returned'] and row.get('original_return_branch_reached')
                        and sp==int(row['entry_SP'],16) and uc.reg_read(UC_ARM_REG_R0)==row['original_return'],
                        'Decoder native epilogue/actual caller result/SP incomplete')
                if row['operation']=='lock':
                    require(row['original_return']==0 and self.word(pointer+8)==self.dispatcher_task,
                            'Decoder lock did not acquire actual Dispatcher ownership')
                row.update(actual_caller_continuation_seen=True,actual_return_SP=hex(sp),
                           actual_return_r0=uc.reg_read(UC_ARM_REG_R0))
                state['raw_returns_pending'].remove(row)
        for function,frames in state['frames'].items():
            if frames and address==(frames[-1]['LR']&~1):
                frame=frames[-1];sp=self._da_actor(uc);result=uc.reg_read(UC_ARM_REG_R0)
                require(sp==frame['SP'],'Decoder containing-function return SP differs')
                if function==0x3697CC:require(result==8,'Original null-callback status8 return differs')
                if function==0x369438:require(result==0,'Original null-prepare-callback result differs')
                if function in (0x396B3E,0x39720C):require(result==0,'Original absent-driver query result differs')
                frame.update(returned=True,result=hex(result));frames.pop()
        if address in FUNCTIONS:
            sp=self._da_actor(uc);call=self._da_original_call(uc,address,lr)
            args=[uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
            self._da_opcode(uc,address)
            if address==0x39720C:
                require(caller==0x405394 and sp==self.dispatcher_callback_SP-40,
                        'Decoder query caller/frame differs from original405390')
            else:
                outer=self._decoder_frame(0x39720C)
                if address==0x396B3E:
                    require(caller==0x397218 and sp==outer['SP']-16 and args[:2]==[0,sp],
                            'Original decoder query arguments/caller/frame differ')
                else:
                    decoder=self._decoder_frame(0x396B3E)
                    if address==0x36944A:
                        require(caller==0x396B56 and sp==decoder['SP']-24 and args[:2]==[0,100000],
                                'Original slot0 lock helper arguments/frame differ')
                    elif address==0x3697B8:
                        require(caller==0x396B9C and sp==decoder['SP']-24 and args[0]==0,
                                'Original slot0 unlock helper arguments/frame differ')
                    elif address==0x369438:
                        slot=self._decoder_frame(0x36944A)
                        require(caller==0x369468 and sp==slot['SP']-16 and args[:2]==[100000,0],
                                'Original slot prepare arguments/frame differ')
                        if self.word(CALLBACKS+16):self._decoder_boundary(address,'Unknown nonzero original prepare callback')
                    else:
                        require(caller in (0x396B68,0x396B8C) and sp==decoder['SP']-24
                                and args==[0,1 if caller==0x396B68 else 2,0x21,sp+8]
                                and [self.word(sp),self.word(sp+4)]==[1,1 if caller==0x396B68 else 1000],
                                'Original bus query registers/stack arguments differ')
                        if self.word(CALLBACKS):self._decoder_boundary(address,'Unknown nonzero original IO callback')
            frame=dict(entry=hex(address),SP=sp,LR=lr,arguments=[hex(v) for v in args],
                       original_call=call,returned=False)
            state['frames'][address].append(frame);state['frame_history'].append(frame)
        if (address,caller) in RAW:
            self._decoder_begin_raw(uc,address,caller);return True
        # Native300A0A/30092A return False: a323 and NativeTaskMutexVM consume
        # their existing pending native epilogues exactly once.
        return super().observe_dispatcher_actor(uc,address,size,data)

    def snapshot_dispatcher_actor_observer(self):
        result=super().snapshot_dispatcher_actor_observer()
        state={k:v for k,v in self.decoder_actor_state.items() if k!='hooks'}
        result['decoder_actor_observer']=json.loads(json.dumps(state));return result

    def verify_dispatcher_actor_observer(self):
        result=super().verify_dispatcher_actor_observer()
        state=self.decoder_actor_state
        require(state['inputs'] is not None and not state['unknown_boundaries']
                and not state['raw_returns_pending'] and all(not r for r in state['frames'].values()),
                'Decoder bounded functions/returns incomplete')
        require(state['raw_ops'] and all(r['native_body_returned'] and r['actual_caller_continuation_seen']
                for r in state['raw_ops']),'Decoder raw operations incomplete')
        for start,row in state['zones'].items():
            expected=bytearray.fromhex(row['before_hex'])
            for store in row['stores']:
                offset=int(store['address'],16)-start;n=store['size']
                require(0<=offset and offset+n<=row['bytes'] and expected[offset:offset+n].hex()==store['before_hex'],
                        'Decoder chronological history missed a write')
                expected[offset:offset+n]=store['value'].to_bytes(n,'little')
            actual=bytes(self.uc.mem_read(start,row['bytes']))
            require(actual==expected,'Whole exact decoder/slot/callback zone differs')
            row.update(whole_zone_replayed=True,after_sha256=hashlib.sha256(actual).hexdigest())
        for pointer in (DECODER,BACKEND):
            require(self.word(pointer+8)==self.word(pointer+12)==0
                    and int.from_bytes(self.uc.mem_read(pointer+20,2),'little')==0,
                    'Released decoder/slot backend retains owner/waiter/depth')
        require(self.uc.mem_read(SLOT+28,1)[0]==0,'Slot status remains active')
        # Released +0/+4 links retain original historical bytes; no all-zero
        # requirement and no host clearing of those native fields.
        state['full_scoped_guards_passed']=True
        return self.snapshot_dispatcher_actor_observer()
