"""Narrow original Dispatcher get_smphr and its native100D default stores.

Subclass only; root owns mapping, immutable cold prefix, scheduling, FP,
whole-body/initialized-data and inherited font/GIR/cache journals. No guest
register/memory writes, native return replacement, VM invocation or mapping.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
    UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
    UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_PC,UC_ARM_REG_CPSR)
ROOT=Path(__file__).resolve().parents[3]
PARENT=ROOT/'staging/native-player-decoder-scope/gui-static/decoder_actor_observer_v2.py'
PARENT_SHA='9ac6b6d8a1139e0ff41413b0bfe0ba715b69b290c60be360629216bd266fa9a1'
if hashlib.sha256(PARENT.read_bytes()).hexdigest()!=PARENT_SHA:
    raise RuntimeError('Frozen decoder v2 observer changed')
spec=importlib.util.spec_from_file_location('garmin_settings_frozen_decoder_parent',PARENT)
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
require=parent.require
GET=0x148E6CC
TAG=0x2CBF6C
BASE=0x3AAED08
PAGE=0x3AAF000
SETTING=0x100D
FUNCTIONS=(0x40434C,0x26DCE8,0x2CAD0A,0x2CABBC)
PAIR={(0x3009A0,0x2CABFA):'lock',(0x3008B0,0x2CAC08):'unlock'}
# Five direct setup stores precede the lookup, followed by its absent-record
# default. ARM35B4F4 zeroes a different prefix in between these instructions.
DIRECT={0x26DCF6:(BASE+0xB10,1,'r1',0x10),
        0x26DD14:(BASE+0xB2C,1,'r5',0xC),
        0x26DD16:(BASE+0xB34,4,'r7',0x34),
        0x26DD1A:(BASE+0xB38,1,'r5',0x18),
        0x26DD20:(BASE+0xB39,1,'r5',0x19),
        0x26DD3C:(BASE+0xB30,4,'r7',0x30)}
REGS={'r0':UC_ARM_REG_R0,'r1':UC_ARM_REG_R1,'r2':UC_ARM_REG_R2,
      'r3':UC_ARM_REG_R3,'r4':UC_ARM_REG_R4,'r5':UC_ARM_REG_R5,
      'r6':UC_ARM_REG_R6,'r7':UC_ARM_REG_R7}

def settings_raw_shape(entry,continuation,function_SP):
    """Pure data contract; captured native2CABBC frame SP is the input."""
    require((entry,continuation) in PAIR,'Unreviewed Dispatcher settings raw pair')
    require(isinstance(function_SP,int) and function_SP%4==0,'Unaligned settings frame')
    return dict(entry=entry,continuation=continuation,LR=continuation|1,
        entry_SP=function_SP-24,pointer=GET,tag=TAG,classification_byte=0,
        operation=PAIR[entry,continuation])

class SettingsDispatcherActorObserverMixin(parent.DecoderDispatcherActorObserverMixin):
    def init_dispatcher_actor_observer(self):
        super().init_dispatcher_actor_observer()
        require(not hasattr(self,'settings_actor_state'),'Settings observer initialized twice')
        self.settings_actor_state=dict(inputs=None,zones={},hooks=[],
            frames={p:[] for p in FUNCTIONS},frame_history=[],raw_ops=[],raw_returns_pending=[],
            page_allocator=None,source_id_witness=None,lower_queries=[],lower_pending=None,
            defaults=[],default_pending=None,direct_stores=[],zero_call=None,zero_calls=[],
            unknown_boundaries=[],full_scoped_guards_passed=False)

    def _ss_frame(self,function):
        rows=self.settings_actor_state['frames'][function]
        require(rows,'Missing original settings containing function '+hex(function))
        return rows[-1]

    def _ss_boundary(self,uc,address,reason,target=None):
        mapped=target is not None and any(lo<=target and target+3<=hi for lo,hi,_ in uc.mem_regions())
        row=dict(PC=hex(address),reason=reason,running_task=hex(self.running_task),
            SP=hex(uc.reg_read(UC_ARM_REG_SP)),actual_target=hex(target) if target is not None else None,
            span_bytes=4 if target is not None else None,is_mapped=bool(mapped),
            before_hex=bytes(uc.mem_read(target,4)).hex() if mapped else None)
        self.settings_actor_state['unknown_boundaries'].append(row)
        raise RuntimeError('Dispatcher settings boundary: '+reason)

    def capture_dispatcher_settings_inputs(self):
        """Read actual whole24 and page4096 after complete cold prefix."""
        state=self.settings_actor_state
        require(state['inputs'] is None and not self.dispatcher_body_active,
                'Settings inputs must be captured once before actual body')
        require(self.running_task==self.controller==self.word(0xF09090),
                'Settings input capture lacks actual completed cold controller')
        source=self.zone_rows.get(0x148E680)
        require(source is not None,'Missing inherited whole settings BSS journal')
        init=[r for r in self.backend_initializations if int(r['pointer'],16)==GET]
        require(len(init)==1 and init[0]['native_caller']=='0x2cbd54'
                and init[0]['original_body_executed'],'Missing native get_smphr constructor provenance')
        expected=[dict(PC=hex(0x3008A2+2*i),address=hex(GET+4*i),size=4,value=0) for i in range(6)]
        require(init[0]['native_zero_writes']==expected,'Original get_smphr sixzero body differs')
        zero=[r for r in source['stores'] if r['PC'] in [hex(0x3008A2+2*i) for i in range(6)]
              and GET<=int(r['address'],16)<GET+24]
        tag=[r for r in source['stores'] if r['PC']=='0x2cbd58' and int(r['address'],16)==GET+16]
        require(len(zero)==6 and len(tag)==1 and tag[0]['value']==TAG
                and all(r['running_task']==hex(self.controller) for r in zero+tag),
                'Native controller init/tag CPU store provenance differs')
        for r in zero+tag:
            op=bytes.fromhex(r['opcode_hex'])
            require(self.stock.read(int(r['PC'],16),len(op))==op,'Native initialization opcode differs')
        raw=bytes(self.uc.mem_read(GET,24));words=list(struct.unpack('<6I',raw))
        require(words[2:]==[0,0,TAG,0],'Actual released get_smphr owner/waiter/tag/class/depth differs')
        uses=[r for r in self.native_mutex_runs if int(r['pointer'],16)==GET]
        require(uses and uses[-1]['native_body_returned'] and uses[-1]['operation']=='unlock'
                and raw==struct.pack('<6I',*[int(v,16) for v in uses[-1]['after_words']]),
                'Current whole24 differs from last original controller unlock')
        require(GET in self.native_semaphores and not self.native_semaphores[GET]['retained_condition_token'],
                'Settings getter backend has no ordinary native semaphore ledger')
        regions=[]
        for pointer,n,kind in [(GET,24,'native_settings_backend24'),(PAGE,4096,'bounded_native_SFS_page4096')]:
            provenance=[r for r in self.stock.zeros if r['runtime_start']<=pointer and pointer+n<=r['runtime_end']]
            require(len(provenance)==1 and self.declared_storage(pointer,n),
                    'Settings/page input lacks exact stock zero-range backing')
            if not any(lo<=pointer and pointer+n-1<=hi for lo,hi,_ in self.uc.mem_regions()):
                self._ss_boundary(self.uc,0,'Root must declare unmapped original-zero page before capture',pointer)
            row=dict(start=hex(pointer),bytes=n,kind=kind,
                before_hex=bytes(self.uc.mem_read(pointer,n)).hex(),stores=[],startup_zero_range=provenance[0])
            state['zones'][pointer]=row;regions.append(json.loads(json.dumps(row)))
            state['hooks'].append(self.uc.hook_add(UC_HOOK_MEM_WRITE,self.journal_settings_actor_write,
                begin=pointer,end=pointer+n-1))
        state['inputs']=dict(regions=regions,backend_words=[hex(v) for v in words],
            native_initializer=json.loads(json.dumps(init[0])),native_sixzero_CPU_stores=json.loads(json.dumps(zero)),
            native_tag_CPU_store=json.loads(json.dumps(tag[0])),last_native_controller_unlock=json.loads(json.dumps(uses[-1])),
            original_current=hex(self.word(0xF09090)),captured_running_task=hex(self.running_task),
            page_is_explicit_original_zero_range_input=True,physical_page_before_proven=False,
            actual_mapped_bytes_were_reset=False,host_seeded_backend_or_scalar=False,
            released_plus0_plus4_links_preserved=True)
        return json.loads(json.dumps(state['inputs']))

    def journal_settings_actor_write(self,uc,access,address,size,value,data):
        state=self.settings_actor_state
        require(self.dispatcher_body_active,'Settings/page input changed before actual body')
        thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32);sp=self._da_actor(uc,thumb=thumb)
        rows=[r for p,r in state['zones'].items() if p<=address and address+size<=p+r['bytes']]
        require(len(rows)==1 and size in (1,2,4),'Settings/page store crosses whole zone')
        row=rows[0];pc=uc.reg_read(UC_ARM_REG_PC);opcode,instruction,load=self.original_store(pc,thumb)
        value&=(1<<(8*size))-1
        if row['kind']=='native_settings_backend24':
            pending=self.task_mutex_ops[self.dispatcher_task]
            require(0x300800<=pc<0x300E00 and pending and pending[-1] in state['raw_ops']
                    and int(pending[-1]['pointer'],16)==GET,
                    'Settings backend store lacks exact active original native raw operation')
        elif pc in DIRECT:
            target,n,register,offset=DIRECT[pc];frame=self._ss_frame(0x26DCE8)
            require(thumb and sp==frame['SP']-72 and (address,size,value)==(target,n,0)
                    and uc.reg_read(REGS[register])+offset==target and uc.reg_read(UC_ARM_REG_R6)==0,
                    'Native settings setup/default register/address/frame/value differs')
            expected_pcs=[0x26DCF6,0x26DD14,0x26DD16,0x26DD1A,0x26DD20,0x26DD3C]
            require(len(state['direct_stores'])<len(expected_pcs)
                    and pc==expected_pcs[len(state['direct_stores'])],'Native setup/default store order differs')
            if pc==0x26DD3C:
                default=state['default_pending']
                require(default and default['native_wrapper_return']==0xFFFFFFFF
                        and default['source_setting_id']==SETTING and not default.get('store_seen')
                        and uc.reg_read(UC_ARM_REG_R0)==0xFFFFFFFF,
                        'Default store lacks actual100D absent-record return branch')
                default.update(store_seen=True,target=hex(address),before_hex=bytes(uc.mem_read(address,size)).hex())
                state['defaults'].append(default);state['default_pending']=None
            state['direct_stores'].append(dict(PC=hex(pc),address=hex(address),size=size,value=value))
        else:
            zero=state['zero_call']
            if zero is None or pc not in (0x35B50C,0x35B510,0x35B520,0x35B524,0x35B530):
                self._ss_boundary(uc,pc,'Unreviewed writer in bounded native SFS page',address)
            require(not thumb and sp==zero['entry_SP']-4 and size==4 and value==0
                    and address==PAGE+4*zero['page_zero_events'] and address+4<=BASE+0xB10,
                    'Original ARM memzero page span/order/SP/value differs')
            require(uc.reg_read(UC_ARM_REG_R2)==uc.reg_read(UC_ARM_REG_R3)==0,
                    'Original ARM memzero source registers differ')
            zero['page_zero_events']+=1
        row['stores'].append(dict(PC=hex(pc),load_PC=hex(load),Thumb=thumb,address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),opcode_hex=opcode.hex(),original_instruction=instruction,
            running_task=hex(self.running_task)))

    def _ss_begin_raw(self,uc,entry,caller):
        state=self.settings_actor_state;frame=self._ss_frame(0x2CABBC)
        reviewed=settings_raw_shape(entry,caller,frame['SP']);sp=self._da_actor(uc)
        require(uc.reg_read(UC_ARM_REG_R0)==GET and uc.reg_read(UC_ARM_REG_LR)==reviewed['LR']
                and sp==reviewed['entry_SP'] and self.word(GET+16)==TAG
                and uc.mem_read(GET+22,1)[0]==0,'Exact Dispatcher get_smphr shape differs')
        require(self.declared_storage(GET,24) and GET in self.native_semaphores
                and not self.native_semaphores[GET]['retained_condition_token'],
                'Settings backend lost original storage/native ordinary ledger')
        require(self.word(GET+8)==(0 if reviewed['operation']=='lock' else self.dispatcher_task),
                'Settings native pre-operation owner differs')
        self._da_opcode(uc,entry);self._da_original_call(uc,entry,reviewed['LR'])
        row=dict(original_entry=hex(entry),pointer=hex(GET),native_caller=hex(caller),
            operation=reviewed['operation'],scope='exact_Dispatcher_settings_get100D',running_task=hex(self.running_task),
            entry_SP=hex(sp),entry_LR=hex(reviewed['LR']),before_words=[hex(self.word(GET+4*i)) for i in range(6)],
            native_body_returned=False,actual_caller_continuation_seen=False,
            semaphore_fields_written_by_original_only=True,host_CPU_context_restore=False,reviewed_shape=reviewed)
        self.native_mutex_runs.append(row);self.task_mutex_ops[self.running_task].append(row)
        state['raw_ops'].append(row);state['raw_returns_pending'].append(row);self.visits[entry]+=1

    def observe_dispatcher_actor(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):return False
        state=self.settings_actor_state
        require(state['inputs'] is not None,'Root must capture_dispatcher_settings_inputs before body')
        lr=uc.reg_read(UC_ARM_REG_LR);caller=lr&~1
        for row in list(state['raw_returns_pending']):
            if address==int(row['native_caller'],16):
                sp=self._da_actor(uc)
                require(row['native_body_returned'] and row.get('original_return_branch_reached')
                        and sp==int(row['entry_SP'],16) and uc.reg_read(UC_ARM_REG_R0)==row['original_return'],
                        'Settings native epilogue/actual caller SP/result incomplete')
                if row['operation']=='lock':
                    require(row['original_return']==0 and self.word(GET+8)==self.dispatcher_task,
                            'Native settings lock did not acquire actualDispatcher')
                else:require(self.word(GET+8)==self.word(GET+12)==0,'Native settings unlock not released')
                row.update(actual_caller_continuation_seen=True,actual_return_SP=hex(sp),
                           actual_return_r0=uc.reg_read(UC_ARM_REG_R0));state['raw_returns_pending'].remove(row)
        for function,frames in state['frames'].items():
            if frames and address==(frames[-1]['LR']&~1):
                frame=frames[-1];sp=self._da_actor(uc);result=uc.reg_read(UC_ARM_REG_R0)
                require(sp==frame['SP'],'Native settings containing-function return SP differs')
                if function in (0x2CABBC,0x2CAD0A):
                    require(result==0xFFFFFFFF and state['lower_queries']
                            and state['lower_queries'][-1].get('actual_absent_return_seen'),
                            'Expected actual100D absent-record wrapper branch differs')
                frame.update(returned=True,result=hex(result));frames.pop()
                if function==0x2CAD0A:
                    state['default_pending']=dict(source_setting_id=SETTING,native_wrapper_return=result,
                        actual_continuation=hex(address),actual_SP=hex(sp),store_seen=False)
        if address==0x3954CC and caller==0x4053B8:
            sp=self._da_actor(uc,thumb=False)
            require(state['page_allocator'] is None and sp==self.dispatcher_callback_SP-40
                    and uc.reg_read(UC_ARM_REG_R0)==0x3F04,'Original PageMainMenu allocation request/frame differs')
            self._da_original_call(uc,address,lr);self._da_opcode(uc,address,8)
            state['page_allocator']=dict(request=0x3F04,SP=sp,LR=lr,actual_return_seen=False)
        if address==0x4053B8:
            row=state['page_allocator'];sp=self._da_actor(uc);p=uc.reg_read(UC_ARM_REG_R0)
            require(row and not row['actual_return_seen'] and sp==row['SP'] and p,
                    'Original page allocation return absent/null/different frame')
            allocation=self._da_live_raw(p,0x3F04)
            require(allocation['pointer']==hex(p),'Page pointer is not original live allocation base')
            row.update(actual_return_seen=True,pointer=p,allocation=allocation)
        if address in FUNCTIONS:
            sp=self._da_actor(uc);args=[uc.reg_read(REGS['r'+str(i)]) for i in range(4)]
            call=self._da_original_call(uc,address,lr);self._da_opcode(uc,address)
            if address==0x40434C:
                allocation=state['page_allocator']
                require(caller==0x4053C2 and sp==self.dispatcher_callback_SP-40 and allocation
                        and allocation['actual_return_seen'] and args[0]==allocation['pointer'] and args[1] in (0,1),
                        'Original MainMenu page entry/allocated object/flag differs')
            else:
                page=self._ss_frame(0x40434C)
                require(sp<page['SP']-2664,'Nested native settings frame is not inside actual MainMenu frame')
                if address==0x26DCE8:
                    require(caller==0x26DE5C and args[0]==BASE and not state['frames'][address],
                            'Original SFS constructor caller/base/reentry differs')
                elif address==0x2CAD0A:
                    sfs=self._ss_frame(0x26DCE8);w=state['source_id_witness']
                    require(caller==0x26DD38 and sp==sfs['SP']-72 and args==[SETTING,BASE+0xB30,4,sp]
                            and self.word(sp)==0 and w and w['SP']==sp,
                            'Original100D source/register/stack/caller mapping differs')
                else:
                    wrapper=self._ss_frame(0x2CAD0A)
                    require(caller==0x2CAD36 and sp==wrapper['SP']-24 and args[:2]==[SETTING,sp],
                            'Original settings getter child caller/frame/sourceID differs')
            frame=dict(entry=hex(address),SP=sp,LR=lr,arguments=[hex(v) for v in args],
                       original_call=call,returned=False)
            state['frames'][address].append(frame);state['frame_history'].append(frame)
        if address==0x35B4F4 and caller==0x26DD26:
            sp=self._da_actor(uc,thumb=False);sfs=self._ss_frame(0x26DCE8)
            require(caller==0x26DD26 and sp==sfs['SP']-72 and state['zero_call'] is None
                    and not state['zero_calls'] and [uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)]==[BASE,0xB10],
                    'Native SFS ARM memzero caller/span/frame differs')
            self._da_original_call(uc,address,lr);self._da_opcode(uc,address,4)
            state['zero_call']=dict(entry_SP=sp,LR=lr,start=BASE,bytes=0xB10,page_zero_events=0,
                original_return_seen=False,host_zeroed_memory=False)
        if address==0x26DD26:
            zero=state['zero_call'];sp=self._da_actor(uc)
            require(zero and sp==zero['entry_SP'] and zero['page_zero_events']==518
                    and uc.reg_read(UC_ARM_REG_R0)==BASE+0xB10,
                    'Original ARM memzero return/518 page stores incomplete')
            zero.update(original_return_seen=True,actual_return_SP=hex(sp));state['zero_calls'].append(zero);state['zero_call']=None
        if address==0x26DD2C:
            sp=self._da_actor(uc);sfs=self._ss_frame(0x26DCE8)
            require(sp==sfs['SP']-72 and uc.reg_read(UC_ARM_REG_R4)==BASE
                    and uc.reg_read(UC_ARM_REG_R7)==BASE+0xB00 and self.stock.word(0x26E0BC)==SETTING,
                    'Actual original settings100D source/frame/base differs')
            self._da_opcode(uc,address)
            state['source_id_witness']=dict(PC=hex(address),literal='0x26e0bc',value=SETTING,SP=sp,
                base=hex(BASE),native_mainmenu_active=True)
        if address==0x2CAB14 and caller==0x2CAC02:
            sp=self._da_actor(uc);frame=self._ss_frame(0x2CABBC)
            require(sp==frame['SP']-24 and [uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)]==[SETTING,sp]
                    and self.word(sp)==0 and self.word(GET+8)==self.dispatcher_task and state['lower_pending'] is None,
                    'Actual100D lower lookup arguments/owned backend differ')
            self._da_original_call(uc,address,lr)
            row=dict(source_setting_id=SETTING,entry_SP=sp,output=hex(sp),actual_absent_return_seen=False,
                inherited_lower_inventory_fixture_preserved=True,host_return_supplied_by_this_observer=False)
            state['lower_queries'].append(row);state['lower_pending']=row
        if address==0x2CAC02:
            row=state['lower_pending'];sp=self._da_actor(uc)
            require(row and sp==row['entry_SP'] and uc.reg_read(UC_ARM_REG_R0)==0 and self.word(sp)==0,
                    'Actual inherited100D no-record lookup result differs')
            row.update(actual_absent_return_seen=True,actual_return=0);state['lower_pending']=None
        if (address,caller) in PAIR:
            self._ss_begin_raw(uc,address,caller);return True
        # Preserve native epilogue consumers and every older strict scope.
        return super().observe_dispatcher_actor(uc,address,size,data)

    def snapshot_dispatcher_actor_observer(self):
        result=super().snapshot_dispatcher_actor_observer()
        state={k:v for k,v in self.settings_actor_state.items() if k!='hooks'}
        result['settings_actor_observer']=json.loads(json.dumps(state));return result

    def verify_dispatcher_actor_observer(self):
        super().verify_dispatcher_actor_observer()
        state=self.settings_actor_state
        require(state['inputs'] and not state['unknown_boundaries'] and not state['raw_returns_pending']
                and not state['lower_pending'] and not state['default_pending'] and not state['zero_call']
                and all(not r for r in state['frames'].values()),'Settings/native containing returns incomplete')
        require(len(state['raw_ops'])==2 and all(r['native_body_returned'] and r['actual_caller_continuation_seen']
                for r in state['raw_ops']) and len(state['defaults'])==1 and state['defaults'][0]['store_seen'],
                'Settings getter/default native operation closure incomplete')
        for start,row in state['zones'].items():
            expected=bytearray.fromhex(row['before_hex'])
            for s in row['stores']:
                p=int(s['address'],16)-start;n=s['size']
                require(expected[p:p+n].hex()==s['before_hex'],'Settings/page journal omitted an intervening write')
                expected[p:p+n]=s['value'].to_bytes(n,'little')
            actual=bytes(self.uc.mem_read(start,row['bytes']))
            require(actual==expected,'Whole settings24/page4096 differs from CPU store history')
            row.update(whole_zone_replayed=True,after_sha256=hashlib.sha256(actual).hexdigest())
        require(self.word(GET+8)==self.word(GET+12)==0 and self.word(GET+16)==TAG and self.word(GET+20)==0,
                'Final settings raw owner/waiter/tag/class/depth differs')
        state['full_scoped_guards_passed']=True
        return self.snapshot_dispatcher_actor_observer()
