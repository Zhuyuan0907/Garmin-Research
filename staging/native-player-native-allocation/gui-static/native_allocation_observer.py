"""New public-extent fixture initialization and exact Dispatcher native malloc.

Only original CPU instructions initialize the WORK/free bins/descriptors and
return allocations. Input bytes describe guarded fixture extents, not physical
Garmin RAM. No VM is instantiated or executed by this module.
"""
from pathlib import Path
import hashlib,importlib.util,json,re,struct
from unicorn import UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_WRITE
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[3]
BASE=Path(__file__).resolve().parent
PARENT=ROOT/'staging/native-player-clock-caller/gui-static/clock_caller_observer_v2.py'
PARENT_SHA='1a3253998dbdee390aa99fadf53e9c2bdc1de806b417d7e3258372ad7780a0b1'
OPCODES=BASE/'native-heap-original-opcodes.json'
OPCODES_SHA='04af8ff13024ec9028858fdfa0c31d9985d4a93d5f41899e0d1196250a9165da'
CONFIG=BASE/'native-public-heap-input-config.json'
CONFIG_SHA='2d895f58547a43804957dbe11947ee44d49da1528c56b04bcc04bdeaafd55ad9'
for p,h in [(PARENT,PARENT_SHA),(OPCODES,OPCODES_SHA),(CONFIG,CONFIG_SHA)]:
    if hashlib.sha256(p.read_bytes()).hexdigest()!=h:raise RuntimeError('Frozen native allocation dependency changed '+str(p))
spec=importlib.util.spec_from_file_location('garmin_native_heap_frozen_clock',PARENT)
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
require=parent.require
WORK=0x3A7F170;BACKEND=WORK+28;PRIVATE=0x18301000;PRIVATE_BYTES=8192
PUBLIC=0x18305000;PUBLIC_BYTES=16384;ENVELOPE=0x18304000;ENVELOPE_BYTES=24576
DESC_PAGE=0x1830B000;DESC=DESC_PAGE+32;D=0x8804FB8;RETURN=0x10000
ARGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
REGISTER={'r'+str(i):globals()['UC_ARM_REG_R'+str(i)]for i in range(13)}
REGISTER.update(sp=UC_ARM_REG_SP,lr=UC_ARM_REG_LR,ip=UC_ARM_REG_R12,sb=UC_ARM_REG_R9,sl=UC_ARM_REG_R10,fp=UC_ARM_REG_R11)
RAW={(0x3009A0,0x38851C):(0x38850A,24,'lock'),(0x3008B0,0x388534):(0x38850A,24,'unlock'),
     (0x3009A0,0x388812):(0x388804,16,'lock'),(0x3008B0,0x388826):(0x388804,16,'unlock')}
FRAME_SIZES={0x388B6C:(36,20),0x388DF2:(8,0),0x38806C:(8,0),0x3880BC:(24,0),
  0x21210C:(0,0),0x35B4F4:(4,0),0x2DC954:(16,0),0x38850A:(24,0),
  0x3881BC:(36,20),0x388804:(16,0),0x388E92:(16,0)}


def native_public_heap_recipe():
    """Host expected bytes only; the return value must never be guest-written."""
    private=bytearray(bytes(4096)+b'\xcc'*4096)
    def put(o,v):struct.pack_into('<I',private,o,v)
    put(0,27);put(0x78,PRIVATE+0x7C);put(4096,0);put(4100,0)
    previous=0
    for i in range(170):
        node=PRIVATE+4096+24*i;put(node-PRIVATE+4,0);put(node-PRIVATE+20,previous);previous=node
    start=PRIVATE+4096+169*24;end=start-24;remaining=end-24
    slot=PRIVATE+0x7C+10*32*4
    for o,v in [(0,0),(4,PUBLIC|1),(8,end),(16,slot|1),(20,0)]:put(start-PRIVATE+o,v)
    for o,v in [(0,start),(4,(PUBLIC+PUBLIC_BYTES)|2),(8,0)]:put(end-PRIVATE+o,v)
    put(4,1<<10);put(8+10*4,1);put(slot-PRIVATE,start)
    work=bytearray(96)
    for o,v in [(0xC,remaining),(0x10,start),(0x14,end),(0x18,PRIVATE),(0x2C,0x388D00),
                (0x50,PRIVATE_BYTES),(0x54,8192),(0x58,8192)]:struct.pack_into('<I',work,o,v)
    return dict(private=bytes(private),workspace=bytes(work),start=start,end=end,remaining=remaining,
                bin_slot=slot,public=bytes(b'\xcc'*PUBLIC_BYTES))


def allocation_shape(body_SP,request,continuation):
    require(type(body_SP)is int and body_SP%4==0 and body_SP>=128,'Native allocation body SP invalid')
    require((request,continuation)in [(48,0x395534),(8,0x395544)],'Only original48/8 callers admitted')
    return dict(B=body_SP,request=request,continuation=continuation,LR=continuation|1,
                output_cell=body_SP-16,malloc_entry_SP=body_SP-16,malloc_body_SP=body_SP-40,
                core_entry_SP=body_SP-40,core_body_SP=body_SP-96,
                query_entry_SP=body_SP-16,query_body_SP=body_SP-32,validator_entry_SP=body_SP-32,
                lower_request=request+8,flags=0,alignment=8,backend=BACKEND,tag=0x388D00)


def check_allocation_raw(shape,function_entry_SP,event):
    key=event['entry'],event['continuation'];require(key in RAW,'Unknown allocator raw pair')
    f,push,operation=RAW[key]
    require(event['task']==event['current']==D and event['Thumb'] is True,
            'Allocator raw actualD/current/mode differs')
    require(event['pointer']==BACKEND and event['SP']==function_entry_SP-push
            and event['LR']==event['continuation']|1 and event['tag']==0x388D00 and event['class']==0,
            'Allocator raw pointer/frame/tag/class differs')
    require(event['SP']==(shape['malloc_body_SP']if f==0x38850A else shape['query_body_SP']),
            'Allocator raw relative native frame differs')
    return operation


class NativeAllocationDispatcherActorObserverMixin(parent.ClockCallerDispatcherActorObserverMixin):
    def init_dispatcher_actor_observer(self):
        super().init_dispatcher_actor_observer()
        require(not hasattr(self,'native_allocation_state'),'Native allocation observer repeated')
        self.native_allocation_state=dict(prepared=False,cold_frame=None,cold_init_returned=False,
          frames={p:[]for p in FRAME_SIZES},frame_history=[],cold_recipe_verified=False,
          heap_writes=[],TCB_writes=[],raw_ops=[],raw_returns_pending=[],allocations=[],pending=None,
          inputs_after_cold=None,constructor_stack=None,two_native_allocations_returned=False,payload_setup_stores=[],next_boundary=None,
          whole_allocation_prefix_verified=False,full_dispatcher_body_or_foreground_verified=False)
        self._na_tables=json.loads(OPCODES.read_text());self._na_hooks=[];self._na_constructor_push=None
        for low,n in [(WORK,96),(PRIVATE,PRIVATE_BYTES)]:
            self._na_hooks.append(self.uc.hook_add(UC_HOOK_MEM_WRITE,self.journal_native_heap_write,begin=low,end=low+n-1))

    def prepare_native_public_heap_input(self):
        state=self.native_allocation_state
        require(not state['prepared'] and not self.zone_active and not self.dispatcher_body_active,
                'Public heap input must precede original constructor and zone baselines')
        require(self.kernel_active and self.running_task==self.controller==self.word(0xF09090)
                and bytes(self.uc.mem_read(WORK,96))==bytes(96),
                'Refusing warm/repeated/public heap initialization or unobserved WORK state')
        require(bytes(self.uc.mem_read(PRIVATE,PRIVATE_BYTES))==b'\xcc'*PRIVATE_BYTES,
                'Original private fixture has been consumed before new public input')
        ranges=[(ENVELOPE,ENVELOPE_BYTES),(DESC_PAGE,4096)]
        existing=list(self.uc.mem_regions())
        for low,n in ranges:
            require(low%4096==0 and n%4096==0 and low+n<=2**32
                    and not any(lo<low+n and low<=hi for lo,hi,_ in existing),
                    'New public fixture mapping overlaps an existing zone')
            require(not any(low<PRIVATE+PRIVATE_BYTES+4096 and PRIVATE-4096<low+n for _ in [0]),
                    'New public fixture overlaps old private guarded envelope')
        require(PUBLIC%4096==PUBLIC_BYTES%4096==0 and PUBLIC+PUBLIC_BYTES==ENVELOPE+ENVELOPE_BYTES-4096,
                'Public extent alignment/guarded envelope differs')
        for low,n in ranges:self.uc.mem_map(low,n,UC_PROT_READ|UC_PROT_WRITE)
        self.uc.mem_write(ENVELOPE,b'\xa5'*ENVELOPE_BYTES)
        self.uc.mem_write(PUBLIC,b'\xcc'*PUBLIC_BYTES)
        self.uc.mem_write(DESC_PAGE,b'\xa5'*4096)
        self.uc.mem_write(DESC,struct.pack('<2I',PUBLIC,PUBLIC_BYTES))
        self.synthetic_heap_ranges.extend([(PUBLIC,PUBLIC+PUBLIC_BYTES),(DESC,DESC+8)])
        self.zones[ENVELOPE]=ENVELOPE_BYTES;self.zones[DESC_PAGE]=4096
        for low,n in ranges:
            self._na_hooks.append(self.uc.hook_add(UC_HOOK_MEM_WRITE,self.journal_native_heap_write,begin=low,end=low+n-1))
        meta=self.word(self.controller+28);pool=self.word(meta+8)
        require(pool==0x09500000 and self.controller==pool+0x3F90 and self.declared_storage(pool,16384),
                'Native public initializer controller whole-stack metadata/backing differs')
        state['constructor_stack_pool']=pool
        self._na_hooks.append(self.uc.hook_add(UC_HOOK_MEM_WRITE,self.journal_native_heap_constructor_stack,
          begin=pool,end=pool+16384-1))
        state.update(prepared=True,input=dict(fixture_only=True,physical_heap_available_verified=False,
          private_extent=[hex(PRIVATE),PRIVATE_BYTES],public_extent=[hex(PUBLIC),PUBLIC_BYTES],
          descriptor=hex(DESC),input_descriptor_hex=bytes(self.uc.mem_read(DESC,8)).hex(),
          guarded_public_before_hex=bytes(self.uc.mem_read(ENVELOPE,ENVELOPE_BYTES)).hex(),
          descriptor_page_before_hex=bytes(self.uc.mem_read(DESC_PAGE,4096)).hex(),
          original_WORK96_actual_before_hex=bytes(self.uc.mem_read(WORK,96)).hex(),
          new_input_regions=[[hex(low),n]for low,n in ranges],guest_bins_or_descriptors_seeded=False))
        return json.loads(json.dumps(state['input']))

    def native_heap_init_arguments(self,private_descriptor):
        s=self.native_allocation_state
        require(s['prepared'] and s['cold_frame'] is None and self.zone_active and self.phase=='heap_ctor',
                'Native public arguments outside first journaled heap call')
        require(bytes(self.uc.mem_read(private_descriptor,8))==struct.pack('<2I',PRIVATE,PRIVATE_BYTES)
                and bytes(self.uc.mem_read(DESC,8))==struct.pack('<2I',PUBLIC,PUBLIC_BYTES),
                'Native primary/public array inputs differ')
        s['private_descriptor']=private_descriptor
        return private_descriptor,1,DESC,1

    def _na_opcode(self,uc,address,thumb):
        load=self.stock.runtime_to_load(address,4)if any(r['runtime_start']<=address and address+4<=r['runtime_end']for r in self.stock.copies)else address
        raw=self.stock.read(load,4);rows=list(self.store_disassemblers[thumb].disasm(raw,address,count=1))
        require(len(rows)==1 and bytes(uc.mem_read(address,rows[0].size))==raw[:rows[0].size],
                'Original native heap instruction changed')
        i=rows[0];return raw[:i.size],i.mnemonic+' '+i.op_str

    def _na_task(self,uc,body,thumb=True):
        if body:return self._da_actor(uc,thumb)
        require(self.running_task==self.controller==self.word(0xF09090)
                and self.controller in self.native_TCBs and self.pending_restore is None,
                'Native public initializer actor/current/restore differs')
        require(bool(uc.reg_read(UC_ARM_REG_CPSR)&32)==thumb,'Native cold heap boundary mode differs')
        sp=uc.reg_read(UC_ARM_REG_SP)
        require(sp%4==0 and sp<=self.controller and self.declared_storage(sp,self.controller-sp),
                'Native public initializer actual stack backing differs')
        return sp

    def _na_frame(self,function):
        frames=self.native_allocation_state['frames'][function]
        require(frames,'Missing exact original native allocation frame '+hex(function));return frames[-1]

    def _na_new_frame(self,uc,function,body):
        s=self.native_allocation_state;thumb=function not in (0x21210C,0x35B4F4)
        sp=self._na_task(uc,body,thumb);lr=uc.reg_read(UC_ARM_REG_LR);push,local=FRAME_SIZES[function]
        require(self.declared_storage(sp-push-local,push+local) if push+local else True,
                'Original allocator frame has no declared native stack')
        op,ins=self._na_opcode(uc,function,thumb)
        row=dict(entry=hex(function),SP=sp,LR=lr,arguments=[uc.reg_read(r)for r in ARGS],
          Thumb=thumb,push_bytes=push,local_bytes=local,body_SP=sp-push-local,
          actual_frame_before_hex=bytes(uc.mem_read(sp-push-local,push+local)).hex(),
          original_entry_opcode=op.hex(),original_entry_instruction=ins,
          actual_task=hex(self.running_task),returned=False,epilogue_return_branch_seen=False,
          host_context_or_return_supplied=False)
        if function not in (0x388B6C,0x2DC954):row['original_source_call']=self._da_original_call(uc,function,lr)
        if function==0x2DC954:
            require(self._da_opcode(uc,0x2DC9F2)=='afe7','Original thunk tail branch changed')
            row['tail_branch_source']={'PC':'0x2dc9f2','opcode_hex':'afe7','target':'0x2dc954'}
        if push:
            reglists={0x388B6C:('r0','r1','r2','r3','r4','r5','r6','r7','lr'),
              0x388DF2:('r4','lr'),0x38806C:('r4','lr'),0x3880BC:('r3','r4','r5','r6','r7','lr'),
              0x35B4F4:('lr',),0x2DC954:('r3','r4','r5','lr'),
              0x38850A:('r3','r4','r5','r6','r7','lr'),
              0x3881BC:('r0','r1','r2','r3','r4','r5','r6','r7','lr'),
              0x388804:('r4','r5','r6','lr'),0x388E92:('r4','r5','r6','lr')}
            journals=self.body_zones if body else {s['constructor_stack_pool']:s['constructor_stack']}
            zones=[z for lo,z in journals.items()if lo<=sp-push and sp<=lo+z['bytes']]
            require(len(zones)==1,'Native allocator PUSH lacks one whole current-actor stack journal')
            row.update(push_values=[uc.reg_read(REGISTER[r])for r in reglists[function]],
              push_writer=hex(function+4 if function==0x35B4F4 else function),
              journal_start=zones[0]['start'],journal_event_index=len(zones[0]['stores']),
              original_push_verified=False,whole_stack_journal_actor='body'if body else'cold')
        else:row['original_push_verified']=True
        s['frames'][function].append(row);s['frame_history'].append(row);return row

    def _na_verify_pushes(self,uc,body):
        s=self.native_allocation_state
        if not body and s['constructor_stack'] is None:return
        journals=self.body_zones if body else {s['constructor_stack_pool']:s['constructor_stack']}
        for row in s['frame_history']:
            if row['actual_task']!=hex(self.running_task) or row['original_push_verified']:continue
            if row['whole_stack_journal_actor']!=('body'if body else'cold'):continue
            zone=journals[int(row['journal_start'],16)]
            events=[e for e in zone['stores'][row['journal_event_index']:]if e.get('PC')==row['push_writer']
              and row['SP']-row['push_bytes']<=int(e['address'],16)<row['SP']]
            if not events:continue
            require(len(events)==len(row['push_values']),'Native allocator PUSH count/repetition differs')
            expected=bytearray.fromhex(row['actual_frame_before_hex'])
            offset=row['local_bytes']
            for i,e in enumerate(events):
                require((int(e['address'],16),e['size'],e['value'])==
                        (row['SP']-row['push_bytes']+4*i,4,row['push_values'][i])
                        and e['Thumb']==row['Thumb'] and e['before_hex']==expected[offset+4*i:offset+4*i+4].hex(),
                        'Native allocator actual PUSH register/offset/mode/beforeimage differs')
                expected[offset+4*i:offset+4*i+4]=e['value'].to_bytes(4,'little')
            row.update(original_push_verified=True,actual_push_events=json.loads(json.dumps(events)))

    def _na_finish_frames(self,uc,address,body):
        s=self.native_allocation_state
        for f,rows in s['frames'].items():
            if rows and address==(rows[-1]['LR']&~1):
                r=rows[-1];sp=self._na_task(uc,body,thumb=bool(r['LR']&1))
                require(sp==r['SP'] and r['original_push_verified'],'Native allocator actual caller return SP/PUSH differs '+hex(f))
                r.update(returned=True,actual_return_SP=hex(sp),actual_return_r0=uc.reg_read(UC_ARM_REG_R0),
                  actual_return_arguments=[hex(uc.reg_read(x))for x in ARGS]);rows.pop()
                if f==0x388B6C:
                    require(r is s['cold_frame'] and r['epilogue_return_branch_seen'],
                            'Native public ctor returned without original BXr3')
                    s['cold_init_returned']=True;self._na_seal_constructor_stack()

    def _na_cold_observe(self,uc,address):
        s=self.native_allocation_state
        if not s['prepared'] or self.phase!='heap_ctor':return
        if address==0x23D6E8:require(False,'Native public initializer reached unreviewed original diagnostic')
        self._na_verify_pushes(uc,False);self._na_finish_frames(uc,address,False)
        if address==0x388B6C:
            require(s['cold_frame'] is None and not s['cold_init_returned'] and self.word(WORK+0x18)==0,
                    'Original public initializer WORK/onlyonce provenance differs')
            pool=s['constructor_stack_pool']
            require(s['constructor_stack'] is None and not self.cold_journal_active and self.cold_boot_sealed,
                    'Heap ctor must use a new journal after frozen five boot zones')
            s['constructor_stack']=dict(start=hex(pool),bytes=16384,before_hex=bytes(uc.mem_read(pool,16384)).hex(),
              stores=[],active=True,old_five_cold_boot_zones_restarted=False,whole_net_zone_matches_original_stores=False)
            row=self._na_new_frame(uc,address,False)
            require(row['SP']==self.controller and row['LR']==RETURN|1
                    and row['arguments']==[s['private_descriptor'],1,DESC,1],
                    'Original native public constructor cold API arguments/caller/SP differ')
            row['actual_WORK96_before_hex']=bytes(uc.mem_read(WORK,96)).hex();s['cold_frame']=row
        root=s['cold_frame']
        if not root:return
        t=root['body_SP'];caller=uc.reg_read(UC_ARM_REG_LR)&~1
        cold_entries={0x388DF2:{0x388D8E:t,0x388DAC:t},0x38806C:{0x388E00:t-8},
          0x3880BC:{0x388DE0:t},0x21210C:{0x388B80:t,0x3880D6:t-24},0x35B4F4:{0x388BC2:t}}
        if address in cold_entries:
            require(caller in cold_entries[address] and uc.reg_read(UC_ARM_REG_SP)==cold_entries[address][caller],
                    'Cold public helper exact original caller/SP differs '+hex(address))
            row=self._na_new_frame(uc,address,False)
            if address==0x35B4F4:require(row['arguments'][:2]==[PRIVATE,4096],'Native heap prefix memzero input differs')
            if address==0x38806C:require(self.word(WORK+4)==PRIVATE+4096 and self.word(WORK+8)==0,
                    'Native descriptor page is not original live private freelist page')
            if address==0x3880BC:require(row['arguments'][0]==native_public_heap_recipe()['start'],
                    'Native first public free-bin descriptor differs')
        if address==0x388DF0:
            require(self._na_task(uc,False)==root['SP'] and uc.reg_read(UC_ARM_REG_R3)==root['LR'],
                    'Native public constructor BXr3/frame differs')
            self._na_opcode(uc,address,True);root['epilogue_return_branch_seen']=True

    def observe(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):
            self._na_cold_observe(uc,address);self._na_capture_constructor_push(uc,address)
        return super().observe(uc,address,size,data)

    def _na_capture_constructor_push(self,uc,address):
        row=self.native_allocation_state['constructor_stack']
        if row is None or not row['active']:return
        thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32);op,ins=self._na_opcode(uc,address,thumb)
        if not(ins.startswith('push ')or ins.startswith('stmdb sp!')):return
        names=[v.strip()for v in ins[ins.index('{')+1:ins.index('}')].split(',')]
        require(all(v in REGISTER for v in names),'Unknown original heap constructor PUSH register')
        sp=uc.reg_read(UC_ARM_REG_SP);low=sp-4*len(names)
        self._na_constructor_push=dict(PC=address,SP=sp,opcode_hex=op.hex(),
          values={low+4*i:uc.reg_read(REGISTER[n])for i,n in enumerate(names)})

    def journal_native_heap_constructor_stack(self,uc,access,address,size,value,data):
        row=self.native_allocation_state['constructor_stack']
        if row is None or not row['active']:return
        thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32);sp=self._na_task(uc,False,thumb)
        pc=uc.reg_read(UC_ARM_REG_PC);op,ins=self._na_opcode(uc,pc,thumb)
        require(size in (1,2,4) and ins.startswith(('str','stm','swp','push'))
                and int(row['start'],16)<=address and address+size<=int(row['start'],16)+row['bytes'],
                'Native heap constructor stack write mode/family/span differs')
        value&=(1<<(8*size))-1
        if ins.startswith('push ')or ins.startswith('stmdb sp!'):
            push=self._na_constructor_push
            require(push and push['PC']==pc and push['opcode_hex']==op.hex() and size==4
                    and push['values'].get(address)==value,'Native heap constructor actual PUSH register binding differs')
        else:self._na_writer_binding(uc,ins,address,size,value)
        row['stores'].append(dict(PC=hex(pc),opcode_hex=op.hex(),original_instruction=ins,Thumb=thumb,
          address=hex(address),size=size,value=value,before_hex=bytes(uc.mem_read(address,size)).hex(),
          SP=hex(sp),LR=hex(uc.reg_read(UC_ARM_REG_LR)),actual_task=hex(self.running_task)))

    def _na_seal_constructor_stack(self):
        row=self.native_allocation_state['constructor_stack'];require(row and row['active'],'New heap constructor stack journal absent/repeated')
        raw=bytearray.fromhex(row['before_hex']);low=int(row['start'],16)
        for e in row['stores']:
            o=int(e['address'],16)-low;n=e['size']
            require(raw[o:o+n].hex()==e['before_hex'],'Native heap constructor whole-stack replay missed a net mutation')
            raw[o:o+n]=e['value'].to_bytes(n,'little')
        actual=bytes(self.uc.mem_read(low,row['bytes']));require(actual==raw,'Native heap ctor whole current-controller stack differs outside CPU history')
        row.update(active=False,after_sha256=hashlib.sha256(actual).hexdigest(),
          whole_net_zone_matches_original_stores=True,seal_after_original_constructor_return=True)

    def verify_heap(self,cold=False):
        s=self.native_allocation_state
        if not s['prepared']:return super().verify_heap(cold)
        require(cold is True and s['cold_init_returned'] and s['cold_frame']['returned']
                and all(r['original_push_verified'] and r['returned']for r in s['frame_history']),
                'New public recipe is only verified immediately after genuine first constructor return')
        recipe=native_public_heap_recipe()
        require(bytes(self.uc.mem_read(PRIVATE,PRIVATE_BYTES))==recipe['private']
                and bytes(self.uc.mem_read(WORK,96))==recipe['workspace']
                and bytes(self.uc.mem_read(PUBLIC,PUBLIC_BYTES))==recipe['public'],
                'Native initialized public/private/WORK whole recipes differ')
        nodes=[];p=self.word(0x2D226B4)
        while p:
            require(p in [0x3A7F150,0x3A7F160,0x3AB1028] and p not in [r['pointer']for r in nodes],
                    'Public heap original exit-list listener chain differs')
            w=struct.unpack('<4I',self.uc.mem_read(p,16));nodes.append(dict(pointer=p,words=[hex(x)for x in w]));p=w[0]
        require([r['pointer']for r in nodes]==[0x3A7F150,0x3A7F160,0x3AB1028]
                and nodes[0]['words'][1:]==['0x1000000','0x388b57','0x0']
                and nodes[1]['words'][1:]==['0x3000000','0x388b37','0x0']
                and nodes[2]['words']==['0x0','0x7fffffff','0x20edb1','0x0'],
                'Three original heap/FP listener values differ')
        ops=[r for r in self.backend_initializations if r['native_caller']=='0x388bd0']
        require(len(ops)==1 and ops[0]['original_body_executed'] and len(ops[0]['native_zero_writes'])==6
                and self.word(BACKEND+16)==0x388D00 and self.word(BACKEND+20)==0,
                'Native heap original six-zero initializer/tag/class incomplete')
        require([r['native_return']for r in self.listener_registrations]==['0x388be6','0x388bf8']
                and not any(self.task_mutex_ops.values()) and not any(self.mutexes.values()),
                'Original heap listener returns or released ordinary mutex ledger differ')
        guards=self.verify_native_public_heap_guards();s['cold_recipe_verified']=True
        return dict(workspace96_hex=recipe['workspace'].hex(),listeners=nodes,native_initializer=ops[0],
          declared_private_extent=[hex(PRIVATE),PRIVATE_BYTES],declared_public_extent=[hex(PUBLIC),PUBLIC_BYTES],
          declared_extent=[hex(PRIVATE),PRIVATE_BYTES],original_prefix_reserve_bytes=4096,
          whole_extent_matches_original_recipe=True,whole_cold_workspace_recipe_checked=True,
          native_public_free_bin=dict(start=hex(recipe['start']),end=hex(recipe['end']),slot=hex(recipe['bin_slot'])),
          native_ctor_frame=s['cold_frame'],listener_registration_returns=self.listener_registrations,
          public_fixture_guards=guards,native_real_device_allocator_verified=False)

    def verify_native_public_heap_guards(self):
        s=self.native_allocation_state;require(s['prepared'],'Public heap fixture absent')
        require(bytes(self.uc.mem_read(ENVELOPE,4096))==b'\xa5'*4096
                and bytes(self.uc.mem_read(PUBLIC+PUBLIC_BYTES,4096))==b'\xa5'*4096,
                'Original public allocator crossed leading/trailing guard pages')
        expected=bytearray(b'\xa5'*4096);struct.pack_into('<2I',expected,32,PUBLIC,PUBLIC_BYTES)
        require(bytes(self.uc.mem_read(DESC_PAGE,4096))==expected,
                'Original public descriptor or whole descriptor page guards changed')
        result=[]
        for start in [ENVELOPE,DESC_PAGE]:
            require(start in self.zone_rows,'Public extent lacks inherited whole-zone before/stores ledger')
            row=self.zone_rows[start];raw=bytearray.fromhex(row['before_hex'])
            for e in row['stores']:
                o=int(e['address'],16)-start;n=e['size'];require(raw[o:o+n].hex()==e['before_hex'],
                    'Public whole-zone replay missed a net mutation');raw[o:o+n]=int(e['value']).to_bytes(n,'little')
            actual=bytes(self.uc.mem_read(start,row['bytes']));require(actual==raw,'Public whole-zone after differs from CPU history')
            result.append(dict(start=hex(start),bytes=row['bytes'],after_sha256=hashlib.sha256(actual).hexdigest(),
                CPU_events=len(row['stores']),whole_net_zone_matches_original_stores=True))
        return dict(all_passed=True,whole_zones=result,guard_pages_unchanged=True,descriptor_page_unchanged=True,
                    physical_heap_available_verified=False)

    def capture_dispatcher_settings_inputs(self):
        r=super().capture_dispatcher_settings_inputs();s=self.native_allocation_state
        require(s['cold_recipe_verified'] and s['inputs_after_cold'] is None and self.word(BACKEND+8)==0
                and self.word(BACKEND+12)==0 and self.word(BACKEND+16)==0x388D00 and self.word(BACKEND+20)==0,
                'Native allocation capture lacks original cold initialization/released semaphore')
        init=[r for r in self.backend_initializations if r['native_caller']=='0x388bd0']
        require(len(init)==1,'Native allocator backend initializer provenance missing')
        s['inputs_after_cold']=dict(backend24_actual_before_hex=bytes(self.uc.mem_read(BACKEND,24)).hex(),
          WORK96_actual_before_hex=bytes(self.uc.mem_read(WORK,96)).hex(),
          native_initializer=json.loads(json.dumps(init[0])),original_tag_writer='0x388bd2',tag='0x388d00',class22=0,
          F070B0_actual_before_hex=bytes(self.uc.mem_read(0xF070B0,4)).hex(),
          private_whole_before_hex=bytes(self.uc.mem_read(PRIVATE,PRIVATE_BYTES)).hex(),
          public_whole_before_hex=bytes(self.uc.mem_read(PUBLIC,PUBLIC_BYTES)).hex(),
          old_caller_released_stale_links_preserved=True,physical_heap_or_foreground_verified=False)
        require(s['inputs_after_cold']['F070B0_actual_before_hex']=='00000000','Original initialized allocation flags are not0')
        for task in self.native_TCBs:
            self._na_hooks.append(self.uc.hook_add(UC_HOOK_MEM_WRITE,self.journal_native_allocation_TCB_write,begin=task,end=task+107))
        return dict(r,native_allocation_inputs=json.loads(json.dumps(s['inputs_after_cold'])))

    def _na_begin_allocation(self,uc,continuation):
        s=self.native_allocation_state;c=self.clock_caller_state['constructor']
        require(s['inputs_after_cold'] and self.clock_caller_state['clock_prefix_complete'] and s['pending'] is None,
                'Native allocation lacks current captured constructor/clock/heap or is reentrant')
        request=48 if continuation==0x395534 else 8;sp=self._da_actor(uc,False)
        shape=allocation_shape(c['SP']-128,request,continuation)
        require(sp==shape['B'] and uc.reg_read(UC_ARM_REG_LR)==shape['LR']
                and uc.reg_read(UC_ARM_REG_R0)==request and self.word(0xF070B0)==0
                and len(s['allocations'])==(0 if request==48 else 1),
                'Original48/8 allocator entry/caller/order/SP/input differs')
        if request==8:require(s['allocations'][0]['actual_original_caller_return_seen'],
                'Second allocation before genuine first caller return')
        require(self._da_opcode(uc,0x3954CC,8)=='00c09fe51cff2fe1' and self.stock.word(0x3954D4)==0x2DC9EB,
                'Original ARM allocator veneer/literal changed')
        original_call=self._da_original_call(uc,0x3954CC,shape['LR'])
        require(self.word(D+36)==(0 if request==48 else s['allocations'][0]['native_handle']),
                'Native allocation head does not originate in exact currentD two-allocation sequence')
        output=shape['output_cell'];zone=self._cc_zone(output,4)
        rawTCBs={hex(t):bytes(self.uc.mem_read(t,108)).hex()for t in sorted(self.native_TCBs)}
        row=dict(shape=shape,entry='0x3954cc',entry_SP=sp,entry_LR=shape['LR'],entry_arguments=[uc.reg_read(r)for r in ARGS],
          actual_before_TCB108=rawTCBs,actual_before_D_allocation_head=hex(self.word(D+36)),
          backend24_before_hex=bytes(self.uc.mem_read(BACKEND,24)).hex(),WORK96_before_hex=bytes(self.uc.mem_read(WORK,96)).hex(),
          original_call=original_call,lower_return_seen=False,query_return_seen=False,
          actual_original_caller_return_seen=False,native_handle=None,native_pointer=None,prefix_store_seen=False,
          TCB_stores=[],heap_stores=[],raw_operations=[],output_before_hex=bytes(uc.mem_read(output,4)).hex(),
          output_zone_start=zone['start'],output_zone_event_index=len(zone['stores']),
          host_allocation_or_context_or_return_supplied=False)
        s['allocations'].append(row);s['pending']=row;self.visits[0x3954CC]+=1

    def _na_begin_raw(self,uc,entry,continuation):
        s=self.native_allocation_state;a=s['pending'];require(a is not None,'Allocator raw without pending exact malloc')
        f,_,_=RAW[entry,continuation];frame=self._na_frame(f);sp=self._da_actor(uc)
        event=dict(entry=entry,continuation=continuation,task=self.running_task,current=self.word(0xF09090),
          Thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32),pointer=uc.reg_read(UC_ARM_REG_R0),SP=sp,
          LR=uc.reg_read(UC_ARM_REG_LR),tag=self.word(BACKEND+16),**{'class':self.uc.mem_read(BACKEND+22,1)[0]})
        op=check_allocation_raw(a['shape'],frame['SP'],event)
        self._da_original_call(uc,entry,event['LR']);self._da_opcode(uc,entry)
        require(BACKEND in self.native_semaphores and not self.native_semaphores[BACKEND]['retained_condition_token'],
                'Native malloc backend lacks existing initialized ordinary semaphore')
        require(self.word(BACKEND+8)==(0 if op=='lock' else D) and self.word(BACKEND+12)==0
                and not self.task_mutex_ops[D], 'Allocator native lock owner/waiter/pending differs')
        row=dict(original_entry=hex(entry),pointer=hex(BACKEND),native_caller=hex(continuation),operation=op,
          scope='exact_Dispatcher_native_public_heap',running_task=hex(D),entry_SP=hex(sp),entry_LR=hex(event['LR']),
          before_words=[hex(self.word(BACKEND+4*i))for i in range(6)],native_body_returned=False,
          actual_caller_continuation_seen=False,semaphore_fields_written_by_original_only=True,
          host_CPU_context_restore=False,reviewed_shape=dict(event))
        self.native_mutex_runs.append(row);self.task_mutex_ops[D].append(row)
        s['raw_ops'].append(row);s['raw_returns_pending'].append(row);a['raw_operations'].append(row);self.visits[entry]+=1

    def _na_returns(self,uc,address):
        s=self.native_allocation_state;a=s['pending']
        for r in list(s['raw_returns_pending']):
            if address==int(r['native_caller'],16):
                sp=self._da_actor(uc)
                require(r['native_body_returned'] and r.get('original_return_branch_reached')
                        and sp==int(r['entry_SP'],16) and uc.reg_read(UC_ARM_REG_R0)==r['original_return']==0
                        and self.word(BACKEND+8)==(D if r['operation']=='lock' else 0)
                        and self.word(BACKEND+12)==0,'Allocator raw genuine epilogue/caller return differs')
                r.update(actual_caller_continuation_seen=True,actual_return_SP=hex(sp),actual_return_r0=0,
                  whole24_actual_at_caller_hex=bytes(uc.mem_read(BACKEND,24)).hex());s['raw_returns_pending'].remove(r)
        self._na_verify_pushes(uc,True);self._na_finish_frames(uc,address,True)
        if not a:return
        shape=a['shape'];sp=self._da_actor(uc,thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32))
        if address==0x2DC964:
            h=uc.reg_read(UC_ARM_REG_R0)
            require(sp==shape['output_cell'] and h==self.word(shape['output_cell']) and h!=0
                    and len(a['raw_operations'])==2 and all(x['actual_caller_continuation_seen']for x in a['raw_operations']),
                    'Native malloc wrapper actual handle/output/raw returns differ')
            require(PRIVATE+4096<=h and h+24<=PRIVATE+8192 and (h-PRIVATE-4096)%24==0,
                    'Native malloc handle lacks original live descriptor-page provenance')
            q=self.word(h+4)&~7;require(PUBLIC<=q and q+shape['lower_request']<=PUBLIC+PUBLIC_BYTES
                    and self.word(h+4)&7==5 and self.word(self.word(h+8))==h,
                    'Native handle public backing/allocated flag/end reciprocal link differ')
            zone=self.body_zones[int(a['output_zone_start'],16)]
            writes=[e for e in zone['stores'][a['output_zone_event_index']:]if int(e['address'],16)==shape['output_cell']]
            require([(e['PC'],e['size'],e['value'])for e in writes]==
                    [('0x2dc954',4,shape['LR']),('0x2dc95c',4,0),('0x3881ca',4,0),('0x3884c0',4,h)],
                    'Actual malloc output lacks native thunk/core zeros and final original handle store')
            raw=bytes.fromhex(a['output_before_hex'])
            for e in writes:
                require(e['before_hex']==raw.hex(),'Actual malloc output CPU beforeimage differs')
                raw=e['value'].to_bytes(4,'little')
            require(bytes(uc.mem_read(shape['output_cell'],4))==raw,'Actual native output word differs from exact CPU history')
            a['actual_output_word_CPU_stores']=json.loads(json.dumps(writes))
            a.update(lower_return_seen=True,native_handle=h,native_backing=q,
              actual_lower_return_SP=hex(sp),native_handle24_at_lower_return_hex=bytes(uc.mem_read(h,24)).hex())
        if address==0x2DC96A:
            require(a['lower_return_seen'] and sp==shape['output_cell'] and uc.reg_read(UC_ARM_REG_R0)==a['native_backing']
                    and len(a['raw_operations'])==4 and all(r['actual_caller_continuation_seen']for r in a['raw_operations']),
                    'Native handle query actual pointer/return/raw scopes differ')
            a.update(query_return_seen=True,actual_query_return_SP=hex(sp),actual_query_return_r0=hex(a['native_backing']))
        if address==shape['continuation']:
            p=uc.reg_read(UC_ARM_REG_R0)
            require(a['lower_return_seen'] and a['query_return_seen'] and a['prefix_store_seen']
                    and sp==shape['B'] and p==a['native_backing']+8 and p%8==0
                    and self.word(p-4)==a['native_handle'] and self.word(BACKEND+8)==0,
                    'Native allocator original48/8 caller return/pointer/prefix differs')
            for t in self.native_TCBs:
                raw=bytearray.fromhex(a['actual_before_TCB108'][hex(t)])
                if t==D:struct.pack_into('<I',raw,36,a['native_handle'])
                require(bytes(uc.mem_read(t,108))==raw,'Whole native TCB108 changed outside exactD malloc head '+hex(t))
            a.update(native_pointer=p,actual_original_caller_return_seen=True,actual_original_return_SP=hex(sp),
              actual_after_TCB108={hex(t):bytes(uc.mem_read(t,108)).hex()for t in sorted(self.native_TCBs)},
              native_payload_before_ctor_hex=bytes(uc.mem_read(p,shape['request'])).hex(),
              actual_reserved_stack_byte_source=hex(shape['B']+0x30),
              actual_reserved_stack_byte_value=uc.mem_read(shape['B']+0x30,1)[0],
              backend24_after_hex=bytes(uc.mem_read(BACKEND,24)).hex())
            s['pending']=None
            if len(s['allocations'])==2:s['two_native_allocations_returned']=True

    def observe_dispatcher_actor(self,uc,address,size,data):
        if not getattr(self,'dispatcher_body_active',False):return False
        s=self.native_allocation_state;lr=uc.reg_read(UC_ARM_REG_LR);caller=lr&~1
        if address==0x3954CC and caller in (0x395534,0x395544):
            self._na_begin_allocation(uc,caller);return True  # Original ARM veneer executes; never LoadedVM host provider.
        if s['pending']:
            if address==0x23D6E8:require(False,'Original public allocator diagnostic/invalid-handle branch is outside successful bounded scope')
            self._na_returns(uc,address);a=s['pending']
            if a:
                shape=a['shape']
                routes={0x2DC954:(shape['B'],None),0x38850A:(shape['malloc_entry_SP'],0x2DC964),
                  0x3881BC:(shape['core_entry_SP'],0x38852C),0x388804:(shape['query_entry_SP'],0x2DC96A),
                  0x388E92:(shape['validator_entry_SP'],0x38881A),0x388DF2:(shape['core_body_SP'],0x38835E),
                  0x3880BC:(shape['core_body_SP'],0x3883DC)}
                if address in routes:
                    expected_SP,cont=routes[address]
                    require(uc.reg_read(UC_ARM_REG_SP)==expected_SP and (cont is None or caller==cont),
                            'Native malloc helper caller/frame differs '+hex(address))
                    row=self._na_new_frame(uc,address,True)
                    if address==0x2DC954:require(row['arguments']==[shape['request'],0,8,shape['LR']],
                      'Native thunk flags/alignment/callerLR differ')
                    if address in (0x38850A,0x3881BC):require(row['arguments']==[shape['lower_request'],0,shape['output_cell'],shape['LR']],
                      'Native malloc core original four inputs differ')
                    if address==0x388804:require(row['arguments'][0]==a['native_handle'],'Native query handle differs')
                    if address==0x388E92:require(row['arguments'][:2]==[a['native_handle'],0x2DC96B],
                      'Original validator actual handle/query LR differs')
                    if address==0x388DF2:require(self.word(WORK+0xC)!=0 and self.word(WORK+4)==self.word(WORK+8)==0,
                      'Native successful small allocation exhausted descriptor freelist')
                if address==0x21210C:
                    expected={0x388210:shape['core_body_SP'],0x388230:shape['core_body_SP'],
                      0x388268:shape['core_body_SP'],0x3882E8:shape['core_body_SP'],
                      0x3882F6:shape['core_body_SP'],0x3880D6:shape['core_body_SP']-24,
                      0x38817E:shape['core_body_SP']-24}
                    require(caller in expected and uc.reg_read(UC_ARM_REG_SP)==expected[caller],
                      'Native allocator floorlog2 caller/frame is unreviewed')
                    self._na_new_frame(uc,address,True)
                if (address,caller)in RAW:self._na_begin_raw(uc,address,caller);return True
                if address in (0x38806C,0x221D34,0x388EB8,0x388EC4):
                    require(False,'Native malloc reached unreviewed page/provider/invalid descriptor branch '+hex(address))
        elif address in (0x395534,0x395544):
            # _na_returns above normally clears pending at these addresses; a repeat is invalid.
            require(False,'Native48/8 caller continuation lacks pending original allocation')
        if address in (0x395534,0x395544) and s['allocations']:
            return True  # Bypass frozen clock hardstop, execute original caller instruction.
        if address==0x395552 and s['two_native_allocations_returned']:
            s['next_boundary']=dict(entry=hex(address),reason='Post-allocation timer/container lifetime not yet admitted',
              SP=hex(self._da_actor(uc)),original_opcode=self._da_opcode(uc,address),hardware_or_firmware_fault=False)
            self.verify_native_allocation_prefix()
            require(False,'Original post-allocation timer/container initialization requires separate lifetime scope')
        # Parent original300A0A/30092A epilogues, all controller/timer and unknown scopes remain.
        return super().observe_dispatcher_actor(uc,address,size,data)

    def _na_writer_binding(self,uc,instruction,address,size,value):
        m=re.fullmatch(r'str([bh]?)\w* (\w+), \[(\w+)(?:, #(0x[0-9a-f]+|[0-9]+)|(, \w+))?\].*',instruction)
        if not m:return  # Multi-store semantics are bounded by actual frame/span/recipe + original journals.
        suffix,source,base,imm,regoffset=m.groups();require(source in REGISTER and base in REGISTER,'Unknown store register')
        expected_size={'':4,'b':1,'h':2}[suffix]
        off=int(imm,0)if imm else uc.reg_read(REGISTER[regoffset.split(', ')[1]])if regoffset else 0
        require(size==expected_size and address==uc.reg_read(REGISTER[base])+off
                and value==(uc.reg_read(REGISTER[source])&((1<<(8*size))-1)),
                'Original native heap STR register/address/value binding differs')

    def journal_native_heap_write(self,uc,access,address,size,value,data):
        s=self.native_allocation_state
        if not s['prepared'] or not self.zone_active:return
        pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32);body=self.dispatcher_body_active
        if DESC_PAGE<=address<DESC_PAGE+4096:require(False,'Native heap attempted to mutate readonly public input descriptor page')
        if ENVELOPE<=address<ENVELOPE+ENVELOPE_BYTES:
            require(PUBLIC<=address and address+size<=PUBLIC+PUBLIC_BYTES,'Native public heap crossed a guard page')
        active=s['pending'] if body else s['cold_frame'] if self.phase=='heap_ctor' else None
        if not active:
            if body and pc in (0x395548,0x395550):
                require(s['two_native_allocations_returned'] and len(s['allocations'])==2,
                        'Temporary payload store before genuine native allocation returns')
                a=s['allocations'][1];p=a['native_pointer'];sp=self._da_actor(uc)
                expected=(p,4,0xC1C0EC)if pc==0x395548 else(p+4,1,a['actual_reserved_stack_byte_value'])
                require((address,size,value)==expected and sp==a['shape']['B']
                        and uc.reg_read(UC_ARM_REG_R0)==p and uc.reg_read(UC_ARM_REG_R1)==expected[2]
                        and len(s['payload_setup_stores'])==(0 if pc==0x395548 else 1),
                        'Original temporary vtable/actual stack byte tuple/frame/order differs')
                op,ins=self._na_opcode(uc,pc,True)
                require(op.hex()==('0160'if pc==0x395548 else '0171'), 'Original temporary writer opcode differs')
                s['payload_setup_stores'].append(dict(PC=hex(pc),opcode_hex=op.hex(),instruction=ins,
                  address=hex(address),size=size,value=value,before_hex=bytes(uc.mem_read(address,size)).hex(),
                  SP=hex(sp),actual_task=hex(D),source_actual_stack_byte=a['actual_reserved_stack_byte_source']if size==1 else None))
                return
            if body:require(False,'Unknown actor/public heap writer outside pending native allocation/setup')
            return  # Preserve original controller/listener scopes and old journals.
        sp=self._na_task(uc,body,thumb);op,ins=self._na_opcode(uc,pc,thumb)
        require(size in (1,2,4) and ins.startswith(('str','stm','swp')),'Native heap write width/opcode family differs')
        value&=(1<<(8*size))-1
        raw=BACKEND<=address and address+size<=BACKEND+24
        if raw and not body and 0x3008A0<=pc<0x3008AE:
            init=self.active_backend
            require(init and init['pointer']==hex(BACKEND) and init['native_caller']=='0x388bd0'
                    and size==4 and value==0 and thumb and sp==s['cold_frame']['body_SP']
                    and address in range(BACKEND,BACKEND+24,4),
                    'Cold native heap six-zero backend store lacks original pending initializer')
        elif raw and body:
            pending=self.task_mutex_ops[D]
            require(pending and pending[-1] in s['raw_ops'] and pending[-1]['pointer']==hex(BACKEND)
                    and (0x3009A0<=pc<0x300A0C if pending[-1]['operation']=='lock' else 0x3008B0<=pc<0x30092C),
                    'Native malloc whole24 write lacks exact pending original raw frame')
            require(sp==int(pending[-1]['entry_SP'],16)-8, 'Native malloc raw body SP differs')
        else:
            record=self._na_tables['writer_opcodes'].get(hex(pc))
            require(record and record['Thumb']==thumb and record['opcode_hex']==op.hex(),
                    'Heap write PC/mode/opcode outside bounded original functions')
            f=int(record['function_entry'],16)
            if f==0x388144:
                frame=self._na_frame(0x3881BC);require(body and sp in (frame['body_SP'],frame['body_SP']-24),
                    'Free-bin removal lacks exact native malloc core frame')
            elif f==0x2DC9EA:
                require(body and sp==self._na_frame(0x2DC954)['body_SP'],'Native allocator thunk frame differs')
            else:
                frame=self._na_frame(f);require(sp==frame['body_SP'],
                    'Bounded native heap writer relative frame differs '+hex(pc))
            if not body and f==0x35B4F4:
                require(PRIVATE<=address and address+size<=PRIVATE+4096 and value==0,
                    'Native heap prefix zero store escaped exact4096 span')
        self._na_writer_binding(uc,ins,address,size,value)
        row=dict(PC=hex(pc),Thumb=thumb,opcode_hex=op.hex(),original_instruction=ins,address=hex(address),
          size=size,value=value,before_hex=bytes(uc.mem_read(address,size)).hex(),SP=hex(sp),LR=hex(uc.reg_read(UC_ARM_REG_LR)),
          actual_task=hex(self.running_task),phase=self.phase)
        s['heap_writes'].append(row)
        if body:active['heap_stores'].append(row)
        if body and pc==0x2DC97E:
            require(active['query_return_seen'] and address==active['native_backing']+4 and size==4
                    and value==active['native_handle'] and sp==active['shape']['output_cell'],
                    'Original native allocation handle-prefix store differs')
            active['prefix_store_seen']=True

    def journal_native_allocation_TCB_write(self,uc,access,address,size,value,data):
        s=self.native_allocation_state;a=s['pending']
        if not self.dispatcher_body_active or a is None:return
        pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32);sp=self._da_actor(uc,thumb)
        if address==D+32:
            pending=self.task_mutex_ops[D]
            require(pending and pending[-1] in s['raw_ops'] and size==4 and thumb
                    and sp==int(pending[-1]['entry_SP'],16)-8,
                    'Native raw owned-list TCB store lacks exact malloc raw pending frame')
            row=pending[-1]
            if row['operation']=='lock':
                require(pc==0x3009D4 and value==BACKEND and uc.reg_read(UC_ARM_REG_R0)==BACKEND
                        and uc.reg_read(UC_ARM_REG_R2)==D+32,'Native malloc raw owned-head insertion differs')
            else:
                require(pc==0x3008F8 and value==int(row['before_words'][0],16)
                        and uc.reg_read(UC_ARM_REG_R1)==D+32 and uc.reg_read(UC_ARM_REG_R2)==value,
                        'Native malloc raw owned-head restoration differs')
            op,ins=self._na_opcode(uc,pc,True)
            s['TCB_writes'].append(dict(kind='native_heap_raw_owned_head',PC=hex(pc),opcode_hex=op.hex(),
              address=hex(address),size=4,value=value,before_hex=bytes(uc.mem_read(address,4)).hex(),
              SP=hex(sp),actual_task=hex(D)))
            return
        require(size==4 and address==D+36 and pc==0x388448 and thumb
                and uc.reg_read(UC_ARM_REG_R0)==D and value==uc.reg_read(UC_ARM_REG_R4)
                and sp==a['shape']['core_body_SP'] and PRIVATE+4096<=value and value+24<=PRIVATE+8192,
                'Native malloc TCB store outside exact actualD+24 handle-owner update')
        op,ins=self._na_opcode(uc,pc,True);require(op.hex()=='4462','Original native TCB ownership opcode differs')
        row=dict(PC=hex(pc),opcode_hex=op.hex(),instruction=ins,address=hex(address),size=4,value=value,
          before_hex=bytes(uc.mem_read(address,4)).hex(),SP=hex(sp),actual_task=hex(D))
        a['TCB_stores'].append(row);s['TCB_writes'].append(row)

    def verify_native_allocation_prefix(self):
        s=self.native_allocation_state
        require(s['cold_recipe_verified'] and s['two_native_allocations_returned'] and s['pending'] is None
                and len(s['allocations'])==2 and len(s['payload_setup_stores'])==2 and len(s['raw_ops'])==8 and not s['raw_returns_pending']
                and all(a['actual_original_caller_return_seen'] and len(a['TCB_stores'])==1 for a in s['allocations'])
                and all(r['native_body_returned'] and r['actual_caller_continuation_seen']for r in s['raw_ops']),
                'Native public allocation/raw/wholeTCB prefix incomplete')
        self.verify_native_public_heap_guards()
        a=s['allocations'][1];expected=bytearray.fromhex(a['native_payload_before_ctor_hex'])
        struct.pack_into('<I',expected,0,0xC1C0EC);expected[4]=a['actual_reserved_stack_byte_value']
        require(bytes(self.uc.mem_read(a['native_pointer'],8))==expected,
                'Whole temporary8 payload differs outside exact vtable/stack-byte stores; gaps must remain actualbefore')
        head=self.word(D+36);ordered=[];prev=D+36
        while head:
            require(head not in ordered and len(ordered)<3
                    and self.word(head+16)==(prev|1 if prev==D+36 else prev),
                    'Native public allocation owner/backlink chain differs')
            ordered.append(head);prev=head+20;head=self.word(head+20)
        require(ordered==[r['native_handle']for r in reversed(s['allocations'])],
                'Native public allocation owned chain differs from exact two returned handles')
        s['whole_allocation_prefix_verified']=True
        return json.loads(json.dumps({k:v for k,v in s.items()if k!='frames'}))

    def snapshot_dispatcher_actor_observer(self):
        r=super().snapshot_dispatcher_actor_observer()
        r['native_allocation_observer']=json.loads(json.dumps(self.native_allocation_state));return r

    def verify_dispatcher_actor_observer(self):
        self.verify_native_allocation_prefix()
        return super().verify_dispatcher_actor_observer()
