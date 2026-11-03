#!/usr/bin/env python3
"""New controller integration observer with exact contiguous font inputs.

The failed original runner stays frozen. Raw font callbacks must have font
ownership, avoid native kernel storage, and cover consecutive writable pages.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_CPSR,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R7
import probe_native_controller_gir_component as driver
from emulate_native_player_external_fonts import ExternalFontVM
from emulate_native_vpm_filesystem import require
from emulate_native_vpm_filesystem import REGS
from emulate_native_player_external_fonts import FONT_IO

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'staging/native-player-controller-gir-integration/runtime-contiguous'
CACHE_LOW=0x34fa3bc
CACHE_BYTES=0xc0000
CACHE_HIGH=CACHE_LOW+CACHE_BYTES

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def dump(path,data):
    with path.open('x') as out:json.dump(data,out,ensure_ascii=False,indent=2);out.write('\n')

class ContiguousFontControllerGIRVM(driver.ControllerGIRVM):
    def __init__(self,stock,build):
        self.font_span_coverages=[]
        self.cache_contexts={};self.cache_control_witnesses=[]
        self.cache_allocations=[];self.cache_live={};self.cache_alloc_pending=[];self.cache_free_pending=[]
        self.cache_returns_pending={};self.cache_writer_instructions={}
        self.cache_read_bindings=[];self.cache_read_pending=[]
        self.cache_reader_route_pending=None;self.cache_reader_route_witnesses=[]
        self.cache_expected=bytearray(CACHE_BYTES);self.cache_journal=[];self.cache_CPU_store_count=0
        super().__init__(stock,build)
        require(any(row['runtime_start']<=CACHE_LOW and CACHE_HIGH<=row['runtime_end'] for row in stock.zeros),
                'Whole original shared font cache lacks startup-zero provenance')
        for low,end,flags in self.uc.mem_regions():
            begin,stop=max(low,CACHE_LOW),min(end+1,CACHE_HIGH)
            if begin<stop:
                require(bytes(self.uc.mem_read(begin,stop-begin))==bytes(stop-begin),
                        'Shared font cache differs from declared cold zero input')
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.journal_cache_CPU_write,begin=CACHE_LOW,end=CACHE_HIGH-1)

    def live_font_payload(self,pointer,length):
        for handle in self.font_handles:
            entry=self.handles[handle];base=entry['pointer']
            if entry['freed']:continue
            require(self.word(base)==handle and 0<self.word(base+4)<=entry['length']-8,
                    'Live font allocation lacks its original prefix')
            if base+8<=pointer and pointer+length<=base+8+self.word(base+4):return handle
        return None

    def cache_control(self,context,require_initialized=True):
        require(context in self.cache_contexts,'Font cache context lacks original control-pointer publication')
        control=self.word(context+0x58)
        require(control==self.cache_contexts[context] and self.live_font_payload(control,620) is not None and
                self.word(control-4)==620,'Font cache control lacks original live620-byte allocation')
        if require_initialized:
            require(self.word(control+0x214)==CACHE_BYTES and self.word(control+0x228)==CACHE_LOW,
                    'Original font cache capacity/base publication differs')
        return control

    def journal_cache(self,address,payload,before,kind,**metadata):
        require(CACHE_LOW<=address and address+len(payload)<=CACHE_HIGH,'Font cache write exceeds whole original cache')
        offset=address-CACHE_LOW
        require(self.cache_expected[offset:offset+len(payload)]==before,
                'Font cache chronological journal missed an earlier mutation')
        self.cache_expected[offset:offset+len(payload)]=payload
        key=dict(kind=kind,**metadata)
        if self.cache_journal:
            last=self.cache_journal[-1]
            if last['metadata']==key and last['address']+last['bytes']==address and last['bytes']+len(payload)<=4096:
                last['bytes']+=len(payload);last['before_hex']+=before.hex();last['after_hex']+=payload.hex()
                last['events']+=1;return
        self.cache_journal.append(dict(address=address,bytes=len(payload),before_hex=before.hex(),after_hex=payload.hex(),
            events=1,metadata=key))

    def journal_cache_CPU_write(self,uc,access,address,size,value,data):
        require(self.component_active and self.running_task==self.controller and size in [1,2,4,8],
                'Shared font cache native writer task/phase/width differs')
        pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)
        key=(pc,thumb)
        if key not in self.cache_writer_instructions:self.cache_writer_instructions[key]=self.original_store(pc,thumb)
        opcode,instruction,load=self.cache_writer_instructions[key]
        require(bytes(uc.mem_read(pc,len(opcode)))==opcode,'Cached original font writer instruction changed')
        require(CACHE_LOW<=address and address+size<=CACHE_HIGH,'Original cache CPU store exceeds cache boundary')
        before=bytes(uc.mem_read(address,size));payload=(value&((1<<(size*8))-1)).to_bytes(size,'little')
        self.journal_cache(address,payload,before,'exact_original_MAIN_CPU_store',PC=hex(pc),load_PC=hex(load),
            opcode_hex=opcode.hex(),instruction=instruction,running_task=hex(self.running_task),width=size)
        self.cache_CPU_store_count+=1

    def observe(self,uc,address,size,data):
        caller=uc.reg_read(UC_ARM_REG_LR);sp=uc.reg_read(UC_ARM_REG_SP)
        if self.component_active:
            if address in self.cache_returns_pending:
                row=self.cache_returns_pending.pop(address)
                require(sp==row['SP'] and uc.reg_read(REGS[0])==row['pointer'],'Native font allocation actual return differs')
                row['actual_caller_return_observed']=True
            for row in self.cache_free_pending:
                if row.get('native_epilogue_observed') and address==(row['LR']&~1):
                    require(sp==row['SP'] and uc.reg_read(REGS[0])==0,'Native font free actual return differs')
                    allocation=self.cache_allocations[row['allocation_index']]
                    require(allocation['pointer'] in self.cache_live,'Native font free target already released')
                    del self.cache_live[allocation['pointer']]
                    allocation.update(freed=True,free_context=hex(row['context']),free_caller=hex(row['LR']),
                        original_free_actual_caller_return_observed=True)
                    row['actual_caller_return_observed']=True
            self.cache_free_pending=[row for row in self.cache_free_pending if not row.get('actual_caller_return_observed')]
            for row in self.cache_read_pending:
                if address==(row['LR']&~1):
                    require(sp==row['SP'],'Original font read wrapper return stack differs')
                    row['actual_caller_return_observed']=True
            self.cache_read_pending=[row for row in self.cache_read_pending if not row.get('actual_caller_return_observed')]
            if address==0x265f5c:
                context=uc.reg_read(UC_ARM_REG_R4);control=self.word(context+0x58)
                require(control==uc.reg_read(REGS[0]) and self.live_font_payload(control,620) is not None and
                    self.word(control-4)==620 and bytes(uc.mem_read(0x265f5a,2))==self.stock.read(0x265f5a,2),
                    'Original root font cache control store differs')
                self.cache_contexts[context]=control
                self.cache_control_witnesses.append(dict(after_PC=hex(address),context=hex(context),control=hex(control),
                    original_store_PC='0x265f5a',live_original_font_malloc_requested_bytes=620))
            if address==0x265fb0:
                context=uc.reg_read(UC_ARM_REG_R4);control=self.cache_control(context)
                require(uc.reg_read(REGS[0])==CACHE_LOW and bytes(uc.mem_read(0x265fae,2))==self.stock.read(0x265fae,2),
                    'Original root font cache base store differs')
                self.cache_control_witnesses.append(dict(after_PC=hex(address),context=hex(context),control=hex(control),
                    original_store_PC='0x265fae',original_capacity=self.word(control+0x214),original_cache_base=hex(CACHE_LOW)))
            if address==0x268598:
                context,parent=uc.reg_read(UC_ARM_REG_R4),uc.reg_read(UC_ARM_REG_R5);control=self.cache_control(parent)
                require(self.word(context+0x58)==control and bytes(uc.mem_read(0x268596,2))==self.stock.read(0x268596,2),
                    'Original shared font cache context store differs')
                self.cache_contexts[context]=control
                self.cache_control_witnesses.append(dict(after_PC=hex(address),context=hex(context),parent=hex(parent),
                    control=hex(control),original_store_PC='0x268596'))
            if address==0x263f60:
                context,requested=[uc.reg_read(r) for r in REGS[:2]];control=self.cache_control(context)
                require(0<requested<CACHE_BYTES and self.running_task==self.controller,'Native font allocator request/task differs')
                opcode,instruction,load=self.original_call(caller)
                self.cache_alloc_pending.append(dict(context=context,control=control,requested_bytes=requested,SP=sp,LR=caller,
                    entry_PC=hex(address),caller_opcode_hex=opcode.hex(),caller_instruction=instruction,caller_load_PC=hex(load)))
            if address in [0x264032,0x264044]:
                require(self.cache_alloc_pending,'Native cache allocation epilogue lacks captured entry')
                row=self.cache_alloc_pending.pop();pointer=uc.reg_read(REGS[0])
                require(sp==row['SP'] and uc.reg_read(REGS[3])==row['LR'],'Original font allocator epilogue frame differs')
                if address==0x264044:
                    require(pointer==0,'Original font allocation failure differs')
                    row.update(pointer=0,native_epilogue_observed=True,failed=True,freed=True)
                else:
                    units=((row['requested_bytes']+7)>>3)+1;capacity=(units-1)*8
                    require(CACHE_LOW<=pointer-8 and pointer+capacity<=CACHE_HIGH and (pointer-CACHE_LOW)%8==0 and
                        self.word(pointer-4)==units and pointer not in self.cache_live,'Original live font allocation/header differs')
                    for other in self.cache_live.values():
                        require(not (pointer-8<other['pointer']+other['capacity'] and other['pointer']-8<pointer+capacity),
                                'Original native font cache allocations overlap')
                    row.update(pointer=pointer,units=units,capacity=capacity,native_epilogue_observed=True,freed=False)
                    self.cache_live[pointer]=row
                self.cache_allocations.append(row)
                require((row['LR']&~1) not in self.cache_returns_pending,'Original allocator has overlapping caller continuations')
                self.cache_returns_pending[row['LR']&~1]=row
            if address==0x26475c:
                context,pointer=[uc.reg_read(r) for r in REGS[:2]];control=self.cache_control(context)
                require(pointer in self.cache_live,'Native font free lacks a live original allocation')
                allocation=self.cache_live[pointer]
                require(allocation['control']==control and self.word(pointer-4)==allocation['units'],
                        'Native font free shared owner/header differs')
                opcode,instruction,load=self.original_call(caller)
                self.cache_free_pending.append(dict(context=context,control=control,pointer=pointer,SP=sp,LR=caller,
                    allocation_index=self.cache_allocations.index(allocation),caller_opcode_hex=opcode.hex(),
                    caller_instruction=instruction,caller_load_PC=hex(load)))
            if address==0x2647d6:
                require(self.cache_free_pending,'Native cache free epilogue lacks captured entry')
                row=self.cache_free_pending[-1]
                require(sp==row['SP'] and caller==row['LR'] and uc.reg_read(REGS[0])==0,
                        'Original font free epilogue frame differs')
                row['native_epilogue_observed']=True
            if address==0x26491c:
                context=self.word(sp+4);parser=uc.reg_read(UC_ARM_REG_R4);pointer=uc.reg_read(UC_ARM_REG_R5)
                requested=uc.reg_read(UC_ARM_REG_R7);handle=self.word(parser+8)
                require(self.cache_reader_route_pending is None and pointer in self.cache_live and
                    self.cache_live[pointer].get('actual_caller_return_observed') and
                    self.cache_live[pointer]['requested_bytes']==requested and
                    any(row['context']==hex(context) and row['parser']==hex(parser) and row['stream']==hex(handle)
                        for row in self.font_stream_owners),
                    'Original cache reader route lacks native allocation/context/parser/stream')
                self.cache_reader_route_pending=dict(context=context,parser=parser,handle=handle,pointer=pointer,
                    requested_bytes=requested,SP=sp,original_after_allocation_PC=hex(address))
            if address==0x14f084:
                context,handle,pointer,requested=[uc.reg_read(r)for r in REGS]
                if CACHE_LOW<=pointer<CACHE_HIGH:
                    require(pointer in self.cache_live,'Cache stream request lacks a live native payload')
                    route=self.cache_reader_route_pending
                    require(route is not None and caller==0x264939 and sp==route['SP'] and
                        [context,handle,pointer,requested]==[route[k]for k in ['context','handle','pointer','requested_bytes']] and
                        bytes(uc.mem_read(0x264934,4))==self.stock.read(0x264934,4),
                        'Original cache reader frame and exact wrapper caller differ')
                    self.cache_reader_route_witnesses.append(dict(**route,wrapper_entry='0x14f084',
                        original_caller_opcode_hex=self.stock.read(0x264934,4).hex()))
                    self.cache_reader_route_pending=None
                    allocation=self.cache_live[pointer];control=self.cache_control(context)
                    require(allocation.get('actual_caller_return_observed') and allocation['control']==control and
                        0<requested<=allocation['requested_bytes'] and
                        any(row['context']==hex(context) and row['stream']==hex(handle) for row in self.font_stream_owners),
                        'Original font read lacks exact live payload/context/parser/stream binding')
                    row=dict(context=context,control=control,handle=handle,pointer=pointer,requested_bytes=requested,
                        allocation_index=self.cache_allocations.index(allocation),SP=sp,LR=caller,actual_caller_return_observed=False)
                    self.cache_read_bindings.append(row);self.cache_read_pending.append(row)
            if FONT_IO.get(address)=='read' and uc.reg_read(REGS[0]) in self.external_files:
                handle,pointer,count=[uc.reg_read(r)for r in REGS[:3]];entry=self.external_files[handle]
                available=min(count,len(self.raw_font_sources[entry['path']])-entry['position'])
                if CACHE_LOW<=pointer<CACHE_HIGH and available>0:
                    bindings=[row for row in self.cache_read_pending if row['handle']==handle and row['pointer']<=pointer and
                        pointer+available<=row['pointer']+row['requested_bytes']]
                    require(len(bindings)==1,'Lower font read does not match its unique original stream request')
                    binding=bindings[0];allocation=self.cache_allocations[binding['allocation_index']]
                    require(allocation['control']==self.cache_control(binding['context']) and not allocation['freed'] and
                        self.cache_live.get(allocation['pointer']) is allocation,'Lower font read context/live generation differs')
                    self.map_verified_file_destination(pointer,available)
                    before=bytes(uc.mem_read(pointer,available));offset=entry['position']
                    result=super().observe(uc,address,size,data)
                    payload=bytes(uc.mem_read(pointer,available))
                    self.journal_cache(pointer,payload,before,'raw_exact_backup_file_input',handle=hex(handle),path=entry['path'],
                        file_offset=offset,input_sha256=hashlib.sha256(payload).hexdigest())
                    return result
        return super().observe(uc,address,size,data)

    def original_call(self,LR):
        # Direct Thumb BL ends at LR-1, ARM BL at LR; decode only exact MAIN.
        high=LR&~1;low=high-4
        opcode=self.stock.read(low,4)
        ins=list(self.store_disassemblers[bool(LR&1)].disasm(opcode,low,count=1))
        require(len(ins)==1 and ins[0].size==4 and ins[0].mnemonic in ['bl','blx'] and
                bytes(self.uc.mem_read(low,4))==opcode,'Native font allocation/free caller lacks exact MAIN BL')
        return opcode,ins[0].mnemonic+' '+ins[0].op_str,low

    def map_verified_file_destination(self,pointer,length):
        require(length>0 and pointer+length<=0x100000000,'Invalid complete font chunk')
        high=pointer+length;ownership=None
        if ownership is None and self.running_task==self.controller and self.uc.reg_read(UC_ARM_REG_SP)<=pointer and high<=self.controller:
            ownership='actual_live_controller_font_call_stack_slice'
        if ownership is None and CACHE_LOW<=pointer and high<=CACHE_HIGH:
            bindings=[row for row in self.cache_read_pending if row['pointer']<=pointer and
                high<=row['pointer']+row['requested_bytes']]
            require(len(bindings)==1,'Font cache input lacks one active original read request')
            binding=bindings[0];allocation=self.cache_allocations[binding['allocation_index']]
            require(not allocation['freed'] and self.cache_live.get(allocation['pointer']) is allocation and
                allocation['pointer']<=pointer and high<=allocation['pointer']+allocation['requested_bytes'] and
                self.word(allocation['pointer']-4)==allocation['units'],
                'Font cache input overlaps header/padding/released or adjacent native allocation')
            ownership='original_live_native_cache_payload_and_context_parser_stream_read_binding'
        require(ownership is not None,'Font input chunk lacks exact font/cache/active-stack ownership')
        protected=[]
        for task in self.native_TCBs:
            protected.append((task,task+108,'live_native_TCB'))
            if task!=self.controller:
                frame=self.word(task+12);protected.append((frame,frame+52,'resident_native_saved_frame'))
        protected.extend((p,p+24,'registered_native_semaphore') for p in self.native_semaphores)
        protected.extend((control,control+620,'live_native_font_cache_control') for control in set(self.cache_contexts.values()))
        for row in self.font_stream_owners:
            parser=int(row['parser'],16);context=int(row['context'],16)
            protected.extend([(parser,parser+152,'live_native_font_parser'),(context,context+100,'live_native_font_context')])
        protected.extend([(0x14b3c60,0x14b3c60+64*13,'original_font_metadata'),
            (0x14b4014,0x14b4014+816*13,'original_font_records')])
        for start,length in self.zones.items():
            if length==20:protected.append((start,start+20,'resident_native_timed_thread_node'))
        protected.extend([(driver.CONFIG,driver.CONFIG+76,'companion_config'),
            (driver.OUTPUT,driver.OUTPUT+80,'companion_result'),
            (driver.COMP_BASE,driver.COMP_BSS+4096,'companion_code_and_BSS')])
        for low,end,name in protected:
            require(not (pointer<end and low<high),'Raw font input overlaps '+name)
        ExternalFontVM.map_verified_file_destination(self,pointer,length)
        cursor=pointer;coverage=[]
        for low,end,flags in sorted(self.uc.mem_regions()):
            if end<cursor:continue
            if cursor>=high:break
            require(low<=cursor and flags&unicorn.UC_PROT_WRITE,'Font chunk has a page gap or nonwritable segment')
            stop=min(end+1,high)
            coverage.append(dict(low=hex(cursor),high_exclusive=hex(stop),region=[hex(low),hex(end)],permissions=flags))
            cursor=stop
        require(cursor==high,'Font chunk writable page coverage incomplete')
        self.font_destination_provenance=ownership
        self.font_span_coverages.append(dict(pointer=hex(pointer),bytes=length,ownership=ownership,
            contiguous_writable_segments=coverage,native_critical_storage_excluded=True))

    def verify_component_memory(self,voice,exports,dbsha):
        result=super().verify_component_memory(voice,exports,dbsha)
        require(self.cache_reader_route_pending is None and not self.cache_alloc_pending and not self.cache_returns_pending and not self.cache_free_pending and not self.cache_read_pending and
            all(row.get('actual_caller_return_observed') for row in self.cache_allocations) and
            all(row.get('actual_caller_return_observed') for row in self.cache_read_bindings),
            'Original cache allocation/free/read continuations incomplete')
        expected=bytearray(CACHE_BYTES)
        for row in self.cache_journal:
            offset=row['address']-CACHE_LOW
            require(expected[offset:offset+row['bytes']].hex()==row['before_hex'],'Independent whole-cache replay missed mutation')
            expected[offset:offset+row['bytes']]=bytes.fromhex(row['after_hex'])
        require(expected==self.cache_expected,'Independent cache replay differs from observer')
        covered=[]
        for low,end,flags in self.uc.mem_regions():
            begin,stop=max(low,CACHE_LOW),min(end+1,CACHE_HIGH)
            if begin<stop:
                require(bytes(self.uc.mem_read(begin,stop-begin))==bytes(expected[begin-CACHE_LOW:stop-CACHE_LOW]),
                        'Whole original cache differs from native CPU/raw input history')
                covered.append((begin,stop))
        cursor=CACHE_LOW
        for begin,stop in sorted(covered):
            require(not any(expected[cursor-CACHE_LOW:begin-CACHE_LOW]),'Modified font cache span remains unmapped')
            cursor=stop
        require(not any(expected[cursor-CACHE_LOW:]),'Modified font cache tail remains unmapped')
        descriptors=json.loads((ROOT/'staging/native-player-settings-vfp-context/gui-static/controller-gir-native-integration-contract.json').read_text())['font_input_table']['descriptors']
        external={0:'05',1:'06',2:'01',7:'07',8:'08',9:'02',10:'03',12:'04'}
        for row in self.font_inventory:
            index=row['index'];descriptor=descriptors[index]
            require(row['metadata']==hex(0x14b3c60+64*index) and row['record']==hex(0x14b4014+816*index) and
                    row['source_metadata']==row['metadata'] and row['name']==str(index),
                    'Original font record/metadata/index publication differs')
            active=index not in [6,11]
            require(row['metadata_flags']==[descriptor['kind'],int(active)] and
                    row['context_error']==('0x0' if active else '0x66'),
                    'Original present/embedded/missing font activation differs')
            if index in external:
                owners=[w for w in self.font_stream_owners if w['context']==row['context']]
                require(len(owners)==1,'Active external font lacks unique parser/stream owner')
                stream=int(owners[0]['stream'],16);entry=self.external_files[stream]
                require(not entry['closed'] and entry['path']=='0:/.System/ExtData/006-D0952-'+external[index]+'.bin',
                        'Fresh native external font index/path ownership differs')
        require(self.word(0xf071f0)==0x14b5004,'Original selected font record differs')
        result.update(full_original_font_activation_index_path_and_selector_checked=True,
            font_span_coverages=self.font_span_coverages,raw_font_callbacks_avoid_native_critical_storage=True,
            whole_original_shared_font_cache_replayed=True,whole_original_cache_bytes=CACHE_BYTES,
            native_cache_CPU_store_count=self.cache_CPU_store_count,cache_journal=self.cache_journal,
            original_cache_control_witnesses=self.cache_control_witnesses,native_cache_allocations=self.cache_allocations,
            native_cache_read_bindings=self.cache_read_bindings)
        result['original_cache_reader_frame_witnesses']=self.cache_reader_route_witnesses
        return result

def main():
    STAGE.mkdir(parents=True,exist_ok=True)
    require(not (STAGE/'observer-at-run.py').exists(),'Preserve previous contiguous observer run')
    source=Path(__file__).resolve();deps={}
    previous=json.loads((ROOT/'staging/native-player-controller-gir-integration/previous-audit.json').read_text())
    deps.update(previous['protected_sources'])
    for path in ['scripts/probe_native_controller_gir_component.py',str(source.relative_to(ROOT)),
                 'staging/native-player-controller-gir-integration/runtime/terminal-metadata.json',
                 'staging/native-player-controller-gir-integration/resource-static/font-provider-SQL-peer-review.json',
                 'staging/native-player-controller-gir-integration/resource-static/font-stream-owner-supplement.json',
                 'staging/native-player-controller-gir-integration/resource-static/font-cache-span-preflight.json',
                 'staging/native-player-controller-gir-integration/gui-static/native-runner-static-review-024714df092f.json']:
        deps[path]=sha(path)
    for path,digest in deps.items():require(sha(path)==digest,'Protected source differs '+path)
    (STAGE/'observer-at-run.py').write_bytes(source.read_bytes())
    dump(STAGE/'observer-inputs-before-run.json',dict(source=str(source.relative_to(ROOT)),source_sha256=deps,
        driver='scripts/probe_native_controller_gir_component.py',driver_sha256=sha('scripts/probe_native_controller_gir_component.py'),
        original_shared_font_cache_span=[hex(CACHE_LOW),hex(CACHE_HIGH)],
        raw_file_inputs_require_single_live_native_requested_payload_and_original_stream_binding=True,
        whole_cache_CPU_and_raw_input_chronological_replay_required=True,device_io=False,sounds_emitted=False))
    driver.ControllerGIRVM=ContiguousFontControllerGIRVM;driver.STAGE=STAGE
    try:driver.main()
    finally:
        vm=ContiguousFontControllerGIRVM.last_VM
        if vm is not None:
            dump(STAGE/'actual-observer-state.json',dict(updated_utc=datetime.now(timezone.utc).isoformat(),
                observer_sha256=sha(str(source.relative_to(ROOT))),driver_sha256=sha('scripts/probe_native_controller_gir_component.py'),
                memory_regions=[dict(low=hex(lo),high=hex(hi),permissions=flags) for lo,hi,flags in vm.uc.mem_regions()],
                font_span_coverages=vm.font_span_coverages,actual_final_FPU_state=vm.lazy.snapshot(),
                original_cache_control_witnesses=vm.cache_control_witnesses,native_cache_allocations=vm.cache_allocations,
                native_cache_alloc_pending=vm.cache_alloc_pending,native_cache_free_pending=vm.cache_free_pending,
                native_cache_returns_pending=vm.cache_returns_pending,
                native_cache_read_bindings=vm.cache_read_bindings,native_cache_read_pending=vm.cache_read_pending,
                native_cache_reader_frame_witnesses=vm.cache_reader_route_witnesses,
                native_cache_reader_route_pending=vm.cache_reader_route_pending,
                native_cache_CPU_store_count=vm.cache_CPU_store_count,whole_cache_journal=vm.cache_journal,
                native_critical_font_storage_excluded=True,device_io=False,sounds_emitted=False))

if __name__=='__main__':main()
