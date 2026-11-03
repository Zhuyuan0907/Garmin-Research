#!/usr/bin/env python3
"""Integrate the frozen stock-GIR preparation component on native controller.

All native heap/settings/kernel code remains intact. The new RX companion,
its argument/output/BSS storage, readonly font/SQL providers and architectural
exception inputs are declared offline fixtures, never an installed App.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, struct, sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_CPSR,UC_ARM_REG_R4,UC_ARM_REG_R5
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_settings_lazy_vfp_v2 import LazySettingsVM
from probe_native_heap_settings_boot import WORK,EXTENT
from probe_native_kernel_context import POST,WAIT,CODE,CONTROLLER_STACK,IDLE_STACK
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import GIR
from emulate_native_player_menu_selection import DATABASE
from emulate_native_player_external_fonts import FONT_IO
from emulate_native_vpm_filesystem import REGS,RETURN,require

STAGE=ROOT/'staging/native-player-controller-gir-integration/runtime'
COMPONENT='staging/controller-gir-prep-stock-v2/verification.json'
COMP_BASE=0x0ea10000
COMP_BSS=0x0ea11000
ARGS=0x18320000
CONFIG=ARGS+0x40
OUTPUT=ARGS+0x100

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def dump(path,value):
    with path.open('x') as out:json.dump(value,out,ensure_ascii=False,indent=2);out.write('\n')

class ControllerGIRVM(LazySettingsVM):
    def __init__(self,stock,build):
        self.component_active=False;self.component_calls=[];self.component_nested_calls=[];self.component_input_stores=[]
        self.font_raw_input_ledger=[];self.font_raw_pending=None
        self.font_stream_owners=[];self.font_stream_wrapper_observations=[]
        self.gui_store_rows=[];self.component_ranges=[]
        super().__init__(stock,build)
        manifest=json.loads((ROOT/COMPONENT).read_text())
        for path,digest in manifest['source_sha256'].items():require(sha(path)==digest,'Companion dependency changed '+path)
        require(sha(manifest['flat_binary'])==manifest['flat_binary_sha256'],'Companion flat bytes differ')
        self.comp_bytes=(ROOT/manifest['flat_binary']).read_bytes()
        require(len(self.comp_bytes)==2412 and manifest['symbols']['cg_controller_prepare']['address']==COMP_BASE+0x4c,'Exact companion entry differs')
        require(bytes(self.uc.mem_read(COMP_BASE,8192))==b'\0'*8192 and
                all(not (p<=COMP_BASE+8191 and COMP_BASE<=p+entry['length']-1) for p,entry in self.raw_allocations.items()),
                'Companion reservation overlaps occupied transition input storage')
        self.uc.mem_write(COMP_BASE,b'\xcc'*4096);self.uc.mem_write(COMP_BASE,self.comp_bytes)
        self.uc.mem_write(COMP_BSS,b'\xa5'*4096);self.uc.mem_write(COMP_BSS,b'\0'*4)
        self.uc.mem_protect(COMP_BASE,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        require(not any(lo<=ARGS+4095 and ARGS<=hi for lo,hi,_ in self.uc.mem_regions()),'Companion arguments overlap prior mapping')
        self.uc.mem_map(ARGS,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.mem_write(ARGS,b'\xa5'*4096);self.uc.mem_write(OUTPUT,b'\xcc'*80)
        config=[0x13520800,76,15,0x9503f90,0x9500040,0x9503f90,GIR,len(self.resource_bytes),
                self.resource_directory_bytes,GIR,GIR+len(self.resource_bytes),0x08800000,0x08c00000,
                0x18001000,0x18009000,0x084c0000,0x7f135201,12,0]
        self.config_bytes=struct.pack('<19I',*config)
        self.uc.mem_write(CONFIG,self.config_bytes)
        self.component_ranges=[(CONFIG,CONFIG+76),(OUTPUT,OUTPUT+80),(COMP_BSS,COMP_BSS+4)]
        self.zones[ARGS]=4096;self.zones[COMP_BSS]=4096;self.zones[0x34f7000]=4096
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.observe_SQL_provider_store)
        self.RAW_CALLS[0x3009a0,0x11c510]=dict(pointer=0x34f773c,tag=0x41b544,
            reviewed_original_GIR_outer_raw_guard=True)
        self.RAW_CALLS[0x3008b0,0x41ccd2]=dict(pointer=0x34f773c,tag=0x41b544,
            reviewed_original_GIR_outer_raw_guard=True)
        self.gui_bank_base=0x05400000
        self.gui_bank_before=bytes(self.initial_regions[self.gui_bank_base])
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.journal_gui_write,begin=self.gui_bank_base,
            end=self.gui_bank_base+len(self.gui_bank_before)-1)
        self.external_IO_active=True
        self.component_manifest=manifest
        self.helper_entries=[0x2ca82c,0x2cabbc,0x395980,0x2db540,0x25dc80,0x41cc46,
            0x41b15a,0x4df248,0x4de236,0x4a388a,0x316276]
        self.helper_return_pairs=dict(zip(self.helper_entries,[0xea10264,0xea102dc,0xea10380,0xea103dc,
            0xea10438,0xea104bc,0xea10534,0xea10654,0xea106b4,0xea10724,0xea107e8]))

    def declared_storage(self,pointer,length):
        value=super().declared_storage(pointer,length)
        if value:return value
        if any(lo<=pointer and pointer+length<=hi for lo,hi in getattr(self,'component_ranges',[])):
            return 'explicit_guarded_companion_argument_output_or_BSS'
        return None

    def observe_SQL_provider_store(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        if not self.component_active or pc not in [0xea108b0,0xea108b8]:return
        row=self.component_input_stores[-1]
        require((row['PC'],row['address'],row['size'],row['value'])==(hex(pc),hex(address),size,value),
                'Companion SQL CPU store differs from admitted lower input')
        opcode=struct.pack('<I',0xe5c01000 if pc==0xea108b8 else 0xe5801000)
        require(bytes(uc.mem_read(pc,4))==opcode and self.comp_bytes[pc-COMP_BASE:pc-COMP_BASE+4]==opcode,
                'Companion SQL provider store opcode differs')
        row['actual_CPU_store_observed']=True;row['opcode_hex']=opcode.hex()

    def original_store(self,pc,thumb):
        address=pc
        copies=[row for row in self.stock.copies if row['runtime_start']<=pc and pc+4<=row['runtime_end']]
        if copies:address=self.stock.runtime_to_load(pc,4)
        opcode=self.stock.read(address,4)
        instructions=list(self.store_disassemblers[thumb].disasm(opcode,pc,count=1))
        require(len(instructions)==1,'Original writer has no exact instruction')
        ins=instructions[0]
        require(bytes(self.uc.mem_read(pc,ins.size))==opcode[:ins.size] and ins.mnemonic.startswith(('str','stm','swp')),
                'Original writer is not an exact mapped MAIN store')
        return opcode[:ins.size],ins.mnemonic+' '+ins.op_str,address

    def journal_gui_write(self,uc,access,address,size,value,data):
        if not self.component_active:return
        pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)
        allowed={(0x551c7f8,4,1,0x385450),(0x551c80c,4,1,0x385450),
                 (0x551c800,4,1,0x385450),(0x551c804,4,0xc035f8,0x26de42),
                 (0x551c808,4,0x3aaed08,0x26de6c),(0x551c804,4,0xc0fd70,0x344e22),
                 (0x551c7fc,4,1,0x385450)}
        require((address,size,value,pc) in allowed,'Original GUI writer outside reviewed exact tuple')
        opcode,ins,load=self.original_store(pc,thumb)
        self.gui_store_rows.append(dict(PC=hex(pc),load_PC=hex(load),address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),opcode_hex=opcode.hex(),original_instruction=ins))

    def journal_zone_write(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        if not self.zone_active or not (COMP_BASE<=pc<COMP_BASE+len(getattr(self,'comp_bytes',b''))):
            return super().journal_zone_write(uc,access,address,size,value,data)
        require(not uc.reg_read(UC_ARM_REG_CPSR)&32 and self.running_task==self.controller and size in [1,4],
                'Companion store actor/ARM mode/size differs')
        offset=pc-COMP_BASE;opcode=self.comp_bytes[offset:offset+4]
        require(bytes(uc.mem_read(pc,4))==opcode,'Companion writer opcode changed')
        ins=list(self.store_disassemblers[False].disasm(opcode,pc,count=1))[0]
        require(ins.mnemonic.startswith('str') and
                ((OUTPUT<=address and address+size<=OUTPUT+80) or (address==COMP_BSS and size==4 and value==1)),
                'Companion writes outside exact result or first-start BSS')
        zone=next(row for start,row in self.zone_rows.items() if start<=address and address+size<=start+row['bytes'])
        zone['stores'].append(dict(PC=hex(pc),address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),phase=self.phase,running_task=hex(self.running_task),Thumb=False,
            original_instruction=ins.mnemonic+' '+ins.op_str,opcode_hex=opcode.hex(),writer_kind='frozen_ARM_companion'))

    def map_verified_file_destination(self,pointer,length):
        require(length>0 and pointer+length<=0x100000000,'Invalid raw font callback span')
        live=None
        for entry in self.handles.values():
            if not entry['freed'] and entry['pointer']<=pointer and pointer+length<=entry['pointer']+entry['length']:
                live='live_guarded_opaque_font_allocation';break
        if live is None:
            for base,entry in self.raw_allocations.items():
                if not entry['freed'] and base<=pointer and pointer+length<=base+entry['length']:
                    live='live_guarded_raw_font_allocation';break
        if live is None and self.running_task==self.controller and self.uc.reg_read(UC_ARM_REG_SP)<=pointer and pointer+length<=self.controller:
            live='actual_live_controller_stack_slice'
        if live is None:
            require(any(row['runtime_start']<=pointer and pointer+length<=row['runtime_end'] for row in self.stock.zeros),
                    'Mapped font destination still lacks whole-span provenance')
            live='verified_original_zero_BSS_span'
        super().map_verified_file_destination(pointer,length)
        require(any(lo<=pointer and pointer+length-1<=hi and flags&unicorn.UC_PROT_WRITE for lo,hi,flags in self.uc.mem_regions()),
                'Font lower input destination is not writable')
        self.font_destination_provenance=live

    def observe(self,uc,address,size,data):
        caller=uc.reg_read(UC_ARM_REG_LR)&~1
        if self.component_active:
            if address in self.helper_entries:
                row=dict(entry=hex(address),caller=hex(caller),SP=hex(uc.reg_read(UC_ARM_REG_SP)),
                    arguments=[hex(uc.reg_read(r)) for r in REGS],returned=False)
                if caller==self.helper_return_pairs[address]:
                    require(self.running_task==self.controller==self.word(0xf09090),'Companion helper entered on wrong task')
                    self.component_calls.append(row)
                    print(json.dumps(dict(phase='component_original_helper',**row)),flush=True)
                else:self.component_nested_calls.append(row)
            for row in reversed(self.component_calls):
                if not row['returned'] and address==int(row['caller'],16):
                    row.update(returned=True,result=hex(uc.reg_read(REGS[0])),return_SP=hex(uc.reg_read(UC_ARM_REG_SP)))
                    break
            if address==0x265526:
                parser,context=uc.reg_read(UC_ARM_REG_R4),uc.reg_read(UC_ARM_REG_R5)
                handle=self.word(parser+8)
                require(handle in self.external_files and not self.external_files[handle]['closed'] and
                        self.declared_storage(parser,0x98),'Original parser stream store lacks live backing')
                require(bytes(uc.mem_read(0x265524,2))==self.stock.read(0x265524,2),'Original parser store opcode differs')
                self.font_stream_owners.append(dict(context=hex(context),parser=hex(parser),stream=hex(handle),
                    original_store='0x265524',original_store_observed_after_execution=True))
            if address==0x14f084:
                context,handle=[uc.reg_read(r)for r in REGS[:2]]
                self.font_stream_wrapper_observations.append(dict(context=hex(context),stream=hex(handle),caller=hex(caller)))
            if address in [0x3009a0,0x3008b0] and caller in [0x11c510,0x41ccd2]:
                p=self.controller-40
                require(self.word(p-24)==0x34f773c and
                        uc.reg_read(UC_ARM_REG_SP)==p-(56 if address==0x3009a0 else 48),
                        'GIR RAII/raw semaphore stack differs from actual component frame')
            if address==0x2dc954 and caller==0x6f8364:
                args=[uc.reg_read(r)for r in REGS]
                require(0<args[0]<=0x100000 and args[1:3]==[1,8],'Unexpected transition allocation')
                pointer=self.next_transition_buffer
                if pointer-32<COMP_BSS+4096 and COMP_BASE<pointer+args[0]+32:
                    pointer=COMP_BSS+4096+32
                self.next_transition_buffer=pointer+((args[0]+127)&~63)
                require(self.next_transition_buffer<0x0f000000,'Transition fixture exhausted excluding companion')
                uc.mem_write(pointer-32,b'\xa5'*(args[0]+64))
                self.raw_allocations[pointer]=dict(length=args[0],freed=False,service=hex(address))
                self.transition_heap_requests.append(dict(native_allocator=hex(address),caller=hex(caller),
                    pointer=hex(pointer),requested_bytes=args[0],companion_reservation_excluded=True))
                self.visits[address]+=1;self.ret(pointer);return
            if address in [0xea108b0,0xea108b8]:
                target,value=uc.reg_read(REGS[0]),uc.reg_read(REGS[1]);n=1 if address==0xea108b8 else 4
                expected=[(0xea108b0,self.menu_pointer()+24,4,0x84c0000),
                          (0xea108b8,self.menu_pointer()+28,1,1),(0xea108b0,0x84c0000,4,0)]
                i=len(self.component_input_stores)
                require(i<3 and (address,target,n,value)==expected[i],'Exact companion SQL provider input order differs')
                self.component_input_stores.append(dict(PC=hex(address),address=hex(target),size=n,value=value,
                    before_hex=bytes(uc.mem_read(target,n)).hex(),writer_kind='frozen_companion_lower_SQL_provider_input'))
            if FONT_IO.get(address)=='read' and uc.reg_read(REGS[0]) in self.external_files:
                handle,destination,count=[uc.reg_read(r)for r in REGS[:3]];entry=self.external_files[handle]
                require(not entry['closed'] and 0<count<=0x100000,'Invalid font stream read')
                raw=self.raw_font_sources[entry['path']];available=min(count,len(raw)-entry['position'])
                require(available>0,'Unexpected EOF font read must be separately admitted')
                self.map_verified_file_destination(destination,available)
                payload=raw[entry['position']:entry['position']+available]
                item=dict(handle=hex(handle),path=entry['path'],offset=entry['position'],destination=hex(destination),bytes=available,
                    whole_span_provenance=self.font_destination_provenance,raw_input_sha256=hashlib.sha256(payload).hexdigest(),
                    before_sha256=hashlib.sha256(bytes(uc.mem_read(destination,available))).hexdigest(),host_raw_file_input=True,
                    decoded_font_bytes_supplied=False)
                value=super().observe(uc,address,size,data)
                require(bytes(uc.mem_read(destination,available))==payload,'Raw font callback payload differs from backup')
                self.font_raw_input_ledger.append(item)
                return value
        return super().observe(uc,address,size,data)

    def verify_component_memory(self,voice,exports,dbsha):
        require(not self.invalid_accesses and not self.native_fatal_entries and not self.audio,'Component fault or unexpected audio')
        oldram=struct.unpack_from('<I',(ROOT/self.build['original_binary']).read_bytes(),4)[0]
        require(bytes(self.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(self.uc.mem_read(STUBS,480))==exports,'Voice/code imports changed')
        for table,names in [('app_component_api',self.build['private_api']),('player_component_api',self.build['player_api'])]:
            require(list(struct.unpack('<'+str(len(names))+'I',self.uc.mem_read(self.symbol(table),4*len(names))))==[self.symbol(n)for n in names],'Private/player API changed')
        require(bytes(self.uc.mem_read(self.build['extension_base'],0x10000))==self.extension_code,'Old RX extension changed')
        expected=bytearray(self.gui_bank_before)
        for row in self.gui_store_rows:
            offset=int(row['address'],16)-self.gui_bank_base
            require(expected[offset:offset+row['size']].hex()==row['before_hex'],'GUI journal missed mutation')
            expected[offset:offset+row['size']]=int(row['value']).to_bytes(row['size'],'little')
        for address,raw in self.initial_regions.items():
            require(bytes(self.uc.mem_read(address,len(raw)))==(bytes(expected) if address==self.gui_bank_base else raw),'Original initialized region changed outside native history')
        require(len(self.gui_store_rows)==len(self.conditional_region_writes),'GUI history missing event')
        for address,raw in self.code_images:require(bytes(self.uc.mem_read(address,len(raw)))==raw,'Original code image changed')
        require(bytes(self.uc.mem_read(COMP_BASE,4096))==self.comp_bytes+b'\xcc'*(4096-len(self.comp_bytes)),'New RX companion changed')
        require(bytes(self.uc.mem_read(CONFIG,76))==self.config_bytes,'Companion readonly arguments changed')
        require(bytes(self.uc.mem_read(GIR,len(self.resource_bytes)))==self.resource_bytes,'Readonly stock GIR changed')
        for pointer,entry in self.raw_allocations.items():self.verify_guard(pointer,entry)
        for entry in self.handles.values():
            p,n=entry['pointer'],entry['length']
            require(bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(p+n,32))==b'\xa5'*32,'Opaque allocation canary changed')
        self.verify_storage_guards();self.verify_descriptor_guards();self.verify_closed_files()
        for bottom in [CONTROLLER_STACK,IDLE_STACK]:require(bytes(self.uc.mem_read(bottom,64))==b'\xa5'*64,'Native controller/idle stack guard changed')
        require(bytes(self.uc.mem_read(0x2d226f4,24))==b'\xa5'*24,'Timer stack guard changed')
        for row in self.GUI_stack_canaries:
            require(bytes(self.uc.mem_read(int(row['bottom'],16),64)).hex()==row['leading64_after_native_fill_hex'],'Original GUI stack guard changed')
        require(bytes(self.uc.mem_read(CODE,8))==struct.pack('<2I',0xeafffffe,0xe12fff1e),'Sentinel code changed')
        rows=list(self.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))
        expected_rows=[(id,0x7f135201,0) if id==12 else (id,icon,size) for id,icon,size in self.database_before]
        require(rows==expected_rows and sha(DATABASE)==dbsha and self.statements and all(row['closed'] for row in self.statements.values()),
                'SQL selected endpoint or original finalizers differ')
        require(len(self.component_input_stores)==3 and all(row.get('actual_CPU_store_observed') for row in self.component_input_stores),
                'Companion SQL provider inputs incomplete')
        catalog=0x34f7730;begin,end,cap=struct.unpack('<3I',self.uc.mem_read(catalog,12))
        require(end-begin==24 and cap>=end and any(not row['freed'] and p<=begin and cap<=p+row['length'] for p,row in self.raw_allocations.items()),
                'Native GIR catalog lacks live actual allocation')
        self.font_inventory=self.fonts()
        require(len(self.font_inventory)==13,'Font inventory count differs')
        for handle in self.font_handles:
            entry=self.handles[handle];p,n=entry['pointer'],entry['length']
            require(entry['locks']==0,'Font lower handle pinning changed')
            if entry['freed']:require(any(int(row['handle'],16)==handle for row in self.font_release_records),'Missing original font free')
            else:require(self.word(p)==handle and 0<self.word(p+4)<=n-8 and any(int(row['handle'],16)==handle for row in self.font_pointer_queries),'Resident font prefix/query differs')
        live=[dict(handle=hex(h),**entry) for h,entry in self.external_files.items() if not entry['closed']]
        require(len(live)==8 and {entry['path'] for entry in live}==set(self.raw_font_sources),'Resident font stream ownership inventory differs')
        for entry in live:
            owners=[row for row in self.font_stream_owners if row['stream']==entry['handle']]
            require(len(owners)==1 and any(row['context']==owners[0]['context'] and
                row['source_metadata']==row['metadata'] for row in self.font_inventory),
                'Resident stream lacks exact original parser/font context ownership')
            require(any(row['stream']==entry['handle'] and row['context']==owners[0]['context']
                        for row in self.font_stream_wrapper_observations),'Original context/stream wrapper not observed')
        return dict(all_scoped_memory_guards_passed=True,selected_SQL_rows=rows,all_SQL_statements_closed=True,
            actual_font_inventory=self.font_inventory,resident_font_streams=live,raw_font_input_ledger=self.font_raw_input_ledger,
            original_parser_stream_owners=self.font_stream_owners,
            GUI_original_write_history=self.gui_store_rows,whole_GUI_region_replayed=True,baseline_not_reset=True,
            readonly_resources_and_code_unchanged=True,hardware_IRQ_or_fullboot_or_App_or_unload_verified=False)

def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(parents=True,exist_ok=True);require(not (STAGE/'terminal-probe.json').exists(),'Preserve original component terminal evidence')
    source=Path(__file__).resolve();build=json.loads((ROOT/BUILD).read_text())
    previous=json.loads((ROOT/'staging/native-player-controller-gir-integration/previous-audit.json').read_text())
    deps=dict(previous['protected_sources'])
    deps[str(source.relative_to(ROOT))]=sha(str(source.relative_to(ROOT)))
    for path,digest in deps.items():require(sha(path)==digest,'Protected source changed '+path)
    (STAGE/'runner-at-run.py').write_bytes(source.read_bytes())
    dump(STAGE/'inputs-before-run.json',dict(source_sha256=deps,component_manifest=COMPONENT,component_manifest_sha256=sha(COMPONENT),
        source=str(source.relative_to(ROOT)),source_snapshot=str((STAGE/'runner-at-run.py').relative_to(ROOT)),device_io=False,sounds_emitted=False))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=sha(str(source.relative_to(ROOT))),
        completed=False,full_scoped_final_guards_passed=False,device_io=False,sounds_emitted=False,physical_App_verified=False)
    vm=None
    try:
        vm=ControllerGIRVM(NativeImage(),build)
        result['phase']='load_and_native_boot';print(json.dumps(dict(phase=result['phase'])),flush=True)
        result['load']=vm.load()
        oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480));dbsha=sha(DATABASE)
        vm.uc.reg_write(UC_ARM_REG_CPSR,(vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        result['kernel']=vm.configure_native_kernel_inventory();vm.kernel_invoke(POST,(vm.timer_task,16))
        vm.kernel_invoke(0x5d2f7d,());D=vm.kernel_invoke(0x5d2131,())
        require(vm.returned and D==0x8800520,'Original singleton did not return')
        result['prior_inventory']=vm.verify_singleton_inventory();result['prior_memory']=vm.verify_memory(voice,exports,dbsha)
        vm.kernel_invoke(WAIT);require(vm.idle_endpoint and vm.running_task==vm.idle,'Background not drained')
        vm.kernel_invoke(POST,(vm.controller,1),stack=vm.idle);require(vm.returned and vm.running_task==vm.controller,'Original controller not resumed')
        before=vm.native_task_inventory();gui_condition=int(vm.native_condition_waits[0]['condition'],16)
        thread=next(t for t in vm.native_TCBs if t not in [vm.controller,vm.idle,vm.timer_task,vm.word(D+0xaa8)])
        timed=vm.timed_thread_inventory(thread);vm.begin_extra_zones(before,timed)
        vm.phase='exit_list_ctor';result['phase']=vm.phase;vm.kernel_invoke(0x3cc57d,(0x2d226b4,))
        vm.phase='heap_ctor';result['phase']=vm.phase;vm.kernel_invoke(0x388b6d,(EXTENT,1,0,0));result['cold_heap']=vm.verify_heap(cold=True)
        vm.phase='settings';result['phase']=vm.phase;vm.kernel_invoke(0x2cbd17,())
        result['settings_native_endpoint']=vm.verify_native_endpoint(gui_condition,before,timed)
        result['settings_memory']=vm.verify_memory(voice,exports,dbsha)
        result['settings_all_scoped_guards_passed']=True
        vm.verify_mutable_scope();vm.verify_extra_zones()
        require(vm.controller==0x9503f90 and bytes(vm.uc.mem_read(CONFIG,76))==vm.config_bytes,'Declared controller config differs')
        vm.component_active=True;vm.phase='native_controller_component';result['phase']=vm.phase
        print(json.dumps(dict(phase=vm.phase)),flush=True)
        status=vm.kernel_invoke(COMP_BASE+0x4c,(CONFIG,OUTPUT))
        result['component_return']=hex(status);result['component_result20']=list(struct.unpack('<20I',vm.uc.mem_read(OUTPUT,80)))
        require(status==1 and result['component_result20'][2]==0x2ffc and result['component_result20'][3]==1,
                'Original helper sequence did not return full compiled component endpoint')
        require(len(vm.component_calls)==11 and all(row['returned'] for row in vm.component_calls),'Native helper return inventory incomplete')
        result['native_endpoint']=vm.verify_native_endpoint(gui_condition,before,timed)
        result['memory']=vm.verify_component_memory(voice,exports,dbsha)
        result['initialized_data_journal']=vm.verify_mutable_scope();result['extra_zones']=vm.verify_extra_zones()
        result.update(completed=True,full_scoped_final_guards_passed=True)
    except Exception as error:
        result.update(error=str(error));print(json.dumps(dict(phase=result.get('phase'),error=str(error))),flush=True)
    if vm is not None:
        result.update(component_calls=vm.component_calls,component_nested_calls=vm.component_nested_calls,
            font_stream_owners=vm.font_stream_owners,font_stream_wrapper_observations=vm.font_stream_wrapper_observations,
            component_SQL_input_stores=vm.component_input_stores,
            font_raw_input_ledger=vm.font_raw_input_ledger,GUI_stores=vm.gui_store_rows,
            native_mutex_operations=vm.native_mutex_runs,backend_initializations=vm.backend_initializations,
            initialized_CPU_store_journal=vm.mutable_cpu_stores,journal_zones=vm.zone_rows,
            actual_FPU_state=vm.lazy.snapshot(),original_lazy_handler_rows=vm.lazy.rows,
            invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,recent=list(vm.recent),
            SQL_statements={hex(p):dict(SQL=row['sql'],bound=row['bound'],closed=row['closed']) for p,row in vm.statements.items()},
            external_files={hex(p):row for p,row in vm.external_files.items()},
            registers={n:hex(vm.uc.reg_read(r)) for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
        vm.db.close()
    result['finished_utc']=datetime.now(timezone.utc).isoformat()
    dump(STAGE/'terminal-probe.json',result)
    print(json.dumps({key:result.get(key) for key in ['completed','phase','error','full_scoped_final_guards_passed','component_return']}),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
