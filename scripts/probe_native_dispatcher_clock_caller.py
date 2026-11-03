#!/usr/bin/env python3
"""Full cold preparation followed by native queued MainMenu Dispatcher work.

No native callback is invoked from the host. Whole prior guards are checked
before publication; subsequent body work adds strictly observed decoder and settings lock/default-store actor and FP
observation. Unsupported boundaries fail with an immutable terminal probe.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
sys.dont_write_bytecode=True
import unicorn
from unicorn.arm_const import *
from analyze_native_sections import ROOT,NativeImage
from analyze_native_loader import IMAGE,STUBS
from probe_native_cold_fp_controller import ColdFPControllerVM,M,NAME,FP_NODE,EXIT_LIST
from probe_native_heap_settings_boot import HeapSettingsVM,EXTENT
from probe_native_kernel_context import CONTROLLER_STACK,IDLE_STACK,STACK_BYTES,POST,WAIT
from probe_native_settings_lazy_vfp_v2 import TRAPSTACK,TRAPBYTES
from probe_native_controller_gir_component import COMP_BASE,CONFIG,OUTPUT,COMPONENT
from probe_native_player_mainmenu import BUILD
from probe_native_lazy_vfp import OWNER
from emulate_native_independent_signal import IndependentSignalVM
from emulate_native_player_menu_selection import DATABASE
from emulate_native_vpm_filesystem import REGS,RETURN,require
from native_dispatcher_multiowner_vfp import NativeDispatcherMultiOwnerVFPState

BASE='staging/native-player-clock-caller/'
STAGE=ROOT/BASE/'runtime'
GUI_SOURCE=BASE+'gui-static/clock_caller_observer_v2.py'
_spec=importlib.util.spec_from_file_location('new_dispatcher_actor_observer',ROOT/GUI_SOURCE)
_module=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_module)
ActorMixin=_module.ClockCallerDispatcherActorObserverMixin

def sha(path):
    digest=hashlib.sha256()
    with (ROOT/path).open('rb') as handle:
        while chunk:=handle.read(8*1024*1024):digest.update(chunk)
    return digest.hexdigest()
def dump(path,doc):
    with path.open('x') as handle:json.dump(doc,handle,ensure_ascii=False,indent=2);handle.write('\n')

class DispatcherBodyVM(ActorMixin,ColdFPControllerVM):
    signal_inventory=IndependentSignalVM.signal_inventory
    def __init__(self,stock,build):
        self.dispatcher_body_active=False;self.dispatcher_task=None;self.dispatcher_callback_SP=None;self.manager_object=None
        self.native_fp=None;self.body_journal_active=False;self.body_zones={};self.body_push=None
        self.signal_chain=[];self.callback_entry_seen=False;self.callback_return_seen=False;self.stop_at_callback=False
        self.body_BSS_inputs=[];self.body_store_decode={};self.body_push_decode={}
        super().__init__(stock,build)
        for page in [0x34f9000,0x3aae000,0x2d16000,0x2d1f000,0x3aaf000]:
            provenance=next((r for r in stock.zeros if r['runtime_start']<=page and page+4096<=r['runtime_end']),None)
            require(provenance,'New manager/cleanup/decoder page lacks original startup-zero provenance')
            if not any(lo<=page and page+4095<=hi for lo,hi,_ in self.uc.mem_regions()):
                self.uc.mem_map(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
                self.body_BSS_inputs.append(dict(page=hex(page),bytes=4096,original_zero_provenance=provenance,
                    initial_mapping_is_declared_input=True,existing_mapped_bytes_reset=False))
        self.init_dispatcher_actor_observer()

    def begin_body_observer(self,D):
        require(not self.body_journal_active and self.running_task==self.controller and self.word(OWNER)==self.controller,
            'Body observer must inherit actual complete cold controller endpoint')
        self.dispatcher_task=self.word(D+0xaa8);dm=self.word(self.dispatcher_task+28);ds=self.word(dm+8)
        require(self.dispatcher_task==0x8804fb8 and dm==0x8800fe0 and ds==0x8801024,'Original Dispatcher metadata/pool inventory differs')
        self.prior_lazy=self.lazy
        tasks={self.controller:dict(metadata=M,pool=CONTROLLER_STACK,minimum_live_SP=CONTROLLER_STACK+4096),
            self.dispatcher_task:dict(metadata=dm,pool=ds,minimum_live_SP=ds+4096)}
        self.native_fp=NativeDispatcherMultiOwnerVFPState(self.uc,self.stock,lambda:self.running_task,
            lambda p,n:bool(self.declared_storage(p,n)),TRAPSTACK+TRAPBYTES-32,tasks,self.prior_lazy,exclusive=False)
        self.lazy=self.native_fp
        for low,n in [(CONTROLLER_STACK,STACK_BYTES),(ds,STACK_BYTES),(0x34f9000,4096),(0x3aae000,4096),(0x2d16000,4096),(0x2d1f000,4096),(0x3aaf000,4096)]:
            self.body_zones[low]=dict(start=hex(low),bytes=n,before_hex=bytes(self.uc.mem_read(low,n)).hex(),stores=[])
            self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.journal_body_store,begin=low,end=low+n-1)
        self.body_journal_active=True

    def native_store(self,pc,thumb):
        key=(pc,thumb)
        if key not in self.body_store_decode:
            load=self.stock.runtime_to_load(pc,4) if any(r['runtime_start']<=pc and pc+4<=r['runtime_end'] for r in self.stock.copies) else pc
            raw=self.stock.read(load,4);ins=list(self.store_disassemblers[thumb].disasm(raw,pc,count=1))
            require(len(ins)==1 and ins[0].mnemonic.startswith(('str','stm','swp','push','vstm','vstr')),'Body writer is outside unchanged original MAIN store scope')
            self.body_store_decode[key]=(load,raw[:ins[0].size],ins[0].mnemonic+' '+ins[0].op_str)
        load,opcode,instruction=self.body_store_decode[key]
        require(bytes(self.uc.mem_read(pc,len(opcode)))==opcode,'Body writer opcode changed')
        return load,opcode,instruction

    def capture_native_push(self,uc,address):
        thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)
        key=(address,thumb)
        if key not in self.body_push_decode:
            try:
                load=self.stock.runtime_to_load(address,4) if any(r['runtime_start']<=address and address+4<=r['runtime_end'] for r in self.stock.copies) else address
                raw=self.stock.read(load,4);ins=list(self.store_disassemblers[thumb].disasm(raw,address,count=1))
            except ValueError:self.body_push_decode[key]=None;return
            self.body_push_decode[key]=(raw[:ins[0].size],ins[0].op_str) if len(ins)==1 and ins[0].mnemonic=='push' else None
        decoded=self.body_push_decode[key]
        if decoded is None:return
        opcode,operands=decoded
        require(bytes(uc.mem_read(address,len(opcode)))==opcode,'Original body push opcode changed')
        mapping={**{'r'+str(i):UC_ARM_REG_R0+i for i in range(13)},'sb':UC_ARM_REG_R9,'sl':UC_ARM_REG_R10,
            'fp':UC_ARM_REG_R11,'ip':UC_ARM_REG_R12,'sp':UC_ARM_REG_SP,'lr':UC_ARM_REG_LR,'pc':UC_ARM_REG_PC}
        names=[name.strip() for name in operands.strip('{}').split(',')]
        require(all(name in mapping for name in names),'Unknown original push register')
        sp=uc.reg_read(UC_ARM_REG_SP);low=sp-4*len(names)
        self.body_push=dict(PC=address,before_SP=sp,expected={low+4*i:uc.reg_read(mapping[name]) for i,name in enumerate(names)})

    def journal_body_store(self,uc,access,address,size,value,data):
        if not self.body_journal_active:return
        zone=next((r for low,r in self.body_zones.items() if low<=address and address+size<=low+r['bytes']),None)
        require(zone is not None and size in [1,2,4,8],'Body store crosses a declared whole-zone')
        pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32);load,opcode,instruction=self.native_store(pc,thumb)
        value &= (1<<(8*size))-1
        if instruction.startswith('push'):
            p=self.body_push;require(p and p['PC']==pc and size==4 and p['expected'].get(address)==value,'Original body stack push lacks actual pre-instruction SP/register binding')
        zone['stores'].append(dict(PC=hex(pc),load_PC=hex(load),Thumb=thumb,address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),opcode_hex=opcode.hex(),original_instruction=instruction,
            running_task=hex(self.running_task),processor_mode=uc.reg_read(UC_ARM_REG_CPSR)&31))

    def journal_zone_write(self,uc,access,address,size,value,data):
        if self.native_fp is not None and self.native_fp.active:
            store=self.native_fp.validate_parent_store(uc,access,address,size,value,data)
            zone=next((r for low,r in self.zone_rows.items() if low<=address and address+size<=low+r['bytes']),None)
            require(store is not None and zone is not None and len(zone['stores'])<20000,'Active FP store crosses prior inherited zone/budget')
            zone['stores'].append(dict(store,phase=self.phase,running_task=hex(self.running_task)));return
        if self.body_journal_active:
            pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32);load,opcode,instruction=self.native_store(pc,thumb)
            if instruction.startswith(('push','vstr','vstm')):
                zone=next((r for low,r in self.zone_rows.items() if low<=address and address+size<=low+r['bytes']),None)
                require(zone is not None and size in [1,2,4,8],'Original body extended store crosses inherited zone')
                if instruction.startswith('push'):
                    p=self.body_push;require(p and p['PC']==pc and size==4 and p['expected'].get(address)==value,'Consumed original Dispatcher frame push binding differs')
                zone['stores'].append(dict(PC=hex(pc),address=hex(address),size=size,value=value&((1<<(8*size))-1),
                    before_hex=bytes(uc.mem_read(address,size)).hex(),phase=self.phase,running_task=hex(self.running_task),
                    Thumb=thumb,original_instruction=instruction,opcode_hex=opcode.hex(),load_PC=hex(load)));return
        return super().journal_zone_write(uc,access,address,size,value,data)

    def observe(self,uc,address,size,data):
        if self.body_journal_active:self.capture_native_push(uc,address)
        if self.kernel_active and address in [0x4b571c,0x5d28fe,0x37bce4,0x52353c,0x609338,0x574760,0x405340,0x4053e4,0x60935c]:
            self.signal_chain.append(dict(entry=hex(address),running_task=hex(self.running_task),ready_head=hex(self.word(0xf09090)),
                SP=hex(uc.reg_read(UC_ARM_REG_SP)),LR=hex(uc.reg_read(UC_ARM_REG_LR)),arguments=[hex(uc.reg_read(r)) for r in REGS]))
        if address==0x405340 and self.body_journal_active:
            require(self.running_task==self.dispatcher_task==self.word(0xf09090) and uc.reg_read(UC_ARM_REG_LR)==0x60935d and
                uc.reg_read(UC_ARM_REG_SP)==0x8804f78,'Actual original Dispatcher callback actor/SP/LR differs')
            self.callback_entry_seen=True;self.dispatcher_callback_SP=uc.reg_read(UC_ARM_REG_SP)
            if self.stop_at_callback:uc.emu_stop();return
            self.dispatcher_body_active=True
        if address==0x60935c and self.dispatcher_body_active:
            require(self.running_task==self.dispatcher_task and uc.reg_read(UC_ARM_REG_SP)==self.dispatcher_callback_SP,
                'Original callback did not return to actual Dispatcher caller/frame')
            self.callback_return_seen=True
        if self.dispatcher_body_active and self.observe_dispatcher_actor(uc,address,size,data):return
        return super().observe(uc,address,size,data)

    def resume_same_native_work(self,start,callback_only=False):
        current=start
        for quantum in range(48):
            try:self.uc.emu_start(current,RETURN+2,count=3000000,timeout=15000000)
            except unicorn.UcError as error:
                if error.errno!=unicorn.UC_ERR_INSN_INVALID:
                    self.unexpected_emulation_UcErrors.append(dict(errno=error.errno,error=str(error),PC=hex(self.uc.reg_read(UC_ARM_REG_PC))));raise
                current=self.lazy.enter(error)
                print(json.dumps(dict(phase='actual_native_multiowner_FP',fault=self.lazy.rows[-1]['before'])),flush=True);continue
            if self.returned or self.idle_endpoint or callback_only and self.callback_entry_seen:return
            pc=self.uc.reg_read(UC_ARM_REG_PC);current=pc|1 if self.uc.reg_read(UC_ARM_REG_CPSR)&32 else pc&~1
            print(json.dumps(dict(phase='resume_same_actual_native_dispatch',PC=hex(pc),quantum=quantum+1)),flush=True)
        raise AssertionError('Actual original Dispatcher work exceeded declared observation quanta')

    def verify_body_zones(self):
        result=[]
        for low,row in self.body_zones.items():
            expected=bytearray.fromhex(row['before_hex'])
            for store in row['stores']:
                offset=int(store['address'],16)-low;n=store['size']
                require(expected[offset:offset+n].hex()==store['before_hex'],'Body history missed an intervening mutation')
                expected[offset:offset+n]=store['value'].to_bytes(n,'little')
            actual=bytes(self.uc.mem_read(low,row['bytes']));require(actual==expected,'Whole native body zone differs from original CPU history')
            result.append(dict(row,after_sha256=hashlib.sha256(actual).hexdigest(),whole_zone_replayed=True))
        return result

def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(parents=True,exist_ok=True);require(not (STAGE/'runner-at-run.py').exists(),'Preserve native body terminal run')
    import os
    print(json.dumps(dict(phase='preflight',PID=os.getpid(),new_clock_caller=True)),flush=True)
    source=Path(__file__).resolve();deps=dict(json.loads((ROOT/BASE/'previous-audit.json').read_text())['protected_sources'])
    for path in [str(source.relative_to(ROOT)),GUI_SOURCE,'scripts/native_dispatcher_multiowner_vfp.py',BASE+'gui-static/clock-caller-observer-v2-contract.json','scripts/seal_native_inline_fields_attempt.py']:deps[path]=sha(path)
    for path,digest in deps.items():require(sha(path)==digest,'Protected source differs '+path)
    (STAGE/'runner-at-run.py').write_bytes(source.read_bytes())
    dump(STAGE/'inputs-before-run.json',dict(source_sha256=deps,device_io=False,sounds_emitted=False,original_MAIN_patch_bytes=0,
        explicit_native_API_Signal_publication_not_host_direct_callback=True))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=sha(str(source.relative_to(ROOT))),
        phase='constructor',completed=False,cold_prefix_full_guards_passed=False,body_full_guards_passed=False,device_io=False,sounds_emitted=False)
    vm=None
    try:
        vm=DispatcherBodyVM(NativeImage(),json.loads((ROOT/BUILD).read_text()));result['phase']='load_and_cold_kernel'
        print(json.dumps(dict(phase=result['phase'])),flush=True);result['load']=vm.load()
        oldram=struct.unpack_from('<I',(ROOT/vm.build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480));dbsha=sha(DATABASE)
        vm.uc.reg_write(UC_ARM_REG_CPSR,(vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        result['kernel']=vm.configure_native_kernel_inventory()
        require(vm.word(OWNER)==0 and vm.uc.reg_read(UC_ARM_REG_FPEXC)==0x40000000 and vm.uc.reg_read(UC_ARM_REG_C1_C0_2)==0xf00000,'Cold FP startup differs')
        require(bytes(vm.uc.mem_read(FP_NODE,16))==bytes(16),'Cold listener already initialized')
        vm.pre_FP_boot_TCB108=bytes(vm.uc.mem_read(vm.controller,108))
        vm.phase='cold_exit_list_ctor';result['phase']=vm.phase;vm.kernel_invoke(0x3cc57d,(EXIT_LIST,))
        vm.phase='cold_FP_boot';result['phase']=vm.phase;vm.kernel_invoke(0x20ed68,());result['cold_boot']=vm.seal_cold_boot()
        vm.phase='native_GUI_boot';result['phase']=vm.phase;vm.kernel_invoke(POST,(vm.timer_task,16))
        vm.kernel_invoke(0x5d2f7d,());D=vm.kernel_invoke(0x5d2131,());require(vm.returned and D==0x8800520,'Original singleton not returned')
        result['prior_inventory']=vm.verify_singleton_inventory();result['prior_memory']=vm.verify_memory(voice,exports,dbsha)
        vm.kernel_invoke(WAIT);require(vm.idle_endpoint and vm.running_task==vm.idle,'Background not drained')
        vm.kernel_invoke(POST,(vm.controller,1),stack=vm.idle);require(vm.returned and vm.running_task==vm.controller,'Controller not resumed')
        before=vm.native_task_inventory();gui_condition=int(vm.native_condition_waits[0]['condition'],16)
        thread=next(t for t in vm.native_TCBs if t not in [vm.controller,vm.idle,vm.timer_task,vm.word(D+0xaa8)])
        timed=vm.timed_thread_inventory(thread);vm.begin_extra_zones(before,timed)
        vm.phase='heap_ctor';result['phase']=vm.phase;vm.kernel_invoke(0x388b6d,(EXTENT,1,0,0));result['cold_heap']=vm.verify_heap(cold=True)
        vm.phase='settings';result['phase']=vm.phase;vm.kernel_invoke(0x2cbd17,())
        result['settings_native_endpoint']=vm.verify_native_endpoint(gui_condition,before,timed)
        result['settings_memory']=vm.verify_memory(voice,exports,dbsha);vm.verify_mutable_scope();vm.verify_extra_zones()
        vm.component_active=True;vm.phase='native_controller_component';result['phase']=vm.phase
        status=vm.kernel_invoke(COMP_BASE+0x4c,(CONFIG,OUTPUT));result['component_return']=hex(status)
        result['component_result20']=list(struct.unpack('<20I',vm.uc.mem_read(OUTPUT,80)))
        require(status==1 and result['component_result20'][2:4]==[0x2ffc,1] and len(vm.component_calls)==11 and all(r['returned'] for r in vm.component_calls),'Cold component not complete')
        result['native_endpoint']=vm.verify_native_endpoint(gui_condition,before,timed);result['memory']=vm.verify_component_memory(voice,exports,dbsha)
        result['initialized_data_journal']=vm.verify_mutable_scope();result['extra_zones']=vm.verify_extra_zones()
        result['initialized_data_journal']['before_hex']=vm.mutable_bank_before.hex()
        result['cold_prefix_full_guards_passed']=True;result['cold_lazy_handler_rows']=list(vm.lazy.rows)
        # Freeze completed prefix histories before body work can append to live
        # lists. This file remains independent of the later terminal outcome.
        result=json.loads(json.dumps(result))
        prefix=dict(result,component_calls=vm.component_calls,whole_cache_journal=vm.cache_journal,
            native_cache_CPU_store_count=vm.cache_CPU_store_count,native_cache_allocations=vm.cache_allocations,
            native_cache_read_bindings=vm.cache_read_bindings)
        dump(STAGE/'cold-prefix-sealed.json',prefix)
        result['cold_prefix_evidence']=str((STAGE/'cold-prefix-sealed.json').relative_to(ROOT))
        result['cold_prefix_evidence_sha256']=sha(result['cold_prefix_evidence'])
        print(json.dumps(dict(cold_prefix_complete=True,all11_helpers_returned=True)),flush=True)
        vm.phase='native_independent_Signal_publication';result['phase']=vm.phase;vm.begin_body_observer(D)
        result['decoder_inputs_after_cold_prefix']=vm.capture_decoder_inputs()
        result['settings_inputs_after_cold_prefix']=vm.capture_dispatcher_settings_inputs()
        retained=vm.signal_inventory(D+0x464);retained_thread=vm.word(D+0x4ba4)
        S=vm.kernel_invoke(0x3954cc,(80,));require(vm.returned and S and S%8==0 and vm.declared_storage(S,80),'Signal80 backing invalid')
        vm.kernel_invoke(0x57458d,(S,));require(vm.returned,'Signal ctor not returned')
        expected=[0xc1b59c,0,0,0,0,0,0,0xc1b5c4,0,0,0,0,0x31041c,0,0,0,0,0,0x46c2c8,0]
        require(bytes(vm.uc.mem_read(S,80))==struct.pack('<20I',*expected),'Original Signal80 ctor differs')
        vm.kernel_invoke(0x4b571d,(S,0x405341));registered=vm.signal_inventory(S)
        require(vm.returned and len(registered['vectors'][0]['entries'])==1 and registered['vectors'][0]['entries'][0]['function']=='0x405341','Native callback registration invalid')
        vm.kernel_invoke(0x5d28ff,(D,S));require(vm.returned and vm.running_task==vm.controller,'Original queue API not returned')
        result['independent_signal']=registered
        vm.stop_at_callback=True;vm.returned=False;vm.idle_endpoint=False
        vm.uc.reg_write(UC_ARM_REG_SP,vm.controller);vm.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        vm.resume_same_native_work(WAIT,callback_only=True)
        require(vm.callback_entry_seen and all(a in [int(r['entry'],16) for r in vm.signal_chain] for a in [0x52353c,0x609338,0x574760,0x405340]),'Native queued Dispatcher callback not reached')
        require(vm.signal_inventory(D+0x464)==retained and vm.word(D+0x4ba4)==retained_thread,'Original cleanup Signal/Thread changed')
        require(vm.timed_thread_inventory(thread)==timed and vm.word(0xf09098)==0,'Timed Thread/clock changed')
        result['callback_entry_inventory']=vm.native_task_inventory();result['callback_entry_timed_thread']=vm.timed_thread_inventory(thread)
        result['callback_entry_owned_signal_mutex24']=bytes(vm.uc.mem_read(S+56,24)).hex()
        result['callback_entry_reached']=True
        vm.stop_at_callback=False;vm.phase='actual_Dispatcher405340_body';result['phase']=vm.phase
        vm.resume_same_native_work(vm.uc.reg_read(UC_ARM_REG_PC)|1)
        require(vm.callback_return_seen and vm.idle_endpoint,'Original MainMenu callback did not complete/drain to idle')
        result['body_actor_guards']=vm.verify_dispatcher_actor_observer();result['body_zones']=vm.verify_body_zones()
        result['FP_zones']=vm.native_fp.verify();result['body_mutable_bank']=vm.verify_mutable_scope()
        result['body_inherited_zones']=HeapSettingsVM.verify_extra_zones(vm)
        result['completed']=True
        # Whole foreground/font/cache/lifecycle/code inventory remains separate.
        result['body_full_guards_passed']=False
    except Exception as error:
        result.update(error=str(error),error_type=type(error).__name__)
        if isinstance(error,unicorn.UcError):result['UcError_errno']=error.errno
        print(json.dumps(dict(phase=result['phase'],error=str(error))),flush=True)
    if vm is not None:
        result.update(mutable_bank_initial_before_hex=vm.mutable_bank_before.hex() if vm.mutable_bank_before is not None else None,
            component_calls=vm.component_calls,cold_boot_zones=vm.cold_zones,cold_fill=vm.cold_fill,
            body_BSS_inputs=vm.body_BSS_inputs,body_zone_journals=vm.body_zones,
            actual_FPU_state=vm.lazy.snapshot(),original_lazy_handler_rows=vm.lazy.rows,
            native_FP_allocations=vm.native_fp.allocations if vm.native_fp else [],
            native_FP_zone_journals=vm.native_fp.zones if vm.native_fp else {},
            body_actor_observations=vm.snapshot_dispatcher_actor_observer(),signal_chain=vm.signal_chain,
            callback_entry_seen=vm.callback_entry_seen,callback_return_seen=vm.callback_return_seen,
            native_mutex_operations=vm.native_mutex_runs,native_restores=vm.kernel_restores,journal_zones=vm.zone_rows,
            native_cache_allocations=vm.cache_allocations,native_cache_read_bindings=vm.cache_read_bindings,
            whole_cache_journal=vm.cache_journal,native_cache_CPU_store_count=vm.cache_CPU_store_count,
            cache_observer_UcErrors=vm.cache_observer_UcErrors,unexpected_emulation_UcErrors=vm.unexpected_emulation_UcErrors,
            invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,recent=list(vm.recent),
            pending_mutex_operations={hex(t):rows for t,rows in vm.task_mutex_ops.items() if rows},
            registers={n:hex(vm.uc.reg_read(r)) for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
        for key,fn in [('partial_body_zone_verification',vm.verify_body_zones),('partial_initialized_bank_verification',vm.verify_mutable_scope),
                       ('partial_inherited_zone_verification',lambda:HeapSettingsVM.verify_extra_zones(vm))]:
            if vm.body_journal_active:
                try:result[key]=fn()
                except Exception as error:result[key]=dict(passed=False,error=str(error))
        if vm.native_fp and vm.native_fp.rows:
            try:result['partial_FP_zone_verification']=vm.native_fp.verify()
            except Exception as error:result['partial_FP_zone_verification']=dict(passed=False,error=str(error))
        vm.db.close()
    result['finished_utc']=datetime.now(timezone.utc).isoformat();dump(STAGE/'terminal-probe.json',result)
    print(json.dumps({k:result.get(k) for k in ['completed','phase','error','cold_prefix_full_guards_passed','callback_entry_reached','body_full_guards_passed']}),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
