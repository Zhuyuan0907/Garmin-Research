#!/usr/bin/env python3
"""Fresh native component run with typed cold task metadata and original FP boot.

No live TCB is patched. Ready membership and undefined exception entry remain
explicit architectural inputs. First/same-owner only; no cross-owner success.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, struct, sys
import unicorn
from unicorn.arm_const import *
from analyze_native_sections import ROOT, NativeImage
from analyze_native_loader import IMAGE, STUBS
from probe_native_controller_gir_cache_declared import DeclaredCacheVM
from probe_native_controller_gir_component import COMP_BASE, CONFIG, OUTPUT, COMPONENT
from native_cold_fp_guard_copies import ColdFPGuardMixin
from probe_native_heap_settings_boot import HeapSettingsVM, EXTENT
from probe_native_kernel_context import CODE, DESCRIPTORS, CONTROLLER_STACK, IDLE_STACK, STACK_BYTES, POST, WAIT
from probe_native_player_mainmenu import BUILD
from probe_native_settings_lazy_vfp_v2 import TRAPSTACK, TRAPBYTES
from probe_native_lazy_vfp import OWNER
from emulate_native_player_menu_selection import DATABASE
from emulate_native_vpm_filesystem import REGS, RETURN, require

BASE = 'staging/native-player-cold-fp-controller/'
STAGE = ROOT/BASE/'runtime'
RECIPE = 'staging/native-player-cache-declared-followup/fp-static/native-multiowner-fp-input-and-journal-recipe.json'
M, NAME, FP_NODE, EXIT_LIST = 0x9400900, 0x9400980, 0x3ab1028, 0x2d226b4

def sha(path): return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def dump(path, doc):
    with path.open('x') as handle: json.dump(doc, handle, ensure_ascii=False, indent=2); handle.write('\n')

class ColdFPControllerVM(ColdFPGuardMixin, DeclaredCacheVM):
    def __init__(self, stock, build):
        self.cold_zones = {}; self.cold_journal_active = False; self.cold_store_decode = {}
        self.cold_fill = None; self.cold_fill_pending = False; self.cold_controller_building = False
        self.FP_boot_registration = None; self.cold_boot_sealed = False; self.cold_typed_ranges = []
        super().__init__(stock, build)
        recipe = json.loads((ROOT/RECIPE).read_text())
        self.cold_inputs = recipe['typed_cold_inputs']
        for row in self.cold_inputs:
            raw = (ROOT/row['path']).read_bytes(); address = int(row['address'], 16)
            require(hashlib.sha256(raw).hexdigest() == row['sha256'] and len(raw) == row['bytes'], 'Cold typed input changed')
            require(bytes(self.uc.mem_read(address, len(raw))) == bytes(len(raw)), 'Cold typed slot occupied')
            self.uc.mem_write(address, raw)
        self.metadata_before = bytes(self.uc.mem_read(M, 40))
        for lo, hi in [(M-32, M+40+32), (NAME-32, NAME+17+32)]:
            for address, length in [(lo,32),(hi-32,32)]:
                require(bytes(self.uc.mem_read(address,length)) == bytes(length), 'Cold guard slot occupied')
                self.uc.mem_write(address,b'\xa5'*length)
            self.cold_typed_ranges.append((lo,hi))
        self.virtual_fp_inputs.update(original_FP_boot20ED68_not_executed=False,
            original_FP_exit_listener_not_registered=False, original_FP_boot_execution_pending=True,
            controller_metadata_is_explicit_cold_boot_input=True, controller_metadata=hex(M))
        self.zones[CONTROLLER_STACK] = 256
        self.zones[M-32] = 104; self.zones[NAME-32] = 81
        for low, length in [(CONTROLLER_STACK, STACK_BYTES), (OWNER&~4095,4096), (EXIT_LIST,64),
                            (M-32,104),(NAME-32,81)]:
            self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.journal_cold_write, begin=low, end=low+length-1)

    def declared_storage(self, pointer, length):
        value = super().declared_storage(pointer,length)
        if value: return value
        if any(lo <= pointer and pointer+length <= hi for lo,hi in self.cold_typed_ranges):
            return 'explicit_typed_cold_metadata_name_and_guard_input'
        return None

    def start_cold_journals(self):
        require(not self.cold_journal_active and not self.cold_zones, 'Cold journals already started')
        for low,length in [(CONTROLLER_STACK,STACK_BYTES),(OWNER&~4095,4096),(EXIT_LIST,64),
                           (M-32,104),(NAME-32,81)]:
            self.cold_zones[low] = dict(start=hex(low),bytes=length,before_hex=bytes(self.uc.mem_read(low,length)).hex(),stores=[])
        self.cold_journal_active = True

    def journal_cold_write(self, uc, access, address, size, value, data):
        if not self.cold_journal_active: return
        zone = next((row for low,row in self.cold_zones.items() if low <= address and address+size <= low+row['bytes']),None)
        require(zone is not None and size in [1,2,4,8], 'Cold CPU store crosses a declared zone')
        pc, thumb = uc.reg_read(UC_ARM_REG_PC), bool(uc.reg_read(UC_ARM_REG_CPSR)&32)
        key = (pc,thumb)
        if key not in self.cold_store_decode:
            load = self.stock.runtime_to_load(pc,4) if any(r['runtime_start']<=pc and pc+4<=r['runtime_end'] for r in self.stock.copies) else pc
            raw = self.stock.read(load,4); instructions = list(self.store_disassemblers[thumb].disasm(raw,pc,count=1))
            require(len(instructions)==1, 'Cold writer has no original instruction')
            ins=instructions[0]
            require(ins.mnemonic.startswith(('str','stm','swp','push')), 'Cold writer is outside original CPU store scope')
            self.cold_store_decode[key]=(load,raw[:ins.size],ins.mnemonic+' '+ins.op_str)
        load, opcode, instruction = self.cold_store_decode[key]
        require(bytes(uc.mem_read(pc,len(opcode)))==opcode, 'Cold writer original opcode changed')
        zone['stores'].append(dict(kind='original_MAIN_CPU_store',PC=hex(pc),load_PC=hex(load),Thumb=thumb,
            address=hex(address),size=size,value=value&((1<<(8*size))-1),before_hex=bytes(uc.mem_read(address,size)).hex(),
            opcode_hex=opcode.hex(),instruction=instruction,phase=self.phase))

    def declare_ready_input(self, address, raw):
        zone=next((row for low,row in self.cold_zones.items() if low<=address and address+len(raw)<=low+row['bytes']),None)
        if zone is not None:
            zone['stores'].append(dict(kind='declared_initial_ready_membership_input',address=hex(address),size=len(raw),
                before_hex=bytes(self.uc.mem_read(address,len(raw))).hex(),value=int.from_bytes(raw,'little')))
        self.uc.mem_write(address,raw)

    def configure_native_kernel_inventory(self):
        require(self.owner_thread is None and not any(self.mutexes.values()), 'Cold kernel configured with active locks')
        self.uc.mem_write(DESCRIPTORS,struct.pack('<5I',CODE,0,IDLE_STACK+STACK_BYTES,240<<16,0))
        require(bytes(self.uc.mem_read(DESCRIPTORS+32,20))==(ROOT/self.cold_inputs[0]['path']).read_bytes(), 'Typed cold descriptor differs')
        self.start_cold_journals()
        before={hex(a):self.word(a) for a in [0xf0908c,0xf09090,0xf09094,0xf090a0]}
        self.idle=self.invoke(0x358bf9,(DESCRIPTORS,))
        self.cold_controller_building=True
        self.controller=self.invoke(0x358bf9,(DESCRIPTORS+32,))
        self.cold_controller_building=False
        require(self.controller==0x9503f90 and self.idle==0x9508f90 and self.cold_fill is not None,
            'Native cold task placement/fill differs')
        require(self.word(self.controller+28)==M and self.word(self.controller+72)==NAME and self.word(self.controller+96)==NAME,
            'Original cold metadata/tag publication differs')
        self.put(0xf09090,self.controller)
        self.declare_ready_input(self.controller,struct.pack('<I',self.idle)); self.put(self.idle,0)
        self.declare_ready_input(self.controller+22,b'\x01'); self.uc.mem_write(self.idle+22,b'\x01')
        self.put(0xf09094,0); self.owner_thread=self.controller; self.kernel_active=True
        self.initialize_native_timer_owner()
        self.kernel_inventory=dict(original_global_words_before=before, original_TCB_builder='0x358bf8',
            controller=hex(self.controller),idle=hex(self.idle),timer=hex(self.timer_task),
            initial_controller_idle_ready_membership_is_fixture=True,original_all_task_list_preserved=True,
            controller_metadata=M,controller_metadata_is_declared_cold_input=True,original_MAIN_instructions_patched=False,
            real_boot_or_physical_task_inventory_verified=False)
        return self.kernel_inventory

    def observe(self, uc, address, size, data):
        if self.cold_controller_building and address==0x3794f0 and (uc.reg_read(UC_ARM_REG_LR)&~1)==0xf6f48:
            require([uc.reg_read(r) for r in REGS[:3]]==[CONTROLLER_STACK,STACK_BYTES,255] and not self.cold_fill_pending,
                'Original controller fill arguments differ')
            self.cold_fill_pending=True
        if address==0xf6f48 and self.cold_fill_pending:
            require(bytes(uc.mem_read(CONTROLLER_STACK,STACK_BYTES))==b'\xff'*STACK_BYTES,'Whole original controller fill differs')
            self.cold_fill=dict(original_entry='0x3794f0',actual_return='0xf6f48',whole16384_FF_checked=True,
                whole_sha256=hashlib.sha256(bytes(uc.mem_read(CONTROLLER_STACK,STACK_BYTES))).hexdigest(),host_filled_stack=False)
            self.cold_fill_pending=False
        if self.phase=='cold_FP_boot' and address==0x3cc5c2:
            require(uc.reg_read(UC_ARM_REG_LR)==0x20eda0 and not self.FP_boot_registration,
                'Original ARM FP boot to Thumb listener call differs')
            require([uc.reg_read(r) for r in REGS]==[EXIT_LIST,FP_NODE,0x7fffffff,0x20edb1] and self.word(uc.reg_read(UC_ARM_REG_SP))==0,
                'Original FP listener arguments differ')
            self.FP_boot_registration=dict(entry='0x3cc5c2',actual_LR='0x20eda0',returned=False)
        if self.phase=='cold_FP_boot' and address==0x20eda0:
            require(self.FP_boot_registration and uc.reg_read(REGS[0])==0 and not uc.reg_read(UC_ARM_REG_CPSR)&32,
                'Original FP listener registration did not return0 in ARM')
            self.FP_boot_registration.update(returned=True,result=0)
        return super().observe(uc,address,size,data)

    def verify_cold_controller_or_idle_boundary(self,bottom):
        if bottom==CONTROLLER_STACK:
            require(self.cold_fill and self.cold_fill['whole16384_FF_checked'] and
                bytes(self.uc.mem_read(bottom,256))==b'\xff'*256, 'Cold native-filled controller pool boundary changed')
        else: require(bottom==IDLE_STACK and bytes(self.uc.mem_read(bottom,64))==b'\xa5'*64,'Idle stack boundary changed')

    def verify_cold_metadata(self):
        require(bytes(self.uc.mem_read(M,40))==self.metadata_before and self.word(self.controller+28)==M and self.word(M+28)==0,
            'First/same-owner metadata or empty saved-slot changed')
        require(bytes(self.uc.mem_read(NAME,17))==(ROOT/self.cold_inputs[2]['path']).read_bytes(),'Declared native task name changed')
        for lo,hi in self.cold_typed_ranges:
            require(bytes(self.uc.mem_read(lo,32))==b'\xa5'*32 and bytes(self.uc.mem_read(hi-32,32))==b'\xa5'*32,'Cold metadata/name canary changed')
        self.verify_cold_controller_or_idle_boundary(CONTROLLER_STACK)

    def seal_cold_boot(self):
        require(self.FP_boot_registration and self.FP_boot_registration['returned'] and self.word(OWNER)==0 and
            self.uc.reg_read(UC_ARM_REG_FPSCR)==0x03000000 and self.uc.reg_read(UC_ARM_REG_FPEXC)==0x40000000,
            'Original FP boot register result differs')
        require(self.word(EXIT_LIST)==FP_NODE and list(struct.unpack('<4I',self.uc.mem_read(FP_NODE,16)))==[0,0x7fffffff,0x20edb1,0],
            'Original cold FP listener chain differs')
        require(bytes(self.uc.mem_read(self.controller,108))==self.pre_FP_boot_TCB108 and self.word(self.controller+32)==0,
            'Cold FP boot changed whole original TCB108 or retained a mutex')
        require(bytes(self.uc.mem_read(EXIT_LIST+4,24))==struct.pack('<6I',0,self.controller+32,0,0,0x3cc660,0),
            'Cold released list backend differs from original stale-link recipe')
        self.verify_cold_metadata()
        for start,row in self.cold_zones.items():
            expected=bytearray.fromhex(row['before_hex'])
            for store in row['stores']:
                offset=int(store['address'],16)-start;n=store['size']
                require(expected[offset:offset+n].hex()==store['before_hex'],'Cold journal missed a host or native mutation')
                expected[offset:offset+n]=store['value'].to_bytes(n,'little')
            raw=bytes(self.uc.mem_read(start,row['bytes']))
            require(raw==expected,'Whole cold boot zone differs from exact CPU/input history')
            row.update(after_sha256=hashlib.sha256(raw).hexdigest(),whole_zone_replayed=True)
        self.cold_journal_active=False;self.cold_boot_sealed=True
        self.virtual_fp_inputs['original_FP_boot_execution_pending']=False
        return dict(original_FP_boot_executed=True,original_listener_registered=True,FPSCR='0x03000000',FPowner=0,
            cold_controller_fill=self.cold_fill,listener_registration=self.FP_boot_registration,whole_boot_zones=self.cold_zones,
            declared_cold_metadata_inputs=self.cold_inputs,whole_TCB108_unchanged=True,released_list_backend24_checked=True,
            multiowner_exchange_executed=False)

    def verify_extra_zones(self):
        rows=HeapSettingsVM.verify_extra_zones(self)
        require(self.cold_boot_sealed and self.lazy.active is None and self.lazy.rows and all(
            r['original_handler_entered'] and r['original_exception_return_seen'] and r['original_opcode_retry_reached'] and
            not r['host_wrote_FP_enable_or_context'] for r in self.lazy.rows),'Cold lazy FP rows incomplete')
        require(self.word(OWNER)==self.controller,'First/same native FP owner differs')
        for lo in [TRAPSTACK,TRAPSTACK+TRAPBYTES-32]: require(bytes(self.uc.mem_read(lo,32))==b'\xa5'*32,'Undefined stack canary changed')
        self.verify_cold_metadata()
        return rows

def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(parents=True,exist_ok=True);require(not (STAGE/'runner-at-run.py').exists(),'Preserve prior cold run')
    source=Path(__file__).resolve();deps=dict(json.loads((ROOT/BASE/'previous-audit.json').read_text())['protected_sources'])
    for path in [str(source.relative_to(ROOT)),'scripts/native_cold_fp_guard_copies.py',BASE+'guard-copy-provenance.json',RECIPE]:deps[path]=sha(path)
    for path,digest in deps.items():require(sha(path)==digest,'Protected dependency differs '+path)
    (STAGE/'runner-at-run.py').write_bytes(source.read_bytes())
    dump(STAGE/'inputs-before-run.json',dict(source_sha256=deps,component_manifest=COMPONENT,component_manifest_sha256=sha(COMPONENT),
        device_io=False,sounds_emitted=False,modified_guest_code_bytes=0,new_cold_metadata_and_original_FP_boot=True))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=sha(str(source.relative_to(ROOT))),
        phase='constructor',completed=False,full_scoped_final_guards_passed=False,device_io=False,sounds_emitted=False,physical_App_verified=False)
    vm=None
    try:
        vm=ColdFPControllerVM(NativeImage(),json.loads((ROOT/BUILD).read_text()));result['phase']='load_and_cold_kernel'
        print(json.dumps(dict(phase=result['phase'])),flush=True);result['load']=vm.load()
        oldram=struct.unpack_from('<I',(ROOT/vm.build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480));dbsha=sha(DATABASE)
        vm.uc.reg_write(UC_ARM_REG_CPSR,(vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        result['kernel']=vm.configure_native_kernel_inventory()
        require(vm.word(OWNER)==0 and vm.uc.reg_read(UC_ARM_REG_FPEXC)==0x40000000 and vm.uc.reg_read(UC_ARM_REG_C1_C0_2)==0xf00000,
            'Cold FP boot actual startup register precondition differs')
        require(bytes(vm.uc.mem_read(FP_NODE,16))==bytes(16),'Cold FP listener node already initialized')
        vm.pre_FP_boot_TCB108=bytes(vm.uc.mem_read(vm.controller,108))
        vm.phase='cold_exit_list_ctor';result['phase']=vm.phase;vm.kernel_invoke(0x3cc57d,(EXIT_LIST,))
        vm.phase='cold_FP_boot';result['phase']=vm.phase;vm.kernel_invoke(0x20ed68,());result['cold_boot']=vm.seal_cold_boot()
        print(json.dumps(dict(cold_boot_complete=True,FPSCR=hex(vm.uc.reg_read(UC_ARM_REG_FPSCR)))),flush=True)
        vm.phase='native_GUI_boot';result['phase']=vm.phase;vm.kernel_invoke(POST,(vm.timer_task,16))
        vm.kernel_invoke(0x5d2f7d,());D=vm.kernel_invoke(0x5d2131,());require(vm.returned and D==0x8800520,'Original singleton did not return')
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
        status=vm.kernel_invoke(COMP_BASE+0x4c,(CONFIG,OUTPUT))
        result['component_return']=hex(status);result['component_result20']=list(struct.unpack('<20I',vm.uc.mem_read(OUTPUT,80)))
        require(status==1 and result['component_result20'][2:4]==[0x2ffc,1] and len(vm.component_calls)==11 and all(r['returned']for r in vm.component_calls),
            'Full cold native component endpoint incomplete')
        result['native_endpoint']=vm.verify_native_endpoint(gui_condition,before,timed)
        result['memory']=vm.verify_component_memory(voice,exports,dbsha)
        result['initialized_data_journal']=vm.verify_mutable_scope();result['extra_zones']=vm.verify_extra_zones()
        result.update(completed=True,full_scoped_final_guards_passed=True)
    except Exception as error:
        result['error']=str(error);print(json.dumps(dict(phase=result['phase'],error=str(error))),flush=True)
    if vm is not None:
        result.update(component_calls=vm.component_calls,cold_boot_zones=vm.cold_zones,cold_fill=vm.cold_fill,
            FP_boot_registration=vm.FP_boot_registration,cold_boot_sealed=vm.cold_boot_sealed,
            actual_FPU_state=vm.lazy.snapshot(),original_lazy_handler_rows=vm.lazy.rows,
            journal_zones=vm.zone_rows,native_mutex_operations=vm.native_mutex_runs,
            native_cache_allocations=vm.cache_allocations,native_cache_read_bindings=vm.cache_read_bindings,
            whole_cache_journal=vm.cache_journal,native_cache_CPU_store_count=vm.cache_CPU_store_count,
            cache_observer_UcErrors=vm.cache_observer_UcErrors,unexpected_emulation_UcErrors=vm.unexpected_emulation_UcErrors,
            invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,recent=list(vm.recent),
            registers={n:hex(vm.uc.reg_read(r))for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
        vm.db.close()
    result['finished_utc']=datetime.now(timezone.utc).isoformat();dump(STAGE/'terminal-probe.json',result)
    print(json.dumps({k:result.get(k)for k in ['completed','phase','error','full_scoped_final_guards_passed','component_return']}),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
