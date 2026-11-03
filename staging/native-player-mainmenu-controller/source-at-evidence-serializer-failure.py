#!/usr/bin/env python3
"""Development only: original controller creates/attaches general MainMenu.

Explicit virtual clock and guarded transition storage are lower inputs.
No full final guards, foreground/UI-thread/device App or safe lifetime claim.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP
from analyze_native_sections import ROOT,NativeImage
from emulate_native_mainmenu_constructor import ConstructorVM
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_loaded import PLAYER_ID
from emulate_native_vpm_filesystem import REGS,require

STAGE=ROOT/'staging/native-player-mainmenu-controller'

class ControllerVM(ConstructorVM):
    def __init__(self,stock,build):
        self.virtual_clock_ticks=[];self.virtual_clock_milliseconds=0
        self.transition_heap_requests=[];self.next_transition_buffer=0x0e800020
        super().__init__(stock,build)
        self.uc.mem_map(0x0e800000,0x800000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)

    def observe(self,uc,address,size,data):
        if address==0x2dc954 and (uc.reg_read(UC_ARM_REG_LR)&~1)==0x6f8364:
            args=[uc.reg_read(r)for r in REGS]
            require(0<args[0]<=0x100000 and args[1:3]==[1,8],
                'Unexpected original transition-buffer allocator request')
            pointer=self.next_transition_buffer;self.next_transition_buffer+=(args[0]+127)&~63
            require(self.next_transition_buffer<0x0f000000,'Finite transition-buffer fixture exhausted')
            uc.mem_write(pointer-32,b'\xa5'*(args[0]+64))
            self.raw_allocations[pointer]=dict(length=args[0],freed=False,service=hex(address))
            self.transition_heap_requests.append(dict(native_allocator=hex(address),caller='0x6f8364',
                requested_bytes=args[0],pointer=hex(pointer),alignment=8,
                guarded_storage_only_no_host_pixel_content=True,physical_free_RAM_verified=False))
            self.visits[address]+=1;self.ret(pointer);return
        if address==0x353a9c:
            require(len(self.virtual_clock_ticks)<10000,'Finite virtual-clock input exhausted')
            self.virtual_clock_milliseconds+=20;self.put(0xf09098,self.virtual_clock_milliseconds)
            self.virtual_clock_ticks.append(dict(original_entry=hex(address),word='0xf09098',
                supplied_virtual_milliseconds=self.virtual_clock_milliseconds,
                real_wall_time_kernel_tick_and_scheduler_verified=False))
        return super().observe(uc,address,size,data)

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(exist_ok=True);source=Path(__file__).resolve()
    vm=ControllerVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        full_integration_checkpoint=False,full_scoped_final_guards_passed=False,
        source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest())
    try:
        result['load']=vm.load()
        vm.invoke(0x2cbd17,());vm.uc.mem_write(INPUT+0x400,struct.pack('<I',1))
        require(vm.invoke(0x2ca82d,(0x19b,INPUT+0x400,4,0))==0,'Original setting19B control write failed')
        require(vm.settings_catalog_fixture is None,'Lower settings inventory unexpectedly replaced')
        vm.invoke(0x395981,());vm.invoke(0x2db541,());vm.register_stock_GIR()
        vm.external_IO_active=True;vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Original fonts failed')
        vm.invoke(0x4a388b,());vm.init_DB_fixture();vm.set_cell(12,PLAYER_ID,0)
        result['phase']='before_original_general_MainMenu_controller'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        # Controller is an entrypoint with no input object argument.
        returned=vm.invoke(0x405341,())
        ctor_entries=[r for r in vm.main_entries if r['entry']=='0x40434c']
        require(len(ctor_entries)==1,'Original controller did not create exactly one general page')
        page=ctor_entries[0]['arguments'][0]
        require(vm.word(page)==0xc03f98,'Original controller created unexpected Page type')
        manager=vm.invoke(0x393a2d,(0,))
        result.update(completed=True,original_controller_returned=hex(returned),page=hex(page),
            Page_vtable=hex(vm.word(page)),manager=hex(manager),native_tree=vm.tree(page),
            original_controller_ctor_entry=ctor_entries[0],original_controller_root_registration_executed=
            any(r['entry']=='0x38e696'for r in vm.main_entries),
            general_menu_embedded_Grid_rows=vm.grid_rows(page+0x39b0))
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        vm.verify_storage_guards();vm.verify_descriptor_guards()
        result['allocation_storage_descriptor_guards_intact']=True
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(original_main_entries=vm.main_entries,conditional_writes=vm.conditional_region_writes,
        native_fatal_entries=vm.native_fatal_entries,virtual_clock_ticks=vm.virtual_clock_ticks,
        transition_heap_requests=vm.transition_heap_requests,original_default_writes=vm.original_main_default_writes,
        metadata_reads=vm.consumer_metadata_reads,SQL_statement_count=len(vm.statements),
        SQL_closed_inventory={hex(p):s['closed']for p,s in vm.statements.items()},SQL_last_events=vm.sql_events[-100:],
        native_menu_state=vm.menu_state(),audio_requests=vm.audio,main_execution_resumes=vm.main_execution_resumes)
    (STAGE/'controller-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','page','original_controller_returned','native_tree']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
