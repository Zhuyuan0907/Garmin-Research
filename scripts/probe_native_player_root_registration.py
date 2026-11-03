#!/usr/bin/env python3
"""Development: stock root registration with a stock custom Page; offline.

This does not execute general MainMenu/controller, deliver a GUI event queue,
or install an App. All storage/kernel boundaries remain explicit VM fixtures.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP
from analyze_native_sections import NativeImage,ROOT
from probe_native_player_mainmenu import MainMenuVM,BUILD,STAGE
from emulate_native_vpm_filesystem import REGS,require

class RootVM(MainMenuVM):
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
            require(self.next_transition_buffer<0x0f000000,'Finite transition-buffer storage fixture exhausted')
            uc.mem_write(pointer-32,b'\xa5'*(args[0]+64))
            self.raw_allocations[pointer]=dict(length=args[0],freed=False,service=hex(address))
            self.transition_heap_requests.append(dict(native_allocator=hex(address),caller='0x6f8364',
                requested_bytes=args[0],pointer=hex(pointer),alignment=8,
                guarded_storage_only_no_host_pixel_content=True,physical_free_RAM_verified=False))
            self.visits[address]+=1;self.ret(pointer);return
        if address==0x353a9c:
            require(len(self.virtual_clock_ticks)<10000,'Finite virtual clock input budget exhausted')
            self.virtual_clock_milliseconds+=20
            # Exact original353A9C reads the kernel clock wordF09098. Supply
            # advancing virtual time only; original clock read still executes.
            self.put(0xf09098,self.virtual_clock_milliseconds)
            self.virtual_clock_ticks.append(dict(original_entry=hex(address),word='0xf09098',
                supplied_virtual_milliseconds=self.virtual_clock_milliseconds,
                real_wall_time_kernel_tick_and_scheduler_verified=False))
        return super().observe(uc,address,size,data)

def main():
    source=Path(__file__).resolve();vm=RootVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        full_integration_checkpoint=False,source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        general_MainMenu_constructor_or_controller_executed=False,actual_root_event_queue_delivery_verified=False)
    try:
        result['load']=vm.load()
        vm.invoke(0x395981,());vm.invoke(0x2db541,());vm.register_stock_GIR()
        vm.external_IO_active=True;vm.invoke(0x4df249,())
        require(vm.invoke(0x4de237,(1,))==0,'Original font initialization failed')
        vm.init_DB_fixture();vm.supply_setting_record(1)
        page=vm.invoke(0x3954cc,(0x7c4,));vm.invoke(0x5a2995,(page,))
        manager=vm.invoke(0x393a2d,(0,))
        result.update(page=hex(page),Page_vtable=hex(vm.word(page)),manager=hex(manager),
            manager_vtable=hex(vm.word(manager)),queue_count_before=vm.word(manager+0xe30))
        result['phase']='before_original_root_registration';print(json.dumps(dict(phase=result['phase'])),flush=True)
        returned=vm.invoke(0x38e697,(manager,page,0,0))
        result.update(completed=True,original_registration_returned=hex(returned),
            queue_count_after=vm.word(manager+0xe30),wake_boundaries=vm.wake_boundaries,
            native_tree=vm.tree(page))
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        result['allocation_guards_intact']=True
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(original_main_entries=vm.main_entries,conditional_writes=vm.conditional_region_writes,
        native_fatal_entries=vm.native_fatal_entries,virtual_clock_ticks=vm.virtual_clock_ticks,
        SQL_statement_count=len(vm.statements),SQL_last_events=vm.sql_events[-100:],
        settings_reads=vm.setting_reads,missing_setting_searches=vm.missing_setting_searches,
        transition_heap_requests=vm.transition_heap_requests)
    (STAGE/'root-registration-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','page','manager','queue_count_before','queue_count_after']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
