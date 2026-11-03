#!/usr/bin/env python3
"""Development: unchanged PageMainMenu ctor with stock GIR/fonts; offline.

Synthetic player catalog and direct native ctor call are explicit inputs.
No original controller/root, loader acceptance or displayed device App claim.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
from unicorn import UC_HOOK_MEM_READ,UC_PROT_READ
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_CPSR
from analyze_native_sections import NativeImage,ROOT
from probe_native_player_resource_cache import ResourceCacheVM
from probe_native_player_resources import INPUT
from emulate_native_player_menu_loaded import PLAYER_ID,SEED
from emulate_native_player_menu_selection import SQL_OUT
from emulate_native_vpm_filesystem import REGS,require,STACK,RETURN

STAGE=ROOT/'staging/native-player-mainmenu'
BUILD='staging/native-player-resources/manifest.json'

class MainMenuVM(ResourceCacheVM):
    def __init__(self,stock,build):
        self.main_entries=[]
        self.missing_setting_searches=[]
        self.main_execution_resumes=[]
        self.GPS_inventory_queries=[]
        self.clock_counter_reads=[]
        self.native_fatal_entries=[]
        self.unavailable_audio_pool_waits=[]
        super().__init__(stock,build)
        # Exact native counter read1076E2. No other clock/MMIO services exist.
        # Run the original function, including output store and ready-byte read.
        self.uc.mem_map(0x101e8000,0x1000)
        self.uc.mem_write(0x101e8000,b'\xcc'*0x1000)
        self.put(0x101e8090,0)
        self.uc.mem_protect(0x101e8000,0x1000,UC_PROT_READ)
        self.uc.hook_add(UC_HOOK_MEM_READ,self.observe_clock_read,begin=0x101e8000,end=0x101e8fff)

    def observe_clock_read(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        require(address==0x101e8090 and size==4 and pc==0x1076e2,
            'Unexpected clock/MMIO read outside exact native counter boundary')
        self.clock_counter_reads.append(dict(address=hex(address),size=size,original_PC=hex(pc),
            emulated_counter_word=0,actual_hardware_clock_or_GPS_time_verified=False))

    def observe(self,uc,address,size,data):
        if address==0x3ec6aa and (uc.reg_read(UC_ARM_REG_LR)&~1)==0x3b4c14:
            args=[uc.reg_read(r)for r in REGS]
            require(args[:3]==[0x35e0308,0x35e02f0,1000] and self.mutexes[args[1]]==1,
                'Unexpected absent audio-pool condition wait boundary')
            # Native pool lookup found no available records. No kernel wait or
            # mutex owner exists in this VM. Return an explicit failure status;
            # original3B4BA8 must take its unavailable-pool -> FF branch.
            self.unavailable_audio_pool_waits.append(dict(entry=hex(address),caller='0x3b4c14',
                arguments=[hex(a)for a in args[:3]],emulated_wait_failure_status=1,
                real_condition_wait_or_audio_pool_initialized=False))
            self.visits[address]+=1;self.ret(1);return
        if address==0x23d6e8:
            self.native_fatal_entries.append(dict(original_entry=hex(address),
                arguments=[hex(uc.reg_read(r))for r in REGS],caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1),
                stack_words=[hex(self.word(uc.reg_read(UC_ARM_REG_SP)+4*n))for n in range(48)]))
            raise ValueError('Original fatal reporter entry23D6E8; failure captured before unconditional self-loop')
        require(address!=0x23d77e,'Original fatal reporter reached its unconditional self-loop23D77E')
        if address==0x4590da:
            caller=uc.reg_read(UC_ARM_REG_LR)&~1
            require(caller==0x1f4728,'Unexpected GPS inventory provider caller')
            # Original1F471E -> missing driver-table slot3C returns a count.
            # Emulated inventory has no satellite records. Original indicator
            # ctor/updater and absence branches execute unchanged.
            self.GPS_inventory_queries.append(dict(original_boundary=hex(address),caller=hex(caller),
                emulated_satellite_record_count=0,actual_GPS_receiver_or_signal_verified=False))
            self.visits[address]+=1;self.ret(0);return
        if address==0x2cab14 and self.settings_catalog_fixture is not None:
            args=[uc.reg_read(r)for r in REGS]
            if args[0]!=0x19b:
                require(0<args[0]<=0xffff and self.word(args[1])==0,
                    'Unexpected missing-setting lower inventory request')
                # Inventory contains only the provided19B record. Other IDs
                # are absent; native2CABBC/2CAD0A/default branches still run.
                self.missing_setting_searches.append(dict(id=hex(args[0]),output=hex(args[1]),
                    lower_inventory_returned_no_record=True,host_supplied_setting_value=False))
                self.visits[address]+=1;self.ret(0);return
        if address in [0x40434c,0x405340,0x38e696,0x36ba5c,0x546c94,0x403dee,
            0x31632e,0x393a2c]:
            self.main_entries.append(dict(entry=hex(address),arguments=[uc.reg_read(r)for r in REGS],
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1)))
        return super().observe(uc,address,size,data)

    def invoke(self,address,args,stack=()):
        if address not in [0x40434d,0x405341,0x38e697]:
            return super().invoke(address,args,stack)
        self.returned=False
        for register,value in zip(REGS,args):self.uc.reg_write(register,value)
        for n,value in enumerate(stack):self.put(STACK+n*4,value)
        self.uc.reg_write(UC_ARM_REG_SP,STACK);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        current=address
        for quantum in range(24):
            self.uc.emu_start(current,RETURN+2,count=3000000,timeout=15000000)
            if self.returned:break
            pc=self.uc.reg_read(UC_ARM_REG_PC);cpsr=self.uc.reg_read(UC_ARM_REG_CPSR)
            row=dict(original_entry=hex(address),next_PC=hex(pc),Thumb=bool(cpsr&32),
                quantum=quantum+1,resume_same_VM_registers_stack_and_memory=True,constructor_not_reentered=True)
            self.main_execution_resumes.append(row)
            print(json.dumps(dict(phase='continue_original_MainMenu_native_work',**row)),flush=True)
            current=pc|1 if cpsr&32 else pc&~1
        require(self.returned,'Original MainMenu did not return within24 unchanged-state quanta')
        require(not any(self.mutexes.values()),'Inherited synthetic mutex left held')
        value=self.uc.reg_read(REGS[0]);self.calls.append(dict(entry=hex(address),result=hex(value)))
        return value

def main():
    STAGE.mkdir(exist_ok=True);source=Path(__file__).resolve()
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        full_integration_checkpoint=False,source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest())
    vm=MainMenuVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    try:
        vm.invoke(0x395981,());vm.invoke(0x2db541,());vm.register_stock_GIR();vm.external_IO_active=True
        vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Original fonts failed')
        vm.put(SEED+0x110,0);vm.seed_control(PLAYER_ID,'Pi 播放器',0x13528000)
        vm.invoke(0x3894ad,(INPUT+0x100,0x8a56eac))
        for n in range(7):vm.invoke(0x3894f1,(vm.menu_records()[0]+28+8*n,INPUT+0x100))
        vm.init_DB_fixture();vm.set_cell(12,PLAYER_ID,0)
        # Real persistent boot setting19B remains unknown. Ask the original
        # wrappers to read a provided lower record with custom menu enabled.
        vm.supply_setting_record(1)
        obj=vm.invoke(0x3954cc,(0x3f04,));result['object']=hex(obj)
        result['phase']='before_original_PageMainMenu_constructor';print(json.dumps(dict(phase=result['phase'])),flush=True)
        returned=vm.invoke(0x40434d,(obj,1))
        result.update(constructor_returned=True,returned=hex(returned),vtable=hex(vm.word(obj)),
            embedded_Grid_vtable=hex(vm.word(obj+0x39b0)),native_tree=vm.tree(obj),
            embedded_Grid_rows=vm.grid_rows(obj+0x39b0),synthetic_catalog_and_lower_setting_record=True,
            original_controller_or_root_registration_executed=False,completed=True)
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        result['allocation_guards_intact']=True
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC))})
    result.update(original_main_entries=vm.main_entries,conditional_writes=vm.conditional_region_writes,
        resource_heap_requests=vm.resource_heap_requests,setting_reads=vm.setting_reads,
        missing_setting_searches=vm.missing_setting_searches,main_execution_resumes=vm.main_execution_resumes,
        GPS_inventory_queries=vm.GPS_inventory_queries)
    result['clock_counter_reads']=vm.clock_counter_reads
    result['native_fatal_entries']=vm.native_fatal_entries
    result['unavailable_audio_pool_waits']=vm.unavailable_audio_pool_waits
    (STAGE/'constructor-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','object','returned','vtable','embedded_Grid_vtable']}),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
