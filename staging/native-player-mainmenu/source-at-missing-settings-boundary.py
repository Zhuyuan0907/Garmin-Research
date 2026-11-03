#!/usr/bin/env python3
"""Development: unchanged PageMainMenu ctor with stock GIR/fonts; offline.

Synthetic player catalog and direct native ctor call are explicit inputs.
No original controller/root, loader acceptance or displayed device App claim.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR
from analyze_native_sections import NativeImage,ROOT
from probe_native_player_resource_cache import ResourceCacheVM
from probe_native_player_resources import INPUT
from emulate_native_player_menu_loaded import PLAYER_ID,SEED
from emulate_native_player_menu_selection import SQL_OUT
from emulate_native_vpm_filesystem import REGS,require

STAGE=ROOT/'staging/native-player-mainmenu'
BUILD='staging/native-player-resources/manifest.json'

class MainMenuVM(ResourceCacheVM):
    def __init__(self,stock,build):
        self.main_entries=[]
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        if address in [0x40434c,0x405340,0x38e696,0x36ba5c,0x546c94,0x403dee,
            0x31632e,0x393a2c]:
            self.main_entries.append(dict(entry=hex(address),arguments=[uc.reg_read(r)for r in REGS],
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1)))
        return super().observe(uc,address,size,data)

def main():
    STAGE.mkdir(exist_ok=True);source=Path(__file__).resolve()
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        full_integration_checkpoint=False,source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest())
    vm=MainMenuVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    try:
        vm.invoke(0x395981,());vm.register_stock_GIR();vm.external_IO_active=True
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
        resource_heap_requests=vm.resource_heap_requests,setting_reads=vm.setting_reads)
    (STAGE/'constructor-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','object','returned','vtable','embedded_Grid_vtable']}),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
