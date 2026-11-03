#!/usr/bin/env python3
"""General-menu development with original settings initialization; offline.

Catalog/icon/DB/boot/GPS/kernel boundaries remain synthetic. Returning from
the constructor is not a full UI/control/loading or physical App checkpoint.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP
from analyze_native_sections import NativeImage,ROOT
from probe_native_settings_writer import SettingsVM,STAGE,GLOBAL
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_loaded import SEED,PLAYER_ID
from emulate_native_vpm_filesystem import REGS,require

def main():
    STAGE.mkdir(exist_ok=True);source=Path(__file__).resolve()
    vm=SettingsVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        VM_source='scripts/probe_native_settings_writer.py',VM_source_sha256=hashlib.sha256((ROOT/'scripts/probe_native_settings_writer.py').read_bytes()).hexdigest(),
        device_io=False,sounds_emitted=False,full_integration_checkpoint=False,
        full_general_MainMenu_final_guards_passed=False,general_MainMenu_controller_executed=False,
        catalog_seed_is_synthetic_not_loaded_player_entry=True)
    try:
        vm.invoke(0x2cbd17,());vm.verify_storage_guards()
        vm.uc.mem_write(INPUT+0x400,struct.pack('<I',1))
        require(vm.invoke(0x2ca82d,(0x19b,INPUT+0x400,4,0))==0,'Native setting19B control write failed')
        require(vm.settings_catalog_fixture is None,'Lower record lookup was unexpectedly replaced')
        vm.invoke(0x395981,());vm.invoke(0x2db541,());vm.register_stock_GIR();vm.external_IO_active=True
        vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Original fonts failed')
        vm.invoke(0x4a388b,());vm.put(SEED+0x110,0);vm.seed_control(PLAYER_ID,'Pi 播放器',0x13528000)
        vm.invoke(0x3894ad,(INPUT+0x100,0x8a56eac))
        for n in range(7):vm.invoke(0x3894f1,(vm.menu_records()[0]+28+8*n,INPUT+0x100))
        vm.init_DB_fixture();vm.set_cell(12,PLAYER_ID,0)
        obj=vm.invoke(0x3954cc,(0x3f04,));result['object']=hex(obj)
        print(json.dumps(dict(phase='original_MainMenu_with_native_settings_cache')),flush=True)
        value=vm.invoke(0x40434d,(obj,1));vm.verify_storage_guards();vm.verify_descriptor_guards()
        result.update(completed=True,constructor_returned=hex(value),vtable=hex(vm.word(obj)),native_tree=vm.tree(obj),
            embedded_Grid_rows=vm.grid_rows(obj+0x39b0),global_words=[hex(vm.word(GLOBAL+4*n))for n in range(10)])
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={n:hex(vm.uc.reg_read(r))for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(storage_events=vm.storage_events,settings_native_entries=vm.settings_native_entries,
        condition_bootstrap_tokens=vm.condition_bootstrap_tokens,heap_descriptor_entries=vm.heap_descriptor_entries,
        native_heap_validation_returns=vm.native_heap_validation_returns,conditional_writes=vm.conditional_region_writes,
        original_main_entries=vm.main_entries,native_fatal_entries=vm.native_fatal_entries,
        full_constructor_GUI_data_voice_allocation_SQL_final_guards_not_run=True)
    (STAGE/'general-menu-settings-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(completed=result['completed'],error=result.get('error'),constructor_returned=result.get('constructor_returned'))),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
