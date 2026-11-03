#!/usr/bin/env python3
"""Development: original controller after full mutex bootstrap controls.

No full final-guard, visible device App, real kernel or safe lifetime claim.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP
from analyze_native_sections import ROOT,NativeImage
from probe_native_gui_runtime_bootstrap import BootstrapVM
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_loaded import PLAYER_ID
from emulate_native_page_root_integration import inventory
from emulate_native_vpm_filesystem import REGS,require

STAGE=ROOT/'staging/native-player-gui-bootstrap'

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    source=Path(__file__).resolve();vm=BootstrapVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        full_integration_checkpoint=False,full_scoped_final_guards_passed=False,
        source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest())
    try:
        result['load']=vm.load();vm.invoke(0x5d2f7d,());vm.invoke(0x2cbd17,());vm.uc.mem_write(INPUT+0x400,struct.pack('<I',1))
        require(vm.invoke(0x2ca82d,(0x19b,INPUT+0x400,4,0))==0,'Original setting19B control write failed')
        require(vm.settings_catalog_fixture is None,'Lower settings inventory unexpectedly replaced')
        vm.invoke(0x395981,());vm.invoke(0x2db541,());vm.register_stock_GIR()
        vm.external_IO_active=True;vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Original fonts failed')
        vm.invoke(0x4a388b,());vm.init_DB_fixture();vm.set_cell(12,PLAYER_ID,0)
        result['phase']='before_original_controller_with_native_mutex_bootstrap'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        returned=vm.invoke(0x405341,())
        entries=[e for e in vm.main_entries if e['entry']=='0x40434c'and e['caller']=='0x4053c2']
        require(len(entries)==1,'Original controller did not create exactly one general page')
        page=entries[0]['arguments'][0];require(vm.word(page)==0xc03f98,'Original controller created unexpected Page')
        manager=vm.invoke(0x393a2d,(0,));roots=inventory(vm,manager)
        result.update(original_controller_returned=hex(returned),page=hex(page),Page_vtable=hex(vm.word(page)),
            manager=hex(manager),native_tree_after_cold_controller=vm.tree(page),root_catalog_after_cold_controller=roots,
            original_root_registration_entered=any(e['entry']=='0x38e696'and e['caller']=='0x4053d6'for e in vm.main_entries),
            general_menu_embedded_Grid_rows=vm.grid_rows(page+0x39b0))
        before_ctor=len(entries);before_roots=[dict(row)for row in roots]
        result['phase']='before_original_existing_page_controller_lookup'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        second=vm.invoke(0x405341,())
        require(len([e for e in vm.main_entries if e['entry']=='0x40434c'and e['caller']=='0x4053c2'])==before_ctor and
            inventory(vm,manager)==before_roots,'Existing page lookup recreated or altered root catalog')
        result.update(completed=True,second_original_controller_returned=hex(second),
            original_existing_page_lookup_skips_recreation=True,native_tree_after_existing_page_lookup=vm.tree(page))
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        vm.verify_storage_guards();vm.verify_descriptor_guards()
        result['allocation_storage_descriptor_guards_intact']=True
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
        print(json.dumps(dict(phase=result.get('phase'),completed=False,error=str(error)),ensure_ascii=False),flush=True)
    result.update(original_main_entries=vm.main_entries,conditional_writes=vm.conditional_region_writes,
        native_fatal_entries=vm.native_fatal_entries,virtual_clock_ticks=vm.virtual_clock_ticks,
        transition_heap_requests=vm.transition_heap_requests,original_default_writes=vm.original_main_default_writes,
        metadata_reads=vm.consumer_metadata_reads,SQL_statement_count=len(vm.statements),
        SQL_closed_inventory={hex(p):s['closed']for p,s in vm.statements.items()},SQL_last_events=vm.sql_events[-100:],
        native_menu_state=list(struct.unpack('<6I',vm.uc.mem_read(vm.symbol('native_player_menu_state'),24))),
        audio_requests=vm.audio,main_execution_resumes=vm.main_execution_resumes,
        pool_context=vm.pool_context,pool_native_runs=vm.pool_native_runs,scoped_lower_wait_failures=vm.pool_wait_failures,
        mutex_inventory={hex(p):n for p,n in vm.mutexes.items()},original_bootstrap_entries=vm.gui_bootstrap_entries)
    (STAGE/'controller-bootstrap-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','page','original_controller_returned','native_tree_after_cold_controller']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
