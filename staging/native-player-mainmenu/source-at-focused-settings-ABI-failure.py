#!/usr/bin/env python3
"""Five scoped original-code controls for MainMenu dependencies; offline.

These controls validate explicit inventory/kernel/peripheral fixtures. They
do not assert a complete PageMainMenu/controller/root, display or App test.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_player_mainmenu import MainMenuVM,BUILD,STAGE
from probe_native_player_resources import INPUT
from emulate_native_player_menu_selection import SelectionPlayerVM,DATABASE,sha
from emulate_native_vpm_filesystem import require

def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());database_sha=sha(DATABASE)
    vm=MainMenuVM(NativeImage(),build);cases=[]
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load()
        oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        vm.supply_setting_record(1)
        out=INPUT+0x800;vm.uc.mem_write(out-16,b'\xa5'*36)
        returned=vm.invoke(0x2cad0b,(0x100d,out,4))
        require(returned==0xffffffff and bytes(vm.uc.mem_read(out-16,36))==b'\xa5'*36,
            'Absent setting altered output or did not return-1')
        record('original_missing_settings_wrappers_leave_output_unchanged',native_entry='0x2cad0a',
            ID='0x100d',returned=-1,output_and_guards_unchanged=True,
            only19B_inventory_record_provided=True,host_supplied100D_setting_value=False)
        vm.uc.mem_write(out-16,b'\xa5'*36);before=len(vm.clock_counter_reads)
        returned=vm.invoke(0x1076d9,(out,))
        expected=b'\xa5'*16+b'\0'*4+b'\xa5'*16
        require(returned==0 and bytes(vm.uc.mem_read(out-16,36))==expected and len(vm.clock_counter_reads)==before+1,
            'Original hardware counter ABI or scoped output store differs')
        record('original_hardware_counter_output_store_and_status_with_exact_readonly_MMIO',
            original_entry='0x1076d8',returned_status=returned,output_counter_word=vm.word(out),
            surrounding_canaries_intact=True,original_read_PC='0x1076e2',MMIO_word='0x101e8090',
            hardware_counter_clock_or_GPS_time_verified=False)
        vm.invoke(0x2db541,());global_address=0x34a5614;sentinel=vm.word(global_address+0x10)
        require(sentinel and vm.word(sentinel)==sentinel and vm.word(sentinel+4)==sentinel and vm.word(global_address+0x14)==0,
            'Original display-list initializer did not create an empty self-linked list')
        record('original_display_list_initializer_constructs_empty_self_linked_sentinel',
            original_entry='0x2db540',global_address=hex(global_address),sentinel=hex(sentinel),
            original_sentinel_next_and_previous_equal_self=True,host_seeded_list_links=False)
        values=[vm.invoke(0x1f471f,(n,))for n in range(12)]
        require(values==[255]*12 and len(vm.GPS_inventory_queries)==12,'Original no-satellite branches differ')
        record('original_GPS_indicator_query_handles_explicit_empty_satellite_inventory',
            original_entry='0x1f471e',requested_indices=list(range(12)),native_results=values,
            GPS_count_lower_callback_fixture=0,actual_GPS_receiver_or_signal_verified=False)
        before=len(vm.unavailable_audio_pool_waits);returned=vm.invoke(0x3b4ba9,(0,))
        require(returned==255 and len(vm.unavailable_audio_pool_waits)==before+1 and not any(vm.mutexes.values()),
            'Original unavailable-audio-pool branch failed or retained a lock')
        record('original_audio_pool_nonzero_lower_wait_failure_returns_FF_and_unlocks',
            original_entry='0x3b4ba8',returned_pool_index=returned,fixture_wait_failure_status=1,
            stock_pool_lookup_loop_and_failure_branch_executed=True,all_fixture_mutexes_released=True,
            real_condition_variable_scheduling_pool_or_speaker_verified=False)
        require(not vm.invalid_accesses and not vm.audio,'Focused controls faulted or requested playback')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original voice RAM/40 exports changed')
        require(sha(DATABASE)==database_sha and not vm.statements,'Backup DB changed or unexpected SQL')
        # No GUI ctor runs in this control suite; all initialized copy regions
        # must remain byte-identical. Preserve narrower historical GUI guards.
        require(not vm.conditional_region_writes,'Focused controls mutated a GUI once/data word')
        snapshot=SelectionPlayerVM.finish(vm);vm.db.close()
        dependencies={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],
            ROOT/build['extension_elf'],ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',
            STAGE/'MainMenu-root-settings-preflight.json',Path(__file__).resolve()}
        dependencies.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            name=getattr(module,'__file__',None)
            if name:
                path=Path(name).resolve()
                if path.is_file() and path.is_relative_to(ROOT/'scripts'):dependencies.add(path)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
            build_manifest=BUILD,build_manifest_sha256=sha(BUILD),
            source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(dependencies)},
            case_count=len(cases),all_passed=True,cases=cases,load=load,snapshot=snapshot,
            clock_counter_reads=vm.clock_counter_reads,GPS_inventory_queries=vm.GPS_inventory_queries,
            missing_setting_searches=vm.missing_setting_searches,unavailable_audio_pool_waits=vm.unavailable_audio_pool_waits,
            original_voice_RAM_and40_exports_unchanged=True,raw_DB_backup_unchanged=True,
            full_MainMenu_integration_checkpoint=False,general_MainMenu_constructor_returned=False,
            general_MainMenu_controller_or_root_registration_verified=False,device_io=False,sounds_emitted=False,
            actual_device_App_display_or_direct_phone_music_verified=False,
            limits='Five original-code controls validate scoped missing settings, exact readonly counter MMIO, original display-list initializer, empty satellite inventory and nonzero unavailable-audio-pool wait. Synthetic storage/mutex/IRQ/heap/peripheral boundaries remain explicit. No complete general MainMenu/controller/root/display, actual boot inventory/kernel/audio pool, accepted modified package or physical App/direct music is established.')
        target=ROOT/'evidence/firmware-analysis/native-mainmenu-boundaries-emulation.json'
        require(not target.exists(),'Frozen focused proof already exists; use a new namespace')
        target.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(evidence=str(target.relative_to(ROOT)),focused_groups=len(cases),
            exact_dependencies=len(dependencies),all_final_guards_passed=True,full_MainMenu_integration=False)),flush=True)
    except Exception as error:
        failure=dict(error=str(error),completed_cases=cases,all_final_guards_passed=False,
            recent=list(vm.recent),invalid_accesses=vm.invalid_accesses)
        (STAGE/'focused-boundaries-failure.json').write_text(json.dumps(failure,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases),all_final_guards_passed=False)),flush=True)
        sys.exit(1)

if __name__=='__main__':main()
