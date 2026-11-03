#!/usr/bin/env python3
"""Five original settings controls on a guarded fictional NOR bank; offline."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_settings_writer import SettingsVM,STAGE,FLASH,SECTOR_SIZE,SECTOR_COUNT,GLOBAL
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_selection import SelectionPlayerVM,DATABASE,sha
from emulate_native_vpm_filesystem import require

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());vm=SettingsVM(NativeImage(),build);cases=[];database_sha=sha(DATABASE)
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        require(vm.word(GLOBAL+16)==0 and bytes(vm.uc.mem_read(GLOBAL+3,1))==b'\0' and
            bytes(vm.uc.mem_read(FLASH,SECTOR_SIZE*SECTOR_COUNT))==b'\xff'*(SECTOR_SIZE*SECTOR_COUNT),
            'Cold settings inputs were not original uninitialized state and erased synthetic storage')
        require(vm.invoke(0x2cbd17,())==0,'Original initializer did not return')
        require(bytes(vm.uc.mem_read(GLOBAL+3,1))==b'\1' and
            struct.unpack('<HH',vm.uc.mem_read(GLOBAL+6,4))==(2,2) and
            vm.word(GLOBAL+16)==FLASH+20 and vm.word(GLOBAL+24)==SECTOR_SIZE-20,
            'Native initialized ready/count/cursor/capacity differs')
        require(vm.word(FLASH)==0x0001c00c and vm.word(FLASH+12)==0xc008,
            'Native sector and state record headers not committed')
        record('original_cold_initializer_builds_sector_records_and_write_cursor',original_entry='0x2cbd16',
            ready_set_by_original=True,host_seeded_headers_or_cursor=False,logical_sectors=2,physical_sectors=2,
            cursor=hex(vm.word(GLOBAL+16)),free_bytes=vm.word(GLOBAL+24),
            fictional_geometry=dict(guest_base=hex(FLASH),sector_bytes=SECTOR_SIZE,sector_count=SECTOR_COUNT),
            actual_device_flash_geometry_or_kernel_condition_owner_verified=False)
        output=INPUT+0x500;copy=INPUT+0x600
        vm.put(output,0);vm.uc.mem_write(copy-32,b'\xa5'*68)
        r=vm.invoke(0x2cabbd,(0x121e,output));c=vm.invoke(0x2cad0b,(0x121e,copy,2,0))
        require(r==c==0xffffffff and vm.word(output)==0 and bytes(vm.uc.mem_read(copy-32,68))==b'\xa5'*68,
            'Absent record native reader/copy changed output')
        require(vm.settings_catalog_fixture is None,'Unexpected inherited lower record fixture')
        record('original_record_lookup_and_copy_reject_missing_key_without_fake_default',
            key='0x121e',read_result='0xffffffff',copy_result='0xffffffff',outputs_unchanged=True,
            native_lookup_not_replaced_with_host_inventory=True)
        initial_cursor=vm.word(GLOBAL+16);source=INPUT+0x400
        vm.uc.mem_write(source-32,b'\xa5'*72);vm.uc.mem_write(source,struct.pack('<HH',0x1234,0xffff))
        operations=len(vm.storage_events)
        require(vm.invoke(0x2ca82d,(0x121e,source,2,0))==0,'Original setter failed')
        vm.put(output,0);require(vm.invoke(0x2cabbd,(0x121e,output))==2,'Original pointer reader length differs')
        data_pointer=vm.word(output)
        require(data_pointer==initial_cursor+4 and bytes(vm.uc.mem_read(data_pointer,2))==b'\x34\x12' and
            vm.word(GLOBAL+16)==initial_cursor+8 and vm.word(initial_cursor)==0x121ec006,
            'Original program/commit/read cursor or header differs')
        vm.uc.mem_write(copy-32,b'\xa5'*68)
        require(vm.invoke(0x2cad0b,(0x121e,copy,2,0))==2 and bytes(vm.uc.mem_read(copy,2))==b'\x34\x12' and
            bytes(vm.uc.mem_read(copy-32,32))==b'\xa5'*32 and bytes(vm.uc.mem_read(copy+2,34))==b'\xa5'*34,
            'Original copied value or guards differ')
        require(bytes(vm.uc.mem_read(source-32,32))==b'\xa5'*32 and bytes(vm.uc.mem_read(source+4,36))==b'\xa5'*36,
            'Original setter changed input guards')
        writes=[e for e in vm.storage_events[operations:]if e['operation']=='program']
        require([e['bytes']for e in writes]==[4,4,2] and all(e['one_to_zero_only']for e in writes),
            'Header/padded payload/commit program sequence differs')
        record('original_setter_programs_header_padded_payload_commits_and_reads_back',key='0x121e',
            synthetic_control_value=0x1234,record_data_pointer=hex(data_pointer),cursor_advanced_bytes=8,
            native_copy_bytes=2,program_writes=writes,native_record_header='0x121ec006',
            unchanged_input_and_output_guards=True,physical_persistence_verified=False)
        cached=INPUT+0x700;vm.put(cached,data_pointer)
        ops=len(vm.storage_events);cursor=vm.word(GLOBAL+16)
        require(vm.invoke(0x2ca82d,(0x121e,source,2,cached))==1 and len(vm.storage_events)==ops and
            vm.word(GLOBAL+16)==cursor and vm.word(cached)==data_pointer,'Identical cached value wrote flash')
        vm.uc.mem_write(source,struct.pack('<HH',0xabcd,0xffff))
        require(vm.invoke(0x2ca82d,(0x121e,source,2,cached))==0,'Native cached replacement failed')
        replacement=vm.word(cached);vm.put(output,0)
        require(vm.invoke(0x2cabbd,(0x121e,output))==2 and vm.word(output)==replacement and replacement!=data_pointer and
            bytes(vm.uc.mem_read(replacement,2))==b'\xcd\xab' and
            not (struct.unpack('<H',vm.uc.mem_read(data_pointer-4,2))[0]&0x8000),
            'Original replacement did not invalidate old record or return newest value')
        record('original_cached_identical_value_skips_write_and_changed_value_replaces_record',
            identical_result=1,identical_no_storage_or_cursor_change=True,replacement_result=0,
            old_data_pointer=hex(data_pointer),new_data_pointer=hex(replacement),
            original_old_record_invalidation_and_new_lookup=True)
        rejected=[];ops=len(vm.storage_events);cursor=vm.word(GLOBAL+16)
        for key,length,cache_pointer in [(0x121e,0,0),(0x121e,8192,0),(0x121f,2,cached)]:
            require(vm.invoke(0x2ca82d,(key,source,length,cache_pointer))==2,'Invalid setter request accepted')
            rejected.append(dict(key=hex(key),length=length,cached_pointer=hex(cache_pointer),original_result=2))
        require(len(vm.storage_events)==ops and vm.word(GLOBAL+16)==cursor,'Rejected request modified NOR store')
        record('original_setter_rejects_zero_oversized_and_mismatched_cached_record_ID',controls=rejected,
            no_storage_operations_or_cursor_changes=True)
        vm.verify_storage_guards();vm.verify_descriptor_guards()
        require(not vm.invalid_accesses and not vm.audio and not vm.conditional_region_writes,'Focused settings controls faulted or requested audio/GUI')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original voice RAM/40 exports changed')
        require(sha(DATABASE)==database_sha and not vm.statements,'Backup DB changed or unexpected SQL')
        snapshot=SelectionPlayerVM.finish(vm);vm.db.close()
        deps={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve(),
            STAGE/'settings-writer-static-preflight.json'}
        deps.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                p=Path(filename).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):deps.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(deps)},
            case_count=len(cases),all_passed=True,cases=cases,load=load,snapshot=snapshot,
            storage_events=vm.storage_events,settings_native_entries=vm.settings_native_entries,native_flash_reads=vm.native_flash_reads,
            condition_bootstrap_tokens=vm.condition_bootstrap_tokens,storage_and_temporary_index_buffer_guards_verified=True,
            original_voice_RAM_and40_exports_unchanged=True,raw_DB_backup_unchanged=True,
            no_GUI_conditional_initialized_data_changes=True,descriptor_canaries_verified=True,
            actual_physical_flash_geometry_persistence_kernel_condition_and_boot_order_verified=False,
            general_MainMenu_constructor_or_controller_verified=False,device_io=False,sounds_emitted=False,
            limits='Original settings initializer enumerates and formats explicit fictional two16KiB erased NOR sectors, builds cursor/ready state, and original reader/program/commit/cache replacement/rejection execute. Lower bank13 geometry/program/erase, erased auxiliary bank34 metadata,4288-byte temporary heap and retained condition-bootstrap token are explicit fixtures; no physical flash, real kernel/current thread or boot order. Existing voice40/code/canary/DB final guards pass; no general Main/controller/foreground/accepted package/device App/audio or safe unload proof.')
        path=ROOT/'evidence/firmware-analysis/native-settings-writer-emulation.json';require(not path.exists(),'Use new proof namespace')
        path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,groups=len(cases),exact_dependencies=len(deps))),flush=True)
    except Exception as error:
        (STAGE/'focused-settings-failure.json').write_text(json.dumps(dict(error=str(error),completed_cases=cases,all_final_guards_passed=False,
            recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries),ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases))),flush=True);sys.exit(1)

if __name__=='__main__':main()
