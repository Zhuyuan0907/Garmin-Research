#!/usr/bin/env python3
"""Original native consumer metadata/default fallback controls; offline only."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_mainmenu_metadata import MetadataVM,STAGE,PROFILE_TABLE,DRIVER,MAX_BODY_BYTES
from probe_native_player_mainmenu import BUILD
from emulate_native_player_menu_selection import SelectionPlayerVM,DATABASE,sha
from emulate_native_vpm_filesystem import require

OFFSETS={139:8,140:0x788,141:0x7a8,142:0x8f8,143:0xb28}

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());vm=MetadataVM(NativeImage(),build);cases=[];database_sha=sha(DATABASE)
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        obj=vm.invoke(0x3954cc,(3072,));blank=b'\xa5'*3072
        def run(inventory):
            vm.install_inventory(inventory);vm.uc.mem_write(obj,blank);start=len(vm.consumer_metadata_reads)
            vm.invoke(0x35d431,(obj,));rows=vm.consumer_metadata_reads[start:]
            require(bytes(vm.uc.mem_read(0x18400000,4096))==vm.driver_inventory_snapshot,
                'Original dispatcher changed synthetic driver inventory')
            vm.verify_guard(obj,vm.raw_allocations[obj]);return rows,bytes(vm.uc.mem_read(obj,3072))
        absent={n:None for n in MAX_BODY_BYTES};rows,after=run(absent)
        require(after==blank and len(rows)==5 and all(r['operation']=='header'and r['native_generic_read_return']==11 and
            r['native_missing_profile_status11']and not r['output_written']for r in rows),
            'Original missing profile paths wrote default buffer or returned synthetic status')
        record('five_original_missing_profile_paths_preserve_guarded_consumer_buffer',native_read_requests=rows,
            profile_table_original_zero_BSS=True,original_generic_read_and_profile_lookup_executed=True,
            host_returned_missing_read_status=False,consumer_buffer_unchanged=True,real_factory_defaults_or_schema_verified=False)
        start=len(vm.consumer_metadata_reads)
        require(vm.invoke(0x2363b1,())==0,'Original absence getter incorrectly reports consumer data present')
        reads=vm.consumer_metadata_reads[start:];require(len(reads)==1 and reads[0]['native_generic_read_return']==11,
            'Original absence getter did not use native bank140 error path')
        record('separate_original_consumer_presence_getter_returns_false_for_missing_bank140',
            original_entry='0x2363b0',native_result=0,native_read_requests=reads,host_bool_override=False)
        payload={n:bytes((n+i)%251 for i in range(MAX_BODY_BYTES[n]))for n in MAX_BODY_BYTES}
        supplied={n:struct.pack('<Q',MAX_BODY_BYTES[n])+payload[n]for n in MAX_BODY_BYTES}
        rows,after=run(supplied);expected=bytearray(blank)
        for n,b in payload.items():expected[OFFSETS[n]:OFFSETS[n]+len(b)]=b
        expected[0x788]=1
        require(after==bytes(expected)and len(rows)==10 and all(r['native_generic_read_return']==0 and r['output_written']for r in rows),
            'Original native metadata lookup/indirect driver/read field changes differ')
        start=len(vm.consumer_metadata_reads);require(vm.invoke(0x2363b1,())==1,'Original presence getter rejects supplied32-byte header')
        record('original_profile_lookup_indirect_driver_dispatch_and_five_field_copies',native_read_requests=rows,
            original_presence_getter_result=1,fields=OFFSETS,whole_guarded_consumer_buffer_matches_native_expected_fields=True,
            supplied_inventory_is_fictional=True,original_wrapper_not_replaced_by_success=True)
        zero={n:struct.pack('<Q',0)for n in MAX_BODY_BYTES};legacy_payload=bytes(range(16));legacy=dict(zero)
        legacy[140]=struct.pack('<Q',24)+legacy_payload;rows,after=run(legacy);expected=bytearray(blank)
        expected[0x788:0x798]=legacy_payload;expected[0x788]=1
        require(after==bytes(expected) and [r['normalized_driver_bytes']for r in rows if r['operation']=='body']==[16],
            'Original legacy length24 did not request16 payload bytes and set read flag')
        underflow=dict(zero);underflow[140]=struct.pack('<Q',4);urows,uafter=run(underflow);uexpected=bytearray(blank);uexpected[0x788]=0
        body=[r for r in urows if r['operation']=='body'];require(uafter==bytes(uexpected)and len(body)==1 and
            body[0]['requested_bytes']==0xfffffffc and body[0]['normalized_driver_bytes']==4 and body[0]['native_generic_read_return']==1 and
            not body[0]['output_written'],'Original signed request normalization/lower rejection/read flag differs')
        invalid={n:struct.pack('<Q',(1<<32)+MAX_BODY_BYTES[n])for n in MAX_BODY_BYTES};irows,iafter=run(invalid)
        require(iafter==blank and len(irows)==5 and all(r['operation']=='header'for r in irows),'64-bit high word not rejected natively')
        record('original_legacy_length_and_signed_normalization_and_64bit_rejection_controls',
            legacy_header_value=24,legacy_body_bytes=16,legacy_native_read_flag=1,
            short_header_value=4,unsigned_underflow_request='0xfffffffc',original_generic_driver_normalizes_to4=True,
            lower_unavailable_body_returns1_no_output_native_flag0=True,underflow_read_requests=urows,
            five_high_word_headers_skip_all_body_reads=True,not_a_claim_of_live_driver_or_corrupt_factory_schema=True)
        partial={n:None for n in MAX_BODY_BYTES};partial[139]=struct.pack('<Q',32)+payload[139]
        rows,after=run(partial);expected=bytearray(blank);expected[8:42]=payload[139];expected[0x788]=0
        missing_bodies=[r for r in rows if r['operation']=='body'and r['bank']!=139]
        require(after==bytes(expected)and [r['bank']for r in missing_bodies]==[140,141,142,143]and
            all(r['native_generic_read_return']==11 and not r['output_written']for r in missing_bodies),
            'Original shared header buffer did not reuse earlier32 after later absent reads')
        record('original_shared_header_buffer_reuses_earlier_length_when_later_profiles_absent',
            supplied_first_bank_header=32,later_bank_header_reads_leave_outputs_unchanged=True,
            later_native_body_requests=[r['bank']for r in missing_bodies],native_bank140_read_failure_flag=0,
            guarded_object_only_declared_native_fields_change=True,not_claimed_as_device_firmware_bug=True)
        vm.install_inventory(absent)
        require(bytes(vm.uc.mem_read(PROFILE_TABLE,24))==b'\0'*24 and bytes(vm.uc.mem_read(DRIVER,2))==b'\x70\x47',
            'Synthetic registry restore or readonly lower driver code differs')
        vm.verify_descriptor_guards();require(not vm.invalid_accesses and not vm.audio and not vm.conditional_region_writes,
            'Focused consumer controls faulted or requested audio/GUI')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original voice RAM/40 exports changed')
        require(sha(DATABASE)==database_sha and not vm.statements,'Backup DB changed or unexpected SQL')
        snapshot=SelectionPlayerVM.finish(vm);vm.db.close()
        deps={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve(),
            STAGE/'consumer-metadata-static-preflight.json'}
        deps.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                p=Path(filename).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):deps.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(deps)},
            case_count=len(cases),all_passed=True,cases=cases,load=load,snapshot=snapshot,
            consumer_metadata_reads=vm.consumer_metadata_reads,native_bank_lookup_entries=vm.native_bank_lookup_entries,
            original_voice_RAM_and40_exports_unchanged=True,raw_DB_backup_unchanged=True,no_GUI_conditional_initialized_data_changes=True,
            descriptor_and_consumer_object_and_driver_inventory_guards_verified=True,synthetic_profile_table_restored_to_original_zero_BSS=True,
            actual_factory_schema_data_driver_boot_or_consumer_default_object_constructor_verified=False,
            general_MainMenu_constructor_or_controller_verified=False,device_io=False,sounds_emitted=False,
            limits='Five scoped controls execute original35D430 and2363B0 plus original26A300 read/26A240 profile lookup; missing native registry returns original11 without host success override. Present profiles and lower driver byte inventory are guarded fictional inputs, no factory metadata/schema or actual consumer default ctor proof. Native field copies/legacy/signed length/high-word/stale-header behavior observed with full code/voice40/canary/DB guards. No complete general Main/controller/foreground/accepted package/device App/audio or safe lifetime proof.')
        path=ROOT/'evidence/firmware-analysis/native-mainmenu-metadata-emulation.json';require(not path.exists(),'Use new proof namespace')
        path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,groups=len(cases),exact_dependencies=len(deps))),flush=True)
    except Exception as error:
        (STAGE/'focused-consumer-metadata-failure.json').write_text(json.dumps(dict(error=str(error),completed_cases=cases,all_final_guards_passed=False,
            recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries),ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases))),flush=True);sys.exit(1)

if __name__=='__main__':main()
