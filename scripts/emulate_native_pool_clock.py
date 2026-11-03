#!/usr/bin/env python3
"""Five scoped clock/addition/scan/failure/unlock controls with full guards."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_pool_clock import PoolClockVM
from probe_native_player_mainmenu import BUILD
from emulate_native_player_menu_selection import SelectionPlayerVM,DATABASE,sha
from emulate_native_vpm_filesystem import require

STAGE=ROOT/'staging/native-player-pool-clock'

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());vm=PoolClockVM(NativeImage(),build);cases=[];dbsha=sha(DATABASE)
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        for name,word in [('original_zero_clock_retains1000_baseline',0),('original_nonzero20_clock_requests1020',20),
            ('original180_clock_requests1180_without_fixed1000_override',180),('original_u32_wraparound_addition_is_retained',0xfffffe00)]:
            vm.set_pool_clock_inputs([word]);before=len(vm.pool_native_runs)
            value=vm.invoke(0x3b4ba9,(0,))
            require(value==255 and len(vm.pool_native_runs)==before+1 and not vm.scripted_pool_clock_inputs and
                vm.pool_context is None and not any(vm.mutexes.values()),'Original pool did not returnFF with balanced locks')
            row=vm.pool_native_runs[-1];require(row['clock_result']==word and
                row['native_calculated_argument']==(word+1000)&0xffffffff,'Native clock/addition differs')
            record(name,original_native_run=row,original_returned_index=value,
                lower_wait_failure=vm.pool_wait_failures[-1],real_time_units_or_kernel_condition_owner_verified=False)
        vm.set_pool_clock_inputs(None);vm.virtual_clock_milliseconds=0
        before=len(vm.pool_native_runs)
        values=[vm.invoke(0x3b4ba9,(0,))for _ in range(2)];rows=vm.pool_native_runs[before:]
        require(values==[255,255]and [r['clock_result']for r in rows]==[20,40]and
            [r['native_calculated_argument']for r in rows]==[1020,1040]and not any(vm.mutexes.values()),
            'Original repeated reads failed to track advancing virtual time')
        record('repeated_original_pool_calls_track_advancing_input_and_release_locks',native_runs=rows,
            original_returned_indices=values,host_reentered_current_native_function=False)
        require(not vm.invalid_accesses and not vm.audio and not vm.conditional_region_writes and vm.pool_context is None,
            'Focused pool controls faulted, requested audio/GUI or retained native context')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original whole voice RAM/40 exports changed')
        require(sha(DATABASE)==dbsha and not vm.statements,'Readonly backup DB changed or unexpected SQL')
        vm.verify_descriptor_guards();snapshot=SelectionPlayerVM.finish(vm);vm.db.close()
        deps={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve(),
            ROOT/'staging/native-player-mainmenu-controller/audio-pool-clock-argument-preflight.json',
            ROOT/'staging/native-player-mainmenu/MainMenu-root-settings-preflight.json'}
        deps.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                p=Path(filename).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):deps.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(deps)},
            all_passed=True,case_count=len(cases),cases=cases,load=load,snapshot=snapshot,
            original_pool_runs=vm.pool_native_runs,scoped_lower_wait_failures=vm.pool_wait_failures,
            virtual_clock_inputs=vm.virtual_clock_ticks,original_voice_RAM_and40_exports_unchanged=True,
            descriptor_guards_and_raw_DB_backup_unchanged=True,no_GUI_initialized_data_changes=True,
            controller_root_foreground_device_App_audio_and_kernel_scheduling_verified=False,device_io=False,sounds_emitted=False,
            limits='Five complete controls execute original353A9C read,3B4BA8 clock+1000 modulo u32, original stack store/load, seven-slot scan, nativeFF failure/unlock. Exact lower unavailable-wait failure1 requires original caller, computed argument and held fixture mutex1; no argument rewrite or host final index. Explicit clock words and lower heap/kernel/storage/absent pool remain fixtures, no actual time units/owner/scheduler/audio pool. Same frozen EMULATION-ONLY loaded player; whole voice40/private12/player2/code/canary/DB guards pass. No general controller/root/foreground/accepted loading/device App/audio/safe lifetime proof.')
        path=ROOT/'evidence/firmware-analysis/native-pool-clock-emulation.json';require(not path.exists(),'Use new proof namespace')
        path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,groups=len(cases),exact_dependencies=len(deps))),flush=True)
    except Exception as error:
        (STAGE/'focused-pool-clock-failure.json').write_text(json.dumps(dict(error=str(error),completed_cases=cases,
            all_final_guards_passed=False,register_recent=list(vm.recent),pool_context=vm.pool_context,
            pool_native_runs=vm.pool_native_runs,scoped_lower_wait_failures=vm.pool_wait_failures,
            mutex_inventory={hex(p):n for p,n in vm.mutexes.items()},invalid_accesses=vm.invalid_accesses),ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases),all_final_guards_passed=False)),flush=True);sys.exit(1)

if __name__=='__main__':main()
