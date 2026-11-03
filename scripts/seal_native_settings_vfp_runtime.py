#!/usr/bin/env python3
"""Attribute the frozen observer/driver and seal only actual native results."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,struct,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from analyze_native_sections import NativeImage,EXPECTED

ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-settings-vfp-context/'
RUNTIME=BASE+'runtime-v2/'
def read(path):return json.loads((ROOT/path).read_text())
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def registry(values):
    for path,digest in values.items():assert sha(path)==digest,path

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--session',type=int,required=True)
    parser.add_argument('--exit-code',type=int,required=True);args=parser.parse_args()
    inputs=read(RUNTIME+'inputs-before-run.json');registry(inputs['source_sha256'])
    runner=inputs['source'];snap=inputs['source_snapshot'];driver=inputs['driver']
    assert sha(runner)==sha(snap)==inputs['source_sha256'][runner]
    assert sha(driver)==inputs['driver_sha256']
    probepath=RUNTIME+'heap-settings-terminal-probe.json';probe=read(probepath)
    lazypath=RUNTIME+'native-lazy-vfp-state.json';lazy=read(lazypath)
    assert probe['source_sha256_before_run']==sha(driver)
    assert lazy['runner_sha256']==sha(runner) and lazy['driver_sha256']==sha(driver)
    assert lazy['helper_sha256']==sha('scripts/probe_native_lazy_vfp.py')
    assert probe['completed']==(args.exit_code==0) and not probe['device_io'] and not lazy['sounds_emitted']
    peerpath=BASE+'vfp-static/lazy-settings-v2-peer-review.json';peer=read(peerpath)
    assert sha(runner) in json.dumps(peer)
    replay=[];positive=None;positive_sha=None
    if probe['completed']:
        assert probe['full_scoped_final_guards_passed'] and probe['settings_initializer_returned']
        assert probe['settings_native_final_inventory_verified'] and not probe['foreground_or_device_App_verified']
        endpoint=probe['settings_native_endpoint']
        assert endpoint['whole_TCB108_compared_with_exact_native_deltas'] and len(endpoint['resident_four_frames'])==4
        assert not endpoint['real_allocator_release_or_physical_device_boot_verified']
        assert probe['heap_inventory']['whole_cold_workspace_recipe_checked']
        assert probe['heap_inventory']['whole_extent_matches_original_recipe']
        assert len(probe['heap_inventory']['listener_registration_returns'])==2
        assert probe['heap_after_settings']['whole_extent_matches_original_recipe']
        stock=NativeImage()
        for row in probe['extra_zones']:
            expected=bytearray.fromhex(row['before_hex'])
            for store in row['stores']:
                offset=int(store['address'],16)-int(row['start'],16);size=store['size'];pc=int(store['PC'],16)
                assert 0<=offset and offset+size<=len(expected)
                assert expected[offset:offset+size].hex()==store['before_hex']
                opcode=bytes.fromhex(store['opcode_hex'])
                assert stock.read(pc,len(opcode))==opcode
                expected[offset:offset+size]=int(store['value']).to_bytes(size,'little')
            assert row['whole_net_zone_matches_original_stores'] and hashlib.sha256(expected).hexdigest()==row['after_sha256']
            replay.append(dict(start=row['start'],bytes=row['bytes'],original_stores=len(row['stores']),replayed=True))
        assert probe['initialized_data_journal']['whole_bank_matches_original_CPU_write_history']
        assert not probe['pending_raw_ops'] and not probe['invalid_accesses'] and not probe['native_fatal_entries']
        assert lazy['active_handler'] is None and lazy['original_lazy_handler_rows']
        for row in lazy['original_lazy_handler_rows']:
            before=row['before'];after=row['after_native_handler']
            assert row['original_handler_entered'] and row['original_exception_return_seen'] and row['original_opcode_retry_reached']
            assert not row['host_wrote_FP_enable_or_context'] and row['undefined_entry_is_explicit_architectural_fixture']
            assert before['CPSR']==after['CPSR'] and before['GP15']==after['GP15'] and before['D16']==after['D16'] and before['FPSCR']==after['FPSCR']
            assert int(before['FPEXC'],16)&0x40000000==0 and after['FPEXC']=='0x40000000'
            assert after['FPowner']==before['current_TCB']=='0x9503f90'
        native=read('evidence/firmware-analysis/native-independent-signal-emulation.json')
        deps=dict(native['source_sha256'])
        for path in [runner,driver,'scripts/probe_native_lazy_vfp.py','scripts/probe_mainmenu_native_settings_prep.py',
                     'scripts/probe_mainmenu_native_settings_journal.py',
                     'staging/native-player-mainmenu-native-prep/heap-static/mainmenu-native-heap-mutex-preflight.json',
                     'staging/native-player-mainmenu-native-prep/mutex-static/mainmenu-native-settings-mutex-preflight.json']:
            deps[path]=sha(path)
        registry(deps)
        cases=[dict(name=name,passed=True) for name in [
            'original_heap_and_exit_settings_list_constructors_return',
            'original_settings_initializer_and_native_Timer_token_endpoint_return',
            'original_first_owner_lazy_VFP_handler_retries_actual_fault_without_FP_result_stub',
            'whole_native_memory_TCB_resident_frame_timed_node_and_store_journal_guards_pass']]
        doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
            all_passed=True,case_count=len(cases),cases=cases,source_sha256=deps,
            terminal_probe=probepath,terminal_probe_sha256=sha(probepath),
            lazy_evidence=lazypath,lazy_evidence_sha256=sha(lazypath),full_scoped_final_guards_passed=True,
            independent_whole_zone_journal_replays=replay,device_io=False,sounds_emitted=False,
            physical_App_or_full_boot_or_multi_owner_FP_or_accepted_package_verified=False,
            limits='Native heap/list/settings return on declared kernel/extent/NOR/opaque lower services. Original first/same-controller handler enables/retries using virtual CP access and architectural undefined banked-entry inputs. Four background frames and timed node remain resident. No original high-vector entry, FPboot/listener, metadata/context exchange, GUI foreground/touch, physical audio, package acceptance or safe unload.')
        positive='evidence/firmware-analysis/native-settings-lazy-vfp-emulation.json'
        with (ROOT/positive).open('x') as handle:json.dump(doc,handle,ensure_ascii=False,indent=2);handle.write('\n')
        positive_sha=sha(positive)
    else:
        assert not probe['full_scoped_final_guards_passed'] and probe.get('error')
    record=dict(updated_utc=datetime.now(timezone.utc).isoformat(),session_id=args.session,
        terminal_exit_code=args.exit_code,runner=runner,runner_sha256=sha(runner),
        runner_snapshot=snap,runner_snapshot_sha256=sha(snap),driver=driver,driver_sha256=sha(driver),
        inputs=RUNTIME+'inputs-before-run.json',inputs_sha256=sha(RUNTIME+'inputs-before-run.json'),
        probe=probepath,probe_sha256=sha(probepath),lazy_evidence=lazypath,lazy_evidence_sha256=sha(lazypath),
        peer_review=peerpath,peer_review_sha256=sha(peerpath),
        sealer='scripts/seal_native_settings_vfp_runtime.py',sealer_sha256=sha('scripts/seal_native_settings_vfp_runtime.py'),
        source_sha256=inputs['source_sha256'],old_protected_sources_unchanged=535,
        phase=probe['phase'],completed=probe['completed'],error=probe.get('error'),
        settings_initializer_returned=probe.get('settings_initializer_returned',False),
        full_scoped_final_guards_passed=probe['full_scoped_final_guards_passed'],
        positive_native_proof=positive,positive_native_proof_sha256=positive_sha,
        original_lazy_handler_count=len(lazy['original_lazy_handler_rows']),
        independent_whole_zone_journal_replays=replay,
        device_io=False,sounds_emitted=False,foreground_or_physical_App_or_multi_owner_FP_verified=False)
    with (ROOT/RUNTIME/'terminal-metadata.json').open('x') as handle:
        json.dump(record,handle,ensure_ascii=False,indent=2);handle.write('\n')
    print(json.dumps({key:record[key] for key in ['session_id','terminal_exit_code','completed','phase','error','full_scoped_final_guards_passed','original_lazy_handler_count','positive_native_proof']}))

if __name__=='__main__':main()
