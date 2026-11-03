#!/usr/bin/env python3
"""Seal actual terminal evidence without relabeling partial development."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,struct

ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-heap-settings-boot/'
def read(path):return json.loads((ROOT/path).read_text())
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--session',type=int,required=True)
    parser.add_argument('--exit-code',type=int,required=True);args=parser.parse_args()
    inputs=read(BASE+'inputs-before-run.json')
    for path,digest in inputs['source_sha256'].items():assert sha(path)==digest,path
    runner=inputs['source'];snapshot=inputs['source_snapshot']
    assert sha(runner)==sha(snapshot)==inputs['source_sha256'][runner]
    path=BASE+'heap-settings-terminal-probe.json';probe=read(path)
    assert probe['source_sha256_before_run']==sha(runner)
    assert probe['completed']==(args.exit_code==0)
    assert not probe['device_io'] and not probe['sounds_emitted']
    peerpath=BASE+'static/runner-667d7225-peer-review.json';peer=read(peerpath)
    assert sha(runner) in json.dumps(peer)
    journal_checks=[]
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
        for row in probe['extra_zones']:
            expected=bytearray.fromhex(row['before_hex'])
            for store in row['stores']:
                offset=int(store['address'],16)-int(row['start'],16);size=store['size']
                assert 0<=offset and offset+size<=len(expected)
                assert expected[offset:offset+size].hex()==store['before_hex']
                expected[offset:offset+size]=int(store['value']).to_bytes(size,'little')
            assert row['whole_net_zone_matches_original_stores']
            assert hashlib.sha256(expected).hexdigest()==row['after_sha256']
            journal_checks.append(dict(start=row['start'],bytes=row['bytes'],original_stores=len(row['stores']),replayed=True))
        assert probe['initialized_data_journal']['whole_bank_matches_original_CPU_write_history']
        assert not probe['pending_raw_ops'] and not probe['invalid_accesses'] and not probe['native_fatal_entries']
    else:
        assert not probe['full_scoped_final_guards_passed'] and probe.get('error')
    record=dict(updated_utc=datetime.now(timezone.utc).isoformat(),session_id=args.session,
        terminal_exit_code=args.exit_code,runner=runner,runner_sha256=sha(runner),
        runner_snapshot=snapshot,runner_snapshot_sha256=sha(snapshot),
        inputs=BASE+'inputs-before-run.json',inputs_sha256=sha(BASE+'inputs-before-run.json'),
        probe=path,probe_sha256=sha(path),peer_review=peerpath,peer_review_sha256=sha(peerpath),
        sealer='scripts/seal_native_heap_settings_boot.py',sealer_sha256=sha('scripts/seal_native_heap_settings_boot.py'),
        old_protected_sources_unchanged=inputs['old_protected_source_count'],
        dependency_hashes_rechecked=len(inputs['source_sha256']),source_sha256=inputs['source_sha256'],
        phase=probe['phase'],completed=probe['completed'],error=probe.get('error'),
        full_scoped_final_guards_passed=probe['full_scoped_final_guards_passed'],
        independent_whole_zone_journal_replays=journal_checks,
        settings_initializer_returned=probe.get('settings_initializer_returned',False),
        allocator_opaque_translation_and_lower_release_remain_fixtures=True,
        native_mainmenu_foreground_or_physical_App_or_accepted_package_verified=False,
        selected_positive_native_suite_created=False,device_io=False,sounds_emitted=False,
        scope='Native heap/list/settings development on declared kernel, extent, NOR and lower-service inputs; no full hardware boot or App acceptance.')
    with (ROOT/BASE/'terminal-metadata.json').open('x') as handle:
        json.dump(record,handle,ensure_ascii=False,indent=2);handle.write('\n')
    print(json.dumps({k:record[k] for k in ['session_id','terminal_exit_code','completed','phase','error','full_scoped_final_guards_passed','old_protected_sources_unchanged']}))

if __name__=='__main__':main()
