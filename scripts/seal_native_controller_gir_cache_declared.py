#!/usr/bin/env python3
"""Attribute outer/inner/controller sources for one confirmed terminal run."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-controller-gir-integration/runtime-cache-declared/'
PREVIOUS='staging/native-player-cache-declared-followup/'
def read(path):return json.loads((ROOT/path).read_text())
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def main():
    session_id,exit_code=int(sys.argv[1]),int(sys.argv[2]);review=sys.argv[3]
    outer='scripts/probe_native_controller_gir_cache_declared.py';inner='scripts/probe_native_controller_gir_component_contiguous.py';driver='scripts/probe_native_controller_gir_component.py'
    paths=dict(runner=outer,runner_snapshot=BASE+'outer-observer-at-run.py',inner_observer=inner,inner_snapshot=BASE+'observer-at-run.py',
        driver=driver,driver_snapshot=BASE+'runner-at-run.py',outer_inputs=BASE+'outer-observer-inputs-before-run.json',
        inner_inputs=BASE+'observer-inputs-before-run.json',driver_inputs=BASE+'inputs-before-run.json',probe=BASE+'terminal-probe.json',
        actual_observer_state=BASE+'actual-observer-state.json',declared_cache_state=BASE+'declared-cache-observer-state.json',
        peer_review=review,previous_checkpoint=PREVIOUS+'previous-checkpoint.json',previous_audit=PREVIOUS+'previous-audit.json',
        sealer=str(Path(__file__).resolve().relative_to(ROOT)))
    registry={}
    for key in ['outer_inputs','inner_inputs','driver_inputs']:
        for path,digest in read(paths[key])['source_sha256'].items():
            assert sha(path)==digest,path
            assert path not in registry or registry[path]==digest,path
            registry[path]=digest
    p=read(paths['probe']);a=read(paths['actual_observer_state']);c=read(paths['declared_cache_state'])
    assert sha(outer)==sha(paths['runner_snapshot'])==c['outer_observer_sha256']
    assert sha(inner)==sha(paths['inner_snapshot'])==a['observer_sha256']==c['driver_observer_sha256']
    assert sha(driver)==sha(paths['driver_snapshot'])==a['driver_sha256']==p['source_sha256_before_run']
    assert exit_code==(0 if p['completed']else 1)
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),session_id=session_id,terminal_exit_code=exit_code,
        authoritative_terminal_result_received_from_exec=True,**paths,**{key+'_sha256':sha(path)for key,path in paths.items()},
        source_sha256=registry,completed=p['completed'],full_scoped_final_guards_passed=p['full_scoped_final_guards_passed'],
        settings_all_scoped_guards_passed=p.get('settings_all_scoped_guards_passed',False),phase=p.get('phase'),error=p.get('error'),
        registers=p.get('registers'),component_native_original_helpers_entered=len(p.get('component_calls',[])),
        component_native_original_helpers_returned=sum(row['returned']for row in p.get('component_calls',[])),
        original_cache_allocations_observed=len(a['native_cache_allocations']),native_cache_CPU_store_count=a['native_cache_CPU_store_count'],
        new_zero_page_inputs=len(c['declared_startup_zero_cache_pages']),cache_observer_UcErrors=c['cache_observer_UcErrors'],
        unexpected_emulation_UcErrors=c['unexpected_emulation_UcErrors'],physical_App_or_menu_or_direct_phone_music_verified=False,
        device_io=False,sounds_emitted=False)
    with (ROOT/BASE/'terminal-metadata.json').open('x')as out:json.dump(result,out,ensure_ascii=False,indent=2);out.write('\n')
    print(json.dumps({key:result[key]for key in ['session_id','terminal_exit_code','completed','component_native_original_helpers_returned','original_cache_allocations_observed','native_cache_CPU_store_count','error']}))
if __name__=='__main__':main()
