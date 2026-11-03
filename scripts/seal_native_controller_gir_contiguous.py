#!/usr/bin/env python3
"""Seal a known-terminal exec session; never infer liveness from a JSON file."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-controller-gir-integration/runtime-contiguous/'
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def read(path):return json.loads((ROOT/path).read_text())
def main():
    session_id,exit_code=int(sys.argv[1]),int(sys.argv[2]);review=sys.argv[3]
    runner='scripts/probe_native_controller_gir_component_contiguous.py';driver='scripts/probe_native_controller_gir_component.py'
    probe_path=BASE+'terminal-probe.json';probe=read(probe_path);actual_path=BASE+'actual-observer-state.json';actual=read(actual_path)
    inputs_path=BASE+'observer-inputs-before-run.json';inputs=read(inputs_path)
    for path,digest in inputs['source_sha256'].items():assert sha(path)==digest,path
    assert sha(runner)==sha(BASE+'observer-at-run.py')==actual['observer_sha256']
    assert sha(driver)==sha(BASE+'runner-at-run.py')==probe['source_sha256_before_run']==actual['driver_sha256']
    assert exit_code==(0 if probe['completed'] else 1)
    if probe['completed']:
        assert probe['full_scoped_final_guards_passed'] and len(probe['component_calls'])==11 and all(x['returned']for x in probe['component_calls'])
    metadata=dict(updated_utc=datetime.now(timezone.utc).isoformat(),session_id=session_id,terminal_exit_code=exit_code,
        authoritative_exit_received_from_exec_tool=True,runner=runner,runner_sha256=sha(runner),
        runner_snapshot=BASE+'observer-at-run.py',runner_snapshot_sha256=sha(BASE+'observer-at-run.py'),
        driver=driver,driver_sha256=sha(driver),driver_snapshot=BASE+'runner-at-run.py',driver_snapshot_sha256=sha(BASE+'runner-at-run.py'),
        inputs=inputs_path,inputs_sha256=sha(inputs_path),probe=probe_path,probe_sha256=sha(probe_path),
        actual_observer_state=actual_path,actual_observer_state_sha256=sha(actual_path),peer_review=review,peer_review_sha256=sha(review),
        sealer=str(Path(__file__).resolve().relative_to(ROOT)),sealer_sha256=sha(str(Path(__file__).resolve().relative_to(ROOT))),
        completed=probe['completed'],full_scoped_final_guards_passed=probe['full_scoped_final_guards_passed'],
        settings_all_scoped_guards_passed=probe.get('settings_all_scoped_guards_passed',False),
        component_native_original_helpers_entered=len(probe.get('component_calls',[])),
        component_native_original_helpers_returned=sum(row['returned']for row in probe.get('component_calls',[])),
        phase=probe['phase'],error=probe.get('error'),registers=probe.get('registers'),
        original_cache_allocations_observed=len(actual['native_cache_allocations']),native_cache_CPU_store_count=actual['native_cache_CPU_store_count'],
        native_component_foreground_or_physical_App_verified=False,device_io=False,sounds_emitted=False,
        limitation='Only reached original native instructions and explicit external input fixtures are evidence. Final guards require a full endpoint; no physical App, menu foreground, package acceptance or direct phone music claim.')
    with (ROOT/BASE/'terminal-metadata.json').open('x')as out:json.dump(metadata,out,ensure_ascii=False,indent=2);out.write('\n')
    print(json.dumps({key:metadata[key]for key in ['session_id','terminal_exit_code','completed','component_native_original_helpers_returned','error']}))
if __name__=='__main__':main()
