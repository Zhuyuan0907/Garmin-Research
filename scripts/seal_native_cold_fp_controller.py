#!/usr/bin/env python3
"""Seal one cold-controller terminal run using the execution tool's exit result."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json
ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-cold-fp-controller/runtime/'
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--session',type=int,required=True)
    parser.add_argument('--exit-code',type=int,required=True);args=parser.parse_args()
    out=ROOT/BASE/'terminal-metadata.json';assert not out.exists(),'Keep terminal metadata immutable'
    inputs=read(BASE+'inputs-before-run.json');probe=read(BASE+'terminal-probe.json')
    runner='scripts/probe_native_cold_fp_controller.py';snapshot=BASE+'runner-at-run.py'
    assert sha(runner)==sha(snapshot)==inputs['source_sha256'][runner]==probe['source_sha256_before_run']
    for p,d in inputs['source_sha256'].items():assert sha(p)==d,p
    assert args.exit_code==(0 if probe['completed']else 1)
    paths=dict(runner=runner,runner_snapshot=snapshot,inputs=BASE+'inputs-before-run.json',probe=BASE+'terminal-probe.json',
        guard_copy_source='scripts/native_cold_fp_guard_copies.py',guard_copy_provenance='staging/native-player-cold-fp-controller/guard-copy-provenance.json',
        previous_checkpoint='staging/native-player-cold-fp-controller/previous-checkpoint.json',
        sealer=str(Path(__file__).resolve().relative_to(ROOT)))
    meta=dict(updated_utc=datetime.now(timezone.utc).isoformat(),session_id=args.session,terminal_exit_code=args.exit_code,
        authoritative_terminal_result_received_from_exec=True,**paths,
        **{k+'_sha256':sha(p)for k,p in paths.items()},source_sha256=inputs['source_sha256'],
        completed=probe['completed'],full_scoped_final_guards_passed=probe['full_scoped_final_guards_passed'],phase=probe['phase'],
        error=probe.get('error'),cold_boot_sealed=probe.get('cold_boot_sealed',False),
        original_FP_boot_registration_returned=bool((probe.get('FP_boot_registration')or{}).get('returned')),
        original_controller_native_FF_fill_checked=bool((probe.get('cold_fill')or{}).get('whole16384_FF_checked')),
        original_helpers_returned=sum(r['returned']for r in probe.get('component_calls',[])),
        physical_App_or_foreground_or_multiowner_FP_or_package_or_direct_phone_music_verified=False,
        device_io=False,sounds_emitted=False)
    with out.open('x')as f:json.dump(meta,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps({k:meta[k]for k in ['session_id','terminal_exit_code','completed','phase','error','cold_boot_sealed','original_helpers_returned']}))
if __name__=='__main__':main()
