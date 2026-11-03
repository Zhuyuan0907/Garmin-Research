#!/usr/bin/env python3
"""Seal a terminal native Dispatcher attempt using the tool's actual exit."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json
ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-dispatcher-native-body/runtime/'
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--session',type=int,required=True);parser.add_argument('--exit-code',type=int,required=True)
    args=parser.parse_args();out=ROOT/BASE/'terminal-metadata.json';assert not out.exists()
    inputs,probe=read(BASE+'inputs-before-run.json'),read(BASE+'terminal-probe.json')
    for p,s in inputs['source_sha256'].items():assert sha(p)==s,p
    runner='scripts/probe_native_dispatcher_body_fp.py';snapshot=BASE+'runner-at-run.py'
    assert sha(runner)==sha(snapshot)==inputs['source_sha256'][runner]==probe['source_sha256_before_run']
    assert args.exit_code==(0 if probe['completed'] else 1)
    paths=dict(runner=runner,runner_snapshot=snapshot,inputs=BASE+'inputs-before-run.json',probe=BASE+'terminal-probe.json',
        FP_helper='scripts/native_dispatcher_multiowner_vfp.py',GUI_observer='staging/native-player-dispatcher-native-body/gui-static/dispatcher_actor_observer.py',
        sealer=str(Path(__file__).resolve().relative_to(ROOT)))
    if probe.get('cold_prefix_evidence'):
        paths['cold_prefix']=probe['cold_prefix_evidence'];assert sha(paths['cold_prefix'])==probe['cold_prefix_evidence_sha256']
    metadata=dict(updated_utc=datetime.now(timezone.utc).isoformat(),session_id=args.session,terminal_exit_code=args.exit_code,
        authoritative_terminal_result_received_from_exec=True,**paths,**{k+'_sha256':sha(p) for k,p in paths.items()},
        source_sha256=inputs['source_sha256'],completed=probe['completed'],phase=probe['phase'],error=probe.get('error'),
        cold_prefix_full_guards_passed=probe['cold_prefix_full_guards_passed'],body_full_guards_passed=probe['body_full_guards_passed'],
        callback_entry_seen=probe.get('callback_entry_seen',False),callback_return_seen=probe.get('callback_return_seen',False),
        post_cold_FP_rows=len(probe.get('original_lazy_handler_rows',[])) if probe.get('callback_entry_seen') else 0,
        device_io=False,sounds_emitted=False,physical_App_direct_music_or_package_acceptance_verified=False)
    with out.open('x') as f:json.dump(metadata,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps({k:metadata[k] for k in ['session_id','terminal_exit_code','phase','error','cold_prefix_full_guards_passed','callback_entry_seen','body_full_guards_passed']}))
if __name__=='__main__':main()
