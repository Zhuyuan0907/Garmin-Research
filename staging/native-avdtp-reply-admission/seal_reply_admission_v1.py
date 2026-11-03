#!/usr/bin/env python3
"""Seal completed native wire scopes and their preserved failures, FILE only."""
import json,hashlib
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    proof=json.loads((BASE/'ROOT-native-reply-admission-file-proof-v2.json').read_text())
    assert proof['all_passed']and proof['case_count']==8 and not proof['VM_import_or_execution']
    assert not proof['native_send_zero_with_written_zero_demonstrated']
    sources=dict(proof['source_sha256'])
    for p,h in sources.items():assert sha(ROOT/p)==h,p
    for p in BASE.rglob('*'):
        if p.is_file()and '__pycache__'not in p.parts:sources[str(p.relative_to(ROOT))]=sha(p)
    seal=dict(all_passed=True,source_sha256=sources,selected_scopes='staging/native-avdtp-reply-admission/ROOT-selected-eight-wire-scopes-v2.json',
              ROOT_FILE='staging/native-avdtp-reply-admission/ROOT-native-reply-admission-file-proof-v2.json',
              case_count=8,completed_exit1_prefix_cases=2,new_exit0_cases=6,totals=proof['totals'],
              command_scope_generation_not_remote_stream_generation=True,native_Config_state2_precedes_reply=True,
              original_pending_Open_reject_Start_false_state_transition_blocked=True,
              false_native_TX_return0_inference_corrected=True,accepted_stream_generation_binding_still_required=True,
              direct_phone_PCM_App_or_warm_ownership_or_physical_verified=False,new_independent_agent_review=False,
              guest_rerun_or_device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
    p=BASE/'ROOT-native-reply-admission-terminal-seal-v1.json'
    with p.open('x')as f:json.dump(seal,f,indent=2);f.write('\n')
    print(json.dumps(dict(all_passed=True,case_count=8,source_count=len(sources),seal_sha256=sha(p),totals=proof['totals'],device_IO=False)))
if __name__=='__main__':main()
