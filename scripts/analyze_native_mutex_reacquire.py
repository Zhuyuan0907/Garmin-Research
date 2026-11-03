#!/usr/bin/env python3
"""Explain current native wait/unlock failure from exact CFG and harness scopes."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import ROOT,EXPECTED

def main():
    base=ROOT/'staging/native-player-mutex-owner'
    waitpath=ROOT/'staging/native-player-dispatcher-bootstrap/condition-owner-static-preflight.json'
    wait=json.loads(waitpath.read_text())
    for p,s in wait['source_sha256'].items():assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==s,p
    rows={int(r['address'],16):r for r in wait['functions']['0x3ec5c6']['instructions']}
    assert rows[0x3ec68c]['instruction']=='movs r0, r5'
    assert rows[0x3ec68e]['direct_call']=='0x3009a0'and rows[0x3ec694]['direct_call']=='0x21b6dc'
    probe_path=base/'dispatcher-native-owner-terminal-failure.json';probe=json.loads(probe_path.read_text())
    assert probe['native_condition_waits'][0]['native_owner_gate_passed']and '0x6048d2'in probe['recent']
    fatal=probe['native_fatal_entries'][-1]
    assert fatal['arguments'][:2]==['0x6e5d800b','0x2']and fatal['caller']=='0x3008e0'
    op=probe['native_mutex_operations'][-1]
    assert op['operation']=='unlock'and op['native_caller']=='0x310414'and op['before_words'][2]=='0x0'
    assert probe['mutex_inventory'][op['pointer']]==2
    owner=ROOT/'scripts/probe_native_mutex_owner.py'
    original_probe=base/'source-at-dispatcher-native-owner-failure.py'
    parent=ROOT/'scripts/emulate_native_vpm_filesystem.py'
    assert 'allowed=ptr in self.native_semaphores and (caller==RETURN or condition)'in owner.read_text()
    assert '0x3ec692'not in original_probe.read_text()
    assert "0x3009a0: 'mutex_lock'"in parent.read_text()
    assert "elif name == 'mutex_lock': self.mutexes[args[0]] += 1"in parent.read_text()
    files=[Path(__file__).resolve(),waitpath,probe_path,owner,original_probe,parent,
           ROOT/'evidence/firmware-analysis/main_02bd.bin']
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in files},
        exact_original_reacquire_call='0x3ec68e ->0x3009a0',original_reacquire_native_caller='0x3ec692',
        current_reacquire_scope_gap_inferred_from_original_CFG_and_harness=True,
        current_native_owner_gate_passed=True,actual_wait_return_observed_in_recent='0x6048d2',
        raw_wait_return_false_field_was_unupdated_default=True,
        subsequent_original_unlock=op,native_fatal=fatal,
        observed_counter2_with_native_owner0_is_inconsistent_bookkeeping=True,
        inherited_counter_only_backend_not_native_owner_reacquisition=True,
        original300BB8_release_not_yet_reconciled_in_observed_counters=True,
        equal_F09090_F090A0_same_owner_fixture_not_real_wait_or_event_delivery=True,
        successful_wait_event_scheduler_dispatcher_foreground_or_device_App_verified=False,
        device_io=False,sounds_emitted=False,
        limits='Source/CFG explanation of partial45010, not another successful native run. Native owner gate and subsequent wait return/unowned unlock are directly recorded; reacquisition fallback is inferred from exact original3EC68E call and current subclass/parent hook scopes. Counter-only3009A0 changes no native owner field. Raw wait-return false is an unupdated journal default, not nonreturn evidence. Real wake/event delivery and original constructor owner/thread identities remain unverified; equal fictional TCB can select a different wait path from actual boot. Restore original reacquire and journal native releases before any complete dispatcher claim.')
    path=base/'reacquisition-boundary-preflight.json';assert not path.exists()
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(native_reacquire_caller='0x3ec692',owner_gate_passed=True,wait_return_observed=True,dispatcher_complete=False)))

if __name__=='__main__':main()
