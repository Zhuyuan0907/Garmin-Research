#!/usr/bin/env python3
"""Seal a confirmed terminal native-settings run without changing its source."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,sys
from analyze_native_sections import ROOT,EXPECTED

STAGE=ROOT/'staging/native-player-mainmenu-native-prep/journal-runtime'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    session,exit_code=map(int,sys.argv[1:3])
    target=STAGE/'terminal-metadata.json';assert not target.exists()
    probe=STAGE/'settings-native-prep-terminal-probe.json';d=json.loads(probe.read_text())
    inputs=json.loads((STAGE/'inputs-before-run.json').read_text())
    for p,s in inputs['source_sha256'].items():assert digest(ROOT/p)==s,p
    runner=ROOT/'scripts/probe_mainmenu_native_settings_journal.py'
    assert digest(runner)==digest(STAGE/'runner-at-run.py')
    driver=ROOT/'scripts/probe_mainmenu_native_settings_prep.py'
    assert d['source_sha256_before_run']==digest(driver)
    assert d['completed']==(exit_code==0)
    meta=dict(updated_utc=datetime.now(timezone.utc).isoformat(),session_id=session,terminal_exit_code=exit_code,
        runner=str(runner.relative_to(ROOT)),runner_sha256=digest(runner),
        runner_snapshot=str((STAGE/'runner-at-run.py').relative_to(ROOT)),runner_snapshot_sha256=digest(STAGE/'runner-at-run.py'),
        driver=str(driver.relative_to(ROOT)),driver_sha256=digest(driver),
        probe=str(probe.relative_to(ROOT)),probe_sha256=digest(probe),
        completed=d['completed'],full_scoped_final_guards_passed=d['full_scoped_final_guards_passed'],
        phase=d['phase'],error=d.get('error'),device_io=False,sounds_emitted=False)
    if d['completed']:
        assert d['full_scoped_final_guards_passed'] and not d['invalid_accesses'] and not d['native_fatal_entries']
        inv=d['settings_native_inventory'];journal=inv['whole_mutable_initialized_bank']
        assert journal['whole_bank_matches_original_CPU_write_history'] and journal['bytes']==467532
        assert len(inv['raw_init_operations'])==5 and len(inv['retained_tokens'])==2
        assert not inv['inherited_settings_lock_ret0_used'] and all(r['native_body_returned'] for r in inv['native_raw_mutex_operations'])
        old=json.loads((ROOT/'evidence/firmware-analysis/native-independent-signal-emulation.json').read_text())
        deps=dict(old['source_sha256']);deps.update(inputs['source_sha256'])
        for p in ['scripts/analyze_mainmenu_native_settings_mutex.py',str(Path(__file__).resolve().relative_to(ROOT))]:deps[p]=digest(ROOT/p)
        for p,s in deps.items():assert digest(ROOT/p)==s,p
        proof=dict(updated_utc=meta['updated_utc'],MAIN_sha256=EXPECTED,all_passed=True,case_count=3,
            cases=[dict(name='prior_original_singleton_inventory_and_memory_guards',passed=True,
                inventory=d['prior_singleton_inventory'],memory=d['prior_memory_guards']),
                dict(name='actual_controller_five_native_settings_semaphores_and_dual_Timer_condition_tokens',passed=True,
                    inventory=inv),dict(name='whole_initialized_bank_CPU_store_history_and_existing_memory_guards',passed=True,
                    journal=journal,memory=d['settings_whole_memory_guards'])],
            source_sha256=deps,original_MAIN_patch_bytes=0,device_io=False,sounds_emitted=False,
            scope='Native settings initialization from an actual controller on explicitly initialized kernel/NOR/BSS fixtures. Five native raw semaphore initializers, reviewed raw lock calls and real retained condition lock/Timer transfer are executed. Whole108 TCBs are compared except the Timer owned head; two owned condition-token records and raw backend epilogues are checked. Whole467532 initialized-data bank matches observed CPU stores, each writer instruction bytes checked against exact MAIN; existing voice/code/privateAPI/GUI/DB/allocation/storage/descriptor/stack-boundary guards pass.',
            limits='This is not full boot, GIR/font/menu preparation, Dispatcher MainMenu body, foreground/touch, accepted package, hardware IRQ/audio or physical App. Synthetic NOR and recovered-zero BSS pages are fixtures. Mutable-bank history checks final/net bank changes and intervening journal writes, not all possible same-value/restored host writes. Background live saved-frame contents and timed-node interior are not newly compared in this settings endpoint; TCB words and stack boundaries are checked. No safe cleanup/unload or direct phone music proof.',
            background_saved_frames_or_timed_node_interiors_newly_verified=False,
            actual_MainMenu_body_or_foreground_verified=False,device_install_candidate=False)
        path=ROOT/'evidence/firmware-analysis/native-mainmenu-settings-prep-emulation.json'
        with path.open('x')as f:json.dump(proof,f,ensure_ascii=False,indent=2);f.write('\n')
        meta.update(complete_proof=str(path.relative_to(ROOT)),complete_proof_sha256=digest(path))
    with target.open('x')as f:json.dump(meta,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(session_id=session,terminal_exit_code=exit_code,completed=d['completed'],
        native_settings_proof=meta.get('complete_proof'))))

if __name__=='__main__':main()
