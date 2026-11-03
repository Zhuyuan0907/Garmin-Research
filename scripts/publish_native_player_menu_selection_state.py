#!/usr/bin/env python3
"""Publish caption correction/SQL selection; preserve GUI and device limits."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,value):(ROOT/p).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')

def main():
    previous=read('staging/native-player-menu-selection/previous-checkpoint.json')
    before=read(previous['state']);prior=read(previous['audit'])
    assert prior['all_passed'] and prior['state_sha256']==sha(previous['state'])
    state=read('evidence/deep-research-state.json');task=read('evidence/task-state.json')
    for name,value in before['native_app_music']['static_findings'].items():
        assert state['native_app_music']['static_findings'][name]==value,name
    evidence='evidence/firmware-analysis/native-player-menu-selection-emulation.json'
    proof=read(evidence);build=read(proof['build_manifest'])
    assert proof['all_passed'] and proof['case_count']==3 and not proof['device_io']
    assert sha(proof['build_manifest'])==proof['build_manifest_sha256']
    for p,h in proof['source_sha256'].items():assert sha(p)==h,p
    assert not state['attended_testing']['user_present']
    now=datetime.now(timezone.utc).isoformat()
    item={k:v for k,v in proof.items() if k not in ['source_sha256','cases']}
    item.update({'evidence':evidence,'evidence_sha256':sha(evidence),
        'case_names':[c['name'] for c in proof['cases']],
        'extension_bytes':build['extension_bytes'],'combined_file_bytes':build['combined_file_bytes'],
        'combined_ram_bytes':build['combined_ram_bytes'],'BSS_bytes':build['BSS_bytes'],
        'caption_string_bytes':16,'caption_record_bytes':20,'caption_auxiliary_initialized_to_zero':True,
        'SQL_selection_scenarios':len(proof['cases'][1]['stages']),
        'SQLite_engine_is_host_in_memory_fixture':True,'widget_factory_is_boundary':True,
        'root_Add_stops_before_constructor':True,'previous_checkpoint':previous})
    app=state['native_app_music'];app['static_findings']['native_player_menu_selection']=item
    app['current_player_variant']=proof['build_manifest']
    app['player_caption_initialization_and_SQL_cell_selection_offline']=True
    app.setdefault('development_observations',{})['caption_and_Add_selection']={
        'old_stack_poison_retained_auxiliary_word':'0xa5a5a5a5',
        'old_text_only_tests_did_not_cover_auxiliary_word':True,
        'prior_physical_UI_failure_proven':False,
        'corrected_variant':proof['build_manifest'],
        'stock_string_ctor_copy_size16_plus_separate_caption_auxiliary4':True,
        '3954F0_is_Thumb_refcount_holder_cleanup_not_raw_free':True,
        'selection_suite_first_partial_failed_on_old_raw_free_model':True,
        'original_cleanup_executes_after_removing_only_the_bad_fixture_hook':True,
        'complete_three_group_run_terminal0_after_fix':True,
        'matched_lookup_ignores_widget_factory_return_not_widget_success':True}
    actions=[
        'Execute the original normal/Add widget constructors and event/render chain using the caption-initialized variant. Original SQL setter/getter and6 selection scenarios now pass with host in-memory SQLite engine fixture; category0 reaches6A56D8 but stops before construction. Actual rendered/touchable App remains unverified.',
        'Recover/verify visual resources and caption auxiliary semantics, DB open/schema readiness, GUI shared ownership and UI-thread timing. Previous variants left caption auxiliary uninitialized; retain historical evidence but use the corrected selection variant for further UI work.3954F0 is native refcount cleanup, not raw free.',
        'Establish accepted modified VPM loading, ID9 playback ownership/repeated clicks/stop and resident module callbacks/strings. No MAIN patch in player variant, but physical SIG/package acceptance and safe unregister/reload/unload remain open. Never install EMULATION-ONLY package.',
        'Connect player controls to direct Bluetooth music and original continuous-source/kernel pipeline; representative packet pacing, adequate buffer/prefill, reader-copy cancellation, initialization failure recovery and speaker/navigation coexistence remain required. Stereo/fidelity polishing stays deprioritized.',
        'User sleeping: offline only, no calls/sounds/device writes or physical questions. On return prepare live audio service and matching-device pairing agent first. Microphone canceled; Android Auto after player/music; Maps deferred; full goal active/no-achieve.'
    ]
    state['next_actions']=actions;app['remaining_work']=actions[:4];state['updated_utc']=now
    state['last_goal_turn']={'classification':'progress','previous_goal_turn_classification':'progress',
        'validated_utc':now,'previous_state_snapshot':previous['state'],
        'previous_current_audit_snapshot':previous['audit'],
        'previous_turn_revalidation':'Fresh prior14-scope loaded menu audit saved with exact state;18 earlier evidence suites remain frozen.',
        'reasons':[
            'Poisoned-stack control exposes original caption auxiliaryA5 despite correct UTF16 text; corrected new namespace models16-byte string plus4-byte auxiliary initialized0. Prior binaries/sources untouched.',
            'Relink54906 code2353926 file2462860 RAM18036 BSS, original40/private12/player2 preserved, no MAIN patch; full3-group terminal0 proof with81 dependencies.',
            'Native SQL formatting/UTF conversion/bind/step/error mapping/finalize/getter/setter/caption and chosen callback execute. Host SQLite engine uses verified backup copied read-only into memory;6 scenarios, all15 rows restored, backup unchanged.',
            'Native normal getter matched1 selects record but ignores widget-factory return; boundary output untouched, no Widget/render claim. Category1 excludes player and returns; category0 reaches actual6A56D8 with corrected caption then stops before constructor.',
            'First partial run exposed wrong3954F0 raw-free fixture; originalThumb reference-count cleanup now executes, full suite rerun. User asleep; no physical I/O/sound/package installation; full goal active.'
        ],
        'build_manifest':proof['build_manifest'],'build_manifest_sha256':proof['build_manifest_sha256'],
        'integration_evidence':evidence,'integration_evidence_sha256':sha(evidence),
        'offline_integration_device_io':False,'device_io':False,'device_files_written':False,
        'native_firmware_or_research_package_written':False,'automatic_calls_or_sound':False,
        'attended_calls_or_sound':False,'automatic_calls_or_sound_while_away':False,
        'next_focus':actions[0],'goal_status':'active','full_goal_complete':False}
    for key in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction',
                'attended_testing','ordered_priorities','user_resting']:
        task[key]=state[key]
    task['player_caption_initialization_and_SQL_cell_selection_offline']=True
    task['user_away']=True;task['current_connection_not_rechecked_this_offline_turn']=True
    task['current_device_connection_verified']=False
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task)
    print(json.dumps({'finding':'native_player_menu_selection','groups':3,'SQL_scenarios':6,'device_io':False}))

if __name__=='__main__':main()
