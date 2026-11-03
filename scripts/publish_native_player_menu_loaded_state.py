#!/usr/bin/env python3
"""Publish verified loader-to-catalog evidence; do not promote it to installation."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def read(path):return json.loads((ROOT/path).read_text())
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def write(path,value):(ROOT/path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')

def main():
    previous=read('staging/native-player-menu-loaded/previous-checkpoint.json')
    before=read(previous['state']);prior=read(previous['audit'])
    assert prior['all_passed'] and prior['state_sha256']==sha(previous['state'])
    state=read('evidence/deep-research-state.json');task=read('evidence/task-state.json')
    for name,value in before['native_app_music']['static_findings'].items():
        assert state['native_app_music']['static_findings'][name]==value,name
    evidence='evidence/firmware-analysis/native-player-menu-loaded-emulation.json'
    proof=read(evidence);build=read(proof['build_manifest'])
    assert proof['all_passed'] and proof['case_count']==3 and not proof['device_io']
    assert sha(proof['build_manifest'])==proof['build_manifest_sha256']
    for path,h in proof['source_sha256'].items():assert sha(path)==h,path
    for path,h in build['source_sha256'].items():assert sha(path)==h,path
    assert state['attended_testing']['waiting_for_user_return'] and not state['attended_testing']['user_present']
    now=datetime.now(timezone.utc).isoformat()
    item={k:v for k,v in proof.items() if k not in ['source_sha256','cases']}
    item.update({'evidence':evidence,'evidence_sha256':sha(evidence),
        'case_names':[c['name'] for c in proof['cases']],
        'extension_bytes':build['extension_bytes'],'combined_file_bytes':build['combined_file_bytes'],
        'combined_ram_bytes':build['combined_ram_bytes'],
        'remaining_reservation_bytes':build['remaining_reservation_bytes'],
        'BSS_bytes':build['BSS_bytes'],'previous_checkpoint':previous,
        'development_observation':'Initial region guard detected inherited synthetic platform active byte at05400000. Only that one declared initialization differs from original. Full3-case suite re-executed after replacing the overbroad guard with exact initialized-fixture snapshot plus original MAIN/044 code guards. Partial failed run not published as evidence.'})
    app=state['native_app_music'];app['static_findings']['native_player_menu_loaded']=item
    app['original_loader_to_resident_player_catalog_offline']=True
    actions=[
        'Connect the auto-registered player catalog record to original custom-menu Add/SQL selection and full button/Widget/render event chain. Three loader cases now preserve existing entries and reject duplicate ID; no actual menu image or touchscreen event is verified.',
        'Validate accepted modified VPM loading and production UI-thread registration timing, ID9 playback ownership/stop/repeated clicks, and resident module/string/callback lifetime. Player variant has no MAIN patch; actual package/SIG acceptance and safe unregister/reload/unload remain unproven. Never transfer EMULATION-ONLY package.',
        'Integrate the resident player controls with direct Bluetooth music and existing continuous-source/kernel pipeline. Representative phone packet arrival, adequate PCM buffering and reader-copy cancellation remain required; stereo/fidelity polishing stays deprioritized.',
        'Reconcile initialization failure and published SDP/hooks/module/TCBs, unpublish/rollback/restart/unload; combine storage/selection/menu with running music kernel without resetting live RAM, then verify physical speaker/navigation coexistence.',
        'User sleeping: no calls, sounds, device writes or physical questions. On explicit return, live audio service and pairing agent first; request only tests that advance native loading/menu/new functions. Microphone canceled; Android Auto after player/music; Maps deferred; goal active/no-achieve.'
    ]
    state['next_actions']=actions;app['remaining_work']=actions[:4]
    state['updated_utc']=now
    state['last_goal_turn']={'classification':'progress','previous_goal_turn_classification':'progress',
        'validated_utc':now,'previous_state_snapshot':previous['state'],
        'previous_current_audit_snapshot':previous['audit'],
        'previous_turn_revalidation':'Previous14-scope menu audit freshly executed and exact state saved.17 prior evidence suites/builds remain frozen.',
        'reasons':[
            'Relinked preserving original voice plus private menu callback inside original3MiB:54894 code2353914 file2462860 RAM,18036 BSS,682868 remaining; no undefined symbols, RX/RW, no MAIN patch.',
            'Full3-case terminal0 run: original outer readback/selector/DLL loader executes compiled entry, automatically registers private catalog callback without host installer call, then original bind/click consumer requests stock WAV API boundaries.',
            'Existing synthetic catalog controls retain semantic fields across original vector growth; duplicate player ID returns wrapper2 and keeps prior owner, original voice return11 and40 exports/runtime remain intact.',
            'First partial run rejected an overbroad code guard because inherited platform fixture05400000 byte differs from ROM. Corrected only the declared fixture comparison; full3 cases rerun and passed. No original proof altered.',
            'No physical VPM acceptance, rendered/touchable App, UI-thread proof or real WAV/DAC/Bluetooth in this variant. Module/callback resources pinned; user sleeping, no device I/O or sound; full goal active.'
        ],
        'build_manifest':proof['build_manifest'],'build_manifest_sha256':proof['build_manifest_sha256'],
        'integration_evidence':evidence,'integration_evidence_sha256':sha(evidence),
        'offline_integration_device_io':False,'device_io':False,'device_files_written':False,
        'native_firmware_or_research_package_written':False,'automatic_calls_or_sound':False,
        'attended_calls_or_sound':False,'automatic_calls_or_sound_while_away':False,
        'next_focus':actions[0],'goal_status':'active','full_goal_complete':False}
    state['goal_status']='active';state['goal_complete']=False;state['required_work_remaining']=True
    state['connection']['historical_snapshot']=True
    state['connection']['not_rechecked_this_offline_turn']=True
    for key in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction',
                'attended_testing','ordered_priorities','user_resting']:
        task[key]=state[key]
    task['user_away']=True;task['current_connection_not_rechecked_this_offline_turn']=True
    task['current_device_connection_verified']=False
    task['original_loader_to_resident_player_catalog_offline']=True
    task['required_work_remaining']=True;task['research_completed']=False;task['goal_status']='active'
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task)
    print(json.dumps({'finding':'native_player_menu_loaded','cases':3,'device_io':False,'goal_status':'active'}))

if __name__=='__main__':main()
