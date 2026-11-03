#!/usr/bin/env python3
"""Publish the completed offline menu unit; keep previous evidence frozen."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def read(path): return json.loads((ROOT/path).read_text())
def sha(path): return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def write(path,value): (ROOT/path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')

def main():
    state=read('evidence/deep-research-state.json')
    task=read('evidence/task-state.json')
    previous=read('staging/native-player-menu/previous-checkpoint.json')
    before=read(previous['state'])
    prior_audit=read(previous['audit'])
    assert prior_audit['all_passed'] and prior_audit['state_sha256']==sha(previous['state'])
    for name,item in before['native_app_music']['static_findings'].items():
        assert state['native_app_music']['static_findings'][name]==item,name
    evidence='evidence/firmware-analysis/native-player-menu-emulation.json'
    proof=read(evidence)
    build=read(proof['build_manifest'])
    assert proof['all_passed'] and proof['case_count']==4 and not proof['device_io']
    for path,h in proof['source_sha256'].items(): assert sha(path)==h,path
    assert sha(proof['build_manifest'])==proof['build_sha256']
    for path,h in build['source_sha256'].items(): assert sha(path)==h,path
    assert not state['attended_testing']['user_present']
    now=datetime.now(timezone.utc).isoformat()
    item={k:v for k,v in proof.items() if k not in ['source_sha256','cases','functions']}
    item.update({'evidence':evidence,'evidence_sha256':sha(evidence),
        'case_names':[c['name'] for c in proof['cases']],
        'compiled_code_bytes':build['flat_binary_bytes'],
        'private_menu_registration_and_click_identified':True,
        'previous_checkpoint':previous})
    state['native_app_music']['static_findings']['native_player_menu']=item
    state['native_app_music']['private_menu_registry_and_click_callback_offline']=True
    state['native_app_music']['menu_icon_visible_on_device']=False
    actions=[
        'Complete original catalog-to-menu display and actual button event path: private registry44/record100/click consumer now execute4 offline cases with compiled player callback. Blank visual resources and full GUI/SQL selection remain untested. Do not alter the icon database to claim an installed App.',
        'Integrate resident player menu/callback with accepted native loading and UI-thread lifetime. This ARM prototype currently uses synthetic VM addresses and allocation/audio API fixtures; do not transfer it or EMULATION-ONLY packages to the navigator.',
        'Continue direct Bluetooth music function using the existing5 persistent-source cases: representative packet arrival, adequate PCM buffering and reader-copy cancellation need integration. Stereo/fidelity polishing stays deprioritized by user.',
        'Reconcile initialization failure, published SDP/hooks/module/TCBs, unpublish/rollback/restart/unload. Combine full outer storage/selection with original DLL loader and live kernel without resetting RAM; verify changed-package acceptance and physical MAIN permissions/cache.',
        'When the user returns, prepare live audio service and matching-device pairing agent first. Only request a physical test that advances loading, normal-menu entry or a new function; stock WAV/HFP baselines already succeeded.',
        'User is sleeping: no calls, sounds, device writes or physical questions. Microphone canceled; Android Auto follows player/music; offline Google Maps deferred; goal remains active and never marked achieved.'
    ]
    state['next_actions']=actions
    state['native_app_music']['remaining_work']=actions[:4]
    state['attended_testing']['next_attended_test_not_requested_yet']=True
    state['attended_testing']['current_attended_test']='No pending test; user sleeping. New menu work is offline only.'
    state['current_priority']='Resident native player/normal-menu entry and direct Bluetooth music functions. User sleeping; offline only. Attended pairing preempts research on return; no stereo/fidelity polishing, microphone canceled, Android Auto later, Maps deferred, goal active/no-achieve.'
    state['updated_utc']=now
    state['last_goal_turn']={
        'classification':'progress','previous_goal_turn_classification':'progress',
        'validated_utc':now,'previous_state_snapshot':previous['state'],
        'previous_current_audit_snapshot':previous['audit'],
        'previous_turn_revalidation':'Saved exact attended19-scope continuous/WAV state and audit before offline menu research; existing findings and original proofs are frozen.',
        'reasons':[
            'New exact HWID1352 SW8.00 private Registry44/GridIconType100 ABI and stock3-instruction click consumer identified.',
            'Freestanding ARMv6 prototype1236bytes builds with zero undefined symbols and separate RX/RW segments. Four complete cases execute original construction/copy/vector growth/member bind/dispatch; compiled callback requests stock WAV register/start at explicit API fixtures.',
            'Chinese label survives source overwrite,12 entries retain callbacks across5 original vector reallocations, wrapper rejects duplicate/malformed input, original bind-copy destruction preserves catalog label; all allocation guards and original code regions unchanged.',
            'No full GUI/SQL selection or accepted loading/physical App proved; blank visual resources, UI-thread ownership and resident callback lifetime remain open. No device I/O/call/sound this turn.',
            'User sleeping; new functions first, stereo/fidelity tuning stopped, microphone canceled, Android Auto later/Maps deferred, no goal completion.'
        ],
        'build_manifest':proof['build_manifest'],'build_manifest_sha256':proof['build_sha256'],
        'integration_evidence':evidence,'integration_evidence_sha256':sha(evidence),
        'offline_integration_device_io':False,'device_io':False,'device_files_written':False,
        'native_firmware_or_research_package_written':False,'automatic_calls_or_sound':False,
        'attended_calls_or_sound':False,'automatic_calls_or_sound_while_away':False,
        'next_focus':actions[0],'goal_status':'active','full_goal_complete':False}
    state['user_resting']=True
    state['goal_status']='active';state['goal_complete']=False;state['required_work_remaining']=True
    for key in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction',
                'attended_testing','ordered_priorities','user_resting']:
        task[key]=state[key]
    task['user_away']=True
    task['current_connection_not_rechecked_this_offline_turn']=True
    task['current_device_connection_verified']=False
    task['required_work_remaining']=True;task['research_completed']=False;task['goal_status']='active'
    task['private_menu_registry_and_click_callback_offline']=True
    write('evidence/deep-research-state.json',state)
    write('evidence/task-state.json',task)
    print(json.dumps({'finding':'native_player_menu','case_count':4,'device_io':False,'goal_status':'active'}))

if __name__=='__main__':main()
