#!/usr/bin/env python3
"""Publish completed Widget construction/signal evidence with physical limits."""
from datetime import datetime, timezone
import json
from check_native_music_stream_checkpoint import ROOT, read, sha, artifacts


def write(path, value):
    (ROOT / path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def main():
    previous = read('staging/native-player-widget/previous-checkpoint.json')
    before, prior = read(previous['state']), read(previous['audit'])
    assert prior['all_passed'] and prior['state_sha256'] == sha(previous['state'])
    state, task = read('evidence/deep-research-state.json'), read('evidence/task-state.json')
    for name, value in before['native_app_music']['static_findings'].items():
        assert state['native_app_music']['static_findings'][name] == value, name
    evidence = 'evidence/firmware-analysis/native-player-widget-emulation.json'
    proof = read(evidence)
    assert proof['all_passed'] and proof['case_count'] == 3 and not proof['device_io']
    for path, expected in proof['source_sha256'].items():
        assert sha(path) == expected, path
    assert sha(proof['build_manifest']) == proof['build_manifest_sha256']
    artifacts(read(proof['build_manifest']))
    assert not state['attended_testing']['user_present'] and state['user_resting']
    app = state['native_app_music']
    item = {key: value for key, value in proof.items() if key not in ['source_sha256', 'cases', 'load', 'snapshot']}
    item.update({'evidence': evidence, 'evidence_sha256': sha(evidence),
                 'source_artifact_count': len(proof['source_sha256']),
                 'case_names': [row['name'] for row in proof['cases']],
                 'normal_Widget_constructor_complete_offline': True,
                 'stock_Widget_signal_to_loaded_callback_offline': True,
                 'Add_node_constructor_complete_offline': True,
                 'software_signal_request_not_physical_touch': True,
                 'complete_Add_builder_or_Page_executed': False, 'previous_checkpoint': previous})
    app['static_findings']['native_player_widget'] = item
    app['stock_Widget_factory_and_signal_offline'] = True
    app['development_observations']['Widget_construction'] = {
        'system_211_library_host_SIGSEGV': 'staging/native-player-widget/host-crash.json',
        'specific_host_crash_root_cause_identified': False,
        'isolated214_runner_required_and_final_full_run_passed': True,
        'Widget_shared_ptr_output_must_be_initialized_empty': True,
        'getter_r3_forwarded_as_factory_fifth_argument_0_binds_1_does_not': True,
        'prior_opaque1352_factory_boundary_not_a_valid_constructed_Widget_proof': True,
        'original_GUI_timer_constructor395980_called_explicitly': True,
        'VFP_access_and_startup_zero_BSS_including_conditional_supplied': True,
        'original_GUI_guard385450_sets_initialized_data_word0551C80C_to1': True,
        'full_region_exact_single_word_allowance_not_blanket_guard_removal': True,
        'prior_partial_three_groups_not_full_suite_due_to_overbroad_readonly_data_guard': True,
        'visual_assets_still_empty_and_sourceID9_safe_repeat_unverified': True}
    actions = [
        'Complete the actual normal PageCustomMainMenu and Add builder, parent/root attachment, layout/enabled state, touch capture/event queue, nonempty visual resources and render/display chain. Stock normal Widget factory/connection/software signal now reaches loaded player, but a rendered touchable App is still unproved.',
        'Recover original GUI boot ordering, timer/event delivery, UI-thread ownership and actual DB open/schema. Current test supplies VFP/zero BSS and explicitly invokes stock GUI timer initialization; heap/DB/driver inventories remain fixtures. Keep constructed Widgets, shared_ptr holders, signal copies and module pinned until native detach/quiescence are verified.',
        'Establish accepted changed VPM loading and actual resident player lifecycle, sourceID9 ownership, repeated play/stop/cleanup and safe unregister/reload/unload. No MAIN patch in player build; original RAM GUI initialization flag is not a firmware patch. EMULATION-ONLY package must not be installed.',
        'Connect real player controls to direct Bluetooth music and original continuous-source/kernel pipeline; sufficient buffering/packet pacing, cancellation, init failure recovery and speaker/navigation coexistence remain required. Stereo/fidelity tuning stays deprioritized.',
        'User still sleeping: offline only, no calls/sounds/USB/Bluetooth/device writes or physical questions. On explicit return prepare live audio/agent and handle pairing first. Microphone canceled, Android Auto later, Maps deferred, full goal active/no-achieve.'
    ]
    now = datetime.now(timezone.utc).isoformat()
    state['updated_utc'] = now
    state['next_actions'] = actions
    app['remaining_work'] = actions[:4]
    state['last_goal_turn'] = {
        'classification': 'progress', 'previous_goal_turn_classification': 'progress', 'validated_utc': now,
        'previous_state_snapshot': previous['state'], 'previous_current_audit_snapshot': previous['audit'],
        'previous_turn_revalidation': 'Fresh prior16-scope caption/SQL audit saved with exact state;19 earlier suites and their sources remain frozen.',
        'reasons': [
            'Three complete groups: original outer/native load, stock normal Widget factory/slot connection/software signal to compiled resident player; flag1 Widget control has no player subscription; complete stock Add-node constructor from loaded catalog.',
            'Two software signal requests each run original slot/member dispatcher and produce WAV register/start API-boundary requests. No host-constructed member bind or direct compiled callback call. Real touch/Page/render/speaker unverified.',
            'Original constructors initialize labels/vtables/children; empty shared_ptr output required. VFP/verified startup-zero BSS and original timer ctor provided; C++/aligned allocator, DB/driver/audio endpoints remain fixtures. Original voice RAM/40 exports, guards and code retained.',
            'System runtime host crash diagnosed to its library/normal-factory phase, specific cause unknown; isolated214 used. Final guard identified one native once-initialization word0->1 in conditional data, original385450; exact full-region allowance then full suite rerun, no MAIN patch.',
            'User remains asleep; no device operations or sounds. Ordinary menu App, accepted loading, direct phone music and full goal remain incomplete.'
        ], 'build_manifest': proof['build_manifest'], 'build_manifest_sha256': proof['build_manifest_sha256'],
        'integration_evidence': evidence, 'integration_evidence_sha256': sha(evidence),
        'offline_integration_device_io': False, 'device_io': False, 'device_files_written': False,
        'native_firmware_or_research_package_written': False, 'automatic_calls_or_sound': False,
        'attended_calls_or_sound': False, 'automatic_calls_or_sound_while_away': False,
        'next_focus': actions[0], 'goal_status': 'active', 'full_goal_complete': False}
    for key in ['updated_utc', 'last_goal_turn', 'next_actions', 'current_priority', 'latest_user_instruction',
                'attended_testing', 'ordered_priorities', 'user_resting']:
        task[key] = state[key]
    task['stock_Widget_factory_and_signal_offline'] = True
    task['user_away'] = True
    task['current_connection_not_rechecked_this_offline_turn'] = True
    task['current_device_connection_verified'] = False
    write('evidence/deep-research-state.json', state)
    write('evidence/task-state.json', task)
    print(json.dumps({'finding': 'native_player_widget', 'groups': 3,
                      'dependencies': item['source_artifact_count'], 'device_io': False}))


if __name__ == '__main__':
    main()
