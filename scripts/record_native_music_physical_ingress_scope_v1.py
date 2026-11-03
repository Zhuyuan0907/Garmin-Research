#!/usr/bin/env python3
"""Reconcile existing attended voice tests; metadata FILE reads only."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/native-music-physical-ingress-readonly-20261007-v1'
ORIGINAL = 'b5f132ae4b073d6e804f7a7b639a60b1055573f9fbb65144f18f3b2198a5de68'
MARKER = '736b863344031a6d0e1c59fbcca6448e8b5bb67042b134020bbc3069fd31f891'
WARM = '1fa09e3258ac9e571f8e2ca6d824c5edd305d2f00e7c956c1d6b33df5a3226ba'


def main():
    names = [
        'evidence/native-marker-physical-positive-20261005.json',
        'evidence/native-marker-original-voice-restore-20261005.json',
        'evidence/native-marker-physical-original-control-20261005T044607Z.json',
        'evidence/native-warm-probe-physical-stage-20261005T044711Z.json',
        'evidence/native-warm-probe-physical-positive-20261005T045004Z.json',
        'evidence/native-warm-probe-physical-original-restore-20261005T045115Z.json',
        'evidence/native-warm-probe-physical-final-control-20261005T045419Z.json',
        'staging/native-player-warm-probe/local-warm-probe-bundle-manifest-v1.json',
    ]
    inputs, documents = {}, []
    for name in names:
        path = ROOT / name
        assert not path.is_symlink() and path.is_file() and path.stat().st_size <= 16384
        raw = path.read_bytes()
        inputs[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        documents.append(json.loads(raw))
    assert sum(item['bytes'] for item in inputs.values()) <= 32768
    marker, marker_restore, control, stage, positive, restore, final, manifest = documents
    assert marker['candidate_exact_SHA256'] == MARKER and marker['expected_marker_observed']
    assert marker['displayed_marker'] == 'M7Q9' and marker['positive_physical_modified_code_observation']
    marker_return = json.loads(marker_restore['restore_actual_terminal']['output'])
    assert marker_restore['restore_actual_terminal']['exit_code'] == 0
    assert marker_return['installed_sha256'] == ORIGINAL and marker_return['readback_verified']
    assert marker_restore['safely_unmounted'] and control['physical_original_Aud_Ver_2_10_confirmed']
    assert control['prior_modified_marker_observation'] == names[0]
    assert control['prior_original_restore_readback'] == names[1]
    assert stage['candidate_sha256'] == WARM and stage['readonly_audio_state_diagnostic']
    assert stage['safely_unmounted'] and not stage['large_player_or_MAIN_hooks_installed']
    assert positive['candidate_sha256'] == WARM and positive['stage_evidence'] == names[3]
    assert positive['user_answer_verbatim'] == 'WFFF' and positive['sample_mask'] == 4095
    assert len(positive['observations']) == 12 and all(row['observed_true'] for row in positive['observations'])
    assert positive['cached_voice_initialization_snapshot_not_live_monitor']
    restored = json.loads(restore['restore_actual_terminal']['output'])
    assert restore['restore_actual_terminal']['exit_code'] == 0
    assert restored['live_voice_sha256'] == WARM and restored['installed_sha256'] == ORIGINAL
    assert restored['bytes'] == 20133888 and restored['readback_verified']
    assert not restored['other_files_written'] and not restored['firmware_flashed']
    assert restore['safely_unmounted'] and not restore['large_player_or_MAIN_hooks_installed']
    assert final['positive_observation'] == names[4] and final['original_restore'] == names[5]
    assert final['physical_final_original_Aud_Ver_2_10_confirmed'] and final['physical_A_B_A_sequence_complete']
    assert final['sequence'] == ['2.10', 'WFFF', '2.10'] and final['no_pending_physical_question']
    assert manifest['candidate_sha256'] == WARM and manifest['rollback_sha256'] == ORIGINAL
    assert manifest['exact_target']['HWID'] == 1352 and manifest['exact_target']['SW'] == '8.00'
    assert manifest['original_DLLINFO_and_SIG_retained_byte_exact'] and not manifest['signature_forged_or_recomputed']
    assert manifest['no_new_audio_calls_or_native_audio_writes']
    result = {
        'schema': 'native-music-attended-ingress-scope-readonly/v1', 'all_assigned_checks_passed': True,
        'updated_utc': datetime.now(timezone.utc).isoformat(), 'STOP': True,
        'inputs': inputs, 'input_metadata_bytes': sum(item['bytes'] for item in inputs.values()),
        'large_historical_ROOT_audits_or_marker_allocation_arrays_needed': False,
        'exact_target': {'HWID': 1352, 'software': '8.00', 'voice': 'Chinese_Big5_MeiLing'},
        'historical_attended_marker_code_ingress': {'marker': 'M7Q9', 'candidate_sha256': MARKER,
            'later_original_readback_and_Aud_Ver_2_10_confirmed': True},
        'historical_attended_warm_diagnostic': {'marker': 'WFFF', 'candidate_sha256': WARM,
            'snapshot_at_module_initialization': True, 'bits': positive['observations'],
            'matching_idle_route_8_observed_then': True,
            'durable_exclusive_ownership_or_ready_to_play_certificate': False},
        'last_attended_original_voice_restoration': {'recorded_utc': final['recorded_utc'],
            'restored_bytes': 20133888, 'restored_sha256': ORIGINAL, 'readback_verified_then': True,
            'cold_restart_Aud_Ver': '2.10', 'sequence_complete': True,
            'duplicate_2_10_physical_question_needed': False,
            'current_device_or_USB_queried': False},
        'superseded_pending_fields_in_current_summary': ['local_reversible_marker_voice_bundle.rollback_Aud_Ver_2_10_pending'],
        'historical_preparation_or_restore_records_rewritten': False,
        'scope_limits': [
            'The two exact diagnostic candidates were accepted/executed; a larger integrated music VPM is not validated.',
            'Preserved original signature bytes plus acceptance does not establish general signature enforcement or full DSA verification.',
            'Twelve cached initialization predicates are not current raw values, channel ownership or navigation coexistence proof.',
            'No real native App menu, direct A2DP phone transport, decoder, mixer or speaker sound was tested by these diagnostics.',
        ],
        'next_binding_obligation': 'Use existing route initialization as an observed starting point, but establish real per-session ownership and actual UI/SEP binding before native playback.',
        'metadata_FILE_only_this_run': True, 'native_guest_compile_firmware_import_or_execution': False,
        'device_write_or_query_audio_service_or_playback_this_run': False,
        'install_ready': False, 'full_goal_complete': False,
    }
    OUT.mkdir(mode=0o700)
    for name, value in [('proof.json', result), ('source-pin.json', {
            'path': str(Path(__file__).relative_to(ROOT)), 'sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'only_new_artifacts': ['proof.json', 'source-pin.json']})]:
        with (OUT / name).open('x') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2); stream.write('\n')
        os.chmod(OUT / name, 0o444)
    print(json.dumps({'all_assigned_checks_passed': True, 'metadata_inputs': len(inputs),
                      'metadata_bytes': result['input_metadata_bytes'],
                      'proof_sha256': hashlib.sha256((OUT / 'proof.json').read_bytes()).hexdigest(),
                      'physical_tests_run_now': False}))


if __name__ == '__main__':
    main()
