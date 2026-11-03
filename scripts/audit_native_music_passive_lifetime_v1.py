#!/usr/bin/env python3
"""Review entry/lifetime/output guards as FILE data, without target execution."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/native-music-passive-lifetime-readonly-20261007-v1'
ENTRY = 'staging/native-player-loaded-single-image/resident_entry_v1.c'
V2 = 'staging/native-player-loaded-single-image/build-v2/'
V3 = 'staging/native-player-loaded-single-image/build-v3/'
V3_MANIFEST = 'staging/native-player-loaded-single-image/build-v3.json'
EXPECTED = {
    ENTRY: '2fdc2a5899ba0f42485c13af80c09dee0eefc7fba32da6f2b60791b04bd19c3a',
    V2 + 'memory_output_loaded_owner_v1.c': '068069947d5e8d02a9e54ce3717a7a34b48d2ba0067be666eda76ddab23bfffa',
    V2 + 'resident.ld': 'f7fce4ac5823d187a19a491514c573d74a19582e7c0ec849a6af2bf33180945a',
    V3_MANIFEST: '9790e7d3951d9dd1210212fbb303c381eb8c9b6f64ebe7f80746ab074fe91677',
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def create(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    (OUT / name).chmod(0o444)
    return {'path': name, 'bytes': len(raw), 'sha256': digest(raw)}


def main():
    assert not OUT.exists()
    inputs = {}
    for name in [*EXPECTED, V3 + 'memory_output_loaded_owner_v1.c', V3 + 'resident.ld']:
        cap = 81920 if name.endswith('.json') else 8192
        path = ROOT / name
        assert path.stat().st_size <= cap
        with path.open('rb') as stream:
            raw = stream.read(cap + 1)
        assert len(raw) <= cap
        if name in EXPECTED:
            assert digest(raw) == EXPECTED[name]
        inputs[name] = raw
    manifest = json.loads(inputs[V3_MANIFEST])
    assert manifest['HWID'] == 1352 and manifest['software'] == '8.00'
    for name in (ENTRY, V3 + 'memory_output_loaded_owner_v1.c'):
        assert digest(inputs[name]) == manifest['source_sha256'][name]
    assert inputs[V3 + 'memory_output_loaded_owner_v1.c'] == inputs[V2 + 'memory_output_loaded_owner_v1.c']
    entry = inputs[ENTRY].decode()
    body = entry[entry.index('int resident_music_entry(void *loader)'):]
    assert 'original_tts_entry(loader)' in body and 'return status;' in body
    assert 'resident_passive_ready=(status==11 || status==6);' in body
    assert 'memset(__resident_bss_start,0,' in body
    assert all(name not in body for name in ('mh_boot_source', 'aas_media_ingress', 'mh_request_command',
                                            'nr_configuration_gate', 'nr_start_suspend_gate', 'nr_reply_dispatch'))
    assert 'word on every new file load' in entry and 'cannot protect against voice replacement' in entry
    linker = inputs[V2 + 'resident.ld'].decode()
    zero_start = linker.index('__resident_bss_start = .;')
    zero_end = linker.index('__resident_bss_end = .;')
    included = linker[zero_start:zero_end]
    reset_sections = ['.bss', '.pcm0', '.pcm1', '.pcm2', '.pcm3', '.mh_source_stack', '.gather', '.queue_payload']
    assert all(name in included for name in reset_sections)
    owner = inputs[V2 + 'memory_output_loaded_owner_v1.c'].decode()
    assert 'mcs_reader_admit(mcs_bridge_context,instance)' in owner
    assert 'return mcs_original_output_read(instance,output,capacity);' in owner
    assert 'if(g->borrow || memory_output_control.reader_in_flight){unlock(f);return UMC_PENDING;}' in owner
    assert 'session!=g->epoch || session!=g->selected_session' in owner
    assert 'r=mcs_original_output_release(seed);' in owner
    assert all(not manifest[flag] for flag in ('activation_performed_by_entry', 'guest_executed',
               'device_IO', 'modified_VPM_generated', 'device_install_candidate',
               'native_warm_activation_heap_menu_lifetime_pin_or_phone_verified'))
    OUT.mkdir(mode=0o700)
    ledger = {
        'schema': 'native-music-passive-lifetime-FILE-ledger/v1',
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'input_pins': {name: {'bytes': len(raw), 'sha256': digest(raw)} for name, raw in inputs.items()},
        'entry_calls_original_TTS_and_returns_original_status': True,
        'entry_passive_ready_is_original_status_11_or_6': True,
        'entry_passive_ready_means_Source_or_player_READY': False,
        'custom_activation_functions_exist_only_in_export_table_at_this_entry': True,
        'entry_calls_custom_boot_phone_publish_or_play': False,
        'entry_phase_is_reloaded_initialized_data_not_external_lifetime_pin': True,
        'explicit_BSS_reset_span_contains': reset_sections,
        'conditional_voice_replacement_issue': 'A new file load restores initialized phase; the entry then clears the declared state/PCM/Source stack span. The source explicitly disclaims replacement protection. No live reload or overwritten callback was reproduced.',
        'real_loader_or_voice_replacement_experiment_run': False,
        'no_outside_copy_or_module_pin_established_by_this_entry': True,
        'guarded_reader_is_real_source_implementation': True,
        'reader_guard_is_hardware_all_writer_ownership_proof': False,
        'release_borrow_or_reader_in_flight_returns_PENDING': True,
        'release_requires_matching_nonzero_selected_session_and_held_mutation_registration': True,
        'release_forwards_to_frozen_original_owner_callee': True,
        'frozen_callee_or_full_stop_return_executed': False,
        'release_success_alone_proves_STOP_DONE_or_safe_unload': False,
        'v3_selected_entry_and_owner_source_pins_match_current_selected_source': True,
        'v3_owner_source_bytes_identical_to_v2': True,
        'v3_linker_bytes_identical_to_v2': inputs[V3 + 'resident.ld'] == inputs[V2 + 'resident.ld'],
        'v2_v3_all_provider_or_lifecycle_semantics_equal_claimed': False,
        'proof_scope': 'Six fixed text/metadata inputs; source assertions, declared linker ordering and selected v3 source pins, not compiled code or runtime evidence.',
        'native_import_compile_guest_firmware_binary_RAM': False,
        'device_service_DBUS_BT_audio': False,
        'native_GUI_phone_speaker_ownership_STOP_DONE_verified': False,
        'native_install_ready': False,
        'full_goal_complete': False,
        'next_obligation': 'Separate passive TTS-entry success from original Source READY and actual GUI activation; establish real resident storage and voice-replacement/callback lifetime before live music.',
    }
    pin = create('lifetime-ledger.json', ledger)
    proof = create('proof.json', {'schema': 'native-music-passive-lifetime-FILE-proof/v1',
        'all_assigned_checks_passed': True, 'STOP': True, 'review_only': True, 'target_execution': False,
        'inputs': len(inputs), 'input_bytes_this_check': sum(len(raw) for raw in inputs.values()),
        'ledger': pin, 'device_IO': False, 'native_install_ready': False, 'full_goal_complete': False})
    create('reviewer-source-pin.json', {'path': str(Path(__file__).resolve().relative_to(ROOT)),
                                      'sha256': digest(Path(__file__).read_bytes()), 'metadata_and_text_FILE_only': True})
    print(json.dumps({'all_assigned_checks_passed': True, 'inputs': len(inputs),
                      'input_bytes': sum(len(raw) for raw in inputs.values()),
                      'passive_ready_is_music_READY': False, 'v3_selected_owner_matches_v2': True,
                      'proof_sha256': proof['sha256'], 'device_IO': False}))


if __name__ == '__main__':
    main()
