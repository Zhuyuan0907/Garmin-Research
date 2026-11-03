#!/usr/bin/env python3
"""Check an older cleanup contract's metadata; do not execute its code."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/native-music-cleanup-contract-scope-readonly-20261007-v1'
EXPECTED = {
    'native/ui-music-native-adapter/cleanup_bridge_contract.h':
        '2a00d053ce16869aff831f2e00f60f39c74b571242d077733afd683ee8e5040d',
    'native/ui-music-native-adapter/ADAPTER_BINDING.md':
        '9326b8b49b85013a7fdc88f99e7cd54c6f611bdb8b2fa93bf142f49532626055',
    'staging/ui-music-native-adapter/verification.json':
        '43353416c7e5d2314bf1d7becb7a438fd050dafb3833239a2a0c4c6a9443e14f',
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
    for path, expected in EXPECTED.items():
        p = ROOT / path; cap = 81920 if path.endswith('.json') else 16384
        assert p.stat().st_size <= cap
        with p.open('rb') as stream:
            raw = stream.read(cap + 1)
        assert len(raw) <= cap and digest(raw) == expected
        inputs[path] = raw
    metadata = json.loads(inputs['staging/ui-music-native-adapter/verification.json'])
    for path in EXPECTED:
        if not path.endswith('.json'):
            assert metadata['source_sha256'][path] == EXPECTED[path]
    assert metadata['all_passed'] and metadata['host_tests']['all_passed']
    assert metadata['host_tests']['case_count'] == 12
    assert not metadata['old_music_build_linked'] and not metadata['frozen_control_object_linked_into_ARM']
    assert not metadata['guest_emulator_or_original_native_instructions_executed']
    assert not metadata['device_service_IO'] and not metadata['sounds_emitted']
    assert not metadata['device_install_candidate']
    contract = inputs['native/ui-music-native-adapter/cleanup_bridge_contract.h'].decode()
    assert '#define UMCN_CLEANUP_FRAME_BYTES 64' in contract
    doc = inputs['native/ui-music-native-adapter/ADAPTER_BINDING.md'].decode()
    assert 'Invoke `umcn_after_native_iteration` only after' in doc
    assert 'This call site is not yet installed' in doc
    assert 'No original MAIN site or old source has been modified' in doc
    OUT.mkdir(mode=0o700)
    ledger = {
        'schema': 'native-music-old-cleanup-contract-scope-FILE/v1',
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'inputs': {path: {'bytes': len(raw), 'sha256': digest(raw)} for path, raw in inputs.items()},
        'legacy_host_controls': {'count': 12, 'recorded_passed': True, 'rerun_this_turn': False,
                                 'scope': 'adapter C over typed private-state/native-array fixtures, not original runtime returns or physical ownership'},
        'cleanup_contract': {'typed_frame_bytes': 64, 'single_source_record_r0_ABI_only': True,
                             'incoming_record_result_SP_LR_preservation_is_contract_not_new_native_validation': True},
        'ARM_artifact_old_music_or_frozen_controller_objects_linked': False,
        'native_cleanup_bridge_execution_or_installation_verified': False,
        'documented_source_actor_service_is_conditional_integration_requirement': True,
        'documented_post_registration_before_start_publication_hook_installed': False,
        'documented_full_return_source_iteration_and_cleanup_hooks_installed': False,
        'required_witnesses': ['same native ownership epoch', 'matching control generation/source token',
                              'returned original source iteration', 'advanced original remove/release/cancel baselines',
                              'whole cleanup-notification frame still held during preemption',
                              'current idle native/private work and guarded callback lifetimes'],
        'new_loaded_source_provider_can_use_old_fixed_state_map_without_rebind': False,
        'request_return_zero_certifies_stop': False,
        'STOP_DONE_certifies_safe_module_unload_or_future_callback_exclusion': False,
        'ASM_file_ELF_firmware_or_live_RAM_read': False,
        'historical_metadata_contains_embedded_disassembly_but_no_new_instruction_analysis': True,
        'native_target_producer_import_compile_guest_tests_or_device_audio': False,
        'install_ready': False, 'full_goal_complete': False,
        'next_obligation': 'Match actual new Source/provider types and full-return callers; retain code/context/stacks until a real lifetime barrier. Do not reuse legacy fixture proof as a deployed new stop provider.',
    }
    pin = create('contract-scope-ledger.json', ledger)
    proof = create('proof.json', {'schema': 'native-music-cleanup-contract-scope-proof/v1',
        'all_assigned_metadata_checks_passed': True, 'STOP': True, 'review_only': True,
        'inputs': len(inputs), 'bytes_this_check': sum(len(raw) for raw in inputs.values()),
        'ledger': pin, 'old_host_tests_rerun': False, 'native_executed': False,
        'device_IO': False, 'full_goal_complete': False})
    create('reviewer-source-pin.json', {'path': str(Path(__file__).resolve().relative_to(ROOT)),
                                      'sha256': digest(Path(__file__).read_bytes()), 'FILE_metadata_only': True})
    print(json.dumps({'all_assigned_metadata_checks_passed': True, 'inputs': len(inputs),
                      'bytes_this_check': sum(len(raw) for raw in inputs.values()),
                      'legacy_host_controls_retained': 12, 'host_tests_rerun': False,
                      'proof_sha256': proof['sha256'], 'device_IO': False}))


if __name__ == '__main__':
    main()
