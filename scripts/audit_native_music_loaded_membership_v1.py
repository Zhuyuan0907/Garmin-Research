#!/usr/bin/env python3
"""Read a newer image's existing metadata, not its code or build command."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/native-music-loaded-membership-readonly-20261007-v1'
PINS = {
    'staging/native-player-loaded-single-image/build-v2.json':
        'ee7d464e806cfc2d2f506989ffc7b2d7b30c6ce5e2d5f068b95f303cc6b76f75',
    'staging/native-player-loaded-single-image/build_loaded_image_v2.py':
        '624bc81001a23fbdd4e8ea4da22b8a92e45aca778c44342a6bab69c0b1ae0c85',
    'staging/native-player-loaded-single-image/build-v2/source_imports_v1.h':
        '68b1cc523c4310a583c8b91886a9be5f820cba0efb72b88d86efd76e454bdb76',
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def create(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    (OUT / name).chmod(0o444)
    return {'path': name, 'bytes': len(raw), 'sha256': digest(raw)}


def main():
    assert not OUT.exists()
    inputs = {}
    for name, expected in PINS.items():
        path = ROOT / name
        cap = 81920 if name.endswith('.json') else 16384
        assert path.stat().st_size <= cap
        with path.open('rb') as stream:
            raw = stream.read(cap + 1)
        assert len(raw) <= cap and digest(raw) == expected
        inputs[name] = raw
    manifest = json.loads(inputs[next(iter(PINS))])
    assert manifest['HWID'] == 1352 and manifest['software'] == '8.00'
    assert manifest['one_native_DLL_image'] and manifest['no_absolute_VM_Source_imports']
    assert manifest['source_sha256']['staging/native-player-loaded-single-image/build_loaded_image_v2.py'] == PINS[
        'staging/native-player-loaded-single-image/build_loaded_image_v2.py']
    symbols = manifest['symbols']
    names = ['aas_media_ingress', 'mh_request_command', 'resident_music_entry',
             'umc_init', 'umc_request_start', 'umc_request_stop', 'umc_service']
    selected = {}
    for name in names:
        value = symbols[name]
        assert value['binding'] == 1 and value['type'] == 2 and value['section_index'] == 2
        assert manifest['extension_base'] <= value['value'] < manifest['module_base'] + manifest['combined_file_bytes']
        selected[name] = value
    assert 'native/ui-music-control-prototype/ui_music_control.c' in manifest['source_sha256']
    absent = ['native/ui-music-native-adapter/native_adapter.c',
              'native/ui-music-native-adapter/original_imports.c', 'native/player-resources/player_menu.c']
    assert all(name not in manifest['source_sha256'] for name in absent)
    assert not any(name.startswith(('umcn_', 'native_player_menu_')) for name in symbols)
    for flag in ['activation_performed_by_entry', 'guest_executed', 'device_IO',
                 'modified_VPM_generated', 'device_install_candidate',
                 'native_warm_activation_heap_menu_lifetime_pin_or_phone_verified']:
        assert not manifest[flag]
    assert manifest['sole_passive_bootstrap'] == 'resident_music_entry'
    OUT.mkdir(mode=0o700)
    ledger = {
        'schema': 'native-music-newer-loaded-membership-readonly/v1',
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'input_pins': {name: {'bytes': len(raw), 'sha256': digest(raw)} for name, raw in inputs.items()},
        'existing_image': {'ELF': manifest['ELF'], 'ELF_sha256_inherited_from_manifest': manifest['ELF_sha256'],
                           'module_base': manifest['module_base'], 'extension_base': manifest['extension_base'],
                           'combined_file_bytes': manifest['combined_file_bytes'],
                           'combined_ram_bytes': manifest['combined_ram_bytes']},
        'declared_native_Source_and_remote_and_controller_in_one_image': True,
        'declared_symbols': selected,
        'declared_controller_source_sha256': manifest['source_sha256'][
            'native/ui-music-control-prototype/ui_music_control.c'],
        'controller_body_not_read_this_check': True,
        'missing_older_adapter_and_resource_menu_sources': absent,
        'older_umcn_and_resource_menu_symbols_present': False,
        'passive_entry': manifest['sole_passive_bootstrap'],
        'activation_by_entry': False,
        'generated_symbolic_Source_header_sha256': PINS[
            'staging/native-player-loaded-single-image/build-v2/source_imports_v1.h'],
        'declared_absolute_offline_Source_imports_removed': True,
        'old_resource_menu_and_newer_loaded_image_are_same_artifact': False,
        'ELF_or_flat_binary_read_or_independently_relocation_checked': False,
        'proof_scope': 'Pinned manifest, builder text and small generated header as FILE data; exported symbols are declared metadata, not fresh binary or executed ABI validation.',
        'guest_executed_in_this_check': False,
        'producer_compiled_or_imported': False,
        'native_UI_launch_READY_session_ownership_stop_or_speaker_verified': False,
        'modified_VPM_generated_this_check': False,
        'device_IO': False, 'native_install_ready': False, 'full_goal_complete': False,
        'next_review': 'Use this newer declared coherent Source/remote/controller image as a comparison basis; separately identify its legal GUI provider and readiness/ownership/lifecycle binding. Do not graft old exact maps or diagnostic menu callbacks by address.',
    }
    ledger_pin = create('membership-ledger.json', ledger)
    proof_pin = create('proof.json', {
        'schema': 'native-music-loaded-membership-proof/v1', 'FILE_review_completed': True,
        'all_assigned_metadata_checks_passed': True, 'STOP': True, 'inputs': len(inputs),
        'input_content_bytes_this_check': sum(len(raw) for raw in inputs.values()),
        'ledger': ledger_pin, 'newer_controller_declared_linked': True,
        'older_resources_GUI_and_adapter_declared_linked': False,
        'native_target_runs': 0, 'device_IO': False, 'full_goal_complete': False,
    })
    create('reviewer-source-pin.json', {'path': str(Path(__file__).resolve().relative_to(ROOT)),
                                     'sha256': digest(Path(__file__).read_bytes()),
                                     'ordinary_host_FILE_metadata_review': True})
    print(json.dumps({'FILE_review_completed': True, 'inputs': len(inputs),
                      'input_content_bytes': sum(len(raw) for raw in inputs.values()),
                      'newer_controller_declared_linked': True, 'older_menu_declared_linked': False,
                      'proof_sha256': proof_pin['sha256'], 'device_IO': False}))


if __name__ == '__main__':
    main()
