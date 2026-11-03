#!/usr/bin/env python3
"""Inspect one existing build recipe as data, without executing its targets."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/native-music-resource-membership-readonly-20261007-v1'
MANIFEST = 'staging/native-player-resources/manifest.json'
RECIPE = 'scripts/build_native_player_resources.py'
MANIFEST_SHA = 'f3365f39ca17cc6b19a5d0f67fd3d9c04d4195071937e0cb289fc77f07e91d68'
REQUIRED_UI = (
    'native/ui-music-control-prototype/ui_music_control.c',
    'native/ui-music-native-adapter/native_adapter.c',
    'native/ui-music-native-adapter/original_imports.c',
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_small(name, cap):
    path = ROOT / name
    assert path.stat().st_size <= cap
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    assert len(raw) <= cap
    return raw


def local_path(raw):
    path = Path(raw)
    if path.is_absolute():
        return str(path.relative_to(ROOT))
    assert '..' not in path.parts
    return str(path)


def create(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    (OUT / name).chmod(0o444)
    return {'path': name, 'bytes': len(raw), 'sha256': digest(raw)}


def main():
    assert not OUT.exists(), 'A review result must not overwrite historical evidence'
    raw = read_small(MANIFEST, 49152)
    assert digest(raw) == MANIFEST_SHA
    manifest = json.loads(raw)
    recipe = read_small(RECIPE, 12288)
    assert digest(recipe) == manifest['source_sha256'][RECIPE]
    commands = manifest['commands']
    units, object_outputs, link_inputs = {}, {}, []
    links = []
    for index, command in enumerate(commands):
        assert isinstance(command, list) and all(isinstance(value, str) for value in command)
        if '-c' in command:
            source = local_path(command[command.index('-c') + 1])
            output = local_path(command[command.index('-o') + 1])
            units.setdefault(source, []).append(index)
            object_outputs.setdefault(output, set()).add(source)
        if any(value.startswith('-Wl,--gc-sections,') for value in command):
            objects = [local_path(value) for value in command if value.endswith('.o')]
            links.append({'command_index': index, 'output': local_path(command[command.index('-o') + 1]),
                          'objects': objects})
            link_inputs.extend(objects)
    assert links and all(link['output'] == manifest['extension_elf'] for link in links)
    assert all(obj in object_outputs for obj in link_inputs), 'Every recipe link object has a declared compile unit'
    assert all(path in manifest['source_sha256'] for path in units), 'Compiled source membership is declared'
    compiled_and_linked = sorted({source for obj in link_inputs for source in object_outputs[obj]})
    absent = [path for path in REQUIRED_UI if path not in units and path not in compiled_and_linked
              and path not in manifest['source_sha256']]
    assert absent == list(REQUIRED_UI)
    ui_exports = [name for name in manifest['symbols'] if name.startswith(('umc_', 'umcn_'))]
    assert not ui_exports
    menu_exports = {name: manifest['symbols'][name] for name in (
        'native_player_menu_activate', 'native_player_menu_install', 'source_worker_boot')}
    assert not manifest['device_install_candidate'] and not manifest['real_package_acceptance_verified']
    # Recipe text is evidence of the frozen loop plus two menu extras, not code we execute.
    text = recipe.decode()
    assert "for old in f['commands']:" in text
    assert "extra=[ROOT/'native/player-menu-loaded/entry.c',ROOT/'native/player-resources/player_menu.c']" in text
    assert not any(path in text for path in REQUIRED_UI)
    OUT.mkdir(mode=0o700)
    ledger = {
        'schema': 'native-music-resource-build-membership-readonly/v1',
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'exact_existing_artifact': {'manifest': MANIFEST, 'manifest_sha256': MANIFEST_SHA,
                                    'extension_elf': manifest['extension_elf'],
                                    'binary_not_read_or_rehashed': True,
                                    'artifact_updated_utc': manifest['updated_utc']},
        'input_pins': {MANIFEST: {'bytes': len(raw), 'sha256': digest(raw)},
                       RECIPE: {'bytes': len(recipe), 'sha256': digest(recipe)}},
        'compiler_unit_count': len(units),
        'link_command_count': len(links),
        'compiled_and_linked_sources': compiled_and_linked,
        'missing_UI_controller_adapter_import_units': absent,
        'manifest_umc_or_umcn_exports': ui_exports,
        'existing_menu_and_older_Source_symbols': menu_exports,
        'declared_standalone_UI_packages_linked_into_this_artifact': False,
        'native_phone_App_complete': False,
        'proof_scope': 'Membership and hash pins of this exact declared recipe/manifest, not instruction execution or a whole-project absence claim.',
        'package_rejection_or_hardware_failure_proved': False,
        'next_review': 'Require one coherent image manifest linking GUI requests, controller/adapter and matching native Source/runtime/state providers. A separate standalone facade does not supply this membership.',
        'native_target_import_compile_guest_producer_execution': False,
        'device_query_write_service_audio': False,
        'install_ready': False,
        'full_goal_complete': False,
    }
    ledger_pin = create('membership-ledger.json', ledger)
    proof = {'schema': 'native-music-resource-membership-proof/v1', 'FILE_review_completed': True,
             'STOP': True, 'all_assigned_metadata_checks_passed': True,
             'inputs': 2, 'input_content_bytes_this_check': len(raw) + len(recipe),
             'ledger': ledger_pin, 'missing_UI_units': len(absent),
             'native_target_runs': 0, 'device_IO': False, 'installed': False,
             'full_goal_complete': False}
    proof_pin = create('proof.json', proof)
    create('reviewer-source-pin.json', {'path': str(Path(__file__).resolve().relative_to(ROOT)),
                                     'sha256': digest(Path(__file__).read_bytes()),
                                     'ordinary_host_metadata_reader': True})
    print(json.dumps({'FILE_review_completed': True, 'inputs': 2,
                      'input_content_bytes': len(raw) + len(recipe), 'missing_UI_units': len(absent),
                      'compiler_unit_count': len(units), 'proof_sha256': proof_pin['sha256'],
                      'device_IO': False}))


if __name__ == '__main__':
    main()
