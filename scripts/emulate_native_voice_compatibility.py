#!/usr/bin/env python3
"""Execute original current-voice/version compatibility checks offline.

Registered voice metadata comes from original package parsing. Current-selection
cache and deliberately changed record/version controls are explicit RAM fixtures.
No compatibility branch or firmware instruction is patched or bypassed.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from unicorn.arm_const import UC_ARM_REG_SP
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace
from analyze_tts_vpm import sha, require
from emulate_native_voice_registry import RegistryVM, STACK

REQUIREMENTS = 0x9bb86c
STRIDE = 0x24c
VERSION_OFFSET = 0x226
OUTPUT = 'evidence/firmware-analysis/native-voice-compatibility-emulation.json'


def wide(raw):
    return raw.decode('utf-16le').split('\0', 1)[0]


def main():
    stock = NativeImage()
    runtime = RuntimeImage(stock)
    requirements = [{'index': i, 'volume_id': wide(runtime.read(REQUIREMENTS + i * STRIDE, 40)),
        'version_text': wide(runtime.read(REQUIREMENTS + i * STRIDE + VERSION_OFFSET, 10))}
        for i in range(94)]
    rows = [r for r in json.loads((ROOT / 'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers']
            if r['native_module_container']]
    cases = []

    def run(name, row, expected, *, selected=True, version=None, changed_id=None,
            kind=None, subtype=None, direct=False):
        data = (ROOT / row['file']).read_bytes()
        vm = RegistryVM(stock, [{'name': Path(row['file']).name, 'data': data}])
        enumeration = vm.enumerate()
        record = enumeration['registry'][0]
        p = vm.handles[record['handle']]['pointer']
        identifier = changed_id or record['volume_id']
        if changed_id:
            vm.uc.mem_write(p + 0x3fc, (identifier + '\0').encode('utf-16le'))
        if kind is not None:
            vm.uc.mem_write(p + 0x760, bytes([kind]))
        if subtype is not None:
            vm.uc.mem_write(p + 0x761, bytes([subtype]))
        version = version or vm.wide(p + 0x6b8)
        vm.uc.mem_write(0x0802c000, (identifier + '\0').encode('utf-16le'))
        vm.uc.mem_write(0x0802d000, (version + '\0').encode('utf-16le'))
        if selected:
            vm.uc.mem_write(0xf09638, (identifier + '\0').encode('utf-16le'))
        entry = 0x2229c4 if direct else 0x222a34
        args = (0x0802c000, 0x0802d000) if direct else (0,)
        result = vm.call(entry, args)
        require(result == expected, name + ': unexpected original predicate result')
        require(vm.uc.reg_read(UC_ARM_REG_SP) == STACK and not any(vm.mutexes.values()),
                'Compatibility SP/mutex changed')
        require(not vm.init_calls and not vm.module_executed, 'Compatibility unexpectedly executed module')
        require(all(bytes(vm.uc.mem_read(a, len(raw))) == raw for a, raw in vm.code_images),
                'Original compatibility code changed')
        matched = next((r for r in requirements if r['volume_id'] == identifier), None)
        cases.append({'name': name, 'passed': True, 'native_entry': hex(entry), 'native_result': result,
            'volume_id': identifier, 'version_control': version, 'current_voice_cache_populated_fixture': selected,
            'requirement_record': matched, 'record_type_control': kind, 'record_subtype_control': subtype,
            'original_package_sha256': sha(data),
            'native_visits': {hex(a): vm.visits[a] for a in [0x222a34, 0x2229c4, 0x273e18,
                0x273f24, 0x2741f4, 0x2744f6, 0x359820, 0x274452, 0x274488]},
            'original_code_unchanged_no_override_or_module_execution_SP_mutex_checked': True})

    for row in rows:
        run('matching_original_' + Path(row['file']).stem, row, 1)
    row = rows[0]
    run('empty_current_selection_cache', row, 0, selected=False)
    run('unknown_TTS_voice_ID_fallback_reject', row, 0, changed_id='custom-vpm')
    for version, expected in [('0.99', 0), ('1.00', 0), ('1.29', 0), ('1.30', 1), ('1.99', 1), ('2.10', 1)]:
        run('known_meiling_version_' + version + '_original_compare_mode2', row, expected,
            version=version, direct=True)
    for kind, subtype, expected in [(0, 1, 1), (0, 2, 1), (0, 3, 0), (1, 1, 0)]:
        run('unknown_ID_fallback_type' + str(kind) + '_subtype' + str(subtype), row, expected,
            changed_id='custom-vpm', kind=kind, subtype=subtype)
    deps = [Path(__file__), ROOT / 'scripts/emulate_native_voice_registry.py',
        ROOT / 'scripts/emulate_native_voice_metadata.py', ROOT / 'scripts/emulate_native_vpm_filesystem.py',
        ROOT / 'scripts/analyze_native_sections.py', ROOT / 'scripts/analyze_native_voice_acceptance.py',
        ROOT / 'scripts/analyze_tts_vpm.py', ROOT / 'scripts/analyze_sdp_activation.py']
    evidence = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'MAIN_sha256': EXPECTED,
        'all_passed': True, 'case_count': len(cases), 'cases': cases,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in deps},
        'requirements': requirements, 'requirements_bytes_sha256': sha(runtime.read(REQUIREMENTS, STRIDE * 94)),
        'functions': {hex(a): trace(runtime, a, 1400) for a in
            [0x222a34, 0x2229c4, 0x273e18, 0x2744f6, 0x274452, 0x274488,
             0x23cd9c, 0x23cdbc, 0x23cd64, 0x1c0600, 0x1c0624, 0x358d24]},
        'native_version_comparison_mode_argument': 2,
        'native_version_comparison_length_is_maximum_of_both_strings': True,
        'complete_semantic_version_ordering_verified': False,
        'empty_current_selection_cache_explains_prior_fixture_diagnostic409': True,
        'settings_initializer_or_live_current_voice_recovered': False,
        'original_current_task_helpers_are_mutex_not_IRQ_save_restore': True,
        'device_io': False, 'backup_modified': False, 'device_install_candidate': False,
        'limits': 'Original selected-voice lookup and94-entry volume-ID/version table execute. Cache/metadata controls are explicit fixture RAM, not measured live preference or recovered settings initialization. Stock359820 compares max string length; third arg2 is a mode passed to35980C, not two UTF16 units. Complete semantic-version behavior remains unverified. Unknown/inadequate version falls back to type0 and subtype1/2 only. This is neither module signature/acceptance nor App/phone/audio evidence. Candidate settings helpers23CD9C/23CDBC submit persistent store23CD64/2CA82C; full initializer/update propagation remains unknown.'}
    (ROOT / OUTPUT).write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'evidence': OUTPUT, 'case_count': len(cases), 'all_passed': True}))


if __name__ == '__main__':
    main()
