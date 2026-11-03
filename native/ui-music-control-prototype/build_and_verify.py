#!/usr/bin/env python3
"""Compile ONLY this new component and run deterministic host adapter controls.

No imports from old analyzers/builders, no native emulator/device/service use.
verification.json is exclusive-create so a published report is not overwritten.
"""
from datetime import datetime, timezone
import hashlib
import json
import platform
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'native/ui-music-control-prototype'
OUT = ROOT / 'staging/ui-music-control-prototype'
REPORT = OUT / 'verification.json'
PLAN = ROOT / 'staging/native-player-task-runtime-full/single-bootstrap-ui-music-implementation-plan.json'
EXPECTED_PLAN = 'f0613adf5cc2089fa7bb62a42a258d4567b3a71f3df3004c723451c3c512b0fc'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    started = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f'{command}: exit{result.returncode}\n{result.stdout}\n{result.stderr}')
    return {'command': command, 'exit_code': result.returncode,
            'elapsed_host_seconds': time.monotonic() - started,
            'stdout': result.stdout, 'stderr': result.stderr}


def main():
    assert not REPORT.exists(), 'Published verification is immutable; use a new namespace.'
    assert sha(PLAN) == EXPECTED_PLAN
    plan = json.loads(PLAN.read_text())
    frozen = plan['frozen_evidence']['source_sha256']
    for name, expected in frozen.items():
        assert sha(ROOT / name) == expected, name
    OUT.mkdir(exist_ok=True)
    c = str((SOURCE / 'ui_music_control.c').relative_to(ROOT))
    tests = str((SOURCE / 'host_controls.c').relative_to(ROOT))
    obj = 'staging/ui-music-control-prototype/ui-music-control-armv6.o'
    elf = 'staging/ui-music-control-prototype/ui-music-control-armv6-relocatable.elf'
    archive = 'staging/ui-music-control-prototype/lib-ui-music-control-armv6.a'
    host = 'staging/ui-music-control-prototype/host-controls-sanitized'
    common = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wshadow', '-Wstrict-prototypes']
    commands = [
        ['arm-linux-gnueabi-gcc', *common, '-Os', '-mcpu=arm1176jzf-s', '-marm',
         '-mfloat-abi=soft', '-ffreestanding', '-fno-builtin', '-fno-pic', '-fno-pie',
         '-fdata-sections', '-ffunction-sections', '-fno-unwind-tables',
         '-fno-asynchronous-unwind-tables', '-c', c, '-o', obj],
        ['arm-linux-gnueabi-gcc', '-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft',
         '-nostdlib', '-r', '-Wl,--build-id=none', obj, '-o', elf],
        ['arm-linux-gnueabi-ar', 'rcD', archive, obj],
        ['gcc', *common, '-O2', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
         c, tests, '-o', host],
    ]
    compilation = [run(command) for command in commands]
    execution = run([host])
    controls = json.loads(execution['stdout'])
    assert controls['all_passed'] and controls['case_count'] == len(controls['cases']) == 27
    assert all(row['passed'] for row in controls['cases'])
    assert not execution['stderr'], execution['stderr']
    undefined = run(['arm-linux-gnueabi-nm', '-u', elf])
    attributes = run(['arm-linux-gnueabi-readelf', '-h', '-A', elf])
    sections = run(['arm-linux-gnueabi-readelf', '-S', elf])
    size = run(['arm-linux-gnueabi-size', elf])
    exports = run(['arm-linux-gnueabi-nm', '-g', '--defined-only', elf])
    assert not undefined['stdout'].strip(), undefined['stdout']
    assert 'Machine:                           ARM' in attributes['stdout']
    assert 'Type:                              REL' in attributes['stdout']
    assert 'Tag_CPU_arch: v6' in attributes['stdout']
    assert 'Tag_ABI_VFP_args' not in attributes['stdout']
    assert 'umc_service' in exports['stdout'] and 'ui_music_control_api' in exports['stdout']
    assert all(value not in sections['stdout'] for value in ['.interp', '.dynamic'])
    for name, expected in frozen.items():
        assert sha(ROOT / name) == expected, ('frozen source changed', name)
    sources = sorted(p for p in SOURCE.iterdir() if p.is_file())
    artifacts = [ROOT / name for name in [obj, elf, archive, host]]
    report = {
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'exact_target': plan['exact_target'],
        'prototype_only': True, 'device_install_candidate': False,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
        'source_reference_plan': {'path': str(PLAN.relative_to(ROOT)), 'sha256': sha(PLAN)},
        'unchanged_frozen_dependency_count': len(frozen),
        'unchanged_frozen_source_sha256': frozen,
        'compile_artifacts': [{'path': str(p.relative_to(ROOT)), 'bytes': p.stat().st_size,
                               'sha256': sha(p)} for p in artifacts],
        'compilation': compilation,
        'host_platform': platform.machine(),
        'host_compiler': run(['gcc', '--version'])['stdout'].splitlines()[0],
        'ARM_compiler': run(['arm-linux-gnueabi-gcc', '--version'])['stdout'].splitlines()[0],
        'ARM_ELF_header_attributes': attributes['stdout'],
        'ARM_ELF_sections': sections['stdout'],
        'ARM_ELF_size': size['stdout'], 'ARM_defined_exports': exports['stdout'],
        'ARM_ELF_machine': 'ARM', 'ARM_ELF_type': 'REL',
        'ARM_ELF_is_executable_loader_image': False,
        'ARM_unresolved_symbols': [], 'Linux_runtime_or_dynamic_loader_required': False,
        'host_tests': controls, 'host_test_execution': execution,
        'host_sanitizers': ['AddressSanitizer', 'UndefinedBehaviorSanitizer'],
        'all_passed': True, 'existing_sources_builds_manifests_proofs_report_state_modified': False,
        'old_build_linked': False, 'native_firmware_instructions_executed': False,
        'native_IRQ_scheduler_mutex_audio_or_GUI_runtime_verified': False,
        'guest_emulator_run': False, 'device_service_IO': False, 'sounds_emitted': False,
        'physical_App_direct_phone_or_stop_mute_verified': False,
        'limits': '27 deterministic host adapter controls, including16 native-busy field witnesses. '
                  'Mock witnesses and actor/admission interleavings verify control semantics only. '
                  'ARM1176 soft-float relocatable component crosscompiled with zero unresolved symbols; '
                  'no original firmware/native IRQ/kernel/mutex/audio/GUI execution or new integrated loader image. '
                  'Real channel reservation, source-token capture/future callback exclusion, native stop/peripheral '
                  'progress, physical mute/navigation, acceptedVPM-SIG and safe unload remain adapter/integration contracts. '
                  'All controller/callback/module memory remains resident; no shutdown/free/unload API.'
    }
    with REPORT.open('x') as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write('\n')
    print(json.dumps({'report': str(REPORT.relative_to(ROOT)), 'sha256': sha(REPORT),
                      'case_count': controls['case_count'], 'all_passed': True,
                      'ARM_unresolved_symbols': [], 'frozen_dependencies_unchanged': len(frozen)}))


if __name__ == '__main__':
    main()
