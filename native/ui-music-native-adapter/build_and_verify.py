#!/usr/bin/env python3
"""New-only ARM adapter compile, host observer controls and frozen source audit.
Does not import prior builders/analyzers or run emulators/device/services.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'native/ui-music-native-adapter'
OUT = ROOT / 'staging/ui-music-native-adapter'
REPORT = OUT / 'verification.json'
CHECKPOINT = ROOT / 'evidence/firmware-analysis/native-independent-signal-checkpoint-audit.json'
CHECKPOINT_SHA = 'aa76de82e6b1912efc0c85789268a7a562f8360f3907a42d6dbece94383e7968'
CONTROL = ROOT / 'staging/ui-music-control-prototype/verification.json'
CONTROL_SHA = '261e23dfbd6be6a18945c1b634f477add767f18be3ba98e3e01e5b80c6dc4986'
PLAN = ROOT / 'staging/native-player-task-runtime-full/single-bootstrap-ui-music-implementation-plan.json'
MUSIC = ROOT / 'staging/native-music-continuous/manifest.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    start = time.monotonic()
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    if completed.returncode:
        raise RuntimeError(f'{command}:exit{completed.returncode}\n{completed.stdout}\n{completed.stderr}')
    return {'command': command, 'exit_code': 0, 'elapsed_host_seconds': time.monotonic()-start,
            'stdout': completed.stdout, 'stderr': completed.stderr}


def verify_registry(registry):
    for path, expected in registry.items():
        assert sha(ROOT/path) == expected, path


def main():
    assert not REPORT.exists(), 'Published report is immutable; choose a new namespace.'
    assert sha(CHECKPOINT) == CHECKPOINT_SHA
    assert sha(CONTROL) == CONTROL_SHA
    audit = json.loads(CHECKPOINT.read_text())
    control = json.loads(CONTROL.read_text())
    protected = {}
    suites = audit['selected_frozen_suites']
    assert len(suites) == 39
    for row in suites:
        path = ROOT / row['path']
        assert sha(path) == row['sha256'], row['path']
        d = json.loads(path.read_text())
        for name, value in d['source_sha256'].items():
            if name in protected:
                assert protected[name] == value
            protected[name] = value
    assert len(protected) == 430
    for name, value in control['source_sha256'].items():
        assert name not in protected
        protected[name] = value
    assert len(protected) == 435
    verify_registry(protected)
    plan = json.loads(PLAN.read_text())
    plan_registry = plan['frozen_evidence']['source_sha256']
    assert len(plan_registry) == 135
    verify_registry(plan_registry)
    music = json.loads(MUSIC.read_text())
    assert sha(MUSIC) == '50a2dd7f312b2aa34ae9cd3283a20968840fa32edb7667bde0d62b1d73afaabe'
    macro_map = {
        'UMCN_RUNTIME_CANCEL': 'music_runtime_cancel', 'UMCN_SOURCE_COMPLETED': 'source_worker_completed',
        'UMCN_RUNTIME_STATE': 'music_runtime_state', 'UMCN_SOURCE_STATE': 'source_worker_state',
        'UMCN_COORDINATOR_STATE': 'coordinator_state', 'UMCN_OUTPUT_STATE': 'memory_output_control',
        'UMCN_OWNED_STATE': 'owned_media_control', 'UMCN_QUEUE_STATE': 'media_queue_control',
        'UMCN_DECODER_STATE': 'media_worker_state', 'UMCN_OUTPUT_SLOTS': 'memory_output_slots',
        'UMCN_ANCHOR_ZERO': 'anchor_zero'}
    header = (SOURCE/'exact_continuous_bindings.h').read_text()
    addresses = {}
    for macro, symbol in macro_map.items():
        actual = int(re.search(r'^#define '+macro+r' (0x[0-9a-f]+)u$', header, re.M).group(1), 16)
        expected = music['symbols'][symbol]['address']
        assert actual == expected, macro
        addresses[macro] = {'symbol': symbol, 'address': actual, 'hex': hex(actual)}
    main_image = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
    assert sha(main_image) == '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'
    raw = main_image.read_bytes()
    prologue = raw[0x3b9dfc-0x50000:0x3b9e06-0x50000]
    assert prologue.hex() == 'f0b5050000202e0087b0'
    OUT.mkdir(exist_ok=True)
    common = ['-std=c11','-Wall','-Wextra','-Werror','-Wshadow','-Wstrict-prototypes']
    arm = ['-Os','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-ffreestanding',
           '-fno-builtin','-fno-pic','-fno-pie','-fdata-sections','-ffunction-sections',
           '-fno-unwind-tables','-fno-asynchronous-unwind-tables']
    native_c = 'native/ui-music-native-adapter/native_adapter.c'
    imports_c = 'native/ui-music-native-adapter/original_imports.c'
    bridge_s = 'native/ui-music-native-adapter/cleanup_bridge.S'
    objects = ['staging/ui-music-native-adapter/native-adapter-armv6.o',
               'staging/ui-music-native-adapter/original-imports-armv6.o',
               'staging/ui-music-native-adapter/cleanup-bridge-armv6.o']
    elf = 'staging/ui-music-native-adapter/native-adapter-armv6-relocatable.elf'
    host = 'staging/ui-music-native-adapter/host-controls-sanitized'
    commands = [
        ['arm-linux-gnueabi-gcc',*common,*arm,'-c',native_c,'-o',objects[0]],
        ['arm-linux-gnueabi-gcc',*common,*arm,'-c',imports_c,'-o',objects[1]],
        ['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft',
         '-c',bridge_s,'-o',objects[2]],
        ['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft',
         '-nostdlib','-r','-Wl,--build-id=none',*objects,'-o',elf],
        ['gcc',*common,'-O2','-fsanitize=address,undefined','-fno-omit-frame-pointer',
         native_c,'native/ui-music-native-adapter/host_controls.c',
         'native/ui-music-control-prototype/ui_music_control.c','-o',host]
    ]
    compilation = [run(command) for command in commands]
    execution = run([host]); controls = json.loads(execution['stdout'])
    assert controls['case_count'] == len(controls['cases']) == 12
    assert controls['all_passed'] and all(x['passed'] for x in controls['cases'])
    assert not execution['stderr']
    undefined = run(['arm-linux-gnueabi-nm','-u',elf])
    attributes = run(['arm-linux-gnueabi-readelf','-h','-A',elf])
    sections = run(['arm-linux-gnueabi-readelf','-S',elf])
    exports = run(['arm-linux-gnueabi-nm','-g','--defined-only',elf])
    disassembly = run(['arm-linux-gnueabi-objdump','-dr',objects[2]])
    size = run(['arm-linux-gnueabi-size',elf])
    assert not undefined['stdout'].strip()
    assert 'Machine:                           ARM' in attributes['stdout']
    assert 'Type:                              REL' in attributes['stdout']
    assert 'Tag_CPU_arch: v6' in attributes['stdout']
    assert 'Tag_ABI_VFP_args' not in attributes['stdout']
    assert not any(x in sections['stdout'] for x in ['.interp','.dynamic'])
    for name in ['umcn_service_owner','umcn_cleanup_bridge','umcn_cleanup_original_full_return',
                 'umcn_original_cleanup_continuation','umcn_fill_exact_continuous_bindings']:
        assert name in exports['stdout']
    assert '003b9e07' in disassembly['stdout']
    verify_registry(protected); verify_registry(plan_registry)
    assert sha(CONTROL) == CONTROL_SHA and sha(CHECKPOINT) == CHECKPOINT_SHA
    sources = sorted(p for p in SOURCE.iterdir() if p.is_file())
    artifact_paths = [ROOT / p for p in objects+[elf,host]]
    report = {
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'exact_target': plan['exact_target'], 'all_passed': True,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
        'frozen_controller_verification': {'path':str(CONTROL.relative_to(ROOT)),'sha256':sha(CONTROL)},
        'frozen_checkpoint': {'path':str(CHECKPOINT.relative_to(ROOT)),'sha256':sha(CHECKPOINT)},
        'protected_suite_count':39,'protected_native_sources':430,'protected_native_and_control_sources':435,
        'protected_source_sha256':dict(sorted(protected.items())),
        'plan_source_dependencies_135_verified_unchanged':True,
        'frozen_plan_sha256':sha(PLAN),'exact_continuous_manifest_sha256':sha(MUSIC),
        'immutable_symbol_bindings':addresses,
        'native_source_record_address':hex(0x034e6f08+8*520),
        'native_mixer_record_address':hex(0x034e5378+8*304),
        'native_driver_record_address':hex(0x034e32bc+8*84),
        'native_source_state_address':hex(0x034e9398+8),
        'provider_pool_address':'0x034e3cf4','provider_pool_slots':5,'provider_pool_stride':576,
        'original_cleanup':{'entry':'0x3b9dfc','mode':'Thumb','prologue_hex':prologue.hex(),
                            'prologue_bytes_sha256':hashlib.sha256(prologue).hexdigest(),
                            'resume':'0x3b9e07','signature':'single r0 source-record only',
                            'new_wrapper_frame_bytes':64,'SP_alignment':8,
                            'preserved':'r4-r8/callerLR/SP/originalr0return','native_execution_verified':False},
        'compilation':compilation,
        'artifacts':[{'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'sha256':sha(p)} for p in artifact_paths],
        'ARM_machine':'ARM','ARM_ELF_type':'REL','ARM_ELF_header_attributes':attributes['stdout'],
        'ARM_ELF_size':size['stdout'],'ARM_ELF_sections':sections['stdout'],
        'ARM_exports':exports['stdout'],'ARM_cleanup_bridge_disassembly':disassembly['stdout'],
        'ARM_unresolved_symbols':[],'ARM_Linux_or_dynamic_loader_dependency':False,
        'host_platform':platform.machine(),'host_tests':controls,'host_test_execution':execution,
        'host_sanitizers':['AddressSanitizer','UndefinedBehaviorSanitizer'],
        'missing_integration_bindings':['actualnativechannelreservation/futureborrowingcallback witness',
                                        'coherentAVsession/localsessionresume glue',
                                        'existing source-loop service and after-iteration call sites',
                                        'originalcoordinator owned-publication call site',
                                        'original3B9DFC replacement in a newly linked protected variant',
                                        'config/START/event17/F1/consumer andlegalGUI launch call sites'],
        'route9_unsupported_fail_closed':True,'exact_map_helper_returns_BINDING_MISSING':True,
        'callback_count_or_cancel_return_zero_used_as_stop_done':False,
        'existing_sources_manifests_proofs_canonical_modified':False,
        'old_music_build_linked':False,'frozen_control_object_linked_into_ARM':False,
        'frozen_control_C_compiled_readonly_for_host_tests':True,
        'single_bootstrap_resident_no_reset_unload_free':True,
        'guest_emulator_or_original_native_instructions_executed':False,
        'device_service_IO':False,'sounds_emitted':False,'device_install_candidate':False,
        'native_kernel_IRQ_audio_GUI_or_integrated_App_proven':False,
        'limits':'12 host groups run actual new adapter observations over identified ABI/byte fixtures; '
                 'native returns/ownership/session/kernel services are mocks. New ARM original-address imports '
                 'and64-byte cleanup bridge crosscompile with zero undefined symbols but are not run or installed. '
                 'Missing actual reservation/future-callback witness, session glue andoriginal call-site wiring '
                 'fail closed; source9unsupported. No currentMAINpatch, oldsource/build/proof overwrite, '
                 'nativeIRQ/mutex/scheduler/audio/phone/GUI/acceptedVPM-SIG/physicalmute/App orsafeunload proof.'
    }
    with REPORT.open('x') as output:
        json.dump(report,output,ensure_ascii=False,indent=2);output.write('\n')
    print(json.dumps({'report':str(REPORT.relative_to(ROOT)),'sha256':sha(REPORT),
                      'all_passed':True,'host_groups':12,'protected_frozen_sources':435,
                      'ARM_unresolved_symbols':[]}))


if __name__ == '__main__':
    main()
