#!/usr/bin/env python3
"""Load the SBC module using stock instructions, then call its RAM exports.

This performs no navigator or Bluetooth I/O. The emulator gets the compiled
bytes through synthetic file callbacks, never by directly mapping its ELF.
The two export slots are experimental and do not preserve the stock APIs.
"""
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import struct

import unicorn
from unicorn import UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import STUBS
from emulate_native_loader import simulate
from emulate_native_sbc import (Machine, Reference, INPUT_PAGE, OUTPUT_PAGE,
                                RESULT_PAGE, PAGE_BYTES, RETURN, verify_guard_faults)

BUILD = ROOT / 'staging/native-sbc-component-emulation'


def sha(data):
    return hashlib.sha256(data).hexdigest()


class LoadedMachine(Machine):
    """Reuse guarded frame calls, looking up stock import pointers each time."""
    def __init__(self, emulator, manifest):
        self.uc = emulator
        self.manifest = manifest
        self.symbols = {}
        self.counter = 0
        self.active = False
        self.total_instructions = 0
        self.trampoline_visits = []
        for page, permissions in ((INPUT_PAGE, UC_PROT_READ),
                                  (OUTPUT_PAGE, UC_PROT_READ | UC_PROT_WRITE),
                                  (RESULT_PAGE, UC_PROT_READ | UC_PROT_WRITE)):
            self.uc.mem_map(page, PAGE_BYTES, permissions)
        self.uc.mem_map(RETURN, PAGE_BYTES, UC_PROT_READ | UC_PROT_EXEC)
        # The stock loader's stack mapping also supports the decoder calls.
        # Machine.call uses 0x0900f000, so provide its independent stack.
        self.uc.mem_map(0x09000000, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.hook_add(UC_HOOK_CODE, self.code)

    def code(self, uc, address, size, data):
        self.counter += 1
        if address in (STUBS, STUBS+12):
            self.trampoline_visits.append(address)

    def call(self, name, args=(), fifth=None):
        index = self.manifest['exports'].index(name)
        storage = 0xf094f0 + index*4
        trampoline = struct.unpack('<I', self.uc.mem_read(storage, 4))[0]
        target = struct.unpack('<I', self.uc.mem_read(trampoline+8, 4))[0]
        if trampoline != STUBS+index*12 or target != self.manifest['symbols'][name]['address']:
            raise ValueError('Stock RAM export pointer differs from the compiled module')
        self.symbols[name] = {'address': trampoline}
        before = len(self.trampoline_visits)
        result = super().call(name, args, fifth)
        if self.trampoline_visits[before:] != [trampoline]:
            raise ValueError('Call did not pass through the stock-created ARM trampoline')
        return result


def main():
    manifest = json.loads((BUILD / 'manifest.json').read_text())
    binary = (ROOT / manifest['flat_binary']).read_bytes()
    if sha(binary) != manifest['flat_binary_sha256']:
        raise ValueError('Compiled module hash mismatch')
    targets = [manifest['symbols'][name]['address'] for name in manifest['exports']]
    stock = NativeImage()
    emulator, loader = simulate(stock, 'compiled_decoder', module_bytes=binary,
                                module_ram_bytes=manifest['ram_bytes'], export_targets=targets,
                                poison_module_ram=True, return_session=True)
    bss = bytes(emulator.mem_read(manifest['bss_start'], manifest['bss_bytes']))
    if any(bss): raise ValueError('Component entry failed to clear poisoned BSS')
    machine = LoadedMachine(emulator, manifest)
    reference = Reference()
    results, guards = [], []
    config = dict(frequency=2, mode=3, subbands=1, blocks=3, allocation=0, bitpool=53)
    baseline = reference.encode(config, frames=8)
    expected_baseline = reference.decode_stream(baseline)
    status, _, _, _ = machine.decode(baseline[0])
    if status != -2: raise ValueError('Decoder was active before reset after component entry')
    guards.append({'name': 'not_ready_after_load', 'status': status, 'passed': True})
    frame_count = 0
    configs = [config,
               dict(config, frequency=3),
               dict(config, frequency=0, mode=0, bitpool=31),
               dict(config, frequency=1, mode=1, allocation=1, bitpool=31),
               dict(config, mode=2, subbands=0, blocks=1, bitpool=31),
               dict(config, blocks=0, allocation=1, bitpool=31)]
    for current in configs:
        frames = reference.encode(current, frames=8)
        expected = reference.decode_stream(frames)
        machine.reset()
        output, instruction_counts = [], []
        for encoded, pcm in zip(frames, expected):
            status, result, actual, count = machine.decode(encoded)
            if status != 0 or result[0] != len(encoded) or actual != pcm:
                raise ValueError('Loaded module PCM differs from the reference')
            output.append(actual)
            instruction_counts.append(count)
            frame_count += 1
        results.append({'config': current, 'frames': len(frames),
                        'encoded_sha256': sha(b''.join(frames)),
                        'pcm_sha256': sha(b''.join(output)),
                        'pcm_bytes': len(b''.join(output)),
                        'reference_byte_identical': True,
                        'instructions_per_frame': instruction_counts})
    for name, encoded, cap, expected_status in [
            ('truncated', baseline[0][:-1], 512, -3),
            ('small_output', baseline[0], 511, -4),
            ('bad_crc', baseline[0][:3]+bytes([baseline[0][3]^1])+baseline[0][4:], 512, -6)]:
        machine.reset()
        status, _, _, _ = machine.decode(encoded, cap=cap)
        if status != expected_status: raise ValueError('Loaded decoder rejection differs')
        status, _, pcm, _ = machine.decode(baseline[0])
        if status != 0 or pcm != expected_baseline[0]:
            raise ValueError('Rejected frame poisoned the loaded component')
        guards.append({'name': name, 'status': expected_status, 'passed': True,
                       'recovery_reference_byte_identical': True})
        frame_count += 1
    machine.reset()
    bitpools = [2, 53, 31, 45, 53, 2, 53, 31]
    frames = reference.encode(config, frames=len(bitpools), bitpools=bitpools)
    expected = reference.decode_stream(frames)
    for encoded, pcm in zip(frames, expected):
        status, result, actual, _ = machine.decode(encoded)
        if status != 0 or actual != pcm or result[6] != encoded[2]:
            raise ValueError('Loaded decoder did not handle negotiated bitpool transitions')
        frame_count += 1
    output = {'updated_utc': datetime.now(timezone.utc).isoformat(),
              'stock_sha256': EXPECTED, 'cpu_model': 'ARM1176JZF-S',
              'emulator': 'Unicorn', 'version': unicorn.__version__,
              'build_manifest': str((BUILD / 'manifest.json').relative_to(ROOT)),
              'module_binary_sha256': sha(binary), 'module_binary_bytes': len(binary),
              'module_ram_bytes': manifest['ram_bytes'], 'loader_result': loader,
              'module_loaded_by_stock_instructions': True,
              'elf_directly_mapped': False,
              'bss_poisoned_before_load': True, 'bss_cleared_by_module_entry': True,
              'bss_bytes': manifest['bss_bytes'], 'export_calls_through_ram_trampolines': True,
              'trampoline_call_count': len(machine.trampoline_visits),
              'configuration_cases': results, 'decoded_frames': frame_count,
              'guard_cases': guards, 'guard_page_fault_controls': verify_guard_faults(),
              'bitpool_transition': {'bitpools': bitpools, 'reference_byte_identical': True},
              'reference': {'upstream_version': '2.1', 'debian_version': reference.version,
                            'library_sha256': sha(reference.library_path.read_bytes())},
              'instructions_executed_total': machine.total_instructions,
              'all_passed': True, 'device_io': False, 'audible_output': False,
              'native_on_garmin_verified': False,
              'device_install_candidate': False, 'preserves_original_component_api': False,
              'limitations': 'Offline stock-loader-to-SBC integration only. File callbacks/cache/strcmp are hooks, and this test invokes the initializer directly rather than satisfying the real conditional caller. The two decoder exports use experimental API slots, not the original 40 signatures. No UI, SDP Audio Sink, AVDTP reception, speaker ABI, hardware performance, install path or recovery is verified. Do not install this module.'}
    path = ROOT / 'evidence/firmware-analysis/native-sbc-component-emulation.json'
    path.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'decoded_frames': frame_count,
                      'configuration_cases': len(results), 'loader_to_decoder_verified_offline': True,
                      'bss_cleared': True, 'all_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
