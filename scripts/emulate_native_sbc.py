#!/usr/bin/env python3
"""Compare the freestanding ARMv6 prototype with upstream libsbc on the Pi.

All audio is synthetic and remains in memory/files. No Bluetooth/device I/O.
The host reference is libsbc 2.1; the tested machine code runs on ARM1176
emulation, not on the Pi's native AArch64 CPU and not on the Garmin.
"""
import ctypes as C
import hashlib
import itertools
import json
import math
from pathlib import Path
import struct
import subprocess
from datetime import datetime, timezone

import unicorn
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE,
                     UC_PROT_ALL,
                     UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
                     UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED)
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
                               UC_ARM_REG_LR, UC_ARM_REG_PC)

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'staging/native-sbc'
INPUT_PAGE = 0x09101000
OUTPUT_PAGE = 0x09103000
RESULT_PAGE = 0x09105000
PAGE_BYTES = 4096
STACK = 0x0900f000
RETURN = 0x09200000
RESULT_BYTES = 36


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_guard_faults():
    """Verify protection still traps a later access in the same ARM block."""
    results = []
    for kind, instructions, expected in (
            ('read', (0xe5d01000, 0xe5d02001), UC_ERR_READ_UNMAPPED),
            ('write', (0xe5c01000, 0xe5c01001), UC_ERR_WRITE_UNMAPPED)):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        uc.mem_map(0x10000, 4096)
        uc.mem_map(0x20000, 4096)
        uc.mem_write(0x10000, struct.pack('<2I', *instructions))
        uc.reg_write(UC_ARM_REG_R0, 0x20fff)
        try:
            uc.emu_start(0x10000, 0x10008, count=2)
        except unicorn.UcError as error:
            if error.errno != expected: raise
            results.append({'kind': kind, 'first_access_mapped': True,
                            'second_access_unmapped_fault': error.errno,
                            'fault_pc': hex(uc.reg_read(UC_ARM_REG_PC)), 'passed': True})
        else:
            raise ValueError('Unmapped guard page failed to trap')
    return results


class Sbc(C.Structure):
    _fields_ = [('flags', C.c_ulong), ('frequency', C.c_uint8),
                ('blocks', C.c_uint8), ('subbands', C.c_uint8),
                ('mode', C.c_uint8), ('allocation', C.c_uint8),
                ('bitpool', C.c_uint8), ('endian', C.c_uint8),
                ('priv', C.c_void_p), ('priv_alloc_base', C.c_void_p)]


class Reference:
    def __init__(self):
        self.library_path = Path('/lib/aarch64-linux-gnu/libsbc.so.1').resolve()
        self.version = subprocess.check_output(
            ['dpkg-query', '-W', '-f=${Version}', 'libsbc1'], text=True)
        if not self.version.startswith('2.1-'):
            raise ValueError('Tests expect the matching upstream 2.1 host reference')
        self.lib = C.CDLL(str(self.library_path))
        self.lib.sbc_init.argtypes = [C.POINTER(Sbc), C.c_ulong]
        self.lib.sbc_init.restype = C.c_int
        self.lib.sbc_finish.argtypes = [C.POINTER(Sbc)]
        self.lib.sbc_finish.restype = None
        for name in ('sbc_get_codesize', 'sbc_get_frame_length'):
            function = getattr(self.lib, name)
            function.argtypes = [C.POINTER(Sbc)]
            function.restype = C.c_size_t
        for name in ('sbc_encode', 'sbc_decode'):
            function = getattr(self.lib, name)
            function.argtypes = [C.POINTER(Sbc), C.c_void_p, C.c_size_t,
                                 C.c_void_p, C.c_size_t, C.c_void_p]
            function.restype = C.c_ssize_t

    def new(self, config=None):
        context = Sbc()
        if self.lib.sbc_init(C.byref(context), 0) != 0:
            raise ValueError('Host libsbc initialization failed')
        context.endian = 0
        if config:
            for key, value in config.items(): setattr(context, key, value)
        return context

    def encode(self, config, frames=4, bitpools=None):
        context = self.new(config)
        result = []
        rate = (16000, 32000, 44100, 48000)[config['frequency']]
        channels = 1 if config['mode'] == 0 else 2
        sample_index = 0
        try:
            for frame_index in range(frames):
                if bitpools: context.bitpool = bitpools[frame_index]
                size = self.lib.sbc_get_codesize(C.byref(context))
                samples = []
                for index in range(size // (2 * channels)):
                    for channel in range(channels):
                        phase = 2 * math.pi * (440 + channel * 227) * (sample_index + index) / rate
                        samples.append(round(14000 * math.sin(phase)))
                sample_index += size // (2 * channels)
                pcm = struct.pack('<' + 'h' * len(samples), *samples)
                source = C.create_string_buffer(pcm)
                encoded = C.create_string_buffer(1024)
                written = C.c_ssize_t()
                consumed = self.lib.sbc_encode(C.byref(context), source, len(pcm),
                                               encoded, len(encoded), C.byref(written))
                if consumed != len(pcm) or not 4 <= written.value <= 1024:
                    raise ValueError('Reference encoder failed')
                result.append(encoded.raw[:written.value])
        finally:
            self.lib.sbc_finish(C.byref(context))
        return result

    def decode_stream(self, frames):
        context = self.new()
        output = []
        try:
            for frame in frames:
                source = C.create_string_buffer(frame)
                pcm = C.create_string_buffer(512)
                written = C.c_size_t()
                consumed = self.lib.sbc_decode(C.byref(context), source, len(frame),
                                               pcm, len(pcm), C.byref(written))
                if consumed != len(frame) or written.value == 0:
                    raise ValueError('Reference decoder rejected an encoded frame')
                output.append(pcm.raw[:written.value])
        finally:
            self.lib.sbc_finish(C.byref(context))
        return output


class Machine:
    def __init__(self, manifest):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        self.symbols = manifest['symbols']
        elf = (ROOT / manifest['elf']).read_bytes()
        if digest(elf) != manifest['elf_sha256']: raise ValueError('ELF hash mismatch')
        header = struct.unpack_from('<16sHHIIIIIHHHHHH', elf)
        if header[0][:6] != b'\x7fELF\x01\x01' or header[1:3] != (2, 40):
            raise ValueError('Expected a little-endian ARM ELF32 executable')
        self.segments = []
        for i in range(header[10]):
            segment = struct.unpack_from('<8I', elf, header[5] + i * header[9])
            kind, offset, address, _, filesz, memsz, flags, _ = segment
            if kind != 1: raise ValueError('Unexpected non-load ELF program segment')
            start = address & ~4095
            end = (address + memsz + 4095) & ~4095
            if end == start: continue
            self.uc.mem_map(start, end - start, UC_PROT_ALL)
            self.uc.mem_write(address, elf[offset:offset+filesz])
            permissions = (UC_PROT_READ if flags & 4 else 0) | \
                          (UC_PROT_WRITE if flags & 2 else 0) | \
                          (UC_PROT_EXEC if flags & 1 else 0)
            self.uc.mem_protect(start, end - start, permissions)
            self.segments.append({'address': hex(address), 'file_bytes': filesz,
                                  'memory_bytes': memsz, 'flags': flags})
        self.uc.mem_map(0x09000000, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
        # Every buffer ends immediately before an unmapped guard page.
        # This is independent of memory hooks, which the installed Unicorn
        # ARM engine can omit for later accesses within a translated block.
        self.uc.mem_map(INPUT_PAGE, PAGE_BYTES, UC_PROT_READ)
        self.uc.mem_map(OUTPUT_PAGE, PAGE_BYTES, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(RESULT_PAGE, PAGE_BYTES, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(RETURN, 4096, UC_PROT_READ | UC_PROT_EXEC)
        self.counter = 0
        self.active = False
        self.total_instructions = 0
        self.uc.hook_add(UC_HOOK_CODE, self.code)

    def code(self, uc, address, size, data):
        self.counter += 1

    def call(self, name, args=(), fifth=None):
        self.counter = 0
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                    UC_ARM_REG_R3), args):
            self.uc.reg_write(register, value)
        if fifth is not None: self.uc.mem_write(STACK, struct.pack('<I', fifth))
        self.uc.emu_start(self.symbols[name]['address'], RETURN, timeout=5000000, count=1000000)
        if self.uc.reg_read(UC_ARM_REG_PC) != RETURN:
            raise ValueError(f'Function did not return within bounded execution: {name}')
        self.total_instructions += self.counter
        return C.c_int32(self.uc.reg_read(UC_ARM_REG_R0)).value

    def reset(self):
        self.active = False
        if self.call('garmin_sbc_reset') != 0: raise ValueError('ARM decoder reset failed')

    def decode(self, frame, cap=512, null_input=False, null_output=False, null_result=False):
        if len(frame) > PAGE_BYTES-32 or not 0 <= cap <= 512:
            raise ValueError('Experiment buffer outside guarded capacity')
        input_address = INPUT_PAGE + PAGE_BYTES - len(frame)
        output_address = OUTPUT_PAGE + PAGE_BYTES - cap
        result_address = RESULT_PAGE + PAGE_BYTES - RESULT_BYTES
        for page in (INPUT_PAGE, OUTPUT_PAGE, RESULT_PAGE):
            self.uc.mem_write(page, b'\xa5' * PAGE_BYTES)
        if frame: self.uc.mem_write(input_address, frame)
        self.input_len = len(frame)
        self.output_cap = cap
        self.active = True
        try:
            status = self.call('garmin_sbc_decode_frame',
                               (0 if null_input else input_address, len(frame),
                                0 if null_output else output_address, cap),
                               fifth=0 if null_result else result_address)
        finally:
            self.active = False
        for address, size in ((output_address-32, 32), (result_address-32, 32)):
            if bytes(self.uc.mem_read(address, size)) != b'\xa5' * size:
                raise ValueError('Output/result guard overwritten')
        result = struct.unpack('<7IiI', self.uc.mem_read(result_address, RESULT_BYTES)) if not null_result else (0,)*9
        if result[1] > cap: raise ValueError('Result claimed more output than its buffer')
        pcm = bytes(self.uc.mem_read(output_address, result[1])) if result[1] else b''
        if status < 0 and bytes(self.uc.mem_read(OUTPUT_PAGE, PAGE_BYTES)) != b'\xa5' * PAGE_BYTES:
            raise ValueError('Rejected frame wrote PCM')
        return status, result, pcm, self.counter


def main():
    guard_fault_controls = verify_guard_faults()
    manifest = json.loads((BUILD / 'manifest.json').read_text())
    machine, reference = Machine(manifest), Reference()
    config_template = dict(frequency=2, mode=3, subbands=1, blocks=3, allocation=0, bitpool=53)
    baseline = reference.encode(config_template, frames=8)
    baseline_pcm = reference.decode_stream(baseline)
    status, _, _, _ = machine.decode(baseline[0])
    if status != -2: raise ValueError('Uninitialized decoder was not rejected')
    configurations = []
    frame_count = 0
    arena_usage = set()
    for frequency, mode, subbands in itertools.product(range(4), range(4), range(2)):
        index = len(configurations)
        config = dict(frequency=frequency, mode=mode, subbands=subbands,
                      blocks=(frequency+mode+subbands) % 4,
                      allocation=(frequency+mode) % 2,
                      bitpool=53 if subbands else 31)
        # This matrix covers every rate/mode/subband tuple; blocks and
        # allocation rotate across it, rather than claiming every combination.
        frames = reference.encode(config)
        expected = reference.decode_stream(frames)
        machine.reset()
        instructions, decoded = [], []
        for frame, pcm in zip(frames, expected):
            status, result, actual, count = machine.decode(frame)
            samples = (4*(config['blocks']+1)) * (8 if subbands else 4)
            expected_meta = (len(frame), len(pcm), (16000,32000,44100,48000)[frequency],
                             1 if mode == 0 else 2, samples, frame[1], config['bitpool'])
            if status != 0 or result[:7] != expected_meta or actual != pcm:
                raise ValueError(f'ARM/reference disagreement in configuration {config}: {status}, {result}')
            instructions.append(count)
            decoded.append(actual)
            arena_usage.add(result[8])
            frame_count += 1
        all_pcm = b''.join(decoded)
        if not any(all_pcm): raise ValueError('Synthetic PCM was silent')
        configurations.append({'config': config, 'frames': len(frames),
                               'encoded_sha256': digest(b''.join(frames)),
                               'pcm_sha256': digest(all_pcm), 'pcm_bytes': len(all_pcm),
                               'reference_byte_identical': True,
                               'instructions_per_frame': instructions})

    # A2DP SBC can change bitpool while retaining the negotiated format.
    bitpools = [2, 53, 31, 45, 53, 2, 53, 31]
    frames = reference.encode(config_template, frames=len(bitpools), bitpools=bitpools)
    expected = reference.decode_stream(frames)
    machine.reset()
    for frame, pcm in zip(frames, expected):
        status, result, actual, _ = machine.decode(frame)
        if status != 0 or actual != pcm or result[6] != frame[2]:
            raise ValueError('Bitpool transition disagreed with upstream')
        frame_count += 1

    machine.reset()
    continuous_instructions = []
    for frame, pcm in zip(baseline, baseline_pcm):
        status, result, actual, count = machine.decode(frame)
        if status != 0 or actual != pcm: raise ValueError('Stereo baseline mismatch')
        continuous_instructions.append(count)
        frame_count += 1

    invalid_cases = []
    for cut in (0, 1, 2, 3, 4, len(baseline[0])//2, len(baseline[0])-1):
        invalid_cases.append((f'truncated_{cut}', baseline[0][:cut], 512, -3, {}))
    bad_sync = bytes([0]) + baseline[0][1:]
    bad_crc = baseline[0][:3] + bytes([baseline[0][3] ^ 1]) + baseline[0][4:]
    bad_bitpool = baseline[0][:2] + bytes([0]) + baseline[0][3:]
    invalid_cases.extend([
        ('bad_sync', bad_sync, 512, -1, {}),
        ('bad_crc', bad_crc, 512, -6, {}),
        ('bad_bitpool', bad_bitpool, 512, -1, {}),
        ('small_output', baseline[0], 511, -4, {}),
        ('zero_output', baseline[0], 0, -4, {}),
        ('null_input', baseline[0], 512, -1, {'null_input': True}),
        ('null_output', baseline[0], 512, -1, {'null_output': True}),
        ('null_result', baseline[0], 512, -1, {'null_result': True}),
    ])
    guards = []
    for name, frame, cap, expected_status, kwargs in invalid_cases:
        machine.reset()
        status, result, _, _ = machine.decode(frame, cap=cap, **kwargs)
        if status != expected_status: raise ValueError(f'Wrong rejection in {name}: {status}')
        # Every rejected first frame must leave/reset a usable fresh decoder.
        status2, _, actual, _ = machine.decode(baseline[0])
        if status2 != 0 or actual != baseline_pcm[0]:
            raise ValueError(f'Invalid frame poisoned decoder state: {name}')
        guards.append({'name': name, 'status': status, 'codec_error': result[7],
                       'no_pcm_write': True, 'recovery_byte_identical': True})
        frame_count += 1

    # Avoid initializing the synthesis filter with a new subband count
    # without a reset. The original stream must resume byte-identically.
    other_config = dict(config_template, subbands=0, bitpool=31)
    other_frame = reference.encode(other_config, frames=1)[0]
    machine.reset()
    machine.decode(baseline[0])
    status, _, _, _ = machine.decode(other_frame)
    if status != -5: raise ValueError('Negotiated format change was not rejected')
    status, _, actual, _ = machine.decode(baseline[1])
    if status != 0 or actual != baseline_pcm[1]: raise ValueError('Format guard lost original stream state')
    guards.append({'name': 'format_change_without_reset', 'status': -5,
                   'no_pcm_write': True, 'original_stream_resumed_byte_identical': True})
    frame_count += 2

    # Extra data belongs to subsequent SBC frames; consume exactly one.
    machine.reset()
    status, result, actual, _ = machine.decode(baseline[0] + baseline[1])
    if status != 0 or result[0] != len(baseline[0]) or actual != baseline_pcm[0]:
        raise ValueError('Decoder did not consume exactly one frame')
    guards.append({'name': 'two_frames_consume_one', 'status': 0,
                   'consumed_bytes': result[0], 'pcm_matches_first_frame': True})
    frame_count += 1
    output = {'updated_utc': datetime.now(timezone.utc).isoformat(),
              'emulator': 'Unicorn', 'module_version': unicorn.__version__,
              'cpu_model': 'ARM1176JZF-S', 'elf_sha256': manifest['elf_sha256'],
              'build_manifest': str((BUILD / 'manifest.json').relative_to(ROOT)),
              'segments': machine.segments,
              'reference': {'library': str(reference.library_path), 'debian_version': reference.version,
                            'library_sha256': digest(reference.library_path.read_bytes()),
                            'upstream_version': '2.1'},
              'configuration_cases': configurations, 'configuration_count': len(configurations),
              'bitpool_transition': {'bitpools': bitpools, 'reference_byte_identical': True},
              'stereo_baseline': {'rate': 44100, 'channels': 2, 'frames': len(baseline),
                                  'pcm_sha256': digest(b''.join(baseline_pcm)),
                                  'instructions_per_frame': continuous_instructions},
              'guard_cases': guards, 'decoded_frames': frame_count,
              'guard_page_fault_controls': guard_fault_controls,
              'arena_used_bytes': sorted(arena_usage), 'reserved_arena_bytes': 16384,
              'guarded_buffers': {'input': 'Read-only, right-aligned to unmapped next page',
                                 'pcm_output': 'Capacity right-aligned to unmapped next page plus leading canary',
                                 'result': '36 bytes right-aligned to unmapped next page plus leading canary',
                                 'stack_mapping_bytes': 65536,
                                 'unicorn_memory_hooks_used_for_bounds': False},
              'instructions_executed_total': machine.total_instructions,
              'all_passed': True, 'device_io': False, 'audible_output': False,
              'native_on_garmin_verified': False,
              'limitations': 'Offline decoder feasibility only. CPU/ABI on physical Garmin not validated. Synthetic inputs from upstream encoder; byte comparison verifies this build against the upstream decoder, not external Bluetooth interoperability. No real-time benchmark, native loading, UI, A2DP transport, PCM speaker ABI or firmware update/recovery achieved.'}
    path = ROOT / 'evidence/firmware-analysis/native-sbc-emulation.json'
    path.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'output': str(path), 'configuration_count': len(configurations),
                      'decoded_frames': frame_count, 'guard_cases': len(guards),
                      'arena_used_bytes': sorted(arena_usage), 'all_passed': True,
                      'device_io': False}))


if __name__ == '__main__':
    main()
