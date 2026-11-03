#!/usr/bin/env python3
"""Exercise decoder -> original TTS PCM ring -> original reader, offline only.

Scheduling/priority predicates and channel registration are controlled hooks.
The stock PCM writer, reservation, commit, reader and memcpy execute their
original instructions. No device, Bluetooth or actual speaker is accessed.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct

from unicorn import UC_HOOK_CODE, UcError
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import DESCRIPTOR, STUBS
from analyze_sdp_activation import trace
from emulate_native_loader import simulate
from emulate_native_sbc import (Machine, Reference, INPUT_PAGE, OUTPUT_PAGE,
                                RESULT_PAGE, PAGE_BYTES, RESULT_BYTES)
from emulate_native_sbc_component import LoadedMachine

BUILD = ROOT / 'staging/native-sbc-pcm-emulation'
CONTEXT = 0xf09294
RING = 0x2d3f030
RING_BYTES = 0xa000
TAIL_RESERVE = 0x1400
HOST_OUTPUT = 0x21c62a
READER = 0x484c04


def sha(data):
    return hashlib.sha256(data).hexdigest()


class PcmMachine(LoadedMachine):
    def __init__(self, stock, emulator, manifest):
        super().__init__(emulator, manifest)
        self.setup_pcm_route(stock)

    def setup_pcm_route(self, stock):
        """Attach stock buffer code and explicit policy hooks to loaded code."""
        self.events = []
        self.policy_events = []
        # 0x39129c ARM memcpy is already supplied by the stock-loader test.
        for page in (0x21c000, 0x33f000, 0x373000, 0x484000, 0x255000,
                     0x36b000, 0x270000):
            self.uc.mem_map(page, PAGE_BYTES)
            self.uc.mem_write(page, stock.read(page, PAGE_BYTES))
        self.uc.mem_map(0x2d3f000, 0xc000)
        self.uc.mem_write(RING-32, b'\xa5' * (32+RING_BYTES+TAIL_RESERVE+32))
        self.policy = {
            0x2554ca: ('channel_selector', 1),
            0x25541c: ('priority_interrupt', 0),
            0x2554d6: ('accepted_sequence', 0),
            0x36b69a: ('channel_busy', 1),
            0x36b720: ('channel_start', 0),
            0x270458: ('channel_register', 0),
            0x27058a: ('channel_queue', 0),
        }
        for address in self.policy:
            self.uc.mem_write(address, b'\x70\x47')
        self.uc.hook_add(UC_HOOK_CODE, self.observe)

    def code(self, uc, address, size, data):
        self.counter += 1
        if address in tuple(STUBS+12*i for i in range(len(self.manifest['exports']))):
            self.trampoline_visits.append(address)

    def observe(self, uc, address, size, data):
        if address in self.policy:
            name, value = self.policy[address]
            self.policy_events.append({'name': name, 'return': value})
            uc.reg_write(UC_ARM_REG_R0, value)
        elif address in (HOST_OUTPUT, READER, 0x33f662, 0x33f474):
            args = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                            UC_ARM_REG_R2, UC_ARM_REG_R3)]
            self.events.append({'entry': hex(address), 'args': [hex(v) for v in args]})

    def configure(self, index=0, active=True):
        state = bytearray(32)
        state[4] = int(active)
        state[7] = 1  # Synthetic already-initialized producer state.
        struct.pack_into('<2I', state, 12, index, index)
        self.uc.mem_write(CONTEXT, bytes(state))

    def offsets(self):
        return struct.unpack('<2I', self.uc.mem_read(CONTEXT+12, 8))

    def queued(self):
        write, read = self.offsets()
        return (write-read) % RING_BYTES

    def submit(self, frame):
        if not 0 < len(frame) <= PAGE_BYTES-32: raise ValueError('Frame outside guard')
        source = INPUT_PAGE+PAGE_BYTES-len(frame)
        result = RESULT_PAGE+PAGE_BYTES-RESULT_BYTES
        self.uc.mem_write(INPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.uc.mem_write(source, frame)
        self.uc.mem_write(RESULT_PAGE, b'\xa5'*PAGE_BYTES)
        try:
            name = getattr(self, 'submit_function', 'garmin_sbc_submit_frame')
            status = self.call(name, (source, len(frame), result))
        except UcError as error:
            raise RuntimeError(f'PCM submit: {error}, PC={self.uc.reg_read(UC_ARM_REG_PC):#x}, '
                               f'offsets={self.offsets()}, events={self.events[-4:]}, '
                               f'policy={self.policy_events[-5:]}') from error
        if bytes(self.uc.mem_read(result-32, 32)) != b'\xa5'*32:
            raise ValueError('Submit changed result leading guard')
        decoded = struct.unpack('<9I', self.uc.mem_read(result, RESULT_BYTES))
        self.verify_ring_guards()
        return status, decoded

    def read(self, cap):
        if not 0 < cap <= PAGE_BYTES-32: raise ValueError('Read outside guard')
        destination = OUTPUT_PAGE+PAGE_BYTES-cap
        self.uc.mem_write(OUTPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.symbols['_stock_reader'] = {'address': READER | 1}
        count = Machine.call(self, '_stock_reader', (0, destination, cap))
        if not 0 <= count <= cap: raise ValueError('Native reader returned invalid count')
        if bytes(self.uc.mem_read(destination-32, 32)) != b'\xa5'*32:
            raise ValueError('Native reader changed leading guard')
        if bytes(self.uc.mem_read(destination+count, cap-count)) != b'\xa5'*(cap-count):
            raise ValueError('Native reader wrote beyond reported count')
        self.verify_ring_guards()
        return bytes(self.uc.mem_read(destination, count))

    def verify_ring_guards(self):
        for address in (RING-32, RING+RING_BYTES+TAIL_RESERVE):
            if bytes(self.uc.mem_read(address, 32)) != b'\xa5'*32:
                raise ValueError('Ring/tail reservation changed canary')


def main():
    stock = NativeImage()
    manifest = json.loads((BUILD/'manifest.json').read_text())
    binary = (ROOT/manifest['flat_binary']).read_bytes()
    if sha(binary) != manifest['flat_binary_sha256']:
        raise ValueError('PCM component changed since build')
    for path, expected in manifest['source_sha256'].items():
        if sha((ROOT/path).read_bytes()) != expected: raise ValueError('Source changed: '+path)
    targets = [manifest['symbols'][name]['address'] for name in manifest['exports']]
    emulator, loader = simulate(stock, 'compiled_decoder', module_bytes=binary,
                                module_ram_bytes=manifest['ram_bytes'], export_targets=targets,
                                poison_module_ram=True, return_session=True)
    host_table = struct.unpack('<I', emulator.mem_read(DESCRIPTOR+36, 4))[0]
    host_zero = struct.unpack('<I', emulator.mem_read(host_table, 4))[0]
    if host_zero != HOST_OUTPUT | 1: raise ValueError('Stock host callback differs')
    machine = PcmMachine(stock, emulator, manifest)
    reference = Reference()
    config = dict(frequency=0, mode=0, subbands=1, blocks=3, allocation=0, bitpool=31)
    frames = reference.encode(config, frames=180)
    expected = reference.decode_stream(frames)
    cases = []
    for index in (0, RING_BYTES-256, RING_BYTES-64):
        machine.configure(index)
        machine.reset()
        output = []
        before_events = len(machine.events)
        wraps = 0
        for encoded, pcm in zip(frames, expected):
            before_write, _ = machine.offsets()
            status, result = machine.submit(encoded)
            if status != 0 or result[:4] != (len(encoded), len(pcm), 16000, 1):
                raise ValueError('PCM submit differs from 16 kHz mono decoder')
            if machine.offsets()[0] < before_write: wraps += 1
            # Retain one frame between drains. Repeatedly exhausting the queue
            # invokes the stock underrun-stop policy after four empty drains.
            if machine.queued() >= 4096:
                chunk = machine.read(3840)
                if len(chunk) != 3840: raise ValueError('Reader failed to drain queued PCM')
                output.append(chunk)
        while machine.queued(): output.append(machine.read(3840))
        if b''.join(output) != b''.join(expected):
            actual_pcm, wanted_pcm = b''.join(output), b''.join(expected)
            difference = next((n for n, (a, b) in enumerate(zip(actual_pcm, wanted_pcm))
                               if a != b), None)
            raise ValueError(f'Stock ring differs at initial={index:#x}, byte={difference}, '
                             f'lengths={len(actual_pcm)}/{len(wanted_pcm)}; '
                             f'actual={actual_pcm[max(0,(difference or 0)-8):(difference or 0)+24].hex()} '
                             f'expected={wanted_pcm[max(0,(difference or 0)-8):(difference or 0)+24].hex()}')
        if wraps < 1 or machine.offsets()[0] != machine.offsets()[1]:
            raise ValueError('Wrap/drain case incomplete')
        events = machine.events[before_events:]
        if sum(e['entry'] == hex(HOST_OUTPUT) for e in events) != len(frames):
            raise ValueError('Module did not call original host output for every frame')
        cases.append({'initial_ring_index': index, 'frames': len(frames),
                      'pcm_bytes': len(b''.join(output)), 'pcm_sha256': sha(b''.join(output)),
                      'reference_byte_identical': True, 'write_wraps': wraps,
                      'stock_host_calls': len(frames),
                      'stock_reader_calls': sum(e['entry'] == hex(READER) for e in events),
                      'ring_drained': True})
    guards = []
    for name, frame, wanted in [
            ('truncated', frames[0][:3], -3),
            ('bad_crc', frames[0][:3]+bytes([frames[0][3]^1])+frames[0][4:], -6),
            ('stereo_44100_requires_conversion',
             reference.encode(dict(config, frequency=2, mode=3, bitpool=53), frames=1)[0], -7)]:
        machine.configure()
        machine.reset()
        before = len(machine.events)
        status, result = machine.submit(frame)
        if status != wanted or machine.queued() != 0 or len(machine.events) != before:
            raise ValueError('Rejected audio reached native output callback')
        status, result = machine.submit(frames[0])
        actual = machine.read(result[1])
        if status != 0 or actual != expected[0]: raise ValueError('Rejection lost recovery')
        guards.append({'name': name, 'status': status if wanted == 0 else wanted,
                       'no_host_call_on_rejection': True, 'recovery_byte_identical': True})
    # Empty and inactive readers must not expose stale bytes.
    machine.configure()
    if machine.read(256) != b'': raise ValueError('Empty native reader returned old samples')
    guards.append({'name': 'empty_reader', 'returned_bytes': 0, 'passed': True})
    machine.configure(active=False)
    machine.reset()
    status, result = machine.submit(frames[0])
    if status != 0 or machine.read(256) != b'': raise ValueError('Inactive channel gate failed')
    guards.append({'name': 'inactive_reader', 'queued_bytes': machine.queued(),
                   'returned_bytes': 0, 'passed': True})
    machine.configure()
    machine.reset()
    machine.policy[0x2554d6] = ('accepted_sequence', 1)
    status, result = machine.submit(frames[0])
    if status != 0 or machine.queued() != 0:
        raise ValueError('Sequence-discard policy was not reproduced')
    machine.policy[0x2554d6] = ('accepted_sequence', 0)
    if machine.submit(frames[1])[0] != 0 or machine.read(256) != expected[1]:
        raise ValueError('Sequence-discard case did not recover')
    guards.append({'name': 'sequence_discard_despite_success_return',
                   'submit_return': 0, 'discarded_queued_bytes': 0,
                   'subsequent_frame_byte_identical': True})
    machine.configure()
    machine.reset()
    for encoded, wanted in zip(frames[:4], expected[:4]):
        if machine.submit(encoded)[0] != 0 or machine.read(256) != wanted:
            raise ValueError('Underrun policy changed samples before stopping')
    if bytes(machine.uc.mem_read(CONTEXT+7, 1)) != b'\x00':
        raise ValueError('Stock four-empty-drain stop policy not reproduced')
    guards.append({'name': 'four_empty_drains_stop_producer',
                   'producer_initialized_flag': 0,
                   'next_frame_requires_native_initialization': True})
    # Exercise the stock buffer threshold/channel-start branch with hooked OS
    # registration. This records a requested channel, not a real speaker.
    machine.configure(active=False)
    machine.reset()
    start_events = len(machine.events)
    for encoded in frames[:40]:
        if machine.submit(encoded)[0] != 0: raise ValueError('Threshold submit failed')
    if not any(e['entry'] == '0x33f474' for e in machine.events[start_events:]):
        raise ValueError('Stock start threshold not reached')
    if bytes(machine.uc.mem_read(CONTEXT+4, 1)) != b'\x01':
        raise ValueError('Stock state did not mark hooked channel active')
    chunk = machine.read(3840)
    if chunk != b''.join(expected[:15]): raise ValueError('Threshold route changed samples')
    output = {
        'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
        'build_manifest': str((BUILD/'manifest.json').relative_to(ROOT)),
        'module_binary_sha256': sha(binary), 'module_binary_bytes': len(binary),
        'module_ram_bytes': manifest['ram_bytes'], 'loader_result': loader,
        'host_api_slot': 0, 'host_callback': hex(HOST_OUTPUT | 1),
        'host_argument_usage': 'r2 = PCM bytes pointer; r3 = byte count; r0/r1 not read',
        'ring': {'base': hex(RING), 'bytes': RING_BYTES, 'context': hex(CONTEXT),
                 'write_offset_field': 12, 'read_offset_field': 16,
                 'tail_copy_reservation_bytes': TAIL_RESERVE},
        'stock_routines': {'reserve': '0x33f824', 'commit': '0x33f586',
                           'reader': '0x33f662', 'reader_gate': hex(READER),
                           'memcpy': '0x3732c8', 'channel_start': '0x33f474'},
        'function_traces': {hex(a): trace(stock, a, 350) for a in
                            (HOST_OUTPUT, 0x33f824, 0x33f586, 0x33f662, READER, 0x33f474)},
        'cases': cases, 'decoded_and_routed_frames': sum(c['frames'] for c in cases),
        'guard_cases': guards, 'stock_channel_start_threshold_exercised': True,
        'hooked_policy_calls': machine.policy_events,
        'caller_invokes_native_submit_export': True,
        'decoder_calls_native_host_callback_itself': True,
        'pcm_copy_and_ring_instructions_unmodified': True,
        'ring_state_synthetic': True, 'operating_system_policy_hooked': True,
        'ring_wait_backpressure_tested': False, 'all_passed': True,
        'device_io': False, 'audible_output': False,
        'native_on_garmin_verified': False, 'physical_speaker_verified': False,
        'physical_sample_clock_verified': False, 'a2dp_packets_received': False,
        'stereo_downmix_or_resampling_implemented': False,
        'preserves_original_component_api': False, 'device_install_candidate': False,
        'limitations': 'Only 16 kHz mono SBC is submitted; other formats are explicitly rejected. Original native PCM dataflow and wrap/drain are executed with synthetic ring state and hooked scheduling/priority/channel operations. Hardware mixer/DAC, exact sample clock, backpressure scheduling, concurrent navigation speech, A2DP transport, UI, signature acceptance and physical installation remain unverified. Original TTS APIs are not preserved; never install this experiment.'}
    path = ROOT/'evidence/firmware-analysis/native-sbc-pcm-emulation.json'
    path.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'decoded_and_routed_frames': output['decoded_and_routed_frames'],
                      'ring_cases': len(cases), 'guard_cases': len(guards), 'all_passed': True,
                      'device_io': False, 'physical_speaker_verified': False}))


if __name__ == '__main__':
    main()
