#!/usr/bin/env python3
"""Original reader releases capacity and wakes compiled media work offline.

Uses an explicit synthetic factory instance, not a live registered source.
The IRQ-marker case enters a controlled IRQ mode/stack; real interrupt entry,
exit scheduling, clock, navigation ownership and hardware remain untested.
"""
from datetime import datetime, timezone
import ctypes
import json
from pathlib import Path
import struct
import time

from unicorn.arm_const import (UC_ARM_REG_CPSR, UC_ARM_REG_R9, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_sbc import Reference, OUTPUT_PAGE, PAGE_BYTES, STACK, RETURN
from emulate_native_sbc_pcm import CONTEXT, RING, RING_BYTES
from emulate_native_voice_convert import reference_pcm
from emulate_native_voice_media import packet
from emulate_native_media_queue import VOICES, sha, require
from emulate_native_media_worker import WorkerSession, POST, WAIT, IDLE_ENTRY
from emulate_avdtp_media import HANDLER

BUILD = ROOT/'staging/native-media-consumer'
METHODS = 0x09600020
OTHER_METHODS = 0x09600120
IRQ_STACK = 0x09610000
IRQ_MARKER = 0xf09094
FACTORY = 0x437765
STOCK_READER = 0x484c05
IRQ_POST = 0x2fce38


class ConsumerSession(WorkerSession):
    def __init__(self, stock, voice, consumer):
        self.consumer_visits = set()
        self.max_call_instructions = 0
        super().__init__(stock, voice, consumer)
        for page in (0x437000, 0x35b000, 0x48f000):
            self.uc.mem_map(page, PAGE_BYTES)
            self.uc.mem_write(page, stock.read(page, PAGE_BYTES))
        self.uc.mem_map(METHODS & ~4095, PAGE_BYTES)
        self.uc.mem_map(IRQ_STACK, 16384)
        self.uc.mem_write(IRQ_STACK, b'\xa5'*16384)
        require(self.invoke('media_consumer_init') == 0, 'Consumer init failed')
        self.factory(METHODS, 17)
        self.original_methods = bytes(self.uc.mem_read(METHODS, 68))

    def address(self, name):
        if name == '_factory': return FACTORY
        if name == '_read_method': return self.word(METHODS+20)
        return super().address(name)

    def invoke(self, name, args=(), fifth=None, stack=None):
        stock_calls = {'_kernel_create': 0x358bf9, '_mutex_init': 0x3008a1,
                       '_post': POST, '_wait': WAIT}
        address = HANDLER | 1 if name == 'stock_handler' else stock_calls.get(name)
        if address is None: address = self.address(name)
        if stack is None: stack = self.current() if getattr(self, 'controller', 0) else STACK
        self.uc.reg_write(UC_ARM_REG_SP, stack)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.uc.reg_write(register, value)
        if fifth is not None: self.uc.mem_write(stack, struct.pack('<I', fifth))
        before = self.machine.counter if hasattr(self, 'machine') else 0
        started = time.monotonic()
        # Added per-instruction observers exceed the older harness's 10s wall
        # limit for a full fifteen-frame FIR packet on this Pi. Keep its 6M
        # instruction ceiling; only the emulator host deadline changes to30s.
        self.uc.emu_start(address, RETURN, timeout=30000000, count=6000000)
        instructions = self.machine.counter-before
        self.max_call_instructions = max(self.max_call_instructions, instructions)
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        if pc not in (RETURN, IDLE_ENTRY):
            print(json.dumps({'failed_call': name, 'elapsed_seconds': time.monotonic()-started,
                              'instructions': instructions, 'pc': hex(pc)}), flush=True)
            raise ValueError('Consumer call exceeded execution endpoint bounds: '+hex(pc))
        return ctypes.c_uint32(self.uc.reg_read(UC_ARM_REG_R0)).value

    def observe(self, uc, address, size, data):
        super().observe(uc, address, size, data)
        if address in (FACTORY & ~1, 0x35b4f4, STOCK_READER & ~1,
                       0x33f662, POST, IRQ_POST, 0x2fcea4, 0x2fceec):
            self.consumer_visits.add(address)

    def consumer_state(self):
        return struct.unpack('<6Ii', self.uc.mem_read(self.address('media_consumer_state'), 28))

    def factory(self, methods, kind):
        self.uc.mem_write(methods-32, b'\xa5'*(32+68+32))
        require(self.invoke('_factory', (methods, kind)) == 0, 'Original factory failed')
        self.verify_method_guards(methods)

    def verify_method_guards(self, methods=METHODS):
        require(bytes(self.uc.mem_read(methods-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(methods+68, 32)) == b'\xa5'*32,
                'Factory/attachment changed method descriptor guards')

    def attach(self):
        require(self.invoke('media_consumer_attach', (METHODS, 68)) == 0, 'Consumer attach failed')
        expected = bytearray(self.original_methods)
        struct.pack_into('<I', expected, 20, self.address('media_consumer_read'))
        require(bytes(self.uc.mem_read(METHODS, 68)) == expected,
                'Attachment changed a method other than the reader')
        self.verify_method_guards()

    def detach(self):
        require(self.invoke('media_consumer_detach') == 0, 'Consumer detach failed')
        require(bytes(self.uc.mem_read(METHODS, 68)) == self.original_methods,
                'Detach did not restore exact original descriptor')
        self.verify_method_guards()

    def seed_ring(self, free=8958, start=RING_BYTES-32):
        """Only initial PCM fixture is synthetic; all capacity release is stock reading."""
        count = RING_BYTES-free
        require(0 < count < RING_BYTES, 'Invalid seeded occupancy')
        data = bytes((index*37+19) & 255 for index in range(count))
        first = min(count, RING_BYTES-start)
        self.uc.mem_write(RING+start, data[:first])
        self.uc.mem_write(RING, data[first:])
        self.put(CONTEXT+12, (start+count)%RING_BYTES)
        self.put(CONTEXT+16, start)
        return data

    def read(self, capacity, stack=None):
        require(0 < capacity <= PAGE_BYTES-32, 'Read exceeds guarded output')
        destination = OUTPUT_PAGE+PAGE_BYTES-capacity
        self.uc.mem_write(OUTPUT_PAGE, b'\xa5'*PAGE_BYTES)
        count = self.invoke('_read_method', (0, destination, capacity), stack=stack)
        require(count <= capacity, 'Wrapped reader changed original count semantics')
        require(bytes(self.uc.mem_read(destination-32, 32)) == b'\xa5'*32,
                'Reader changed leading output canary')
        require(bytes(self.uc.mem_read(destination+count, capacity-count)) == b'\xa5'*(capacity-count),
                'Reader wrote beyond its returned count')
        self.machine.verify_ring_guards()
        return bytes(self.uc.mem_read(destination, count))

    def drain(self):
        chunks = []
        while self.machine.queued():
            chunk = self.read(3840)
            require(chunk, 'Attached reader failed to advance occupied ring')
            chunks.append(chunk)
        return b''.join(chunks)


def signed(result): return ctypes.c_int32(result).value


def attachment_guards(session):
    cases = []
    for name, args, error in (
        ('null_descriptor', (0, 68), -20),
        ('unaligned_descriptor', (METHODS+1, 68), -20),
        ('short_descriptor', (METHODS, 67), -20)):
        require(signed(session.invoke('media_consumer_attach', args)) == error, name)
        require(bytes(session.uc.mem_read(METHODS, 68)) == session.original_methods,
                'Rejected attach changed original descriptor')
        cases.append({'case': name, 'error': error, 'passed': True})
    session.factory(OTHER_METHODS, 1)
    require(signed(session.invoke('media_consumer_attach', (OTHER_METHODS, 68))) == -27,
            'Wrong factory kind accepted')
    cases.append({'case': 'wrong_source_kind', 'error': -27, 'passed': True})
    require(signed(session.invoke('media_consumer_detach')) == -28, 'Missing attachment accepted')
    cases.append({'case': 'detach_without_attachment', 'error': -28, 'passed': True})
    session.attach()
    require(signed(session.invoke('media_consumer_attach', (METHODS, 68))) == -25,
            'Duplicate attachment accepted')
    cases.append({'case': 'duplicate_attachment', 'error': -25, 'passed': True})
    session.put(METHODS+20, STOCK_READER)
    require(signed(session.invoke('media_consumer_detach')) == -29 and
            session.word(METHODS+20) == STOCK_READER, 'Detach clobbered provider replacement')
    cases.append({'case': 'provider_replaced_reader', 'error': -29, 'passed': True})
    session.put(METHODS+20, session.address('media_consumer_read'))
    session.detach(); session.attach()
    cases.append({'case': 'exact_restore_then_reattach', 'passed': True})
    return cases


def capacity_stream(session, reference, tables, frequency, mode, frame_count, irq=False):
    session.fresh()
    config = dict(frequency=frequency, mode=mode, subbands=1, blocks=3,
                  allocation=0, bitpool=31 if mode == 0 else 53)
    frames = reference.encode(config, frames=frame_count)
    rate, channels = (16000, 32000, 44100, 48000)[frequency], 1 if mode == 0 else 2
    wanted, _ = reference_pcm(reference, frames, rate, channels, tables)
    seed = session.seed_ring()
    handled, deferred = session.state()[3:5]
    notifications = session.consumer_state()[3]
    require(session.deliver(packet(frames)) == 0, 'Stock packet delivery failed')
    session.park_controller()
    require(session.control()[2] == 1 and session.state()[4] == deferred+1 and
            session.byte(session.worker_tcb+22) == 2, 'Capacity-starved worker did not block')
    session.activate_controller()
    chunks = [session.read(2)]
    require(chunks[0] == seed[:2] and session.consumer_state()[3] == notifications and
            session.byte(session.worker_tcb+22) == 2, 'Below-threshold read prematurely woke worker')
    before_read = session.machine.offsets()[1]
    if irq:
        session.put(IRQ_MARKER, 1)
        session.uc.reg_write(UC_ARM_REG_CPSR, 0x92)
        session.uc.reg_write(UC_ARM_REG_R9, 0x19762483)
        chunks.append(session.read(2, stack=IRQ_STACK+16384))
        require(session.uc.reg_read(UC_ARM_REG_CPSR) & 0xff == 0x92,
                'IRQ-marker reader changed CPU mode/mask')
        require(session.uc.reg_read(UC_ARM_REG_R9) == 0x19762483,
                'IRQ alternate post changed callee-saved SB')
        require({IRQ_POST, 0x2fcea4, 0x2fceec}.issubset(session.consumer_visits),
                'Original IRQ-marker post branch was skipped')
        require(session.state()[3] == handled and session.current() == session.controller,
                'Lower-priority worker executed inside controlled IRQ read')
        session.put(IRQ_MARKER, 0)
        session.uc.reg_write(UC_ARM_REG_CPSR, 0x1f)
    else:
        chunks.append(session.read(2))
    require(chunks[1] == seed[2:4] and session.machine.offsets()[1] == (before_read+2)%RING_BYTES,
            'Actual stock reader did not release requested capacity')
    require(session.consumer_state()[3] == notifications+1 and
            session.byte(session.worker_tcb+22) == 1 and session.word(session.worker_tcb+4) == 1,
            'Reader did not automatically post original worker capacity event')
    session.park_controller(); session.activate_controller()
    require(session.control()[2] == 0 and session.state()[3] == handled+1 and
            session.byte(session.worker_tcb+22) == 2, 'Capacity wake failed to process pending packet')
    chunks.append(session.drain())
    actual = b''.join(chunks)
    require(actual == seed+wanted, 'Reader notification changed seeded or decoded PCM')
    require(session.consumer_state()[3] == notifications+1, 'Empty queue caused extra notification')
    session.verify_worker()
    return {'rate': rate, 'channels': channels, 'frames': frame_count, 'packets': 1,
            'initial_free_bytes': 8958, 'after_first_read_free_bytes': 8960,
            'after_second_read_free_bytes': 8962, 'automatic_notifications': 1,
            'stock_reader_releases_capacity': True, 'no_new_packet_required_to_resume': True,
            'reference_byte_identical': True, 'pcm_sha256': sha(wanted),
            'seed_plus_pcm_sha256': sha(actual), 'initial_ring_pcm_fixture_synthetic': True,
            'irq_marker_branch': irq, 'actual_interrupt_entry_exit_verified': False,
            'passed': True}


def notification_guards(session, reference):
    cases = []
    config = dict(frequency=0, mode=0, subbands=1, blocks=3, allocation=0, bitpool=31)
    frame = reference.encode(config, frames=1)[0]
    session.fresh(); seed = session.seed_ring(free=RING_BYTES-64)
    before = session.consumer_state()[3]
    require(session.read(8) == seed[:8] and session.consumer_state()[3] == before,
            'Empty queue generated a capacity event')
    cases.append({'case': 'occupied_pcm_but_no_pending_packet_no_notify', 'passed': True})
    session.fresh(); session.seed_ring(free=10000); session.deliver(packet([frame]))
    session.uc.mem_write(CONTEXT+4, b'\x00')
    before = session.consumer_state()[3]
    require(session.read(8) == b'' and session.consumer_state()[3] == before,
            'Inactive reader notified without releasing PCM')
    cases.append({'case': 'inactive_original_reader_zero_count_no_notify', 'passed': True})
    session.fresh(); seed = session.seed_ring(); session.deliver(packet([frame]))
    session.park_controller(); session.activate_controller()
    session.detach(); before = session.consumer_state()[3]
    require(session.read(4) == seed[:4] and session.consumer_state()[3] == before and
            session.byte(session.worker_tcb+22) == 2, 'Detached reader still notified worker')
    session.attach()
    require(session.read(2) == seed[4:6] and session.consumer_state()[3] == before+1,
            'Reattached read did not resume retained packet')
    session.park_controller(); session.activate_controller(); session.drain()
    cases.append({'case': 'detach_disables_feedback_reattach_next_read_resumes', 'passed': True})
    session.fresh(); seed = session.seed_ring(); session.deliver(packet([frame]))
    require(session.invoke('media_worker_shutdown') == 0, 'Worker shutdown failed')
    session.park_controller(); session.activate_controller()
    before = session.consumer_state()[3]
    require(session.read(4) == seed[:4] and session.consumer_state()[3] == before and
            session.byte(session.worker_tcb+22) == 0x80, 'Reader posted to exited worker')
    session.detach()
    cases.append({'case': 'shutdown_discards_pending_reader_does_not_wake_dead_task', 'passed': True})
    return cases


def main():
    consumer = json.loads((BUILD/'manifest.json').read_text())
    for path, digest in consumer['source_sha256'].items():
        require(sha((ROOT/path).read_bytes()) == digest, 'Consumer source changed: '+path)
    for field in ('elf', 'flat_binary'):
        require(sha((ROOT/consumer[field]).read_bytes()) == consumer[field+'_sha256'], 'Consumer artifact changed')
    stock, reference = NativeImage(), Reference()
    tables = json.loads((ROOT/'staging/native-pcm-converter/coefficients.json').read_text())['tables']
    paths = sorted(VOICES.glob('*/manifest.json'))
    require(len(paths) == 3, 'Three preserving voice modules required')
    rows = []
    for index, path in enumerate(paths):
        voice = json.loads(path.read_text())
        for source, digest in voice['source_sha256'].items():
            require(sha((ROOT/source).read_bytes()) == digest, 'Voice source changed: '+source)
        session = ConsumerSession(stock, voice, consumer)
        guards = attachment_guards(session) if index == 0 else []
        if index: session.attach()
        streams = [capacity_stream(session, reference, tables, 0, 0, 1),
                   capacity_stream(session, reference, tables, 2, 3, 15),
                   capacity_stream(session, reference, tables, 3, 2, 8)]
        irq_case = capacity_stream(session, reference, tables, 0, 0, 1, irq=True) if index == 0 else None
        if index == 0: guards += notification_guards(session, reference)
        else: session.detach()
        session.verify_worker()
        require({FACTORY & ~1, 0x35b4f4, STOCK_READER & ~1, 0x33f662, POST}
                .issubset(session.consumer_visits), 'Stock factory/clear/reader/post route skipped')
        rows.append({'voice': voice['voice_package'], 'streams': streams, 'irq_control': irq_case,
                     'controls': guards, 'consumer_state': list(session.consumer_state()),
                     'max_call_instructions': session.max_call_instructions,
                     'stock_paths_visited': [hex(a) for a in sorted(session.consumer_visits)],
                     'original40_exports_imports_trampolines_and_ram_preserved': True,
                     'all_passed': True})
        print(json.dumps({'voice_finished': voice['voice_package'], 'stream_frames': 24,
                          'controls': len(guards), 'irq_control': bool(irq_case), 'all_passed': True}), flush=True)
    dependencies = ('scripts/emulate_native_media_worker.py', 'scripts/emulate_native_media_queue.py',
                    'scripts/emulate_native_voice_convert.py', 'scripts/emulate_native_sbc_pcm.py',
                    'staging/native-pcm-converter/coefficients.json')
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'source_sha256': sha(Path(__file__).read_bytes()),
              'consumer_elf_sha256': consumer['elf_sha256'],
              'consumer_manifest': str((BUILD/'manifest.json').relative_to(ROOT)),
              'dependency_sha256': {p: sha((ROOT/p).read_bytes()) for p in dependencies},
              'cases': rows, 'voices': len(rows), 'decoded_converted_stream_frames': 72,
              'emulator_call_instruction_limit': 6000000,
              'emulator_call_host_timeout_seconds': 30,
              'accepted_stream_packets': 9, 'additional_control_cases': 13,
              'all_passed': True, 'explicit_factory_instance_capacity_feedback_implemented': True,
              'stock_factory_and_memzero_unhooked': True,
              'original_reader_capacity_release_and_auto_event_post_executed': True,
              'interrupt_marker_post_branch_executed': True,
              'irq_mode_mask_and_callee_saved_sb_preserved': True,
              'actual_interrupt_entry_exit_and_preemption_verified': False,
              'live_registered_audio_instance_wiring_verified': False,
              'cold_pcm_init_and_navigation_output_ownership_verified': False,
              'safe_module_unload_verified': False, 'native_on_device_verified': False,
              'device_io': False, 'device_install_candidate': False,
              'limitations': 'Offline companion attaches only to an explicitly created synthetic kind17 factory descriptor and replaces offset20. Factory and memzero, reader and capacity-event post run original instructions. Ring fixture is seeded once; actual reader advances indices and compiled wrapper automatically wakes blocked original-kernel worker without a new packet or explicit test capacity notification. IRQ case sets synthetic marker/mode/banked stack with lower-priority worker, executes the exact ARM alternate branch and restores synthetic normal mode; no true interrupt entry/exit scheduler, higher-priority IRQ preemption or clock. Prior endpoint/ring init/kernel construction/mutex/audio policy controls remain. Navigation ownership, cold init, SEP/UI/phone traffic, physical output/performance, actual registration selecting this wrapped instance, package acceptance, in-flight callback quiescence and safe unload remain unverified. Not merged into DLLIMG/VPM or installed.'}
    path = ROOT/'evidence/firmware-analysis/native-media-consumer-emulation.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'voices': 3, 'stream_frames': 72, 'packets': 9,
                      'controls': 13, 'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__': main()
