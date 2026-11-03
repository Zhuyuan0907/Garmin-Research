#!/usr/bin/env python3
"""Stock dispatch -> compiled queue -> preserving converter -> stock PCM.

Queue work is explicitly invoked. Interleavings pause original ARM execution,
run a second compiled call on another stack, then restore the suspended CPU
context. This is deterministic single-core emulation, not live OS scheduling.
"""
from datetime import datetime, timezone
import ctypes
import hashlib
import json
from pathlib import Path
import struct

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC, UC_ARM_REG_CPSR)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, STUBS
from emulate_native_loader import simulate
from emulate_native_sbc import Reference, INPUT_PAGE, RESULT_PAGE, PAGE_BYTES, STACK, RETURN
from emulate_native_sbc_pcm import CONTEXT, HOST_OUTPUT, RING_BYTES
from emulate_native_voice_convert import ConvertedMachine, reference_pcm, drain
from emulate_native_voice_media import packet, counters
from emulate_avdtp_media import MediaDispatch, HANDLER, LOOKUP, VENEER

BUILD = ROOT/'staging/native-media-queue'
VOICES = ROOT/'staging/native-voice-convert-extension-emulation'


def sha(data): return hashlib.sha256(data).hexdigest()
def require(condition, message):
    if not condition: raise ValueError(message)


class QueueDispatch(MediaDispatch):
    direct_guard = False

    def observe(self, uc, address, size, data):
        # Direct API guards intentionally have no stock temporary handle and
        # can supply an oversized declared length. Keep stock-call observation
        # unchanged; don't impose that observer's valid-input precondition here.
        if self.direct_guard and address == self.callback:
            return
        super().observe(uc, address, size, data)


class QueueSession:
    def __init__(self, stock, voice, queue):
        self.voice, self.queue = voice, queue
        combined = (ROOT/voice['combined_binary']).read_bytes()
        original = (ROOT/voice['original_binary']).read_bytes()
        require(sha(combined) == voice['combined_sha256'], 'Combined voice changed')
        require(sha(original) == voice['original_binary_sha256'], 'Original voice changed')
        original_uc, baseline = simulate(stock, 'original_voice', module_bytes=original,
            module_ram_bytes=voice['original_ram_bytes'], poison_module_ram=True, return_session=True)
        uc, loader = simulate(stock, 'extended_voice', module_bytes=combined,
            module_ram_bytes=voice['combined_ram_bytes'], poison_module_ram=True, return_session=True)
        self.loader = loader
        require(loader['trampolines_verified'] == baseline['trampolines_verified'],
                'Original TTS trampoline contents differ')
        for field in ('version', 'export_table', 'count', 'targets'):
            require(loader['module_export_registration'][-1][field] ==
                    baseline['module_export_registration'][-1][field], 'Original exports differ')
        require(loader['module_export_registration'][-1]['count'] == 40, 'Forty exports required')
        self.original_runtime = bytes(original_uc.mem_read(IMAGE+12, voice['original_ram_bytes']-12))
        require(bytes(uc.mem_read(IMAGE+12, len(self.original_runtime))) == self.original_runtime,
                'Preserving bootstrap changed original RAM')
        self.machine = ConvertedMachine(stock, uc, voice)
        self.uc = uc
        symbols = queue['symbols']
        flat = (ROOT/queue['flat_binary']).read_bytes()
        code = queue['load_base']
        code_bytes = (symbols['__queue_code_end']['address']-code+4095) & ~4095
        uc.mem_map(code, code_bytes)
        uc.mem_write(code, flat)
        state = symbols['__queue_state_start']['address']
        state_bytes = (symbols['__queue_state_end']['address']-state+4095) & ~4095
        uc.mem_map(state, state_bytes)
        uc.mem_write(state, b'\xa5'*state_bytes)
        payload = symbols['__queue_payload_start']['address']
        uc.mem_map(payload, queue['payload_bytes'])
        uc.mem_write(payload, b'\xa5'*queue['payload_bytes'])
        for page in (0x21b000, 0x353000):
            if not any(begin <= page and page+4095 <= end for begin, end, _ in uc.mem_regions()):
                uc.mem_map(page, 4096)
                uc.mem_write(page, stock.read(page, 4096))
        self.visited = set()
        self.pause_address = None
        self.paused = False
        uc.hook_add(UC_HOOK_CODE, self.observe)
        self.dispatch = QueueDispatch(stock, uc, self.address('media_queue_callback'))
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x1f)
        consume = voice['symbols']['voice_extension_media_callback']['address']
        reset = voice['symbols']['voice_convert_reset']['address']
        require(self.invoke('media_queue_init', (consume, reset)) == 0, 'Queue init failed')
        require(bytes(uc.mem_read(payload, queue['payload_bytes'])) == b'\xa5'*queue['payload_bytes'],
                'Queue initialization unnecessarily accessed uninitialized payload')

    def address(self, name): return self.queue['symbols'][name]['address']

    def observe(self, uc, address, size, data):
        if address in (0x21b6cc, 0x21b6dc, HOST_OUTPUT, 0x33f824):
            self.visited.add(address)
        if address == 0x353be4:
            raise ValueError('Queue capacity gate allowed a stock blocking reservation')
        if address == self.pause_address:
            require(not (uc.reg_read(UC_ARM_REG_CPSR) & 0x80),
                    'Attempted synthetic interrupt inside an IRQ critical section')
            self.paused = True
            self.pause_address = None
            uc.emu_stop()

    def control(self):
        return struct.unpack('<9I', self.uc.mem_read(self.address('media_queue_control'), 36))

    def stats(self):
        return struct.unpack('<7IiI', self.uc.mem_read(self.address('media_queue_stats'), 36))

    def invoke(self, name, args=(), fifth=None, stack=STACK):
        address = HANDLER | 1 if name == 'stock_handler' else self.address(name)
        self.uc.reg_write(UC_ARM_REG_SP, stack)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.uc.reg_write(reg, value)
        if fifth is not None: self.uc.mem_write(stack, struct.pack('<I', fifth))
        self.uc.emu_start(address, RETURN, timeout=10000000, count=4000000)
        if self.paused:
            self.paused = False
            return None
        require(self.uc.reg_read(UC_ARM_REG_PC) == RETURN, 'Queue call exceeded execution bounds')
        return ctypes.c_int32(self.uc.reg_read(UC_ARM_REG_R0)).value

    def resume(self, context):
        self.uc.context_restore(context)
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        thumb = bool(self.uc.reg_read(UC_ARM_REG_CPSR) & 0x20)
        self.uc.emu_start(pc | int(thumb), RETURN, timeout=10000000, count=4000000)
        require(self.uc.reg_read(UC_ARM_REG_PC) == RETURN, 'Suspended queue call did not return')
        return ctypes.c_int32(self.uc.reg_read(UC_ARM_REG_R0)).value

    def deliver(self, data, stack=STACK):
        require(0 < len(data) <= PAGE_BYTES, 'Synthetic source exceeds guarded page')
        source = INPUT_PAGE+PAGE_BYTES-len(data)
        self.uc.mem_write(INPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.uc.mem_write(source, data)
        returned = self.invoke('stock_handler', (0x1234, source, len(data)), stack=stack)
        require(not self.dispatch.mutex_held, 'Stock dispatcher retained its mutex')
        require(bytes(self.uc.mem_read(source, len(data))) == data, 'Queue wrote to read-only input')
        self.machine.verify_ring_guards()
        return returned

    def fresh(self):
        require(self.invoke('media_queue_stop') == 0, 'Queue stop failed')
        self.dispatch.configure(slot=2, channel_index=11, context_index=1)
        self.machine.configure(RING_BYTES-64)
        require(self.invoke('media_queue_begin') == 0, 'Fresh queue stream failed')
        require(self.control()[2] == 0, 'New stream retained pending packets')

    def direct(self, event, status, pointer, length, stack=STACK):
        self.dispatch.direct_guard = True
        try:
            return self.invoke('media_queue_callback', (event, status, 0, pointer), length, stack)
        finally:
            self.dispatch.direct_guard = False

    def verify_preserved(self):
        require(bytes(self.uc.mem_read(IMAGE+12, len(self.original_runtime))) == self.original_runtime,
                'Queue/audio processing changed original voice RAM')
        for record in self.loader['trampolines_verified']:
            pointer = struct.unpack('<I', self.uc.mem_read(int(record['storage'], 16), 4))[0]
            target = struct.unpack('<I', self.uc.mem_read(STUBS+record['slot']*12+8, 4))[0]
            require(pointer == int(record['trampoline'], 16) and target == int(record['target_word'], 16),
                    'Queue/audio processing changed original TTS imports/trampolines')
        require({0x21b6cc, 0x21b6dc, HOST_OUTPUT, 0x33f824}.issubset(self.visited),
                'Original IRQ/PCM route was skipped')
        require({HANDLER, LOOKUP, VENEER}.issubset(self.dispatch.visited),
                'Original media dispatch/lookup/veneer was skipped')


def stream(session, reference, tables, frequency, mode):
    session.fresh()
    config = dict(frequency=frequency, mode=mode, subbands=1, blocks=3, allocation=0, bitpool=53)
    if mode == 0: config['bitpool'] = 31
    rate = (16000, 32000, 44100, 48000)[frequency]
    channels = 1 if mode == 0 else 2
    frames = reference.encode(config, frames=40)
    wanted, _ = reference_pcm(reference, frames, rate, channels, tables)
    output, position, packets = [], 0, 0
    while position < len(frames):
        for _ in range(4):
            if position == len(frames): break
            count = min((1, 4, 8, 15)[packets%4], len(frames)-position)
            raw = packet(frames[position:position+count], packets,
                         csrc=True, extension=True, padding=True)
            before = counters(session.machine, session.voice)
            queued_pcm = session.machine.queued()
            require(session.deliver(raw) == 0, 'Stock dispatch rejected valid synthetic channel')
            require(counters(session.machine, session.voice) == before and
                    session.machine.queued() == queued_pcm, 'Bluetooth callback performed decoding/output')
            # Destroy the caller's source and stack handle before consuming.
            session.uc.mem_write(INPUT_PAGE, b'\xcc'*PAGE_BYTES)
            packets += 1; position += count
        while session.control()[2]:
            status = session.invoke('media_queue_step')
            require(status == 0, 'Queued stream was unexpectedly deferred/rejected')
            while session.machine.queued() >= 4096:
                output.append(session.machine.read(3840))
    output.append(drain(session.machine))
    actual = b''.join(output)
    require(actual == wanted, 'Copied queue changed SBC/converter/stock reader samples')
    require(session.invoke('media_queue_step') == 2, 'Empty queue did not return promptly')
    return {'rate': rate, 'channels': channels, 'frames': len(frames), 'packets': packets,
            'source_destroyed_after_enqueue': True, 'callback_did_not_decode_or_output': True,
            'pcm_sha256': sha(actual), 'reference_byte_identical': True, 'passed': True}


def guards_and_interleavings(session, reference, tables):
    config = dict(frequency=2, mode=3, subbands=1, blocks=3, allocation=0, bitpool=53)
    frames = reference.encode(config, frames=4)
    first, _ = reference_pcm(reference, frames[:1], 44100, 2, tables)
    pair, _ = reference_pcm(reference, frames[:2], 44100, 2, tables)
    raw = packet(frames[:1])
    cases = []
    session.fresh()
    before = session.stats()
    for _ in range(4): require(session.deliver(raw) == 0, 'Queue fill failed')
    require(session.control()[2] == 4, 'Queue capacity differs')
    require(session.deliver(raw) == 0, 'Stock dispatch unexpectedly propagates full callback result')
    require(session.control()[2] == 4 and session.stats()[2] == before[2]+1 and
            session.stats()[7] == -23, 'Full queue changed a pending slot or failed to record rejection')
    require(session.machine.queued() == 0, 'Queue fill produced PCM')
    session.invoke('media_queue_stop')
    require(session.control()[2] == 0 and session.stats()[6] == before[6]+4, 'Stop retained pending work')
    cases.append({'case': 'full_queue_drops_newest_and_stop_discards_pending', 'capacity': 4,
                  'stock_dispatch_ignores_full_error': True, 'passed': True})

    session.fresh()
    source = INPUT_PAGE+PAGE_BYTES-len(raw)
    session.uc.mem_write(source, raw)
    for name, event, status, pointer, length in (
        ('wrong_event', 0, 0, source, len(raw)), ('bad_status', 0xf1, 0x131, source, len(raw)),
        ('null_source', 0xf1, 0, 0, len(raw)), ('short_length', 0xf1, 0, source, 12),
        ('oversized_declared_length', 0xf1, 0, INPUT_PAGE, 4097)):
        require(session.direct(event, status, pointer, length) == -20 and session.control()[2] == 0,
                'Invalid input was copied/published: '+name)
        cases.append({'case': name, 'returned': -20, 'no_slot_published': True, 'passed': True})
    # Exactly4096 bytes can be copied; existing RTP validator rejects the
    # extra payload when work is consumed, rather than in the enqueue callback.
    oversized_payload = raw+bytes(4096-len(raw))
    require(session.deliver(oversized_payload) == 0 and session.control()[2] == 1,
            'Maximum-capacity packet was not copied')
    require(session.invoke('media_queue_step') == -17 and session.machine.queued() == 0,
            'Worker failed to report malformed maximum-capacity RTP')
    cases.append({'case': 'maximum_packet_copied_then_validation_error_reported',
                  'packet_bytes': 4096, 'worker_error': -17, 'passed': True})

    session.fresh()
    require(session.deliver(raw) == 0, 'Capacity test enqueue failed')
    # A synthetic fullish stock ring must cause a prompt deferral with no
    # reservation or decode; restoring room allows the same packet to run.
    write, _ = session.machine.offsets()
    session.uc.mem_write(CONTEXT+16, struct.pack('<I', (write+8960)%RING_BYTES))
    previous_media = counters(session.machine, session.voice)
    require(session.invoke('media_queue_step') == 1 and session.control()[2] == 1 and
            counters(session.machine, session.voice) == previous_media, 'Capacity gate blocked/decoded')
    require(session.invoke('media_queue_stop') == 0 and session.control()[2] == 0,
            'Deferred work prevented stopping')
    cases.append({'case': 'pcm_capacity_defer_then_cancel', 'free_bytes': 8960,
                  'stock_blocking_reserve_not_called': True, 'passed': True})

    session.fresh()
    # Pause after producer reservation and IRQ restore, before the copy.
    session.pause_address = session.address('memcpy')
    require(session.deliver(raw) is None, 'Producer copy pause was not reached')
    context = session.uc.context_save()
    require(session.control()[5] == 1, 'Producer slot was not reserved before copying')
    require(session.invoke('media_queue_stop', stack=STACK-0x4000) == 0, 'Mid-copy stop failed')
    require(session.invoke('media_queue_begin', stack=STACK-0x4000) == -25,
            'Begin reused a slot while a producer was still copying')
    require(session.resume(context) == 0 and session.control()[2] == 0 and session.stats()[7] == -24,
            'Stopped producer published its stale copied packet')
    cases.append({'case': 'stop_during_copy_prevents_publication_and_restart',
                  'second_call_on_separate_stack': True, 'passed': True})

    session.fresh()
    session.deliver(raw)
    session.pause_address = session.voice['symbols']['voice_extension_media_callback']['address']
    require(session.invoke('media_queue_step') is None, 'Consumer pause not reached')
    context = session.uc.context_save()
    require(session.invoke('media_queue_step', stack=STACK-0x4000) == -25,
            'Second consumer entered shared decoder')
    require(session.deliver(packet(frames[1:2]), stack=STACK-0x4000) == 0,
            'Producer could not enqueue while consumer was decoding')
    require(session.resume(context) == 0 and session.invoke('media_queue_step') == 0,
            'Consumer/producer interleaving lost queued packets')
    require(drain(session.machine) == pair, 'Interleaved output/order differs from reference')
    cases.append({'case': 'enqueue_during_decode_and_reentrant_consumer_rejected',
                  'fifo_and_pcm_reference_identical': True, 'passed': True})

    session.fresh()
    session.deliver(raw); session.deliver(packet(frames[1:2]))
    session.pause_address = session.voice['symbols']['voice_extension_media_callback']['address']
    require(session.invoke('media_queue_step') is None, 'Cancellation consumer pause not reached')
    context = session.uc.context_save()
    require(session.invoke('media_queue_stop', stack=STACK-0x4000) == 0, 'In-flight stop failed')
    require(session.invoke('media_queue_begin', stack=STACK-0x4000) == -25,
            'Restart reset an in-flight codec')
    require(session.resume(context) == -24 and session.control()[2] == 0,
            'In-flight completion failed to discard later packets')
    require(drain(session.machine) == first, 'Cancellation incorrectly claimed zero in-flight output')
    session.fresh(); session.deliver(raw)
    require(session.invoke('media_queue_step') == 0 and drain(session.machine) == first,
            'Restart retained old SBC/FIR history')
    cases.append({'case': 'stop_during_decode_finishes_selected_packet_then_discards_pending',
                  'in_flight_pcm_can_still_be_submitted': True,
                  'restart_waits_for_quiescence_and_resets_codec_fir': True, 'passed': True})

    session.invoke('media_queue_stop')
    session.pause_address = session.voice['symbols']['voice_convert_reset']['address']
    require(session.invoke('media_queue_begin') is None, 'Reset pause not reached')
    context = session.uc.context_save()
    require(session.invoke('media_queue_stop', stack=STACK-0x4000) == 0, 'Stop during reset failed')
    require(session.resume(context) == -24 and session.control()[4] == 0,
            'Begin re-enabled a stream after a concurrent stop request')
    cases.append({'case': 'stop_during_begin_reset_does_not_reenable_stream', 'passed': True})
    # Restore configured stock dispatch observations for the final preservation
    # check after direct guards and cancellation tests.
    session.fresh(); session.deliver(raw)
    require(session.invoke('media_queue_step') == 0 and drain(session.machine) == first,
            'Final stream recovery failed')
    return cases


def main():
    queue = json.loads((BUILD/'manifest.json').read_text())
    require(sha((ROOT/queue['flat_binary']).read_bytes()) == queue['flat_binary_sha256'],
            'Queue binary changed')
    require(sha((ROOT/queue['elf']).read_bytes()) == queue['elf_sha256'], 'Queue ELF changed')
    for source, digest in queue['source_sha256'].items():
        require(sha((ROOT/source).read_bytes()) == digest, 'Queue source changed: '+source)
    stock, reference = NativeImage(), Reference()
    tables = json.loads((ROOT/'staging/native-pcm-converter/coefficients.json').read_text())['tables']
    cases = []
    paths = sorted(VOICES.glob('*/manifest.json'))
    require(len(paths) == 3, 'Three preserving voice builds required')
    for index, path in enumerate(paths):
        voice = json.loads(path.read_text())
        for source, digest in voice['source_sha256'].items():
            require(sha((ROOT/source).read_bytes()) == digest, 'Voice source changed: '+source)
        session = QueueSession(stock, voice, queue)
        streams = [stream(session, reference, tables, 2, 3),
                   stream(session, reference, tables, 3, 2),
                   stream(session, reference, tables, 0, 0)]
        guards = guards_and_interleavings(session, reference, tables) if index == 0 else []
        session.verify_preserved()
        row = {'voice': voice['voice_package'], 'combined_sha256': voice['combined_sha256'],
               'streams': streams, 'guards_and_interleavings': guards,
               'original_40_exports_imports_trampolines_and_ram_preserved': True,
               'original_irq_save_restore_executed': True, 'queue_work_invoked_explicitly': True,
               'all_passed': True}
        cases.append(row)
        print(json.dumps({'voice_finished': voice['voice_package'], 'frames': sum(s['frames'] for s in streams),
                          'guards_and_interleavings': len(guards), 'all_passed': True}), flush=True)
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'source_sha256': sha(Path(__file__).read_bytes()),
              'queue_manifest': str((BUILD/'manifest.json').relative_to(ROOT)),
              'queue_elf_sha256': queue['elf_sha256'],
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                                   (ROOT/'scripts/emulate_native_voice_convert.py',
                                    ROOT/'scripts/emulate_native_voice_media.py',
                                    ROOT/'scripts/emulate_avdtp_media.py',
                                    ROOT/'scripts/emulate_native_sbc_pcm.py',
                                    ROOT/'staging/native-pcm-converter/coefficients.json')},
              'cases': cases, 'voices': len(cases), 'queue_slots': 4,
              'payload_bytes': 16384, 'packet_capacity_bytes': 4096,
              'conservative_pcm_free_bytes': 8961,
              'decoded_converted_and_routed_frames': sum(s['frames'] for c in cases for s in c['streams']),
              'accepted_stream_packets': sum(s['packets'] for c in cases for s in c['streams']),
              'guard_and_interleaving_cases': sum(len(c['guards_and_interleavings']) for c in cases),
              'all_passed': True, 'device_io': False, 'device_install_candidate': False,
              'queue_callback_returns_without_decoding_or_pcm_output': True,
              'input_and_temporary_handle_not_borrowed': True,
              'work_step_invoked_explicitly': True, 'os_worker_or_event_loop_implemented': False,
              'real_concurrent_irq_scheduling_tested': False,
              'real_output_ring_single_producer_ownership_verified': False,
              'cold_pcm_initialization_verified': False, 'physical_speaker_verified': False,
              'real_sep_registration_verified': False, 'signature_acceptance_verified': False,
              'limitations': 'Standalone compiled ARMv6 queue companion, not merged into the voice package or installed. Exact stock dispatch/lookup/BX veneer enqueues copied synthetic packets; explicit work calls run the existing preserving SBC/FIR and original PCM writer/reader. Three voices retain original40exports/imports/trampolines/RAM. Real IRQ save/restore protects metadata; deterministic interleavings use paused ARM contexts and separate caller stacks, not a real scheduler or concurrent hardware. Capacity deferral assumes an initialized ring with exclusive producer ownership; that ownership, cold initialization, actual channel policy and timing remain unverified. Stop during a selected packet permits that packet to finish submitting PCM, then discards pending work; it is not immediate mute. First init requires quiescence, and module/stack reclamation and OS task/wakeup remain unimplemented. No fragmentation, jitter/loss handling, SEP, UI or hardware playback is supplied.'}
    path = ROOT/'evidence/firmware-analysis/native-media-queue-emulation.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'voices': report['voices'],
                      'frames': report['decoded_converted_and_routed_frames'],
                      'packets': report['accepted_stream_packets'],
                      'guard_and_interleaving_cases': report['guard_and_interleaving_cases'],
                      'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__': main()
