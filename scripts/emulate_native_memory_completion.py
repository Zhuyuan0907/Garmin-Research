#!/usr/bin/env python3
"""Stock finite-memory source FIFO, mixer cleanup and notice dispatch, offline.

The original mixer actor selects/reads/stops/cleans sources; stock source-list
deletion and audio notice translation also execute. Transport/wait, hardware
activation and handles remain controlled. The global main dispatcher is a
capture boundary, not a registered App listener. No device I/O occurs.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace
from emulate_native_memory_audio import (MemoryAudio, POOL10, POOL11,
                                        INSTANCE_COUNT, INSTANCE_BYTES)
from emulate_native_audio_registration import (CHANNELS, CHANNEL_STRIDE,
                                              MIX_DESCRIPTOR, MIX_BUFFER, SCRATCH,
                                              require, sha)
from emulate_native_audio_messages import WAIT
from emulate_native_sbc import OUTPUT_PAGE, PAGE_BYTES, STACK, RETURN

NOTICE_QUEUE = 0x0000b00d
NOTICE_DISPATCH = 0x455b64
MAIN_DISPATCH = 0x330b48
REMOVE_SOURCE = 0x277674
DELETE_AFTER_NOTICE = 0x2775e6
DELETE_STACK = 0x0990d000


class CompletionAudio(MemoryAudio):
    def __init__(self, stock, companion):
        self.notice_packets = []
        self.main_requests = []
        self.submitted = []
        super().__init__(stock, companion)
        # Execute the real notification wrappers up to this broad application
        # event hub. Do not pretend its subsystem/App handlers are registered.
        self.uc.mem_map(MAIN_DISPATCH & ~4095, PAGE_BYTES)
        self.uc.mem_write(MAIN_DISPATCH & ~4095, stock.read(MAIN_DISPATCH & ~4095, PAGE_BYTES))
        self.uc.mem_write(MAIN_DISPATCH, bytes.fromhex('7047'))
        self.control_hooks[MAIN_DISPATCH] = 'main_event_dispatch_capture'
        self.symbols.update({'stock_notice_dispatch': {'address': NOTICE_DISPATCH | 1},
                             'source_remove': {'address': REMOVE_SOURCE | 1}})
        self.put(0xf2936c, NOTICE_QUEUE)

    def call(self, name, args=(), stack_args=()):
        # A suspended actor has a live frame on STACK. Controller calls must
        # use the separate inherited external stack, preserving that frame.
        if getattr(self, 'worker_context', None) is not None:
            require(not stack_args, 'Paused-actor controller call needs explicit stack-argument support')
            return self.external(name, args)
        return super().call(name, args, stack_args)

    def observe(self, uc, address, size, data):
        # Capture before inherited hooks replace r0 with their success result.
        args = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                        UC_ARM_REG_R2, UC_ARM_REG_R3)]
        if address == 0x37bce4 and args[0] == NOTICE_QUEUE:
            packet = bytes(uc.mem_read(args[1], 20))
            self.notice_packets.append({'channel': packet[0], 'event': packet[1],
                                        'packet_owner': struct.unpack_from('<I', packet, 4)[0],
                                        'bytes': packet})
        elif address == MAIN_DISPATCH:
            require(args[0] == 0x246, 'Unexpected broad main event captured')
            owner, flags, channel = struct.unpack('<3I', uc.mem_read(args[1], 12))
            self.main_requests.append({'main_event': args[0], 'owner': owner,
                                       'flags': flags, 'channel': channel})
        super().observe(uc, address, size, data)

    def enqueue(self, pointer, payload, owner, mask=0x7f):
        self.allowed_channels.add(self.channel)
        params = bytearray(0x20c)
        struct.pack_into('<5I', params, 0, 1, 16000, 16, pointer, len(payload))
        self.uc.mem_write(OUTPUT_PAGE, bytes(params))
        metadata = OUTPUT_PAGE+0x400
        self.uc.mem_write(metadata, struct.pack('<3I', 0, owner, mask))
        before = self.next_handle
        require(self.call('register', (self.channel, 10, 12, OUTPUT_PAGE),
                          (len(params), metadata, 1)) == 0, 'Original memory enqueue failed')
        require(self.next_handle == before+1, 'Enqueue did not allocate exactly one list node')
        handle = 0xd0000000+before
        entry = self.handles[handle]
        require(self.word(entry['pointer']+4) == owner and self.word(entry['pointer']+8) == mask,
                'Original source queue did not copy owner/notice-mask metadata')
        item = {'handle': handle, 'pointer': pointer, 'payload': payload,
                'owner': owner, 'mask': mask}
        self.submitted.append(item)
        return item

    def select_current(self):
        require(self.call('queue_start', (self.record+0x1a8,)) == 0, 'Original queue start failed')
        before = len(self.factory_results)
        require(self.run_worker(((13, 0),)) == WAIT, 'Original selector actor did not reach wait')
        require(len(self.factory_results) == before+1 and self.factory_results[-1] == 0 and
                self.byte(self.record+2) == 1 and self.word(self.record+0x108) == 0x48edf9,
                'Original actor did not prepare the memory source')
        require(struct.unpack('<HHII', self.uc.mem_read(self.record+0x138, 12)) == (1, 16, 2, 16000),
                'Original selected memory format differs')
        return {'record': self.record, 'kind': 10, 'channel': self.channel,
                'instance': self.word(self.record+0xf0)}

    def activate_fixture(self):
        # This small ring/scratch and activation are explicit hardware fixtures.
        # Real message14 would allocate/configure hardware buffers; it is absent.
        self.setup_mixer()
        self.uc.mem_write(self.mixer+0x84, b'\x01')
        self.uc.mem_write(self.mixer+0x7e, b'\x00')

    def actor_pull(self):
        before = self.word(MIX_DESCRIPTOR+16)
        self.uc.mem_write(SCRATCH-32, b'\xa5'*(32+256))
        require(self.run_worker(((18, 0),)) == WAIT, 'Original read actor did not reach wait')
        after = self.word(MIX_DESCRIPTOR+16)
        count = (after-before)%2048
        require(count <= 256, 'Original actor read exceeded fixture capacity')
        first = min(count, MIX_BUFFER+2048-before)
        output = bytes(self.uc.mem_read(before, first))
        if first < count: output += bytes(self.uc.mem_read(MIX_BUFFER, count-first))
        require(bytes(self.uc.mem_read(SCRATCH-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(SCRATCH+count, 256-count)) == b'\xa5'*(256-count),
                'Original actor crossed scratch capacity/guards')
        require(bytes(self.uc.mem_read(MIX_BUFFER-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(MIX_BUFFER+2048, 32)) == b'\xa5'*32,
                'Original actor crossed mixer-buffer guards')
        return output

    def stop_cleanup(self):
        start = len(self.notice_packets)
        require(self.run_worker(((15, 0), (19, 0))) == WAIT,
                'Original stop/cleanup actor did not reach wait')
        require(self.byte(self.mixer+0x84) == 0 and self.byte(self.record+2) == 0 and
                bytes(self.uc.mem_read(self.record+0xf4, 68)) == bytes(68),
                'Original stop/cleanup left a live reader or prepared source')
        return self.notice_packets[start:]

    def remove_first(self):
        start = len(self.notice_packets)
        require(self.call('source_remove', (self.record+0x1a8, 0)) == 0,
                'Original source-list remove failed')
        return self.notice_packets[start:]

    def deliver(self, packets, separate_stack=False):
        start = len(self.main_requests)
        for packet in packets:
            self.uc.mem_write(OUTPUT_PAGE, packet['bytes'])
            if separate_stack:
                self.external('stock_notice_dispatch', (OUTPUT_PAGE,))
            else:
                self.call('stock_notice_dispatch', (OUTPUT_PAGE,))
        return self.main_requests[start:]

    def verify(self):
        # Unlike the parent memory-source test, this test actually executes
        # the actor with synthetic transport and Python context restoration.
        current = bytes(self.uc.mem_read(CHANNELS, 18*CHANNEL_STRIDE))
        baseline = bytearray(self.original_channel_baseline)
        for channel in self.allowed_channels:
            lo, hi = channel*CHANNEL_STRIDE, (channel+1)*CHANNEL_STRIDE
            baseline[lo:hi] = current[lo:hi]
        self.channel_baseline = bytes(baseline)
        self.verify_controls()
        require(bytes(self.uc.mem_read(POOL10-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(POOL11+INSTANCE_COUNT*INSTANCE_BYTES, 4)) == b'\xa5'*4,
                'Source pool crossed guards')
        for pointer, payload in self.pcm_fixtures.items():
            require(bytes(self.uc.mem_read(pointer, len(payload))) == payload and
                    bytes(self.uc.mem_read(pointer-32, 32)) == b'\xa5'*32,
                    'Original lifecycle mutated caller PCM or leading guard')


def queued_sequence(stock, companion):
    m = CompletionAudio(stock, companion)
    initial_tts = m.tts_snapshot()
    lengths = (666, 1024, 512, 384, 128, 768)
    items = []
    for j, length in enumerate(lengths):
        payload = struct.pack('<'+'h'*(length//2),
                              *[((j*1201+k*77)%60001)-30000 for k in range(length//2)])
        pointer = m.pcm_page(j, payload)
        items.append(m.enqueue(pointer, payload, 0xa100+j))
    require(m.half(m.record+0x1c0) == 6 and not m.factory_results and
            all(m.byte(POOL10+j*INSTANCE_BYTES+12) == 0 for j in range(5)),
            'Queued nodes consumed provider slots before stock selection')
    outputs, instances, event_sequences = [], [], []
    for j, item in enumerate(items):
        source = m.select_current(); instances.append(source['instance'])
        require(source['instance'] == 0 and m.word(m.object_for(source)) == item['pointer'],
                'Serialized queued sources did not reuse the released original slot')
        m.activate_fixture()
        result = b''.join(m.actor_pull() for _ in range((len(item['payload'])+255)//256))
        require(result == item['payload'], 'Original queued actor PCM differs from reference')
        require(m.actor_pull() == b'' and m.byte(m.mixer+0x7e) == 1 and
                m.byte(pool_marker(source)) == 1 and m.byte(m.record+2) == 1,
                'EOF unexpectedly released the prepared source')
        require(m.half(m.record+0x1c0) == len(items)-j and
                not m.handles[item['handle']]['freed'], 'EOF deleted a queued node')
        cleanup = m.stop_cleanup()
        require([p['event'] for p in cleanup] == [26, 25, 22] and
                m.byte(pool_marker(source)) == 0 and
                not m.handles[item['handle']]['freed'], 'Cleanup/source-list lifetimes conflated')
        deletion = m.remove_first()
        require([p['event'] for p in deletion] == [23] and m.handles[item['handle']]['freed'],
                'Original source deletion did not release its node')
        reports = cleanup+deletion
        require(all(p['packet_owner'] == item['owner'] for p in reports), 'Notice packet owner differs')
        translated = m.deliver(reports)
        require([r['flags'] for r in translated] == [64, 32, 2, 8] and
                all(r['owner'] == item['owner'] and r['channel'] == m.channel for r in translated),
                'Original notice dispatcher translated unexpected owner/event fields')
        outputs.append(result); event_sequences.append([p['event'] for p in reports])
    require(m.half(m.record+0x1c0) == 0 and m.word(m.record+0x1ac) == 0xffff and
            m.tts_snapshot() == initial_tts and m.visits[0x21c62a] == 0,
            'Final source queue or global TTS state differs')
    required = {0x2fa0dc, 0x2fa294, 0x2fa572, 0x2fa316, 0x2f9f1c, 0x437a90,
                0x277674, 0x277596, 0x455c86, 0x455d1e, NOTICE_DISPATCH,
                0x36b22e, 0x36b24e, 0x36b28a, 0x36b29a, 0x1fa4a6, MAIN_DISPATCH}
    require(required.issubset(m.registration_visits), 'Original lifecycle skipped required paths')
    m.verify()
    actual = b''.join(outputs)
    return {'name': 'six_source_nodes_serialized_through_original_actor',
            'queued_blocks': len(items), 'pcm_bytes': len(actual), 'pcm_sha256': sha(actual),
            'reference_byte_identical': True, 'source_instances': instances,
            'provider_slots_not_consumed_at_enqueue': True, 'eof_leaves_source_and_queue_live': True,
            'actor_stop15_cleanup19_then_original_remove': True,
            'cleanup_notice_sequences': event_sequences, 'translated_flags_each': [64, 32, 2, 8],
            'notice_translation_original_up_to_controlled_main_dispatch': True,
            'all_source_nodes_released_at_end': True, 'tts_context_and_ring_unchanged': True,
            'original_paths_visited': [hex(p) for p in sorted(required)], 'passed': True}


def pool_marker(source):
    return POOL10+source['instance']*INSTANCE_BYTES+12


def delete_live_case(stock, companion):
    m = CompletionAudio(stock, companion)
    pcm = struct.pack('<256h', *range(-128, 128))
    item = m.enqueue(m.pcm_page(0, pcm), pcm, 0xaa01)
    source = m.select_current()
    m.activate_fixture()
    packets = m.remove_first()
    translated = m.deliver(packets)
    require([p['event'] for p in packets] == [23] and translated[0]['flags'] == 8 and
            m.handles[item['handle']]['freed'] and m.half(m.record+0x1c0) == 0,
            'Live-node deletion control did not execute')
    require(m.byte(m.record+2) == 1 and m.byte(pool_marker(source)) == 1 and
            m.source_read(source, 1000) == pcm, 'Deleting source node stopped/invalidated reader')
    m.stop_cleanup(); m.verify()
    return {'name': 'delete_notice23_does_not_imply_reader_cleanup',
            'source_node_freed_before_cleanup': True,
            'prepared_reader_and_pool_slot_remain_live': True,
            'original_reader_still_returns_borrowed_pcm': True,
            'translated_flag8_not_a_standalone_recycle_signal': True, 'passed': True}


def delayed_notice_case(stock, companion):
    m = CompletionAudio(stock, companion)
    pcm = b'\x12\x34'*128
    a = m.enqueue(m.pcm_page(0, pcm), pcm, 0xaa01)
    b = m.enqueue(m.pcm_page(1, pcm), pcm, 0xaa02)
    m.select_current()
    m.activate_fixture()
    notices = m.stop_cleanup()+m.remove_first()
    m.select_current()
    require(m.word(m.record+0x1b0) == b['owner'] and m.handles[a['handle']]['freed'],
            'Source metadata did not advance before delayed notice delivery')
    translated = m.deliver(notices)
    require([p['packet_owner'] for p in notices] == [a['owner']]*4 and
            [r['owner'] for r in translated] == [a['owner'], a['owner'], b['owner'], b['owner']],
            'Original notification wrappers unexpectedly preserved all packet owners')
    m.stop_cleanup(); m.remove_first(); m.verify()
    return {'name': 'delayed_notices_use_different_owner_fields',
            'notice_packet_owner': a['owner'], 'new_current_channel_owner': b['owner'],
            'source_events': [26, 25, 22, 23], 'translated_flags': [64, 32, 2, 8],
            'translated_owners': [a['owner'], a['owner'], b['owner'], b['owner']],
            'events22_23_reload_current_channel_metadata': True,
            'events25_26_use_notice_packet_owner': True,
            'per_block_generation_cannot_be_assumed_from_translated_owner': True,
            'transport_delay_is_test_control_not_actual_scheduling': True, 'passed': True}


def filtered_notice_case(stock, companion):
    cases = []
    for mask, expected in ((0, []), (6, [22, 23])):
        m = CompletionAudio(stock, companion)
        pcm = b'\x4a\x39'*64
        m.enqueue(m.pcm_page(0, pcm), pcm, 0xaa01, mask=mask)
        source = m.select_current()
        m.activate_fixture()
        m.stop_cleanup(); m.remove_first()
        require([p['event'] for p in m.notice_packets] == expected and
                m.byte(pool_marker(source)) == 0 and m.half(m.record+0x1c0) == 0,
                'Notice mask prevented lifecycle or emitted wrong packets')
        require([e['event'] for e in m.error_notifications] == [26, 25, 22, 23],
                'Original reporting calls absent in filtered control')
        translated = m.deliver(m.notice_packets)
        require([r['flags'] for r in translated] == ([2, 8] if mask else []),
                'Selective notice filter translated wrong main flags')
        m.verify()
        cases.append({'report_mask': mask, 'queued_events': expected,
                      'translated_flags': [r['flags'] for r in translated]})
    return {'name': 'notice_mask_filters_without_blocking_source_cleanup',
            'original_reporting_calls_each': [26, 25, 22, 23], 'cases': cases,
            'source_cleaned_and_node_deleted_each': True,
            'source_report_mask6_selects_events22_23': True,
            'source_report_bits_differ_from_main_translated_flags': True,
            'passed': True}


def early_notice_case(stock, companion):
    m = CompletionAudio(stock, companion)
    pcm = b'\x2a\x5a'*64
    item = m.enqueue(m.pcm_page(0, pcm), pcm, 0xaa01)
    m.select_current()
    m.activate_fixture()
    m.stop_cleanup()
    # Stop the original remove caller immediately AFTER enqueueing notice23,
    # BEFORE unlocking/releasing its node and updating queue count/current.
    m.stop_address = DELETE_AFTER_NOTICE
    m.uc.reg_write(UC_ARM_REG_R0, m.record+0x1a8)
    m.uc.reg_write(UC_ARM_REG_R1, 0)
    m.uc.reg_write(UC_ARM_REG_SP, DELETE_STACK)
    m.uc.reg_write(UC_ARM_REG_LR, RETURN)
    m.uc.emu_start(REMOVE_SOURCE | 1, RETURN, timeout=1000000, count=100000)
    require(m.uc.reg_read(UC_ARM_REG_PC) == DELETE_AFTER_NOTICE, 'Remove missed early-notice boundary')
    paused = m.uc.context_save()
    pending = m.notice_packets[-1]
    require(pending['event'] == 23 and not m.handles[item['handle']]['freed'] and
            m.handles[item['handle']]['locks'] == 1 and m.half(m.record+0x1c0) == 1,
            'Notice23 not emitted before node release/count update')
    translated = m.deliver([pending], separate_stack=True)
    require(translated[0]['flags'] == 8 and not m.handles[item['handle']]['freed'] and
            m.half(m.record+0x1c0) == 1, 'Delivery control completed the paused source removal')
    m.stop_address = None
    m.uc.context_restore(paused)
    m.uc.emu_start(DELETE_AFTER_NOTICE | 1, RETURN, timeout=1000000, count=100000)
    require(m.uc.reg_read(UC_ARM_REG_PC) == RETURN and m.handles[item['handle']]['freed'] and
            m.half(m.record+0x1c0) == 0, 'Original source remove did not complete after resume')
    m.verify()
    return {'name': 'notice23_precedes_node_release_and_queue_count_update',
            'paused_original_caller': hex(DELETE_AFTER_NOTICE),
            'notice_delivered_while_remove_call_still_in_flight': True,
            'node_still_locked_not_freed_and_count1_at_delivery': True,
            'original_remove_resumed_and_released_node': True,
            'python_context_restore_and_separate_stack_control': True,
            'actual_os_preemption_or_callback_quiescence_verified': False, 'passed': True}


def main():
    stock = NativeImage()
    manifest = ROOT/'staging/native-media-consumer/manifest.json'
    companion = json.loads(manifest.read_text())
    for path, digest in companion['source_sha256'].items():
        require(sha((ROOT/path).read_bytes()) == digest, 'Companion source changed: '+path)
    for key in ('elf', 'flat_binary'):
        require(sha((ROOT/companion[key]).read_bytes()) == companion[key+'_sha256'],
                'Companion artifact changed')
    routes = [queued_sequence(stock, companion)]
    controls = [delete_live_case(stock, companion), delayed_notice_case(stock, companion),
                filtered_notice_case(stock, companion), early_notice_case(stock, companion)]
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'script_sha256': sha(Path(__file__).read_bytes()),
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                                   (ROOT/'scripts/emulate_native_memory_audio.py',
                                    ROOT/'scripts/emulate_native_pcm_initialization.py',
                                    ROOT/'scripts/emulate_native_audio_messages.py',
                                    ROOT/'scripts/emulate_native_audio_registration.py',
                                    ROOT/'scripts/emulate_native_pcm_flow_control.py',
                                    ROOT/'scripts/emulate_native_sbc.py',
                                    ROOT/'scripts/emulate_native_sbc_pcm.py',
                                    ROOT/'scripts/analyze_native_sections.py',
                                    ROOT/'scripts/analyze_sdp_activation.py', manifest)},
              'consumer_companion_elf_sha256': companion['elf_sha256'],
              'routes': routes, 'controls': controls, 'all_passed': True,
              'original_mixer_messages': {'select': 13, 'read': 18, 'stop': 15, 'cleanup': 19},
              'source_remove': hex(REMOVE_SOURCE), 'source_notice_report': '0x455c86',
              'source_notice_dispatch': hex(NOTICE_DISPATCH), 'main_capture_boundary': hex(MAIN_DISPATCH),
              'main_audio_notification_event': 0x246,
              'notice_flags': {'21': 1, '22': 2, '23': 8, '24': 16, '25': 32, '26': 64, '27': 64},
              'source_report_mask_for_cleanup22_and_deletion23': 6,
              'original_lifecycle_and_notice_translation_executed_offline': True,
              'notice23_alone_does_not_establish_pcm_recycle_safety': True,
              'events22_23_translated_owner_reloaded_from_current_channel': True,
              'production_pinning_source_reservation_callback_lifetime_adapter_implemented': False,
              'native_app_listener_or_main_dispatch_implemented': False,
              'real_hardware_message14_or_drain_trigger_verified': False,
              'actual_os_irq_preemption_or_navigation_coexistence_verified': False,
              'compiled_sbc_queue_worker_consumer_called_or_changed': False,
              'device_io': False, 'device_install_candidate': False,
              'stock_notice_dispatch_trace': trace(stock, NOTICE_DISPATCH),
              'stock_source_remove_trace': trace(stock, REMOVE_SOURCE),
              'stock_cleanup19_trace': trace(stock, 0x2fa2e8),
              'limitations': 'Offline original finite PCM source FIFO/selection/reader through mixer actor, message15 stop, message19 provider cleanup, source-list removal and notice reporting/translation. Inherited handles/mutexes/priority/message transport/start/busy controls and bounded channel/profile init remain. Small scratch/mixer ring and hardware activation are synthetic; message14 allocation/configuration and real hardware drain/end triggers are not executed. Tests explicitly send13/18/15/19 and remove nodes; no production auto-advance adapter. Actor uses synthetic wait/get and Python CPU-context restoration. Notice transport is captured and original dispatcher invoked explicitly, up to a stub main event hub0x330b48; no actual App handler/listener or main subsystem routing. Notice23 occurs before node release/count updates; early-delivery control pauses original caller and runs original translation on a separate stack then restores Python context, not actual OS preemption/quiescence. Delayed notices22/23 reload current channel owner while25/26 use packet owner: artificial distinct per-block owners expose field semantics, not proven real-world misrouting. No production pinning/reservation/callback lifetime, decoder output integration, actual navigation concurrency/resampling/DAC/speaker, registered SEP/UI/phone traffic, accepted package loading or Google Maps. Existing compiled companion/artifacts unchanged and not called. No device I/O or install candidate.'}
    path = ROOT/'evidence/firmware-analysis/native-memory-completion-emulation.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'queued_blocks': routes[0]['queued_blocks'],
                      'pcm_bytes': routes[0]['pcm_bytes'], 'controls': len(controls),
                      'all_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
