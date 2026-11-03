#!/usr/bin/env python3
"""Register stock memory-backed audio providers and pull their PCM, offline.

Kinds10/11 with source flags12 select the original memory IO implementation;
no fabricated reader or injected callback is supplied. Existing handle,
mutex, mixer-priority/message and hardware controls remain synthetic. PCM
pages and mixer buffers are fixtures, not accepted App allocations. Explicit
pull/cleanup calls do not prove native task scheduling or speaker playback.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace
from emulate_native_pcm_initialization import ColdPcm
from emulate_native_audio_registration import CHANNELS, CHANNEL_STRIDE, require, sha
from emulate_native_sbc import INPUT_PAGE, OUTPUT_PAGE, PAGE_BYTES
from emulate_native_sbc_pcm import CONTEXT, RING, RING_BYTES

POOL10 = 0x034e3cf4
POOL11 = 0x034e4834
INSTANCE_BYTES = 0x240
INSTANCE_COUNT = 5
PCM_PAGES = 0x08a00000
MEMORY_FLAGS = 12
CLEANUP = 0x437a90


class MemoryAudio(ColdPcm):
    def __init__(self, stock, companion):
        self.factory_results = []
        self.free_indices = []
        self.error_notifications = []
        self.allowed_channels = set()
        self.pcm_fixtures = {}
        super().__init__(stock, companion)
        require(POOL10 + INSTANCE_COUNT*INSTANCE_BYTES == POOL11,
                'Memory provider pools no longer adjacent')
        require(any(z['runtime_start'] <= 0x34e3000 and 0x34e5000 <= z['runtime_end']
                    for z in stock.zeros), 'Provider pools not covered by stock BSS zeroing')
        self.uc.mem_map(0x34e3000, 0x2000)
        self.uc.mem_write(POOL10-32, b'\xa5'*32)
        self.uc.mem_write(POOL11+INSTANCE_COUNT*INSTANCE_BYTES, b'\xa5'*4)
        self.symbols['source_cleanup'] = {'address': CLEANUP | 1}
        self.original_channel_baseline = self.channel_baseline

    def observe(self, uc, address, size, data):
        super().observe(uc, address, size, data)
        if address == 0x437a3a:
            self.factory_results.append(uc.reg_read(UC_ARM_REG_R0))
        elif address in (0x48ee58, 0x48efa4):
            self.free_indices.append({'kind': 10 if address == 0x48ee58 else 11,
                                      'index': uc.reg_read(UC_ARM_REG_R0)})
        elif address == 0x455c86:
            args = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                            UC_ARM_REG_R2, UC_ARM_REG_R3)]
            self.error_notifications.append({'channel': args[0], 'event': args[2]})

    def pcm_page(self, index, payload):
        require(0 < len(payload) <= PAGE_BYTES-32, 'PCM fixture exceeds guarded page')
        page = PCM_PAGES+index*2*PAGE_BYTES
        self.uc.mem_map(page, PAGE_BYTES)  # Unmapped page after every payload.
        self.uc.mem_write(page, b'\xa5'*PAGE_BYTES)
        pointer = page+PAGE_BYTES-len(payload)
        self.uc.mem_write(pointer, payload)
        self.pcm_fixtures[pointer] = payload
        return pointer

    def register_memory(self, kind, channel, pointer, count, channels=1, rate=16000):
        require(kind in (10, 11), 'Only characterized memory provider kinds allowed')
        self.allowed_channels.add(channel)
        if kind == 10:
            # Stock caller0x2701dc passes a 0x20c-byte kind10 structure;
            # only its first five words are consumed by this memory backend.
            params = bytearray(0x20c)
            struct.pack_into('<5I', params, 0, channels, rate, 16, pointer, count)
            params = bytes(params)
        else:
            params = bytearray(0x210)
            struct.pack_into('<2I', params, 0, pointer, count)
            struct.pack_into('<2I', params, 0x208, rate, channels)
            params = bytes(params)
        self.uc.mem_write(OUTPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.uc.mem_write(OUTPUT_PAGE, params)
        require(self.call('register', (channel, kind, MEMORY_FLAGS, OUTPUT_PAGE),
                          (len(params), 0, 1)) == 0, 'Stock source registration failed')
        record = CHANNELS+channel*CHANNEL_STRIDE
        require(self.call('queue_start', (record+0x1a8,)) == 0, 'Stock queue start failed')
        before = len(self.factory_results)
        selector_return = self.call('select', (channel, 0))
        require(len(self.factory_results) == before+1, 'Stock constructor result not observed')
        return {'record': record, 'kind': kind, 'channel': channel,
                'instance': self.word(record+0xf0),
                'constructor_return': self.factory_results[-1],
                'selector_return': selector_return,
                'prepared': self.byte(record+2), 'parameter_bytes': len(params)}

    def object_for(self, source):
        base = POOL10 if source['kind'] == 10 else POOL11
        return base+source['instance']*INSTANCE_BYTES+0x10

    def source_read(self, source, capacity):
        require(0 <= capacity <= PAGE_BYTES-32, 'Read capacity exceeds guarded output')
        pointer = OUTPUT_PAGE+PAGE_BYTES-capacity
        self.uc.mem_write(OUTPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.symbols['selected_memory_read'] = {'address': self.word(source['record']+0x108)}
        count = self.call('selected_memory_read', (source['instance'], pointer, capacity))
        require(count <= capacity, 'Stock memory reader exceeded capacity')
        require(bytes(self.uc.mem_read(pointer-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(pointer+count, capacity-count)) == b'\xa5'*(capacity-count),
                'Stock memory reader crossed output guards')
        return bytes(self.uc.mem_read(pointer, count))

    def tts_snapshot(self):
        return (bytes(self.uc.mem_read(CONTEXT, 32)), bytes(self.uc.mem_read(RING, RING_BYTES)))

    def verify(self):
        # This test intentionally registers selected channels. All other
        # source-channel records still have the original initialization baseline.
        current = bytes(self.uc.mem_read(CHANNELS, 18*CHANNEL_STRIDE))
        baseline = bytearray(self.original_channel_baseline)
        for channel in self.allowed_channels:
            lo, hi = channel*CHANNEL_STRIDE, (channel+1)*CHANNEL_STRIDE
            baseline[lo:hi] = current[lo:hi]
        self.channel_baseline = bytes(baseline)
        super().verify()
        require(bytes(self.uc.mem_read(POOL10-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(POOL11+INSTANCE_COUNT*INSTANCE_BYTES, 4)) == b'\xa5'*4,
                'Provider pool crossed outside guards')
        for pointer, payload in self.pcm_fixtures.items():
            require(bytes(self.uc.mem_read(pointer, len(payload))) == payload and
                    bytes(self.uc.mem_read(pointer-32, 32)) == b'\xa5'*32,
                    'Source modified borrowed PCM page or leading guard')


def registered_route(stock, companion, kind, channels, rate):
    m = MemoryAudio(stock, companion)
    payload = struct.pack('<'+'h'*(333*channels),
                          *[((j*211)%60001)-30000 for j in range(333*channels)])
    pointer = m.pcm_page(0, payload)
    initial_tts = m.tts_snapshot()
    source = m.register_memory(kind, m.channel, pointer, len(payload), channels, rate)
    require(source['constructor_return'] == 0 and source['prepared'] == 1,
            'Stock memory provider was not constructed/prepared')
    expected_reader, expected_format = ((0x48edf9, 0x48ee31) if kind == 10
                                        else (0x48ef3d, 0x48ef7d))
    require(m.word(m.record+0x108) == expected_reader and
            m.word(m.record+0x10c) == expected_format, 'Factory selected wrong memory methods')
    fmt = struct.unpack('<HHII', m.uc.mem_read(m.record+0x138, 12))
    require(fmt == (channels, 16, channels*2, rate), 'Stock memory-source logical format differs')
    inner = m.object_for(source)
    callbacks = struct.unpack('<8I', m.uc.mem_read(inner+0x210, 32))
    require(callbacks == (0x5e759f, 0x5e75b3, 0x5e75bb, 0x5e75f1,
                          0x5e7623, 0x5e7667, 0x5e7677, 0x5e7687),
            'Original IO constructor did not install the stock memory backend')
    require(m.half(inner+0x20c) == 3 and m.word(inner) == pointer,
            'Memory backend state/borrowed pointer differs')
    m.setup_mixer()
    chunks, wraps = [], 0
    for _ in range((len(payload)+255)//256):
        chunk, wrapped = m.pull(); chunks.append(chunk); wraps += int(wrapped)
    actual = b''.join(chunks)
    require(actual == payload and wraps == 1, 'Original memory reader/mixer PCM differs')
    for _ in range(4): require(m.source_read(source, 256) == b'', 'Memory source EOF returned audio')
    require(m.tts_snapshot() == initial_tts, 'Memory-source route changed global TTS state/ring')
    require(m.visits[0x21c62a] == 0, 'Memory route unexpectedly used the global TTS PCM host')
    m.call('source_cleanup', (m.record,))
    pool = POOL10 if kind == 10 else POOL11
    require(m.byte(pool+source['instance']*INSTANCE_BYTES+0xc) == 0 and
            m.byte(inner+0xc) == 0 and m.half(inner+0x20c) == 0 and
            bytes(m.uc.mem_read(m.record+0xf4, 68)) == bytes(68) and m.byte(m.record+2) == 0,
            'Original source cleanup did not stop/release/clear provider')
    required = {0x270458, 0x277c6a, 0x277b38, 0x277536, 0x2f9f2e, 0x277ac2,
                0x2777f0, 0x4379d4, 0x437764, 0x35b4f4, 0x4caf2e, 0x4cadec, 0x4cae18,
                0x5e759e, 0x437a3e, 0x2f9cca, 0x2f9d1a, 0x4cae6c, 0x5e75ba,
                0x3732c8, CLEANUP, 0x4cae44, 0x5e75b2}
    require(required.issubset(m.registration_visits), 'Original memory route skipped required code')
    m.verify()
    return {'name': f'kind{kind}_{channels}ch_{rate}', 'source_kind': kind,
            'source_flags': MEMORY_FLAGS, 'channel': m.channel,
            'provider_instance': source['instance'], 'source_constructor_return': 0,
            'parameter_bytes': source['parameter_bytes'], 'reader': hex(expected_reader),
            'io_callbacks': [hex(p) for p in callbacks],
            'logical_format': {'channels': channels, 'bits': 16, 'align': channels*2, 'rate': rate},
            'pcm_bytes': len(actual), 'pcm_sha256': sha(actual), 'reference_byte_identical': True,
            'explicit_mixer_pulls': len(chunks), 'final_pull_bytes': len(chunks[-1]),
            'mixer_copy_wraps': wraps, 'four_eof_reads_zero': True,
            'tts_context_and_entire_ring_unchanged': True, 'original_cleanup_released_instance': True,
            'original_methods_and_io_callbacks_not_supplied_by_test': True,
            'stock_paths_visited': [hex(a) for a in sorted(required)], 'passed': True}


def isolation_case(stock, companion):
    m = MemoryAudio(stock, companion)
    payload_a = struct.pack('<300h', *range(-150, 150))
    payload_b = struct.pack('<300h', *range(1200, 1500))
    a = m.register_memory(10, 0, m.pcm_page(0, payload_a), len(payload_a))
    b = m.register_memory(10, 1, m.pcm_page(1, payload_b), len(payload_b))
    require((a['instance'], b['instance']) == (0, 1), 'Stock allocator did not separate streams')
    initial_tts = m.tts_snapshot()
    require(m.source_read(a, 128) == payload_a[:128] and
            m.source_read(b, 256) == payload_b[:256], 'Independent source reads differ')
    b_state = bytes(m.uc.mem_read(m.object_for(b), 0x230))
    m.call('source_cleanup', (a['record'],))
    require(bytes(m.uc.mem_read(m.object_for(b), 0x230)) == b_state and
            m.source_read(b, 1000) == payload_b[256:], 'Cleanup changed the other memory source')
    c = m.register_memory(10, 2, m.pcm_page(2, payload_a), len(payload_a))
    require(c['instance'] == 0 and m.source_read(c, 1000) == payload_a,
            'Released stock provider instance did not reset and reuse')
    require(m.tts_snapshot() == initial_tts, 'Sequential multi-source test changed TTS ring')
    m.verify()
    return {'name': 'independent_instances_cleanup_and_reuse', 'instances': [0, 1, 0],
            'sequential_read_bytes': 1328, 'cleanup_preserves_other_provider': True,
            'tts_ring_unchanged': True, 'concurrent_navigation_or_scheduler_test': False,
            'passed': True}


def tts_case(stock, companion):
    m = MemoryAudio(stock, companion)
    payload = struct.pack('<333h', *range(-166, 167))
    source = m.register_memory(10, m.channel, m.pcm_page(0, payload), len(payload))
    require(m.source_read(source, 128) == payload[:128], 'Initial independent read differs')
    voice_pcm = b'\x34\x12'*128
    for _ in range(40): m.host_pcm(voice_pcm)
    require(m.queued() == 10240 and m.byte(CONTEXT+7) == 1,
            'Original cold TTS host did not create pending source17 data')
    before = m.tts_snapshot()
    require(m.source_read(source, 256) == payload[128:384] and m.tts_snapshot() == before,
            'Memory read changed pending TTS state/data')
    memory_state = bytes(m.uc.mem_read(m.object_for(source), 0x230))
    require(m.read(256) == voice_pcm, 'Original TTS reader did not return its own PCM')
    m.call('stock_discard')
    require(m.queued() == 0 and bytes(m.uc.mem_read(m.object_for(source), 0x230)) == memory_state,
            'TTS reader/discard altered independent memory-source state')
    after_discard = m.tts_snapshot()
    require(m.source_read(source, 1000) == payload[384:] and
            m.tts_snapshot() == after_discard, 'Memory remainder changed after original TTS discard')
    m.verify()
    return {'name': 'memory_provider_vs_original_cold_tts_and_discard',
            'original_cold_tts_queued_bytes': 10240, 'original_tts_read_bytes': 256,
            'memory_pcm_bytes': len(payload), 'both_pcm_streams_reference_identical': True,
            'tts_discard_preserves_memory_source': True,
            'sequential_data_isolation_only': True, 'actual_navigation_concurrency_verified': False,
            'passed': True}


def borrowed_buffer_case(stock, companion):
    m = MemoryAudio(stock, companion)
    payload = bytes(range(256))*2
    pointer = m.pcm_page(0, payload)
    source = m.register_memory(10, m.channel, pointer, len(payload))
    require(m.source_read(source, 128) == payload[:128], 'Borrowed-buffer initial read differs')
    changed = payload[:128]+b'\x39\x6a'*192
    m.uc.mem_write(pointer, changed)
    m.pcm_fixtures[pointer] = changed
    require(m.source_read(source, 1000) == changed[128:], 'Stock source unexpectedly owns a PCM copy')
    require(all(e['size'] != len(payload) for e in m.handles.values()),
            'Test unexpectedly allocated a PCM-sized stock handle')
    m.verify()
    return {'name': 'caller_retains_pcm_buffer_lifetime',
            'source_holds_original_pointer': True, 'later_caller_mutation_changes_reader_output': True,
            'parameter_struct_copied_but_pcm_not_copied': True,
            'production_must_pin_buffer_until_source_finished': True, 'passed': True}


def exhaustion_case(stock, companion):
    m = MemoryAudio(stock, companion)
    pointer = m.pcm_page(0, bytes(range(64)))
    adjacent = m.register_memory(11, 6, pointer, 64)
    require(adjacent['instance'] == 0 and m.byte(POOL11+0xc) == 1,
            'Adjacent pool control source not allocated')
    successful = [m.register_memory(10, c, pointer, 64) for c in range(5)]
    require([s['instance'] for s in successful] == list(range(5)) and
            all(s['constructor_return'] == 0 and s['prepared'] == 1 for s in successful),
            'Stock provider pool does not have five usable instances')
    occupied = bytes(m.uc.mem_read(POOL10, 5*INSTANCE_BYTES))
    inner_adjacent = bytes(m.uc.mem_read(POOL11+0x10, 0x230))
    failed = m.register_memory(10, 5, pointer, 64)
    # The allocator leaves output untouched on exhaustion. Stock constructor
    # preseeded it with channel5, then its failure path calls free(index5).
    # The slot5 used marker is exactly the adjacent kind11 slot0 marker.
    require(failed['constructor_return'] == 0xffff and failed['prepared'] == 0 and
            failed['instance'] == 5 and failed['selector_return'] == 0,
            'Original exhaustion/result handling differs')
    require(m.free_indices[-1] == {'kind': 10, 'index': 5} and m.byte(POOL11+0xc) == 0,
            'Stock failure path did not reproduce adjacent-marker overwrite')
    require(bytes(m.uc.mem_read(POOL10, 5*INSTANCE_BYTES)) == occupied and
            bytes(m.uc.mem_read(POOL11+0x10, 0x230)) == inner_adjacent and
            m.error_notifications == [{'channel': 5, 'event': 27}, {'channel': 5, 'event': 23}],
            'Exhaustion altered occupied data or omitted stock error notification')
    m.verify()
    return {'name': 'sixth_kind10_source_failure_and_adjacent_pool_marker',
            'successful_instances': 5, 'constructor_return': 65535, 'selector_return': 0,
            'failed_source_prepared': False, 'failed_constructor_free_index': 5,
            'adjacent_kind11_slot0_used_marker_cleared': True,
            'occupied_kind10_records_and_kind11_inner_state_unchanged': True,
            'original_error_and_followup_events': [27, 23],
            'requires_reservation_and_checked_prepared_status': True,
            'synthetic_bss_and_explicit_calls_only': True, 'passed': True}


def main():
    stock = NativeImage()
    manifest = ROOT/'staging/native-media-consumer/manifest.json'
    companion = json.loads(manifest.read_text())
    for path, digest in companion['source_sha256'].items():
        require(sha((ROOT/path).read_bytes()) == digest, 'Companion source changed: '+path)
    for key in ('elf', 'flat_binary'):
        require(sha((ROOT/companion[key]).read_bytes()) == companion[key+'_sha256'],
                'Companion artifact changed')
    routes = [registered_route(stock, companion, kind, channels, rate)
              for kind in (10, 11) for channels, rate in ((1, 16000), (2, 44100))]
    controls = [isolation_case(stock, companion), tts_case(stock, companion),
                borrowed_buffer_case(stock, companion), exhaustion_case(stock, companion)]
    switch = stock.read(0x4caf54, 9)
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(),
              'stock_sha256': EXPECTED, 'script_sha256': sha(Path(__file__).read_bytes()),
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                                   (ROOT/'scripts/analyze_native_sections.py',
                                    ROOT/'scripts/analyze_sdp_activation.py',
                                    ROOT/'scripts/emulate_native_pcm_initialization.py',
                                    ROOT/'scripts/emulate_native_audio_messages.py',
                                    ROOT/'scripts/emulate_native_audio_registration.py',
                                    ROOT/'scripts/emulate_native_pcm_flow_control.py',
                                    ROOT/'scripts/emulate_native_sbc.py',
                                    ROOT/'scripts/emulate_native_sbc_pcm.py', manifest)},
              'consumer_companion_elf_sha256': companion['elf_sha256'],
              'routes': routes, 'controls': controls, 'all_passed': True,
              'original_source_registration_factory_io_and_mixer_executed': True,
              'independent_memory_pcm_source_identified_offline': True,
              'global_tts_pcm_host_not_needed_for_memory_route': True,
              'source_kinds': [10, 11], 'memory_source_flags': MEMORY_FLAGS,
              'provider_pool_bases': [hex(POOL10), hex(POOL11)],
              'instances_per_pool': INSTANCE_COUNT, 'instance_bytes': INSTANCE_BYTES,
              'memory_io_setup': '0x4caf2e', 'io_callback_constructor': '0x4cadec',
              'source_flags_switch_table': '0x4caf54', 'computed_pc_base': '0x4caf56',
              'source_flags_switch': [{'flags': j+6, 'target': hex(0x4caf56+b*2)}
                                      for j, b in enumerate(switch)],
              'memory_read': '0x5e75ba', 'memory_initialize': '0x5e759e',
              'source_cleanup': hex(CLEANUP), 'source_parameter_pcm_pointer_is_borrowed': True,
              'existing_stock_kind10_flags12_caller': '0x2701dc',
              'existing_stock_registration_callsite': '0x270268',
              'stock_kind10_parameter_struct_bytes': 0x20c,
              'stock_caller_format': {'channels': 1, 'bits': 16, 'rate': 16000},
              'stock_caller_is_public_app_api_verified': False,
              'source_pool_exhaustion_hazard_verified_offline': True,
              'production_buffer_pinning_reservation_completion_adapter_implemented': False,
              'hardware_format_conversion_or_output_verified': False,
              'actual_navigation_scheduling_or_audio_coexistence_verified': False,
              'native_app_ui_or_direct_phone_music_verified': False,
              'device_io': False, 'device_install_candidate': False,
              'stock_memory_backend_trace': trace(stock, 0x5e75ba),
              'stock_io_callback_constructor_trace': trace(stock, 0x4cadec),
              'existing_stock_memory_playback_caller_trace': trace(stock, 0x2701dc),
              'limitations': 'Offline exact kind10/11 registration/source queue/factory/IO constructor/prepare/indirect reader/mixer copy and explicit cleanup. Original source methods and IO callbacks come from stock instructions; no custom callback supplied. ColdPcm harness supplies channel/global initialization bounded before hardware, heap handles/mutexes/mixer priority/message transport/start/busy policies and virtual VFP controls. Companion is integrity-checked and loaded by inherited harness but no compiled worker/queue/consumer is called. Synthetic PCM pages are borrowed by stock backend and retained by test. Sequential stream isolation and original cold TTS read/discard are data-state tests, not real navigation tasks or scheduling/IRQ/concurrency/hardware audio. Logical 16k mono/44.1k stereo formats do not prove DAC/resampling. Five-instance exhaustion executes stock failure cleanup and clears adjacent kind11 used marker in synthetic BSS; it is not a live memory observation. No production pinning/reservation/completion/source-advance adapter, SEP/UI/phone reception, modified package acceptance/App deployment/Google Maps or speaker verification. Not an installation candidate.'}
    path = ROOT/'evidence/firmware-analysis/native-memory-audio-emulation.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'registered_routes': len(routes),
                      'controls': len(controls), 'pcm_bytes_total': sum(r['pcm_bytes'] for r in routes),
                      'all_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
